#!/usr/bin/env python3
"""
Weekly blocklist merger

- Reads URLs from sources.txt (relative to this script)
- Downloads each list
- Extracts domain entries
- Deduplicates + sorts
- Writes output atomically to:
  /var/www/vhosts/mallouki.de/httpdocs/cms/blocklist/merged_list.txt
- Logs to:
  /root/blocklist-generator/merge_blocklists.log

NEW (auto-prune failing sources):
- Tracks consecutive fetch failures per source URL in source_failures.json
- If a URL fails 5 times in a row, it is removed from sources.txt automatically
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import time
from pathlib import Path
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

import requests


# ---- Config ----
SCRIPT_DIR = Path(__file__).resolve().parent
SOURCES_FILE = SCRIPT_DIR / "sources.txt"
ALLOWED_FILE = SCRIPT_DIR / "allowed.txt"
OUTPUT_FILE = Path("/var/www/vhosts/mallouki.de/httpdocs/cms/blocklist/merged_list.txt")
LOG_FILE = SCRIPT_DIR / "merge_blocklists.log"

# Persistent failure tracking (NEW)
FAILURE_STATE_FILE = SCRIPT_DIR / "source_failures.json"
MAX_CONSECUTIVE_FAILURES = 5

HTTP_TIMEOUT_SECONDS = 45
USER_AGENT = "blocklist-generator/1.0"


# ---- Parsing helpers ----
CANDIDATE_RE = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9\-_.]*[a-z0-9])?$")
ADBLOCK_DOMAIN_RE = re.compile(r"^\|\|([a-z0-9][a-z0-9\-_.]*[a-z0-9])(?:\^|$)", re.IGNORECASE)
URL_IN_LINE_RE = re.compile(r"(?i)\bhttps?://[^\s\"']+")

IGNORE_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-allnodes",
    "ip6-allrouters",
    "0.0.0.0",
}


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S %z")
    line = f"{ts} {msg}\n"
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line)
    print(line, end="")


def normalize_url(u: str) -> str:
    u = html.unescape(u.strip())
    # Convert GitHub "blob" -> "raw"
    if "github.com/" in u and "/blob/" in u:
        u = u.replace("github.com/", "raw.githubusercontent.com/").replace("/blob/", "/")
    return u


def is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def normalize_domain(d: str) -> Optional[str]:
    d = d.strip().strip(".").lower()
    if not d or d in IGNORE_HOSTS:
        return None

    d = d.strip("[](){}<>;,")
    if d.startswith("*."):
        d = d[2:]

    if is_ip(d):
        return None

    if len(d) > 253 or "." not in d:
        return None
    if not CANDIDATE_RE.match(d):
        return None
    if ".." in d:
        return None

    # Normalize IDN to punycode for stable dedupe
    try:
        d_idna = d.encode("idna").decode("ascii")
    except Exception:
        return None

    return d_idna


def extract_domains_from_line(line: str) -> Set[str]:
    out: Set[str] = set()
    s = line.strip()
    if not s:
        return out

    # skip full-line comments
    if s.startswith(("#", "!", ";")):
        return out

    # strip inline comments
    if "#" in s:
        s = s.split("#", 1)[0].strip()
        if not s:
            return out

    tokens = s.split()

    # hosts format: "<ip> <host> [host2...]"
    if tokens and is_ip(tokens[0]):
        for host in tokens[1:]:
            nd = normalize_domain(host)
            if nd:
                out.add(nd)
        return out

    # AdBlock style: ||domain^
    m = ADBLOCK_DOMAIN_RE.match(s)
    if m:
        nd = normalize_domain(m.group(1))
        if nd:
            out.add(nd)
        return out

    # lines containing URLs -> hostname
    for um in URL_IN_LINE_RE.findall(s):
        try:
            p = urlparse(um)
            if p.hostname:
                nd = normalize_domain(p.hostname)
                if nd:
                    out.add(nd)
        except Exception:
            pass

    # treat remaining chunks as potential domains
    for chunk in re.split(r"[,\s]+", s):
        if not chunk:
            continue
        chunk = chunk.strip().lstrip("@|")
        chunk = chunk.split("^", 1)[0]
        chunk = chunk.split("$", 1)[0]
        nd = normalize_domain(chunk)
        if nd:
            out.add(nd)

    return out


# ---------------- NEW: failure state helpers ----------------
def load_failure_state() -> dict[str, int]:
    if not FAILURE_STATE_FILE.exists():
        return {}
    try:
        data = json.loads(FAILURE_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            out: dict[str, int] = {}
            for k, v in data.items():
                if isinstance(k, str) and isinstance(v, int):
                    out[k] = v
            return out
    except Exception as e:
        log(f"[WARN] Could not read {FAILURE_STATE_FILE.name}: {e} (starting fresh)")
    return {}


def save_failure_state(state: dict[str, int]) -> None:
    tmp = FAILURE_STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, FAILURE_STATE_FILE)


def remove_sources_from_file(urls_to_remove: Set[str]) -> int:
    """
    Remove URLs from sources.txt while preserving comments/blank lines.
    Replaces removed URLs with a PRUNED comment including date and reason.
    Returns how many URL lines were pruned.
    """
    if not urls_to_remove or not SOURCES_FILE.exists():
        return 0

    today = time.strftime("%Y-%m-%d")
    lines = SOURCES_FILE.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    pruned = 0

    for raw in lines:
        stripped = raw.strip()

        # keep empty lines & comments unchanged
        if not stripped or stripped.startswith("#"):
            out.append(raw)
            continue

        norm = normalize_url(stripped)
        if norm in urls_to_remove:
            pruned += 1
            out.append(
                f"# PRUNED {today} after {MAX_CONSECUTIVE_FAILURES} consecutive failures: {raw}"
            )
            continue

        out.append(raw)

    if pruned > 0:
        SOURCES_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")

    return pruned


def read_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        raise FileNotFoundError(f"Missing sources file: {SOURCES_FILE}")

    urls: list[str] = []
    for raw in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(normalize_url(line))

    if not urls:
        raise ValueError(f"No URLs found in {SOURCES_FILE}")

    return urls


def read_allowed() -> Set[str]:
    """
    Read allowed/excluded domains from allowed.txt (relative to script).
    These domains will be removed from the merged output.
    """
    allowed: Set[str] = set()
    if not ALLOWED_FILE.exists():
        return allowed

    for raw in ALLOWED_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        nd = normalize_domain(line)
        if nd:
            allowed.add(nd)

    return allowed


def fetch_text(url: str) -> str:
    headers = {"User-Agent": USER_AGENT}
    r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
    r.raise_for_status()
    return r.text


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(tmp, path)


def main() -> int:
    try:
        urls = read_sources()
    except Exception as e:
        log(f"[FATAL] Cannot read sources: {e}")
        return 2

    failure_state = load_failure_state()

    all_domains: Set[str] = set()
    failures_this_run = 0
    urls_to_prune: Set[str] = set()

    log(f"[START] Sources={len(urls)} Output={OUTPUT_FILE}")

    for url in urls:
        try:
            text = fetch_text(url)
            domains: Set[str] = set()
            for line in text.splitlines():
                domains |= extract_domains_from_line(line)
            all_domains |= domains

            # success => reset consecutive failure count
            if url in failure_state:
                del failure_state[url]

            log(f"[OK]   {url}  domains={len(domains)}")
        except Exception as e:
            failures_this_run += 1

            # track consecutive failures
            failure_state[url] = int(failure_state.get(url, 0)) + 1
            cnt = failure_state[url]

            log(f"[FAIL] {url}  error={e} consecutive_failures={cnt}/{MAX_CONSECUTIVE_FAILURES}")

            if cnt >= MAX_CONSECUTIVE_FAILURES:
                urls_to_prune.add(url)

    # prune broken sources after threshold
    if urls_to_prune:
        removed = remove_sources_from_file(urls_to_prune)
        for u in urls_to_prune:
            failure_state.pop(u, None)
        log(f"[PRUNE] removed_sources={removed} threshold={MAX_CONSECUTIVE_FAILURES}")
    else:
        log("[PRUNE] removed_sources=0")

    # --- summary ---
    try:
        total_lines = SOURCES_FILE.read_text(encoding="utf-8").splitlines()
        total_urls = 0
        pruned_urls = 0

        for raw in total_lines:
            s = raw.strip()
            if not s:
                continue
            if s.startswith("# PRUNED "):
                pruned_urls += 1
                continue
            if s.startswith("#"):
                continue
            total_urls += 1

        log(
            "[SUMMARY] "
            f"sources_active={total_urls} "
            f"sources_pruned={pruned_urls} "
            f"sources_total_seen={total_urls + pruned_urls} "
            f"failures_this_run={failures_this_run} "
            f"unique_domains={len(all_domains)}"
        )
    except Exception as e:
        log(f"[WARN] Could not compute summary: {e}")


    # persist updated state
    try:
        save_failure_state(failure_state)
    except Exception as e:
        log(f"[WARN] Could not write {FAILURE_STATE_FILE.name}: {e}")

    allowed = read_allowed()
    if allowed:
        def is_allowed(domain: str) -> bool:
            return any(domain == a or domain.endswith("." + a) for a in allowed)

        before = len(all_domains)
        all_domains = {d for d in all_domains if not is_allowed(d)}
        removed = before - len(all_domains)
        log(f"[INFO] allowlist_entries={len(allowed)} removed={removed} (including subdomains)")

    merged = "\n".join(sorted(all_domains)) + "\n"

    try:
        atomic_write(OUTPUT_FILE, merged)
        log(f"[DONE] unique_domains={len(all_domains)} failures={failures_this_run} wrote={OUTPUT_FILE}")
        return 0 if len(all_domains) else 1
    except Exception as e:
        log(f"[FATAL] Cannot write output: {e}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
