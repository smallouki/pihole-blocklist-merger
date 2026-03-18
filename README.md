# Pi-hole Blocklist Merger

Merges multiple DNS blocklists into a single deduplicated, sorted list served at a static URL for Pi-hole to import.

## Features

- Merges remote URLs and local files listed in `sources.txt`
- Deduplicates and sorts all domains
- Supports hosts file, AdBlock (`||domain^`), plain domain, and URL-in-line formats
- Local allowlist via `allow.txt` (removes domains including subdomains)
- Local blocklist via `block.txt` (force-adds domains)
- Auto-prunes remote sources that fail 5 consecutive times
- Detailed log output with per-source domain counts and a run summary

## Files

- `sources.txt` — list of remote URLs and/or local file paths to merge
- `allow.txt` — domains to remove from the merged output (subdomains included)
- `block.txt` — domains to force-add to the merged output
- `custom/` — directory for local custom blocklists referenced in `sources.txt`
- `merge_blocklists.py` — main script
- `merge_blocklists.log` — run log (gitignored)

## Sources (`sources.txt`)

Each non-comment line is either a **remote URL** or a **local file path**:

- **Remote URL** — any line starting with `http://` or `https://`. Fetched via HTTP on each run. GitHub `blob` URLs are automatically converted to raw URLs.
- **Local file path** — any other line. Resolved relative to the directory containing `merge_blocklists.py`. Absolute paths also work.

```
# Remote blocklists
https://adaway.org/hosts.txt
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Local custom blocklists (relative to the script directory)
custom/my-extra-blocks.txt
custom/work-ads.txt
```

All formats are supported in local files too: hosts file (`0.0.0.0 domain`), AdBlock (`||domain^`), plain domains, or URLs.

Local file sources are **never auto-pruned** — a missing file logs a `[WARN]` but remains in `sources.txt`.

## `custom/` directory

Place your own domain lists here and reference them in `sources.txt`. Example files included:

- `custom/reddit.list` — Reddit-related domains
- `custom/tiktok.list` — TikTok-related domains

## Log output

Each run produces log lines with the following tags:

| Tag | Meaning |
|---|---|
| `[START]` | Run started; shows total, remote, and local source counts |
| `[OK]` | Remote source fetched successfully; shows domain count |
| `[LOCAL]` | Local file read successfully; shows domain count |
| `[FAIL]` | Remote source fetch failed; shows consecutive failure count |
| `[WARN]` | Local file could not be read |
| `[PRUNE]` | Sources removed after hitting the failure threshold |
| `[INFO]` | `block.txt` and `allow.txt` application results |
| `[DONE]` | Output written; shows final unique domain count |
| `[SUMMARY]` | Full run summary including all counters |
| `[LOCAL_SOURCES]` | Per-file recap of all local sources and their domain counts |

Example `[SUMMARY]` and `[LOCAL_SOURCES]` output:

```
[SUMMARY] sources_active=76 sources_pruned=1 sources_total_seen=77 failures_this_run=0 local_sources=2 local_block_entries=0 local_block_added=0 allowlist_entries=0 allowlist_removed=0 unique_domains=1923456
[LOCAL_SOURCES] count=2
[LOCAL_SOURCES]   OK     /root/blocklist-generator/custom/reddit.list  domains=68
[LOCAL_SOURCES]   OK     /root/blocklist-generator/custom/tiktok.list  domains=61
```

## Setup

1. Adjust `OUTPUT_FILE` in `merge_blocklists.py` to point to your web-served path
2. Install dependencies: `pip install -r requirements.txt`
3. Schedule via cron:

```
15 3 * * * cd /root/blocklist-generator && python3 merge_blocklists.py >> cron.log 2>&1
```

4. Add the output URL to Pi-hole under **Group Management → Adlists**

## Why
Centralizes blocklist management across Pi-hole instances, eliminates duplication, and automatically retires broken sources after 5 consecutive failures.
