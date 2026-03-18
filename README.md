# Handles pihole blocklists to improve performance in pihole
The script merges the blocklists given in the sources.txt file into one large list. 
Additionally you may define allowed domains and additional blocked domains in the files `allow.txt` and `block.txt` to avoid having rules within pihole.
Adjust the output path as required and then you can import the newly merged blocklist from the target url. 
Of course you may combine the local rules and additional blocklists as you wish. 

## Sources (`sources.txt`)

Each non-comment line in `sources.txt` is either a **remote URL** or a **local file path**:

- **Remote URL** — any line starting with `http://` or `https://`. Fetched via HTTP on each run. GitHub `blob` URLs are automatically converted to raw URLs.
- **Local file path** — any other line. Resolved relative to the directory containing `merge_blocklists.py`. Absolute paths also work.

```
# Remote blocklists
https://adaway.org/hosts.txt
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Local custom blocklists (relative to the script directory)
./my-extra-blocks.txt
custom/work-ads.txt
```

All formats are supported in local files too: hosts file (`0.0.0.0 domain`), AdBlock (`||domain^`), plain domains, or URLs.

Local file sources are **never auto-pruned** — a missing file logs a `[WARN]` but remains in `sources.txt`.

## Why
This should centralize the lists for my pihole instances and improve performance. It will also remove duplication and deactivate non working block lists
after 5 successive failures. The log output will tell you about the details. 

Enjoy.
