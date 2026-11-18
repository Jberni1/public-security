# Browser Cache IOC Scanner

A small, **read-only** Linux browser-cache indicator scanner designed for defensive incident-response triage. Built with Python's standard library; no installation or network connection required.

It checks byte sequences inside Firefox, Brave, Chromium, and Chrome cache files for a curated set of domain strings and two Base64-encoded URL variants. It also reports contextual mentions of `optimizely.com`.

> **Not a malware detector.** A matching domain may come from a news report, blocklist, or harmless webpage. A cached JavaScript entry does not establish execution. Conversely, a negative result **does not** rule out prior exposure: caches can be cleared, compressed, replaced, or bypassed (e.g. private browsing). The specific domain list is a historical snapshot, **not live threat intelligence**.

## One-command scan with private summary (recommended)

From the root of a cloned `public-security` repository:

```sh
bash browser/cache-ioc-scanner/run_scan.sh
```

Or, from this scanner's directory:

```sh
bash run_scan.sh
```

**Origin:** `run_scan.sh` is the portable, anonymized adaptation of **Code Block 149-2.1** (2026-11-18), not a verbatim copy of the machine-specific command.

The runner finds its accompanying Python scanner automatically, performs the same cache scan without `--root`, prints only an anonymized summary, and stores the full scan log **locally** in `${XDG_STATE_HOME:-$HOME/.local/state}/public-security/browser-cache-ioc-scanner/`. The log directory has permissions `700`, and each new log file has permissions `600`. It is **not** uploaded to GitHub. Avoid sharing the raw log; it can include browser-cache entry names and investigation indicators.

Optional scanner flags can be forwarded, e.g. `bash run_scan.sh --ioc example.test`. The runner preserves the scanner's exit code: `0` means the scan completed without reported read errors or oversized-file skips, **not** that no IOC terms were found or that the machine is safe.

The summary counts **matching files** and **matching category labels**; a single file may contribute multiple category labels. IOC, BASE64, and CONTEXT matches are leads, not evidence of execution.

## Direct Python invocation
### Automatic profile discovery

Requires Python 3.9+ on Linux. Run this command from the scanner's directory:

```sh
python3 browser_cache_ioc_scanner.py
```

**No `--root` argument is needed for the first scan.** The program automatically locates known Firefox, Brave, Chromium, and Chrome caches and performs a bounded search for custom browser profiles under the current user's home directory.

To avoid walking unrelated private data, automatic discovery skips common user-data and development folders (such as Documents, Downloads, projects, backups, and `.local`), does not follow symbolic links, and stays on the home filesystem. It searches to depth 12 and visits at most 20,000 directories. It can therefore miss unusual locations, external mounts, or already-evicted caches.

If a browser profile is in an excluded location, explicitly select it:

```sh
python3 browser_cache_ioc_scanner.py --root "/path/to/browser-profiles"
```

The `--root` option overrides automatic discovery, allowing a narrower scan. Repeat it to scan more than one custom root:

```sh
python3 browser_cache_ioc_scanner.py \
  --root "/path/to/profile-a" \
  --root "/path/to/profile-b" \
  --ioc 'example.test'
```

Replace `/path/to/...` with paths from your own computer. Avoid publishing real paths in screenshots and logs. An incomplete-discovery warning (exit code `2`) signals a directory limit or filesystem error; use a focused `--root` to complete that investigation.

Use `--show-paths` **only for private analysis**. By default, filesystem paths are replaced with generic cache identifiers so that copying the output into a video is less likely to disclose personal usernames or directory structures.

The scanner performs no HTTP requests, does not execute cached scripts, and does not modify or delete files. Exit code `0` means that the scan ran without read errors or skipped oversized files, **not that a machine is clean**. Exit code `2` means no cache directory was found or scanning was incomplete.

## Testing

```sh
python3 -m unittest discover -s tests -v
```

## Publishing and security notes

- Publish this source code and this README **only**. Do not upload cache samples, browsing history, DNS logs, packet captures, screenshots with personal paths, NFS backups, cookies, or investigation notes from your personal environment.
- Never turn an existing private research repository public merely to share this scanner: its prior Git history may contain information even if files were removed later.
- Validate the list against original advisories before using it in a new investigation. The script intentionally does not claim to determine if JavaScript executed or data was stolen.
- For a video, show an example using synthetic files or sanitize on-screen output.


## License

MIT (see `LICENSE`).
