# Video notes (60–90 seconds)

1. **Situation:** A compromised third-party JavaScript dependency can affect visitors without infecting the Linux OS.
2. **Question:** Did a browser cache contain a known malicious domain? This is **one indicator**, not a definitive infection test.
3. **Demo:** Run `python3 browser_cache_ioc_scanner.py` (no path arguments) on a synthetic or sanitized browser profile; cache locations are discovered automatically.
4. **Interpretation:** `IOC:` means a string was detected; `CONTEXT:` can also mean an article, screenshot metadata, or an ordinary script mention. Both require attribution.
5. **Limitations:** Browser caches do not reliably show execution, and absence of matches does not prove safety. Examine browser history, DNS/firewall logs, headers, timestamps, and the original payload if a suspicious match is found.
6. **Call to action:** Link to a tagged GitHub release; avoid distributing private browsing histories or original cache files.
