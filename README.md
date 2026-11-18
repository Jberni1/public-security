# Public Security

Defensive security utilities, published as small, self-contained tools with documentation and reproducible tests.

## Tools

- [Browser Cache IOC Scanner](browser/cache-ioc-scanner/README.md) — a read-only Linux browser-cache indicator scanner with automatic profile discovery and a private local report.

## Quick start

After cloning this repository:

```bash
bash browser/cache-ioc-scanner/run_scan.sh
```

See the tool's README for prerequisites, optional arguments, limitations, and tests. A string match does **not** prove script execution or compromise.

## Privacy

Do not commit real browser caches, browsing history, cookies, credentials, personal paths, incident evidence, packet captures, or private investigation logs. All included test fixtures are synthetic.

## Licenses

Each tool supplies its own license file.
