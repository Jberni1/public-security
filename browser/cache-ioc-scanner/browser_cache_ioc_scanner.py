#!/usr/bin/env python3
"""Read-only browser cache IOC keyword scanner (standard library only).

Designed for defensive Linux browser-cache incident-response triage.
Findings are *leads*, not evidence of execution or host compromise.
"""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import sys

IOC_DOMAINS = (
    "1688360.cc",
    "webshell.lol",
    "pay-cloud.online",
    "pay-relay.wordpressadmin001.workers.dev",
    "5vobauua3ojpklx.icu",
    "eil786npto9u5bq.icu",
    "l7bcsnwc7nzr3uo.icu",
    "ios-hack.icu",
    "linkforge.cc",
    "je4ft3gn8vxudum.icu",
    "q1ls1ho9x7wsxlu.icu",
    "p55abnw2pnsz0bo.icu",
    "1y69gy2mdzaltz1.icu",
    "gm38duxoihbmy5o.icu",
)

CONTEXT_MARKERS = ("optimizely.com",)
BASE64_URLS = (
    "https://1688360.cc/track.js",
    "https://webshell.lol/get.js",
)

DEFAULT_ROOTS = (
    ".cache/mozilla/firefox",
    ".mozilla/firefox",
    ".config/mozilla/firefox",
    "snap/firefox/common/.cache/mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
    ".var/app/org.mozilla.firefox/cache",
    ".var/app/org.mozilla.firefox/config",
    ".cache/BraveSoftware",
    ".config/BraveSoftware",
    ".var/app/com.brave.Browser/cache",
    ".var/app/com.brave.Browser/config",
    ".cache/google-chrome",
    ".config/google-chrome",
    ".cache/chromium",
    ".config/chromium",
)


class ScanError(Exception):
    pass


def markers(extra: list[str]) -> dict[bytes, str]:
    terms: dict[bytes, str] = {}
    for domain in IOC_DOMAINS:
        terms[domain.encode("ascii").lower()] = "IOC:" + domain
    for marker in CONTEXT_MARKERS:
        terms[marker.encode("ascii").lower()] = "CONTEXT:" + marker
    for url in BASE64_URLS:
        terms[base64.b64encode(url.encode("ascii")).lower()] = "BASE64:" + url
    for term in extra:
        term = term.strip()
        if term:
            terms[term.encode("utf-8").lower()] = "CUSTOM:" + term
    return terms


def scan_file(path: Path, terms: dict[bytes, str]) -> list[str]:
    hits: set[str] = set()
    overlap = max(map(len, terms), default=1) - 1
    previous = b""
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            data = (previous + chunk).lower()
            for needle, label in terms.items():
                if needle in data:
                    hits.add(label)
            previous = data[-overlap:] if overlap else b""
    return sorted(hits)


def is_cache_directory(path: Path) -> bool:
    name = path.name.lower()
    return (
        (name == "entries" and path.parent.name.lower() == "cache2")
        or name in {"cache_data", "code cache", "cachestorage", "scriptcache"}
    )


def discover_caches(root: Path, max_depth: int) -> set[Path]:
    if not root.is_dir() or root.is_symlink():
        return set()
    if is_cache_directory(root):
        return {root}
    found: set[Path] = set()
    for parent, dirs, _ in os.walk(root, followlinks=False):
        path = Path(parent)
        depth = len(path.relative_to(root).parts)
        if depth > max_depth:
            dirs[:] = []
            continue
        if is_cache_directory(path):
            found.add(path)
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not (path / d).is_symlink()]
    return found



# Automatic discovery is bounded. Avoid crawling user documents, projects, and
# mounted storage while looking for browser-specific cache directory names.
AUTO_SKIP_TOP = frozenset({
    "Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos",
    "Templates", "Public", "projects", "Projects", "workspace", "Workspace",
    "backups", "Backups", "snapshots", "security-evidence", "VirtualBox VMs",
    ".local", ".cargo", ".rustup", ".npm", ".gradle",
})
AUTO_SKIP_NESTED = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages",
    ".tox", "target", "build", "dist", "evidence", "security-evidence",
})


def discover_home_caches(
    home: Path, max_depth: int, max_directories: int = 20000,
) -> tuple[set[Path], bool]:
    """Discover custom browser profile caches without following links or mounts.

    Return (cache directories, incomplete). Excluded user-data directories are
    intentional; --root PATH remains available for nonstandard locations.
    """
    if not home.is_dir() or home.is_symlink():
        return set(), True

    result: set[Path] = set()
    visited = 0
    incomplete = False
    try:
        home_device = home.stat().st_dev
    except OSError:
        return set(), True

    def walk_error(_error: OSError) -> None:
        nonlocal incomplete
        incomplete = True

    for parent, dirs, _ in os.walk(home, followlinks=False, onerror=walk_error):
        visited += 1
        if visited > max_directories:
            incomplete = True
            dirs[:] = []
            break

        current = Path(parent)
        depth = len(current.relative_to(home).parts)

        if is_cache_directory(current):
            result.add(current)
            dirs[:] = []
            continue
        if depth >= max_depth:
            dirs[:] = []
            continue

        allowed = []
        for name in dirs:
            candidate = current / name
            if name in AUTO_SKIP_NESTED or (depth == 0 and name in AUTO_SKIP_TOP):
                continue
            if candidate.is_symlink():
                continue
            try:
                if candidate.stat().st_dev != home_device:
                    continue
            except OSError:
                incomplete = True
                continue
            allowed.append(name)
        dirs[:] = allowed

    return result, incomplete


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", type=Path, metavar="PATH",
                        help="Scan only this root, repeat for multiple roots (e.g. custom browser profiles)")
    parser.add_argument("--ioc", action="append", default=[], metavar="TEXT",
                        help="Add a custom case-insensitive search string")
    parser.add_argument("--max-file-mib", type=int, default=64,
                        help="Skip files larger than this limit (default: 64 MiB)")
    parser.add_argument("--max-depth", type=int, default=12,
                        help="Directory discovery depth below each root (default: 12)")
    parser.add_argument("--max-directories", type=int, default=20000,
                        help="Maximum directories to inspect during auto-discovery (default: 20000)")
    parser.add_argument("--show-paths", action="store_true",
                        help="Show full filesystem paths; omit for a video or public log")
    args = parser.parse_args(argv)
    if args.max_file_mib <= 0 or args.max_depth < 0 or args.max_directories <= 0:
        parser.error("File size and directory budget must be positive; depth must be nonnegative")

    home = Path.home()
    terms = markers(args.ioc)
    discovered: set[Path] = set()
    incomplete_discovery = False
    if args.root:
        roots = [root.expanduser() for root in args.root]
        for root in roots:
            discovered.update(discover_caches(root, args.max_depth))
    else:
        for name in DEFAULT_ROOTS:
            discovered.update(discover_caches(home / name, args.max_depth))
        extra, incomplete_discovery = discover_home_caches(
            home, args.max_depth, args.max_directories
        )
        discovered.update(extra)
    caches = sorted(discovered)

    print("Browser cache IOC audit | read-only | no network access")
    print(f"Cache directories: {len(caches)}")
    if incomplete_discovery:
        print("WARNING: automatic directory discovery incomplete; use --root for missing profiles.")
    if not caches:
        print("No supported cache directories found. Add --root /path/to/browser/profiles.")
        return 2

    files_scanned = files_skipped = errors = hit_files = 0
    limit = args.max_file_mib * 1024 * 1024
    for number, cache in enumerate(caches, 1):
        label = str(cache) if args.show_paths else f"CACHE_{number}"
        print(f"SCAN: {label}")
        for directory, dirs, names in os.walk(cache, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
            for name in names:
                path = Path(directory) / name
                if path.is_symlink():
                    continue
                try:
                    if path.stat().st_size > limit:
                        files_skipped += 1
                        continue
                    results = scan_file(path, terms)
                    files_scanned += 1
                    if results:
                        hit_files += 1
                        path_label = str(path) if args.show_paths else f"{label}/{path.relative_to(cache)}"
                        print(f"HIT: {path_label} | {', '.join(results)}")
                except OSError:
                    errors += 1
    print(f"SUMMARY files={files_scanned} hit_files={hit_files} "
          f"skipped_large={files_skipped} read_errors={errors}")
    print("NOTE: a text hit is not proof of malware execution or exfiltration.")
    print("NOTE: no hits cannot exclude evicted, compressed, or otherwise inaccessible content.")
    if errors or files_skipped or incomplete_discovery:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
