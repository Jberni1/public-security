#!/usr/bin/env bash
# Read-only browser-cache IOC scan with a private, locally stored report.
# Provenance: adapted from Code Block 149-2.1 (2026-11-18).
# This portable version differs from the original interactive code block;
# keep its own runtime markers and validation history separate.
# Run from any working directory: bash /path/to/run_scan.sh [scanner options]
# No user-specific paths or shell configuration required.

if [ -t 1 ] && [ -n "${TERM:-}" ]; then
    clear || true
fi
echo "=== Browser Cache IOC Scan gestartet ==="

(
    umask 077

    SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
    SCRIPT="$SCRIPT_DIR/browser_cache_ioc_scanner.py"
    LOGDIR="${XDG_STATE_HOME:-$HOME/.local/state}/public-security/browser-cache-ioc-scanner"

    echo "=== 1. VORBEREITUNG ==="

    if [ ! -f "$SCRIPT" ]; then
        echo "FEHLER: Scanner nicht gefunden."
        exit 1
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        echo "FEHLER: Python 3 ist nicht installiert."
        exit 1
    fi

    mkdir -p -- "$LOGDIR" || exit 1
    chmod 700 -- "$LOGDIR" || exit 1

    LOG=$(mktemp "$LOGDIR/scan-$(date +%Y%m%d-%H%M%S)-XXXXXX.log") || exit 1

    echo
    echo "=== 2. AUTOMATISCHER IOC-SCAN ==="

    # Forward optional scanner arguments; no arguments means auto-discovery.
    python3 -B "$SCRIPT" "$@" > "$LOG" 2>&1
    SCAN_RC=$?

    chmod 600 -- "$LOG" || exit 1
    echo "Scanner Exit Code: $SCAN_RC"

    echo
    echo "=== 3. ANONYMISIERTE AUSWERTUNG ==="

    python3 - "$LOG" <<'PY'
from collections import Counter
from pathlib import Path
import sys

try:
    lines = Path(sys.argv[1]).read_text(
        encoding="utf-8", errors="replace"
    ).splitlines()
except OSError as exc:
    print(f"FEHLER: Protokolldatei unlesbar ({type(exc).__name__}).")
    sys.exit(1)

categories = Counter()
hit_files = 0
summary_found = False

for line in lines:
    if line.startswith("Cache directories:"):
        print(line)
    elif line.startswith("WARNING:"):
        print("WARNUNG: Discovery unvollstaendig")
    elif line.startswith("HIT:"):
        hit_files += 1
        if " | " in line:
            labels = line.split(" | ", 1)[1].split(", ")
            for label in labels:
                categories[label.split(":", 1)[0]] += 1
    elif line.startswith("SUMMARY "):
        print(line)
        summary_found = True

print()
print("=== TREFFERKATEGORIEN ===")
print("Dateien mit Treffern:", hit_files)

for category in ("IOC", "BASE64", "CONTEXT", "CUSTOM"):
    print(f"{category}: {categories[category]}")

print()
print("Hinweis: Treffer sind kein Ausfuehrungsnachweis.")

if not summary_found:
    print("WARNUNG: Kein Scan-Summary vorhanden. Privates Log lokal pruefen.")
PY
    REPORT_RC=$?

    echo
    echo "Privates Protokoll gespeichert unter:"
    case "$LOG" in
        "$HOME/"*) printf '~/%s\n' "${LOG#"$HOME/"}" ;;
        *) echo "(benutzerdefiniertes XDG_STATE_HOME)" ;;
    esac

    if [ "$REPORT_RC" -ne 0 ]; then
        exit "$REPORT_RC"
    fi

    exit "$SCAN_RC"
)
RC=$?

echo "=== Browser Cache IOC Scan beendet | Exit Code: $RC ==="
exit "$RC"
