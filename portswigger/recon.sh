#!/usr/bin/env bash

set -u

TARGET="${1:-}"
COOKIE="${2:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <URL> [COOKIE_STRING]"
    echo "Example: $0 https://0a1b...web-security-academy.net \"session=abcdef123456\""
    exit 1
fi

HTTPX_OUT="httpx_ps.txt"
KATANA_OUT="katana_ps.txt"

rm -f "$HTTPX_OUT" "$KATANA_OUT"

echo "[+] Target: $TARGET"
if [ -n "$COOKIE" ]; then
    echo "[+] Using Cookie: $COOKIE"
fi

#################################################
# HTTPX
#################################################
echo "[+] Running httpx..."
if command -v httpx >/dev/null 2>&1; then
    if [ -n "$COOKIE" ]; then
        httpx -u "$TARGET" -H "Cookie: $COOKIE" -title -status-code -tech-detect -server -follow-host-redirects -nc > "$HTTPX_OUT" 2>/dev/null || true
    else
        httpx -u "$TARGET" -title -status-code -tech-detect -server -follow-host-redirects -nc > "$HTTPX_OUT" 2>/dev/null || true
    fi
else
    echo "[!] httpx not found."
    touch "$HTTPX_OUT"
fi

#################################################
# KATANA
#################################################
echo "[+] Running katana..."
if command -v katana >/dev/null 2>&1; then
    if [ -n "$COOKIE" ]; then
        katana -u "$TARGET" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || true
    else
        katana -u "$TARGET" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || true
    fi
else
    echo "[!] katana not found."
    touch "$KATANA_OUT"
fi

echo "[+] Recon done. Saved $HTTPX_OUT and $KATANA_OUT."
