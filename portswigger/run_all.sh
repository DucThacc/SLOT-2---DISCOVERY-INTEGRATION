#!/usr/bin/env bash

set -u

TARGET="${1:-}"
COOKIE="${2:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <URL> [COOKIE]"
    echo "Example: $0 https://0a1b...web-security-academy.net \"session=abcdef123456\""
    exit 1
fi

echo "=========================================="
echo "    PortSwigger Pipeline Starting"
echo "=========================================="
echo "[+] Target: $TARGET"
echo "[+] Cookie: $COOKIE"

echo ""
echo "[1/3] Running Recon..."
bash recon.sh "$TARGET" "$COOKIE"

echo ""
echo "[2/3] Running Filter..."
python3 filter.py

echo ""
echo "[3/3] Running ZAP Scan..."
bash use-zap.sh "$TARGET" "$COOKIE"

echo ""
echo "=========================================="
echo "    Pipeline Completed Successfully"
echo "=========================================="
