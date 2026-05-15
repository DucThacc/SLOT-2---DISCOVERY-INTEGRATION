#!/usr/bin/env bash

set -u

TARGET="${1:-}"
COOKIE="${2:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <URL> [COOKIE]"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 is required."
    exit 1
fi

pip3 install python-owasp-zap-v2.4 requests argparse --quiet 2>/dev/null || true

python3 use-zap.py "$TARGET" ${COOKIE:+--cookie "$COOKIE"}
