#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r zap/requirements.txt

echo "Running filter then use-ZAP (active scan)"
python3 filter_katana.py -i katana.txt -o katana.filtered.txt -b http://192.168.144.155:3000
python3 use-ZAP.py -i katana.filtered.txt -b http://192.168.144.155:3000 --active-scan -p http://127.0.0.1:8080
