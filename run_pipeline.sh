#!/usr/bin/env bash

set -e

# Default settings
TARGET="http://192.168.144.155:3000"
USER="admin"
PASS="password"

echo "================================================================="
echo "   DVWA AUTOMATED VULNERABILITY SCANNER PIPELINE (KATANA -> ZAP)"
echo "================================================================="
echo "[*] Target: $TARGET"
echo "[*] Credentials: $USER / $PASS"
echo ""

# 1. Recon (Katana)
echo ">>> STEP 1: Running Recon (katana)"
bash recon.sh "$TARGET" "$USER" "$PASS"

if [ ! -f "katana.txt" ]; then
    echo "[!] Error: katana.txt not found. Recon failed."
    exit 1
fi

# Extract PHPSESSID from cookies.txt
PHPSESSID=$(grep PHPSESSID cookies.txt | awk '{print $7}')
if [ -z "$PHPSESSID" ]; then
    echo "[!] Error: Failed to extract PHPSESSID from cookies.txt"
    exit 1
fi
echo "[+] Extracted PHPSESSID: $PHPSESSID"
echo ""

# 2. Filter Minimal
echo ">>> STEP 2: Filtering minimal endpoints (XSS and SQLi only to save RAM/Time)"
python3 filter_minimal.py -i katana.txt -o katana.filtered.txt -b "$TARGET" --only-xss-sql
echo ""

# 3. Auto Fill Form
echo ">>> STEP 3: Auto-filling forms and populating ZAP Proxy"
python3 form_auto_submit.py -i katana.filtered.txt -o katana_filtered_2.txt -b "$TARGET" --auth-user "$USER" --auth-pass "$PASS"
echo ""

# 4. Use ZAP Scanner
echo ">>> STEP 4: Scanning with ZAP Active Scan"
python3 use-ZAP-1778601452537.py -i katana_filtered_2.txt -b "$TARGET" --sid "$PHPSESSID" -o zap_results.json
echo ""

echo "================================================================="
echo "   PIPELINE FINISHED SUCCESSFULLY"
echo "================================================================="
echo "[*] Results saved in:"
echo "    - zap_results.json (All findings)"
echo "    - zap_results_high.json (High severity only)"
echo "================================================================="
