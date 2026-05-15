#!/usr/bin/env bash

set -u

#################################################
# CONFIG
#################################################

TARGET="${1:-${TARGET:-http://10.141.82.59:3001/WebGoat}}"
USER="${2:-recon-$(date +%s)}"
PASS="${3:-${PASS:-password}}"

HTTPX_OUT="${HTTPX_OUT:-httpx_wg.txt}"
KATANA_OUT="${KATANA_OUT:-katana_wg.txt}"

#################################################
# CLEAN OLD FILES
#################################################

rm -f cookies_wg.txt
rm -f "$HTTPX_OUT"
rm -f "$KATANA_OUT"

#################################################
# REGISTER
#################################################

echo "[+] Registering user $USER..."

REG_RESP=$(curl -s -i -X POST "$TARGET/register.mvc" \
    -d "username=$USER&password=$PASS&matchingPassword=$PASS&agree=agree" \
    -c cookies_wg.txt)

if echo "$REG_RESP" | grep -qi "User already exists"; then
    echo "[!] User already exists, attempting to login..."
else
    if echo "$REG_RESP" | grep -Eq "^HTTP/.* 302"; then
        echo "[+] Registration successful!"
    else
        echo "[-] Registration failed for an unknown reason"
        echo "$REG_RESP"
        exit 1
    fi
fi

#################################################
# LOGIN
#################################################

echo "[+] Logging in..."

LOGIN_RESP=$(curl -s -i -X POST "$TARGET/login" \
    -d "username=$USER&password=$PASS" \
    -c cookies_wg.txt)

if echo "$LOGIN_RESP" | grep -Eq "^HTTP/.* 302"; then
    echo "[+] Login successful!"
else
    echo "[-] Login failed"
    echo "$LOGIN_RESP"
    exit 1
fi

#################################################
# EXTRACT JSESSIONID
#################################################

JSESSIONID=$(awk '/JSESSIONID/ {print $7}' cookies_wg.txt)

if [ -z "$JSESSIONID" ]; then
    echo "[-] Failed to get JSESSIONID from cookies_wg.txt"
    exit 1
fi

COOKIE="JSESSIONID=$JSESSIONID"

echo "[+] JSESSIONID: $JSESSIONID"

#################################################
# HTTPX
#################################################

echo "[+] Running httpx..."
# Try multiple httpx invocation styles for compatibility across distributions
if command -v httpx >/dev/null 2>&1; then
    echo "[*] httpx found: $(httpx --version 2>/dev/null || true)"

    # Try -u style first, fall back to positional URL style
    if httpx -u "$TARGET" -H "Cookie: $COOKIE" -title -status-code -tech-detect -server -follow-host-redirects -nc > "$HTTPX_OUT" 2>/dev/null; then
        :
    elif httpx "$TARGET" -H "Cookie: $COOKIE" -title -status-code -tech-detect -server -follow-host-redirects -nc > "$HTTPX_OUT" 2>/dev/null; then
        :
    else
        # Last-resort: basic httpx invocation
        httpx -title -status-code -H "Cookie: $COOKIE" "$TARGET" > "$HTTPX_OUT" 2>/dev/null || echo "[!] httpx failed to produce output"
    fi
elif [ -x "$HOME/go/bin/httpx" ]; then
    echo "[*] using $HOME/go/bin/httpx"
    "$HOME/go/bin/httpx" -u "$TARGET" -H "Cookie: $COOKIE" -title -status-code -tech-detect -server -follow-host-redirects -nc > "$HTTPX_OUT" 2>/dev/null || echo "[!] httpx failed to produce output"
elif [ -n "${GOPATH:-}" ] && [ -x "$GOPATH/bin/httpx" ]; then
    echo "[*] using $GOPATH/bin/httpx"
    "$GOPATH/bin/httpx" -u "$TARGET" -H "Cookie: $COOKIE" -title -status-code -tech-detect -server -follow-host-redirects -nc > "$HTTPX_OUT" 2>/dev/null || echo "[!] httpx failed to produce output"
else
    echo "[!] httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    touch "$HTTPX_OUT"
fi

#################################################
# KATANA
#################################################

echo "[+] Running katana..."
if command -v katana >/dev/null 2>&1; then
    echo "[*] katana found: $(katana --version 2>/dev/null || true)"
    katana -u "$TARGET/start.mvc?username=$USER" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || echo "[!] katana execution failed"
else
    # Try common GOPATH locations
    if [ -x "$HOME/go/bin/katana" ]; then
        echo "[*] using $HOME/go/bin/katana"
        "$HOME/go/bin/katana" -u "$TARGET/start.mvc?username=$USER" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || echo "[!] katana execution failed"
    elif [ -n "${GOPATH:-}" ] && [ -x "$GOPATH/bin/katana" ]; then
        echo "[*] using $GOPATH/bin/katana"
        "$GOPATH/bin/katana" -u "$TARGET/start.mvc?username=$USER" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || echo "[!] katana execution failed"
    else
        echo "[!] katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        touch "$KATANA_OUT"
    fi
fi

#################################################
# DONE
#################################################

echo ""
echo "[+] DONE"
echo "[+] Saved: $HTTPX_OUT"
echo "[+] Saved: $KATANA_OUT"
