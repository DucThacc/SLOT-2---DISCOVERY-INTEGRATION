#!/bin/bash

#################################################
# CONFIG
#################################################

TARGET="http://192.168.144.155:3000"
USER="admin"
PASS="password"

HTTPX_OUT="httpx.txt"
KATANA_OUT="katana.txt"

#################################################
# CLEAN OLD FILES
#################################################

rm -f cookies.txt
rm -f $HTTPX_OUT
rm -f $KATANA_OUT

#################################################
# GET CSRF TOKEN
#################################################

echo "[+] Getting CSRF token..."

TOKEN=$(curl -s -c cookies.txt \
$TARGET/login.php \
| grep user_token \
| sed -n "s/.*value='\([^']*\)'.*/\1/p")

if [ -z "$TOKEN" ]; then
    echo "[-] Failed to get CSRF token"
    exit 1
fi

echo "[+] TOKEN: $TOKEN"

#################################################
# LOGIN
#################################################

echo "[+] Logging in..."

curl -s -L \
-b cookies.txt \
-c cookies.txt \
-d "username=$USER&password=$PASS&user_token=$TOKEN&Login=Login" \
$TARGET/login.php > /dev/null

#################################################
# EXTRACT PHPSESSID
#################################################

PHPSESSID=$(grep PHPSESSID cookies.txt | awk '{print $7}')

if [ -z "$PHPSESSID" ]; then
    echo "[-] Failed to get PHPSESSID"
    exit 1
fi

COOKIE="PHPSESSID=$PHPSESSID; security=low"

echo "[+] PHPSESSID: $PHPSESSID"

#################################################
# VERIFY LOGIN
#################################################

echo "[+] Verifying authenticated session..."

curl -s \
-H "Cookie: $COOKIE" \
$TARGET \
| grep vulnerabilities > /dev/null

if [ $? -ne 0 ]; then
    echo "[-] Login failed"
    exit 1
fi

echo "[+] Authenticated successfully"

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
    katana -u "$TARGET" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || echo "[!] katana execution failed"
else
    # Try common GOPATH locations
    if [ -x "$HOME/go/bin/katana" ]; then
        echo "[*] using $HOME/go/bin/katana"
        "$HOME/go/bin/katana" -u "$TARGET" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || echo "[!] katana execution failed"
    elif [ -n "$GOPATH" ] && [ -x "$GOPATH/bin/katana" ]; then
        echo "[*] using $GOPATH/bin/katana"
        "$GOPATH/bin/katana" -u "$TARGET" -H "Cookie: $COOKIE" -jc -d 3 -kf all -nc > "$KATANA_OUT" 2>/dev/null || echo "[!] katana execution failed"
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