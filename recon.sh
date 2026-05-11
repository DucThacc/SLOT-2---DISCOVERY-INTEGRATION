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

httpx \
-u $TARGET \
-H "Cookie: $COOKIE" \
-title \
-status-code \
-tech-detect \
-server \
-follow-host-redirects \
-nc \
> $HTTPX_OUT

#################################################
# KATANA
#################################################

echo "[+] Running katana..."

katana \
-u $TARGET \
-H "Cookie: $COOKIE" \
-jc \
-d 3 \
-kf all \
-nc \
> $KATANA_OUT

#################################################
# DONE
#################################################

echo ""
echo "[+] DONE"
echo "[+] Saved: $HTTPX_OUT"
echo "[+] Saved: $KATANA_OUT"