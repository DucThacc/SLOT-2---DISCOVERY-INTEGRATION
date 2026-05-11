Mục tiêu

Lab này sẽ:

Cài Docker trên Ubuntu Server 22.04
Deploy DVWA
Chạy DVWA tại:
http://IP:3000
Cài:
Katana
httpx
Go
Tự động:
login DVWA
lấy CSRF token
lấy PHPSESSID
authenticated fingerprint
authenticated crawling
Save kết quả:
httpx.txt
katana.txt
1. Update Ubuntu
sudo apt update && sudo apt upgrade -y
2. Cài Go
Xóa Go cũ (nếu có)
sudo rm -rf /usr/local/go
Download Go mới
wget https://go.dev/dl/go1.24.3.linux-amd64.tar.gz
Giải nén
sudo tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz
Add PATH
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
Reload shell
source ~/.bashrc
Kiểm tra
go version

Ví dụ:

go version go1.24.3 linux/amd64
3. Cài Docker
sudo apt install docker.io -y
Enable auto start
sudo systemctl enable docker
sudo systemctl start docker
Kiểm tra
docker --version
4. Deploy DVWA
Pull image
sudo docker pull vulnerables/web-dvwa
Run container
sudo docker run -d \
--name dvwa \
-p 3000:80 \
--restart unless-stopped \
vulnerables/web-dvwa
Kiểm tra
sudo docker ps
Truy cập
http://IP_SERVER:3000

Ví dụ:

http://192.168.144.155:3000
5. Login DVWA

Default account:

Username: admin
Password: password
6. Cài Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest
Kiểm tra
katana -version
7. Cài httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
Kiểm tra
httpx -version
8. Tạo Script Recon

Tạo file:

nano ~/recon.sh
9. Nội dung recon.sh
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
10. Cho phép execute
chmod +x ~/recon.sh
11. Chạy Recon
./recon.sh
12. Output
httpx.txt

Fingerprint công nghệ web:

Ví dụ:

Apache
PHP
MySQL
Status Code
Title
katana.txt

Danh sách URLs crawl được:

Ví dụ:

/vulnerabilities/sqli/
/vulnerabilities/xss_r/
/vulnerabilities/upload/
/vulnerabilities/exec/
Giải thích các thành phần
CSRF Token

DVWA yêu cầu:

user_token

để login.

Script:

GET login page
extract token
dùng token khi POST login
PHPSESSID

Sau login:

PHPSESSID

được server tạo.

Session này đại diện cho:

user đã authenticated
security=low

DVWA có nhiều mức:

low
medium
high
impossible

Script dùng:

security=low

để dễ recon và testing.

httpx

httpx dùng để:

fingerprint web server
detect technology
lấy status code
detect redirects

Ví dụ detect:

Apache
PHP
MySQL
Katana

Katana là web crawler dùng để:

crawl URLs
enumerate attack surface
discover endpoints
crawl authenticated pages
-H "Cookie: ..."

Inject authenticated session vào requests.

Nếu không có cookie:

Katana chỉ thấy login page
-jc

Enable JavaScript crawling.

-d 3

Depth crawl = 3.

-kf all

Keep all forms/endpoints.

-nc

No color.

Fix lỗi:

^[[33m

trong file txt.