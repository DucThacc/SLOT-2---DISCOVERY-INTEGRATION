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

---

## PHẦN 2: Data Processing Pipeline (Windows/Kali)

Sau khi có `httpx.txt` và `katana.txt` từ recon, tiến hành xử lý dữ liệu trước khi đưa qua ZAP:

### BƯỚC 1: Lọc & Deduplicate URLs

**File:** `filter_katana.py`

**Mục đích:**
- Đọc `katana.txt` (raw output từ Katana)
- Extract URLs regex
- Filter chỉ lấy single-origin (http://192.168.144.155:3000)
- Loại bỏ `.css` files
- Deduplicate
- Output: `katana.filtered.txt` (50 entries unique)

**Chạy:**
```bash
python3 filter_katana.py -i katana.txt -o katana.filtered.txt -b http://192.168.144.155:3000
```

**Output ví dụ:**
```
/
/vulnerabilities/sqli/
/vulnerabilities/xss_s/
/vulnerabilities/upload/
/hackable/users/
```

---

### BƯỚC 2: Auto-Find & Auto-Submit Forms

**File:** `form_auto_submit.py` (NEW)

**Mục đích:**
- Đọc `katana.filtered.txt` (URLs từ bước 1)
- Truy cập từng URL qua ZAP proxy
- Parse HTML tìm tất cả `<form>` tags
- Tự động **điền form fields** với test values:
  - `<input type="text">` → `"test"`
  - `<input type="hidden">` → giữ value gốc
  - `<input type="checkbox">` → check tất cả
  - `<select>` → chọn option đầu tiên
  - `<textarea>` → điền `"test content"`
- Tự động **submit forms** qua proxy
- **Capture request URL** (GET) hoặc POST body
- Output: `katana_filtered_2.txt` (các submitted form requests)

**Cài package:**
```bash
pip install beautifulsoup4
```

**Chạy:**
```bash
# Basic (mặc định output katana_filtered_2.txt)
python3 form_auto_submit.py

# Custom input/output
python3 form_auto_submit.py -i katana.filtered.txt -o katana_filtered_2.txt

# Custom proxy (nếu ZAP chạy ở port khác)
python3 form_auto_submit.py -p http://127.0.0.1:8080
```

**Output ví dụ (`katana_filtered_2.txt`):**
```
/vulnerabilities/sqli/?id=test&Submit=Submit
/vulnerabilities/xss_s/?name=test&Submit=Submit
POST /vulnerabilities/upload/ file=test.txt&Upload=Upload
/vulnerabilities/exec/?ip=test&Submit=Submit
```

---

### BƯỚC 3: ZAP Security Scanning với Auto Payload Injection

**File:** `use-ZAP.py`

**Mục đích:**
- Đọc URLs từ `katana_filtered_2.txt` (forms đã submitted)
- **STEP 1:** Truy cập từng URL qua ZAP proxy (passive scanning)
- **STEP 1.5 (NEW):** Tự động inject SQL Injection + XSS payloads vào query parameters:
  - SQL Payloads: `' OR '1'='1`, `admin' --`, `1' UNION SELECT NULL --`, etc.
  - XSS Payloads: `<script>alert('xss')</script>`, `<img src=x onerror=alert('xss')>`, etc.
- **STEP 2:** Chạy active scan của ZAP
- **STEP 3:** Collect findings → normalize → output JSON
- Auto-write findings vào `zap_output.json`

**Chạy:**
```bash
# Quét tất cả URLs với payload injection + active scan
python3 use-ZAP.py -i katana_filtered_2.txt

# Quét chỉ 5 URLs đầu (test)
python3 use-ZAP.py -i katana_filtered_2.txt -n 5

# Bỏ active scan, chỉ payload injection
python3 use-ZAP.py -i katana_filtered_2.txt --no-active-scan

# Custom output
python3 use-ZAP.py -i katana_filtered_2.txt -o my_findings.json
```

**Output (`zap_output.json`):**
```json
{
  "target": "http://192.168.144.155:3000",
  "zap_findings_count": 15,
  "zap_findings": [
    {
      "endpoint": "http://192.168.144.155:3000/vulnerabilities/sqli/?id=' OR '1'='1",
      "method": "GET",
      "param": "id",
      "finding_type": "SQL Injection",
      "severity": "HIGH",
      "confidence": "High",
      "payload": "' OR '1'='1",
      "raw_request": "GET /vulnerabilities/sqli/?id=....",
      "raw_response": "HTTP/1.1 200 OK...",
      "tool_source": "ZAP"
    }
  ],
  "active_scan_enabled": true
}
```

---

## Full Pipeline (Recommended)

### Quick Test (4 URLs)
```bash
python3 useZAP2.py
# Output: zap_output_test.json (2 first + 2 last URLs only)
```

### Full Pipeline
```bash
# 1. Filter URLs
python3 filter_katana.py

# 2. Auto-submit forms
python3 form_auto_submit.py

# 3. ZAP scan with payloads
python3 use-ZAP.py -i katana_filtered_2.txt

# 4. Check output
cat zap_output.json | jq '.zap_findings | .[] | select(.severity=="HIGH")'
```

---

## Requirements

**Python packages:**
```
requests>=2.28.0
pydantic>=1.10
python-owasp-zap-v2.4>=0.0.13
urllib3>=1.26.0
beautifulsoup4>=4.11.0
```

**Install:**
```bash
pip install -r requirements.txt
```

---

## Files Overview

| File | Purpose | Input | Output |
|------|---------|-------|--------|
| `filter_katana.py` | URL filtering & deduplication | `katana.txt` | `katana.filtered.txt` |
| `form_auto_submit.py` | Auto-find & submit forms | `katana.filtered.txt` | `katana_filtered_2.txt` |
| `use-ZAP.py` | ZAP scanning + payload injection | `katana_filtered_2.txt` | `zap_output.json` |
| `useZAP2.py` | Quick test (4 URLs) | `katana.filtered.txt` | `zap_output_test.json` |

---

## Tips

1. **ZAP Proxy Setup (Kali Linux):**
   ```bash
   zaproxy -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true
   ```

2. **Check for HIGH severity issues:**
   ```bash
   cat zap_output.json | jq '.zap_findings | .[] | select(.severity=="HIGH")'
   ```

3. **Filter by vulnerability type:**
   ```bash
   cat zap_output.json | jq '.zap_findings | .[] | select(.finding_type | contains("SQL"))'
   ```

4. **Data for AI Training:**
   - Use `zap_output.json` → extract `zap_findings` array
   - Good for training security detection models
   - Each finding has: payload, raw_request, raw_response, finding_type, severity

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