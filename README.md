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

---

## QUYTRÌNH CHẠY TỪ ĐẦU ĐẾN CUỐI (Kali Linux)

### BÀI TOÁN
Crawl DVWA → Lọc URLs → Auto-submit forms → ZAP scan → JSON output

### BƯỚC 0: Chuẩn bị

**Kiểm tra tools có sẵn:**
```bash
go version
httpx --version
katana --version
python3 --version
```

**Cài thiếu gì:**
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
export PATH=$PATH:$HOME/go/bin
```

**Khởi động ZAP (Terminal 1):**
```bash
zaproxy -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true
```

---

### BƯỚC 1: Crawl DVWA với Recon (Terminal 2)

Chạy script `recon.sh` để lấy authenticated URLs từ DVWA:

```bash
chmod +x recon.sh
./recon.sh
```

**Output:**
- `httpx.txt` — Fingerprint công nghệ (Apache, PHP, MySQL, etc.)
- `katana.txt` — Danh sách URLs (121 entries, có trùng)

**Nếu lỗi login:**
```bash
cat index_debug.html
cat login_response.html
```

---

### BƯỚC 2: Lọc URLs tối thiểu (Terminal 2)

Chỉ giữ lại core vulnerability endpoints:

```bash
python3 filter_minimal.py
```

**Output:**
- `katana.minimal.txt` — 16 URLs sạch, chỉ giữ `/vulnerabilities/*` + `/phpinfo.php`

**Những gì bị lọc:**
- ❌ `.js`, `.css` files
- ❌ `logout.php`, `setup.php` (bảo vệ session + database)
- ❌ `/instructions.php`, `/about.php`, `/security.php` (meta pages)
- ❌ `/hackable/*` (directory browsing)
- ❌ Query params sorting (`?C=...`)
- ❌ External URLs

**Kết quả (16 URLs):**
```
/
/phpinfo.php
/login.php
/vulnerabilities/sqli/
/vulnerabilities/sqli_blind/
/vulnerabilities/xss_r/
/vulnerabilities/xss_s/
/vulnerabilities/xss_d/
/vulnerabilities/csrf/
/vulnerabilities/upload/
/vulnerabilities/exec/
/vulnerabilities/fi/?page=include.php
/vulnerabilities/brute/
/vulnerabilities/captcha/
/vulnerabilities/javascript/
/vulnerabilities/weak_id/
/vulnerabilities/csp/
```

---

### BƯỚC 3: Chạy ZAP Pipeline (Terminal 2)

One-file script kết hợp: login → crawl → form-submit → payload-inject → ZAP-scan → JSON:

```bash
python3 zap_pipeline.py -i katana.minimal.txt -o zap_output.json
```

**Script này tự động làm:**
1. ✅ Login DVWA với `admin/password`
2. ✅ Load URLs từ `katana.minimal.txt`
3. ✅ Truy cập từng URL qua ZAP proxy (passive scanning)
4. ✅ Tự tìm form (`<form>` tags) trên mỗi trang
5. ✅ Tự điền form fields với test values:
   - `<input type="text">` → `"test"`
   - `<input type="checkbox">` → check all
   - `<select>` → chọn option đầu
   - `<textarea>` → `"test content"`
6. ✅ Tự submit form (bỏ qua login/logout/setup forms)
7. ✅ Inject SQLi/XSS payloads vào query params:
   - SQLi: `' OR '1'='1`, `admin' --`, `1' UNION SELECT NULL --`, etc.
   - XSS: `<script>alert('xss')</script>`, `<img src=x onerror=alert('xss')>`, etc.
8. ✅ Chạy ZAP active scan
9. ✅ Xuất findings ra `zap_output.json`

**Thời gian chạy:** ~5-15 phút tùy số URLs và active scan timeout

**Tùy chọn:**

Bỏ active scan (chỉ payload injection):
```bash
python3 zap_pipeline.py -i katana.minimal.txt -o zap_output.json --no-active-scan
```

Bỏ payload injection (chỉ passive scan):
```bash
python3 zap_pipeline.py -i katana.minimal.txt -o zap_output.json --no-payload-injection
```

Tắt auto-login (dùng session sẵn có):
```bash
python3 zap_pipeline.py -i katana.minimal.txt -o zap_output.json --no-auth
```

---

### BƯỚC 4: Kiểm tra Kết quả

**File output:**
- `zap_output.json` — JSON chứa tất cả findings

**Lọc HIGH severity issues:**
```bash
cat zap_output.json | jq '.zap_findings[] | select(.severity=="HIGH")'
```

**Xem tất cả findings:**
```bash
cat zap_output.json | jq '.zap_findings[]'
```

**Cấu trúc JSON:**
```json
{
  "target": "http://192.168.144.155:3000",
  "input_count": 16,
  "submitted_count": 12,
  "scan_target_count": 16,
  "zap_findings": [
    {
      "endpoint": "http://...",
      "method": "GET",
      "param": "id",
      "finding_type": "SQL Injection",
      "severity": "HIGH",
      "confidence": "High",
      "payload": "' OR '1'='1",
      "raw_request": "...",
      "raw_response": "...",
      "tool_source": "ZAP"
    }
  ]
}
```

---

## SƠ ĐỒ LUỒNG

```
ZAP Daemon (port 8080)
        ↓
recon.sh → katana.txt (121 URLs)
        ↓
filter_minimal.py → katana.minimal.txt (16 URLs)
        ↓
zap_pipeline.py
  ├─ Login DVWA
  ├─ Access URLs
  ├─ Auto-submit forms
  ├─ Inject payloads
  ├─ Active scan
  └─ → zap_output.json
        ↓
jq → HIGH findings
```

---

## CHEAT SHEET

**Full run:**
```bash
./recon.sh && python3 filter_minimal.py && python3 zap_pipeline.py -i katana.minimal.txt -o zap_output.json
```

**View HIGH issues:**
```bash
cat zap_output.json | jq '.zap_findings[] | select(.severity=="HIGH")'
```

**Pretty print JSON:**
```bash
cat zap_output.json | jq '.'
```

**Export to CSV (manual):**
```bash
cat zap_output.json | jq -r '.zap_findings[] | [.endpoint, .finding_type, .severity, .param] | @csv' > findings.csv
```

---

## GHI CHÚ

✅ **Form skip logic (bảo vệ session):**
- Tự động bỏ qua login forms (`/login.php`)
- Tự động bỏ qua logout forms (`/logout.php`)
- Tự động bỏ qua setup/reset-db forms (`/setup.php`)
- → Session không bị terminate, database không bị reset

✅ **One-file pipeline:**
- Tất cả trong một process → session không bị mất
- Không cần chạy `form_auto_submit.py` + `use-ZAP.py` riêng rẽ

✅ **Data cho AI training:**
- Dùng `zap_output.json` → extract `zap_findings`
- Mỗi finding có: payload, raw_request, raw_response, finding_type, severity
- Tốt cho training security detection models

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
| `recon.sh` | Authenticated crawling | DVWA | `httpx.txt`, `katana.txt` |
| `filter_minimal.py` | Aggressive URL filtering | `katana.txt` | `katana.minimal.txt` (16 URLs) |
| `zap_pipeline.py` | One-file: login → form-submit → ZAP-scan | `katana.minimal.txt` | `zap_output.json` |
| `form_auto_submit.py` | Standalone form auto-submission | `katana.filtered.txt` | `katana_filtered_2.txt` |
| `use-ZAP.py` | Standalone ZAP + payload injection | URLs | `zap_output.json` |

---

## Tips

1. **ZAP Proxy Setup (Kali Linux):**
   ```bash
   zaproxy -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true
   ```

2. **Check for HIGH severity issues:**
   ```bash
   cat zap_output.json | jq '.zap_findings[] | select(.severity=="HIGH")'
   ```

3. **Filter by vulnerability type:**
   ```bash
   cat zap_output.json | jq '.zap_findings[] | select(.finding_type | contains("SQL"))'
   ```

4. **Data for AI Training:**
   - Use `zap_output.json` → extract `zap_findings` array
   - Good for training security detection models
   - Each finding has: payload, raw_request, raw_response, finding_type, severity

5. **Katana options:**
   - `-jc` — Enable JavaScript crawling
   - `-d 3` — Depth crawl = 3
   - `-kf all` — Keep all forms/endpoints
   - `-nc` — No color output

---

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