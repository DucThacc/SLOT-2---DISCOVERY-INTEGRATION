# DVWA Discovery Integration

Luồng hiện tại đã được rút gọn xuống đúng 4 bước:

1. Chạy `recon.sh` để login DVWA, lấy `httpx.txt` và `katana.txt`.
2. Chạy `filter_minimal.py` để lọc `katana.txt` ra `katana.minimal.txt`.
3. Chạy `use-ZAP.py` để scan danh sách đã lọc và xuất `zap_output.json`.
4. Chạy `idor_exploit.py` để xác minh IDOR theo session và xuất `idor_output.json`.

## File còn lại trong repo

- `recon.sh`
- `filter_minimal.py`
- `use-ZAP.py`
- `idor_exploit.py`
- `windows/`
- `README.md`
- `requirements.txt`

## Cài đặt

```bash
pip install -r requirements.txt
```

## Chạy end-to-end

```bash
chmod +x recon.sh
./recon.sh
python3 filter_minimal.py
python3 use-ZAP.py -i katana.minimal.txt -o zap_output.json
python3 idor_exploit.py -u katana.minimal.txt -o idor_output.json
```

## Output

- `httpx.txt`
- `katana.txt`
- `katana.minimal.txt`
- `zap_output.json`
- `idor_output.json`

## Ghi chú

- `filter_minimal.py` là bộ lọc DVWA tối thiểu đã chốt.
- `use-ZAP.py` mặc định đọc `katana.minimal.txt`.
- Nếu muốn quét ít dòng hơn để test, dùng `-n` trong `use-ZAP.py`.
- `idor_exploit.py` hỗ trợ `--session-cookie alias=COOKIE_STRING` để xác minh cross-session ownership.

## Định dạng session cho IDOR

Ví dụ:

```bash
python3 idor_exploit.py -u katana.minimal.txt -o idor_output.json \
	--session-cookie userA="PHPSESSID=...; security=low" \
	--session-cookie userB="PHPSESSID=...; security=low"
```

Nếu không truyền session, script vẫn chạy được nhưng chỉ sinh `candidate`, không thể confirm IDOR cross-session.

## Cấu trúc hiện tại

```
recon.sh
filter_minimal.py
use-ZAP.py
idor_exploit.py
windows/
README.md
requirements.txt
```

## Chạy trên Windows

Trong thư mục `windows/`, mỗi bước đều có launcher riêng:

- `windows/run_recon.ps1` / `windows/run_recon.cmd`
- `windows/run_filter.ps1` / `windows/run_filter.cmd`
- `windows/run_zap.ps1` / `windows/run_zap.cmd`
- `windows/run_idor.ps1` / `windows/run_idor.cmd`
- `windows/run_all.ps1` / `windows/run_all.cmd`

Chạy toàn bộ flow một lần:

```powershell
.\windows\run_all.ps1 -Target http://192.168.144.155:3000 -Proxy http://127.0.0.1:8080
```

Ví dụ:

```powershell
.\windows\run_idor.ps1 -Urls katana.minimal.txt -Output idor_output.json -SessionCookie 'userA=PHPSESSID=...; security=low' -SessionCookie 'userB=PHPSESSID=...; security=low'
```

Nếu muốn chạy kiểu double-click hoặc từ Command Prompt, dùng:

```cmd
windows\run_idor.cmd -Urls katana.minimal.txt -Output idor_output.json
```
