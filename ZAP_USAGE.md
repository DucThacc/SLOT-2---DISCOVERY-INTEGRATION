**ZAP Usage (Kali Linux) — Hướng Dẫn Nhanh**

Mục đích: hướng dẫn cách chạy `filter_katana.py` để tạo `katana.filtered.txt` và cách dùng `use-ZAP.py` với ZAP trên Kali Linux (cả passive + tùy chọn active scan).

Yêu cầu trước khi chạy:
- Kali Linux hoặc máy ảo Kali với quyền root/user có sudo
- ZAP (OWASP ZAP) cài đặt và chạy trên Kali
- Python 3.8+ (sử dụng virtualenv khuyến nghị)

Tệp chính trong workspace:
- [filter_katana.py](filter_katana.py#L1) — lọc `katana.txt` thành `katana.filtered.txt`
- [use-ZAP.py](use-ZAP.py#L1) — script gọi ZAP, thu thập findings/active scan

1) Cài ZAP trên Kali

```bash
sudo apt update
sudo apt install zaproxy -y
```

Khởi ZAP (GUI):

```bash
zaproxy
```

Khởi ZAP headless/daemon (API mở, port 8080):

```bash
zaproxy -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true
```

Ghi chú: `-config api.disablekey=true` tắt yêu cầu API key. Nếu bạn để API key bật, bạn cần chỉnh `use-ZAP.py` để truyền `apikey` tới `ZAPv2`.

2) Thiết lập Python environment và dependencies

```bash
cd /path/to/"SLOT 2 — DISCOVERY INTEGRATION"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) Lọc đầu vào Katana (trên máy đã thu thập katana.txt)

```bash
# Tạo file katana.filtered.txt (mặc định: base URL = http://192.168.144.155:3000)
python3 filter_katana.py -i katana.txt -o katana.filtered.txt -b http://192.168.144.155:3000
```

Tham số hữu ích:
- `-i/--input` : file đầu vào (mặc định `katana.txt`)
- `-o/--output`: file đầu ra (mặc định `katana.filtered.txt`)
- `-b/--base-url`: base URL để ghép path (ví dụ `http://192.168.144.155:3000`)

4) Chạy `use-ZAP.py` (passive scan / thu thập findings)

Ví dụ: quét tất cả targets trong `katana.filtered.txt` (mặc định lấy hết):

```bash
python3 use-ZAP.py
```

Ví dụ: chỉ lấy 2 dòng đầu (nếu muốn chạy nhanh kiểm thử):

```bash
python3 use-ZAP.py -n 2
```

Bật Active Scan (đọc targets, chạy active scan từng target trước khi lấy findings):

```bash
python3 use-ZAP.py --active-scan
```

Ghi chú các tham số chính thêm:
- `-b/--base-url` : ghi đè base URL nếu muốn
- `-p/--proxy` : ZAP proxy (mặc định `http://127.0.0.1:8080`)
- `--active-scan` : bật active scan (chú ý: tốn thời gian và phát nhiều request)

5) Output và kiểm tra

- `use-ZAP.py` in ra JSON chuẩn (theo mẫu `json-format-template.json`) ra stdout. Nếu muốn lưu vào file, chuyển hướng stdout:

```bash
python3 use-ZAP.py --active-scan > zap_output.json
```

6) Lưu ý vận hành và an toàn
- Active scan rất ồn — chỉ chạy trong môi trường kiểm thử (lab) hoặc khi bạn có quyền kiểm thử ứng dụng.
- Nếu ZAP yêu cầu `apikey`, chỉnh `use-ZAP.py` để truyền `ZAPv2(apikey='YOUR_KEY', proxies=...)` hoặc khởi ZAP với config cho phép vô hiệu API key.
- Nếu targets nhiều, cân nhắc giới hạn bằng `-n` hoặc chạy theo batch để tránh quá tải ZAP.

7) Troubleshooting nhanh
- Nếu không kết nối được ZAP: kiểm tra ZAP đang chạy và proxy URL đúng.
- Nếu không thấy findings: chờ lâu hơn sau access/active-scan hoặc kiểm tra policy active scan trong ZAP GUI.

8) Muốn tôi tự động thêm: cấu hình API key support, ghi JSON ra file tự động, hoặc thêm wrapper systemd/service để chạy headless trên Kali.

---
File liên quan: [use-ZAP.py](use-ZAP.py#L1), [filter_katana.py](filter_katana.py#L1), [katana.filtered.txt](katana.filtered.txt)
