# DVWA Discovery Integration

Luồng hiện tại đã được rút gọn xuống đúng 3 bước:

1. Chạy `recon.sh` để login DVWA, lấy `httpx.txt` và `katana.txt`.
2. Chạy `filter_minimal.py` để lọc `katana.txt` ra `katana.minimal.txt`.
3. Chạy `use-ZAP.py` để scan danh sách đã lọc và xuất `zap_output.json`.

## File còn lại trong repo

- `recon.sh`
- `filter_minimal.py`
- `use-ZAP.py`
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
```

## Output

- `httpx.txt`
- `katana.txt`
- `katana.minimal.txt`
- `zap_output.json`

## Ghi chú

- `filter_minimal.py` là bộ lọc DVWA tối thiểu đã chốt.
- `use-ZAP.py` mặc định đọc `katana.minimal.txt`.
- Nếu muốn quét ít dòng hơn để test, dùng `-n` trong `use-ZAP.py`.

## Cấu trúc hiện tại

```
recon.sh
filter_minimal.py
use-ZAP.py
README.md
requirements.txt
```
