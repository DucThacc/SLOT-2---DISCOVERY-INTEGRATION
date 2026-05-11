# zap/ — Helper files for ZAP usage

This folder contains convenience files for running the ZAP-based collection and scans on a Kali Linux VM.

Quick steps (on Kali VM):

1. Copy the repository to Kali and cd into the `zap/` folder (or run from the root workspace path)

2. Create and activate a Python virtualenv and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Ensure OWASP ZAP is running (headless or GUI). Example headless:

```bash
zaproxy -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true
```

4. Run the filter tool (from root or this folder):

```bash
python3 ../filter_katana.py -i ../katana.txt -o ../katana.filtered.txt -b http://192.168.144.155:3000
```

5. Run the ZAP collector (example: all targets, enable active scan):

```bash
python3 ../use-ZAP.py -i ../katana.filtered.txt -b http://192.168.144.155:3000 --active-scan -p http://127.0.0.1:8080
```

Or run the local copies inside this folder:

```bash
python3 use-ZAP.py --active-scan
```

Notes:
- Active scan is noisy and slow — only use in lab.
- If ZAP requires an API key, either disable API key in ZAP or modify `use-ZAP.py` to pass the key to `ZAPv2`.
