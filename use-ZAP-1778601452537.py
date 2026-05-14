import argparse
import json
import time
import os
import requests
import urllib3
from pathlib import Path
from zapv2 import ZAPv2
from datetime import datetime, timedelta

# ==========================================
# 1. TRIỆT TIÊU PROXY LOOP (KALI ENVIRONMENT)
# ==========================================
os.environ['no_proxy'] = '127.0.0.1,localhost,zap'
for key in list(os.environ.keys()):
    if 'proxy' in key.lower():
        os.environ.pop(key)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FastZapScanner:
    def __init__(self, port="8080", api_key="", sid=None, fast_mode=False):
        self.proxy_url = f"http://127.0.0.1:{port}"
        self.sid = sid
        self.fast_mode = fast_mode
        # Khởi tạo ZAP không qua proxy để tránh lỗi RemoteDisconnected
        self.zap = ZAPv2(apikey=api_key)
        
        # Rule IDs tốn thời gian: SQLi Timing, DOM XSS, v.v.
        self.slow_rules = "40018,40019,40020,40021,40022,40024,40026"

        if self.sid: self._setup_auth()
        if self.fast_mode: self._optimize_policy()

    def _log(self, msg):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def _setup_auth(self):
        try:
            try: self.zap.replacer.remove_rule("auth-sid")
            except: pass
            self.zap.replacer.add_rule(
                description="auth-sid", enabled="true", matchtype="REQ_HEADER",
                matchregex="false", matchstring="Cookie",
                replacement=f"PHPSESSID={self.sid}", initiators=""
            )
            self._log(f"[+] Đã nạp xác thực SID: {self.sid}")
        except Exception as e:
            self._log(f"[!] Lỗi Replacer: {e}")

    def _optimize_policy(self):
        self._log("[*] FAST MODE: Đang vô hiệu hóa các rule tốn thời gian...")
        try:
            self.zap.ascan.disable_scanners(ids=self.slow_rules)
            # Thử các method tùy theo phiên bản thư viện
            for m in ["set_option_attack_strength", "set_option_default_attack_strength"]:
                if hasattr(self.zap.ascan, m):
                    try: getattr(self.zap.ascan, m)("LOW"); break
                    except: pass
            self.zap.ascan.set_option_max_rule_duration_in_mins(2)
            self._log("[+] Đã tối ưu Policy (Attack Strength: LOW).")
        except Exception as e:
            self._log(f"[!] Lỗi tối ưu Policy: {e}")

    def get_findings(self, url, base_url):
        """Trích xuất Alert và mapping sang format yêu cầu"""
        results = []
        try:
            raw_alerts = self.zap.core.alerts(baseurl=url)
            for alert in raw_alerts:
                msg_id = alert.get('messageId')
                raw_req, raw_res = "", ""
                if msg_id:
                    try:
                        msg = self.zap.core.message(msg_id)
                        raw_req = msg.get('requestHeader', '') + msg.get('requestBody', '')
                        raw_res = msg.get('responseHeader', '') + msg.get('responseBody', '')
                    except: pass

                # Format đúng cấu hình user yêu cầu
                results.append({
                    "endpoint": alert.get('url', '').replace(base_url, ""),
                    "method": alert.get('method', 'GET'),
                    "inputVector": alert.get('inputVector', ''),
                    "param": alert.get('param', ''),
                    "finding_type": alert.get('name', ''),
                    "severity": alert.get('risk', ''),
                    "confidence": alert.get('confidence', ''),
                    "evidence": alert.get('evidence', ''),
                    "payload": alert.get('attack', ''),
                    "raw_request": raw_req,
                    "raw_response": raw_res
                })
        except Exception as e:
            self._log(f"[!] Lỗi trích xuất alert cho {url}: {e}")
        return results

    def run_scan(self, target, base_url):
        url = target["url"]
        method = target["method"]
        data = target["data"]
        
        self._log(f"[*] Đang xử lý: {method} {url}")
        
        # Populate ZAP tree if it's not already there
        with requests.Session() as s:
            s.trust_env = False
            s.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            try: 
                if method == "POST":
                    # Convert string data to dict for requests
                    data_dict = dict(urllib.parse.parse_qsl(data))
                    s.post(url, data=data_dict, verify=False, timeout=10)
                else:
                    s.get(url, verify=False, timeout=10)
            except: pass

        try:
            # recurse=False: Ép ZAP chỉ quét duy nhất endpoint này
            if method == "POST":
                scan_id = self.zap.ascan.scan(url=url, recurse=False, method="POST", postdata=data)
            else:
                scan_id = self.zap.ascan.scan(url=url, recurse=False)
                
            if not str(scan_id).isdigit():
                self._log(f"    [!] ZAP Reject: {scan_id}")
                return []

            while int(self.zap.ascan.status(scan_id)) < 100:
                print(f"    [SCAN] {self.zap.ascan.status(scan_id)}% hoàn thành...", end="\r")
                time.sleep(5)
            
            self._log(f"\n    [+] Hoàn tất Scan: {url}")
            return self.get_findings(url, base_url)
        except Exception as e:
            self._log(f"\n    [!] Lỗi trong quá trình Scan {url}: {e}")
            return []

# ==========================================
# 3. MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZAP Authenticated Targeted Scanner")
    parser.add_argument("-i", "--input-file", required=True)
    parser.add_argument("-b", "--base-url", required=True)
    parser.add_argument("--sid", required=True)
    parser.add_argument("--fast-scan", action="store_true")
    parser.add_argument("-a", "--api-key", default="ksggc5u2lduvgiha5t9ues878a")
    parser.add_argument("-o", "--output", default="zap_results.json")
    args = parser.parse_args()

    # Bắt đầu tính thời gian toàn bộ quá trình
    total_start_time = time.time()
    
    base = args.base_url.rstrip("/") + "/"
    path = Path(args.input_file)
    if not path.exists():
        print(f"[!] File không tìm thấy: {args.input_file}"); exit()

    import urllib.parse
    targets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line: continue
        
        if line.startswith("POST "):
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                rel_path = parts[1]
                data = parts[2] if len(parts) > 2 else ""
                url = rel_path if rel_path.startswith("http") else f"{base.rstrip('/')}/{rel_path.lstrip('/')}"
                targets.append({"url": url, "method": "POST", "data": data})
        else:
            url = line if line.startswith("http") else f"{base.rstrip('/')}/{line.lstrip('/')}"
            targets.append({"url": url, "method": "GET", "data": ""})

    print(f"\n{'='*50}\n[*] BẮT ĐẦU QUY TRÌNH QUÉT ({len(targets)} TARGETS)\n{'='*50}")

    scanner = FastZapScanner(sid=args.sid, api_key=args.api_key, fast_mode=args.fast_scan)
    
    all_results = []
    for t in targets:
        findings = scanner.run_scan(t, base)
        all_results.extend(findings)

    # Lọc riêng các findings có severity là HIGH
    high_severity_results = [r for r in all_results if r.get("severity", "").upper() == "HIGH"]

    # Đóng gói dữ liệu đúng Format yêu cầu
    final_data = {
        "base": args.base_url,
        "total_findings": len(all_results),
        "high_severity_findings": len(high_severity_results),
        "results": all_results
    }
    
    high_severity_data = {
        "base": args.base_url,
        "total_high": len(high_severity_results),
        "results": high_severity_results
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=4, ensure_ascii=False)
        
    # Tạo file riêng cho HIGH severity
    high_output_file = args.output.replace('.json', '_high.json')
    if '_high' not in high_output_file:
        high_output_file = 'high_severity.json'
        
    with open(high_output_file, "w", encoding="utf-8") as f:
        json.dump(high_severity_data, f, indent=4, ensure_ascii=False)
    
    # Kết thúc tính thời gian
    total_end_time = time.time()
    duration = str(timedelta(seconds=round(total_end_time - total_start_time)))

    print(f"\n{'='*50}")
    print(f"[+] HOÀN TẤT: Đã ghi {len(all_results)} findings vào {args.output}")
    print(f"[+] Đã ghi {len(high_severity_results)} HIGH severity findings vào {high_output_file}")
    print(f"[+] TỔNG THỜI GIAN THỰC THI: {duration}")
    print(f"{'='*50}\n")
    
    # In ra terminal các HIGH severity findings để dễ xem
    if high_severity_results:
        print("\n[!] PHÁT HIỆN LỖI NGHIÊM TRỌNG (HIGH SEVERITY):")
        for finding in high_severity_results:
            print(f"  - {finding['finding_type']} tại {finding['method']} {finding['endpoint']}")
            print(f"    Param: {finding['param']} | Evidence: {finding['evidence']}")
        print("\n")
