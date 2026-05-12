import argparse
import json
import time
import urllib.parse
from pathlib import Path
from typing import List

import requests
import urllib3
from bs4 import BeautifulSoup
from pydantic import BaseModel
from zapv2 import ZAPv2


BASE_URL = "http://192.168.144.155:3000"
DEFAULT_INPUT_FILE = "katana.filtered.txt"
DEFAULT_OUTPUT_FILE = "zap_output.json"

# ==========================================
# Disable SSL warnings
# ==========================================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. NORMALIZED SCHEMA
# ==========================================


class NormalizedFinding(BaseModel):

    endpoint: str
    method: str

    param: str = ""

    finding_type: str
    severity: str

    confidence: str = ""

    payload: str = ""

    raw_request: str = ""
    raw_response: str = ""

    tool_source: str = "ZAP"


# ==========================================
# 2. CORE COLLECTOR
# ==========================================


class ZapCollector:

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1",
        "admin' --",
        "' OR 1=1 --",
        "1' UNION SELECT NULL --",
    ]

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "'\"><script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
    ]

    def __init__(self, proxy_url="http://127.0.0.1:8080", base_url: str = BASE_URL, auth_user: str = "admin", auth_pass: str = "password", no_auth: bool = False):

        print(f"[*] Đang kết nối tới ZAP Proxy tại {proxy_url}...")

        self.proxy_url = proxy_url
        self.base_url = base_url.rstrip("/")
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.no_auth = no_auth

        self.session = requests.Session()
        self.session.proxies.update({"http": proxy_url, "https": proxy_url})
        self.session.verify = False

        self.zap = ZAPv2(proxies={"http": proxy_url, "https": proxy_url})
        self._message_cache = {}

    def is_login_page(self, html: str, page_url: str = "") -> bool:

        low = html.lower()
        if "<title>login ::" in low:
            return True
        if "name=\"username\"" in low and "name=\"password\"" in low and "login.php" in low:
            return True
        if page_url and "login.php" in page_url.lower():
            return True
        return False

    def perform_login(self, username: str, password: str) -> bool:

        login_url = urllib.parse.urljoin(self.base_url + "/", "login.php")
        print(f"[*] Auto-login to {login_url} as {username}")

        self.session.cookies.set("security", "low")

        resp = self.session.get(login_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", attrs={"name": "user_token"})
        token = token_input.get("value") if token_input else ""

        data = {"username": username, "password": password, "Login": "Login"}
        if token:
            data["user_token"] = token

        post_resp = self.session.post(login_url, data=data, timeout=10, allow_redirects=True)
        print(f"[DEBUG] Login POST response status: {post_resp.status_code}")

        check_url = urllib.parse.urljoin(self.base_url + "/", "index.php")
        check_resp = self.session.get(check_url, timeout=10)
        if "logout" in check_resp.text.lower() and not self.is_login_page(check_resp.text, str(check_resp.url)):
            print("[*] Auto-login successful ✓")
            return True

        print("[!] Auto-login may have failed ⚠")
        print(f"[DEBUG] Auth check URL: {check_resp.url}")
        print(f"[DEBUG] Home page snippet (first 300 chars):\n{check_resp.text[:300]}")
        return False

    def ensure_authenticated(self):

        if self.no_auth:
            return

        self.perform_login(self.auth_user, self.auth_pass)

    # ======================================
    # ACCESS SINGLE PAGE
    # ======================================

    def access_single_page(self, target_url: str):

        print(f"\n[*] Đang gửi request duy nhất tới: {target_url}")

        try:

            response = self.session.get(target_url, timeout=10)

            if not self.no_auth and self.is_login_page(response.text, str(response.url)):
                print("[!] Target trả về login page, thử login lại rồi request lại...")
                if self.perform_login(self.auth_user, self.auth_pass):
                    self.session.get(target_url, timeout=10)

            print("[*] Truy cập thành công! ZAP đang xử lý nền...")

            time.sleep(1)

        except Exception as e:

            print(f"[!] Không thể truy cập {target_url}: {e}")

    def send_payloads_to_targets(self, target_urls: List[str]):

        print("\n[*] Gửi payload để phát hiện High Severity issues...")

        for target_url in target_urls:

            parsed = urllib.parse.urlparse(target_url)
            params = urllib.parse.parse_qs(parsed.query)

            if not params:
                continue

            for param_name in params.keys():

                for payload in self.SQLI_PAYLOADS + self.XSS_PAYLOADS:

                    modified_params = params.copy()
                    modified_params[param_name] = [payload]

                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    payload_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    try:
                        self.session.get(payload_url, timeout=10)
                    except Exception:
                        pass

        print("[*] Payload injection hoàn tất")

    def access_pages(self, target_urls: List[str]):

        for index, target_url in enumerate(target_urls, start=1):

            print(f"\n[*] [{index}/{len(target_urls)}] Đang xử lý: {target_url}")

            self.access_single_page(target_url)

    def _get_messages_for_target(self, target_url: str):

        if target_url not in self._message_cache:

            self._message_cache[target_url] = self.zap.core.messages(baseurl=target_url)

        return self._message_cache[target_url]

    def _find_message_for_alert(self, alert: dict, target_url: str):

        message_id = (
            alert.get("messageId")
            or alert.get("messageid")
            or alert.get("message_id")
        )

        if message_id:

            try:

                return self.zap.core.message(message_id)

            except Exception:

                pass

        alert_url = alert.get("url", "")
        alert_method = alert.get("method", "GET").upper()
        alert_path = urllib.parse.urlsplit(alert_url).path

        for msg in self._get_messages_for_target(target_url):

            request_header = msg.get("requestHeader", "")
            if not request_header:
                continue

            request_line = request_header.split("\r\n", 1)[0]
            parts = request_line.split(" ")
            if len(parts) < 2:
                continue

            request_method = parts[0].upper()
            request_url = parts[1]

            parsed_request_url = urllib.parse.urlsplit(request_url)
            request_path = parsed_request_url.path

            if request_method == alert_method and request_path == alert_path:
                return msg

        return None

    def _format_raw_request(self, message: dict) -> str:

        return message.get("requestHeader", "") if message else ""

    def _format_raw_response(self, message: dict) -> str:

        if not message:
            return ""

        response_header = message.get("responseHeader", "")
        response_body = message.get("responseBody", "")

        if response_body:
            return f"{response_header}\n\n{response_body}"

        return response_header

    def start_active_scan(self, target_url: str):

        print(f"[*] Đang khởi chạy active scan cho: {target_url}")

        scan_id = self.zap.ascan.scan(url=target_url)

        while True:

            status = int(self.zap.ascan.status(scan_id))
            print(f"[*] Active scan status for {target_url}: {status}%")

            if status >= 100:
                break

            time.sleep(2)

        print(f"[*] Active scan hoàn tất cho: {target_url}")

    def start_active_scans(self, target_urls: List[str]):

        for index, target_url in enumerate(target_urls, start=1):

            print(f"\n[*] [{index}/{len(target_urls)}] Active scan target: {target_url}")

            self.start_active_scan(target_url)

    # ======================================
    # GET FINDINGS
    # ======================================

    def get_findings(self, target_url: str) -> List[dict]:

        print(f"[*] Đang trích xuất Findings từ ZAP cho {target_url}...")

        raw_alerts = self.zap.core.alerts(baseurl=target_url)

        normalized_findings = []

        severity_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO",
        }

        # Optional Noise Filter
        ignore_alerts = ["Modern Web Application", "Retrieved from Cache"]

        for alert in raw_alerts:

            if alert.get("name") in ignore_alerts:
                continue

            matching_message = self._find_message_for_alert(alert, target_url)

            finding = NormalizedFinding(
                endpoint=alert.get("url", ""),
                method=alert.get("method", "GET"),
                param=alert.get("param", ""),
                finding_type=alert.get("name", "Unknown"),
                severity=severity_map.get(alert.get("risk"), "INFO"),
                confidence=alert.get("confidence", ""),
                payload=alert.get("attack", ""),
                raw_request=self._format_raw_request(matching_message)[:1000],
                raw_response=self._format_raw_response(matching_message)[:2000],
            )

            normalized_findings.append(finding.model_dump())

        return normalized_findings

    # ======================================
    # REFLECTED PARAM DETECTOR
    # ======================================

    def get_reflected_params(self, target_url: str) -> List[dict]:

        print("[*] Đang dò tìm Reflected Params...")

        history = self.zap.core.messages(baseurl=target_url)

        reflected_results = []

        for msg in history:

            request_header = msg.get("requestHeader", "")

            lines = request_header.split("\r\n")

            if not lines:
                continue

            request_line = lines[0]

            parts = request_line.split(" ")

            if len(parts) < 2:
                continue

            method = parts[0]
            request_url = parts[1]

            response_body = msg.get("responseBody", "")

            parsed_url = urllib.parse.urlparse(request_url)

            params = urllib.parse.parse_qs(parsed_url.query)

            for param_name, param_values in params.items():

                for value in param_values:

                    # Basic reflection logic
                    if (
                        len(value) > 3
                        and not value.isnumeric()
                        and value in response_body
                    ):

                        reflected_results.append(
                            {
                                "endpoint": parsed_url.path,
                                "method": method,
                                "param": param_name,
                                "finding_type": "REFLECTED_PARAM",
                                "severity": "MEDIUM",
                                "confidence": "MEDIUM",
                                "payload": value[:100],
                                "raw_request": request_header[:1000],
                                "raw_response": msg.get("responseHeader", "")[:1000],
                                "tool_source": "ZAP_Custom_Logic",
                            }
                        )

        # Remove duplicates
        unique_reflected = {
            f"{r['endpoint']}-{r['param']}": r for r in reflected_results
        }

        return list(unique_reflected.values())

    def get_reflected_params_multi(self, target_urls: List[str]) -> List[dict]:

        all_reflected = []

        for target_url in target_urls:

            all_reflected.extend(self.get_reflected_params(target_url))

        unique_reflected = {
            f"{r['endpoint']}-{r['param']}": r for r in all_reflected
        }

        return list(unique_reflected.values())


def load_targets(input_file: str, base_url: str, limit: int | None) -> List[str]:

    base_url = base_url.rstrip("/")
    input_path = Path(input_file)

    if not input_path.exists():

        raise FileNotFoundError(f"Không tìm thấy file đầu vào: {input_file}")

    targets = []

    for line in input_path.read_text(encoding="utf-8", errors="ignore").splitlines():

        entry = line.strip()

        if not entry:

            continue

        if entry.startswith("http://") or entry.startswith("https://"):

            full_url = entry

        else:

            if not entry.startswith("/"):

                entry = "/" + entry

            full_url = base_url + entry

        targets.append(full_url)

        if limit is not None and len(targets) >= limit:

            break

    return targets


# ==========================================
# 3. MAIN
# ==========================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="ZAP Multi-Target Collector")

    parser.add_argument(
        "-i",
        "--input-file",
        default=DEFAULT_INPUT_FILE,
        help="File Katana đã lọc để lấy target",
    )

    parser.add_argument(
        "-b",
        "--base-url",
        default=BASE_URL,
        help="Base URL của DVWA để ghép với các path trong file lọc",
    )

    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=None,
        help="Giới hạn số dòng đầu tiên từ file Katana, bỏ trống để lấy hết",
    )

    parser.add_argument(
        "--active-scan",
        dest="active_scan",
        action="store_true",
        default=True,
        help="Kích hoạt active scan của ZAP cho các target đã nạp (mặc định bật)",
    )

    parser.add_argument(
        "--no-active-scan",
        dest="active_scan",
        action="store_false",
        help="Tắt active scan tự động nếu chỉ muốn thu thập passive findings",
    )

    parser.add_argument(
        "-p", "--proxy", default="http://127.0.0.1:8080", help="ZAP Proxy URL"
    )

    parser.add_argument(
        "--auth-user",
        default="admin",
        help="Username to use for auto-login (default: admin)",
    )

    parser.add_argument(
        "--auth-pass",
        default="password",
        help="Password to use for auto-login (default: password)",
    )

    parser.add_argument(
        "--no-auth",
        dest="no_auth",
        action="store_true",
        help="Disable automatic login",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=DEFAULT_OUTPUT_FILE,
        help="File JSON đầu ra sẽ được ghi đè mỗi lần chạy",
    )

    args = parser.parse_args()

    try:

        collector = ZapCollector(
            proxy_url=args.proxy,
            base_url=args.base_url,
            auth_user=args.auth_user,
            auth_pass=args.auth_pass,
            no_auth=args.no_auth,
        )

        collector.ensure_authenticated()

        targets = load_targets(args.input_file, args.base_url, args.limit)

        if not targets:

            raise ValueError("Không có target hợp lệ nào trong file đầu vào")

        # ==================================
        # STEP 1 - ACCESS TARGETS
        # ==================================

        collector.access_pages(targets)

        # ==================================
        # STEP 1.5 - PAYLOAD INJECTION (phát hiện High Severity)
        # ==================================

        collector.send_payloads_to_targets(targets)

        # ==================================
        # STEP 2 - ACTIVE SCAN
        # ==================================

        if args.active_scan:

            collector.start_active_scans(targets)

        # ==================================
        # STEP 3 - GET FINDINGS
        # ==================================

        findings = []

        for target_url in targets:

            findings.extend(collector.get_findings(target_url))

        reflected = collector.get_reflected_params_multi(targets)

        # ==================================
        # FINAL OUTPUT
        # ==================================

        final_output = {
            "target": args.base_url,
            "zap_findings_count": len(findings),
            "zap_findings": findings,
            "reflected_params_count": len(reflected),
            "reflected_params": reflected,
            "active_scan_enabled": args.active_scan,
        }

        print("\n=== KẾT QUẢ JSON CHUẨN ===")

        json_text = json.dumps(final_output, indent=4, ensure_ascii=False)
        print(json_text)

        output_path = Path(args.output_file)
        output_path.write_text(json_text + "\n", encoding="utf-8")

        print(f"[+] Đã ghi JSON vào: {output_path}")

    except Exception as e:

        print(f"[!] Lỗi: {e}")
