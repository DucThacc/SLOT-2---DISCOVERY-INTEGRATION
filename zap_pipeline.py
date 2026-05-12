#!/usr/bin/env python3
"""DVWA + ZAP one-file pipeline.

This script combines:
- authenticated DVWA login
- page access and form auto-submit
- optional payload injection through query params
- ZAP active scan
- JSON output in one run

It keeps the authenticated session in a single process so you do not need
an intermediate session handoff between scripts.
"""

import argparse
import json
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from pydantic import BaseModel
from zapv2 import ZAPv2

BASE_URL = "http://192.168.144.155:3000"
DEFAULT_INPUT_FILE = "katana.filtered.txt"
DEFAULT_OUTPUT_FILE = "zap_output.json"
DEFAULT_PROXY = "http://127.0.0.1:8080"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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


class DVWAZapPipeline:
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

    def __init__(
        self,
        base_url: str = BASE_URL,
        proxy_url: str = DEFAULT_PROXY,
        auth_user: str = "admin",
        auth_pass: str = "password",
        no_auth: bool = False,
        active_scan: bool = True,
        inject_payloads: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.proxy_url = proxy_url
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.no_auth = no_auth
        self.active_scan = active_scan
        self.inject_payloads = inject_payloads

        self.session = requests.Session()
        self.session.proxies.update({"http": proxy_url, "https": proxy_url})
        self.session.verify = False

        self.zap = ZAPv2(proxies={"http": proxy_url, "https": proxy_url})
        self._message_cache: Dict[str, List[dict]] = {}

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
        login_url = urljoin(self.base_url + "/", "login.php")
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

        check_url = urljoin(self.base_url + "/", "index.php")
        check_resp = self.session.get(check_url, timeout=10)
        if "logout" in check_resp.text.lower() and not self.is_login_page(check_resp.text, str(check_resp.url)):
            print("[*] Auto-login successful ✓")
            return True

        print("[!] Auto-login may have failed ⚠")
        print(f"[DEBUG] Auth check URL: {check_resp.url}")
        print(f"[DEBUG] Home page snippet (first 300 chars):\n{check_resp.text[:300]}")
        return False

    def ensure_authenticated(self) -> None:
        if self.no_auth:
            return
        self.perform_login(self.auth_user, self.auth_pass)

    def fetch_page(self, url: str) -> Optional[str]:
        print(f"[*] Fetching: {url}")
        try:
            response = self.session.get(url, timeout=10)
            html = response.text

            if not self.no_auth and self.is_login_page(html, str(response.url)):
                print("[!] Got login page while fetching target. Re-authenticating and retrying once...")
                if self.perform_login(self.auth_user, self.auth_pass):
                    retry = self.session.get(url, timeout=10)
                    return retry.text

            return html
        except Exception as exc:
            print(f"[!] Failed to fetch {url}: {exc}")
            return None

    def find_forms(self, html: str, page_url: str) -> List[Dict]:
        forms: List[Dict] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            form_tags = soup.find_all("form")

            for form_idx, form in enumerate(form_tags):
                method = form.get("method", "GET").upper()
                action = form.get("action", page_url)

                if action.startswith("/"):
                    action = urljoin(self.base_url, action)
                elif not action.startswith("http"):
                    action = urljoin(page_url, action)

                fields: Dict[str, str] = {}
                has_username = False
                has_password = False

                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if not name:
                        continue

                    input_type = inp.get("type", "text").lower()
                    value = inp.get("value", "")

                    if input_type == "hidden":
                        fields[name] = value
                    elif input_type == "checkbox":
                        fields[name] = "on"
                    elif input_type == "radio":
                        fields[name] = value or "option1"
                    elif input_type == "file":
                        fields[name] = "test.txt"
                    else:
                        fields[name] = "test" if not value else value

                    lowered = name.lower()
                    if lowered in ("username", "user", "email"):
                        has_username = True
                    if lowered in ("password", "pass"):
                        has_password = True

                for select in form.find_all("select"):
                    name = select.get("name")
                    if not name:
                        continue
                    options = select.find_all("option")
                    if options:
                        fields[name] = options[0].get("value", options[0].get_text().strip())
                    else:
                        fields[name] = "option1"

                for textarea in form.find_all("textarea"):
                    name = textarea.get("name")
                    if not name:
                        continue
                    fields[name] = "test content"

                action_lower = action.lower()
                is_login_url = "login" in action_lower or "authenticate" in action_lower
                is_setup_url = "setup" in action_lower
                is_logout_url = "logout" in action_lower
                
                has_setup_field = any(
                    field_name.lower() in ("create_db", "setup_db", "initialize")
                    for field_name in fields.keys()
                )
                has_logout_field = any(
                    field_name.lower() in ("logout", "log_out", "signout", "sign_out", "btnLogout", "btnSignout")
                    for field_name in fields.keys()
                )

                is_skip_form = is_login_url or (has_username and has_password) or is_setup_url or has_setup_field or is_logout_url or has_logout_field

                forms.append(
                    {
                        "index": form_idx,
                        "method": method,
                        "action": action,
                        "fields": fields,
                        "page_url": page_url,
                        "skip": is_skip_form,
                    }
                )

        except Exception as exc:
            print(f"[!] Error parsing HTML: {exc}")

        return forms

    def submit_form(self, form: Dict) -> Optional[str]:
        method = form["method"]
        action = form["action"]
        fields = form["fields"]
        page_url = form["page_url"]
        skip = form.get("skip", False)

        if skip:
            print(f"    [!] Skipping login/logout/setup form (already authenticated)")
            print(f"    [DEBUG] Form action: {action}")
            print(f"    [DEBUG] Form fields: {list(fields.keys())}")
            return None

        print(f"    [+] Submitting {method} form to: {action}")
        print(f"    [+] Fields: {fields}")

        try:
            if method == "GET":
                query_string = urllib.parse.urlencode(fields)
                full_url = f"{action}?{query_string}" if query_string else action
                self.session.get(full_url, timeout=10)

                parsed = urlparse(full_url)
                relative_path = parsed.path
                if parsed.query:
                    relative_path += f"?{parsed.query}"
                print(f"    [✓] Captured GET: {relative_path}")
                return full_url

            self.session.post(action, data=fields, timeout=10)
            parsed = urlparse(action)
            relative_path = parsed.path
            query_string = urllib.parse.urlencode(fields)
            result = f"POST {relative_path}"
            if query_string:
                result += f" {query_string}"
            print(f"    [✓] Captured POST: {result}")
            return action

        except Exception as exc:
            print(f"    [!] Failed to submit form: {exc}")
            return None

    def access_single_page(self, target_url: str) -> None:
        print(f"\n[*] Sending target request: {target_url}")
        try:
            response = self.session.get(target_url, timeout=10)
            if not self.no_auth and self.is_login_page(response.text, str(response.url)):
                print("[!] Target returned login page, retrying login once...")
                if self.perform_login(self.auth_user, self.auth_pass):
                    self.session.get(target_url, timeout=10)
            print("[*] Access completed; ZAP is processing in the background...")
            time.sleep(1)
        except Exception as exc:
            print(f"[!] Unable to access {target_url}: {exc}")

    def access_pages(self, target_urls: List[str]) -> None:
        for index, target_url in enumerate(target_urls, start=1):
            print(f"\n[*] [{index}/{len(target_urls)}] Processing: {target_url}")
            self.access_single_page(target_url)

    def process_forms(self, target_urls: List[str]) -> List[str]:
        submitted_targets: List[str] = []
        for index, target_url in enumerate(target_urls, start=1):
            print(f"\n[*] [{index}/{len(target_urls)}] Form discovery: {target_url}")
            html = self.fetch_page(target_url)
            if not html:
                continue
            forms = self.find_forms(html, target_url)
            print(f"[*] Found {len(forms)} form(s) on page")
            for form_idx, form in enumerate(forms, start=1):
                print(f"[*] Form {form_idx}/{len(forms)}:")
                captured = self.submit_form(form)
                if captured:
                    submitted_targets.append(captured)
        return submitted_targets

    def send_payloads_to_targets(self, target_urls: List[str]) -> None:
        if not self.inject_payloads:
            return

        print("\n[*] Sending payloads to detect High severity issues...")
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

        print("[*] Payload injection complete")

    def _get_messages_for_target(self, target_url: str):
        if target_url not in self._message_cache:
            self._message_cache[target_url] = self.zap.core.messages(baseurl=target_url)
        return self._message_cache[target_url]

    def _find_message_for_alert(self, alert: dict, target_url: str):
        message_id = alert.get("messageId") or alert.get("messageid") or alert.get("message_id")

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

    def start_active_scan(self, target_url: str) -> None:
        print(f"[*] Starting active scan for: {target_url}")
        scan_id = self.zap.ascan.scan(url=target_url)

        while True:
            status = int(self.zap.ascan.status(scan_id))
            print(f"[*] Active scan status for {target_url}: {status}%")
            if status >= 100:
                break
            time.sleep(2)

        print(f"[*] Active scan finished for: {target_url}")

    def start_active_scans(self, target_urls: List[str]) -> None:
        for index, target_url in enumerate(target_urls, start=1):
            print(f"\n[*] [{index}/{len(target_urls)}] Active scan target: {target_url}")
            self.start_active_scan(target_url)

    def get_findings(self, target_url: str) -> List[dict]:
        print(f"[*] Extracting findings from ZAP for {target_url}...")
        raw_alerts = self.zap.core.alerts(baseurl=target_url)

        normalized_findings: List[dict] = []
        severity_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO",
        }
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

    def get_reflected_params(self, target_url: str) -> List[dict]:
        print("[*] Looking for reflected parameters...")
        history = self.zap.core.messages(baseurl=target_url)
        reflected_results: List[dict] = []

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
                    if len(value) > 3 and not value.isnumeric() and value in response_body:
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

        unique_reflected = {f"{r['endpoint']}-{r['param']}": r for r in reflected_results}
        return list(unique_reflected.values())

    def get_reflected_params_multi(self, target_urls: List[str]) -> List[dict]:
        all_reflected: List[dict] = []
        for target_url in target_urls:
            all_reflected.extend(self.get_reflected_params(target_url))
        unique_reflected = {f"{r['endpoint']}-{r['param']}": r for r in all_reflected}
        return list(unique_reflected.values())

    def load_targets(self, input_file: str, base_url: str, limit: Optional[int]) -> List[str]:
        base_url = base_url.rstrip("/")
        input_path = Path(input_file)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        targets: List[str] = []
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

    def run(self, input_file: str, base_url: str, limit: Optional[int], output_file: str) -> dict:
        self.ensure_authenticated()

        targets = self.load_targets(input_file, base_url, limit)
        if not targets:
            raise ValueError("No valid targets found in input file")

        # 1) touch pages so ZAP sees them
        self.access_pages(targets)

        # 2) submit forms and keep the captured requests as additional targets
        submitted_targets = self.process_forms(targets)

        # 3) payload injection across original and submitted targets
        scan_targets = list(dict.fromkeys(targets + submitted_targets))
        self.send_payloads_to_targets(scan_targets)

        # 4) active scan
        if self.active_scan:
            self.start_active_scans(scan_targets)

        # 5) collect findings
        findings: List[dict] = []
        for target_url in scan_targets:
            findings.extend(self.get_findings(target_url))
        reflected = self.get_reflected_params_multi(scan_targets)

        final_output = {
            "target": base_url,
            "input_count": len(targets),
            "submitted_count": len(submitted_targets),
            "scan_target_count": len(scan_targets),
            "submitted_targets": submitted_targets,
            "zap_findings_count": len(findings),
            "zap_findings": findings,
            "reflected_params_count": len(reflected),
            "reflected_params": reflected,
            "active_scan_enabled": self.active_scan,
            "payload_injection_enabled": self.inject_payloads,
        }

        json_text = json.dumps(final_output, indent=4, ensure_ascii=False)
        print("\n=== JSON OUTPUT ===")
        print(json_text)

        output_path = Path(output_file)
        output_path.write_text(json_text + "\n", encoding="utf-8")
        print(f"[+] Wrote JSON to: {output_path}")

        return final_output


def main() -> None:
    parser = argparse.ArgumentParser(description="Combined DVWA form-submit + ZAP scanner")
    parser.add_argument("-i", "--input-file", default=DEFAULT_INPUT_FILE, help="Katana filtered input file")
    parser.add_argument("-b", "--base-url", default=BASE_URL, help="Base URL of DVWA")
    parser.add_argument("-n", "--limit", type=int, default=None, help="Limit number of input rows")
    parser.add_argument("-p", "--proxy", default=DEFAULT_PROXY, help="ZAP proxy URL")
    parser.add_argument("-o", "--output-file", default=DEFAULT_OUTPUT_FILE, help="JSON output file")
    parser.add_argument("--auth-user", default="admin", help="DVWA username (default: admin)")
    parser.add_argument("--auth-pass", default="password", help="DVWA password (default: password)")
    parser.add_argument("--no-auth", dest="no_auth", action="store_true", help="Disable automatic login")
    parser.add_argument("--no-active-scan", dest="active_scan", action="store_false", help="Disable active scan")
    parser.add_argument("--no-payload-injection", dest="inject_payloads", action="store_false", help="Disable payload injection")
    parser.set_defaults(active_scan=True, inject_payloads=True)

    args = parser.parse_args()

    pipeline = DVWAZapPipeline(
        base_url=args.base_url,
        proxy_url=args.proxy,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
        no_auth=args.no_auth,
        active_scan=args.active_scan,
        inject_payloads=args.inject_payloads,
    )

    pipeline.run(
        input_file=args.input_file,
        base_url=args.base_url,
        limit=args.limit,
        output_file=args.output_file,
    )


if __name__ == "__main__":
    main()
