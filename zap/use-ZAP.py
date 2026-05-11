#!/usr/bin/env python3
"""
Copy of root use-ZAP.py for convenience inside zap/ folder.
Run this file from within the repository root or this folder's venv.
"""

import argparse
import json
import time
import urllib.parse
from pathlib import Path
from typing import List

import requests
import urllib3
from pydantic import BaseModel
from zapv2 import ZAPv2


BASE_URL = "http://192.168.144.155:3000"
DEFAULT_INPUT_FILE = "katana.filtered.txt"

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


class ZapCollector:

    def __init__(self, proxy_url="http://127.0.0.1:8080"):

        print(f"[*] Đang kết nối tới ZAP Proxy tại {proxy_url}...")

        self.proxy_url = proxy_url

        self.zap = ZAPv2(proxies={"http": proxy_url, "https": proxy_url})

    def access_single_page(self, target_url: str):

        print(f"\n[*] Đang gửi request duy nhất tới: {target_url}")

        proxies = {"http": self.proxy_url, "https": self.proxy_url}

        try:

            requests.get(target_url, proxies=proxies, verify=False, timeout=10)

            print("[*] Truy cập thành công! " "Đợi 3 giây để ZAP Passive Scan...")

            time.sleep(3)

        except Exception as e:

            print(f"[!] Không thể truy cập {target_url}: {e}")

    def access_pages(self, target_urls: List[str]):

        for index, target_url in enumerate(target_urls, start=1):

            print(f"\n[*] [{index}/{len(target_urls)}] Đang xử lý: {target_url}")

            self.access_single_page(target_url)

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

        ignore_alerts = ["Modern Web Application", "Retrieved from Cache"]

        for alert in raw_alerts:

            if alert.get("name") in ignore_alerts:
                continue

            finding = NormalizedFinding(
                endpoint=alert.get("url", ""),
                method=alert.get("method", "GET"),
                param=alert.get("param", ""),
                finding_type=alert.get("name", "Unknown"),
                severity=severity_map.get(alert.get("risk"), "INFO"),
                confidence=alert.get("confidence", ""),
                payload=alert.get("attack", ""),
                raw_request=alert.get("requestHeader", "")[:1000],
                raw_response=alert.get("responseHeader", "")[:1000],
            )

            normalized_findings.append(finding.model_dump())

        return normalized_findings

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

        unique_reflected = {f"{r['endpoint']}-{r['param']}": r for r in reflected_results}

        return list(unique_reflected.values())

    def get_reflected_params_multi(self, target_urls: List[str]) -> List[dict]:

        all_reflected = []

        for target_url in target_urls:

            all_reflected.extend(self.get_reflected_params(target_url))

        unique_reflected = {f"{r['endpoint']}-{r['param']}": r for r in all_reflected}

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
        action="store_true",
        help="Kích hoạt active scan của ZAP cho các target đã nạp",
    )

    parser.add_argument(
        "-p", "--proxy", default="http://127.0.0.1:8080", help="ZAP Proxy URL"
    )

    args = parser.parse_args()

    try:

        collector = ZapCollector(proxy_url=args.proxy)

        targets = load_targets(args.input_file, args.base_url, args.limit)

        if not targets:

            raise ValueError("Không có target hợp lệ nào trong file đầu vào")

        collector.access_pages(targets)

        if args.active_scan:

            collector.start_active_scans(targets)

        findings = []

        for target_url in targets:

            findings.extend(collector.get_findings(target_url))

        reflected = collector.get_reflected_params_multi(targets)

        final_output = {
            "target": args.base_url,
            "zap_findings_count": len(findings),
            "zap_findings": findings,
            "reflected_params_count": len(reflected),
            "reflected_params": reflected,
            "active_scan_enabled": args.active_scan,
        }

        print(json.dumps(final_output, indent=4, ensure_ascii=False))

    except Exception as e:

        print(f"[!] Lỗi: {e}")
