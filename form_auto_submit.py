#!/usr/bin/env python3
"""
Form Auto-Submit Tool
======================
Purpose: 
  1. Read URLs from katana_filtered.txt
  2. For each URL, fetch HTML and find all forms
  3. Auto-fill form fields with test values
  4. Auto-submit forms through ZAP proxy
  5. Capture submitted form URLs (GET) or form actions (POST)
  6. Output to katana_filtered_2.txt for next stage (ZAP scanning)

Output Format:
  - GET forms: /path?param1=value1&param2=value2
  - POST forms: POST /path param1=value1&param2=value2
"""

import argparse
import re
import time
import urllib.parse
from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

BASE_URL = "http://192.168.144.155:3000"
DEFAULT_INPUT_FILE = "katana.filtered.txt"
DEFAULT_OUTPUT_FILE = "katana_filtered_2.txt"
PROXY_URL = "http://127.0.0.1:8080"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FormAutoSubmit:
    """Automatically find and submit forms on web pages."""

    def __init__(self, proxy_url: str = PROXY_URL, base_url: str = BASE_URL):
        self.proxy_url = proxy_url
        self.base_url = base_url.rstrip("/")
        self.proxies = {"http": proxy_url, "https": proxy_url}
        self.submitted_urls = []

    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch HTML content from URL through proxy."""
        print(f"[*] Fetching: {url}")
        try:
            response = requests.get(url, proxies=self.proxies, verify=False, timeout=10)
            return response.text
        except Exception as e:
            print(f"[!] Failed to fetch {url}: {e}")
            return None

    def find_forms(self, html: str, page_url: str) -> List[Dict]:
        """Parse HTML and extract form information."""
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            form_tags = soup.find_all("form")

            for form_idx, form in enumerate(form_tags):
                method = form.get("method", "GET").upper()
                action = form.get("action", page_url)

                # Handle relative URLs
                if action.startswith("/"):
                    action = urljoin(self.base_url, action)
                elif not action.startswith("http"):
                    action = urljoin(page_url, action)

                fields = {}

                # Extract all input fields
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if not name:
                        continue

                    input_type = inp.get("type", "text").lower()
                    value = inp.get("value", "")

                    if input_type == "hidden":
                        # Use hidden field value as-is
                        fields[name] = value
                    elif input_type == "checkbox":
                        # Check checkbox by default
                        fields[name] = "on"
                    elif input_type == "radio":
                        # Select first radio option
                        fields[name] = value or "option1"
                    elif input_type == "file":
                        # Use dummy filename
                        fields[name] = "test.txt"
                    else:
                        # text, email, password, number, etc.
                        fields[name] = "test" if not value else value

                # Extract select fields
                for select in form.find_all("select"):
                    name = select.get("name")
                    if not name:
                        continue

                    options = select.find_all("option")
                    if options:
                        # Use first option value
                        fields[name] = options[0].get("value", options[0].get_text().strip())
                    else:
                        fields[name] = "option1"

                # Extract textarea fields
                for textarea in form.find_all("textarea"):
                    name = textarea.get("name")
                    if not name:
                        continue
                    fields[name] = "test content"

                forms.append(
                    {
                        "index": form_idx,
                        "method": method,
                        "action": action,
                        "fields": fields,
                        "page_url": page_url,
                    }
                )

        except Exception as e:
            print(f"[!] Error parsing HTML: {e}")

        return forms

    def submit_form(self, form: Dict) -> Optional[str]:
        """Submit form and return captured request URL."""
        method = form["method"]
        action = form["action"]
        fields = form["fields"]
        page_url = form["page_url"]

        print(f"    [+] Submitting {method} form to: {action}")
        print(f"    [+] Fields: {fields}")

        try:
            if method == "GET":
                # For GET, append params to URL
                query_string = urllib.parse.urlencode(fields)
                full_url = f"{action}?{query_string}" if query_string else action
                requests.get(full_url, proxies=self.proxies, verify=False, timeout=10)

                # Return relative path for katana_filtered_2.txt
                parsed = urlparse(full_url)
                relative_path = parsed.path
                if parsed.query:
                    relative_path += f"?{parsed.query}"
                print(f"    [✓] Captured GET: {relative_path}")
                return relative_path

            else:  # POST
                requests.post(action, data=fields, proxies=self.proxies, verify=False, timeout=10)

                # Return as "POST /path field1=value1&field2=value2"
                parsed = urlparse(action)
                relative_path = parsed.path
                query_string = urllib.parse.urlencode(fields)

                result = f"POST {relative_path}"
                if query_string:
                    result += f" {query_string}"
                print(f"    [✓] Captured POST: {result}")
                return result

        except Exception as e:
            print(f"    [!] Failed to submit form: {e}")

        return None

    def process_url(self, url: str) -> List[str]:
        """Process single URL: find and submit all forms."""
        captured = []

        # Construct full URL
        if not url.startswith("http"):
            full_url = f"{self.base_url}{url}" if url.startswith("/") else f"{self.base_url}/{url}"
        else:
            full_url = url

        print(f"\n[*] Processing: {full_url}")

        # Fetch HTML
        html = self.fetch_page(full_url)
        if not html:
            return captured

        # Find forms
        forms = self.find_forms(html, full_url)
        print(f"[*] Found {len(forms)} form(s) on page")

        # Submit each form
        for form_idx, form in enumerate(forms, start=1):
            print(f"[*] Form {form_idx}/{len(forms)}:")
            result = self.submit_form(form)
            if result:
                captured.append(result)
            time.sleep(0.5)  # Brief pause between submissions

        return captured

    def process_all(self, input_file: str, output_file: str):
        """Process all URLs from input file."""
        input_path = Path(input_file)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Read input URLs
        urls = []
        for line in input_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

        print(f"[*] Loaded {len(urls)} URLs from {input_file}")

        # Process each URL
        all_captured = []
        for idx, url in enumerate(urls, start=1):
            print(f"\n{'='*60}")
            print(f"[*] [{idx}/{len(urls)}] Processing URL")
            print(f"{'='*60}")

            captured = self.process_url(url)
            all_captured.extend(captured)
            time.sleep(1)  # Pause between URLs

        # Write output
        output_path = Path(output_file)
        output_text = "\n".join(all_captured)
        output_path.write_text(output_text + "\n", encoding="utf-8")

        print(f"\n{'='*60}")
        print(f"[+] Completed! Wrote {len(all_captured)} submitted URLs to: {output_file}")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Auto-submit forms and capture request URLs for ZAP scanning"
    )

    parser.add_argument(
        "-i",
        "--input-file",
        default=DEFAULT_INPUT_FILE,
        help="Filtered Katana file (default: katana.filtered.txt)",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=DEFAULT_OUTPUT_FILE,
        help="Output file with captured URLs (default: katana_filtered_2.txt)",
    )

    parser.add_argument(
        "-b",
        "--base-url",
        default=BASE_URL,
        help="Base URL of target application",
    )

    parser.add_argument(
        "-p",
        "--proxy",
        default=PROXY_URL,
        help="ZAP Proxy URL (default: http://127.0.0.1:8080)",
    )

    args = parser.parse_args()

    try:
        processor = FormAutoSubmit(proxy_url=args.proxy, base_url=args.base_url)
        processor.process_all(args.input_file, args.output_file)
        print("\n[+] Success! Next step: python3 use-ZAP.py -i katana_filtered_2.txt")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
