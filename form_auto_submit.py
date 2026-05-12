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
    def __init__(self, proxy_url: str = PROXY_URL, base_url: str = BASE_URL, auth_user: str = "admin", auth_pass: str = "password", no_auth: bool = False):
        self.proxy_url = proxy_url
        self.base_url = base_url.rstrip("/")
        self.proxies = {"http": proxy_url, "https": proxy_url}
        self.submitted_urls = []
        self.session = requests.Session()
        self.session.proxies.update(self.proxies)
        self.session.verify = False
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.no_auth = no_auth

    def is_login_page(self, html: str, page_url: str = "") -> bool:
        """Heuristic to detect DVWA login page reliably."""
        low = html.lower()
        if "<title>login ::" in low:
            return True
        if "name=\"username\"" in low and "name=\"password\"" in low and "login.php" in low:
            return True
        if page_url and "login.php" in page_url.lower():
            return True
        return False

    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch HTML content from URL through proxy."""
        print(f"[*] Fetching: {url}")
        try:
            response = self.session.get(url, timeout=10)
            html = response.text

            # If redirected/served login page unexpectedly, attempt re-login once.
            if not self.no_auth and self.is_login_page(html, str(response.url)):
                print("[!] Got login page while fetching target. Re-authenticating and retrying once...")
                if self.perform_login(self.auth_user, self.auth_pass):
                    retry = self.session.get(url, timeout=10)
                    return retry.text

            return html
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

                    # detect login forms
                    # mark if form has username/password fields
                    # we'll use this later to optionally skip or perform login
                    # record by setting a special key (not sent)
                    # handled after collecting all inputs

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

                # Detect if this is a login form or setup form
                # Skip: (1) action URL contains "login" OR (2) has both username AND password fields
                # Also skip: (3) action URL contains "setup" or form has "create_db" field
                action_lower = action.lower()
                is_login_url = "login" in action_lower or "authenticate" in action_lower
                is_setup_url = "setup" in action_lower
                
                has_username = any(
                    field_name.lower() in ("username", "user", "email")
                    for field_name in fields.keys()
                )
                has_password = any(
                    field_name.lower() in ("password", "pass")
                    for field_name in fields.keys()
                )
                has_both = has_username and has_password
                has_setup_field = any(
                    field_name.lower() in ("create_db", "setup_db", "initialize")
                    for field_name in fields.keys()
                )
                
                is_login_form = is_login_url or has_both or is_setup_url or has_setup_field

                forms.append(
                    {
                        "index": form_idx,
                        "method": method,
                        "action": action,
                        "fields": fields,
                        "page_url": page_url,
                        "is_login_form": is_login_form,
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
        is_login_form = form.get("is_login_form", False)

        # Skip login/setup forms — they were handled elsewhere
        if is_login_form:
            print(f"    [!] Skipping login form (already authenticated)")
            print(f"    [DEBUG] Form action: {action}")
            print(f"    [DEBUG] Form fields: {list(fields.keys())}")
            # Fetch current page to verify if still showing login or authenticated
            try:
                current_page = self.session.get(page_url, timeout=5).text
                if "logout" in current_page.lower() and not self.is_login_page(current_page, page_url):
                    print(f"    [DEBUG] ✓ Page shows 'logout' - authenticated confirmed")
                elif self.is_login_page(current_page, page_url):
                    print(f"    [DEBUG] ⚠ Page still shows 'login' - login may have failed!")
                    print(f"    [DEBUG] Page title/snippets: {current_page[200:500]}")
                else:
                    print(f"    [DEBUG] Page content (first 300 chars): {current_page[:300]}")
            except Exception as e:
                print(f"    [DEBUG] Could not fetch page: {e}")
            return None

        print(f"    [+] Submitting {method} form to: {action}")
        print(f"    [+] Fields: {fields}")

        try:
            if method == "GET":
                # For GET, append params to URL
                query_string = urllib.parse.urlencode(fields)
                full_url = f"{action}?{query_string}" if query_string else action
                self.session.get(full_url, timeout=10)

                # Return relative path for katana_filtered_2.txt
                parsed = urlparse(full_url)
                relative_path = parsed.path
                if parsed.query:
                    relative_path += f"?{parsed.query}"
                print(f"    [✓] Captured GET: {relative_path}")
                return relative_path

            else:  # POST
                self.session.post(action, data=fields, timeout=10)

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

    def perform_login(self, username: str, password: str) -> bool:
        """Attempt login using /login.php, store session cookies."""
        login_url = urljoin(self.base_url + '/', 'login.php')
        print(f"[*] Performing automated login to {login_url} as {username}")

        # Keep DVWA at low security during recon/automation.
        self.session.cookies.set('security', 'low')

        resp = self.session.get(login_url, timeout=10)
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')
        token_input = soup.find('input', attrs={'name': 'user_token'})
        token = token_input.get('value') if token_input else ''
        
        print(f"[DEBUG] Got CSRF token: {token[:20]}..." if token else "[DEBUG] No CSRF token found")

        data = {'username': username, 'password': password, 'Login': 'Login'}
        if token:
            data['user_token'] = token

        post_resp = self.session.post(login_url, data=data, timeout=10, allow_redirects=True)
        print(f"[DEBUG] Login POST response status: {post_resp.status_code}")

        check_url = urljoin(self.base_url + '/', 'index.php')
        check_resp = self.session.get(check_url, timeout=10)
        check = check_resp.text

        # Success requires logout marker and not being on login page.
        if 'logout' in check.lower() and not self.is_login_page(check, str(check_resp.url)):
            print('[*] Auto-login successful ✓')
            print(f"[DEBUG] Auth confirmed at: {check_resp.url}")
            return True

        print('[!] Auto-login may have failed ⚠')
        print(f"[DEBUG] Auth check URL: {check_resp.url}")
        print(f"[DEBUG] Home page snippet (first 300 chars):\n{check[:300]}")
        return False

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

        # perform authenticated login if not disabled
        if not self.no_auth and self.auth_user and self.auth_pass:
            try:
                self.perform_login(self.auth_user, self.auth_pass)
            except Exception:
                print("[!] Auto-login failed; continuing without auth")

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
        help="Disable automatic login (default: login as admin/password)",
    )

    args = parser.parse_args()

    try:
        processor = FormAutoSubmit(proxy_url=args.proxy, base_url=args.base_url, auth_user=args.auth_user, auth_pass=args.auth_pass, no_auth=args.no_auth)
        processor.process_all(args.input_file, args.output_file)
        print("\n[+] Success! Next step: python3 use-ZAP.py -i katana_filtered_2.txt")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
