#!/usr/bin/env python3
import time
import sys
import os
import argparse
import requests
from zapv2 import ZAPv2

API_KEY = os.environ.get('ZAP_API_KEY', '')
ZAP_ADDRESS = os.environ.get('ZAP_ADDRESS', 'http://127.0.0.1:8080')

def seed_zap_from_file(file_path, proxy, cookie_str):
    print(f"[*] Seeding ZAP with URLs from {file_path}...")
    headers = {}
    if cookie_str:
        headers['Cookie'] = cookie_str
    
    proxies = {
        'http': proxy,
        'https': proxy
    }
    
    if not os.path.exists(file_path):
        print(f"[-] File {file_path} does not exist.")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = f.read().splitlines()
    except Exception as e:
        print(f"[-] Could not read {file_path}: {e}")
        return
        
    for url in urls:
        if not url: continue
        try:
            requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=5)
        except requests.exceptions.RequestException:
            pass
    print(f"[+] Seeding completed. Sent {len(urls)} requests through ZAP.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Base URL of the target")
    parser.add_argument("--cookie", help="Cookie string (e.g. session=xxx)")
    args = parser.parse_args()
    
    target = args.target
    cookie_str = args.cookie
    
    # Disable warnings for unverified HTTPS requests
    requests.packages.urllib3.disable_warnings()
    
    zap = ZAPv2(apikey=API_KEY, proxies={'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS})
    
    print(f"[*] Accessing ZAP API at {ZAP_ADDRESS}")
    
    try:
        zap.core.version
    except Exception as e:
        print(f"[-] Could not connect to ZAP API at {ZAP_ADDRESS}. Is ZAP running?")
        sys.exit(1)
        
    # Configure Cookie using Replacer rule inside ZAP for its own scans
    if cookie_str:
        print(f"[*] Injecting Cookie into ZAP config: {cookie_str}")
        try:
            zap.replacer.remove_rule('AuthCookie')
        except:
            pass
        zap.replacer.add_rule(description='AuthCookie', enabled='true', matchtype='REQ_HEADER',
                              matchregex='false', matchstring='Cookie',
                              replacement=cookie_str, initiators='')
                              
    # Seed ZAP site tree
    seed_zap_from_file("targets.txt", ZAP_ADDRESS, cookie_str)
    
    print(f"[*] Starting Active Scan for target: {target}")
    try:
        scan_id = zap.ascan.scan(target)
        if isinstance(scan_id, dict):
            # API might return a dictionary with error if target not in tree
            print(f"[-] Failed to start scan: {scan_id}")
        else:
            while True:
                try:
                    status = int(zap.ascan.status(scan_id))
                    print(f"[*] Active Scan progress: {status}%")
                    if status >= 100:
                        break
                    time.sleep(5)
                except Exception as e:
                    print(f"[-] Error checking scan status: {e}. ZAP might be busy. Waiting...")
                    time.sleep(5)
            print("[+] Active Scan completed.")
    except Exception as e:
        print(f"[-] Exception during active scan: {e}")
    
    # Generate HTML report
    try:
        print("[*] Generating ZAP HTML report...")
        report_html = zap.core.htmlreport()
        with open('zap_report.html', 'w', encoding='utf-8') as f:
            f.write(report_html)
        print("[+] Saved ZAP report to zap_report.html")
    except Exception as e:
        print(f"[-] Error generating report: {e}")

if __name__ == "__main__":
    main()
