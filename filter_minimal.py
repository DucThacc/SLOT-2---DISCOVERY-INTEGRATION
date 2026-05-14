#!/usr/bin/env python3
"""Aggressive filter for katana.txt - Keep only core vulnerability endpoints."""

import argparse


def filter_minimal(input_file="katana.txt", output_file="katana.minimal.txt", base_url="http://192.168.144.155:3000", only_xss_sql=False):
    """
    Keep ONLY the core vulnerability endpoints:
    - /vulnerabilities/* (exclude view_help, view_source)
    - /phpinfo.php
    - /login.php (for testing)
    
    Remove:
    - .js, .css files
    - logout.php, setup.php
    - /instructions.php, /about.php, /security.php
    - /hackable/* (directory browsing)
    - Query parameters (especially ?C=... sorting params)
    - External URLs
    """
    
    print(f"[*] Reading {input_file}...")
    
    # Strip trailing slash from base_url for consistent processing
    base_url = base_url.rstrip("/")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines()]
    
    print(f"[*] Total lines: {len(lines)}")
    
    filtered = []
    
    for line in lines:
        if not line or not line.startswith(base_url):
            continue
        
        # Skip static files
        if line.lower().endswith(('.js', '.css', '.dtd')):
            continue
        
        # Skip dangerous pages
        if any(x in line.lower() for x in ['logout.php', 'setup.php']):
            continue
        
        # Skip information pages
        if any(x in line.lower() for x in ['/instructions.php', '/about.php', '/security.php', '/var/www/html/', '/config/']):
            continue
        
        # Skip file browsing
        if '/hackable/' in line:
            continue
        
        # Skip sorting/pagination query params
        if '?C=' in line:
            continue
        
        # Skip view_help and view_source (meta pages)
        if 'view_help.php' in line or 'view_source.php' in line:
            continue
        
        # Keep ONLY:
        if only_xss_sql:
            allowed_endpoints = ['/vulnerabilities/sqli', '/vulnerabilities/xss', '/login.php']
        else:
            allowed_endpoints = ['/vulnerabilities/', '/phpinfo.php', '/login.php']

        if any(x in line for x in allowed_endpoints):
            filtered.append(line)
    
    # Deduplicate
    unique = list(dict.fromkeys(filtered))
    
    print(f"\n[+] Filtered to: {len(unique)} minimal URLs")
    
    with open(output_file, 'w') as f:
        for url in unique:
            f.write(url + '\n')
    
    print(f"[+] Saved to: {output_file}\n")
    print("[+] URLs:")
    for url in unique:
        # Extract just the path for readability
        path = url.replace(base_url, '')
        print(f"    {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter katana output to minimal DVWA URLs")
    parser.add_argument("-i", "--input", default="katana.txt", help="Input file from katana")
    parser.add_argument("-o", "--output", default="katana.minimal.txt", help="Output filtered file")
    parser.add_argument("-b", "--base-url", default="http://192.168.144.155:3000", help="Base URL of target application")
    parser.add_argument("--only-xss-sql", action="store_true", help="Only keep XSS and SQLi vulnerabilities")
    args = parser.parse_args()
    filter_minimal(args.input, args.output, args.base_url, args.only_xss_sql)
