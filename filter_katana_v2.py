#!/usr/bin/env python3
"""
Filter katana.txt - Remove .js files, logout.php, setup.php
"""

import re
from pathlib import Path

def filter_katana(input_file="katana.txt", output_file="katana.filtered_clean.txt"):
    """
    Read katana.txt and remove:
    - .js files
    - .css files (static assets)
    - logout.php
    - setup.php
    """
    
    print(f"[*] Reading {input_file}...")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[-] File not found: {input_file}")
        return
    
    print(f"[*] Total lines: {len(lines)}")
    
    filtered = []
    
    for line in lines:
        line = line.strip()
        
        if not line:
            continue
        
        # Skip .js files
        if line.lower().endswith('.js'):
            print(f"[!] Skipping JS file: {line}")
            continue
        
        # Skip .css files
        if line.lower().endswith('.css'):
            print(f"[!] Skipping CSS file: {line}")
            continue
        
        # Skip logout.php
        if 'logout.php' in line.lower():
            print(f"[!] Skipping logout: {line}")
            continue
        
        # Skip setup.php
        if 'setup.php' in line.lower():
            print(f"[!] Skipping setup: {line}")
            continue
        
        # Skip external URLs (w3.org, dvwa.co.uk, etc)
        if not line.startswith('http://192.168.144.155:3000'):
            print(f"[!] Skipping external URL: {line}")
            continue
        
        filtered.append(line)
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for url in filtered:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    
    print(f"\n[+] After filtering: {len(unique)} unique URLs")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for url in unique:
            f.write(url + '\n')
    
    print(f"[+] Saved to: {output_file}")
    print(f"\n[+] Sample URLs:")
    for url in unique[:10]:
        print(f"    {url}")

if __name__ == "__main__":
    filter_katana()
