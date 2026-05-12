#!/usr/bin/env python3
"""
Aggressive filter for katana.txt - Keep only core vulnerability endpoints
"""

def filter_minimal(input_file="katana.txt", output_file="katana.minimal.txt"):
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
    
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines()]
    
    print(f"[*] Total lines: {len(lines)}")
    
    filtered = []
    
    for line in lines:
        if not line or not line.startswith('http://192.168.144.155:3000'):
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
        # - /vulnerabilities/* endpoints
        # - /phpinfo.php
        # - /login.php
        if any(x in line for x in ['/vulnerabilities/', '/phpinfo.php', '/login.php']):
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
        path = url.replace('http://192.168.144.155:3000', '')
        print(f"    {path}")

if __name__ == "__main__":
    filter_minimal()
