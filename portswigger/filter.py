#!/usr/bin/env python3
import sys
import os

def main():
    katana_file = "katana_ps.txt"
    target_out = "targets.txt"
    
    urls = set()
    if not os.path.exists(katana_file):
        print(f"[-] {katana_file} not found. Skipping filter.")
        with open(target_out, "w") as f:
            pass
        return
        
    with open(katana_file, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            # Simple heuristic: remove static files, keep everything else
            if url and not url.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".js", ".woff", ".woff2", ".ico")):
                urls.add(url)
                
    with open(target_out, "w", encoding="utf-8") as f:
        for u in sorted(urls):
            f.write(u + "\n")
            
    print(f"[+] Extracted {len(urls)} unique endpoints to {target_out}")

if __name__ == "__main__":
    main()
