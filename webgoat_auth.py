#!/usr/bin/env python3
import requests
import argparse
import subprocess
import sys
import time

class WebGoatAuth:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.login_url = f"{self.base_url}/WebGoat/login"
        self.register_url = f"{self.base_url}/WebGoat/register.mvc"
        
    def get_cookie_for_user(self, username, password):
        print(f"\n[*] Đang xử lý tài khoản: {username}")
        session = requests.Session()
        
        # 1. Thử đăng nhập trước
        print(f"    [-] Thử đăng nhập với mật khẩu '{password}'...")
        login_data = {
            "username": username,
            "password": password
        }
        
        # Spring Security form login
        resp = session.post(self.login_url, data=login_data, allow_redirects=False)
        
        # Nếu đăng nhập thành công, Spring thường trả về 302 chuyển hướng về trang chủ
        # hoặc có chứa Cookie JSESSIONID/WEbGoat
        if resp.status_code == 302 and "error" not in resp.headers.get("Location", ""):
            print("    [+] Đăng nhập thành công (Tài khoản đã tồn tại).")
            return self._extract_cookies(session)
        
        # Nếu 200 OK nhưng URL vẫn là login (hoặc có chữ error) -> Đăng nhập thất bại
        print("    [-] Đăng nhập thất bại. Tiến hành đăng ký tài khoản mới...")
        
        # 2. Đăng ký tài khoản
        reg_data = {
            "username": username,
            "password": password,
            "matchingPassword": password,
            "agree": "agree"
        }
        
        reg_resp = session.post(self.register_url, data=reg_data, allow_redirects=False)
        if reg_resp.status_code in [200, 302]:
            print("    [+] Đăng ký thành công!")
        else:
            print(f"    [!] Đăng ký thất bại với status: {reg_resp.status_code}")
            return None
            
        # 3. Đăng nhập lại sau khi đăng ký để lấy Cookie chuẩn
        print("    [-] Tiến hành đăng nhập lại để lấy Cookie...")
        login_resp = session.post(self.login_url, data=login_data, allow_redirects=False)
        
        if login_resp.status_code == 302 and "error" not in login_resp.headers.get("Location", ""):
            print("    [+] Đăng nhập sau khi đăng ký thành công!")
            return self._extract_cookies(session)
        else:
            print("    [!] Không thể đăng nhập sau khi đăng ký.")
            return None

    def _extract_cookies(self, session):
        cookies = session.cookies.get_dict()
        cookie_parts = []
        if "JSESSIONID" in cookies:
            cookie_parts.append(f"JSESSIONID={cookies['JSESSIONID']}")
        if "WEbGoat" in cookies: # Tên cookie WebGoat thường có viết hoa W E b G o a t
            cookie_parts.append(f"WEbGoat={cookies['WEbGoat']}")
            
        cookie_string = "; ".join(cookie_parts)
        if cookie_string:
            return cookie_string
        return None

def main():
    parser = argparse.ArgumentParser(description="WebGoat Auto Auth & IDOR Runner")
    parser.add_argument("-u", "--urls", required=True, help="File chứa danh sách URL (vd: urls.txt)")
    parser.add_argument("-t", "--target", default="http://192.168.186.128:3001", help="URL máy ảo WebGoat")
    parser.add_argument("--user1", default="ducthanh1", help="Tên user 1")
    parser.add_argument("--user2", default="ducthanh2", help="Tên user 2")
    parser.add_argument("--passw", default="123456", help="Mật khẩu chung cho cả 2")
    
    args = parser.parse_args()
    
    print("======================================================")
    print("   WEBGOAT AUTO-AUTH & IDOR EXPLOIT RUNNER")
    print("======================================================")
    print(f"Target: {args.target}")
    
    auth = WebGoatAuth(args.target)
    
    cookie1 = auth.get_cookie_for_user(args.user1, args.passw)
    if not cookie1:
        print("[!] Không lấy được Cookie cho user 1. Thoát.")
        sys.exit(1)
        
    # Nghỉ 1 giây để tránh nghẽn server
    time.sleep(1)
        
    cookie2 = auth.get_cookie_for_user(args.user2, args.passw)
    if not cookie2:
        print("[!] Không lấy được Cookie cho user 2. Thoát.")
        sys.exit(1)
        
    print("\n======================================================")
    print("[*] ĐÃ LẤY THÀNH CÔNG 2 COOKIES:")
    print(f"    {args.user1}: {cookie1}")
    print(f"    {args.user2}: {cookie2}")
    print("======================================================\n")
    
    print("[*] Đang khởi chạy idor_exploit.py...\n")
    
    # Xây dựng command line
    # Sửa từ python3 sang python để tương thích với Windows của bạn
    cmd = [
        "python", "idor_exploit.py",
        "-t", args.target,
        "-u", args.urls,
        "--session-cookie", f"{args.user1}={cookie1}",
        "--session-cookie", f"{args.user2}={cookie2}"
    ]
    
    # Chạy subprocess
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Có lỗi khi chạy idor_exploit.py: {e}")

if __name__ == "__main__":
    main()
