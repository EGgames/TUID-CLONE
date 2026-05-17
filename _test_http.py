"""Test login via HTTP directo (port 8888) - verifica que cookie sin Secure funciona"""
import urllib.request, urllib.parse, http.cookiejar, re

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'Mozilla/5.0')]

BASE = "http://localhost:8888"

r1 = opener.open(BASE + "/")
html = r1.read().decode()
tok = re.search(r'name="csrf_token" value="([^"]+)"', html)
csrf_val = tok.group(1) if tok else ""
print("1. CSRF:", csrf_val[:20] + "..." if csrf_val else "NONE")

data = urllib.parse.urlencode({
    "username": "admin",
    "password": "Admin123!",
    "csrf_token": csrf_val
}).encode()
req = urllib.request.Request(BASE + "/login", data=data,
    headers={"Content-Type": "application/x-www-form-urlencoded"})
r2 = opener.open(req)
print("2. Status:", r2.getcode(), "URL:", r2.url)
body = r2.read().decode()
title = re.search(r"<title>([^<]+)</title>", body, re.I)
print("   Pagina:", title.group(1) if title else "sin titulo")
print("3. Cookies:")
for c in jar:
    print(f"   {c.name}={c.value[:20]}... secure={c.secure}")
