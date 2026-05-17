"""Test end-to-end: login → redirect → dashboard"""
import urllib.request, urllib.parse, http.cookiejar, ssl, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPSHandler(context=ctx)
)
opener.addheaders = [('User-Agent', 'Mozilla/5.0')]

BASE = "https://localhost:8443"

# 1. GET login
r1 = opener.open(BASE + "/")
html = r1.read().decode()
tok = re.search(r'name="csrf_token" value="([^"]+)"', html)
csrf_val = tok.group(1) if tok else ""
print("1. CSRF extraido:", csrf_val[:20] + "..." if csrf_val else "NONE")
print("   Longitud CSRF:", len(csrf_val))

# 2. POST login — mostrar qué se envía exactamente
post_data = {
    "username": "admin",
    "password": "Admin123!",
    "csrf_token": csrf_val
}
encoded = urllib.parse.urlencode(post_data)
print("2. Body POST:", encoded[:80] + "..." if len(encoded) > 80 else encoded)

try:
    data = encoded.encode()
    req = urllib.request.Request(BASE + "/login", data=data,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    r2 = opener.open(req)
    print("   Status:", r2.getcode(), "URL final:", r2.url)
    body = r2.read().decode()
    title = re.search(r"<title>([^<]+)</title>", body, re.I)
    print("   Pagina:", title.group(1) if title else "(sin título)")
except Exception as e:
    print("   ERROR:", e)

# Cookies
print("3. Cookies:")
for c in jar:
    print(f"   {c.name}={c.value[:20]}... secure={c.secure}")

