import urllib.request, urllib.parse, re

# 1. GET /  → obtener CSRF token
req = urllib.request.Request("http://localhost:8888/")
with urllib.request.urlopen(req) as r:
    html = r.read().decode("utf-8")

m = re.search(r'name="csrf_token"\s+value="([0-9a-f]+)"', html)
csrf = m.group(1) if m else "NO_CSRF"
print(f"CSRF token len={len(csrf)}: {csrf}")

# 2. POST /login con admin/Admin1234
body = urllib.parse.urlencode({
    "username": "admin",
    "password": "Admin123!",
    "csrf_token": csrf
}).encode()
print(f"Body: {body.decode()[:80]}...")

req2 = urllib.request.Request(
    "http://localhost:8888/login", data=body, method="POST"
)
req2.add_header("Content-Type", "application/x-www-form-urlencoded")

try:
    with urllib.request.urlopen(req2, timeout=10) as r2:
        print(f"Status: {r2.status}")
        for k, v in r2.headers.items():
            print(f"  {k}: {v}")
except urllib.error.HTTPError as e:
    body_resp = e.read().decode()
    print(f"HTTPError: {e.code} {e.reason}")
    print(f"Body: {body_resp[:200]}")
except Exception as ex:
    print(f"Error: {ex}")
