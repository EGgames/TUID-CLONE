"""Test de login sin seguir redirecciones — para ver el 302 directamente."""
import http.client, urllib.parse, re

# 1. GET / para obtener CSRF
conn = http.client.HTTPConnection("localhost", 8888)
conn.request("GET", "/")
r = conn.getresponse()
html = r.read().decode("utf-8")
conn.close()

m = re.search(r'name="csrf_token"\s+value="([0-9a-f]+)"', html)
csrf = m.group(1) if m else "NO_CSRF"
print(f"CSRF: {csrf[:20]}... len={len(csrf)}")

# 2. POST /login  (SIN seguir redirecciones)
body = urllib.parse.urlencode({
    "username": "admin",
    "password": "Admin123!",
    "csrf_token": csrf
})
print(f"Body: {body[:80]}...")

conn2 = http.client.HTTPConnection("localhost", 8888)
conn2.request("POST", "/login", body=body,
               headers={"Content-Type": "application/x-www-form-urlencoded"})
r2 = conn2.getresponse()
resp_body = r2.read().decode("utf-8", errors="replace")
print(f"\nStatus: {r2.status} {r2.reason}")
for k, v in r2.getheaders():
    print(f"  {k}: {v}")

# Diagnostico
if r2.status == 302:
    print("\n=> LOGIN EXITOSO — el servidor redirige al dashboard")
elif r2.status == 403:
    print("\n=> CSRF RECHAZADO — token inválido o expirado")
elif r2.status == 200:
    has_error = 'display:flex' in resp_body and 'loginError' in resp_body
    print(f"\n=> LOGIN FALLIDO — página de error mostrada: {has_error}")
    # Imprimir la parte con el div de error
    idx = resp_body.find("loginError")
    if idx != -1:
        print(resp_body[max(0,idx-30):idx+100])
conn2.close()
