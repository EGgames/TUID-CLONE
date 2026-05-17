"""Test firma digital: login -> GET /sign -> POST /sign"""
import urllib.request, urllib.parse, http.cookiejar, re

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
BASE = "http://localhost:8888"

# 1. Login
r = opener.open(BASE + "/")
tok = re.search(r'name="csrf_token" value="([^"]+)"', r.read().decode()).group(1)
data = urllib.parse.urlencode({"username":"admin","password":"Admin123!","csrf_token":tok}).encode()
req = urllib.request.Request(BASE+"/login", data=data,
    headers={"Content-Type":"application/x-www-form-urlencoded"})
opener.open(req)
print("1. Login OK")

# 2. GET /sign
r2 = opener.open(BASE + "/sign")
html2 = r2.read().decode()
print("2. GET /sign:", r2.getcode())
m = re.search(r'name="csrf_token" value="([^"]+)"', html2)
if not m:
    print("   ERROR: sin CSRF en pagina sign")
    exit(1)
csrf2 = m.group(1)
print("   CSRF:", csrf2[:20]+"...")

# 3. POST /sign
data2 = urllib.parse.urlencode({"csrf_token":csrf2,"text":"Prueba de firma digital"}).encode()
req2 = urllib.request.Request(BASE+"/sign", data=data2,
    headers={"Content-Type":"application/x-www-form-urlencoded"})
r3 = opener.open(req2)
html3 = r3.read().decode()
print("3. POST /sign:", r3.getcode())
if 'display:flex' in html3 and 'signResult' in html3:
    signer = re.search(r'id="signerVal"[^>]*>([^<]+)', html3)
    token = re.search(r'id="tokenVal"[^>]*>\s*([^\s<][^<]*)', html3)
    print("   FIRMA OK - firmante:", signer.group(1) if signer else "?")
    print("   Token (inicio):", (token.group(1)[:40]+"...") if token else "?")
elif 'display:flex' in html3 and 'signErr' in html3:
    print("   FIRMA FALLIDA - error mostrado en pagina")
else:
    print("   ESTADO DESCONOCIDO")
    # Debug: buscar signResult/signErr
    idx = html3.find('signResult')
    if idx > 0: print("   signResult ctx:", html3[idx-50:idx+80])
    idx2 = html3.find('signErr')
    if idx2 > 0: print("   signErr ctx:", html3[idx2-50:idx2+80])
