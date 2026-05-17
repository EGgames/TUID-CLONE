import urllib.request, urllib.parse, urllib.error

# Test 1: login INCORRECTO → espera redirect a /?err=1
data = urllib.parse.urlencode({'username': 'admin', 'password': 'WRONGPASS'}).encode()
req = urllib.request.Request('http://localhost:8888/login', data=data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'})
try:
    r = urllib.request.urlopen(req)
    print("FAIL: 200 OK (esperaba redirect)")
except urllib.error.HTTPError as e:
    loc = e.headers.get('Location', '(sin location)')
    print(f"Test 1 (creds malas) → HTTP {e.code}, Location: {loc}")
    if loc == '/?err=1':
        print("  OK: redirige a /?err=1")
    else:
        print("  FAIL: location incorrecta")

# Test 2: login CORRECTO → espera redirect a /dashboard con cookie
data2 = urllib.parse.urlencode({'username': 'admin', 'password': 'Admin123!'}).encode()
req2 = urllib.request.Request('http://localhost:8888/login', data=data2,
    headers={'Content-Type': 'application/x-www-form-urlencoded'})
try:
    r2 = urllib.request.urlopen(req2)
    print("FAIL: 200 OK (esperaba redirect)")
except urllib.error.HTTPError as e2:
    loc2 = e2.headers.get('Location', '(sin location)')
    cookie = e2.headers.get('Set-Cookie', '(sin cookie)')
    print(f"Test 2 (creds buenas) → HTTP {e2.code}, Location: {loc2}")
    if loc2 == '/dashboard':
        print("  OK: redirige a /dashboard")
    else:
        print("  FAIL: location incorrecta")
    if 'session=' in cookie and 'HttpOnly' in cookie:
        print("  OK: cookie HttpOnly presente")
    else:
        print(f"  FAIL: cookie incorrecta: {cookie}")

# Test 3: el HTML de / NO tiene <script>
r3 = urllib.request.urlopen('http://localhost:8888/')
html = r3.read().decode()
if '<script' in html:
    print("FAIL: hay <script> en el HTML del login")
else:
    print("Test 3: OK - sin <script> en el HTML")

# Test 4: el HTML de /?err=1 tiene display:flex
r4 = urllib.request.urlopen('http://localhost:8888/?err=1')
html4 = r4.read().decode()
if 'display:flex' in html4:
    print("Test 4: OK - error visible inyectado por el servidor")
else:
    print("FAIL: error NO fue inyectado")
