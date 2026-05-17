import urllib.request, urllib.parse, http.cookiejar, re, sys

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'Python/3')]
BASE = 'http://localhost:8888'

# 1. Login
html = opener.open(BASE + '/').read().decode()
csrf = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
data = urllib.parse.urlencode({'username': 'admin', 'password': 'Admin123!', 'csrf_token': csrf}).encode()
opener.open(urllib.request.Request(BASE + '/login', data, {'Content-Type': 'application/x-www-form-urlencoded'}))
print('1. Login OK')

# 2. Sign con texto largo (1200 chars)
html2 = opener.open(BASE + '/sign').read().decode()
csrf2 = re.search(r'name="csrf_token" value="([^"]+)"', html2).group(1)
text_largo = 'A' * 1200
data2 = urllib.parse.urlencode({'csrf_token': csrf2, 'text': text_largo}).encode()
r3 = opener.open(urllib.request.Request(BASE + '/sign', data2, {'Content-Type': 'application/x-www-form-urlencoded'}))
html3 = r3.read().decode()

if 'display:flex' in html3 and 'signResult' in html3:
    print('2. SIGN TEXTO LARGO (1200 chars): OK')
else:
    print('2. SIGN TEXTO LARGO: FALLO')
    sys.exit(1)

tok_match = re.search(r'id="tokenVal"[^>]*>(.*?)</textarea>', html3, re.DOTALL)
token = tok_match.group(1).strip() if tok_match else ''
print(f'   Token len={len(token)}, inicio: {token[:50]}...')

# 3. Verify con ese token
html_v = opener.open(BASE + '/verify').read().decode()
data3 = urllib.parse.urlencode({'csrf_token': '__CSRF_TOKEN__', 'token': token}).encode()
r4 = opener.open(urllib.request.Request(BASE + '/verify', data3, {'Content-Type': 'application/x-www-form-urlencoded'}))
html4 = r4.read().decode()

if 'display:flex' in html4 and 'verifyResult' in html4:
    if 'V&Aacute;LIDA' in html4 or 'VALIDA' in html4.upper():
        print('3. VERIFY: OK - Firma VALIDA')
    else:
        print('3. VERIFY: resultado mostrado pero firma INVALIDA')
elif 'verifyErr' in html4 and 'display:flex' in html4:
    print('3. VERIFY: FALLO - muestra error token invalido')
else:
    print('3. VERIFY: estado desconocido')

# 4. CSP header
resp_csp = opener.open(urllib.request.Request(BASE + '/'))
csp = resp_csp.headers.get('Content-Security-Policy', 'NO CSP')
print('4. CSP:', csp)
has_blob = "blob:" in csp
print('   blob: en CSP:', has_blob)
