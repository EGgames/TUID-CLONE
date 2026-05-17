"""
Wrapper que actúa como auth.py para ver exactamente qué recibe el servidor C.
Coloca temporalmente este archivo como security/auth.py para depurar.
"""
import sys, os, json

_DIR = os.path.dirname(os.path.abspath(__file__))
LOG  = os.path.join(_DIR, "data", "auth_debug.log")

raw = sys.stdin.read()

with open(LOG, "a", encoding="utf-8") as f:
    f.write(f"=== STDIN ===\n{repr(raw)}\n\n")

# Ahora delegar al auth.py real
import importlib.util
spec = importlib.util.spec_from_file_location("auth_real", os.path.join(_DIR, "_auth_real.py"))
mod  = importlib.util.load_from_spec(spec) if hasattr(importlib.util, 'load_from_spec') else None

# O simplemente copiar la lógica de verificación:
import hashlib, hmac

try:
    data = json.loads(raw)
except:
    print(json.dumps({"status": "error", "message": "bad json"}))
    sys.exit(1)

username = data.get("username", "")
password = data.get("password", "")

with open(LOG, "a", encoding="utf-8") as f:
    f.write(f"username={repr(username)}\npassword={repr(password)}\n\n")

print(json.dumps({"status": "debug", "username": username, "password": password}), flush=True)
