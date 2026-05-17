"""
register.py - Modulo de registro de usuarios
==============================================
Lee JSON desde stdin: {"username": "...", "password": "..."}
Escribe JSON en stdout: {"status": "ok"} o {"status": "error", "code": N}

Codigos de error (coinciden con los divs del frontend):
  1 = Datos de entrada invalidos (caracteres no permitidos o formato incorrecto)
  2 = Nombre de usuario ya existe
  3 = Contrasena demasiado debil
  5 = Error interno del servidor
  6 = Numero de cedula de identidad invalido

Nota: el codigo 4 (contrasenas no coinciden) lo valida el servidor C
antes de llamar a este modulo.
"""

import sys
import json
import hashlib
import secrets
import os
import re
import time
import base64
import contextlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from keygen import generate_keys

# -- Rutas de archivos ---------------------------------------------------
_DIR       = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(_DIR, "data", "users.json")

# -- Configuracion de seguridad ------------------------------------------
PBKDF2_ITERS = 200_000   # Igual que auth.py (NIST SP 800-132)
PBKDF2_ALGO  = "sha256"

# CI en reposo (INFO-01): passphrase desde env var o archivo .keymaster
def _load_key_passphrase() -> "bytes | None":
    env_val = os.environ.get("KEY_ENCRYPTION_KEY", "").strip()
    if env_val:
        return env_val.encode("utf-8")
    keymaster = os.path.join(_DIR, "data", ".keymaster")
    try:
        with open(keymaster, "rb") as f:
            val = f.read().strip()
            return val if val else None
    except FileNotFoundError:
        return None

_KEY_PASSPHRASE = _load_key_passphrase()


def _encrypt_ci(ci: str, passphrase: bytes) -> str:
    """Cifra CI con AES-256-GCM. Devuelve 'enc:<base64(iv+ct)>'."""
    key = hashlib.sha256(passphrase).digest()
    iv  = secrets.token_bytes(12)
    ct  = AESGCM(key).encrypt(iv, ci.encode("utf-8"), None)
    return "enc:" + base64.b64encode(iv + ct).decode("ascii")

# -- Codigos de error (deben coincidir con los IDs del HTML) -------------
ERR_INVALID_INPUT = 1
ERR_USER_EXISTS   = 2
ERR_WEAK_PASSWORD = 3
ERR_SERVER        = 5
ERR_INVALID_CI    = 6


# -- Utilidades de E/S ---------------------------------------------------

def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return default


def _save_json_atomic(path: str, data) -> None:
    """Escribe en archivo temporal y renombra para evitar corrupcion."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# -- File locking para users.json (MEDIA-04 / TOCTOU) -------------------

@contextlib.contextmanager
def _users_lock():
    """Exclusión mutua para users.json mediante archivo .lock."""
    lockfile = USERS_FILE + ".lock"
    deadline = time.monotonic() + 5.0
    while True:
        try:
            fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.monotonic() - os.path.getmtime(lockfile) > 30:
                    os.remove(lockfile)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                break
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            os.remove(lockfile)
        except OSError:
            pass


# -- Validacion de entradas ----------------------------------------------

def _is_safe_string(value) -> bool:
    """Solo acepta strings ASCII imprimibles (32-126), longitud 1-128."""
    if not isinstance(value, str):
        return False
    if not (1 <= len(value) <= 128):
        return False
    return all(32 <= ord(c) <= 126 for c in value)


def _is_valid_username(u: str) -> bool:
    """
    Nombre de usuario: 3-32 caracteres.
    Solo letras ASCII, digitos, guion, guion bajo y punto.
    No puede empezar ni terminar con punto o guion.
    No puede ser puramente numerico (evita usernames de bot automatizados).
    """
    if not (3 <= len(u) <= 32):
        return False
    if re.fullmatch(r'\d+', u):           # bloquear nombres 100% numéricos
        return False
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_\-\.]*[a-zA-Z0-9]|[a-zA-Z0-9]', u):
        return False
    return True


def _is_valid_ci(ci: str) -> bool:
    """
    Acepta formatos de CI:
      Con puntos:    1.234.567-8   12.345.678-K
      Sin puntos:    1234567-8     12345678-K
    El dígito verificador puede ser 0-9 o K/k.
    Solo valida el formato; no aplica algoritmo mod-11 para no rechazar
    CIs válidos emitidos con distintos estándares.
    """
    if not isinstance(ci, str):
        return False
    ci_nodots = ci.strip().replace(".", "")
    return bool(re.fullmatch(r"\d{7,8}-[0-9Kk]", ci_nodots))


def _validate_rut_checkdigit(num_str: str, check: str) -> bool:
    """Verifica el dígito verificador del RUT chileno con algoritmo módulo 11."""
    try:
        digits = [int(d) for d in reversed(num_str)]
        factors = [2, 3, 4, 5, 6, 7]
        total = sum(d * factors[i % 6] for i, d in enumerate(digits))
        remainder = 11 - (total % 11)
        if remainder == 11:
            expected = "0"
        elif remainder == 10:
            expected = "K"
        else:
            expected = str(remainder)
        return check.upper() == expected
    except Exception:
        return False


def _normalize_ci(ci: str) -> str:
    """Normaliza a formato N.NNN.NNN-D para almacenamiento uniforme."""
    ci = ci.strip().upper()
    ci_nodots = ci.replace(".", "")
    parts = ci_nodots.split("-")
    if len(parts) != 2:
        return ci
    num, check = parts
    if len(num) == 7:
        return f"{num[0]}.{num[1:4]}.{num[4:]}-{check}"
    elif len(num) == 8:
        return f"{num[0:2]}.{num[2:5]}.{num[5:]}-{check}"
    return ci


def _is_strong_password(p: str) -> bool:
    """
    Contrasena fuerte:
      - Minimo 8 caracteres
      - Al menos una letra mayuscula
      - Al menos una letra minuscula
      - Al menos un digito
      - Al menos un caracter especial (no alfanumerico)
    """
    if len(p) < 8:
        return False
    if not re.search(r'[A-Z]', p):
        return False
    if not re.search(r'[a-z]', p):
        return False
    if not re.search(r'[0-9]', p):
        return False
    if not re.search(r'[^a-zA-Z0-9]', p):
        return False
    return True


# -- Punto de entrada ----------------------------------------------------

def main() -> None:
    # 1. Leer y parsear JSON desde stdin
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    username = data.get("username", "")
    password = data.get("password", "")
    ci       = data.get("ci", "")

    # 2. Validar formato de entrada
    if not _is_safe_string(username) or not _is_safe_string(password):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    if not _is_valid_username(username):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    # 3. Validar fortaleza de contrasena
    if not _is_strong_password(password):
        print(json.dumps({"status": "error", "code": ERR_WEAK_PASSWORD}))
        return

    # 4. Validar formato de CI
    if not _is_valid_ci(ci):
        print(json.dumps({"status": "error", "code": ERR_INVALID_CI}))
        return

    ci_normalized = _normalize_ci(ci)
    # Cifrar CI en reposo si hay passphrase configurada (INFO-01)
    ci_to_store = _encrypt_ci(ci_normalized, _KEY_PASSPHRASE) if _KEY_PASSPHRASE else ci_normalized

    # 5-7. Comprobar unicidad y registrar dentro del lock para evitar TOCTOU (MEDIA-04)
    with _users_lock():
        users = _load_json(USERS_FILE, {})
        if username in users:
            print(json.dumps({"status": "error", "code": ERR_USER_EXISTS}))
            return

        # 6. Generar salt único y derivar hash PBKDF2
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac(
            PBKDF2_ALGO,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            PBKDF2_ITERS
        )

        # 7. Guardar usuario (escritura atómica para evitar corrupcion)
        users[username] = {
            "salt": salt,
            "hash": dk.hex(),
            "ci":   ci_to_store
        }

        try:
            _save_json_atomic(USERS_FILE, users)
        except (OSError, PermissionError):
            print(json.dumps({"status": "error", "code": ERR_SERVER}))
            return

    # 8. Generar par de claves RSA-2048 para firma digital (fuera del lock: operación lenta)
    generate_keys(username)

    print(json.dumps({"status": "ok"}))


if __name__ == "__main__":
    main()
