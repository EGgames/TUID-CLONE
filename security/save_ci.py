"""
save_ci.py - Guardado de Cédula de Identidad (operación única e inmutable)
===========================================================================
Lee JSON desde stdin: {"username": "...", "ci": "..."}
Escribe JSON en stdout: {"status": "ok"} o {"status": "error", "code": N}

Códigos de error:
  1 = Formato de CI inválido
  2 = El usuario ya tiene CI registrado (operación bloqueada por inmutabilidad)
  5 = Error interno del servidor
"""

import sys
import json
import os
import re
import hashlib
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import db

# CI en reposo (INFO-01): passphrase desde env var o archivo .keymaster
def _load_key_passphrase() -> "bytes | None":
    _dir = os.path.dirname(os.path.abspath(__file__))
    env_val = os.environ.get("KEY_ENCRYPTION_KEY", "").strip()
    if env_val:
        return env_val.encode("utf-8")
    keymaster = os.path.join(_dir, "data", ".keymaster")
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

ERR_INVALID_FORMAT = 1
ERR_CI_ALREADY_SET = 2
ERR_SERVER         = 5


def _is_valid_ci(ci: str) -> bool:
    if not isinstance(ci, str):
        return False
    ci_nodots = ci.strip().replace(".", "")
    return bool(re.fullmatch(r"\d{7,8}-[0-9Kk]", ci_nodots))


def _normalize_ci(ci: str) -> str:
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


def main() -> None:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({"status": "error", "code": ERR_INVALID_FORMAT}))
        return

    username = data.get("username", "")
    ci       = data.get("ci", "")

    if not isinstance(username, str) or not username:
        print(json.dumps({"status": "error", "code": ERR_SERVER}))
        return

    if not _is_valid_ci(ci):
        print(json.dumps({"status": "error", "code": ERR_INVALID_FORMAT}))
        return

    ci_normalized = _normalize_ci(ci)

    # Verificar que el usuario existe
    if not db.user_exists(username):
        print(json.dumps({"status": "error", "code": ERR_SERVER}))
        return

    # Cifrar CI en reposo si hay passphrase configurada (INFO-01)
    ci_to_store = _encrypt_ci(ci_normalized, _KEY_PASSPHRASE) if _KEY_PASSPHRASE else ci_normalized

    # update_user_ci usa WHERE ci IS NULL → garantiza inmutabilidad en la BD
    if not db.update_user_ci(username, ci_to_store):
        print(json.dumps({"status": "error", "code": ERR_CI_ALREADY_SET}))
        return

    print(json.dumps({"status": "ok"}))


if __name__ == "__main__":
    main()
