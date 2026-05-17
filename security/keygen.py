"""
keygen.py — Generación de par de claves RSA-2048 por usuario
=============================================================
Lee JSON desde stdin: {"username": "..."}
Escribe JSON en stdout: {"status": "ok"} o {"status": "error", "code": N}

Códigos de error:
  1 = Entrada inválida
  2 = Claves ya existen (idempotente: no sobreescribe)
  5 = Error interno
"""

import sys
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

_DIR      = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR  = os.path.join(_DIR, "data", "keys")

# Cifrado de clave privada (ALTA-02): passphrase leída de env var o archivo .keymaster
def _load_key_passphrase() -> "bytes | None":
    """Lee passphrase de KEY_ENCRYPTION_KEY (env) o de data/.keymaster (archivo)."""
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

ERR_INVALID_INPUT = 1
ERR_KEY_EXISTS    = 2
ERR_SERVER        = 5


def generate_keys(username: str) -> dict:
    """
    Genera y guarda el par RSA-2048 para 'username'.
    Retorna {"status": "ok"} o {"status": "error", "code": N}.
    Es idempotente: si las claves ya existen devuelve ERR_KEY_EXISTS.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    pub_path  = os.path.join(KEYS_DIR, f"{username}_public.pem")

    if os.path.exists(priv_path):
        return {"status": "error", "code": ERR_KEY_EXISTS}

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(_KEY_PASSPHRASE)
                if _KEY_PASSPHRASE else serialization.NoEncryption()
            ),
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        tmp = priv_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(priv_pem)
        os.replace(tmp, priv_path)

        tmp = pub_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(pub_pem)
        os.replace(tmp, pub_path)

        return {"status": "ok"}
    except Exception:
        return {"status": "error", "code": ERR_SERVER}


def main() -> None:
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    username = data.get("username", "")
    if not isinstance(username, str) or not (1 <= len(username) <= 64):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    result = generate_keys(username)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
