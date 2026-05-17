"""
create_demo_user.py — Crea el usuario de demostración automáticamente.
Ejecutado por init.bat. No requiere interacción del usuario.

Usuario demo: admin
Contraseña  : Admin123!
"""

import hashlib
import os
import json

_DIR         = os.path.dirname(os.path.abspath(__file__))
USERS_FILE   = os.path.join(_DIR, "data", "users.json")
PBKDF2_ITERS = 200_000

DEMO_USER = "admin"
DEMO_PASS = "Admin123!"


def _hash_password(password: str) -> tuple:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt.encode("utf-8"), PBKDF2_ITERS)
    return salt, dk.hex()


def main() -> None:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        users = {}

    if DEMO_USER in users:
        print(f"[INFO] El usuario '{DEMO_USER}' ya existe.")
        return

    salt, hashed = _hash_password(DEMO_PASS)
    users[DEMO_USER] = {"salt": salt, "hash": hashed}

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

    print(f"[OK] Usuario demo creado → usuario: {DEMO_USER} / contraseña: {DEMO_PASS}")


if __name__ == "__main__":
    main()
