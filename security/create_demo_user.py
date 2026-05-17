"""
create_demo_user.py — Crea el usuario de demostración automáticamente.
Ejecutado por init.bat. No requiere interacción del usuario.

Usuario demo: admin
Contraseña  : Admin123!
"""

import hashlib
import os

import db

PBKDF2_ITERS = 200_000

DEMO_USER = "admin"
DEMO_PASS = "Admin123!"


def _hash_password(password: str) -> tuple:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt.encode("utf-8"), PBKDF2_ITERS)
    return salt, dk.hex()


def main() -> None:
    if db.user_exists(DEMO_USER):
        print(f"[INFO] El usuario '{DEMO_USER}' ya existe.")
        return

    salt, hashed = _hash_password(DEMO_PASS)
    db.create_user(DEMO_USER, salt, hashed)
    print(f"[OK] Usuario demo creado → usuario: {DEMO_USER} / contraseña: {DEMO_PASS}")


if __name__ == "__main__":
    main()
