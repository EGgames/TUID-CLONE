"""
setup_users.py — Herramienta interactiva para gestionar usuarios
================================================================
Uso:
  python security/setup_users.py          → crear usuario
  python security/setup_users.py --list   → listar usuarios
  python security/setup_users.py --delete → eliminar usuario
"""

import hashlib
import os
import sys
import getpass
import hmac

import db

PBKDF2_ITERS = 200_000
PBKDF2_ALGO  = "sha256"

MIN_PASS_LEN = 8
MIN_USER_LEN = 3
MAX_USER_LEN = 64
MAX_PASS_LEN = 128

# ── Helpers ───────────────────────────────────────────────────────────

def _hash_password(password: str) -> tuple:
    """Devuelve (salt_hex, pbkdf2_hex)."""
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_ALGO,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERS
    )
    return salt, dk.hex()


def _validate_username(username: str) -> str | None:
    """Devuelve None si es válido, o el mensaje de error."""
    if len(username) < MIN_USER_LEN:
        return f"Mínimo {MIN_USER_LEN} caracteres."
    if len(username) > MAX_USER_LEN:
        return f"Máximo {MAX_USER_LEN} caracteres."
    if not all(c.isalnum() or c in '_-.' for c in username):
        return "Solo letras, números, '_', '-' y '.'."
    return None


def _validate_password(password: str) -> str | None:
    if len(password) < MIN_PASS_LEN:
        return f"Mínimo {MIN_PASS_LEN} caracteres."
    if len(password) > MAX_PASS_LEN:
        return f"Máximo {MAX_PASS_LEN} caracteres."
    return None

# ── Acciones ──────────────────────────────────────────────────────────

def cmd_create() -> None:
    print("\n── Crear nuevo usuario ──────────────────────")
    username = input("Usuario   : ").strip()
    err = _validate_username(username)
    if err:
        print(f"[ERROR] {err}")
        sys.exit(1)

    if db.user_exists(username):
        print(f"[ERROR] El usuario '{username}' ya existe.")
        sys.exit(1)

    password  = getpass.getpass("Contraseña: ")
    password2 = getpass.getpass("Confirmar : ")

    if password != password2:
        print("[ERROR] Las contraseñas no coinciden.")
        sys.exit(1)

    err = _validate_password(password)
    if err:
        print(f"[ERROR] {err}")
        sys.exit(1)

    salt, hashed = _hash_password(password)
    db.create_user(username, salt, hashed)
    print(f"[OK] Usuario '{username}' creado correctamente.")


def cmd_list() -> None:
    rows = db.list_users()
    if not rows:
        print("No hay usuarios registrados.")
        return
    print(f"\n{'Usuario':<30}  Hash (primeros 16 chars)")
    print("-" * 55)
    for row in rows:
        print(f"  {row['username']:<28}  {row['hash'][:16]}…")


def cmd_delete() -> None:
    print("\n── Eliminar usuario ─────────────────────────")
    username = input("Usuario a eliminar: ").strip()
    if not db.user_exists(username):
        print(f"[ERROR] El usuario '{username}' no existe.")
        sys.exit(1)
    confirm = input(f"¿Confirmar eliminación de '{username}'? (s/N): ").strip().lower()
    if confirm != 's':
        print("Operación cancelada.")
        return
    db.delete_user(username)
    print(f"[OK] Usuario '{username}' eliminado.")

# ── Menú principal ────────────────────────────────────────────────────

def main() -> None:
    print("╔═══════════════════════════════════════╗")
    print("║   Gestión de Usuarios del Sistema     ║")
    print("╚═══════════════════════════════════════╝")

    args = sys.argv[1:]
    if "--list" in args:
        cmd_list()
    elif "--delete" in args:
        cmd_delete()
    else:
        cmd_create()


if __name__ == "__main__":
    main()
