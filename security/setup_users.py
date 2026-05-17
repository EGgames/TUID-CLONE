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
import json
import getpass
import hmac

_DIR       = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(_DIR, "data", "users.json")

PBKDF2_ITERS = 200_000
PBKDF2_ALGO  = "sha256"

MIN_PASS_LEN = 8
MIN_USER_LEN = 3
MAX_USER_LEN = 64
MAX_PASS_LEN = 128

# ── Helpers ───────────────────────────────────────────────────────────

def _load_users() -> dict:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_users(users: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


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

    users = _load_users()
    if username in users:
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
    users[username] = {"salt": salt, "hash": hashed}
    _save_users(users)
    print(f"[OK] Usuario '{username}' creado correctamente.")


def cmd_list() -> None:
    users = _load_users()
    if not users:
        print("No hay usuarios registrados.")
        return
    print(f"\n{'Usuario':<30}  Hash (primeros 16 chars)")
    print("-" * 55)
    for name, data in users.items():
        print(f"  {name:<28}  {data['hash'][:16]}…")


def cmd_delete() -> None:
    print("\n── Eliminar usuario ─────────────────────────")
    username = input("Usuario a eliminar: ").strip()
    users = _load_users()
    if username not in users:
        print(f"[ERROR] El usuario '{username}' no existe.")
        sys.exit(1)
    confirm = input(f"¿Confirmar eliminación de '{username}'? (s/N): ").strip().lower()
    if confirm != 's':
        print("Operación cancelada.")
        return
    del users[username]
    _save_users(users)
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
