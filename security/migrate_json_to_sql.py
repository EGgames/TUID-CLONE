"""
migrate_json_to_sql.py — Migración única de JSON → SQLite
==========================================================
Ejecutar UNA sola vez desde la raíz del proyecto:
    python security/migrate_json_to_sql.py

Lee los archivos JSON existentes y los importa a app.db sin perder datos.
Los archivos JSON originales NO se eliminan (quedan como respaldo).

Nota: si la BD ya contiene datos de un usuario, se omite silenciosamente
      (INSERT OR IGNORE) para evitar duplicados en caso de re-ejecución.
"""

import json
import os
import sys

# Añadir directorio security al path para importar db
_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

import db  # noqa: E402  (importación después de sys.path)

USERS_FILE    = os.path.join(_DIR, "data", "users.json")
SESSIONS_FILE = os.path.join(_DIR, "data", "sessions.json")
ATTEMPTS_FILE = os.path.join(_DIR, "data", "attempts.json")


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError) as exc:
        print(f"  [AVISO] No se pudo leer {path}: {exc}")
        return default


def migrate_users() -> None:
    print("\n[1/3] Migrando usuarios...")
    data = _load_json(USERS_FILE, {})
    if not data:
        print("  Sin datos en users.json.")
        return

    ok = skip = 0
    with db.get_conn() as conn:
        for username, fields in data.items():
            salt  = fields.get("salt", "")
            hash_ = fields.get("hash", "")
            ci    = fields.get("ci") or None

            if not salt or not hash_:
                print(f"  [OMITIDO] '{username}': faltan salt/hash.")
                skip += 1
                continue

            try:
                conn.execute(
                    "INSERT OR IGNORE INTO users (username, salt, hash, ci)"
                    " VALUES (?, ?, ?, ?)",
                    (username, salt, hash_, ci)
                )
                ok += 1
            except Exception as exc:
                print(f"  [ERROR] '{username}': {exc}")
                skip += 1

    print(f"  → {ok} insertados, {skip} omitidos.")


def migrate_sessions() -> None:
    print("\n[2/3] Migrando sesiones...")
    data = _load_json(SESSIONS_FILE, {})
    if not data:
        print("  Sin datos en sessions.json.")
        return

    ok = skip = 0
    with db.get_conn() as conn:
        for token, fields in data.items():
            username = fields.get("username", "")
            expires  = fields.get("expires", 0.0)

            if not username or not expires:
                skip += 1
                continue

            # Verificar que el usuario exista en la BD antes de insertar
            user_row = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user_row:
                print(f"  [OMITIDO] sesión de '{username}': usuario no encontrado.")
                skip += 1
                continue

            try:
                conn.execute(
                    "INSERT OR IGNORE INTO sessions (token, username, expires)"
                    " VALUES (?, ?, ?)",
                    (token, username, expires)
                )
                ok += 1
            except Exception as exc:
                print(f"  [ERROR] token {token[:16]}…: {exc}")
                skip += 1

    print(f"  → {ok} insertadas, {skip} omitidas.")


def migrate_attempts() -> None:
    print("\n[3/3] Migrando intentos de login...")
    data = _load_json(ATTEMPTS_FILE, {})
    if not data:
        print("  Sin datos en attempts.json.")
        return

    ok = skip = 0
    with db.get_conn() as conn:
        for username, fields in data.items():
            count = fields.get("count", 0)
            since = fields.get("since", 0.0)

            try:
                conn.execute(
                    "INSERT OR IGNORE INTO login_attempts (username, count, since)"
                    " VALUES (?, ?, ?)",
                    (username, count, since)
                )
                ok += 1
            except Exception as exc:
                print(f"  [ERROR] '{username}': {exc}")
                skip += 1

    print(f"  → {ok} insertados, {skip} omitidos.")


def main() -> None:
    print("=" * 55)
    print("  Migración JSON → SQLite")
    print(f"  Base de datos: {db.DB_PATH}")
    print("=" * 55)

    migrate_users()
    migrate_sessions()
    migrate_attempts()

    print("\n[OK] Migración completada.")
    print("     Los archivos JSON originales se conservan como respaldo.")
    print("     Puedes renombrarlos a .bak una vez verificado el sistema.")


if __name__ == "__main__":
    main()
