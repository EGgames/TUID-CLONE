"""
db.py — Capa de acceso a base de datos SQLite
==============================================
Reemplaza los archivos JSON (users.json, sessions.json, attempts.json).
Usa WAL journal mode para soportar accesos concurrentes sin file-locks.

Tablas:
  users          → credenciales de usuario (salt, hash PBKDF2, CI cifrada)
  sessions       → tokens de sesión activos
  login_attempts → conteo de intentos fallidos para rate limiting
"""

import sqlite3
import os

_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_DIR, "data", "app.db")


def get_conn() -> sqlite3.Connection:
    """Abre (o crea) la conexión a la base de datos con WAL mode."""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Crea las tablas si no existen (idempotente)."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt     TEXT NOT NULL,
                hash     TEXT NOT NULL,
                ci       TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token    TEXT PRIMARY KEY,
                username TEXT NOT NULL
                         REFERENCES users(username) ON DELETE CASCADE,
                expires  REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                count    INTEGER NOT NULL DEFAULT 0,
                since    REAL    NOT NULL DEFAULT 0
            );
        """)


# ── Usuarios ──────────────────────────────────────────────────────────

def get_user(username: str) -> "sqlite3.Row | None":
    with get_conn() as conn:
        return conn.execute(
            "SELECT username, salt, hash, ci FROM users WHERE username = ?",
            (username,)
        ).fetchone()


def user_exists(username: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row is not None


def create_user(username: str, salt: str, hash_: str,
                ci: "str | None" = None) -> bool:
    """
    Inserta un nuevo usuario de forma atómica.
    Devuelve False si el nombre de usuario ya existe (IntegrityError).
    """
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, hash, ci) VALUES (?, ?, ?, ?)",
                (username, salt, hash_, ci)
            )
        return True
    except sqlite3.IntegrityError:
        return False


def update_user_ci(username: str, ci: str) -> bool:
    """
    Actualiza la CI solo si el usuario existe Y aún no tiene CI asignada.
    Devuelve True si se actualizó, False en cualquier otro caso.
    La condición WHERE ci IS NULL garantiza inmutabilidad a nivel de BD.
    """
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET ci = ? WHERE username = ? AND ci IS NULL",
            (ci, username)
        )
        return cur.rowcount == 1


def delete_user(username: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        return cur.rowcount == 1


def list_users() -> list:
    with get_conn() as conn:
        return conn.execute(
            "SELECT username, hash FROM users ORDER BY username"
        ).fetchall()


# ── Sesiones ──────────────────────────────────────────────────────────

def create_session(token: str, username: str, expires: float) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token, username, expires)"
            " VALUES (?, ?, ?)",
            (token, username, expires)
        )


def get_session(token: str) -> "sqlite3.Row | None":
    with get_conn() as conn:
        return conn.execute(
            "SELECT username, expires FROM sessions WHERE token = ?",
            (token,)
        ).fetchone()


def purge_expired_sessions(now: float) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expires <= ?", (now,))


# ── Intentos de login ─────────────────────────────────────────────────

def get_attempts(username: str) -> "sqlite3.Row | None":
    with get_conn() as conn:
        return conn.execute(
            "SELECT count, since FROM login_attempts WHERE username = ?",
            (username,)
        ).fetchone()


def increment_attempts(username: str, now: float) -> None:
    """
    Registra un intento fallido.
    Primera vez: count=1, since=now.
    Siguientes:  count+1, since sin cambios (ventana fija desde el primer fallo).
    """
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO login_attempts (username, count, since)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET count = count + 1
            """,
            (username, now)
        )


def reset_attempts(username: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM login_attempts WHERE username = ?", (username,)
        )


# ── Inicialización automática al importar ────────────────────────────
init_db()
