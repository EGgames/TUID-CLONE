"""
auth.py — Módulo de seguridad principal
========================================
Responsabilidades:
  · Validación y saneamiento de entradas
  · Verificación de contraseña con PBKDF2-SHA256
  · Protección anti fuerza bruta (rate limiting por usuario)
  · Prevención de timing attacks (hmac.compare_digest)
  · Prevención de enumeración de usuarios (mismo mensaje de error)

Invocado por el servidor C mediante popen, lee JSON de stdin y
escribe JSON en stdout.
"""

import sys
import json
import hashlib
import hmac
import os
import time
import secrets
import contextlib

# ── Rutas de archivos ────────────────────────────────────────────────
_DIR          = os.path.dirname(os.path.abspath(__file__))
USERS_FILE    = os.path.join(_DIR, "data", "users.json")
ATTEMPTS_FILE = os.path.join(_DIR, "data", "attempts.json")
SESSIONS_FILE = os.path.join(_DIR, "data", "sessions.json")

# ── Configuración de sesiones ─────────────────────────────────────────
SESSION_EXPIRY = 3600   # segundos (1 hora)

# ── Configuración de seguridad ───────────────────────────────────────
MAX_ATTEMPTS  = 5        # intentos fallidos antes del bloqueo
LOCKOUT_SECS  = 300      # duración del bloqueo (5 minutos)
PBKDF2_ITERS  = 200_000  # iteraciones PBKDF2 (NIST SP 800-132 recomienda ≥ 10k)
PBKDF2_ALGO   = "sha256"

# ── Utilidades de E/S ─────────────────────────────────────────────────

def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return default


def _save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ── Exclusión mutua para attempts.json (MEDIA-04) ─────────────────────────

@contextlib.contextmanager
def _attempts_lock():
    """Filesystem lock para attempts.json: previene race conditions entre threads."""
    lockfile = ATTEMPTS_FILE + ".lock"
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
                break  # Fallar abierto: no bloquear el servidor indefinidamente
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            os.remove(lockfile)
        except OSError:
            pass


# ── Validación de entradas ────────────────────────────────────────────

def _is_safe_string(value) -> bool:
    """Acepta solo strings de caracteres ASCII imprimibles (32–126), longitud 1-128."""
    if not isinstance(value, str):
        return False
    if not (1 <= len(value) <= 128):
        return False
    return all(32 <= ord(c) <= 126 for c in value)


# ── Rate limiting ─────────────────────────────────────────────────────

def _check_rate_limit(username: str) -> tuple:
    """
    Devuelve (permitido: bool, mensaje: str).
    Si la cuenta está bloqueada, devuelve (False, mensaje con tiempo restante).
    """
    with _attempts_lock():
        attempts = _load_json(ATTEMPTS_FILE, {})
        entry = attempts.get(username, {"count": 0, "since": 0.0})
        now = time.time()

        if entry["count"] >= MAX_ATTEMPTS:
            elapsed = now - entry["since"]
            if elapsed < LOCKOUT_SECS:
                remaining = int(LOCKOUT_SECS - elapsed)
                mins = remaining // 60
                secs = remaining % 60
                return False, f"Cuenta bloqueada. Intenta en {mins}m {secs}s."
            # El bloqueo expiró → reiniciar
            entry = {"count": 0, "since": now}
            attempts[username] = entry
            _save_json(ATTEMPTS_FILE, attempts)

        return True, ""


def _record_failed(username: str) -> None:
    with _attempts_lock():
        attempts = _load_json(ATTEMPTS_FILE, {})
        entry = attempts.get(username, {"count": 0, "since": 0.0})

        if entry["count"] == 0:
            entry["since"] = time.time()
        entry["count"] += 1
        attempts[username] = entry
        _save_json(ATTEMPTS_FILE, attempts)


def _reset_attempts(username: str) -> None:
    with _attempts_lock():
        attempts = _load_json(ATTEMPTS_FILE, {})
        if username in attempts:
            del attempts[username]
            _save_json(ATTEMPTS_FILE, attempts)


# ── Verificación de contraseña ────────────────────────────────────────

def _verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """
    Deriva la clave con PBKDF2-HMAC-SHA256 y compara con compare_digest
    para evitar ataques de timing.
    """
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_ALGO,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERS
    )
    return hmac.compare_digest(dk.hex(), stored_hash)


# ── Punto de entrada ──────────────────────────────────────────────────

def main() -> None:
    # 1. Leer y parsear JSON desde stdin
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({
            "status": "error",
            "message": "Formato de solicitud inválido"
        }))
        return

    username = data.get("username", "")
    password = data.get("password", "")

    # 2. Validar entradas
    if not _is_safe_string(username) or not _is_safe_string(password):
        print(json.dumps({
            "status": "error",
            "message": "Las credenciales contienen caracteres no permitidos"
        }))
        return

    # 3. Comprobar rate limit
    allowed, lock_msg = _check_rate_limit(username)
    if not allowed:
        print(json.dumps({"status": "error", "message": lock_msg}))
        return

    # 4. Cargar base de datos de usuarios
    users = _load_json(USERS_FILE, {})

    # 5. Verificar credenciales
    #    IMPORTANTE: misma rama de código para usuario inexistente y contraseña
    #    incorrecta → evita enumeración de usuarios.
    valid = False
    if username in users:
        user = users[username]
        valid = _verify_password(password, user["salt"], user["hash"])

    if valid:
        _reset_attempts(username)
        # Generar token de sesión seguro
        token = secrets.token_hex(32)
        sessions = _load_json(SESSIONS_FILE, {})
        # Purgar sesiones expiradas antes de añadir la nueva (MEDIA-02)
        now_ts = time.time()
        sessions = {k: v for k, v in sessions.items() if v.get("expires", 0) > now_ts}
        sessions[token] = {
            "username": username,
            "expires": now_ts + SESSION_EXPIRY
        }
        _save_json(SESSIONS_FILE, sessions)
        print(json.dumps({
            "status": "ok",
            "message": f"¡Bienvenido, {username}!",
            "token": token
        }))
    else:
        _record_failed(username)
        print(json.dumps({
            "status": "error",
            "message": "Usuario o contraseña incorrectos"
        }))


if __name__ == "__main__":
    main()
