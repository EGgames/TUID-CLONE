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

import db

# ── Configuración de sesiones ─────────────────────────────────────────
SESSION_EXPIRY = 3600   # segundos (1 hora)

# ── Configuración de seguridad ───────────────────────────────────────
MAX_ATTEMPTS  = 5        # intentos fallidos antes del bloqueo
LOCKOUT_SECS  = 300      # duración del bloqueo (5 minutos)
PBKDF2_ITERS  = 200_000  # iteraciones PBKDF2 (NIST SP 800-132 recomienda ≥ 10k)
PBKDF2_ALGO   = "sha256"


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
    SQLite garantiza atomicidad; no se necesitan file-locks.
    """
    row = db.get_attempts(username)
    now = time.time()

    if row and row["count"] >= MAX_ATTEMPTS:
        elapsed = now - row["since"]
        if elapsed < LOCKOUT_SECS:
            remaining = int(LOCKOUT_SECS - elapsed)
            mins = remaining // 60
            secs = remaining % 60
            return False, f"Cuenta bloqueada. Intenta en {mins}m {secs}s."
        # El bloqueo expiró → reiniciar
        db.reset_attempts(username)

    return True, ""


def _record_failed(username: str) -> None:
    db.increment_attempts(username, time.time())


def _reset_attempts(username: str) -> None:
    db.reset_attempts(username)


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

    # 4. Obtener usuario de la BD
    user = db.get_user(username)

    # 5. Verificar credenciales
    #    IMPORTANTE: misma rama de código para usuario inexistente y contraseña
    #    incorrecta → evita enumeración de usuarios.
    valid = False
    if user:
        valid = _verify_password(password, user["salt"], user["hash"])

    if valid:
        _reset_attempts(username)
        # Generar token de sesión seguro
        token = secrets.token_hex(32)
        now_ts = time.time()
        # Purgar sesiones expiradas antes de añadir la nueva (MEDIA-02)
        db.purge_expired_sessions(now_ts)
        db.create_session(token, username, now_ts + SESSION_EXPIRY)
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
