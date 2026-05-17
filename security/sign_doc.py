"""
sign_doc.py — Firma digital RSA-2048 PSS/SHA-256
==================================================
Lee JSON desde stdin: {"username": "...", "text": "..."}
Escribe JSON en stdout:
  OK:    {"status": "ok", "signer": "...", "ci": "...", "timestamp": "...",
          "text": "...", "token": "<base64_verif_token>"}
  Error: {"status": "error", "code": N}

Códigos de error:
  1 = Entrada inválida o texto vacío
  3 = Claves RSA no encontradas para el usuario
  5 = Error interno
"""

import sys
import json
import os
import base64
import hashlib
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DIR       = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR   = os.path.join(_DIR, "data", "keys")
USERS_FILE = os.path.join(_DIR, "data", "users.json")

# Cifrado de clave privada (ALTA-02) y CI en reposo (INFO-01)
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


def _decrypt_ci(enc_ci: str, passphrase: bytes) -> str:
    """Descifra CI almacenado con AES-256-GCM. Retrocompat. con CI en texto plano."""
    if not enc_ci.startswith("enc:"):
        return enc_ci
    key = hashlib.sha256(passphrase).digest()
    data = base64.b64decode(enc_ci[4:].encode("ascii"))
    iv, ct = data[:12], data[12:]
    return AESGCM(key).decrypt(iv, ct, None).decode("utf-8")

ERR_INVALID_INPUT = 1
ERR_NO_KEY        = 3
ERR_SERVER        = 5

MAX_TEXT_LEN = 2000  # caracteres


def _get_user_ci(username: str) -> str:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
        ci_raw = users.get(username, {}).get("ci", "") or ""
        if ci_raw and _KEY_PASSPHRASE:
            return _decrypt_ci(ci_raw, _KEY_PASSPHRASE)
        return ci_raw
    except Exception:
        return ""


def sign_text(username: str, text: str) -> dict:
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    if not os.path.exists(priv_path):
        return {"status": "error", "code": ERR_NO_KEY}

    try:
        with open(priv_path, "rb") as f:
            key_bytes = f.read()
        try:
            private_key = serialization.load_pem_private_key(key_bytes, password=_KEY_PASSPHRASE)
        except (ValueError, TypeError):
            # Compatibilidad retroactiva con claves no cifradas generadas antes de ALTA-02
            private_key = serialization.load_pem_private_key(key_bytes, password=None)

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ci = _get_user_ci(username)

        # Payload determinístico — debe ser idéntico al que reconstruye verify_doc.py
        payload = f"v=1\nsigner={username}\nci={ci}\ntimestamp={timestamp}\ntext={text}"

        sig_bytes = private_key.sign(
            payload.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        # Token de verificación compacto (base64 de JSON)
        token_data = {
            "v": 1,
            "signer": username,
            "ci": ci,
            "timestamp": timestamp,
            "text": text,
            "sig": sig_b64,
        }
        token = base64.b64encode(
            json.dumps(token_data, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

        return {
            "status": "ok",
            "signer": username,
            "ci": ci if ci else "\u2014",
            "timestamp": timestamp,
            "text": text,
            "token": token,
        }
    except Exception:
        return {"status": "error", "code": ERR_SERVER}


def main() -> None:
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    username = data.get("username", "")
    text     = data.get("text", "")

    if not isinstance(username, str) or not isinstance(text, str):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return
    if not username or not text.strip():
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return
    if len(text) > MAX_TEXT_LEN:
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    # Normalizar saltos de línea para payload consistente
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    result = sign_text(username, text)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
