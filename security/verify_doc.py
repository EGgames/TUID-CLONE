"""
verify_doc.py — Verificación de firma digital RSA-2048 PSS/SHA-256
===================================================================
Lee JSON desde stdin: {"token": "..."}
Escribe JSON en stdout:
  OK:    {"status": "ok", "valid": true/false, "signer": "...",
          "ci": "...", "timestamp": "..."}
  Error: {"status": "error", "code": N}

Códigos de error:
  1 = Token inválido o malformado
  3 = Clave pública no encontrada para el firmante
  5 = Error interno
"""

import sys
import json
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

_DIR     = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(_DIR, "data", "keys")

ERR_INVALID_INPUT = 1
ERR_NO_KEY        = 3
ERR_SERVER        = 5


def verify_token(token: str) -> dict:
    # Decodificar base64 → JSON
    # Normalizar: quitar espacios y saltos de línea (pueden venir al copiar del PDF)
    try:
        token_clean = token.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        decoded = base64.b64decode(token_clean.encode("ascii"))
        td = json.loads(decoded.decode("utf-8"))
    except Exception:
        return {"status": "error", "code": ERR_INVALID_INPUT}

    required = {"v", "signer", "ci", "timestamp", "text", "sig"}
    if not required.issubset(td.keys()):
        return {"status": "error", "code": ERR_INVALID_INPUT}

    if td.get("v") != 1:
        return {"status": "error", "code": ERR_INVALID_INPUT}

    signer    = td["signer"]
    ci        = td["ci"]
    timestamp = td["timestamp"]
    text      = td["text"]
    sig_b64   = td["sig"]

    pub_path = os.path.join(KEYS_DIR, f"{signer}_public.pem")
    if not os.path.exists(pub_path):
        return {"status": "error", "code": ERR_NO_KEY}

    try:
        with open(pub_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Reconstruir payload idéntico al que se firmó en sign_doc.py
        payload = f"v=1\nsigner={signer}\nci={ci}\ntimestamp={timestamp}\ntext={text}"
        sig_bytes = base64.b64decode(sig_b64.encode("ascii"))

        try:
            public_key.verify(
                sig_bytes,
                payload.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            valid = True
        except InvalidSignature:
            valid = False

        return {
            "status": "ok",
            "valid": valid,
            "signer": signer,
            "ci": ci if ci else "\u2014",
            "timestamp": timestamp,
        }
    except Exception:
        return {"status": "error", "code": ERR_SERVER}


def main() -> None:
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    token = data.get("token", "")
    if not isinstance(token, str) or not token.strip():
        print(json.dumps({"status": "error", "code": ERR_INVALID_INPUT}))
        return

    result = verify_token(token.strip())
    print(json.dumps(result))


if __name__ == "__main__":
    main()
