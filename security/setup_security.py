"""
setup_security.py — Activación de cifrado en reposo
====================================================
Ejecutar UNA VEZ antes del primer despliegue (o cuando se quiera activar
el cifrado de claves RSA y CI).

Acciones:
  1. Genera la clave maestra en data/.keymaster (si no existe).
  2. Re-cifra todos los archivos *_private.pem existentes con AES-256-CBC.
  3. Cifra los CI en texto plano de data/users.json con AES-256-GCM.

Requiere que el servidor esté DETENIDO mientras se ejecuta.

Uso:
    python security/setup_security.py
"""

import os
import sys
import json
import secrets
import hashlib
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DIR         = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR     = os.path.join(_DIR, "data", "keys")
USERS_FILE   = os.path.join(_DIR, "data", "users.json")
KEYMASTER    = os.path.join(_DIR, "data", ".keymaster")


# --------------------------------------------------------------------------- #
# Helpers                                                                       #
# --------------------------------------------------------------------------- #

def _load_or_create_keymaster() -> bytes:
    """Carga la clave maestra existente o genera una nueva de 48 bytes (hex)."""
    if os.path.exists(KEYMASTER):
        with open(KEYMASTER, "rb") as f:
            val = f.read().strip()
        if val:
            print(f"[INFO] Clave maestra existente: {KEYMASTER}")
            return val
    # Generar clave de 48 bytes aleatorios codificados como hex (96 chars ASCII)
    passphrase = secrets.token_hex(48).encode("ascii")
    tmp = KEYMASTER + ".tmp"
    with open(tmp, "wb") as f:
        f.write(passphrase)
    os.replace(tmp, KEYMASTER)
    try:
        os.chmod(KEYMASTER, 0o600)
    except OSError:
        pass  # Windows no soporta chmod, ignorar
    print(f"[OK]  Clave maestra generada: {KEYMASTER}")
    print(f"[!]   Guarda una copia de seguridad en lugar seguro.\n")
    return passphrase


def _encrypt_ci(ci: str, passphrase: bytes) -> str:
    key = hashlib.sha256(passphrase).digest()
    iv  = secrets.token_bytes(12)
    ct  = AESGCM(key).encrypt(iv, ci.encode("utf-8"), None)
    return "enc:" + base64.b64encode(iv + ct).decode("ascii")


# --------------------------------------------------------------------------- #
# Paso 1: Migrar claves RSA privadas                                            #
# --------------------------------------------------------------------------- #

def migrate_rsa_keys(passphrase: bytes) -> None:
    if not os.path.isdir(KEYS_DIR):
        print("[INFO] No se encontró directorio de claves RSA, omitiendo.")
        return

    migrated = skipped = 0
    for fname in sorted(os.listdir(KEYS_DIR)):
        if not fname.endswith("_private.pem"):
            continue
        path = os.path.join(KEYS_DIR, fname)
        with open(path, "rb") as f:
            pem_data = f.read()

        # Intentar cargar SIN contraseña → clave sin cifrar
        try:
            private_key = serialization.load_pem_private_key(pem_data, password=None)
        except (ValueError, TypeError):
            print(f"  [SKIP] {fname} — ya cifrada")
            skipped += 1
            continue

        # Re-guardar cifrada con passphrase
        enc_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(enc_pem)
        os.replace(tmp, path)
        print(f"  [OK]  {fname} — cifrada con AES-256-CBC")
        migrated += 1

    print(f"  → {migrated} migrada(s), {skipped} ya cifrada(s).\n")


# --------------------------------------------------------------------------- #
# Paso 2: Migrar CI en users.json                                               #
# --------------------------------------------------------------------------- #

def migrate_ci(passphrase: bytes) -> None:
    if not os.path.exists(USERS_FILE):
        print("[INFO] users.json no encontrado, omitiendo migración de CI.")
        return

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
    except Exception as e:
        print(f"[ERROR] No se pudo leer users.json: {e}")
        return

    migrated = skipped = 0
    for username, entry in users.items():
        ci = entry.get("ci", "")
        if not ci:
            continue
        if ci.startswith("enc:"):
            skipped += 1
            continue
        entry["ci"] = _encrypt_ci(ci, passphrase)
        print(f"  [OK]  CI de '{username}' cifrada")
        migrated += 1

    if migrated > 0:
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        os.replace(tmp, USERS_FILE)
    print(f"  → {migrated} CI(s) cifrada(s), {skipped} ya cifrada(s).\n")


# --------------------------------------------------------------------------- #
# Main                                                                          #
# --------------------------------------------------------------------------- #

def main() -> None:
    print("=" * 60)
    print("  setup_security.py — Activación de cifrado en reposo")
    print("  ASEGÚRATE DE QUE EL SERVIDOR ESTÉ DETENIDO")
    print("=" * 60)
    print()

    passphrase = _load_or_create_keymaster()

    print("[Paso 1] Migrando claves RSA privadas...")
    migrate_rsa_keys(passphrase)

    print("[Paso 2] Migrando CI en users.json...")
    migrate_ci(passphrase)

    print("[LISTO] Cifrado en reposo activado.")
    print()
    print("  Próximos pasos:")
    print(f"  - Respalda  {KEYMASTER}  en un lugar seguro.")
    print("  - Reinicia el servidor para que los cambios surtan efecto.")


if __name__ == "__main__":
    main()
