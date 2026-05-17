"""
check_session.py — Validador de sesiones
=========================================
Lee un token desde stdin, lo verifica contra la base de datos SQLite.
Escribe JSON a stdout: {"valid": true/false, "username": "..."}
"""

import sys
import json
import time

import db


def main():
    token = sys.stdin.read().strip()

    # Validación básica: solo hex lowercase, 64 chars
    if not token or len(token) != 64:
        print(json.dumps({"valid": False}))
        return
    if not all(c in "0123456789abcdef" for c in token):
        print(json.dumps({"valid": False}))
        return

    row = db.get_session(token)

    if row and time.time() < row["expires"]:
        print(json.dumps({"valid": True, "username": row["username"]}))
    else:
        print(json.dumps({"valid": False}))


if __name__ == "__main__":
    main()
