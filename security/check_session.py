"""
check_session.py — Validador de sesiones
=========================================
Lee un token desde stdin, lo verifica contra sessions.json.
Escribe JSON a stdout: {"valid": true/false, "username": "..."}
"""

import sys
import json
import os
import time

_DIR          = os.path.dirname(os.path.abspath(__file__))
SESSIONS_FILE = os.path.join(_DIR, "data", "sessions.json")


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return default


def main():
    token = sys.stdin.read().strip()

    # Validación básica: solo hex lowercase, 64 chars
    if not token or len(token) != 64:
        print(json.dumps({"valid": False}))
        return
    if not all(c in "0123456789abcdef" for c in token):
        print(json.dumps({"valid": False}))
        return

    sessions = _load_json(SESSIONS_FILE, {})
    entry = sessions.get(token)

    if entry and time.time() < entry.get("expires", 0):
        print(json.dumps({"valid": True, "username": entry["username"]}))
    else:
        print(json.dumps({"valid": False}))


if __name__ == "__main__":
    main()
