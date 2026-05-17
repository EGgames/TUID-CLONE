"""
get_user_ci.py — Lee el CI de un usuario desde la BD SQLite.
=============================================================
Lee un username desde stdin.
Escribe JSON a stdout: {"ci": "<valor>"} o {"ci": null}
"""

import sys
import json

import db


def main() -> None:
    username = sys.stdin.read().strip()
    if not username:
        print(json.dumps({"ci": None}))
        return

    row = db.get_user(username)
    if row:
        print(json.dumps({"ci": row["ci"]}))
    else:
        print(json.dumps({"ci": None}))


if __name__ == "__main__":
    main()
