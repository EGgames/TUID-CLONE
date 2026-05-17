import hashlib

salt   = "f530ce7c6e5523931f331b5b0ee304c6"
stored = "69a4f93b447dc966e4714b1e68be053102b8157c828d1bee54ce39c66e40c85b"

for pw in ["Admin123!", "Admin1234", "admin", "Admin123", "admin123"]:
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000)
    print(f"{pw!r:20s} -> {'OK' if dk.hex() == stored else 'FAIL'}")
