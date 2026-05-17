import subprocess, json

# Simula exactamente lo que hace run_python() en server.c
payload = json.dumps({"username": "admin", "password": "Admin123!"})
print(f"Enviando a auth.py: {payload}")

result = subprocess.run(
    ["python", "security\\auth.py"],
    input=payload,
    capture_output=True,
    text=True,
    timeout=15
)
print(f"stdout: {repr(result.stdout)}")
print(f"stderr: {repr(result.stderr)}")
print(f"returncode: {result.returncode}")

# Verificar si el server.c encontraría "status": "ok"
if '"status": "ok"' in result.stdout:
    print("-> SERVER ACEPTA: login exitoso")
else:
    print("-> SERVER RECHAZA: login fallido")
    # Probar con otros usuarios
    for user, pw in [("jimmyabv", "jimmyabv"), ("nuevousuario", "test")]:
        r2 = subprocess.run(
            ["python", "security\\auth.py"],
            input=json.dumps({"username": user, "password": pw}),
            capture_output=True, text=True, timeout=15
        )
        print(f"  {user}: stdout={repr(r2.stdout[:100])}")
