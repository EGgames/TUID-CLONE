@echo off
chcp 65001 > nul

REM ── Verificar que el ejecutable existe ────
if not exist "backend\server.exe" (
    echo [!] No se encontro server.exe. Ejecuta init.bat primero.
    pause & exit /b 1
)

REM ── Verificar que hay usuarios ────────────
python -c "import json,sys; d=json.load(open('security/data/users.json')); sys.exit(0 if d else 1)" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] No hay usuarios. Ejecuta init.bat primero.
    pause & exit /b 1
)

REM ── Advertencia si KEY_ENCRYPTION_KEY no está definida (ALTA-02) ──
if "%KEY_ENCRYPTION_KEY%"=="" (
    echo [!] ADVERTENCIA: KEY_ENCRYPTION_KEY no definida.
    echo     Las claves RSA privadas NO estarán cifradas en disco.
    echo     Para habilitarlo: set KEY_ENCRYPTION_KEY=^<contraseña_fuerte^>
    echo.
)

echo Iniciando servidor C en http://localhost:8888 ...
start "" /B backend\server.exe

echo Iniciando proxy HTTPS en https://localhost:8443 ...
start "" /B python https_proxy.py

REM Esperar un momento para que los procesos arranquen
timeout /t 2 /nobreak > nul

echo.
echo Abriendo https://localhost:8443 ...
echo Presiona Ctrl+C en esta ventana para detener ambos procesos.
echo.
start "" "https://localhost:8443"

