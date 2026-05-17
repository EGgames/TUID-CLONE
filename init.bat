@echo off
chcp 65001 > nul
echo =========================================
echo   INICIALIZAR Sistema de Login
echo =========================================
echo.

REM ── 1. Crear usuario demo ─────────────────
echo [1/2] Creando usuario demo...
python security\create_demo_user.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Fallo Python. Asegurate de tener Python 3.8+ instalado.
    pause & exit /b 1
)

echo.

REM ── 2. Compilar servidor C ────────────────
echo [2/2] Compilando servidor C...
gcc backend\server.c -o backend\server.exe -lws2_32 -Wall -O2 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Fallo la compilacion con GCC.
    echo   Instala MinGW-w64: https://www.mingw-w64.org/
    echo   O con winget: winget install MSYS2.MSYS2
    pause & exit /b 1
)

echo [OK] server.exe compilado correctamente.
echo.
echo =========================================
echo   Todo listo! Ejecuta: start.bat
echo =========================================
pause
