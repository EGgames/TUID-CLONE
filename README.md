# TUID-CLONE — Sistema de Autenticación e Identidad Digital

> Stack completo de autenticación, firma digital y gestión de identidad.
> Servidor HTTP en C puro (Winsock2) + módulos de seguridad en Python + frontend HTML/CSS/JS.

---

## Tabla de Contenidos

1. [Descripción General](#descripción-general)
2. [Arquitectura](#arquitectura)
3. [Stack Tecnológico](#stack-tecnológico)
4. [Estructura del Proyecto](#estructura-del-proyecto)
5. [Instalación y Arranque](#instalación-y-arranque)
6. [Endpoints y Rutas](#endpoints-y-rutas)
7. [Seguridad — Fortalezas](#seguridad--fortalezas)
8. [Seguridad — Hallazgos y Remediación](#seguridad--hallazgos-y-remediación)
9. [Cumplimiento Normativo](#cumplimiento-normativo)
10. [Plan de Remediación Priorizado](#plan-de-remediación-priorizado)
11. [Variables de Entorno](#variables-de-entorno)
12. [Notas de Desarrollo](#notas-de-desarrollo)

---

## Descripción General

**TUID-CLONE** es un sistema de autenticación e identidad digital que implementa:

- **Registro de usuarios** con política de contraseña fuerte y almacenamiento PBKDF2-SHA256
- **Login** con protección anti fuerza bruta en doble capa (IP + usuario)
- **Gestión de sesiones** con tokens de 256 bits, expiración en 1 hora y cookies HttpOnly/Secure/SameSite=Strict
- **Firma digital de documentos** con RSA-2048 PSS/SHA-256 por usuario
- **Verificación de firmas** mediante token auto-contenido en base64
- **Almacenamiento de cédula de identidad** (RUT chileno) con cifrado AES-256-GCM opcional
- **Auditoría completa** en log ISO 8601 UTC

El servidor está escrito en C puro usando la API Winsock2 de Windows, con multi-threading nativo (`_beginthreadex`). Cada request se atiende en un hilo separado. Los módulos de seguridad están escritos en Python y son invocados mediante pipes desde el proceso C.

---

## Arquitectura

```
[Navegador / Cliente HTTP]
        │ HTTP :8888
        ▼
[server.c — Winsock2, multi-thread]
   ├── GET  /              → HTML cacheado en memoria (index.html)
   ├── POST /login         → pipe → security/auth.py
   ├── POST /register      → pipe → security/register.py + keygen.py
   ├── GET/POST /setup-ci  → pipe → security/save_ci.py
   ├── GET/POST /sign      → pipe → security/sign_doc.py
   ├── GET/POST /verify    → pipe → security/verify_doc.py
   └── GET  /dashboard     → sesión validada en C (c_check_session)
   └── GET  /captcha       → CAPTCHA aritmético single-use (generado en C)
   └── POST /csrf-token    → token CSRF single-use con TTL 30 min

[Capa Python — invocada por popen/pipes]
   ├── auth.py          — PBKDF2-SHA256, rate-limit, sesiones, timing-safe
   ├── register.py      — alta de usuarios, validación, keygen automático
   ├── keygen.py        — generación RSA-2048 por usuario
   ├── sign_doc.py      — firma RSA-2048 PSS/SHA-256
   ├── verify_doc.py    — verificación de firma digital
   └── save_ci.py       — almacenamiento inmutable de cédula (AES-256-GCM)

[Almacenamiento en disco]
   ├── security/data/users.json      — credenciales (hash+salt PBKDF2)
   ├── security/data/sessions.json   — tokens de sesión activos
   ├── security/data/attempts.json   — contadores de rate-limit
   ├── security/data/keys/           — pares RSA PEM por usuario
   └── security/data/audit.log       — log de auditoría ISO 8601 UTC
```

---

## Stack Tecnológico

| Capa | Tecnología |
|------|-----------|
| Servidor HTTP | C (Winsock2, Win32, `_beginthreadex`) |
| Seguridad / Auth | Python 3.10+ (`cryptography`, `hashlib`, `hmac`, `secrets`) |
| Firma digital | RSA-2048 PSS/SHA-256 (`cryptography.hazmat`) |
| Cifrado en reposo | AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead`) |
| Frontend | HTML5, CSS3 (puro), JavaScript ES6+ |
| TLS (proxy) | Python (`ssl`, `http.server`) — `https_proxy.py` |
| Compilación | GCC / MinGW (`build.bat`) |

---

## Estructura del Proyecto

```
TUID-CLONE/
├── backend/
│   └── server.c                  # Servidor HTTP C (Winsock2, ~1850 líneas)
├── frontend/
│   ├── pages/
│   │   ├── index.html            # Login
│   │   ├── register.html         # Registro
│   │   ├── dashboard.html        # Panel principal
│   │   ├── setup-ci.html         # Configurar cédula de identidad
│   │   ├── sign.html             # Firmar documento
│   │   └── verify.html           # Verificar firma
│   ├── css/
│   │   ├── login.css
│   │   ├── register.css
│   │   ├── dashboard.css
│   │   ├── setup-ci.css
│   │   ├── sign.css
│   │   └── verify.css
│   └── js/
│       ├── register.js
│       ├── dash.js
│       └── sign.js
├── security/
│   ├── auth.py                   # Autenticación principal
│   ├── register.py               # Registro de usuarios
│   ├── keygen.py                 # Generación RSA por usuario
│   ├── sign_doc.py               # Firma digital
│   ├── verify_doc.py             # Verificación de firma
│   ├── save_ci.py                # Almacenamiento cédula
│   ├── check_session.py          # Validación de sesión
│   ├── setup_users.py            # Setup inicial de usuarios
│   ├── setup_security.py         # Configuración de seguridad
│   └── create_demo_user.py       # Usuario de demostración
│   └── data/                     # ⚠️ NO SUBIR A PRODUCCIÓN
│       ├── users.json
│       ├── sessions.json
│       ├── attempts.json
│       ├── audit.log
│       └── keys/                 # ⚠️ Claves RSA privadas
├── https_proxy.py                # Proxy TLS de desarrollo
├── build.bat                     # Compilar server.c con GCC
├── start.bat                     # Iniciar servidor
├── init.bat                      # Inicialización completa
├── SECURITY_REPORT.md            # Informe de seguridad completo
└── README.md
```

---

## Instalación y Arranque

### Requisitos previos

- **Windows 10/11** (el servidor usa Winsock2 y Win32 API)
- **GCC / MinGW-w64** en el PATH (`gcc --version`)
- **Python 3.10+** en el PATH (`python --version`)
- Biblioteca `cryptography` para Python:

```powershell
pip install cryptography
```

### Instalación rápida

```bat
rem 1. Clonar el repositorio
git clone https://github.com/EGgames/TUID-CLONE.git
cd TUID-CLONE

rem 2. Inicializar directorios y datos de seguridad
init.bat

rem 3. Compilar el servidor C
build.bat

rem 4. Iniciar el servidor
start.bat
```

El servidor quedará escuchando en `http://localhost:8888`.

### Compilación manual

```bat
gcc -o backend/server.exe backend/server.c -lws2_32 -O2
```

### Proxy HTTPS de desarrollo

Para desarrollo local con TLS auto-firmado:

```powershell
python https_proxy.py
```

Esto levanta un proxy en `https://localhost:8443` → `http://localhost:8888`.

---

## Endpoints y Rutas

| Método | Ruta | Descripción | Autenticación |
|--------|------|-------------|---------------|
| `GET` | `/` | Login (index.html) | No |
| `POST` | `/login` | Autenticación de usuario | No |
| `GET` | `/register` | Formulario de registro | No |
| `POST` | `/register` | Crear cuenta nueva | No (con REGISTER_KEY) |
| `GET` | `/dashboard` | Panel principal | ✅ Sesión válida |
| `GET/POST` | `/setup-ci` | Configurar cédula | ✅ Sesión válida |
| `GET/POST` | `/sign` | Firmar documento | ✅ Sesión válida |
| `GET/POST` | `/verify` | Verificar firma | No |
| `GET` | `/captcha` | Obtener CAPTCHA aritmético | No |
| `GET` | `/csrf-token` | Obtener token CSRF | ✅ Sesión válida |
| `GET` | `/logout` | Cerrar sesión | ✅ Sesión válida |
| `GET` | `/static/*` | Archivos CSS/JS | No |

### Límites de tamaño de body

| Ruta | Límite |
|------|--------|
| `/login` | 1 KB |
| `/register` | 2 KB |
| `/setup-ci` | 512 B |
| `/sign` | 10 KB |
| `/verify` | 16 KB |

---

## Seguridad — Fortalezas

### Autenticación

| Control | Detalle |
|---------|---------|
| **Hashing de contraseñas** | PBKDF2-HMAC-SHA256, 200 000 iteraciones, salt de 16 bytes aleatorios (NIST SP 800-132) |
| **Comparación timing-safe** | `hmac.compare_digest` — resistente a timing attacks |
| **Enumeración de usuarios** | Mismo mensaje de error para usuario inexistente y contraseña incorrecta |
| **Política de contraseña** | Mínimo 8 chars, mayúscula, minúscula, dígito y carácter especial |

### Sesiones

| Control | Detalle |
|---------|---------|
| **Entropía del token** | `secrets.token_hex(32)` → 256 bits |
| **Flags de cookie** | `HttpOnly; Secure; SameSite=Strict; Max-Age=3600` |
| **Expiración** | 1 hora, validada en servidor |
| **Invalidación** | `Max-Age=0` al expirar/logout |

### Rate Limiting (doble capa)

| Capa | Umbral | Bloqueo |
|------|--------|---------|
| **IP (servidor C)** | 20 intentos | 5 minutos |
| **Usuario (Python)** | 5 intentos | 5 minutos |

Ambos contadores están protegidos con `CRITICAL_SECTION` para thread-safety.

### Headers HTTP de seguridad

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: no-referrer
Cache-Control: no-store
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Criptografía asimétrica

- **RSA-2048 con PSS/SHA-256** para firma digital
- `salt_length=PSS.MAX_LENGTH` (máxima entropía de firma)
- Token de verificación auto-contenido: base64 de JSON con firma incluida
- Generación idempotente de claves (no sobreescribe las existentes)

### Escritura atómica

`_save_json_atomic` en `register.py` y `save_ci.py`: escribe en `.tmp` y hace `os.replace` (rename atómico), evitando corrupción ante crash.

### Auditoría

- Log ISO 8601 UTC con severidad, evento, usuario e IP
- Protegido con `CRITICAL_SECTION` (thread-safe)
- **Nunca registra contraseñas ni tokens completos**

### Protección CSRF

Tokens CSRF single-use con TTL de 30 minutos generados en el servidor C. Almacenados en tabla en memoria con purga automática.

### CAPTCHA aritmético

CAPTCHA de operación matemática simple, single-use con TTL de 5 minutos, para proteger el endpoint de registro contra bots.

---

## Seguridad — Hallazgos y Remediación

> Informe completo en [SECURITY_REPORT.md](SECURITY_REPORT.md)

### Resumen de hallazgos

| ID | Título | Severidad | OWASP | Corregido |
|----|--------|-----------|-------|-----------|
| ALTA-01 | Ausencia de TLS | 🔴 ALTA | A02:2021 | No (requiere infraestructura) |
| ALTA-02 | Claves RSA sin cifrar | 🔴 ALTA | A02:2021 | Parcial (AES-GCM opcional) |
| MEDIA-01 | Archivos temporales con credenciales | 🟠 MEDIA | A02:2021 | Parcial |
| MEDIA-02 | Sessions.json sin purga | 🟠 MEDIA | A04:2021 | Pendiente |
| MEDIA-03 | CSP con `unsafe-inline` | 🟠 MEDIA | A03:2021 | Pendiente |
| MEDIA-04 | Race condition en attempts.json | 🟠 MEDIA | A04:2021 | Pendiente |
| BAJA-01 | Sin token CSRF explícito | 🟡 BAJA | A01:2021 | ✅ Implementado |
| BAJA-02 | Sin límite de tamaño de request | 🟡 BAJA | A05:2021 | ✅ Implementado |
| BAJA-03 | RSA-2048 (vida útil hasta 2030) | 🟡 BAJA | A02:2021 | Planificación |
| INFO-01 | CI en texto plano | 🔵 INFO | — | Parcial (AES-GCM opcional) |
| INFO-02 | Sin validación matemática RUT | 🔵 INFO | — | Pendiente |
| INFO-03 | Token en stack de hilo | 🔵 INFO | — | No crítico |

---

### [ALTA-01] Ausencia de TLS

**OWASP:** A02:2021 – Cryptographic Failures

El servidor escucha en TCP puro (puerto 8888) sin TLS. Cualquier atacante en la misma red puede capturar tokens de sesión, credenciales en tránsito y tokens de firma digital.

**Recomendación:**
- **Producción:** Reverse proxy TLS (nginx, Caddy, HAProxy) con certificado válido
- **Desarrollo:** Usar `https_proxy.py` incluido o stunnel

---

### [ALTA-02] Claves privadas RSA almacenadas sin cifrar

**OWASP:** A02:2021 – Cryptographic Failures

Las claves privadas RSA se almacenan en `security/data/keys/<usuario>_private.pem` sin cifrado. Cualquier acceso de lectura al sistema de archivos expone todas las claves.

**Recomendación:**
```python
# En keygen.py — usar cifrado con passphrase
encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase_from_env")
```

Configurar `KEY_ENCRYPTION_KEY` como variable de entorno del proceso.

---

### [MEDIA-01] Archivos temporales con credenciales en texto plano

**OWASP:** A02:2021 – Cryptographic Failures

Para comunicar datos entre C y Python se escriben archivos temporales con credenciales. Si el proceso se interrumpe antes de eliminarlos, las credenciales quedan en disco.

**Recomendación:** Usar `CreateProcess` con pipes anónimos (stdin/stdout) en lugar de archivos temporales.

---

### [MEDIA-02] Sessions.json sin purga — crecimiento ilimitado

**OWASP:** A04:2021 – Insecure Design

Las sesiones expiradas nunca se eliminan, el archivo crece indefinidamente.

```python
# Corrección en auth.py
now = time.time()
sessions = {k: v for k, v in sessions.items() if v.get("expires", 0) > now}
```

---

### [MEDIA-03] CSP permite `unsafe-inline` en scripts

**OWASP:** A03:2021 – Injection (XSS)

`'unsafe-inline'` en `script-src` anula la protección CSP contra XSS.

**Recomendación:** Mover scripts inline a archivos externos y usar nonces o hashes.

---

### [MEDIA-04] Race condition en attempts.json

**OWASP:** A04:2021 – Insecure Design

Sin file locking, dos procesos Python concurrentes pueden corromper el contador de intentos fallidos, permitiendo evadir el rate limiting.

**Recomendación:** Usar `msvcrt.locking` en Windows o migrar a SQLite con transacciones.

---

## Cumplimiento Normativo

| Control | Estado |
|---------|--------|
| NIST SP 800-132 (PBKDF2 ≥ 10k iter) | ✅ Cumple (200 000 iter) |
| NIST SP 800-57 (vida útil de claves) | ⚠️ Parcial (RSA-2048 hasta 2030) |
| ISO 27001 A.8.15 (Logging) | ✅ Cumple |
| ISO 27001 A.9.4 (Control de acceso) | ✅ Cumple (rate limit, session mgmt) |
| OWASP ASVS 3.0+ (Sesiones) | ⚠️ Parcial (falta purga y CSRF completo) |
| GDPR / Ley 19.628 (datos personales CI) | ⚠️ Riesgo (CI opcional AES-GCM) |

---

## Plan de Remediación Priorizado

```
Prioridad 1 — Antes de cualquier despliegue en red:
  ├── [ALTA-02] Cifrar claves RSA privadas con passphrase
  └── [ALTA-01] Configurar TLS (reverse proxy o stunnel)

Prioridad 2 — Sprint siguiente:
  ├── [MEDIA-01] Eliminar archivos temporales (pipes directos)
  ├── [MEDIA-04] Añadir file locking en attempts.json
  └── [MEDIA-02] Implementar purga de sesiones expiradas

Prioridad 3 — Hardening:
  ├── [MEDIA-03] Eliminar 'unsafe-inline' del CSP
  ├── [BAJA-01] Tokens CSRF en /setup-ci y /sign ✅
  └── [BAJA-02] Validar Content-Length por endpoint ✅

Prioridad 4 — Largo plazo:
  ├── [INFO-02] Validar dígito verificador del RUT (módulo 11)
  ├── [INFO-01] Cifrar CI en reposo ✅ (parcial)
  └── [BAJA-03] Planificar migración a Ed25519 o RSA-3072
```

---

## Variables de Entorno

| Variable | Descripción | Obligatoria |
|----------|-------------|-------------|
| `REGISTER_KEY` | Clave secreta para habilitar el registro de usuarios | Recomendada |
| `KEY_ENCRYPTION_KEY` | Passphrase para cifrar claves RSA privadas con AES-256-GCM | Recomendada |

Ejemplo en PowerShell:
```powershell
$env:REGISTER_KEY = "mi-clave-secreta-de-registro"
$env:KEY_ENCRYPTION_KEY = "mi-passphrase-de-cifrado-rsa"
```

---

## Notas de Desarrollo

- **Sistema operativo:** Windows (Winsock2, Win32, `_beginthreadex`, CRITICAL_SECTION)
- **Puerto por defecto:** 8888 (HTTP)
- **HTML pre-cargado:** Los archivos HTML se cachean en memoria al arranque, no se leen en cada request
- **Thread safety:** Todas las secciones críticas están protegidas con `CRITICAL_SECTION`
- **Archivos sensibles:** `security/data/` contiene credenciales reales — **nunca subir a producción sin cifrar**
- **Clave de registro:** Sin `REGISTER_KEY`, el registro está deshabilitado por defecto

---

## Licencia

Este proyecto es un clon/prototipo educativo de un sistema de identidad digital.

---

*Última actualización: 2026-05-17*
