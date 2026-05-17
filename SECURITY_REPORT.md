# Informe de Seguridad — ID_LOGIN Stack

**Fecha:** 2026-05-17  
**Versión del análisis:** 1.0  
**Alcance:** Análisis estático de código completo del stack (backend C, módulos Python, frontend HTML/JS)  
**Metodología:** Revisión manual + mapeo contra OWASP Top 10 2021 y NIST SP 800-132

---

## 1. Resumen Ejecutivo

El stack implementa un sistema de autenticación, gestión de sesiones y firma digital. En general presenta un nivel de seguridad **por encima del promedio** para un proyecto de este tipo: usa PBKDF2-SHA256 con 200 000 iteraciones, cookies HttpOnly/Secure/SameSite=Strict, rate limiting en dos capas, headers de seguridad HTTP y registro de auditoría estructurado.

Sin embargo, se identificaron **3 hallazgos de severidad ALTA/MEDIA** que requieren atención antes de un despliegue en producción, principalmente la ausencia de TLS, el almacenamiento de claves privadas RSA sin cifrar, y la superficie de ataque por archivos temporales con credenciales.

| Severidad | Cantidad |
|-----------|----------|
| 🔴 ALTA | 2 |
| 🟠 MEDIA | 4 |
| 🟡 BAJA | 3 |
| 🔵 INFO | 3 |

---

## 2. Arquitectura del Stack

```
[Navegador / Cliente HTTP]
        │ HTTP :8888
        ▼
[server.c — Winsock2, multi-thread]
   ├── GET  /              → HTML cacheado en memoria
   ├── POST /login         → _popen → security/auth.py
   ├── POST /register      → _popen → security/register.py + keygen.py
   ├── GET/POST /setup-ci  → _popen → security/save_ci.py
   ├── GET/POST /sign      → _popen → security/sign_doc.py
   ├── GET/POST /verify    → _popen → security/verify_doc.py
   └── GET  /dashboard     → sesión validada en C (c_check_session)

[Capa Python — invocada por popen]
   ├── auth.py          — PBKDF2-SHA256, rate-limit, sesiones
   ├── register.py      — alta de usuarios, validación de contraseña
   ├── keygen.py        — generación RSA-2048 por usuario
   ├── sign_doc.py      — firma RSA-2048 PSS/SHA-256
   ├── verify_doc.py    — verificación de firma
   └── save_ci.py       — almacenamiento inmutable de cédula

[Almacenamiento en disco]
   ├── security/users.json      — credenciales (hash+salt PBKDF2)
   ├── security/sessions.json   — tokens de sesión activos
   ├── security/attempts.json   — contadores de rate-limit
   ├── security/keys/           — pares RSA PEM por usuario
   └── security/audit.log       — log de auditoría ISO 8601
```

---

## 3. Fortalezas de Seguridad

### 3.1 Autenticación
- ✅ **PBKDF2-HMAC-SHA256** con 200 000 iteraciones y salt aleatorio de 16 bytes (cumple NIST SP 800-132).
- ✅ **`hmac.compare_digest`** para comparar hashes: resistente a timing attacks.
- ✅ **Prevención de enumeración de usuarios**: mismo mensaje de error para usuario inexistente y contraseña incorrecta.
- ✅ **Política de contraseña fuerte**: mínimo 8 chars, mayúscula, minúscula, dígito y carácter especial.

### 3.2 Sesiones
- ✅ **`secrets.token_hex(32)`** (256 bits de entropía) para tokens de sesión.
- ✅ **Cookies**: `HttpOnly; Secure; SameSite=Strict; Max-Age=3600`.
- ✅ **Expiración de sesión** de 1 hora, validada en el servidor.
- ✅ **Limpieza de cookie** al expirar: `Max-Age=0` en el redirect de logout/invalidación.

### 3.3 Rate Limiting (doble capa)
- ✅ **Nivel IP (C)**: 20 intentos → bloqueo 5 minutos, protegido con `CRITICAL_SECTION`.
- ✅ **Nivel usuario (Python)**: 5 intentos → bloqueo 5 minutos con contador persistente.

### 3.4 Headers HTTP de seguridad
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0            ← correcto: desactiva el buggy filtro IE
Referrer-Policy: no-referrer
Cache-Control: no-store
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 3.5 Criptografía asimétrica
- ✅ **RSA-2048 con PSS/SHA-256** para firma digital (parámetro `salt_length=PSS.MAX_LENGTH`).
- ✅ Token de verificación auto-contenido (base64 de JSON con firma incluida).
- ✅ Generación de claves idempotente: no sobreescribe claves existentes.

### 3.6 Escritura atómica
- ✅ `_save_json_atomic` en `register.py` y `save_ci.py`: escribe en `.tmp` y hace `os.replace` (rename atómico), evitando corrupción del JSON ante crash.

### 3.7 Auditoría
- ✅ Log ISO 8601 UTC con severidad, evento, usuario e IP.
- ✅ Protegido con `CRITICAL_SECTION` (thread-safe).
- ✅ **Nunca registra contraseñas ni tokens completos** (comentado en código).

---

## 4. Hallazgos de Seguridad

---

### [ALTA-01] Ausencia de TLS — Transporte en texto plano

**Severidad:** 🔴 ALTA  
**OWASP:** A02:2021 – Cryptographic Failures  
**Componente:** `backend/server.c`

**Descripción:**  
El servidor escucha en TCP puro (puerto 8888) sin TLS. Aunque las cookies tienen el flag `Secure`, este flag solo impide que el navegador envíe la cookie por HTTP, **pero el servidor mismo sirve HTTP**, por lo que en la práctica el flag es ineficaz. Cualquier atacante en la misma red (o con acceso al tráfico de red) puede capturar tokens de sesión, credenciales en tránsito y tokens de firma digital.

**Impacto:** Robo de sesión, captura de credenciales, MITM completo.

**Recomendación:**
```
Opción A (producción): Colocar un reverse proxy TLS delante del servidor
                       (nginx, Caddy, HAProxy) con certificado válido.
Opción B (desarrollo): Implementar TLS con OpenSSL/SChannel directamente
                       en server.c o usar stunnel como wrapper.
```
Mientras no haya TLS, quitar el flag `Secure` de las cookies para que el sistema sea funcional (pero sin la protección de HTTPS).

---

### [ALTA-02] Claves privadas RSA almacenadas sin cifrar

**Severidad:** 🔴 ALTA  
**OWASP:** A02:2021 – Cryptographic Failures  
**Componente:** `security/keygen.py`, línea ~47

**Descripción:**  
Las claves privadas RSA se generan y almacenan en `security/keys/<usuario>_private.pem` con `encryption_algorithm=serialization.NoEncryption()`. Cualquier proceso o usuario con acceso de lectura al sistema de archivos puede extraer todas las claves privadas.

```python
# Actual — INSEGURO
encryption_algorithm=serialization.NoEncryption(),

# Debería ser
encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
```

**Impacto:** Compromiso total de todas las firmas digitales. Un atacante puede firmar documentos en nombre de cualquier usuario.

**Recomendación:**
1. Cifrar las claves con una passphrase derivada de la contraseña del usuario (PBKDF2) o con una clave maestra del sistema almacenada en un gestor de secretos / variables de entorno.
2. Aplicar ACLs restrictivas al directorio `security/keys/` (solo lectura/escritura para el proceso del servidor).
3. Considerar migrar a almacenamiento en base de datos cifrada en lugar de archivos PEM en disco.

---

### [MEDIA-01] Archivos temporales con credenciales en texto plano

**Severidad:** 🟠 MEDIA  
**OWASP:** A02:2021 – Cryptographic Failures  
**Componente:** `backend/server.c` (funciones `handle_login_post`, `handle_register_post`, `handle_setup_ci_post`)

**Descripción:**  
Para comunicar datos entre el servidor C y los scripts Python, se escribe un archivo temporal con credenciales en texto plano:

```c
// Ejemplo en handle_login:
snprintf(tmp_creds, sizeof(tmp_creds), "tmp_crd_%lu.json", (unsigned long)GetCurrentThreadId());
FILE *tmp = fopen(tmp_creds, "w");
// ... escribe {"username":"...", "password":"..."}
fclose(tmp);
// Luego invoca Python y hace remove(tmp_creds)
```

El archivo existe en disco mientras Python procesa la solicitud. Si el proceso es terminado en ese intervalo (crash, SIGKILL, reinicio del sistema), las credenciales quedan en disco permanentemente. Además, los archivos se crean en el **directorio de trabajo del proceso** (raíz del proyecto) sin permisos restrictivos.

**Impacto:** Exposición de contraseñas en texto plano si el proceso se interrumpe.

**Recomendación:**
1. Pasar datos a Python por **stdin de pipe** directamente (sin archivo intermedio):
   ```c
   FILE *py = _popen(AUTH_CMD, "r+");  // abrir en modo lectura+escritura
   fputs(json_payload, py);
   fclose_write_end(py);
   ```
   Nota: `_popen` en Windows solo soporta `"r"` o `"w"`, no ambos. Usar `CreateProcess` con pipes anónimos como alternativa robusta.
2. Si se mantienen archivos temporales, crearlos en un directorio con ACLs restrictivas y usar `DeleteFile` antes de devolver la respuesta (ya se hace `remove()` pero solo en el flujo normal; añadir limpieza en todos los paths de error).

---

### [MEDIA-02] `sessions.json` sin rotación ni purga — crecimiento ilimitado

**Severidad:** 🟠 MEDIA  
**OWASP:** A04:2021 – Insecure Design  
**Componente:** `security/auth.py`, `security/sessions.json`

**Descripción:**  
Las sesiones expiradas nunca se eliminan del archivo `sessions.json`. El archivo crece indefinidamente y también se carga completo en memoria en cada validación de sesión (`c_check_session` en C lee todo el archivo). Bajo carga alta o con el tiempo, esto puede derivar en:
- Degradación de rendimiento (O(n) en lectura del archivo).
- Denegación de servicio si el archivo crece hasta llenar el disco.
- El JSON completo con todos los tokens históricos queda expuesto si el archivo es accedido.

**Recomendación:**
```python
# En auth.py, tras cargar sessions, limpiar expiradas antes de guardar:
now = time.time()
sessions = {k: v for k, v in sessions.items() if v.get("expires", 0) > now}
```
Alternativamente, migrar a SQLite para gestión eficiente de sesiones.

---

### [MEDIA-03] Content-Security-Policy permite `'unsafe-inline'` en scripts

**Severidad:** 🟠 MEDIA  
**OWASP:** A03:2021 – Injection (XSS)  
**Componente:** `backend/server.c` — función `send_response`

**Descripción:**  
El header CSP enviado en todas las respuestas incluye:
```
script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com
```
La directiva `'unsafe-inline'` permite la ejecución de scripts inline en el HTML, lo cual es el vector principal de XSS. Si alguna ruta llegara a reflejar contenido sin escapar correctamente, `'unsafe-inline'` anularía la protección que debería ofrecer la CSP.

**Recomendación:**
1. Mover todos los scripts inline de los HTML a archivos `.js` externos.
2. Eliminar `'unsafe-inline'` del CSP.
3. Si se necesitan scripts inline, usar `nonces` o `hashes` en su lugar:
   ```
   script-src 'self' 'nonce-<random_per_request>'
   ```

---

### [MEDIA-04] `attempts.json` sin bloqueo de archivo — condición de carrera

**Severidad:** 🟠 MEDIA  
**OWASP:** A04:2021 – Insecure Design  
**Componente:** `security/auth.py`, `security/register.py`

**Descripción:**  
Los módulos Python leen y escriben `attempts.json` sin ningún mecanismo de bloqueo de archivo (`flock`, `msvcrt.locking`, etc.). En un escenario de múltiples hilos del servidor C invocando `auth.py` concurrentemente para el mismo usuario, dos procesos Python pueden leer el mismo contador, incrementarlo por separado y escribir, provocando que se pierdan intentos fallidos. En el peor caso, un atacante podría intentar fuerza bruta enviando solicitudes paralelas y eludir el rate limiting.

**Recomendación:**
```python
import fcntl  # Linux / portlock en Windows

# Al escribir attempts.json:
with open(ATTEMPTS_FILE, "r+") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    data = json.load(f)
    # ... modificar ...
    f.seek(0); json.dump(data, f); f.truncate()
    fcntl.flock(f, fcntl.LOCK_UN)
```
En Windows, usar `msvcrt.locking` o migrar a SQLite con transacciones.

---

### [BAJA-01] No hay protección CSRF explícita en endpoints POST

**Severidad:** 🟡 BAJA  
**OWASP:** A01:2021 – Broken Access Control  
**Componente:** `backend/server.c` — rutas POST

**Descripción:**  
Los endpoints POST (`/login`, `/register`, `/setup-ci`, `/sign`) no implementan tokens CSRF. La protección actual proviene únicamente de `SameSite=Strict` en las cookies, lo cual es suficiente en navegadores modernos, pero no protege contra:
- Navegadores antiguos que no respetan `SameSite`.
- Ataques desde el mismo origen (si hubiera XSS).
- Clientes que no son navegadores (ej. curl, scripts).

**Recomendación:** Añadir un token CSRF (double-submit cookie o synchronizer token pattern) para endpoints sensibles como `/setup-ci` (operación irreversible) y `/sign`.

---

### [BAJA-02] Tamaño de request HTTP no limitado — potencial DoS

**Severidad:** 🟡 BAJA  
**OWASP:** A05:2021 – Security Misconfiguration  
**Componente:** `backend/server.c`, línea ~1483

**Descripción:**  
El servidor lee hasta `BUFFER_SIZE - 1 = 16383` bytes por request:
```c
int received = recv(client, req, BUFFER_SIZE - 1, 0);
```
No hay validación del `Content-Length` ni límite por tipo de endpoint. Un cliente puede enviar requests muy grandes que consuman el buffer completo. Aunque el truncado evita desbordamiento, no evita que un atacante mantenga muchas conexiones abiertas con payloads grandes.

**Recomendación:**
1. Verificar el header `Content-Length` y rechazar bodies superiores a un límite razonable (ej. 4 KB para login, 64 KB para firma de documentos).
2. Implementar timeout de lectura en el socket.

---

### [BAJA-03] RSA-2048 — considerar migración a RSA-3072 o Ed25519

**Severidad:** 🟡 BAJA / INFO  
**Componente:** `security/keygen.py`, `security/sign_doc.py`

**Descripción:**  
RSA-2048 sigue siendo seguro para el horizonte 2030 según NIST SP 800-57, pero:
- NIST recomienda RSA-3072+ para datos con valor más allá de 2030.
- Ed25519 (curva de Edwards) ofrece firmas más pequeñas, operaciones más rápidas y resistencia a ataques de canal lateral por diseño.

**Recomendación:** Planificar migración a Ed25519 o RSA-3072 para nuevos usuarios. Las claves existentes RSA-2048 pueden mantenerse por compatibilidad.

---

### [INFO-01] CI (cédula) almacenada en texto plano en `users.json`

**Severidad:** 🔵 INFO  
**Componente:** `security/users.json`, `security/save_ci.py`

**Descripción:**  
La cédula de identidad se almacena en texto claro dentro de `users.json`. En muchas jurisdicciones, el número de documento nacional es un dato personal protegido (GDPR, Ley 19.628 en Chile). Si `users.json` es exfiltrado, los números de CI quedan expuestos directamente.

**Recomendación:** Considerar cifrado en reposo o almacenamiento de un hash (SHA-256 con salt) si solo se necesita comparación, no recuperación del valor.

---

### [INFO-02] Validación de CI usa solo formato RUT chileno

**Severidad:** 🔵 INFO  
**Componente:** `security/register.py`, `security/save_ci.py`

**Descripción:**  
La validación de CI acepta exclusivamente el formato `XXXXXXX-X` (RUT chileno), incluyendo el dígito verificador `K`. No se valida matemáticamente el dígito verificador (algoritmo módulo 11). Un RUT como `1234567-0` pasa la validación de formato aunque `0` no sea el dígito correcto.

**Recomendación:**
```python
def _validate_rut_check_digit(num: str, check: str) -> bool:
    reversed_digits = [int(d) for d in reversed(num)]
    factors = [2, 3, 4, 5, 6, 7] * 10
    total = sum(d * f for d, f in zip(reversed_digits, factors))
    remainder = 11 - (total % 11)
    expected = "K" if remainder == 10 else ("0" if remainder == 11 else str(remainder))
    return check.upper() == expected
```

---

### [INFO-03] Token de sesión visible en memory dump del proceso C

**Severidad:** 🔵 INFO  
**Componente:** `backend/server.c` — función `handle_login`

**Descripción:**  
Al construir el header `Set-Cookie`, el token de sesión se copia en un buffer `char hdr[512]` en el stack del hilo. En un volcado de memoria del proceso (crash dump, análisis forense), estos valores podrían ser visibles. Este es un riesgo de bajo impacto en entornos controlados.

---

## 5. Resumen de Hallazgos

| ID | Título | Severidad | OWASP | Corregido fácilmente |
|----|--------|-----------|-------|----------------------|
| ALTA-01 | Ausencia de TLS | 🔴 ALTA | A02 | No (requiere infraestructura) |
| ALTA-02 | Claves RSA sin cifrar | 🔴 ALTA | A02 | Sí (1-2 horas) |
| MEDIA-01 | Archivos temporales con credenciales | 🟠 MEDIA | A02 | Parcial |
| MEDIA-02 | Sessions.json sin purga | 🟠 MEDIA | A04 | Sí (30 min) |
| MEDIA-03 | CSP con `unsafe-inline` | 🟠 MEDIA | A03 | Sí (refactor JS) |
| MEDIA-04 | Race condition en attempts.json | 🟠 MEDIA | A04 | Sí (1 hora) |
| BAJA-01 | Sin token CSRF explícito | 🟡 BAJA | A01 | Sí |
| BAJA-02 | Sin límite de tamaño de request | 🟡 BAJA | A05 | Sí |
| BAJA-03 | RSA-2048 (vida útil limitada) | 🟡 BAJA | A02 | Planificación |
| INFO-01 | CI en texto plano | 🔵 INFO | — | Sí |
| INFO-02 | Sin validación matemática RUT | 🔵 INFO | — | Sí |
| INFO-03 | Token en stack de hilo | 🔵 INFO | — | No crítico |

---

## 6. Plan de Remediación Priorizado

```
Prioridad 1 — Antes de cualquier despliegue en red:
  ├── [ALTA-02] Cifrar claves RSA privadas con passphrase
  └── [ALTA-01] Configurar TLS (reverse proxy o stunnel)

Prioridad 2 — Sprint siguiente:
  ├── [MEDIA-01] Eliminar archivos temporales con credenciales (pipes directos)
  ├── [MEDIA-04] Añadir file locking en attempts.json
  └── [MEDIA-02] Implementar purga de sesiones expiradas

Prioridad 3 — Mejoras de hardening:
  ├── [MEDIA-03] Eliminar 'unsafe-inline' del CSP
  ├── [BAJA-01] Añadir tokens CSRF en /setup-ci y /sign
  └── [BAJA-02] Validar Content-Length por endpoint

Prioridad 4 — Deuda técnica / largo plazo:
  ├── [INFO-02] Validar dígito verificador del RUT
  ├── [INFO-01] Cifrar CI en reposo
  └── [BAJA-03] Planificar migración a Ed25519
```

---

## 7. Cumplimiento Normativo

| Control | Estado |
|---------|--------|
| NIST SP 800-132 (PBKDF2 ≥ 10k iter) | ✅ Cumple (200k iter) |
| NIST SP 800-57 (vida útil de claves) | ⚠️ Parcial (RSA-2048 hasta 2030) |
| ISO 27001 A.8.15 (Logging) | ✅ Cumple |
| ISO 27001 A.9.4 (Control de acceso a sistemas) | ✅ Cumple (rate limit, session mgmt) |
| OWASP ASVS 3.0+ (Sesiones) | ⚠️ Parcial (falta purga y CSRF) |
| GDPR / Ley 19.628 (datos personales CI) | ⚠️ Riesgo (CI en texto plano) |

---

*Informe generado mediante análisis estático. No se ejecutaron pruebas de penetración dinámicas. Se recomienda complementar con un pentest dinámico antes del despliegue en producción.*
