/*
 * server.c — Servidor HTTP minimalista en C puro (Winsock2)
 * Puerto: 8888
 * Rutas:
 *   GET  /        → sirve frontend/index.html
 *   POST /login   → delega autenticación a Python (security/auth.py)
 *   OPTIONS /     → CORS preflight
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <process.h>   /* _beginthreadex */

#pragma comment(lib, "ws2_32.lib")

#define PORT              8888
#define BUFFER_SIZE       16384
#define TMP_CREDS         "temp_creds.json"
#define TMP_SESSION       "temp_session.txt"
#define HTML_PATH         "frontend\\pages\\index.html"
#define DASHBOARD_PATH    "frontend\\pages\\dashboard.html"
#define AUTH_CMD          "python security\\auth.py"
#define SESSIONS_FILE     "security\\data\\sessions.json"
#define AUDIT_LOG         "security\\data\\audit.log"
#define REGISTER_PATH     "frontend\\pages\\register.html"
#define REG_CMD           "python security\\register.py"
#define SETUP_CI_PATH     "frontend\\pages\\setup-ci.html"
#define SAVE_CI_CMD       "python security\\save_ci.py"
#define USERS_FILE        "security\\data\\users.json"
#define SIGN_PATH         "frontend\\pages\\sign.html"
#define VERIFY_PATH       "frontend\\pages\\verify.html"
#define SIGN_CMD          "python security\\sign_doc.py"
#define VERIFY_CMD        "python security\\verify_doc.py"
#define KEYGEN_CMD        "python security\\keygen.py"

/* Límites de tamaño de body por ruta (BAJA-02) */
#define MAX_BODY_LOGIN     1024L
#define MAX_BODY_REGISTER  2048L
#define MAX_BODY_SETUP_CI   512L
#define MAX_BODY_SIGN     10240L
#define MAX_BODY_VERIFY   16384L

/* ── HTML cacheado en memoria (read-only tras el arranque) ── */
static char *g_html_index    = NULL;
static long  g_html_index_sz = 0;
static char *g_html_dash     = NULL;
static long  g_html_dash_sz  = 0;
static char *g_html_reg      = NULL;
static long  g_html_reg_sz   = 0;
static char *g_html_setup_ci = NULL;
static long  g_html_setup_ci_sz = 0;
static char *g_html_sign     = NULL;
static long  g_html_sign_sz  = 0;
static char *g_html_verify   = NULL;
static long  g_html_verify_sz = 0;

/* ── Thread safety ── */
static CRITICAL_SECTION g_ip_cs;   /* protege ip_table          */
static CRITICAL_SECTION g_sess_cs; /* protege lectura sessions.json */
static CRITICAL_SECTION g_audit_cs;/* protege escritura audit.log   */
static CRITICAL_SECTION g_users_cs;/* protege lectura/escritura users.json */
/* ── Registro restringido (variable de entorno REGISTER_KEY) ── */
static char g_register_key[129] = {0};

/* ── CSRF token store (single-use, tiempo de vida 2 h) ── */
#define CSRF_TABLE_SIZE   1024
#define CSRF_EXPIRY_SECS  1800   /* 30 min — reduce exposición y acelera purga */

typedef struct { char token[65]; time_t expires; } CsrfEntry;
static CsrfEntry          g_csrf[CSRF_TABLE_SIZE];
static int                g_csrf_len = 0;
static unsigned long long g_csrf_state[2];
static CRITICAL_SECTION   g_csrf_cs;

/* ── CAPTCHA aritmético (single-use, TTL 5 min) ── */
#define CAPTCHA_TABLE_SIZE  512
#define CAPTCHA_EXPIRY_SECS 300

typedef struct { char tok[33]; int answer; time_t expires; } CaptchaEntry;
static CaptchaEntry       g_captcha[CAPTCHA_TABLE_SIZE];
static int                g_captcha_len = 0;
static CRITICAL_SECTION   g_captcha_cs;


/* ------------------------------------------------------------------ */
/* Rate limiting por IP (en memoria, single-thread)                     */
/* ------------------------------------------------------------------ */
#define MAX_IP_ENTRIES   512
#define IP_MAX_ATTEMPTS   20   /* intentos fallidos antes de bloquear */
#define IP_LOCKOUT_SECS  300   /* 5 minutos de bloqueo */

typedef struct { char ip[46]; int count; time_t since; } IpEntry;
static IpEntry ip_table[MAX_IP_ENTRIES];
static int     ip_table_len = 0;

/* Registra un intento. Devuelve 1 si permitido, 0 si bloqueado.
   Thread-safe: adquiere g_ip_cs internamente. */
static int ip_check_and_record(const char *ip)
{
    EnterCriticalSection(&g_ip_cs);
    time_t now = time(NULL);
    for (int i = 0; i < ip_table_len; i++) {
        if (strcmp(ip_table[i].ip, ip) != 0) continue;
        if (ip_table[i].count >= IP_MAX_ATTEMPTS) {
            if (now - ip_table[i].since < IP_LOCKOUT_SECS) {
                LeaveCriticalSection(&g_ip_cs);
                return 0;
            }
            ip_table[i].count = 1;
            ip_table[i].since = now;
            LeaveCriticalSection(&g_ip_cs);
            return 1;
        }
        ip_table[i].count++;
        LeaveCriticalSection(&g_ip_cs);
        return 1;
    }
    if (ip_table_len < MAX_IP_ENTRIES) {
        strncpy(ip_table[ip_table_len].ip, ip, 45);
        ip_table[ip_table_len].ip[45] = '\0';
        ip_table[ip_table_len].count  = 1;
        ip_table[ip_table_len].since  = now;
        ip_table_len++;
    }
    LeaveCriticalSection(&g_ip_cs);
    return 1;
}

static void ip_reset(const char *ip)
{
    EnterCriticalSection(&g_ip_cs);
    for (int i = 0; i < ip_table_len; i++)
        if (strcmp(ip_table[i].ip, ip) == 0) { ip_table[i].count = 0; break; }
    LeaveCriticalSection(&g_ip_cs);
}


/* ------------------------------------------------------------------ */
/* CSRF — generación y validación de tokens de un solo uso              */
/* ------------------------------------------------------------------ */

static void csrf_seed(void)
{
    g_csrf_state[0] = (unsigned long long)time(NULL)
                    ^ ((unsigned long long)GetCurrentProcessId() << 16);
    g_csrf_state[1] = (unsigned long long)(size_t)g_csrf ^ 0xCAFEBABEDEADBEEFULL;
    for (int i = 0; i < 32; i++) {
        unsigned long long s1 = g_csrf_state[0], s0 = g_csrf_state[1];
        g_csrf_state[0] = s0;
        s1 ^= s1 << 23;
        g_csrf_state[1] = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
    }
}

static unsigned long long csrf_rand64(void)
{
    unsigned long long s1 = g_csrf_state[0], s0 = g_csrf_state[1];
    g_csrf_state[0] = s0;
    s1 ^= s1 << 23;
    g_csrf_state[1] = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
    return g_csrf_state[1] + s0;
}

/* Genera un token de 64 hex chars, lo almacena (single-use) y lo escribe en out[65] */
static void csrf_generate(char *out)
{
    EnterCriticalSection(&g_csrf_cs);
    time_t now = time(NULL);
    /* Purgar tokens expirados */
    int w = 0;
    for (int i = 0; i < g_csrf_len; i++)
        if (g_csrf[i].expires > now) g_csrf[w++] = g_csrf[i];
    g_csrf_len = w;
    /* Generar 256 bits de entropía en hex */
    for (int i = 0; i < 4; i++) {
        unsigned long long v = csrf_rand64();
        snprintf(out + i * 16, 17, "%016llx", v);
    }
    out[64] = '\0';
    /* Almacenar token — evictar el más antiguo si la tabla está llena */
    if (g_csrf_len >= CSRF_TABLE_SIZE) {
        int oldest = 0;
        for (int i = 1; i < CSRF_TABLE_SIZE; i++)
            if (g_csrf[i].expires < g_csrf[oldest].expires)
                oldest = i;
        strncpy(g_csrf[oldest].token, out, 65);
        g_csrf[oldest].expires = now + CSRF_EXPIRY_SECS;
    } else {
        strncpy(g_csrf[g_csrf_len].token, out, 65);
        g_csrf[g_csrf_len].expires = now + CSRF_EXPIRY_SECS;
        g_csrf_len++;
    }
    LeaveCriticalSection(&g_csrf_cs);
}

/* Valida y consume un token CSRF. Devuelve 1 si válido, 0 si inválido/expirado. */
static int csrf_validate(const char *token)
{
    if (!token || strlen(token) != 64) return 0;
    for (int i = 0; i < 64; i++) {
        char c = token[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    EnterCriticalSection(&g_csrf_cs);
    time_t now = time(NULL);
    for (int i = 0; i < g_csrf_len; i++) {
        if (strcmp(g_csrf[i].token, token) == 0) {
            int valid = (g_csrf[i].expires > now);
            g_csrf[i] = g_csrf[--g_csrf_len]; /* single-use: consumir */
            LeaveCriticalSection(&g_csrf_cs);
            return valid;
        }
    }
    LeaveCriticalSection(&g_csrf_cs);
    return 0;
}

/* ── Genera un CAPTCHA aritmético (A + B) y almacena la respuesta ── */
static void captcha_generate(char *tok_out, char *q_out)
{
    EnterCriticalSection(&g_captcha_cs);
    time_t now = time(NULL);
    int w = 0;
    for (int i = 0; i < g_captcha_len; i++)
        if (g_captcha[i].expires > now) g_captcha[w++] = g_captcha[i];
    g_captcha_len = w;
    /* token 32 hex chars */
    unsigned long long r1 = csrf_rand64(), r2 = csrf_rand64();
    snprintf(tok_out, 33, "%016llx%016llx", r1, r2);
    /* pregunta A + B, A y B en [1,9] */
    int A = (int)(csrf_rand64() % 9) + 1;
    int B = (int)(csrf_rand64() % 9) + 1;
    snprintf(q_out, 8, "%d + %d", A, B);
    int ans = A + B;
    if (g_captcha_len >= CAPTCHA_TABLE_SIZE) {
        int oldest = 0;
        for (int i = 1; i < CAPTCHA_TABLE_SIZE; i++)
            if (g_captcha[i].expires < g_captcha[oldest].expires)
                oldest = i;
        strncpy(g_captcha[oldest].tok, tok_out, 33);
        g_captcha[oldest].answer  = ans;
        g_captcha[oldest].expires = now + CAPTCHA_EXPIRY_SECS;
    } else {
        strncpy(g_captcha[g_captcha_len].tok, tok_out, 33);
        g_captcha[g_captcha_len].answer  = ans;
        g_captcha[g_captcha_len].expires = now + CAPTCHA_EXPIRY_SECS;
        g_captcha_len++;
    }
    LeaveCriticalSection(&g_captcha_cs);
}

/* Valida y consume un token CAPTCHA. 1=correcto, 0=incorrecto/expirado. */
static int captcha_validate(const char *tok, const char *ans_str)
{
    if (!tok || strlen(tok) != 32 || !ans_str || !ans_str[0]) return 0;
    int ans = atoi(ans_str);
    if (ans <= 0) return 0; /* A+B ≥ 2, nunca 0 o negativo */
    EnterCriticalSection(&g_captcha_cs);
    time_t now = time(NULL);
    int found = 0;
    for (int i = 0; i < g_captcha_len; i++) {
        if (g_captcha[i].expires > now &&
            strncmp(g_captcha[i].tok, tok, 32) == 0) {
            found = (g_captcha[i].answer == ans) ? 1 : -1;
            g_captcha[i].expires = 0; /* single-use: consumir */
            break;
        }
    }
    LeaveCriticalSection(&g_captcha_cs);
    return found == 1;
}

/* ------------------------------------------------------------------
 * Registro de auditoria - ISO 27001 A.8.15 (Logging)
 * Formato: ISO 8601 UTC | severidad | evento | usuario | IP | detalle
 * Thread-safe: protegido por g_audit_cs
 * NUNCA registra contrasenas ni tokens completos.
 * ------------------------------------------------------------------ */
static void audit_log(const char *severity, const char *event,
                      const char *user,     const char *ip,
                      const char *detail)
{
    EnterCriticalSection(&g_audit_cs);
    FILE *f = fopen(AUDIT_LOG, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = gmtime(&now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", t);
        fprintf(f, "%s | %-8s | %-22s | user=%-20s | ip=%-40s | %s\n",
                ts,
                severity ? severity : "INFO",
                event    ? event    : "-",
                user     ? user     : "-",
                ip       ? ip       : "-",
                detail   ? detail   : "-");
        fclose(f);
    }
    LeaveCriticalSection(&g_audit_cs);
}

/* ------------------------------------------------------------------ */
/* Validacion de sesion en C (sin lanzar Python)                        */
/* ------------------------------------------------------------------ */

/* Lee sessions.json y verifica que el token exista y no haya expirado.
   Formato esperado: {"<token>": {"username": "...", "expires": <float>}}
   Devuelve 1 si válido, 0 en caso contrario.                          */
/* user_out (opcional): se rellena con el username de la sesion si la sesion es valida */
static int c_check_session(const char *token, char *user_out, int user_len)
{
    if (user_out && user_len > 0) user_out[0] = '\0';

    EnterCriticalSection(&g_sess_cs);
    FILE *f = fopen(SESSIONS_FILE, "r");
    if (!f) { LeaveCriticalSection(&g_sess_cs); return 0; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); LeaveCriticalSection(&g_sess_cs); return 0; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    LeaveCriticalSection(&g_sess_cs);

    /* Buscar el token como clave JSON: "<token64>" */
    char needle[70];
    snprintf(needle, sizeof(needle), "\"%s\"", token);
    const char *pos = strstr(buf, needle);
    if (!pos) { free(buf); return 0; }

    /* Extraer username del objeto de sesion */
    if (user_out && user_len > 0) {
        const char *up = strstr(pos, "\"username\":");
        if (up) {
            up += 11;
            while (*up == ' ' || *up == '\t') up++;
            if (*up == '"') {
                up++;
                int i = 0;
                while (*up && *up != '"' && i < user_len - 1)
                    user_out[i++] = *up++;
                user_out[i] = '\0';
            }
        }
    }

    /* Localizar "expires": dentro de ese objeto */
    const char *ep = strstr(pos, "\"expires\":");
    if (!ep) { free(buf); return 0; }
    ep += 10;
    while (*ep == ' ') ep++;
    double expires = strtod(ep, NULL);
    free(buf);

    return (double)time(NULL) < expires;
}

/* ------------------------------------------------------------------ */
/* Utilidades                                                           */
/* ------------------------------------------------------------------ */

/* URL-decode: convierte %XX y + en el valor real. */
static void url_decode(char *dst, const char *src, int dstlen)
{
    int i = 0;
    while (*src && i < dstlen - 1) {
        if (*src == '%' && src[1] && src[2]) {
            char hex[3] = {src[1], src[2], '\0'};
            dst[i++] = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            dst[i++] = ' ';
            src++;
        } else {
            dst[i++] = *src++;
        }
    }
    dst[i] = '\0';
}

/* Extrae el valor de un campo de un body URL-encoded. */
static int form_field(const char *body, const char *key,
                      char *out, int outlen)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "%s=", key);
    const char *p = strstr(body, needle);
    /* Requiere límite de campo: inicio del body o precedido por '&' */
    while (p && p != body && *(p - 1) != '&') {
        p = strstr(p + 1, needle);
    }
    if (!p) { out[0] = '\0'; return 0; }
    p += strlen(needle);
    /* Decodificar directamente sin buffer intermedio para soportar valores largos */
    int i = 0;
    while (*p && *p != '&' && i < outlen - 1) {
        if (*p == '%' && p[1] && p[2]) {
            char hex[3] = {p[1], p[2], '\0'};
            out[i++] = (char)strtol(hex, NULL, 16);
            p += 3;
        } else if (*p == '+') {
            out[i++] = ' ';
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return 1;
}

/* Escribe un string escapado dentro de comillas JSON. */
static void fwrite_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    while (*s) {
        if (*s == '"' || *s == '\\') fputc('\\', f);
        fputc(*s, f);
        s++;
    }
    fputc('"', f);
}

/* ------------------------------------------------------------------ */
/* Helpers de IPC y seguridad (MEDIA-01, BAJA-02)                       */
/* ------------------------------------------------------------------ */

/* Escapa un valor string para uso como valor JSON en un buffer de memoria.
   No escribe las comillas externas. */
static void json_escape_str(char *dst, int dstlen, const char *src)
{
    int i = 0;
    while (*src && i < dstlen - 1) {
        unsigned char c = (unsigned char)*src++;
        if (c == '"' || c == '\\') {
            if (i + 1 < dstlen - 1) { dst[i++] = '\\'; dst[i++] = (char)c; }
            else break;
        } else if (c == '\n') {
            if (i + 1 < dstlen - 1) { dst[i++] = '\\'; dst[i++] = 'n'; }
            else break;
        } else if (c == '\r') {
            if (i + 1 < dstlen - 1) { dst[i++] = '\\'; dst[i++] = 'r'; }
            else break;
        } else if (c >= 0x20) {
            dst[i++] = (char)c;
        }
        /* Caracteres de control < 0x20 (excepto \n, \r) se descartan */
    }
    dst[i] = '\0';
}

/* Parsea el valor del header Content-Length. Devuelve -1 si no está presente. */
static long get_content_length(const char *req)
{
    const char *p = strstr(req, "\r\nContent-Length:");
    if (!p) p = strstr(req, "\r\ncontent-length:");
    if (!p) return -1L;
    p += 17; /* saltar "\r\nContent-Length:" */
    while (*p == ' ' || *p == '\t') p++;
    char *end;
    long cl = strtol(p, &end, 10);
    return (end > p && cl >= 0) ? cl : -1L;
}

/* Extrae el valor de una cabecera HTTP (solo sección de cabeceras).
   Devuelve 1 si encontrada, 0 si no. */
static int get_header(const char *req, const char *name,
                      char *out, int outlen)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\r\n%s:", name);
    const char *hdr_end = strstr(req, "\r\n\r\n");
    const char *p = strstr(req, needle);
    if (!p || (hdr_end && p >= hdr_end)) { out[0] = '\0'; return 0; }
    p += strlen(needle);
    while (*p == ' ' || *p == '\t') p++;
    int i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < outlen - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

/* Verifica que Origin o Referer pertenezcan al mismo host.
   Defensa en profundidad para POST sensibles (se apila sobre CSRF token).
   Devuelve 1 si la petición parece legítima del frontend, 0 si debe rechazarse. */
static int same_origin(const char *req)
{
    char host[256]    = {0};
    char origin[512]  = {0};
    char referer[512] = {0};

    /* Sin Host no podemos comparar; el CSRF token es la barrera principal */
    if (!get_header(req, "Host", host, sizeof(host))) return 1;

    if (get_header(req, "Origin", origin, sizeof(origin))) {
        if (strcmp(origin, "null") != 0) {
            /* Origin tiene valor real → debe coincidir con el host */
            char exp_http[300]  = {0};
            char exp_https[300] = {0};
            snprintf(exp_http,  sizeof(exp_http),  "http://%s",  host);
            snprintf(exp_https, sizeof(exp_https), "https://%s", host);
            if (strcmp(origin, exp_http) != 0 && strcmp(origin, exp_https) != 0)
                return 0; /* origen real que no coincide → rechazar */
            return 1;    /* origen coincide → aceptar */
        }
        /* Origin: null (puede ser form-POST mismo origen en Chrome) →
           no rechazar; dejar pasar al check de Referer */
    }

    if (get_header(req, "Referer", referer, sizeof(referer))) {
        char exp_http[300]  = {0};
        char exp_https[300] = {0};
        snprintf(exp_http,  sizeof(exp_http),  "http://%s/",  host);
        snprintf(exp_https, sizeof(exp_https), "https://%s/", host);
        return (strncmp(referer, exp_http,  strlen(exp_http))  == 0 ||
                strncmp(referer, exp_https, strlen(exp_https)) == 0);
    }

    /* Sin Origin ni Referer: cliente sin contexto navegador.
       Se deja pasar; el CSRF token single-use filtra el resto. */
    return 1;
}

/* ------------------------------------------------------------------ */
/* IPC con Python via CreateProcess + pipes anónimas (MEDIA-01)         */
/* Reemplaza el patrón _popen + archivo temporal.                       */
/* script : ruta relativa del script Python (p.ej. "security\\auth.py") */
/* json_in: payload JSON enviado al stdin del proceso hijo               */
/* out_buf: buffer donde se recibe la salida; el llamador lo aloca       */
/* Devuelve 1 si éxito, 0 si fallo al crear el proceso.                 */
/* ------------------------------------------------------------------ */
static int run_python(const char *script, const char *json_in,
                      char *out_buf, int out_len)
{
    HANDLE hInR = NULL, hInW = NULL;   /* stdin  del hijo */
    HANDLE hOutR = NULL, hOutW = NULL; /* stdout del hijo */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    out_buf[0] = '\0';
    if (!CreatePipe(&hInR, &hInW, &sa, 0)) return 0;
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0)) {
        CloseHandle(hInR); CloseHandle(hInW); return 0;
    }
    /* El padre no debe heredar los extremos que él mismo usa */
    SetHandleInformation(hInW,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { 0 };
    si.cb         = sizeof(si);
    si.hStdInput  = hInR;
    si.hStdOutput = hOutW;
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags    = STARTF_USESTDHANDLES;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s", script);

    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hInR);  /* el hijo ya heredó este extremo */
    CloseHandle(hOutW); /* el hijo ya heredó este extremo */
    if (!ok) { CloseHandle(hInW); CloseHandle(hOutR); return 0; }

    /* Enviar JSON al stdin del hijo */
    if (json_in && json_in[0]) {
        DWORD written;
        WriteFile(hInW, json_in, (DWORD)strlen(json_in), &written, NULL);
    }
    CloseHandle(hInW); /* EOF: el hijo detecta fin de stdin */

    /* Leer la salida del hijo */
    DWORD rd, total = 0;
    while (total < (DWORD)(out_len - 1)) {
        if (!ReadFile(hOutR, out_buf + total,
                      (DWORD)(out_len - 1) - total, &rd, NULL) || rd == 0)
            break;
        total += rd;
    }
    out_buf[total] = '\0';
    CloseHandle(hOutR);

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Eliminar espacios/saltos finales */
    while (total > 0 &&
           (out_buf[total-1] == '\r' || out_buf[total-1] == '\n' ||
            out_buf[total-1] == ' '))
        out_buf[--total] = '\0';

    return 1;
}

/* Lee un archivo completo en un buffer heap; el llamador debe liberar. */
static char *read_file(const char *path, long *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    if (out_size) *out_size = sz;
    return buf;
}

/* Cierre limpio de conexión: shutdown + drain + close.
   Elimina la espera de ~2s de TCP TIME_WAIT en Windows. */
static void tcp_close(SOCKET s)
{
    shutdown(s, SD_SEND);          /* envía FIN al cliente                */
    char drain[256];               /* drena datos que aún pueda enviar él */
    while (recv(s, drain, sizeof(drain), 0) > 0) {}
    closesocket(s);
}

/* Extrae method y path de la primera línea HTTP. */
static void parse_request_line(const char *req,
                                char *method, int mlen,
                                char *path,   int plen)
{
    int i = 0, j = 0;
    while (req[i] && req[i] != ' ' && j < mlen - 1) method[j++] = req[i++];
    method[j] = '\0';
    if (req[i] == ' ') i++;
    j = 0;
    while (req[i] && req[i] != ' ' && req[i] != '\r' && j < plen - 1)
        path[j++] = req[i++];
    path[j] = '\0';
}

/* Devuelve puntero al cuerpo (después de \r\n\r\n), o NULL. */
static const char *get_body(const char *req)
{
    const char *p = strstr(req, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

/* Extrae el valor de una cookie por nombre. */
static void get_cookie(const char *req, const char *name,
                       char *out, int outlen)
{
    out[0] = '\0';
    /* Buscar la cabecera Cookie: en una línea propia */
    const char *hdr = strstr(req, "\r\nCookie:");
    if (!hdr) return;
    hdr += 9; /* saltar \r\nCookie: */
    while (*hdr == ' ') hdr++;

    /* Copiar la línea entera de cookies en un buffer temporal */
    char line[1024] = {0};
    int  i = 0;
    while (hdr[i] && hdr[i] != '\r' && hdr[i] != '\n' && i < 1023) {
        line[i] = hdr[i];
        i++;
    }

    /* Buscar name= dentro de la línea */
    char needle[128];
    snprintf(needle, sizeof(needle), "%s=", name);
    const char *p = strstr(line, needle);
    if (!p) return;
    p += strlen(needle);
    i = 0;
    while (p[i] && p[i] != ';' && p[i] != '\r' && p[i] != '\n'
           && i < outlen - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Envío de respuesta HTTP                                              */
/* ------------------------------------------------------------------ */

static void send_response(SOCKET s,
                          int status, const char *status_text,
                          const char *content_type,
                          const char *body, int body_len,
                          const char *extra_headers)
{
    char header[2048];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 0\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Security-Policy: default-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' https://cdnjs.cloudflare.com\r\n"
        "Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n"
        "%s"
        "\r\n",
        status, status_text, content_type, body_len,
        extra_headers ? extra_headers : "");
    send(s, header, hlen, 0);
    if (body && body_len > 0)
        send(s, body, body_len, 0);
}

/* ------------------------------------------------------------------ */
/* Manejadores de GET /register y POST /register                        */
/* ------------------------------------------------------------------ */

/* ─────────────────────────────────────────────────────────────────
 * serve_page: sirve una página HTML con CSRF token inyectado y,
 *   opcionalmente, con un div de error visible (display:none→flex).
 * page_src/page_sz : caché en memoria (NULL → lee page_path desde disco).
 * csrf_token : 64-char hex token (NULL → no inyectar).
 * err_id     : valor del atributo id= a revelar (NULL → ninguno).
 * ───────────────────────────────────────────────────────────────── */
static void serve_page(SOCKET client,
                        const char *page_src, long page_sz,
                        const char *page_path,
                        const char *csrf_token,
                        const char *err_id)
{
    const char *src = page_src;
    long ssz = page_sz;
    char *tmp_html = NULL;
    if (!src) {
        tmp_html = read_file(page_path, &ssz);
        src = tmp_html;
    }
    if (!src) {
        const char *e = "404 Not Found";
        send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        return;
    }
    /* Buffer: +64 bytes para expansión del token CSRF (64-14=50 extra) */
    long buf_cap = ssz + 64;
    char *buf = (char *)malloc(buf_cap);
    if (!buf) {
        if (tmp_html) free(tmp_html);
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }
    memcpy(buf, src, ssz);
    buf[ssz] = '\0';
    long bsz = ssz;

    /* Inyectar token CSRF: reemplaza __CSRF_TOKEN__ (14 chars) por el token (64 chars) */
    if (csrf_token) {
        char *p = strstr(buf, "__CSRF_TOKEN__");
        if (p) {
            long prefix = (long)(p - buf);
            long suffix = bsz - prefix - 14;
            memmove(p + 64, p + 14, suffix + 1);
            memcpy(p, csrf_token, 64);
            bsz += 50; /* 64 - 14 */
        }
    }

    /* Mostrar div de error */
    if (err_id) {
        char *anchor = strstr(buf, err_id);
        if (anchor) {
            char *nd = strstr(anchor, "display:none");
            if (nd) memcpy(nd, "display:flex", 12);
        }
    }

    send_response(client, 200, "OK", "text/html; charset=utf-8", buf, (int)bsz, NULL);
    free(buf);
    if (tmp_html) free(tmp_html);
}

/* Variante para la página de registro: inyecta CSRF + __REGKEY_REQUIRED__
   + muestra div de error opcional. */
static void serve_register_page(SOCKET client, const char *err_id)
{
    char csrf_tok[65] = {0};
    char cap_tok[33]  = {0};
    char cap_q[8]     = {0};
    csrf_generate(csrf_tok);
    captcha_generate(cap_tok, cap_q);

    const char *src  = g_html_reg ? g_html_reg : NULL;
    long         ssz = g_html_reg ? g_html_reg_sz : 0;
    char *tmp_html = NULL;
    if (!src) {
        tmp_html = read_file(REGISTER_PATH, &ssz);
        src = tmp_html;
    }
    if (!src) {
        const char *e = "404 Not Found";
        send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        return;
    }
    /* Buffer: CSRF +50, CAPTCHA_TK +18, CAPTCHA_Q ±8, margen */
    long buf_cap = ssz + 120;
    char *buf = (char *)malloc(buf_cap);
    if (!buf) {
        if (tmp_html) free(tmp_html);
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }
    memcpy(buf, src, ssz);
    buf[ssz] = '\0';
    long bsz = ssz;

    /* Inyectar CSRF token (14 → 64, +50) */
    char *p = strstr(buf, "__CSRF_TOKEN__");
    if (p) {
        long prefix = (long)(p - buf);
        long suffix = bsz - prefix - 14;
        memmove(p + 64, p + 14, suffix + 1);
        memcpy(p, csrf_tok, 64);
        bsz += 50;
    }
    /* Inyectar token CAPTCHA (14 → 32, +18) */
    char *cp = strstr(buf, "__CAPTCHA_TK__");
    if (cp) {
        long prefix = (long)(cp - buf);
        long suffix = bsz - prefix - 14;
        memmove(cp + 32, cp + 14, suffix + 1);
        memcpy(cp, cap_tok, 32);
        bsz += 18;
    }
    /* Inyectar pregunta CAPTCHA (13 → variable, ej. "3 + 7") */
    char *qp = strstr(buf, "__CAPTCHA_Q__");
    if (qp) {
        long qlen   = (long)strlen(cap_q);
        long prefix = (long)(qp - buf);
        long suffix = bsz - prefix - 13;
        memmove(qp + qlen, qp + 13, suffix + 1);
        memcpy(qp, cap_q, qlen);
        bsz += (qlen - 13);
    }
    /* Mostrar div de error */
    if (err_id) {
        char *anchor = strstr(buf, err_id);
        if (anchor) {
            char *nd = strstr(anchor, "display:none");
            if (nd) memcpy(nd, "display:flex", 12);
        }
    }

    send_response(client, 200, "OK", "text/html; charset=utf-8", buf, (int)bsz, NULL);
    free(buf);
    if (tmp_html) free(tmp_html);
}

static void handle_register_get(SOCKET client, const char *path)
{
    (void)path; /* errores ya no se exponen en la URL */
    serve_register_page(client, NULL);
}

static void handle_register_post(SOCKET client, const char *body,
                                  const char *client_ip)
{
    /* ── Validar CSRF token ── */
    char csrf_tok[65] = {0};
    if (body) form_field(body, "csrf_token", csrf_tok, sizeof(csrf_tok));
    if (!csrf_validate(csrf_tok)) {
        audit_log("WARNING", "CSRF_REJECTED", "-", client_ip, "/register");
        const char *e = "403 Forbidden";
        send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        return;
    }

    if (!body || strlen(body) == 0) {
        audit_log("WARNING", "REGISTER_INVALID", "-", client_ip, "empty body");
        serve_register_page(client, "id=\"regErr1\"");
        return;
    }

    char username[128] = {0}, password[512] = {0}, confirm[512] = {0};
    char ci[32] = {0}, cap_tok[33] = {0}, cap_ans[8] = {0};
    form_field(body, "username",    username, sizeof(username));
    form_field(body, "password",    password, sizeof(password));
    form_field(body, "confirm",     confirm,  sizeof(confirm));
    form_field(body, "ci",          ci,       sizeof(ci));
    form_field(body, "captcha_tok", cap_tok,  sizeof(cap_tok));
    form_field(body, "captcha_ans", cap_ans,  sizeof(cap_ans));

    /* ── Validar CAPTCHA ── */
    if (!captcha_validate(cap_tok, cap_ans)) {
        audit_log("WARNING", "REGISTER_CAPTCHA",
                  username[0] ? username : "-", client_ip, "wrong captcha");
        serve_register_page(client, "id=\"regErr8\"");
        return;
    }

    /* ── Validar campos obligatorios ── */
    if (username[0] == '\0' || password[0] == '\0') {
        audit_log("WARNING", "REGISTER_INVALID",
                  username[0] ? username : "-", client_ip, "empty fields");
        serve_register_page(client, "id=\"regErr1\"");
        return;
    }

    /* ── Validar que las contraseñas coinciden en C ── */
    if (strcmp(password, confirm) != 0) {
        audit_log("WARNING", "REGISTER_MISMATCH", username, client_ip,
                  "passwords do not match");
        serve_register_page(client, "id=\"regErr4\"");
        return;
    }

    /* ── Construir JSON para register.py y enviarlo por pipe ── */
    char u_esc[256]  = {0}, p_esc[640]  = {0}, ci_esc[64] = {0};
    json_escape_str(u_esc,  sizeof(u_esc),  username);
    json_escape_str(p_esc,  sizeof(p_esc),  password);
    json_escape_str(ci_esc, sizeof(ci_esc), ci);
    char json_in[1024] = {0};
    snprintf(json_in, sizeof(json_in),
             "{\"username\":\"%s\",\"password\":\"%s\",\"ci\":\"%s\"}",
             u_esc, p_esc, ci_esc);

    char py_out[512] = {0};
    run_python(REG_CMD, json_in, py_out, sizeof(py_out));

    if (strstr(py_out, "\"status\": \"ok\"")) {
        audit_log("INFO", "REGISTER_SUCCESS", username, client_ip,
                  "account created");
        /* POST-Redirect-GET: redirigir al login con indicador de éxito */
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /?registered=1\r\n");
    } else {
        /* Extraer código de error devuelto por Python */
        int code = 1;
        const char *cp = strstr(py_out, "\"code\": ");
        if (cp) code = atoi(cp + 8);
        const char *ev = (code == 2) ? "REGISTER_DUPLICATE" :
                         (code == 3) ? "REGISTER_WEAK_PW"   :
                         (code == 6) ? "REGISTER_INVALID_CI": "REGISTER_ERROR";
        audit_log("WARNING", ev, username, client_ip, py_out);
        /* Servir página directamente con error visible (sin URL leak) */
        char err_div[16];
        snprintf(err_div, sizeof(err_div), "id=\"regErr%d\"", code > 0 && code <= 6 ? code : 1);
        serve_register_page(client, err_div);
    }
}

/* ------------------------------------------------------------------ */
/* Manejador de GET /setup-ci  (formulario único de ingreso de CI)      */
/* ------------------------------------------------------------------ */

/* Declaraciones forward: definiciones completas más abajo */
static int c_user_has_ci(const char *username);
static int c_get_user_ci(const char *username, char *out, int len);
static int buf_replace_all(char *buf, int *sz, int cap,
                            const char *needle, const char *rep);

static void handle_setup_ci_get(SOCKET client, const char *req,
                                 const char *path, const char *client_ip)
{
    /* Verificar sesión activa */
    char token[128] = {0};
    get_cookie(req, "session", token, sizeof(token));
    if (token[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }
    char sess_user[64] = {0};
    if (!c_check_session(token, sess_user, sizeof(sess_user))) {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }

    /* Si el usuario ya tiene CI, redirigir al dashboard (página inaccesible) */
    if (c_user_has_ci(sess_user)) {
        audit_log("INFO", "CI_SETUP_BLOCKED", sess_user, client_ip,
                  "CI already set, redirecting to dashboard");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /dashboard\r\n");
        return;
    }

    /* Servir formulario CI con token CSRF inyectado */
    char csrf_tok[65] = {0};
    csrf_generate(csrf_tok);
    serve_page(client, g_html_setup_ci, g_html_setup_ci_sz, SETUP_CI_PATH,
               csrf_tok, NULL);
}

/* ------------------------------------------------------------------ */
/* Manejador de POST /setup-ci  (guarda el CI vía save_ci.py)           */
/* ------------------------------------------------------------------ */

static void handle_setup_ci_post(SOCKET client, const char *req,
                                  const char *body, const char *client_ip)
{
    /* Verificar sesión activa */
    char token[128] = {0};
    get_cookie(req, "session", token, sizeof(token));
    if (token[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }
    char sess_user[64] = {0};
    if (!c_check_session(token, sess_user, sizeof(sess_user))) {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }

    /* Inmutabilidad: si ya tiene CI, redirigir silenciosamente */
    if (c_user_has_ci(sess_user)) {
        audit_log("INFO", "CI_SETUP_BLOCKED", sess_user, client_ip,
                  "CI already set, blocking POST");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /dashboard\r\n");
        return;
    }

    /* ── Validar CSRF token ── */
    char csrf_tok[65] = {0};
    if (body) form_field(body, "csrf_token", csrf_tok, sizeof(csrf_tok));
    if (!csrf_validate(csrf_tok)) {
        audit_log("WARNING", "CSRF_REJECTED", sess_user, client_ip, "/setup-ci");
        const char *e = "403 Forbidden";
        send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        return;
    }

    if (!body || body[0] == '\0') {
        char new_csrf[65] = {0}; csrf_generate(new_csrf);
        serve_page(client, g_html_setup_ci, g_html_setup_ci_sz, SETUP_CI_PATH,
                   new_csrf, "id=\"ciErr1\"");
        return;
    }

    char ci[32] = {0};
    form_field(body, "ci", ci, sizeof(ci));

    if (ci[0] == '\0') {
        char new_csrf[65] = {0}; csrf_generate(new_csrf);
        serve_page(client, g_html_setup_ci, g_html_setup_ci_sz, SETUP_CI_PATH,
                   new_csrf, "id=\"ciErr1\"");
        return;
    }

    /* Construir JSON para save_ci.py y enviarlo por pipe directo (MEDIA-01) */
    char su_esc[128] = {0}, ci_esc[64] = {0};
    json_escape_str(su_esc, sizeof(su_esc), sess_user);
    json_escape_str(ci_esc, sizeof(ci_esc), ci);
    char json_in[256] = {0};
    snprintf(json_in, sizeof(json_in),
             "{\"username\":\"%s\",\"ci\":\"%s\"}", su_esc, ci_esc);

    char py_out[256] = {0};
    run_python(SAVE_CI_CMD, json_in, py_out, sizeof(py_out));

    if (strstr(py_out, "\"status\": \"ok\"")) {
        audit_log("INFO", "CI_SETUP_SUCCESS", sess_user, client_ip,
                  "CI saved successfully");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /dashboard\r\n");
    } else {
        audit_log("WARNING", "CI_SETUP_INVALID", sess_user, client_ip, py_out);
        char new_csrf[65] = {0}; csrf_generate(new_csrf);
        serve_page(client, g_html_setup_ci, g_html_setup_ci_sz, SETUP_CI_PATH,
                   new_csrf, "id=\"ciErr1\"");
    }
}

/* ------------------------------------------------------------------ */
/* Utilidad: HTML-escape de caracteres especiales                       */
/* ------------------------------------------------------------------ */
static void html_escape(char *dst, const char *src, int dstlen)
{
    int i = 0;
    while (*src && i < dstlen - 1) {
        if (*src == '&') {
            if (i + 5 < dstlen) { memcpy(dst+i,"&amp;",5); i+=5; src++; }
            else break;
        } else if (*src == '<') {
            if (i + 4 < dstlen) { memcpy(dst+i,"&lt;",4); i+=4; src++; }
            else break;
        } else if (*src == '>') {
            if (i + 4 < dstlen) { memcpy(dst+i,"&gt;",4); i+=4; src++; }
            else break;
        } else if (*src == '"') {
            if (i + 6 < dstlen) { memcpy(dst+i,"&quot;",6); i+=6; src++; }
            else break;
        } else {
            dst[i++] = *src++;
        }
    }
    dst[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Manejador GET /sign  — formulario de firma digital                   */
/* ------------------------------------------------------------------ */
static void handle_sign_get(SOCKET client, const char *req, const char *client_ip)
{
    /* Verificar sesión */
    char token[128] = {0};
    get_cookie(req, "session", token, sizeof(token));
    if (token[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }
    char sess_user[64] = {0};
    if (!c_check_session(token, sess_user, sizeof(sess_user))) {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }

    const char *src = g_html_sign ? g_html_sign : NULL;
    long ssz = g_html_sign ? g_html_sign_sz : 0;
    char *tmp_html = NULL;

    if (!src) {
        tmp_html = read_file(SIGN_PATH, &ssz);
        src = tmp_html;
    }
    if (!src) {
        const char *e = "404 Not Found";
        send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        if (tmp_html) free(tmp_html);
        return;
    }

    int cap = (int)ssz + 512;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        if (tmp_html) free(tmp_html);
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }
    memcpy(buf, src, ssz);
    buf[ssz] = '\0';
    int sz = (int)ssz;

    buf_replace_all(buf, &sz, cap, "__SIGNUSER__", sess_user);

    /* Inyectar CSRF token */
    char csrf_tok[65] = {0};
    csrf_generate(csrf_tok);
    char *cp = strstr(buf, "__CSRF_TOKEN__");
    if (cp) {
        int prefix = (int)(cp - buf);
        int suffix = sz - prefix - 14;
        memmove(cp + 64, cp + 14, suffix + 1);
        memcpy(cp, csrf_tok, 64);
        sz += 50;
    }

    send_response(client, 200, "OK", "text/html; charset=utf-8", buf, sz, NULL);
    free(buf);
    if (tmp_html) free(tmp_html);
}

/* ------------------------------------------------------------------ */
/* Extrae un campo JSON string del JSON plano retornado por Python.     */
/* Copia el valor en 'out' (hasta out_len-1 bytes).                    */
/* ------------------------------------------------------------------ */
static void json_extract_str(const char *json, const char *key,
                              char *out, int out_len)
{
    out[0] = '\0';
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (*p != '"') return;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < out_len - 1) {
        if (*p == '\\' && *(p+1) == '"') { out[i++] = '"'; p += 2; }
        else if (*p == '\\' && *(p+1) == 'n') { out[i++] = '\n'; p += 2; }
        else if (*p == '\\' && *(p+1) == '\\') { out[i++] = '\\'; p += 2; }
        else out[i++] = *p++;
    }
    out[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Manejador POST /sign  — firma el documento vía sign_doc.py          */
/* ------------------------------------------------------------------ */
static void handle_sign_post(SOCKET client, const char *req,
                              const char *body, const char *client_ip)
{
    /* Verificar sesión */
    char token[128] = {0};
    get_cookie(req, "session", token, sizeof(token));
    if (token[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }
    char sess_user[64] = {0};
    if (!c_check_session(token, sess_user, sizeof(sess_user))) {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }

    /* ── Validar CSRF token ── */
    char csrf_tok[65] = {0};
    if (body) form_field(body, "csrf_token", csrf_tok, sizeof(csrf_tok));
    if (!csrf_validate(csrf_tok)) {
        audit_log("WARNING", "CSRF_REJECTED", sess_user, client_ip, "/sign");
        const char *e = "403 Forbidden";
        send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        return;
    }

    if (!body || body[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /sign\r\n");
        return;
    }

    char text[2048] = {0};
    form_field(body, "text", text, sizeof(text));
    if (text[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /sign\r\n");
        return;
    }

    /* Generar claves si el usuario no las tiene aún */
    char keys_dir[256];
    snprintf(keys_dir, sizeof(keys_dir),
             "security\\data\\keys\\%s_private.pem", sess_user);
    {
        FILE *kf = fopen(keys_dir, "rb");
        if (!kf) {
            /* Llamar a keygen.py por pipe directo (MEDIA-01) */
            char su_esc_kg[128] = {0};
            json_escape_str(su_esc_kg, sizeof(su_esc_kg), sess_user);
            char kg_in[256] = {0};
            snprintf(kg_in, sizeof(kg_in), "{\"username\":\"%s\"}", su_esc_kg);
            char kg_out[256] = {0};
            run_python(KEYGEN_CMD, kg_in, kg_out, sizeof(kg_out));
        } else {
            fclose(kf);
        }
    }

    /* Preparar JSON para sign_doc.py y enviarlo por pipe directo (MEDIA-01) */
    char su_esc[128] = {0}, t_esc[2560] = {0};
    json_escape_str(su_esc, sizeof(su_esc), sess_user);
    json_escape_str(t_esc,  sizeof(t_esc),  text);
    char sign_in[2816] = {0};
    snprintf(sign_in, sizeof(sign_in),
             "{\"username\":\"%s\",\"text\":\"%s\"}", su_esc, t_esc);

    char py_out[12288] = {0};
    run_python(SIGN_CMD, sign_in, py_out, sizeof(py_out));

    /* Cargar plantilla HTML */
    const char *src = g_html_sign ? g_html_sign : NULL;
    long ssz = g_html_sign ? g_html_sign_sz : 0;
    char *tmp_html = NULL;
    if (!src) {
        tmp_html = read_file(SIGN_PATH, &ssz);
        src = tmp_html;
    }
    if (!src) {
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }

    /* Buffer con espacio para inyecciones (token ~3300 chars, texto ~3000 html-escaped) */
    int cap = (int)ssz + 12288;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        if (tmp_html) free(tmp_html);
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }
    memcpy(buf, src, ssz);
    buf[ssz] = '\0';
    int sz = (int)ssz;

    /* Siempre inyectar el usuario en el encabezado */
    buf_replace_all(buf, &sz, cap, "__SIGNUSER__", sess_user);

    if (strstr(py_out, "\"status\": \"ok\"") || strstr(py_out, "\"status\":\"ok\"")) {
        /* Extraer campos del JSON de respuesta */
        char f_signer[64]   = {0};
        char f_ci[32]       = {0};
        char f_ts[32]       = {0};
        char f_text[2200]   = {0};
        char f_token[4096]  = {0};

        json_extract_str(py_out, "signer",    f_signer,  sizeof(f_signer));
        json_extract_str(py_out, "ci",        f_ci,      sizeof(f_ci));
        json_extract_str(py_out, "timestamp", f_ts,      sizeof(f_ts));
        json_extract_str(py_out, "text",      f_text,    sizeof(f_text));
        json_extract_str(py_out, "token",     f_token,   sizeof(f_token));

        /* HTML-escapar el texto antes de inyectarlo en <pre> */
        char f_text_esc[3200] = {0};
        html_escape(f_text_esc, f_text, sizeof(f_text_esc));

        /* Mostrar la sección de resultado */
        char *anchor = strstr(buf, "id=\"signResult\"");
        if (anchor) {
            char *nd = strstr(anchor, "display:none");
            if (nd) memcpy(nd, "display:flex", 12);
        }

        buf_replace_all(buf, &sz, cap, "__SIGNER__",   f_signer);
        buf_replace_all(buf, &sz, cap, "__SIGNCI__",   f_ci[0] ? f_ci : "&mdash;");
        buf_replace_all(buf, &sz, cap, "__SIGTS__",    f_ts);
        buf_replace_all(buf, &sz, cap, "__SIGTEXT__",  f_text_esc);
        buf_replace_all(buf, &sz, cap, "__SIGTOKEN__", f_token);

        audit_log("INFO", "SIGN_SUCCESS", sess_user, client_ip, "document signed");
    } else {
        /* Mostrar error en la sección de error */
        char *anchor = strstr(buf, "id=\"signErr\"");
        if (anchor) {
            char *nd = strstr(anchor, "display:none");
            if (nd) memcpy(nd, "display:flex", 12);
        }
        audit_log("WARNING", "SIGN_FAILED", sess_user, client_ip, py_out);
    }

    send_response(client, 200, "OK", "text/html; charset=utf-8", buf, sz, NULL);
    free(buf);
    if (tmp_html) free(tmp_html);
}

/* ------------------------------------------------------------------ */
/* Manejador GET /verify — formulario de verificación (público)        */
/* ------------------------------------------------------------------ */
static void handle_verify_get(SOCKET client, const char *client_ip)
{
    (void)client_ip;
    const char *src = g_html_verify ? g_html_verify : NULL;
    long ssz = g_html_verify ? g_html_verify_sz : 0;
    char *tmp_html = NULL;

    if (!src) {
        tmp_html = read_file(VERIFY_PATH, &ssz);
        src = tmp_html;
    }
    if (!src) {
        const char *e = "404 Not Found";
        send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        if (tmp_html) free(tmp_html);
        return;
    }
    send_response(client, 200, "OK", "text/html; charset=utf-8",
                  src, (int)ssz, NULL);
    if (tmp_html) free(tmp_html);
}

/* ------------------------------------------------------------------ */
/* Manejador POST /verify — verifica token vía verify_doc.py           */
/* ------------------------------------------------------------------ */
static void handle_verify_post(SOCKET client, const char *body,
                                const char *client_ip)
{
    if (!body || body[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /verify\r\n");
        return;
    }

    char tok[8192] = {0};
    form_field(body, "token", tok, sizeof(tok));
    if (tok[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /verify\r\n");
        return;
    }

    /* Construir JSON para verify_doc.py y enviarlo por pipe directo (MEDIA-01) */
    char tok_esc[8192] = {0};
    json_escape_str(tok_esc, sizeof(tok_esc), tok);
    char json_in_v[8448] = {0};
    snprintf(json_in_v, sizeof(json_in_v), "{\"token\":\"%s\"}", tok_esc);

    char py_out[1024] = {0};
    run_python(VERIFY_CMD, json_in_v, py_out, sizeof(py_out));

    /* Cargar plantilla */
    const char *src = g_html_verify ? g_html_verify : NULL;
    long ssz = g_html_verify ? g_html_verify_sz : 0;
    char *tmp_html = NULL;
    if (!src) {
        tmp_html = read_file(VERIFY_PATH, &ssz);
        src = tmp_html;
    }
    if (!src) {
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }

    int cap = (int)ssz + 1024;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        if (tmp_html) free(tmp_html);
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }
    memcpy(buf, src, ssz);
    buf[ssz] = '\0';
    int sz = (int)ssz;

    int is_ok = (strstr(py_out, "\"status\": \"ok\"") || strstr(py_out, "\"status\":\"ok\""));

    if (is_ok) {
        /* Extraer valid (booleano) */
        int valid = 0;
        if (strstr(py_out, "\"valid\": true") || strstr(py_out, "\"valid\":true"))
            valid = 1;

        char f_signer[64] = {0};
        char f_ci[32]     = {0};
        char f_ts[32]     = {0};
        json_extract_str(py_out, "signer",    f_signer, sizeof(f_signer));
        json_extract_str(py_out, "ci",        f_ci,     sizeof(f_ci));
        json_extract_str(py_out, "timestamp", f_ts,     sizeof(f_ts));

        /* Mostrar sección resultado */
        char *anchor = strstr(buf, "id=\"verifyResult\"");
        if (anchor) {
            char *nd = strstr(anchor, "display:none");
            if (nd) memcpy(nd, "display:flex", 12);
        }

        if (valid) {
            buf_replace_all(buf, &sz, cap, "__VCLASS__",  "valid");
            buf_replace_all(buf, &sz, cap, "__VSTATUS__", "Firma V&Aacute;LIDA &#10003;");
        } else {
            buf_replace_all(buf, &sz, cap, "__VCLASS__",  "invalid");
            buf_replace_all(buf, &sz, cap, "__VSTATUS__", "Firma INV&Aacute;LIDA &#10007;");
        }
        buf_replace_all(buf, &sz, cap, "__VSIGNER__", f_signer[0] ? f_signer : "&mdash;");
        buf_replace_all(buf, &sz, cap, "__VCI__",     f_ci[0]     ? f_ci     : "&mdash;");
        buf_replace_all(buf, &sz, cap, "__VTS__",     f_ts[0]     ? f_ts     : "&mdash;");

        audit_log("INFO", valid ? "VERIFY_VALID" : "VERIFY_INVALID",
                  f_signer, client_ip, valid ? "signature ok" : "signature mismatch");
    } else {
        /* Token inválido o clave no encontrada */
        char *anchor = strstr(buf, "id=\"verifyErr\"");
        if (anchor) {
            char *nd = strstr(anchor, "display:none");
            if (nd) memcpy(nd, "display:flex", 12);
        }
        audit_log("WARNING", "VERIFY_ERROR", "-", client_ip, py_out);
    }

    send_response(client, 200, "OK", "text/html; charset=utf-8", buf, sz, NULL);
    free(buf);
    if (tmp_html) free(tmp_html);
}

/* ------------------------------------------------------------------ */
/* Manejador de POST /login                                             */
/* ------------------------------------------------------------------ */

static void handle_login(SOCKET client, const char *req_full, const char *client_ip)
{
    const char *body = get_body(req_full);
    /* ¿Vino via proxy HTTPS? Determina si incluimos Secure en la cookie */
    int via_https = (strstr(req_full, "X-Forwarded-Proto: https") != NULL ||
                     strstr(req_full, "x-forwarded-proto: https") != NULL);
    const char *secure_flag = via_https ? "; Secure" : "";

    /* Extraer username para auditoría ANTES de cualquier validación.
       Solo desde form URL-encoded; JSON directo es solo para pruebas. */
    char log_user[128] = "-";
    if (body && body[0] != '\0' && body[0] != '{') {
        char tmp_u[128] = {0};
        form_field(body, "username", tmp_u, sizeof(tmp_u));
        if (tmp_u[0]) {
            strncpy(log_user, tmp_u, sizeof(log_user) - 1);
            log_user[sizeof(log_user) - 1] = '\0';
        }
    }

    /* ── Validar CSRF token ── */
    char csrf_tok[65] = {0};
    if (body) form_field(body, "csrf_token", csrf_tok, sizeof(csrf_tok));
    if (!csrf_validate(csrf_tok)) {
        audit_log("WARNING", "CSRF_REJECTED", log_user, client_ip, "/login");
        const char *e = "403 Forbidden";
        send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        return;
    }

    /* Rate limit por IP — antes de llamar a Python */
    if (!ip_check_and_record(client_ip)) {
        audit_log("CRITICAL", "AUTH_BLOCKED", log_user, client_ip,
                  "IP rate limit exceeded");
        char new_csrf[65] = {0};
        csrf_generate(new_csrf);
        serve_page(client, g_html_index, g_html_index_sz, HTML_PATH,
                   new_csrf, "id=\"loginError\"");
        return;
    }

    if (!body || strlen(body) == 0) {
        audit_log("WARNING", "AUTH_INVALID_INPUT", "-", client_ip,
                  "empty request body");
        char new_csrf[65] = {0};
        csrf_generate(new_csrf);
        serve_page(client, g_html_index, g_html_index_sz, HTML_PATH,
                   new_csrf, "id=\"loginError\"");
        return;
    }

    /* Construir payload JSON para auth.py y enviarlo por pipe directo (MEDIA-01) */
    char json_in[1024] = {0};
    if (body[0] == '{') {
        /* JSON directo (solo para pruebas desde curl, no desde el frontend) */
        snprintf(json_in, sizeof(json_in), "%s", body);
    } else {
        /* Form URL-encoded: username=...&password=... */
        char username[128] = {0}, password[512] = {0};
        char u_esc[256]    = {0}, p_esc[640]    = {0};
        form_field(body, "username", username, sizeof(username));
        form_field(body, "password", password, sizeof(password));
        json_escape_str(u_esc, sizeof(u_esc), username);
        json_escape_str(p_esc, sizeof(p_esc), password);
        snprintf(json_in, sizeof(json_in),
                 "{\"username\":\"%s\",\"password\":\"%s\"}", u_esc, p_esc);
    }

    char py_out[1024] = {0};
    run_python(AUTH_CMD, json_in, py_out, sizeof(py_out));

    /* Si el login fue exitoso: cookie + redirect al dashboard */
    if (strstr(py_out, "\"status\": \"ok\"")) {
        char token[128] = {0};
        const char *tok_pos = strstr(py_out, "\"token\": \"");
        if (tok_pos) {
            tok_pos += 10;
            int ti = 0;
            while (ti < 127 && tok_pos[ti] && tok_pos[ti] != '"') {
                token[ti] = tok_pos[ti];
                ti++;
            }
            token[ti] = '\0';
        }
        ip_reset(client_ip);
        audit_log("INFO", "AUTH_SUCCESS", log_user, client_ip,
                  "session created");
        char hdr[512];
        snprintf(hdr, sizeof(hdr),
            "Set-Cookie: session=%s; HttpOnly%s; SameSite=Strict; Path=/; Max-Age=3600\r\n"
            "Location: /dashboard\r\n",
            token, secure_flag);
        send_response(client, 302, "Found", "text/html", NULL, 0, hdr);
    } else {
        audit_log("WARNING", "AUTH_FAILURE", log_user, client_ip,
                  "invalid credentials");
        /* Servir página de login directamente con error (sin exponer info en URL) */
        char new_csrf[65] = {0};
        csrf_generate(new_csrf);
        serve_page(client, g_html_index, g_html_index_sz, HTML_PATH,
                   new_csrf, "id=\"loginError\"");
    }
}


/* ------------------------------------------------------------------ */
/* Personalizacion del dashboard por usuario                           */
/* ------------------------------------------------------------------ */

/* Reemplaza TODAS las ocurrencias de 'needle' por 'rep' en buf.
   sz: tamano actual del contenido; cap: capacidad total del buffer.
   Retorna 0 si no cabe, 1 si ok. */
/* ------------------------------------------------------------------ */
/* Acceso a users.json para leer CI por usuario                         */
/* ------------------------------------------------------------------ */

/* Lee el valor de 'field' dentro del bloque JSON del 'username' dado.
   Usa g_users_cs para proteger el acceso concurrente.
   Devuelve 1 si encontrado y no vacío; 0 en caso contrario.            */
static int c_get_user_field(const char *username, const char *field,
                             char *out, int out_len)
{
    if (out && out_len > 0) out[0] = '\0';

    EnterCriticalSection(&g_users_cs);
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { LeaveCriticalSection(&g_users_cs); return 0; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); LeaveCriticalSection(&g_users_cs); return 0; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    LeaveCriticalSection(&g_users_cs);

    /* Encontrar la clave "username" en el JSON */
    char user_needle[70];
    snprintf(user_needle, sizeof(user_needle), "\"%s\"", username);
    const char *user_pos = strstr(buf, user_needle);
    if (!user_pos) { free(buf); return 0; }

    /* Encontrar el { que abre el objeto de este usuario */
    const char *block = strchr(user_pos + strlen(user_needle), '{');
    if (!block) { free(buf); return 0; }

    /* Encontrar el } que cierra el objeto (no hay objetos anidados) */
    const char *end = strchr(block + 1, '}');
    if (!end) { free(buf); return 0; }

    /* Buscar "field": dentro del bloque */
    char field_needle[70];
    snprintf(field_needle, sizeof(field_needle), "\"%s\":", field);
    const char *fp = strstr(block, field_needle);
    if (!fp || fp >= end) { free(buf); return 0; }

    fp += strlen(field_needle);
    while (*fp == ' ' || *fp == '\t') fp++;
    if (*fp != '"') { free(buf); return 0; }
    fp++; /* saltar la comilla de apertura */

    int i = 0;
    while (*fp && *fp != '"' && i < out_len - 1)
        out[i++] = *fp++;
    out[i] = '\0';

    free(buf);
    return i > 0;
}

/* Devuelve 1 si el usuario tiene CI registrado, 0 si no. */
static int c_user_has_ci(const char *username)
{
    char ci[64] = {0};
    return c_get_user_field(username, "ci", ci, sizeof(ci));
}

/* Copia el CI del usuario en out[0..len-1]. Devuelve 1 si lo encontró. */
static int c_get_user_ci(const char *username, char *out, int len)
{
    return c_get_user_field(username, "ci", out, len);
}

static int buf_replace_all(char *buf, int *sz, int cap,
                            const char *needle, const char *rep)
{
    int nlen = (int)strlen(needle);
    int rlen = (int)strlen(rep);
    char *p = buf;
    while ((p = strstr(p, needle)) != NULL) {
        int rest = *sz - (int)(p - buf) - nlen;
        int newsize = *sz + (rlen - nlen);
        if (newsize + 1 > cap) return 0;
        memmove(p + rlen, p + nlen, rest + 1);
        memcpy(p, rep, rlen);
        *sz = newsize;
        p += rlen;
    }
    return 1;
}

/* Genera una copia del dashboard personalizada con el 'username' real.
   El llamador debe liberar el puntero retornado. */
static char *dash_inject(const char *tmpl, int tmpl_sz,
                          const char *username, const char *ci, int *out_sz)
{
    int cap = tmpl_sz + 1024;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    memcpy(buf, tmpl, tmpl_sz);
    buf[tmpl_sz] = '\0';
    int sz = tmpl_sz;

    /* Iniciales: primeros 2 chars del username en mayuscula */
    char ini[3];
    ini[0] = (username[0] >= 'a' && username[0] <= 'z')
             ? username[0] - 32 : username[0];
    ini[1] = username[1]
             ? ((username[1] >= 'a' && username[1] <= 'z')
                ? username[1] - 32 : username[1])
             : ini[0];
    ini[2] = '\0';

    const char *role = (strcmp(username, "admin") == 0)
                       ? "Administrador" : "Usuario";

    /* 1. Avatar: >JD< */
    char ini_rep[8];
    snprintf(ini_rep, sizeof(ini_rep), ">%s<", ini);
    buf_replace_all(buf, &sz, cap, ">JD<", ini_rep);

    /* 2. Todas las apariciones de "John Doe" -> username */
    buf_replace_all(buf, &sz, cap, "John Doe", username);

    /* 3. Campo Usuario: el valor literal "admin" entre tags */
    char usr_rep[64];
    snprintf(usr_rep, sizeof(usr_rep), ">%s<", username);
    buf_replace_all(buf, &sz, cap, ">admin<", usr_rep);

    /* 4. Rol */
    char role_needle[] = "<div class=\"info-value\">Administrador</div>";
    char role_rep[64];
    snprintf(role_rep, sizeof(role_rep),
             "<div class=\"info-value\">%s</div>", role);
    buf_replace_all(buf, &sz, cap, role_needle, role_rep);

    /* 5. CI: mostrar el valor real del usuario */
    if (ci && ci[0]) {
        char ci_rep[128];
        snprintf(ci_rep, sizeof(ci_rep),
                 "<div class=\"info-value\">%s</div>", ci);
        buf_replace_all(buf, &sz, cap,
            "<div class=\"info-value\">1.234.567-8</div>", ci_rep);
    } else {
        buf_replace_all(buf, &sz, cap,
            "<div class=\"info-value\">1.234.567-8</div>",
            "<div class=\"info-value\">&mdash;</div>");
    }

    *out_sz = sz;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Manejador de GET /dashboard                                          */
/* ------------------------------------------------------------------ */

static void handle_dashboard(SOCKET client, const char *req, const char *client_ip)
{
    char token[128] = {0};
    get_cookie(req, "session", token, sizeof(token));

    /* Sin cookie → redirigir al login */
    if (token[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }

    /* Validar que el token solo contiene hex lowercase (64 chars) */
    int tlen = (int)strlen(token);
    int safe = (tlen == 64);
    for (int i = 0; i < tlen && safe; i++) {
        char c = token[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            safe = 0;
    }
    if (!safe) {
        audit_log("CRITICAL", "SESSION_TAMPERED", "-", client_ip,
                  "malformed session token (non-hex or wrong length)");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /\r\n");
        return;
    }

    /* Validación de sesión directo en C — sin lanzar Python */
    char sess_user[64] = {0};
    if (c_check_session(token, sess_user, sizeof(sess_user))) {
        audit_log("INFO", "SESSION_ACCESS", sess_user[0] ? sess_user : "-",
                  client_ip, "dashboard accessed with valid session");

        /* Verificar CI — si no tiene, redirigir al formulario único */
        char sess_ci[64] = {0};
        if (!c_get_user_ci(sess_user, sess_ci, sizeof(sess_ci))) {
            audit_log("INFO", "CI_REQUIRED", sess_user, client_ip,
                      "redirecting to setup-ci");
            send_response(client, 302, "Found", "text/html", NULL, 0,
                          "Location: /setup-ci\r\n");
            return;
        }

        const char *tmpl     = g_html_dash;
        int          tmpl_sz = (int)g_html_dash_sz;
        char        *tmp_buf = NULL;
        long         tmp_sz  = 0;

        if (!tmpl) {
            tmp_buf = read_file(DASHBOARD_PATH, &tmp_sz);
            tmpl    = tmp_buf;
            tmpl_sz = (int)tmp_sz;
        }

        if (tmpl && sess_user[0]) {
            int inj_sz = 0;
            char *inj  = dash_inject(tmpl, tmpl_sz, sess_user, sess_ci, &inj_sz);
            if (inj) {
                send_response(client, 200, "OK",
                              "text/html; charset=utf-8", inj, inj_sz, NULL);
                free(inj);
            } else {
                send_response(client, 200, "OK",
                              "text/html; charset=utf-8", tmpl, tmpl_sz, NULL);
            }
        } else if (tmpl) {
            send_response(client, 200, "OK",
                          "text/html; charset=utf-8", tmpl, tmpl_sz, NULL);
        } else {
            send_response(client, 302, "Found", "text/html", NULL, 0,
                          "Location: /\r\n");
        }

        if (tmp_buf) free(tmp_buf);
        return;
    }

    /* Token inválido/expirado → limpiar cookie y redirigir */
    audit_log("WARNING", "SESSION_INVALID", "-", client_ip,
              "token not found or expired");
    send_response(client, 302, "Found", "text/html", NULL, 0,
        "Location: /\r\n"
        "Set-Cookie: session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/\r\n");
}

/* ------------------------------------------------------------------ */
/* Manejador de GET /logout                                             */
/* ------------------------------------------------------------------ */

static void handle_logout(SOCKET client, const char *client_ip)
{
    audit_log("INFO", "LOGOUT", "-", client_ip, "session terminated by user");
    send_response(client, 302, "Found", "text/html", NULL, 0,
        "Location: /\r\n"
        "Set-Cookie: session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/\r\n");
}

/* ------------------------------------------------------------------ */
/* Dispatch por ruta                                                    */
/* ------------------------------------------------------------------ */

static void handle_client(SOCKET client, const char *client_ip)
{
    char req[BUFFER_SIZE] = {0};
    int  received = recv(client, req, BUFFER_SIZE - 1, 0);
    if (received <= 0) { tcp_close(client); return; }
    req[received] = '\0';

    char method[16] = {0}, path[256] = {0};
    parse_request_line(req, method, sizeof(method), path, sizeof(path));
    printf("[REQ] %-7s %s  (IP: %s)\n", method, path, client_ip);

    /* Tamaño del body declarado por el cliente (BAJA-02) */
    long req_cl = get_content_length(req);

    /* CORS preflight */
    if (strcmp(method, "OPTIONS") == 0) {
        send_response(client, 204, "No Content", "text/plain", NULL, 0,
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type\r\n");
    }
    /* Página de login — inyectar CSRF token; ?registered=1 muestra aviso */
    else if (strcmp(method, "GET") == 0 &&
             (strcmp(path, "/") == 0 || strncmp(path, "/?", 2) == 0)) {
        int show_success = (strstr(path, "registered=1") != NULL);
        char csrf_tok[65] = {0};
        csrf_generate(csrf_tok);
        serve_page(client,
                   g_html_index, g_html_index_sz, HTML_PATH,
                   csrf_tok,
                   show_success ? "id=\"loginSuccess\"" : NULL);
    }    /* Pagina de registro */
    else if (strcmp(method, "GET") == 0 &&
             (strcmp(path, "/register") == 0 || strncmp(path, "/register?", 10) == 0)) {
        handle_register_get(client, path);
    }
    /* Procesar nuevo registro */
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/register") == 0) {
        if (req_cl > MAX_BODY_REGISTER) {
            const char *e = "Payload Too Large";
            send_response(client, 413, "Payload Too Large", "text/plain", e, (int)strlen(e), NULL);
        } else if (!same_origin(req)) {
            audit_log("WARNING", "ORIGIN_REJECTED", "-", client_ip, "/register");
            const char *e = "403 Forbidden";
            send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        } else {
            handle_register_post(client, get_body(req), client_ip);
        }
    }    /* Configuración única de CI */
    else if (strcmp(method, "GET") == 0 &&
             (strcmp(path, "/setup-ci") == 0 || strncmp(path, "/setup-ci?", 10) == 0)) {
        handle_setup_ci_get(client, req, path, client_ip);
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/setup-ci") == 0) {
        if (req_cl > MAX_BODY_SETUP_CI) {
            const char *e = "Payload Too Large";
            send_response(client, 413, "Payload Too Large", "text/plain", e, (int)strlen(e), NULL);
        } else {
            handle_setup_ci_post(client, req, get_body(req), client_ip);
        }
    }    /* Firma digital */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/sign") == 0) {
        handle_sign_get(client, req, client_ip);
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/sign") == 0) {
        if (req_cl > MAX_BODY_SIGN) {
            const char *e = "Payload Too Large";
            send_response(client, 413, "Payload Too Large", "text/plain", e, (int)strlen(e), NULL);
        } else {
            handle_sign_post(client, req, get_body(req), client_ip);
        }
    }
    /* Verificación de firma (pública) */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/verify") == 0) {
        handle_verify_get(client, client_ip);
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/verify") == 0) {
        if (req_cl > MAX_BODY_VERIFY) {
            const char *e = "Payload Too Large";
            send_response(client, 413, "Payload Too Large", "text/plain", e, (int)strlen(e), NULL);
        } else {
            handle_verify_post(client, get_body(req), client_ip);
        }
    }    /* Dashboard protegido por sesión */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/dashboard") == 0) {
        handle_dashboard(client, req, client_ip);
    }
    /* Logout */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/logout") == 0) {
        handle_logout(client, client_ip);
    }
    /* Autenticación */
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/login") == 0) {
        if (req_cl > MAX_BODY_LOGIN) {
            const char *e = "Payload Too Large";
            send_response(client, 413, "Payload Too Large", "text/plain", e, (int)strlen(e), NULL);
        } else {
            handle_login(client, req, client_ip);
        }
    }
    /* Archivo JS del dashboard */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/js/dash.js") == 0) {
        long jsz = 0;
        char *js = read_file("frontend\\js\\dash.js", &jsz);
        if (js) {
            send_response(client, 200, "OK",
                          "application/javascript; charset=utf-8",
                          js, (int)jsz, NULL);
            free(js);
        } else {
            const char *e = "404 Not Found";
            send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        }
    }
    /* Archivo JS de registro */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/js/register.js") == 0) {
        long jsz = 0;
        char *js = read_file("frontend\\js\\register.js", &jsz);
        if (js) {
            send_response(client, 200, "OK",
                          "application/javascript; charset=utf-8",
                          js, (int)jsz, NULL);
            free(js);
        } else {
            const char *e = "404 Not Found";
            send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        }
    }
    /* Archivo JS de firma digital (MEDIA-03: CSP sin unsafe-inline) */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/js/sign.js") == 0) {
        long jsz = 0;
        char *js = read_file("frontend\\js\\sign.js", &jsz);
        if (js) {
            send_response(client, 200, "OK",
                          "application/javascript; charset=utf-8",
                          js, (int)jsz, NULL);
            free(js);
        } else {
            const char *e = "404 Not Found";
            send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        }
    }
    /* Librería jsPDF local */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/js/jspdf.min.js") == 0) {
        long jsz = 0;
        char *js = read_file("frontend\\js\\jspdf.min.js", &jsz);
        if (js) {
            /* Enviar en bloques para soportar archivos grandes */
            char hdr[512];
            int hlen = snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/javascript; charset=utf-8\r\n"
                "Content-Length: %d\r\n"
                "Cache-Control: max-age=86400\r\n"
                "Connection: close\r\n"
                "\r\n", (int)jsz);
            send(client, hdr, hlen, 0);
            int sent = 0, remaining = (int)jsz;
            while (remaining > 0) {
                int chunk = remaining > 65536 ? 65536 : remaining;
                int r = send(client, js + sent, chunk, 0);
                if (r <= 0) break;
                sent += r;
                remaining -= r;
            }
            free(js);
        } else {
            const char *e = "404 Not Found";
            send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        }
    }
    /* Favicon — silenciar 404 del navegador */
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/favicon.ico") == 0) {
        send_response(client, 204, "No Content", "image/x-icon", NULL, 0, NULL);
    }
    /* Archivos CSS estáticos */
    else if (strcmp(method, "GET") == 0 && strncmp(path, "/css/", 5) == 0) {
        const char *fname = path + 5;
        /* Rechazar path traversal y nombres inválidos */
        int valid = (fname[0] != '\0' && !strstr(fname, "..") &&
                     !strchr(fname, '/') && !strchr(fname, '\\'));
        if (!valid) {
            const char *e = "403 Forbidden";
            send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        } else {
            char css_path[512];
            snprintf(css_path, sizeof(css_path), "frontend\\css\\%s", fname);
            long csz = 0;
            char *css = read_file(css_path, &csz);
            if (css) {
                send_response(client, 200, "OK",
                              "text/css; charset=utf-8", css, (int)csz, NULL);
                free(css);
            } else {
                const char *e = "404 Not Found";
                send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
            }
        }
    }
    /* Cualquier otra ruta */
    else {
        const char *err = "404 Not Found";
        send_response(client, 404, "Not Found", "text/plain",
                      err, (int)strlen(err), NULL);
    }

    tcp_close(client);
}

/* ------------------------------------------------------------------ */
/* Thread por conexión                                                  */
/* ------------------------------------------------------------------ */

typedef struct { SOCKET sock; char ip[INET_ADDRSTRLEN]; } ClientArgs;

static unsigned __stdcall client_thread(void *arg)
{
    ClientArgs *a = (ClientArgs *)arg;
    handle_client(a->sock, a->ip);
    free(a);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Punto de entrada                                                     */
/* ------------------------------------------------------------------ */

int main(void)
{
    /* Inicializar secciones críticas antes de cualquier cosa */
    InitializeCriticalSection(&g_ip_cs);
    InitializeCriticalSection(&g_sess_cs);
    InitializeCriticalSection(&g_audit_cs);
    InitializeCriticalSection(&g_users_cs);
    InitializeCriticalSection(&g_csrf_cs);
    InitializeCriticalSection(&g_captcha_cs);
    csrf_seed();

    /* Leer clave de registro: primero env var, luego archivo de config */
    {
        const char *rk = getenv("REGISTER_KEY");
        if (rk && rk[0]) {
            strncpy(g_register_key, rk, sizeof(g_register_key) - 1);
            g_register_key[sizeof(g_register_key) - 1] = '\0';
            printf("  [INFO] Registro restringido (REGISTER_KEY desde env)\n");
        } else {
            FILE *kf = fopen("security\\data\\register_key.txt", "r");
            if (kf) {
                if (fgets(g_register_key, sizeof(g_register_key), kf)) {
                    size_t klen = strlen(g_register_key);
                    while (klen > 0 && (g_register_key[klen-1] == '\n' ||
                                        g_register_key[klen-1] == '\r' ||
                                        g_register_key[klen-1] == ' '))
                        g_register_key[--klen] = '\0';
                }
                fclose(kf);
                if (g_register_key[0])
                    printf("  [INFO] Registro restringido (REGISTER_KEY desde archivo)\n");
                else
                    printf("  [WARN] register_key.txt vacío - registro abierto\n");
            } else {
                printf("  [WARN] REGISTER_KEY no configurado - registro abierto\n");
            }
        }
    }

    /* Cargar HTML en memoria (una sola vez; read-only desde los threads) */
    g_html_index = read_file(HTML_PATH,      &g_html_index_sz);
    g_html_dash  = read_file(DASHBOARD_PATH, &g_html_dash_sz);
    g_html_reg   = read_file(REGISTER_PATH,  &g_html_reg_sz);
    g_html_setup_ci = read_file(SETUP_CI_PATH, &g_html_setup_ci_sz);
    g_html_sign     = read_file(SIGN_PATH,     &g_html_sign_sz);
    g_html_verify   = read_file(VERIFY_PATH,   &g_html_verify_sz);
    if (!g_html_index)    fprintf(stderr, "WARN: no se pudo cachear %s\n", HTML_PATH);
    if (!g_html_dash)     fprintf(stderr, "WARN: no se pudo cachear %s\n", DASHBOARD_PATH);
    if (!g_html_reg)      fprintf(stderr, "WARN: no se pudo cachear %s\n", REGISTER_PATH);
    if (!g_html_setup_ci) fprintf(stderr, "WARN: no se pudo cachear %s\n", SETUP_CI_PATH);
    if (!g_html_sign)     fprintf(stderr, "WARN: no se pudo cachear %s\n", SIGN_PATH);
    if (!g_html_verify)   fprintf(stderr, "WARN: no se pudo cachear %s\n", VERIFY_PATH);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup fallo: %d\n", WSAGetLastError());
        return 1;
    }

    /* Dual-stack: acepta tanto IPv4 (127.0.0.1) como IPv6 (::1/localhost) */
    SOCKET srv = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        fprintf(stderr, "socket() fallo: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    /* Reutilización inmediata del puerto */
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    /* IPV6_V6ONLY=0 → acepta también conexiones IPv4 */
    int v6only = 0;
    setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(PORT);
    addr.sin6_addr   = in6addr_any;

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind() fallo: %d\n", WSAGetLastError());
        closesocket(srv); WSACleanup(); return 1;
    }
    if (listen(srv, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "listen() fallo: %d\n", WSAGetLastError());
        closesocket(srv); WSACleanup(); return 1;
    }

    printf("=============================================\n");
    printf("  Servidor HTTP iniciado en puerto %d\n", PORT);
    printf("  Abre: http://localhost:%d\n", PORT);
    printf("  Ctrl+C para detener\n");
    printf("=============================================\n\n");

    /* ISO 27001 A.8.15 — registrar inicio del servidor */
    char start_detail[64];
    snprintf(start_detail, sizeof(start_detail), "listening on port %d (dual-stack)", PORT);
    audit_log("INFO", "SERVER_START", "-", "-", start_detail);

    while (1) {
        struct sockaddr_in6 cli_addr;
        int cli_len = sizeof(cli_addr);
        SOCKET client = accept(srv, (struct sockaddr *)&cli_addr, &cli_len);
        if (client == INVALID_SOCKET) continue;

        /* Extraer IP real: IPv4-mapped (::ffff:x.x.x.x) → mostrar como IPv4 */
        char client_ip[INET6_ADDRSTRLEN] = "unknown";
        if (IN6_IS_ADDR_V4MAPPED(&cli_addr.sin6_addr)) {
            struct in_addr v4;
            memcpy(&v4, &cli_addr.sin6_addr.s6_addr[12], sizeof(v4));
            inet_ntop(AF_INET, &v4, client_ip, sizeof(client_ip));
        } else {
            inet_ntop(AF_INET6, &cli_addr.sin6_addr, client_ip, sizeof(client_ip));
        }

        /* Crear un hilo por conexión — el accept loop no se bloquea */
        ClientArgs *args = (ClientArgs *)malloc(sizeof(ClientArgs));
        if (!args) { tcp_close(client); continue; }
        args->sock = client;
        strncpy(args->ip, client_ip, INET_ADDRSTRLEN - 1);
        args->ip[INET_ADDRSTRLEN - 1] = '\0';

        HANDLE h = (HANDLE)_beginthreadex(NULL, 0, client_thread, args, 0, NULL);
        if (h) {
            CloseHandle(h); /* desvinculamos el handle; el thread se limpia solo */
        } else {
            /* Fallback síncrono si falla la creación del hilo */
            handle_client(client, client_ip);
            free(args);
        }
    }

    closesocket(srv);
    WSACleanup();
    DeleteCriticalSection(&g_ip_cs);
    DeleteCriticalSection(&g_sess_cs);
    return 0;
}
