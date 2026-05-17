"""
Aplica todos los cambios pendientes a backend/server.c:
  1.  Fix #defines de rutas de archivos
  2.  Añade global REGISTER_KEY y estructuras CSRF
  3.  Añade funciones CSRF después de ip_reset()
  4.  Añade helpers serve_page() y serve_register_page()
  5.  Elimina 'unsafe-inline' del CSP
  6.  Reescribe handle_register_get (CSRF + sin URL errors)
  7.  Reescribe handle_register_post (CSRF + REGISTER_KEY + sin URL errors)
  8.  Actualiza GET / (CSRF injection, elimina ?err=1 check)
  9.  Actualiza handle_login (CSRF validation + direct serving on failure)
 10.  Actualiza handle_setup_ci_get (CSRF injection)
 11.  Actualiza handle_setup_ci_post (CSRF + direct serving)
 12.  Actualiza handle_sign_get (CSRF injection)
 13.  Actualiza handle_sign_post (CSRF validation)
 14.  Añade ruta /css/ en handle_client
 15.  Añade CSRF init + REGISTER_KEY read en main()
"""

import sys

SRC = r"backend\server.c"

with open(SRC, "r", encoding="utf-8") as f:
    code = f.read()

errors = []

def replace_once(src, old, new, label):
    if old not in src:
        errors.append(f"NOT FOUND: {label}")
        return src
    n = src.count(old)
    if n > 1:
        errors.append(f"AMBIGUOUS ({n} matches): {label}")
        return src
    return src.replace(old, new)

# ─────────────────────────────────────────────────────────────────────
# 1. Fix #defines
# ─────────────────────────────────────────────────────────────────────
code = replace_once(code,
    '#define HTML_PATH         "frontend\\\\index.html"',
    '#define HTML_PATH         "frontend\\\\pages\\\\index.html"',
    "#define HTML_PATH")

code = replace_once(code,
    '#define SESSIONS_FILE     "security\\\\sessions.json"',
    '#define SESSIONS_FILE     "security\\\\data\\\\sessions.json"',
    "#define SESSIONS_FILE")

code = replace_once(code,
    '#define AUDIT_LOG         "security\\\\audit.log"',
    '#define AUDIT_LOG         "security\\\\data\\\\audit.log"',
    "#define AUDIT_LOG")

code = replace_once(code,
    '#define USERS_FILE        "security\\\\users.json"',
    '#define USERS_FILE        "security\\\\data\\\\users.json"',
    "#define USERS_FILE")

# ─────────────────────────────────────────────────────────────────────
# 2. Añadir REGISTER_KEY global + CSRF globals (después de g_users_cs)
# ─────────────────────────────────────────────────────────────────────
CSRF_GLOBALS = r"""
/* ── Registro restringido (variable de entorno REGISTER_KEY) ── */
static char g_register_key[129] = {0};

/* ── CSRF token store (single-use, tiempo de vida 2 h) ── */
#define CSRF_TABLE_SIZE   1024
#define CSRF_EXPIRY_SECS  7200

typedef struct { char token[65]; time_t expires; } CsrfEntry;
static CsrfEntry          g_csrf[CSRF_TABLE_SIZE];
static int                g_csrf_len = 0;
static unsigned long long g_csrf_state[2];
static CRITICAL_SECTION   g_csrf_cs;
"""

code = replace_once(code,
    "static CRITICAL_SECTION g_users_cs;/* protege lectura/escritura users.json */",
    "static CRITICAL_SECTION g_users_cs;/* protege lectura/escritura users.json */" + CSRF_GLOBALS,
    "g_users_cs decl → insert CSRF globals")

# ─────────────────────────────────────────────────────────────────────
# 3. Añadir funciones CSRF después de ip_reset()
# ─────────────────────────────────────────────────────────────────────
CSRF_FUNCTIONS = r"""
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
    /* Almacenar token */
    if (g_csrf_len < CSRF_TABLE_SIZE) {
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

"""

code = replace_once(code,
    "/* ------------------------------------------------------------------\n * Registro de auditoria",
    CSRF_FUNCTIONS + "/* ------------------------------------------------------------------\n * Registro de auditoria",
    "ip_reset → insert CSRF functions")

# ─────────────────────────────────────────────────────────────────────
# 4. Añadir helpers serve_page() y serve_register_page() antes de
#    handle_register_get
# ─────────────────────────────────────────────────────────────────────
PAGE_HELPERS = r"""/* ─────────────────────────────────────────────────────────────────
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
    csrf_generate(csrf_tok);
    const char *rkr = g_register_key[0] ? "1" : "0";

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
    /* Buffer: +68 bytes (CSRF +50, REGKEY shrinks, safety margin) */
    long buf_cap = ssz + 68;
    char *buf = (char *)malloc(buf_cap);
    if (!buf) {
        if (tmp_html) free(tmp_html);
        send_response(client, 500, "Internal Server Error", "text/plain", NULL, 0, NULL);
        return;
    }
    memcpy(buf, src, ssz);
    buf[ssz] = '\0';
    long bsz = ssz;

    /* Inyectar CSRF token */
    char *p = strstr(buf, "__CSRF_TOKEN__");
    if (p) {
        long prefix = (long)(p - buf);
        long suffix = bsz - prefix - 14;
        memmove(p + 64, p + 14, suffix + 1);
        memcpy(p, csrf_tok, 64);
        bsz += 50;
    }
    /* Inyectar indicador de clave de registro requerida */
    char *rp = strstr(buf, "__REGKEY_REQUIRED__");
    if (rp) {
        long nlen = 19, rlen = (long)strlen(rkr);
        long prefix = (long)(rp - buf);
        long suffix = bsz - prefix - nlen;
        memmove(rp + rlen, rp + nlen, suffix + 1);
        memcpy(rp, rkr, rlen);
        bsz += (rlen - nlen);
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

"""

code = replace_once(code,
    "static void handle_register_get(SOCKET client, const char *path)",
    PAGE_HELPERS + "static void handle_register_get(SOCKET client, const char *path)",
    "Insert serve_page helpers before handle_register_get")

# ─────────────────────────────────────────────────────────────────────
# 5. Eliminar 'unsafe-inline' del CSP
# ─────────────────────────────────────────────────────────────────────
code = replace_once(code,
    "\"Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' https://cdnjs.cloudflare.com\\r\\n\"",
    "\"Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self' https://cdnjs.cloudflare.com\\r\\n\"",
    "CSP remove unsafe-inline")

# ─────────────────────────────────────────────────────────────────────
# 6. Reescribir handle_register_get
# ─────────────────────────────────────────────────────────────────────
OLD_REG_GET = r"""static void handle_register_get(SOCKET client, const char *path)
{
    /* Extraer codigo de error del query string (?err=N) */
    int err = 0;
    const char *ep = strstr(path, "err=");
    if (ep) err = atoi(ep + 4);

    const char *src = g_html_reg ? g_html_reg : NULL;
    long ssz = g_html_reg ? g_html_reg_sz : 0;
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

    /* Mostrar el div de error correspondiente al codigo (1-6) */
    if (err >= 1 && err <= 6) {
        char *copy = (char *)malloc(ssz);
        if (copy) {
            memcpy(copy, src, ssz);
            /* Buscar id="regErrN" y revelar su display:none */
            char needle[16];
            snprintf(needle, sizeof(needle), "id=\"regErr%d\"", err);
            char *anchor = strstr(copy, needle);
            if (anchor) {
                char *nd = strstr(anchor, "display:none");
                if (nd) memcpy(nd, "display:flex", 12);
            }
            send_response(client, 200, "OK",
                          "text/html; charset=utf-8", copy, (int)ssz, NULL);
            free(copy);
        }
    } else {
        send_response(client, 200, "OK",
                      "text/html; charset=utf-8", src, (int)ssz, NULL);
    }

    if (tmp_html) free(tmp_html);
}"""

NEW_REG_GET = r"""static void handle_register_get(SOCKET client, const char *path)
{
    (void)path; /* errores ya no se exponen en la URL */
    serve_register_page(client, NULL);
}"""

code = replace_once(code, OLD_REG_GET, NEW_REG_GET, "handle_register_get rewrite")

# ─────────────────────────────────────────────────────────────────────
# 7. Reescribir handle_register_post
# ─────────────────────────────────────────────────────────────────────
OLD_REG_POST = r"""static void handle_register_post(SOCKET client, const char *body,
                                  const char *client_ip)
{
    if (!body || strlen(body) == 0) {
        audit_log("WARNING", "REGISTER_INVALID", "-", client_ip,
                  "empty body");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /register?err=1\r\n");
        return;
    }

    char username[128] = {0}, password[512] = {0}, confirm[512] = {0};
    char ci[32] = {0};
    form_field(body, "username", username, sizeof(username));
    form_field(body, "password", password, sizeof(password));
    form_field(body, "confirm",  confirm,  sizeof(confirm));
    form_field(body, "ci",       ci,       sizeof(ci));

    /* Validar campos obligatorios */
    if (username[0] == '\0' || password[0] == '\0') {
        audit_log("WARNING", "REGISTER_INVALID",
                  username[0] ? username : "-", client_ip, "empty fields");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /register?err=1\r\n");
        return;
    }

    /* Validar que las contrasenas coinciden en C (evita llamar a Python) */
    if (strcmp(password, confirm) != 0) {
        audit_log("WARNING", "REGISTER_MISMATCH", username, client_ip,
                  "passwords do not match");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /register?err=4\r\n");
        return;
    }

    /* Construir JSON para register.py y enviarlo por pipe directo (MEDIA-01) */
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
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /?registered=1\r\n");
    } else {
        /* Extraer codigo de error devuelto por Python */
        int code = 1;
        const char *cp = strstr(py_out, "\"code\": ");
        if (cp) code = atoi(cp + 8);
        const char *ev = (code == 2) ? "REGISTER_DUPLICATE" :
                         (code == 3) ? "REGISTER_WEAK_PW"   :
                         (code == 6) ? "REGISTER_INVALID_CI": "REGISTER_ERROR";
        audit_log("WARNING", ev, username, client_ip, py_out);
        char loc[64];
        snprintf(loc, sizeof(loc), "Location: /register?err=%d\r\n", code);
        send_response(client, 302, "Found", "text/html", NULL, 0, loc);
    }
}"""

NEW_REG_POST = r"""static void handle_register_post(SOCKET client, const char *body,
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
    char ci[32] = {0}, reg_key[129] = {0};
    form_field(body, "username",     username, sizeof(username));
    form_field(body, "password",     password, sizeof(password));
    form_field(body, "confirm",      confirm,  sizeof(confirm));
    form_field(body, "ci",           ci,       sizeof(ci));
    form_field(body, "register_key", reg_key,  sizeof(reg_key));

    /* ── Validar clave de registro (si REGISTER_KEY está configurado) ── */
    if (g_register_key[0] != '\0' && strcmp(reg_key, g_register_key) != 0) {
        audit_log("WARNING", "REGISTER_BADKEY",
                  username[0] ? username : "-", client_ip, "invalid register key");
        serve_register_page(client, "id=\"regErr1\"");
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
}"""

code = replace_once(code, OLD_REG_POST, NEW_REG_POST, "handle_register_post rewrite")

# ─────────────────────────────────────────────────────────────────────
# 8. Actualizar GET / handler (inyectar CSRF, eliminar ?err=1 check)
# ─────────────────────────────────────────────────────────────────────
OLD_GET_INDEX = r"""    /* Página de login (con o sin ?err=1) */
    else if (strcmp(method, "GET") == 0 &&
             (strcmp(path, "/") == 0 || strncmp(path, "/?", 2) == 0)) {
        int show_error   = (strstr(path, "err=1")        != NULL);
        int show_success = (strstr(path, "registered=1") != NULL);
        /* Usar caché en memoria; solo leer disco si el caché falló al arrancar */
        const char *src  = g_html_index ? g_html_index : NULL;
        long         ssz = g_html_index ? g_html_index_sz : 0;
        char *tmp_html = NULL;
        if (!src) {
            tmp_html = read_file(HTML_PATH, &ssz);
            src = tmp_html;
        }
        if (src) {
            if (show_error || show_success) {
                /* Copia modificable para inyectar el estado (display:none→flex) */
                char *copy = (char *)malloc(ssz);
                if (copy) {
                    memcpy(copy, src, ssz);
                    if (show_error) {
                        char *anchor = strstr(copy, "id=\"loginError\"");
                        if (anchor) {
                            char *nd = strstr(anchor, "display:none");
                            if (nd) memcpy(nd, "display:flex", 12);
                        }
                    }
                    if (show_success) {
                        char *anchor = strstr(copy, "id=\"loginSuccess\"");
                        if (anchor) {
                            char *nd = strstr(anchor, "display:none");
                            if (nd) memcpy(nd, "display:flex", 12);
                        }
                    }
                    send_response(client, 200, "OK",
                                  "text/html; charset=utf-8", copy, (int)ssz, NULL);
                    free(copy);
                }
            } else {
                send_response(client, 200, "OK",
                              "text/html; charset=utf-8", src, (int)ssz, NULL);
            }
            if (tmp_html) free(tmp_html);
        } else {
            const char *err = "404 - index.html no encontrado";
            send_response(client, 404, "Not Found", "text/plain",
                          err, (int)strlen(err), NULL);
        }
    }"""

NEW_GET_INDEX = r"""    /* Página de login — inyectar CSRF token; ?registered=1 muestra aviso */
    else if (strcmp(method, "GET") == 0 &&
             (strcmp(path, "/") == 0 || strncmp(path, "/?", 2) == 0)) {
        int show_success = (strstr(path, "registered=1") != NULL);
        char csrf_tok[65] = {0};
        csrf_generate(csrf_tok);
        serve_page(client,
                   g_html_index, g_html_index_sz, HTML_PATH,
                   csrf_tok,
                   show_success ? "id=\"loginSuccess\"" : NULL);
    }"""

code = replace_once(code, OLD_GET_INDEX, NEW_GET_INDEX, "GET / rewrite")

# ─────────────────────────────────────────────────────────────────────
# 9. Actualizar handle_login — CSRF + serving directo en fallo
# ─────────────────────────────────────────────────────────────────────
OLD_LOGIN_RATELIMIT = r"""    /* Rate limit por IP — antes de llamar a Python */
    if (!ip_check_and_record(client_ip)) {
        audit_log("CRITICAL", "AUTH_BLOCKED", log_user, client_ip,
                  "IP rate limit exceeded");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /?err=1\r\n");
        return;
    }

    if (!body || strlen(body) == 0) {
        audit_log("WARNING", "AUTH_INVALID_INPUT", "-", client_ip,
                  "empty request body");
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /?err=1\r\n");
        return;
    }"""

NEW_LOGIN_RATELIMIT = r"""    /* ── Validar CSRF token ── */
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
    }"""

code = replace_once(code, OLD_LOGIN_RATELIMIT, NEW_LOGIN_RATELIMIT, "handle_login rate-limit section")

OLD_LOGIN_FAILURE = r"""    } else {
        audit_log("WARNING", "AUTH_FAILURE", log_user, client_ip,
                  "invalid credentials");
        /* Credenciales incorrectas → redirect al login con flag de error */
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /?err=1\r\n");
    }
}


/* ------------------------------------------------------------------ */
/* Personalizacion del dashboard por usuario"""

NEW_LOGIN_FAILURE = r"""    } else {
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
/* Personalizacion del dashboard por usuario"""

code = replace_once(code, OLD_LOGIN_FAILURE, NEW_LOGIN_FAILURE, "handle_login failure redirect")

# ─────────────────────────────────────────────────────────────────────
# 10. Actualizar handle_setup_ci_get — inyectar CSRF, eliminar ?err=1
# ─────────────────────────────────────────────────────────────────────
OLD_CI_GET = r"""    /* Extraer código de error del query string (?err=N) */
    int err = 0;
    const char *ep = strstr(path, "err=");
    if (ep) err = atoi(ep + 4);

    const char *src = g_html_setup_ci ? g_html_setup_ci : NULL;
    long ssz = g_html_setup_ci ? g_html_setup_ci_sz : 0;
    char *tmp_html = NULL;

    if (!src) {
        tmp_html = read_file(SETUP_CI_PATH, &ssz);
        src = tmp_html;
    }
    if (!src) {
        const char *e = "404 Not Found";
        send_response(client, 404, "Not Found", "text/plain", e, (int)strlen(e), NULL);
        return;
    }

    if (err == 1) {
        char *copy = (char *)malloc(ssz);
        if (copy) {
            memcpy(copy, src, ssz);
            char *anchor = strstr(copy, "id=\"ciErr1\"");
            if (anchor) {
                char *nd = strstr(anchor, "display:none");
                if (nd) memcpy(nd, "display:flex", 12);
            }
            send_response(client, 200, "OK",
                          "text/html; charset=utf-8", copy, (int)ssz, NULL);
            free(copy);
        }
    } else {
        send_response(client, 200, "OK",
                      "text/html; charset=utf-8", src, (int)ssz, NULL);
    }

    if (tmp_html) free(tmp_html);
}"""

NEW_CI_GET = r"""    /* Servir formulario CI con token CSRF inyectado */
    char csrf_tok[65] = {0};
    csrf_generate(csrf_tok);
    serve_page(client, g_html_setup_ci, g_html_setup_ci_sz, SETUP_CI_PATH,
               csrf_tok, NULL);
}"""

code = replace_once(code, OLD_CI_GET, NEW_CI_GET, "handle_setup_ci_get rewrite")

# ─────────────────────────────────────────────────────────────────────
# 11. Actualizar handle_setup_ci_post — CSRF + serving directo en error
# ─────────────────────────────────────────────────────────────────────
OLD_CI_POST_BODY = r"""    if (!body || body[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /setup-ci?err=1\r\n");
        return;
    }

    char ci[32] = {0};
    form_field(body, "ci", ci, sizeof(ci));

    if (ci[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /setup-ci?err=1\r\n");
        return;
    }"""

NEW_CI_POST_BODY = r"""    /* ── Validar CSRF token ── */
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
    }"""

code = replace_once(code, OLD_CI_POST_BODY, NEW_CI_POST_BODY, "handle_setup_ci_post CSRF+body")

OLD_CI_POST_FAILURE = r"""        audit_log("WARNING", "CI_SETUP_INVALID", sess_user, client_ip, py_out);
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /setup-ci?err=1\r\n");
    }
}

/* ------------------------------------------------------------------ */
/* Utilidad: HTML-escape de caracteres especiales"""

NEW_CI_POST_FAILURE = r"""        audit_log("WARNING", "CI_SETUP_INVALID", sess_user, client_ip, py_out);
        char new_csrf[65] = {0}; csrf_generate(new_csrf);
        serve_page(client, g_html_setup_ci, g_html_setup_ci_sz, SETUP_CI_PATH,
                   new_csrf, "id=\"ciErr1\"");
    }
}

/* ------------------------------------------------------------------ */
/* Utilidad: HTML-escape de caracteres especiales"""

code = replace_once(code, OLD_CI_POST_FAILURE, NEW_CI_POST_FAILURE, "handle_setup_ci_post failure")

# ─────────────────────────────────────────────────────────────────────
# 12. Actualizar handle_sign_get — inyectar CSRF junto con __SIGNUSER__
# ─────────────────────────────────────────────────────────────────────
OLD_SIGN_GET = r"""    int cap = (int)ssz + 512;
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

    send_response(client, 200, "OK", "text/html; charset=utf-8", buf, sz, NULL);
    free(buf);
    if (tmp_html) free(tmp_html);
}"""

NEW_SIGN_GET = r"""    int cap = (int)ssz + 512;
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
}"""

code = replace_once(code, OLD_SIGN_GET, NEW_SIGN_GET, "handle_sign_get CSRF injection")

# ─────────────────────────────────────────────────────────────────────
# 13. Actualizar handle_sign_post — validar CSRF
# ─────────────────────────────────────────────────────────────────────
OLD_SIGN_POST_BODY = r"""    if (!body || body[0] == '\0') {
        send_response(client, 302, "Found", "text/html", NULL, 0,
                      "Location: /sign\r\n");"""

NEW_SIGN_POST_BODY = r"""    /* ── Validar CSRF token ── */
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
                      "Location: /sign\r\n");"""

code = replace_once(code, OLD_SIGN_POST_BODY, NEW_SIGN_POST_BODY, "handle_sign_post CSRF")

# ─────────────────────────────────────────────────────────────────────
# 14. Añadir ruta /css/ en handle_client (antes del else 404)
# ─────────────────────────────────────────────────────────────────────
CSS_ROUTE = r"""    /* Archivos CSS estáticos */
    else if (strcmp(method, "GET") == 0 && strncmp(path, "/css/", 5) == 0) {
        const char *fname = path + 5;
        /* Rechazar path traversal y nombres inválidos */
        int valid = (fname[0] != '\0' && !strstr(fname, "..") &&
                     !strchr(fname, '/') && !strchr(fname, '\\'));
        if (!valid) {
            const char *e = "403 Forbidden";
            send_response(client, 403, "Forbidden", "text/plain", e, (int)strlen(e), NULL);
        } else {
            char css_path[256];
            snprintf(css_path, sizeof(css_path), "frontend\\css\\%.240s", fname);
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
"""

code = replace_once(code,
    "    /* Cualquier otra ruta */\n    else {",
    CSS_ROUTE + "    /* Cualquier otra ruta */\n    else {",
    "CSS route in handle_client")

# ─────────────────────────────────────────────────────────────────────
# 15. Añadir CSRF init + REGISTER_KEY en main()
# ─────────────────────────────────────────────────────────────────────
OLD_MAIN_INIT = r"""    InitializeCriticalSection(&g_ip_cs);
    InitializeCriticalSection(&g_sess_cs);
    InitializeCriticalSection(&g_audit_cs);
    InitializeCriticalSection(&g_users_cs);"""

NEW_MAIN_INIT = r"""    InitializeCriticalSection(&g_ip_cs);
    InitializeCriticalSection(&g_sess_cs);
    InitializeCriticalSection(&g_audit_cs);
    InitializeCriticalSection(&g_users_cs);
    InitializeCriticalSection(&g_csrf_cs);
    csrf_seed();

    /* Leer clave de registro opcional desde variable de entorno */
    {
        const char *rk = getenv("REGISTER_KEY");
        if (rk && rk[0]) {
            strncpy(g_register_key, rk, sizeof(g_register_key) - 1);
            g_register_key[sizeof(g_register_key) - 1] = '\0';
            printf("  [INFO] Registro restringido (REGISTER_KEY configurado)\n");
        } else {
            printf("  [WARN] REGISTER_KEY no configurado - registro abierto\n");
        }
    }"""

code = replace_once(code, OLD_MAIN_INIT, NEW_MAIN_INIT, "main() CSRF + REGISTER_KEY init")

# ─────────────────────────────────────────────────────────────────────
# Verificar y escribir
# ─────────────────────────────────────────────────────────────────────
if errors:
    print("ERRORES encontrados:")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)
else:
    with open(SRC, "w", encoding="utf-8") as f:
        f.write(code)
    print("server.c modificado exitosamente.")
    print(f"Tamaño final: {len(code)} bytes")
