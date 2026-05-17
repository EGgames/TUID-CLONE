"""
https_proxy.py — Proxy HTTPS inverso para ID_LOGIN (ALTA-01)
=============================================================
Escucha en https://localhost:8443 (TLS 1.2+) y reenvía al servidor C
en http://localhost:8888. Inyecta HSTS. Genera certificado autofirmado
en security/ssl/ si no existe.

Uso:
    set KEY_ENCRYPTION_KEY=<clave_fuerte>   (opcional, para claves RSA cifradas)
    python https_proxy.py
"""

import http.server
import http.client
import ssl
import os
import ipaddress
import datetime
import socket
import sys

# ── Configuración ────────────────────────────────────────────────────
LISTEN_HOST   = "localhost"
LISTEN_PORT   = 8443
BACKEND_HOST  = "localhost"
BACKEND_PORT  = 8888
CERT_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "security", "ssl")
CERT_FILE     = os.path.join(CERT_DIR, "server.crt")
KEY_FILE      = os.path.join(CERT_DIR, "server.key")

# Headers hop-by-hop que no deben reenviarse (RFC 2616 §13.5.1)
_HOP_BY_HOP = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
])


# ── Generación de certificado autofirmado ────────────────────────────

def _generate_self_signed_cert(cert_path: str, key_path: str) -> None:
    """Genera un certificado RSA-2048 autofirmado válido 825 días."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("[!] El paquete 'cryptography' es necesario para generar el cert SSL.")
        print("    Instálalo con: pip install cryptography")
        sys.exit(1)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,            "CL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "ID_LOGIN"),
        x509.NameAttribute(NameOID.COMMON_NAME,             "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    # Permisos restrictivos en la clave privada
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[SSL] Certificado autofirmado generado en {cert_path}")


# ── Handler del proxy inverso ────────────────────────────────────────

class ReverseProxyHandler(http.server.BaseHTTPRequestHandler):

    # Suprimir log estándar de BaseHTTPRequestHandler (usamos el nuestro)
    def log_message(self, fmt, *args):
        pass

    def _forward(self, method: str, body: bytes = b"") -> None:
        """Reenvía la petición al backend y retransmite la respuesta."""
        # Filtrar headers hop-by-hop y construir los que se enviarán al backend
        fwd_headers = {}
        for key, val in self.headers.items():
            if key.lower() not in _HOP_BY_HOP:
                fwd_headers[key] = val

        # Sobrescribir Host para el backend
        fwd_headers["Host"] = f"{BACKEND_HOST}:{BACKEND_PORT}"
        # Indicar al backend que la petición original era HTTPS
        fwd_headers["X-Forwarded-Proto"] = "https"
        fwd_headers["X-Forwarded-For"]   = self.client_address[0]

        try:
            conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=30)
            conn.request(method, self.path, body=body if body else None,
                         headers=fwd_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
        except OSError as exc:
            self.send_error(502, f"Bad Gateway: {exc}")
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # Transmitir respuesta al cliente
        self.send_response(resp.status, resp.reason)

        # Reenviar headers de respuesta (filtrar hop-by-hop)
        for key, val in resp.getheaders():
            if key.lower() not in _HOP_BY_HOP:
                self.send_header(key, val)

        # Inyectar HSTS solo en hosts no locales (ALTA-01)
        # localhost/127.x se excluyen: los navegadores aplican HSTS a todos
        # los puertos del host y convertirían http://localhost:8888 → HTTPS
        host = self.headers.get("Host", "").split(":")[0].lower()
        _local = {"localhost", "127.0.0.1", "::1"}
        if host not in _local:
            self.send_header(
                "Strict-Transport-Security",
                "max-age=31536000"
            )
        self.end_headers()

        if resp_body:
            self.wfile.write(resp_body)

        print(f"[PROXY] {method} {self.path} → {resp.status} "
              f"({len(resp_body)} bytes)")

    def do_GET(self):     self._forward("GET")
    def do_HEAD(self):    self._forward("HEAD")
    def do_OPTIONS(self): self._forward("OPTIONS")
    def do_DELETE(self):  self._forward("DELETE")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length > 0 else b""
        self._forward("POST", body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length > 0 else b""
        self._forward("PUT", body)


# ── Punto de entrada ─────────────────────────────────────────────────

def main() -> None:
    # Generar certificado si no existe
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("[SSL] Generando certificado autofirmado...")
        _generate_self_signed_cert(CERT_FILE, KEY_FILE)

    # Configurar contexto TLS (mínimo TLS 1.2)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    server = http.server.HTTPServer((LISTEN_HOST, LISTEN_PORT), ReverseProxyHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[PROXY] Escuchando en https://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[PROXY] Reenviando a   http://{BACKEND_HOST}:{BACKEND_PORT}")
    print("[PROXY] Presiona Ctrl+C para detener.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[PROXY] Detenido.")
        server.server_close()


if __name__ == "__main__":
    main()
