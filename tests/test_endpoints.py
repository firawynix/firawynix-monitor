"""Verificações HTTP/TLS/TCP contra servidores locais com certificados gerados no teste."""

import datetime as dt
import http.server
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.endpoints import check_endpoint, parse_endpoint
from core.models import ServiceStatus

# ---------------------------------------------------------------------------
# Certificados e servidores locais
# ---------------------------------------------------------------------------


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def _cert(subject, issuer, public_key, signing_key, days: int, *, ca: bool = False):
    now = dt.datetime.now(dt.UTC)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=days)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    else:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    folder = tmp_path_factory.mktemp("pki")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(_name("Teste Root CA", "Firawynix Teste"), _name("Teste Root CA", "Firawynix Teste"),
               ca_key.public_key(), ca_key, 3650, ca=True)
    (folder / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def server_cert(name: str, days: int, *, self_signed: bool = False):
        key = ec.generate_private_key(ec.SECP256R1())
        issuer, signer = (_name("localhost"), key) if self_signed else (ca.subject, ca_key)
        cert = _cert(_name("localhost"), issuer, key.public_key(), signer, days)
        (folder / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                               serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption()))
        return str(folder / f"{name}.pem"), str(folder / f"{name}.key")

    return {"ca": str(folder / "ca.pem"), "valid": server_cert("valid", 100), "soon": server_cert("soon", 5),
            "self": server_cert("self", 100, self_signed=True)}


class _Handler(http.server.BaseHTTPRequestHandler):
    routes = {"/": (200, {}), "/down": (503, {}), "/missing": (404, {}), "/old": (301, {"Location": "/new"})}

    def do_GET(self):  # noqa: N802
        status, headers = self.routes.get(self.path, (200, {}))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def _serve(cert: tuple[str, str] | None = None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*cert)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def http_server():
    server = _serve()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def https_servers(pki):
    servers = {name: _serve(pki[name]) for name in ("valid", "soon", "self")}
    yield {name: server.server_address[1] for name, server in servers.items()}
    for server in servers.values():
        server.shutdown()


# ---------------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("text", "scheme", "host", "port", "path"), [
    ("exemplo.com", "https", "exemplo.com", 443, "/"),
    ("https://api.exemplo.com/health?full=1", "https", "api.exemplo.com", 443, "/health?full=1"),
    ("http://10.0.0.5:8080", "http", "10.0.0.5", 8080, "/"),
    ("tls://mail.exemplo.com:993", "tls", "mail.exemplo.com", 993, "/"),
    ("tcp://[2001:db8::1]:5432", "tcp", "2001:db8::1", 5432, "/"),
])
def test_parse_endpoint(text, scheme, host, port, path):
    spec = parse_endpoint(text)
    assert (spec.scheme, spec.host, spec.port, spec.path) == (scheme, host, port, path)


@pytest.mark.parametrize(("text", "message"), [
    ("https://user:senha@exemplo.com", "credenciais"), ("ftp://exemplo.com", "não suportado"),
    ("tcp://db.exemplo.com", "exige a porta"), ("https://", "host ausente"), ("", "vazio"),
    ("https://exemplo.com:99999", "porta"),
])
def test_parse_endpoint_rejects(text, message):
    with pytest.raises(ValueError, match=message):
        parse_endpoint(text)


def test_http_status_codes(http_server):
    base = f"http://127.0.0.1:{http_server}"
    ok = check_endpoint(parse_endpoint(base + "/"))
    assert (ok.status, ok.http_status) == (ServiceStatus.ACTIVE, 200) and ok.latency_ms > 0
    assert check_endpoint(parse_endpoint(base + "/down")).status is ServiceStatus.FAILED
    assert check_endpoint(parse_endpoint(base + "/missing")).status is ServiceStatus.DEGRADED
    moved = check_endpoint(parse_endpoint(base + "/old"))
    assert moved.status is ServiceStatus.ACTIVE and "→ /new" in moved.detail


def test_https_valid_certificate(pki, https_servers):
    result = check_endpoint(parse_endpoint(f"https://localhost:{https_servers['valid']}/"), cafile=pki["ca"])
    assert (result.status, result.http_status, result.cert_valid) == (ServiceStatus.ACTIVE, 200, True)
    assert result.cert_days_left == pytest.approx(100, abs=1)
    assert result.cert_issuer == "Firawynix Teste (Teste Root CA)" and result.cert_subject == "localhost"


def test_https_certificate_expiring_soon(pki, https_servers):
    result = check_endpoint(parse_endpoint(f"https://localhost:{https_servers['soon']}/"), cafile=pki["ca"])
    assert result.status is ServiceStatus.DEGRADED and "expira em" in result.detail


def test_https_self_signed_is_failed_but_expiry_is_read(https_servers):
    result = check_endpoint(parse_endpoint(f"https://localhost:{https_servers['self']}/"))
    assert result.status is ServiceStatus.FAILED and result.cert_valid is False
    assert "certificado inválido" in result.detail and result.http_status == 200
    assert result.cert_days_left == pytest.approx(100, abs=1)


def test_tls_only_and_tcp(pki, https_servers, http_server):
    tls = check_endpoint(parse_endpoint(f"tls://localhost:{https_servers['valid']}"), cafile=pki["ca"])
    assert tls.status is ServiceStatus.ACTIVE and tls.http_status is None and "handshake TLS OK" in tls.detail
    assert check_endpoint(parse_endpoint(f"tcp://127.0.0.1:{http_server}")).status is ServiceStatus.ACTIVE
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
    refused = check_endpoint(parse_endpoint(f"tcp://127.0.0.1:{closed}"), timeout=2)
    assert refused.status is ServiceStatus.FAILED and "recusada" in refused.detail


def test_unresolvable_host():
    result = check_endpoint(parse_endpoint("https://nao-existe.invalid"), timeout=2)
    assert result.status is ServiceStatus.FAILED and result.latency_ms is None
