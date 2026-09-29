"""Verificações feitas a partir do Windows (não usam SSH): sites/APIs (HTTP),
validade e expiração de certificados TLS e portas TCP.

Formatos aceitos em ``endpoints`` no servers.json::

    "https://loja.exemplo.com/health"   GET, status HTTP, latência e certificado
    "http://10.0.0.5:8080/"             GET e status HTTP
    "tls://mail.exemplo.com:993"        só o handshake TLS e o certificado
    "tcp://db.exemplo.com:5432"         só a abertura da porta
    "exemplo.com"                       equivale a https://exemplo.com/

O certificado é lido mesmo quando inválido (autoassinado, expirado, nome errado):
a verificação padrão do Windows é feita primeiro e, se falhar, o motivo é
registrado e a conexão é refeita sem validação só para ler a data de expiração.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.models import EndpointResult, ServiceStatus

USER_AGENT = "FirawynixMonitor"
_DEFAULT_PORTS = {"https": 443, "http": 80, "tls": 443}


@dataclass(frozen=True)
class EndpointSpec:
    raw: str
    scheme: str
    host: str
    port: int
    path: str = "/"

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == _DEFAULT_PORTS.get(self.scheme) else f"{host}:{self.port}"


def parse_endpoint(text: str) -> EndpointSpec:
    raw = (text or "").strip()
    if not raw:
        raise ValueError("endpoint vazio")
    candidate = raw if "://" in raw else f"https://{raw}"
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http", "tls", "tcp"):
        raise ValueError(f"esquema '{scheme}' não suportado (use https, http, tls ou tcp)")
    if parts.username or parts.password:
        raise ValueError("credenciais na URL não são permitidas (segredo em texto plano)")
    if not parts.hostname:
        raise ValueError("host ausente")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"porta inválida: {exc}") from None
    if port is None:
        if scheme == "tcp":
            raise ValueError("tcp:// exige a porta (ex.: tcp://db.exemplo.com:5432)")
        port = _DEFAULT_PORTS[scheme]
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    return EndpointSpec(raw=raw, scheme=scheme, host=parts.hostname, port=port, path=path)


def _remaining(deadline: float) -> float:
    return max(0.2, deadline - time.monotonic())


def _name(name) -> str:
    from cryptography.x509.oid import NameOID

    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        values = name.get_attributes_for_oid(oid)
        if values:
            return str(values[0].value)
    return name.rfc4514_string()


def describe_certificate(der: bytes) -> dict:
    """Validade, emissor e assunto de um certificado DER (via ``cryptography``)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_der_x509_certificate(der)
    issuer = _name(cert.issuer)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if issuer_cn and str(issuer_cn[0].value) != issuer:
        issuer += f" ({issuer_cn[0].value})"
    subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "expires": cert.not_valid_after_utc.timestamp(),
        "issuer": issuer,
        "subject": str(subject_cn[0].value) if subject_cn else cert.subject.rfc4514_string(),
    }


def _tls_connect(spec: EndpointSpec, deadline: float, cafile: str | None) -> tuple[ssl.SSLSocket, str | None]:
    """Handshake verificado; se o certificado for inválido, refaz sem verificar."""
    context = ssl.create_default_context(cafile=cafile)
    raw = socket.create_connection((spec.host, spec.port), timeout=_remaining(deadline))
    try:
        return context.wrap_socket(raw, server_hostname=spec.host), None
    except ssl.SSLCertVerificationError as exc:
        raw.close()
        reason = exc.verify_message or str(exc)
    except BaseException:
        raw.close()
        raise
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((spec.host, spec.port), timeout=_remaining(deadline))
    try:
        return insecure.wrap_socket(raw, server_hostname=spec.host), reason
    except BaseException:
        raw.close()
        raise


def check_endpoint(spec: EndpointSpec, *, timeout: float = 5.0, cert_warning_days: float = 14,
                   now: float | None = None, cafile: str | None = None) -> EndpointResult:
    """``cafile`` substitui o repositório de certificados do Windows (CA interna, testes)."""
    started = time.monotonic()
    deadline = started + timeout
    now = time.time() if now is None else now
    cert: dict = {}
    verify_error = None
    try:
        if spec.scheme == "tcp":
            with socket.create_connection((spec.host, spec.port), timeout=timeout):
                latency = (time.monotonic() - started) * 1000
            return EndpointResult(spec.raw, spec.scheme, ServiceStatus.ACTIVE, latency, detail="porta aberta",
                                  checked_at=now)
        if spec.scheme in ("https", "tls"):
            sock, verify_error = _tls_connect(spec, deadline, cafile)
            der = sock.getpeercert(binary_form=True)
            if der:
                cert = describe_certificate(der)
        else:
            sock = socket.create_connection((spec.host, spec.port), timeout=timeout)
        with sock:
            if spec.scheme == "tls":
                latency = (time.monotonic() - started) * 1000
                return _finish(spec, now, latency, None, cert, verify_error, cert_warning_days, "")
            sock.settimeout(_remaining(deadline))
            request = (f"GET {spec.path} HTTP/1.1\r\nHost: {spec.host_header}\r\nUser-Agent: {USER_AGENT}\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n")
            sock.sendall(request.encode("latin-1", errors="replace"))
            response = http.client.HTTPResponse(sock, method="GET")
            response.begin()
            latency = (time.monotonic() - started) * 1000
            location = response.getheader("Location") or ""
            detail = f"{response.status} {response.reason}".strip()
            if location and 300 <= response.status < 400:
                detail += f" → {location[:120]}"
            return _finish(spec, now, latency, response.status, cert, verify_error, cert_warning_days, detail)
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
        return EndpointResult(spec.raw, spec.scheme, ServiceStatus.FAILED, None, detail=_describe_error(exc),
                              checked_at=now, **_cert_fields(cert, now, verify_error))


def _cert_fields(cert: dict, now: float, verify_error: str | None) -> dict:
    if not cert:
        return {}
    return {"cert_expires": cert["expires"], "cert_days_left": (cert["expires"] - now) / 86400,
            "cert_issuer": cert["issuer"], "cert_subject": cert["subject"], "cert_valid": verify_error is None}


def _finish(spec: EndpointSpec, now: float, latency: float, http_status: int | None, cert: dict,
            verify_error: str | None, warning_days: float, detail: str) -> EndpointResult:
    fields = _cert_fields(cert, now, verify_error)
    days = fields.get("cert_days_left")
    status = ServiceStatus.ACTIVE
    notes = []
    if verify_error:
        status = ServiceStatus.FAILED
        notes.append(f"certificado inválido: {verify_error}")
    elif days is not None and days < 0:
        status = ServiceStatus.FAILED
        notes.append("certificado EXPIRADO")
    elif days is not None and days <= warning_days:
        status = ServiceStatus.DEGRADED
        notes.append(f"certificado expira em {max(0, int(days))} dia(s)")
    if http_status is not None:
        if http_status >= 500:
            status = ServiceStatus.FAILED
        elif http_status >= 400 and status is ServiceStatus.ACTIVE:
            status = ServiceStatus.DEGRADED
    if spec.scheme == "tls" and not notes:
        notes.append("handshake TLS OK")
    text = " · ".join(part for part in (detail, *notes) if part)
    return EndpointResult(spec.raw, spec.scheme, status, latency, http_status, detail=text, checked_at=now, **fields)


def _describe_error(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "DNS: nome não resolvido"
    if isinstance(exc, TimeoutError | socket.timeout):
        return "tempo esgotado"
    if isinstance(exc, ConnectionRefusedError):
        return "conexão recusada (porta fechada)"
    if isinstance(exc, ssl.SSLError):
        return f"erro TLS: {exc.reason or exc}"
    if isinstance(exc, http.client.HTTPException):
        return f"resposta HTTP inválida: {exc.__class__.__name__}"
    return str(exc) or exc.__class__.__name__
