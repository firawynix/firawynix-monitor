"""Conectores: o caminho de rede do Windows até o sshd do servidor.

* ``direct``      — conexão TCP normal.
* ``vpn``         — também direto, mas antes confere se a VPN (WireGuard, Tailscale,
                    OpenVPN…) alcança o servidor e, se configurado, roda o comando que a liga.
* ``cloudflared`` — ``cloudflared access ssh`` (Cloudflare Tunnel + Access), com token de
                    serviço opcional passado por variável de ambiente, nunca pela linha de comando.
* ``socks5`` / ``http`` — proxy SOCKS5 (ex.: ``ssh -D``, Tailscale em modo userspace) ou HTTP CONNECT.
* ``command``     — qualquer programa no estilo ProxyCommand (``%h``, ``%p``, ``%r``).
* ``jump``        — host de salto; implementado em :mod:`core.ssh_client` (canal ``direct-tcpip``).

O Paramiko recebe um socket já ligado ao sshd de destino. O ``ProxyCommand`` do
próprio Paramiko não funciona no Windows (usa ``select()`` em pipes): aqui o
processo do túnel é ligado a um par de sockets locais por threads de cópia, e é
iniciado sem janela de console.
"""

from __future__ import annotations

import base64
import collections
import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from config.settings import ConnectorConfig, ServerConfig

log = logging.getLogger(__name__)

#: Intervalo mínimo entre duas execuções do comando que liga a VPN (evita loop).
VPN_UP_COOLDOWN = 120.0
VPN_UP_WAIT = 20.0
_CREATE_NO_WINDOW = 0x08000000
_last_vpn_up: dict[str, float] = {}
_vpn_lock = threading.Lock()


class ConnectorError(Exception):
    """Falha no caminho até o servidor. ``auth=True`` = exige ação do usuário (login,
    token) — o monitor espaça as tentativas como numa senha errada."""

    def __init__(self, message: str, *, auth: bool = False, login_hostname: str = "") -> None:
        super().__init__(message)
        self.auth = auth
        #: Aplicação do Cloudflare Access que precisa de "cloudflared access login".
        self.login_hostname = login_hostname


@dataclass
class Tunnel:
    """Socket pronto para o Paramiko e como desfazer o caminho."""

    sock: object
    close: Callable[[], None]
    description: str
    #: Últimas linhas de erro do processo do túnel (para mensagens claras).
    diagnostics: Callable[[], str] = lambda: ""


def _popen_flags() -> dict:
    if sys.platform == "win32":
        return {"creationflags": _CREATE_NO_WINDOW}
    return {"start_new_session": True}


# ---------------------------------------------------------------------------
# Processo como túnel (cloudflared, ncat, websocat...)
# ---------------------------------------------------------------------------

class ProcessTunnel:
    """Liga stdin/stdout de um processo a um par de sockets locais."""

    CHUNK = 65536

    def __init__(self, argv: Sequence[str], env: dict[str, str] | None = None, name: str = "") -> None:
        self.argv = list(argv)
        self.name = name or os.path.basename(self.argv[0])
        self._stderr: collections.deque[str] = collections.deque(maxlen=40)
        self._closed = threading.Event()
        self.local, self._relay = socket.socketpair()
        try:
            self.process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, bufsize=0, env=env, **_popen_flags())
        except OSError:
            self.local.close()
            self._relay.close()
            raise
        for target, label in ((self._pump_out, "out"), (self._pump_in, "in"), (self._pump_err, "err")):
            threading.Thread(target=target, name=f"tunnel-{self.name}-{label}", daemon=True).start()

    def _pump_out(self) -> None:
        stdout = self.process.stdout
        try:
            while True:
                data = stdout.read(self.CHUNK)
                if not data:
                    break
                self._relay.sendall(data)
        except OSError:
            pass
        finally:
            try:
                self._relay.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _pump_in(self) -> None:
        stdin = self.process.stdin
        try:
            while True:
                data = self._relay.recv(self.CHUNK)
                if not data:
                    break
                stdin.write(data)
                stdin.flush()
        except OSError:
            pass
        finally:
            try:
                stdin.close()
            except OSError:
                pass

    def _pump_err(self) -> None:
        try:
            for raw in iter(self.process.stderr.readline, b""):
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    self._stderr.append(line)
                    log.debug("[túnel %s] %s", self.name, line)
        except (OSError, ValueError):
            pass

    def diagnostics(self) -> str:
        return " | ".join(list(self._stderr)[-3:])

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        for sock in (self.local, self._relay):
            try:
                sock.close()
            except OSError:
                pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def as_tunnel(self, description: str) -> Tunnel:
        return Tunnel(self.local, self.close, description, self.diagnostics)


def expand_tokens(argv: Sequence[str], host: str, port: int, user: str) -> list[str]:
    """``%h``/``%p``/``%r``/``%%`` como no ProxyCommand do OpenSSH."""
    out = []
    for arg in argv:
        result, i = [], 0
        while i < len(arg):
            if arg[i] == "%" and i + 1 < len(arg):
                token = arg[i + 1]
                result.append({"h": host, "p": str(port), "r": user, "%": "%"}.get(token, "%" + token))
                i += 2
            else:
                result.append(arg[i])
                i += 1
        out.append("".join(result))
    return out


def find_executable(name: str) -> str | None:
    if os.path.sep in name or (os.path.altsep and os.path.altsep in name):
        return name if os.path.isfile(name) else None
    found = shutil.which(name)
    if found:
        return found
    if sys.platform == "win32":  # instalações padrão (winget/MSI) nem sempre entram no PATH do app
        for base in (os.environ.get("PROGRAMFILES(X86)", ""), os.environ.get("PROGRAMFILES", "")):
            candidate = os.path.join(base, "cloudflared", "cloudflared.exe")
            if base and name.lower().startswith("cloudflared") and os.path.isfile(candidate):
                return candidate
    return None


# ---------------------------------------------------------------------------
# Cloudflare Tunnel (cloudflared access ssh)
# ---------------------------------------------------------------------------

def cloudflared_argv(server: ServerConfig) -> tuple[list[str], dict[str, str]]:
    """Comando e ambiente do ``cloudflared access ssh`` (o token vai no ambiente, não no argv)."""
    connector = server.connector
    executable = find_executable(connector.executable or "cloudflared")
    if executable is None:
        raise ConnectorError(
            "cloudflared não encontrado. Instale no Windows (winget install --id Cloudflare.cloudflared) "
            "ou informe \"cloudflared_path\" no conector.")
    hostname = connector.hostname or server.host
    argv = [executable, "access", "ssh", "--hostname", hostname]
    if connector.destination:
        argv += ["--destination", connector.destination]
    env = dict(os.environ)
    token = connector.resolve_service_token()
    if token is not None:
        env["TUNNEL_SERVICE_TOKEN_ID"], env["TUNNEL_SERVICE_TOKEN_SECRET"] = token
    elif connector.token_id_env or connector.token_credential:
        raise ConnectorError("Token de serviço do Cloudflare Access não encontrado (variáveis de ambiente ou "
                             "credencial do Windows).", auth=True)
    return argv, env


def openssh_args(server: ServerConfig) -> list[str]:
    """Opções do ``ssh`` do Windows para o "Terminal SSH" seguir o mesmo caminho do monitor.

    VPN e direto não precisam de nada; proxy SOCKS/HTTP não tem equivalente nativo no OpenSSH do Windows
    (o terminal tenta direto). Segredos nunca entram na linha de comando."""
    connector = server.connector
    if connector.type == "jump" and connector.jump is not None:
        jump = connector.jump
        return ["-J", f"{jump.username}@{jump.host}:{jump.port}"]
    if connector.type == "cloudflared":
        executable = find_executable(connector.executable or "cloudflared") or "cloudflared"
        argv = [executable, "access", "ssh", "--hostname", connector.hostname or server.host]
        if connector.destination:
            argv += ["--destination", connector.destination]
        return ["-o", "ProxyCommand=" + subprocess.list2cmdline(argv)]
    if connector.type == "command" and connector.command:
        return ["-o", "ProxyCommand=" + subprocess.list2cmdline(list(connector.command))]
    return []


def cloudflared_has_session(executable: str, hostname: str, timeout: float = 8.0,
                            run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> bool:
    """Há login do Cloudflare Access salvo para a aplicação? (sem abrir o navegador)."""
    try:
        result = run([executable, "access", "token", f"--app=https://{hostname}"], capture_output=True,
                     timeout=timeout, stdin=subprocess.DEVNULL, **_popen_flags())
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and bool(result.stdout.strip())


def open_cloudflared(server: ServerConfig, timeout: float,
                     has_session: Callable[[str, str], bool] = cloudflared_has_session) -> Tunnel:
    argv, env = cloudflared_argv(server)
    hostname = argv[argv.index("--hostname") + 1]
    if "TUNNEL_SERVICE_TOKEN_ID" not in env and not has_session(argv[0], hostname):
        # Sem token nem login salvo o cloudflared abriria o navegador a cada reconexão.
        raise ConnectorError(
            f"Sem login no Cloudflare Access para {hostname}. Use \"Entrar no Cloudflare Access\" em "
            f"Servidores e conexões (ou rode: cloudflared access login https://{hostname}) ou configure um "
            "token de serviço.", auth=True, login_hostname=hostname)
    try:
        tunnel = ProcessTunnel(argv, env, "cloudflared")
    except OSError as exc:
        raise ConnectorError(f"Falha ao iniciar o cloudflared: {exc}") from exc
    return tunnel.as_tunnel(f"Cloudflare Tunnel ({hostname})")


def cloudflared_login(server: ServerConfig) -> subprocess.Popen:
    """Abre o login do Cloudflare Access no navegador (uma vez; o token fica salvo pelo cloudflared)."""
    argv, env = cloudflared_argv(server)
    hostname = argv[argv.index("--hostname") + 1]
    return subprocess.Popen([argv[0], "access", "login", f"https://{hostname}"], env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            **_popen_flags())


# ---------------------------------------------------------------------------
# Proxies SOCKS5 e HTTP CONNECT
# ---------------------------------------------------------------------------

_SOCKS_ERRORS = {1: "falha geral do servidor SOCKS", 2: "conexão não permitida pelas regras do proxy",
                 3: "rede inacessível", 4: "host inacessível", 5: "conexão recusada pelo destino",
                 6: "TTL expirado", 7: "comando não suportado", 8: "tipo de endereço não suportado"}


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectorError("o proxy fechou a conexão durante a negociação")
        data += chunk
    return data


def socks5_connect(proxy: tuple[str, int], target: tuple[str, int], timeout: float,
                   username: str = "", password: str | None = None) -> socket.socket:
    """CONNECT via SOCKS5 (RFC 1928), com usuário/senha (RFC 1929) opcionais.
    Nomes de host são resolvidos pelo proxy (funciona com DNS da VPN/tailnet)."""
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        methods = b"\x00\x02" if username else b"\x00"
        sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
        version, method = _recv_exact(sock, 2)
        if version != 5 or method == 0xFF:
            raise ConnectorError("o proxy SOCKS5 recusou os métodos de autenticação oferecidos")
        if method == 2:
            user, secret = username.encode(), (password or "").encode()
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
            if _recv_exact(sock, 2)[1] != 0:
                raise ConnectorError("usuário/senha recusados pelo proxy SOCKS5", auth=True)
        host, port = target
        try:
            address = ipaddress.ip_address(host)
            atyp = b"\x01" if address.version == 4 else b"\x04"
            dest = atyp + address.packed
        except ValueError:
            encoded = host.encode("idna")
            dest = b"\x03" + bytes([len(encoded)]) + encoded
        sock.sendall(b"\x05\x01\x00" + dest + port.to_bytes(2, "big"))
        _version, reply, _rsv, atyp_reply = _recv_exact(sock, 4)
        if reply != 0:
            raise ConnectorError(f"proxy SOCKS5: {_SOCKS_ERRORS.get(reply, f'erro {reply}')} ({host}:{port})")
        skip = {1: 4, 4: 16}.get(atyp_reply)
        _recv_exact(sock, (skip if skip else _recv_exact(sock, 1)[0]) + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def http_connect(proxy: tuple[str, int], target: tuple[str, int], timeout: float,
                 username: str = "", password: str | None = None) -> socket.socket:
    """Túnel por proxy HTTP (método CONNECT), com autenticação Basic opcional."""
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        host, port = target
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        if username:
            token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
            request += f"Proxy-Authorization: Basic {token}\r\n"
        sock.sendall((request + "\r\n").encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectorError("o proxy HTTP fechou a conexão")
            response += chunk
            if len(response) > 16384:
                raise ConnectorError("resposta inválida do proxy HTTP")
        status_line = response.split(b"\r\n", 1)[0].decode("latin-1")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise ConnectorError(f"resposta inválida do proxy HTTP: {status_line!r}")
        if parts[1] == "407":
            raise ConnectorError("o proxy HTTP exige autenticação (407)", auth=True)
        if parts[1] != "200":
            raise ConnectorError(f"o proxy HTTP recusou o túnel: {status_line}")
        return sock
    except BaseException:
        sock.close()
        raise


# ---------------------------------------------------------------------------
# VPN
# ---------------------------------------------------------------------------

def reachable(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_vpn(server: ServerConfig, timeout: float, *,
               probe: Callable[[str, int, float], bool] | None = None,
               run: Callable[..., object] = subprocess.run,
               sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
    """Confere se a VPN alcança o servidor; se não, roda ``up_command`` (no máximo a cada 2 min)."""
    connector = server.connector
    probe = probe or reachable
    host, port = connector.check_host or server.host, connector.check_port or server.port
    name = connector.name or "VPN"
    if probe(host, port, min(timeout, 3.0)):
        return
    if connector.up_command:
        with _vpn_lock:
            last = _last_vpn_up.get(server.name)
            now = clock()
            due = last is None or now - last >= VPN_UP_COOLDOWN
            if due:
                _last_vpn_up[server.name] = now
        if due:
            log.info("[%s] %s inacessível por %s:%s; ligando a VPN: %s", server.name, name, host, port,
                     " ".join(connector.up_command))
            # Saída em arquivo, não em pipe: clientes de VPN deixam processos em segundo plano que
            # herdariam o pipe e fariam a espera durar até o timeout.
            with tempfile.TemporaryFile() as output:
                try:
                    result = run(list(connector.up_command), stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.STDOUT, timeout=60, **_popen_flags())
                except (OSError, subprocess.SubprocessError) as exc:
                    raise ConnectorError(f"Não foi possível ligar a {name}: {exc}") from exc
                code = getattr(result, "returncode", 0)
                if code:
                    output.seek(0)
                    detail = output.read(400).decode("utf-8", errors="replace").strip()
                    raise ConnectorError(f"O comando que liga a {name} falhou (código {code}): {detail}")
            deadline = clock() + VPN_UP_WAIT
            while clock() < deadline:
                if probe(host, port, 2.0):
                    log.info("[%s] %s conectada", server.name, name)
                    return
                sleep(1.0)
    hint = "" if connector.up_command else " Conecte a VPN no Windows (ou configure \"up_command\" no conector)."
    raise ConnectorError(f"{name} desconectada ou sem rota: {host}:{port} inacessível.{hint}")


# ---------------------------------------------------------------------------
# Entrada única
# ---------------------------------------------------------------------------

def open_tunnel(server: ServerConfig, timeout: float) -> Tunnel | None:
    """Prepara o caminho até o sshd. ``None`` = o Paramiko conecta direto (direct/vpn).
    O tipo ``jump`` é tratado em :mod:`core.ssh_client`."""
    connector: ConnectorConfig = server.connector
    kind = connector.type
    if kind == "direct":
        return None
    if kind == "vpn":
        ensure_vpn(server, timeout)
        return None
    target = (server.host, server.port)
    if kind in ("socks5", "http"):
        connect = socks5_connect if kind == "socks5" else http_connect
        try:
            sock = connect((connector.host, connector.port), target, timeout, connector.username,
                           connector.resolve_proxy_password() if connector.username else None)
        except OSError as exc:
            raise ConnectorError(f"Proxy {connector.host}:{connector.port} inacessível: {exc}") from exc
        return Tunnel(sock, sock.close, connector.label(server.host))
    if kind == "cloudflared":
        return open_cloudflared(server, timeout)
    if kind == "command":
        argv = expand_tokens(connector.command, server.host, server.port, server.username)
        if find_executable(argv[0]) is None:
            raise ConnectorError(f"Programa do conector não encontrado: {argv[0]}")
        try:
            tunnel = ProcessTunnel(argv, name=os.path.basename(argv[0]))
        except OSError as exc:
            raise ConnectorError(f"Falha ao iniciar {argv[0]}: {exc}") from exc
        return tunnel.as_tunnel(connector.label(server.host))
    raise ConnectorError(f"Conector {kind!r} não suportado aqui")
