"""Conectores (VPN, Cloudflare Tunnel, salto, proxies, comando) e modos de autenticação."""

import socket
import struct
import sys
import threading

import pytest

from config.settings import ConfigError, ConnectorConfig, ServerConfig, parse_config, set_session_secret
from core import connectors
from core.connectors import ConnectorError


def _config(**server):
    base = {"name": "web", "host": "10.0.0.5", "username": "monitor"}
    base.update(server)
    return parse_config({"servers": [base]}).servers[0]


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

def test_connector_defaults_to_direct_and_accepts_a_plain_string():
    assert _config().connector.type == "direct"
    assert _config(connector="direct").connector.is_direct


def test_each_connector_type_parses():
    vpn = _config(connector={"type": "vpn", "name": "WireGuard", "check": "10.8.0.1:22",
                             "up_command": ["wireguard.exe", "/installtunnelservice", "C:/vpn/x.conf"]}).connector
    assert (vpn.check_host, vpn.check_port, vpn.up_command[0], vpn.label()) == (
        "10.8.0.1", 22, "wireguard.exe", "VPN WireGuard")
    cf = _config(connector={"type": "cloudflared", "hostname": "ssh.exemplo.com",
                            "service_token_id_env": "CF_ID", "service_token_secret_env": "CF_SECRET"}).connector
    assert (cf.hostname, cf.token_id_env, cf.label()) == ("ssh.exemplo.com", "CF_ID",
                                                          "Cloudflare Tunnel (ssh.exemplo.com)")
    cred = _config(connector={"type": "cloudflared", "service_token_credential": True}).connector
    assert cred.token_credential == "FirawynixMonitor/web/cloudflared"
    socks = _config(connector={"type": "socks5", "host": "127.0.0.1"}).connector
    assert (socks.port, socks.label()) == (1080, "SOCKS5 127.0.0.1:1080")
    http = _config(connector={"type": "http", "host": "proxy", "username": "u", "password_credential": True})
    assert (http.connector.port, http.connector.password_credential) == (3128, "FirawynixMonitor/web/proxy")
    cmd = _config(connector={"type": "command", "command": ["ncat", "--proxy", "p:8080", "%h", "%p"]}).connector
    assert cmd.command[-2:] == ("%h", "%p")


def test_jump_host_has_its_own_authentication():
    server = _config(connector={"type": "jump", "host": "bastion.exemplo.com", "auth": "password",
                                "password_credential": True})
    jump = server.connector.jump
    assert (jump.host, jump.port, jump.username, jump.auth) == ("bastion.exemplo.com", 22, "monitor", "password")
    assert jump.password_credential == "FirawynixMonitor/web/jump"
    assert server.connector.label() == "salto via monitor@bastion.exemplo.com:22"


@pytest.mark.parametrize(("connector", "needle"), [
    ({"type": "tor"}, "connector.type"),
    ({"type": "vpn", "check": "10.8.0.1"}, "connector.check"),
    ({"type": "vpn", "up_command": "wg-quick up wg0"}, "lista"),
    ({"type": "cloudflared", "service_token_id_env": "ID"}, "service_token_secret_env"),
    ({"type": "cloudflared", "hostname": "https://ssh.x.com/"}, "hostname"),
    ({"type": "socks5"}, "connector.host"),
    ({"type": "command"}, "connector.command"),
    ({"type": "jump"}, "'host' é obrigatório"),
    ({"type": "jump", "host": "b", "password": "x"}, "texto plano"),
    ({"type": "socks5", "host": "p", "hostname": "x"}, "chave desconhecida 'hostname'"),
])
def test_invalid_connectors_are_reported(connector, needle):
    with pytest.raises(ConfigError) as info:
        _config(connector=connector)
    assert needle in str(info.value)


@pytest.mark.parametrize(("server", "needle"), [
    ({"auth": "password"}, "exige uma senha"),
    ({"auth": "key+password", "look_for_keys": False}, "exige uma senha"),
    ({"auth": "key", "look_for_keys": False}, "exige key_file"),
    ({"auth": "agent", "allow_agent": False}, "allow_agent"),
    ({"auth": "otp"}, "auth"),
])
def test_auth_mode_requirements(server, needle):
    with pytest.raises(ConfigError) as info:
        _config(**server)
    assert needle in str(info.value)


def test_password_prompt_uses_the_session_secret_only():
    server = _config(auth="password", password_prompt=True)
    assert server.uses_password and server.resolve_password() is None
    set_session_secret("web", "password", "s3nh@")
    try:
        assert server.resolve_password() == "s3nh@"
        assert _config(auth="auto").resolve_password() is None  # sem password_prompt: nunca usa a memória
    finally:
        set_session_secret("web", "password", None)


# ---------------------------------------------------------------------------
# Modos de autenticação → parâmetros do Paramiko
# ---------------------------------------------------------------------------

def _kwargs(**server):
    from core.ssh_client import SSHClient

    return SSHClient._auth_kwargs(ServerConfig(name="s", host="h", username="u", **server))


def test_auth_kwargs_per_mode(tmp_path, monkeypatch):
    key = tmp_path / "id_ed25519"
    key.write_text("x")
    monkeypatch.setenv("FWX_TEST_PASS", "p")
    password = kw = _kwargs(auth="password", password_env="FWX_TEST_PASS")
    assert (password["password"], password["allow_agent"], password["look_for_keys"], password["key_filename"]) \
        == ("p", False, False, None)
    kw = _kwargs(auth="key", key_file=key, password_env="FWX_TEST_PASS")
    assert (kw["key_filename"], kw["password"], kw["allow_agent"], kw["look_for_keys"]) == (str(key), None,
                                                                                           False, False)
    kw = _kwargs(auth="key+password", key_file=key, password_env="FWX_TEST_PASS")
    assert (kw["key_filename"], kw["password"]) == (str(key), "p")
    kw = _kwargs(auth="agent")
    assert (kw["allow_agent"], kw["look_for_keys"], kw["password"]) == (True, False, None)
    kw = _kwargs(auth="key")  # sem arquivo: chaves padrão de ~/.ssh (e agente)
    assert kw["look_for_keys"] and kw["allow_agent"]


def test_missing_password_asks_the_user_instead_of_trying():
    from core.ssh_client import SSHAuthError

    with pytest.raises(SSHAuthError) as info:
        _kwargs(auth="password", password_prompt=True)
    assert (info.value.needs, info.value.target) == ("password", "s")


def test_no_credentials_error_is_actionable():
    import paramiko

    from core.ssh_client import SSHAuthError, SSHClient

    for auth, needle in (("key", "nenhuma chave SSH encontrada"), ("agent", "agente SSH não tem chaves")):
        server = ServerConfig(name="s", host="h", username="u", auth=auth)
        error = SSHClient(server)._translate_connect_error(
            paramiko.SSHException("No authentication methods available"), server, None)
        assert isinstance(error, SSHAuthError) and needle in str(error)


# ---------------------------------------------------------------------------
# Proxies (servidores falsos locais)
# ---------------------------------------------------------------------------

def _echo_server():
    listener = socket.create_server(("127.0.0.1", 0))

    def serve():
        conn, _ = listener.accept()
        with conn:
            while data := conn.recv(4096):
                conn.sendall(data)

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


def _socks5_server(expected_user: str = "", expected_pass: str = ""):
    listener = socket.create_server(("127.0.0.1", 0))
    seen = {}

    def recv_exact(conn, size):
        data = b""
        while len(data) < size:
            data += conn.recv(size - len(data))
        return data

    def serve():
        conn, _ = listener.accept()
        version, count = recv_exact(conn, 2)
        methods = recv_exact(conn, count)
        if expected_user:
            conn.sendall(b"\x05\x02")
            _ver, ulen = recv_exact(conn, 2)
            user = recv_exact(conn, ulen).decode()
            plen = recv_exact(conn, 1)[0]
            password = recv_exact(conn, plen).decode()
            ok = (user, password) == (expected_user, expected_pass)
            conn.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
            if not ok:
                conn.close()
                return
        else:
            conn.sendall(b"\x05\x00")
        _ver, _cmd, _rsv, atyp = recv_exact(conn, 4)
        if atyp == 3:
            host = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
        else:
            host = socket.inet_ntoa(recv_exact(conn, 4))
        port = struct.unpack(">H", recv_exact(conn, 2))[0]
        seen.update(methods=methods, host=host, port=port)
        upstream = socket.create_connection(("127.0.0.1", port))
        conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", port))
        _relay(conn, upstream)

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1], seen


def _relay(a, b):
    def pump(src, dst):
        try:
            while data := src.recv(4096):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            dst.close()

    threading.Thread(target=pump, args=(a, b), daemon=True).start()
    threading.Thread(target=pump, args=(b, a), daemon=True).start()


def test_socks5_connect_resolves_names_on_the_proxy():
    echo = _echo_server()
    proxy_port, seen = _socks5_server()
    sock = connectors.socks5_connect(("127.0.0.1", proxy_port), ("servidor.tailnet", echo), 3)
    sock.sendall(b"ping")
    assert sock.recv(4) == b"ping"
    assert seen["host"] == "servidor.tailnet" and seen["port"] == echo  # DNS feito pelo proxy
    sock.close()


def test_socks5_with_username_and_password():
    echo = _echo_server()
    proxy_port, _ = _socks5_server("ana", "segredo")
    sock = connectors.socks5_connect(("127.0.0.1", proxy_port), ("127.0.0.1", echo), 3, "ana", "segredo")
    sock.sendall(b"ok")
    assert sock.recv(2) == b"ok"
    sock.close()
    proxy_port, _ = _socks5_server("ana", "segredo")
    with pytest.raises(ConnectorError) as info:
        connectors.socks5_connect(("127.0.0.1", proxy_port), ("127.0.0.1", echo), 3, "ana", "errada")
    assert info.value.auth


def _http_proxy(status: bytes):
    listener = socket.create_server(("127.0.0.1", 0))
    seen = {}

    def serve():
        conn, _ = listener.accept()
        request = b""
        while b"\r\n\r\n" not in request:
            request += conn.recv(1024)
        seen["request"] = request.decode()
        conn.sendall(status + b"\r\n\r\n")
        if b"200" in status:
            port = int(request.split(b" ")[1].rsplit(b":", 1)[1])
            _relay(conn, socket.create_connection(("127.0.0.1", port)))

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1], seen


def test_http_connect_with_basic_auth():
    echo = _echo_server()
    port, seen = _http_proxy(b"HTTP/1.1 200 Connection established")
    sock = connectors.http_connect(("127.0.0.1", port), ("127.0.0.1", echo), 3, "ana", "segredo")
    sock.sendall(b"abc")
    assert sock.recv(3) == b"abc"
    assert "CONNECT 127.0.0.1:" in seen["request"] and "Proxy-Authorization: Basic YW5hOnNlZ3JlZG8=" in seen["request"]
    sock.close()
    port, _ = _http_proxy(b"HTTP/1.1 407 Proxy Authentication Required")
    with pytest.raises(ConnectorError) as info:
        connectors.http_connect(("127.0.0.1", port), ("127.0.0.1", echo), 3)
    assert info.value.auth and "407" in str(info.value)


# ---------------------------------------------------------------------------
# Processo como túnel, tokens, VPN e Cloudflare
# ---------------------------------------------------------------------------

def test_process_tunnel_relays_stdin_and_stdout():
    script = "import sys\nwhile True:\n    d = sys.stdin.buffer.read1(4096)\n    if not d: break\n" \
             "    sys.stdout.buffer.write(d.upper()); sys.stdout.buffer.flush()\n"
    tunnel = connectors.ProcessTunnel([sys.executable, "-c", script], name="eco")
    try:
        tunnel.local.settimeout(5)
        tunnel.local.sendall(b"ssh-2.0")
        received = b""
        while len(received) < 7:
            received += tunnel.local.recv(64)
        assert received == b"SSH-2.0"
    finally:
        tunnel.close()
    assert tunnel.process.poll() is not None


def test_process_tunnel_reports_stderr_when_it_dies():
    tunnel = connectors.ProcessTunnel([sys.executable, "-c", "import sys; sys.stderr.write('acesso negado\\n')"])
    tunnel.process.wait(5)
    tunnel.local.settimeout(5)
    assert tunnel.local.recv(10) == b""
    import time

    for _ in range(50):
        if tunnel.diagnostics():
            break
        time.sleep(0.05)
    assert "acesso negado" in tunnel.diagnostics()
    tunnel.close()


def test_expand_tokens_like_openssh():
    assert connectors.expand_tokens(["nc", "%h", "%p", "%r", "100%%"], "10.0.0.5", 2222, "ana") == [
        "nc", "10.0.0.5", "2222", "ana", "100%"]


def test_vpn_up_command_runs_once_and_waits_for_the_route():
    connectors._last_vpn_up.clear()
    server = _config(connector={"type": "vpn", "name": "Tailscale", "up_command": ["tailscale", "up"]})
    state = {"up": False, "runs": 0, "now": 0.0}

    def probe(host, port, timeout):
        return state["up"]

    def run(argv, **kwargs):
        state["runs"] += 1
        state["up"] = True

    connectors.ensure_vpn(server, 5, probe=probe, run=run, sleep=lambda s: None, clock=lambda: state["now"])
    assert state["runs"] == 1
    state["up"] = False
    run_again = []
    with pytest.raises(ConnectorError) as info:  # cooldown: não roda de novo em seguida
        connectors.ensure_vpn(server, 5, probe=probe, run=lambda *a, **k: run_again.append(1),
                              sleep=lambda s: None, clock=lambda: state["now"])
    assert not run_again and "Tailscale desconectada" in str(info.value)


def test_vpn_without_command_explains_what_to_do():
    server = _config(connector={"type": "vpn", "check": "10.8.0.1:22"})
    with pytest.raises(ConnectorError) as info:
        connectors.ensure_vpn(server, 5, probe=lambda *a: False)
    assert "10.8.0.1:22" in str(info.value) and "Conecte a VPN" in str(info.value)


def test_cloudflared_token_goes_in_the_environment_not_argv(tmp_path, monkeypatch):
    fake = tmp_path / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    fake.write_text("")
    fake.chmod(0o755)
    monkeypatch.setenv("CF_ID", "id-123")
    monkeypatch.setenv("CF_SECRET", "segredo-456")
    server = _config(host="ssh.exemplo.com", connector={
        "type": "cloudflared", "cloudflared_path": str(fake), "service_token_id_env": "CF_ID",
        "service_token_secret_env": "CF_SECRET"})
    argv, env = connectors.cloudflared_argv(server)
    assert argv[1:] == ["access", "ssh", "--hostname", "ssh.exemplo.com"]
    assert "segredo-456" not in " ".join(argv)
    assert (env["TUNNEL_SERVICE_TOKEN_ID"], env["TUNNEL_SERVICE_TOKEN_SECRET"]) == ("id-123", "segredo-456")


def test_cloudflared_without_login_does_not_open_the_browser(tmp_path):
    fake = tmp_path / "cloudflared"
    fake.write_text("")
    fake.chmod(0o755)
    server = _config(host="ssh.exemplo.com", connector={"type": "cloudflared", "cloudflared_path": str(fake)})
    with pytest.raises(ConnectorError) as info:
        connectors.open_cloudflared(server, 5, has_session=lambda exe, host: False)
    assert info.value.auth and info.value.login_hostname == "ssh.exemplo.com"
    assert "cloudflared access login https://ssh.exemplo.com" in str(info.value)


def test_cloudflared_missing_binary_has_install_hint():
    server = _config(connector={"type": "cloudflared", "cloudflared_path": "/nao/existe/cloudflared"})
    with pytest.raises(ConnectorError) as info:
        connectors.cloudflared_argv(server)
    assert "winget install" in str(info.value)


def test_direct_and_vpn_return_no_tunnel(monkeypatch):
    assert connectors.open_tunnel(_config(), 5) is None
    monkeypatch.setattr(connectors, "reachable", lambda *a: True)
    assert connectors.open_tunnel(_config(connector={"type": "vpn"}), 5) is None


def test_connector_label_for_direct():
    assert ConnectorConfig().label() == "direto"


def test_terminal_follows_the_connector(monkeypatch):
    monkeypatch.setattr(connectors, "find_executable", lambda name: "/opt/cf/cloudflared")
    jump = ServerConfig(name="s (salto)", host="bastion", port=2222, username="ops")
    assert connectors.openssh_args(ServerConfig(name="s", host="h", username="u", connector=ConnectorConfig(
        type="jump", jump=jump))) == ["-J", "ops@bastion:2222"]
    cf = connectors.openssh_args(ServerConfig(name="s", host="ssh.exemplo.com", username="u",
                                              connector=ConnectorConfig(type="cloudflared")))
    assert cf == ["-o", "ProxyCommand=/opt/cf/cloudflared access ssh --hostname ssh.exemplo.com"]
    assert connectors.openssh_args(ServerConfig(name="s", host="h", username="u")) == []
