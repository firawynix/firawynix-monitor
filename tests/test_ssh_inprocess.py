"""Conexão SSH de verdade contra um servidor Paramiko no próprio processo.

Roda em qualquer sistema — no Windows é o que garante que o túnel por processo
(o caminho do cloudflared e do conector "command") funciona com pipes do Windows,
onde o ProxyCommand do Paramiko não funciona.
"""

import socket
import sys
import threading
import time

import paramiko
import pytest

from config.settings import ConnectorConfig, ServerConfig, set_session_secret
from core.ssh_client import SSHAuthError, SSHClient, SSHHostKeyError

HOST_KEY = paramiko.RSAKey.generate(2048)
CLIENT_KEY = paramiko.RSAKey.generate(2048)
PASSWORD = "s3nh@-çã"

# Relay mínimo (como "nc %h %p"): stdin → socket e socket → stdout.
RELAY = r"""
import os, socket, sys, threading
sock = socket.create_connection((sys.argv[1], int(sys.argv[2])))
def upstream():
    while True:
        data = os.read(0, 65536)
        if not data:
            break
        sock.sendall(data)
    sock.shutdown(socket.SHUT_WR)
threading.Thread(target=upstream, daemon=True).start()
out = sys.stdout.buffer
while True:
    data = sock.recv(65536)
    if not data:
        break
    out.write(data)
    out.flush()
"""


class _Interface(paramiko.ServerInterface):
    def __init__(self, methods: str) -> None:
        self.methods = methods
        self.commands: list[str] = []
        self.key_ok = False

    def get_allowed_auths(self, username):
        if self.methods == "publickey,password":
            return "password" if self.key_ok else "publickey"
        return self.methods

    def check_auth_password(self, username, password):
        if username != "monitor" or password != PASSWORD:
            return paramiko.AUTH_FAILED
        if self.methods == "publickey,password" and not self.key_ok:
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        if "publickey" not in self.methods or key.asbytes() != CLIENT_KEY.asbytes():
            return paramiko.AUTH_FAILED
        if self.methods == "publickey,password":
            self.key_ok = True
            return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.commands.append(command.decode() if isinstance(command, bytes) else command)

        def reply():
            # Como o OpenSSH: a saída só vai depois de o pedido "exec" ser confirmado (o Paramiko
            # confirma quando este método retorna; responder antes fecha o canal no meio do pedido).
            time.sleep(0.05)
            channel.sendall(b"monitor@ci-windows\n")
            channel.send_exit_status(0)
            channel.close()

        threading.Thread(target=reply, daemon=True).start()
        return True


class _SSHServer:
    def __init__(self, methods: str, host_key: paramiko.PKey = HOST_KEY) -> None:
        self.interface = _Interface(methods)
        self.host_key = host_key
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.transports: list[paramiko.Transport] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self.transports.append(transport)
            try:
                transport.start_server(server=self.interface)
            except (paramiko.SSHException, EOFError, OSError):
                continue

    def close(self):
        self.listener.close()
        for transport in self.transports:
            transport.close()


@pytest.fixture
def ssh_server():
    servers = []

    def start(methods="password", host_key=HOST_KEY):
        server = _SSHServer(methods, host_key)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def _client(tmp_path, port, **kwargs) -> SSHClient:
    server = ServerConfig(name=kwargs.pop("name", "ci"), host="127.0.0.1", port=port, username="monitor",
                          allow_agent=False, look_for_keys=False, **kwargs)
    return SSHClient(server, connect_timeout=10, command_timeout=5, known_hosts_file=tmp_path / "known_hosts")


def test_password_login_runs_commands_and_records_the_host_key(tmp_path, ssh_server, monkeypatch):
    server = ssh_server("password")
    monkeypatch.setenv("CI_SSH_PASS", PASSWORD)
    client = _client(tmp_path, server.port, auth="password", password_env="CI_SSH_PASS")
    try:
        client.connect()
        result = client.run("whoami")
    finally:
        client.close()
    assert result.ok and result.stdout.strip() == "monitor@ci-windows"
    assert server.interface.commands == ["env LC_ALL=C LANG=C sh -c whoami"]
    assert f"[127.0.0.1]:{server.port}" in (tmp_path / "known_hosts").read_text()


def test_key_plus_password_two_factor(tmp_path, ssh_server, monkeypatch):
    server = ssh_server("publickey,password")
    key_file = tmp_path / "id_ci"
    CLIENT_KEY.write_private_key_file(str(key_file))
    monkeypatch.setenv("CI_SSH_PASS", PASSWORD)
    client = _client(tmp_path, server.port, auth="key+password", key_file=key_file, password_env="CI_SSH_PASS")
    try:
        client.connect()
        assert client.run("true").ok
    finally:
        client.close()
    assert server.interface.key_ok


def test_prompted_password_is_used_and_a_wrong_one_is_asked_again(tmp_path, ssh_server):
    server = ssh_server("password")
    client = _client(tmp_path, server.port, name="ci-prompt", auth="password", password_prompt=True)
    with pytest.raises(SSHAuthError) as missing:
        client.connect()
    assert missing.value.needs == "password"
    set_session_secret("ci-prompt", "password", "errada")
    with pytest.raises(SSHAuthError) as wrong:
        client.connect()
    assert wrong.value.needs == "password"
    set_session_secret("ci-prompt", "password", PASSWORD)
    try:
        client.connect()
        assert client.run("true").ok
    finally:
        client.close()
        set_session_secret("ci-prompt", "password", None)


def test_command_connector_tunnels_ssh_through_a_child_process(tmp_path, ssh_server, monkeypatch):
    """O mesmo caminho do cloudflared: SSH pelo stdin/stdout de um processo filho."""
    server = ssh_server("password")
    monkeypatch.setenv("CI_SSH_PASS", PASSWORD)
    connector = ConnectorConfig(type="command", command=(sys.executable, "-c", RELAY, "%h", "%p"))
    client = _client(tmp_path, server.port, auth="password", password_env="CI_SSH_PASS", connector=connector)
    try:
        client.connect()
        outputs = [client.run(f"echo {n}").stdout.strip() for n in range(3)]
    finally:
        client.close()
    assert outputs == ["monitor@ci-windows"] * 3


def test_changed_host_key_is_refused(tmp_path, ssh_server, monkeypatch):
    server = ssh_server("password")
    monkeypatch.setenv("CI_SSH_PASS", PASSWORD)
    (tmp_path / "known_hosts").write_text(
        f"[127.0.0.1]:{server.port} ssh-rsa {paramiko.RSAKey.generate(2048).get_base64()}\n")
    client = _client(tmp_path, server.port, auth="password", password_env="CI_SSH_PASS")
    with pytest.raises(SSHHostKeyError, match="MUDOU"):
        client.connect()
