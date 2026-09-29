"""Integrações com a API do Windows chamadas de verdade (só rodam no Windows; o CI
usa um runner Windows). Fora do Windows o comportamento é coberto por
test_winapi_alerts.py (chamadas viram no-ops seguros)."""

import json
import subprocess
import sys
import uuid

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="API do Windows")

from core import connectors, winapi  # noqa: E402
from core.backups import BackupStore, ChangeRecord  # noqa: E402


@pytest.fixture
def credential_target():
    target = f"FirawynixMonitor/ci-{uuid.uuid4().hex[:12]}"
    yield target
    winapi.cred_delete(target)


def test_credential_manager_round_trip(credential_target):
    secret = "sênha-ç✓ com espaço"
    winapi.cred_write(credential_target, secret, "monitor")
    assert winapi.cred_read_pair(credential_target) == ("monitor", secret)
    assert (credential_target, "monitor") in winapi.cred_list()
    assert winapi.cred_delete(credential_target)
    assert winapi.cred_read(credential_target) is None
    assert credential_target not in [t for t, _u in winapi.cred_list()]


def test_credential_written_by_cmdkey_is_readable(credential_target):
    """Quem grava pelo próprio Windows (cmdkey) é lido igual pelo painel."""
    subprocess.run(["cmdkey", f"/generic:{credential_target}", "/user:deploy", "/pass:Senha-Do-cmdkey-1"],
                   check=True, capture_output=True)
    assert winapi.cred_read_pair(credential_target) == ("deploy", "Senha-Do-cmdkey-1")


def test_cloudflare_service_token_from_credential_manager(credential_target):
    from config.settings import ConnectorConfig

    winapi.cred_write(credential_target, "client-secret-123", "client-id.access")
    connector = ConnectorConfig(type="cloudflared", token_credential=credential_target)
    assert connector.resolve_service_token() == ("client-id.access", "client-secret-123")


def test_dpapi_round_trip_and_tamper_detection():
    data = "definição com segredo: DB_PASSWORD=s3nh@".encode()
    protected = winapi.protect_data(data, "Firawynix CI")
    assert protected != data and b"s3nh@" not in protected
    assert winapi.unprotect_data(protected) == data
    tampered = bytearray(protected)
    tampered[len(tampered) // 2] ^= 0xFF
    with pytest.raises(winapi.CredentialError):
        winapi.unprotect_data(bytes(tampered))


def test_backup_store_encrypts_the_definition(tmp_path):
    store = BackupStore(tmp_path)
    inspect = {"Name": "/shop-db", "Config": {"Image": "postgres:16", "Env": ["POSTGRES_PASSWORD=s3nh@"],
                                              "Labels": {}}}
    directory = store.save_definition("prod", "shop-db", "20260929-120000-stop-ab12", inspect, None, "docker")
    files = sorted(p.name for p in (tmp_path / "prod" / "shop-db").rglob("*") if p.is_file())
    assert files == ["inspect.json.dpapi", "recriar.txt"]
    protected = next(tmp_path.rglob("inspect.json.dpapi")).read_bytes()
    assert b"s3nh@" not in protected and b"POSTGRES_PASSWORD" not in protected
    record = ChangeRecord(id="20260929-120000-stop-ab12", time=0, server="prod", target="shop-db", engine="docker",
                          action="stop", risk="alto", definition_dir=directory)
    assert store.load_definition(record) == inspect
    store.append(record)
    assert [r.id for r in BackupStore(tmp_path).records("prod")] == [record.id]
    assert json.loads((tmp_path / BackupStore.JOURNAL).read_text(encoding="utf-8").splitlines()[0])["id"] == record.id


def test_event_log_accepts_events():
    log = winapi.EventLog()
    try:
        assert log.available
        assert log.write("Teste do CI do Firawynix Monitor", "info", "app")
        assert log.write("Teste de erro do CI", "error", "action")
    finally:
        log.close()


def test_autostart_registry_round_trip(tmp_path):
    name = f"FirawynixMonitorCI{uuid.uuid4().hex[:6]}"
    command = winapi.autostart_command(tmp_path / "servers.json")
    try:
        assert winapi.set_autostart(True, command, name)
        assert winapi.autostart_enabled(name)
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            assert winreg.QueryValueEx(key, name)[0] == command
    finally:
        assert winapi.set_autostart(False, command, name)
    assert not winapi.autostart_enabled(name)


def test_icmp_ping_to_loopback():
    latency = winapi.icmp_ping("127.0.0.1", 2000)
    assert latency is not None and 0 <= latency < 2000


def test_prevent_sleep_toggles():
    assert winapi.prevent_sleep(True)
    assert winapi.prevent_sleep(False)


def test_cloudflared_is_found_in_program_files(tmp_path, monkeypatch):
    install = tmp_path / "cloudflared"
    install.mkdir()
    (install / "cloudflared.exe").write_bytes(b"MZ")
    monkeypatch.setenv("PATH", str(tmp_path / "vazio"))
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "nao-existe"))
    assert connectors.find_executable("cloudflared") == str(install / "cloudflared.exe")


def test_tunnel_child_process_has_no_console_window():
    assert connectors._popen_flags() == {"creationflags": subprocess.CREATE_NO_WINDOW}
