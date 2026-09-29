"""Testes do carregador/validador do servers.json."""

import json

import pytest

from config.settings import (
    MAX_COMMAND_TIMEOUT,
    ConfigError,
    find_config,
    load_config,
    parse_config,
)


def _minimal(**server_overrides):
    server = {"name": "web", "host": "10.0.0.1", "username": "monitor", **server_overrides}
    return {"servers": [server]}


def test_minimal_config_uses_safe_defaults():
    config = parse_config(_minimal())
    server = config.servers[0]
    assert server.port == 22
    assert server.use_sudo is True
    assert server.docker == "auto"
    assert server.host_key_policy == "accept-new"
    assert server.critical_services == ("*",)
    assert config.settings.poll_interval_seconds == 5.0
    assert config.settings.command_timeout_seconds == MAX_COMMAND_TIMEOUT
    assert config.settings.notifications.enabled is True


def test_full_example_file_is_valid():
    """O servers.example.json distribuído precisa sempre ser válido."""
    from pathlib import Path

    example = json.loads((Path(__file__).parent.parent / "servers.example.json").read_text(encoding="utf-8"))
    for server in example["servers"]:
        server.pop("key_file", None)  # a chave do exemplo não existe na máquina de teste
    config = parse_config(example)
    assert len(config.servers) >= 2


@pytest.mark.parametrize(("key", "hint"), [
    ("password", "password_env"),
    ("passphrase", "key_passphrase_env"),
    ("sudo_password", "NOPASSWD"),
])
def test_plaintext_secrets_are_rejected(key, hint):
    with pytest.raises(ConfigError) as err:
        parse_config(_minimal(**{key: "hunter2"}))
    assert hint in str(err.value)


def test_errors_are_accumulated_with_context():
    raw = {
        "settings": {"command_timeout_seconds": 30, "poll_interval_seconds": 0.5, "typo": 1},
        "servers": [
            {"name": "a", "host": "h", "username": "u", "port": 70000},
            {"name": "a", "host": "h", "username": "u"},
            {"name": "b", "host": "h", "username": "u"},
            {"name": "b", "host": "h", "username": "u"},
            {"host": "h"},
        ],
    }
    with pytest.raises(ConfigError) as err:
        parse_config(raw)
    message = str(err.value)
    assert "command_timeout_seconds" in message
    assert "poll_interval_seconds" in message
    assert "chave desconhecida 'typo'" in message
    assert "port" in message
    assert "nome duplicado 'b'" in message
    assert "'name' é obrigatório" in message


def test_boolean_is_not_accepted_as_number():
    with pytest.raises(ConfigError):
        parse_config({"settings": {"poll_interval_seconds": True}, **_minimal()})


def test_docker_accepts_boolean_and_modes():
    assert parse_config(_minimal(docker=False)).servers[0].docker == "off"
    assert parse_config(_minimal(docker=True)).servers[0].docker == "on"
    assert parse_config(_minimal(docker="AUTO")).servers[0].docker == "auto"
    with pytest.raises(ConfigError):
        parse_config(_minimal(docker="sometimes"))


def test_key_file_is_resolved_relative_to_config(tmp_path):
    key = tmp_path / "keys" / "id_ed25519"
    key.parent.mkdir()
    key.write_text("dummy")
    config = parse_config(_minimal(key_file="keys/id_ed25519"), base_dir=tmp_path)
    assert config.servers[0].key_file == key
    with pytest.raises(ConfigError, match="arquivo não encontrado"):
        parse_config(_minimal(key_file="missing"), base_dir=tmp_path)


def test_load_config_reads_dotenv_next_to_file(tmp_path, monkeypatch):
    monkeypatch.delenv("FWX_TEST_PASSWORD", raising=False)
    (tmp_path / "servers.json").write_text(json.dumps(_minimal(password_env="FWX_TEST_PASSWORD")),
                                           encoding="utf-8")
    (tmp_path / ".env").write_text("FWX_TEST_PASSWORD=s3cret\n", encoding="utf-8")
    config = load_config(tmp_path / "servers.json")
    assert config.source == tmp_path / "servers.json"
    assert config.servers[0].resolve_password() == "s3cret"


def test_load_config_reports_invalid_json(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text('{"servers": [', encoding="utf-8")
    with pytest.raises(ConfigError, match="JSON inválido"):
        load_config(path, load_env=False)


def test_find_config_order(tmp_path, monkeypatch):
    explicit = tmp_path / "custom.json"
    with pytest.raises(ConfigError, match="não encontrado"):
        find_config(explicit)
    explicit.write_text("{}", encoding="utf-8")
    assert find_config(explicit) == explicit
    monkeypatch.setenv("FIRAWYNIX_CONFIG", str(explicit))
    assert find_config() == explicit


def test_new_runtime_and_collection_options():
    config = parse_config({
        "settings": {
            "detail_interval_seconds": 20, "inventory_interval_seconds": 120, "process_limit": 50,
            "history": {"enabled": True, "retention_days": 30, "file": "hist.sqlite3"},
            "thresholds": {"cpu_percent": 95, "mem_percent": 0, "disk_percent": 85, "sustain_polls": 5},
            "events": {"priority": "warning", "limit": 200, "since_hours": 48},
        },
        **_minimal(podman=True, kubernetes="on", kubectl_command="k3s kubectl", kubectl_sudo=True,
                   libvirt="off", libvirt_uri="qemu+ssh://root@hv/system", network_sudo=True,
                   process_actions=True, unit_types=["service", "timer"]),
    })
    settings, server = config.settings, config.servers[0]
    assert settings.detail_interval_seconds == 20 and settings.process_limit == 50
    assert settings.history.retention_days == 30 and settings.history.file.name == "hist.sqlite3"
    assert settings.thresholds.mem_percent == 0 and settings.thresholds.sustain_polls == 5
    assert settings.events.priority == "warning" and settings.events.since_hours == 48
    assert (server.podman, server.kubernetes, server.libvirt) == ("on", "on", "off")
    assert server.kubectl_command == "k3s kubectl" and server.kubectl_sudo
    assert server.process_actions and server.network_sudo
    assert server.unit_types == ("service", "timer")


def test_defaults_for_new_options():
    server = parse_config(_minimal()).servers[0]
    assert (server.podman, server.kubernetes, server.libvirt) == ("auto", "auto", "auto")
    assert server.process_actions is False and server.unit_types[0] == "service"


@pytest.mark.parametrize(("overrides", "fragment"), [
    ({"kubectl_command": "kubectl; rm -rf /"}, "kubectl_command"),
    ({"libvirt_uri": "qemu:///system && id"}, "libvirt_uri"),
    ({"unit_types": ["service", "target"]}, "unit_types"),
    ({"podman": "sometimes"}, "podman"),
])
def test_invalid_new_options(overrides, fragment):
    with pytest.raises(ConfigError, match=fragment):
        parse_config(_minimal(**overrides))


def test_invalid_nested_settings():
    with pytest.raises(ConfigError) as err:
        parse_config({"settings": {"thresholds": {"cpu_percent": 150, "bogus": 1}, "events": {"priority": "x"}},
                      **_minimal()})
    message = str(err.value)
    assert "cpu_percent" in message and "bogus" in message and "priority" in message


def test_v3_server_options_and_defaults():
    config = parse_config(_minimal(
        lxd="on", lxd_sudo=True, smart=False, security_sudo=True, security_actions=True,
        endpoints=["https://loja.exemplo.com/health", "tcp://db.exemplo.com:5432"],
        bandwidth_quota_gb=2000, bandwidth_count="total", password_credential=True,
        key_passphrase_credential="Minha/Chave"))
    server = config.servers[0]
    assert (server.lxd, server.lxd_sudo, server.smart) == ("on", True, "off")
    assert server.security and server.security_sudo and server.security_actions
    assert server.endpoints == ("https://loja.exemplo.com/health", "tcp://db.exemplo.com:5432")
    assert (server.bandwidth_quota_gb, server.bandwidth_count) == (2000.0, "total")
    assert server.password_credential == "FirawynixMonitor/web"
    assert server.key_passphrase_credential == "Minha/Chave"
    assert server.uses_password
    defaults = parse_config(_minimal()).servers[0]
    assert (defaults.smart, defaults.security, defaults.security_sudo, defaults.endpoints) == ("auto", True, False, ())
    assert not defaults.uses_password


def test_v3_settings_sections():
    raw = _minimal()
    raw["settings"] = {
        "security_interval_seconds": 600, "endpoint_interval_seconds": 30, "cert_warning_days": 21,
        "latency_probe": "ssh", "thresholds": {"steal_percent": 15, "latency_ms": 250},
        "notifications": {"notify_on_ssh_login": "all", "security_alerts": False},
        "windows": {"event_log": False, "prevent_sleep": True},
    }
    settings = parse_config(raw).settings
    assert (settings.security_interval_seconds, settings.endpoint_interval_seconds) == (600, 30)
    assert (settings.cert_warning_days, settings.latency_probe) == (21, "ssh")
    assert (settings.thresholds.steal_percent, settings.thresholds.latency_ms) == (15, 250)
    assert settings.notifications.notify_on_ssh_login == "all" and not settings.notifications.security_alerts
    assert not settings.windows.event_log and settings.windows.prevent_sleep and settings.windows.flash_taskbar


@pytest.mark.parametrize(("overrides", "message"), [
    ({"endpoints": ["ftp://x"]}, "endpoints[0]"),
    ({"endpoints": ["https://u:p@x"]}, "credenciais"),
    ({"bandwidth_count": "rx"}, "bandwidth_count"),
    ({"bandwidth_quota_gb": True}, "bandwidth_quota_gb"),
    ({"password_credential": 5}, "password_credential"),
    ({"lxd": "sometimes"}, "lxd"),
])
def test_v3_invalid_options(overrides, message):
    with pytest.raises(ConfigError) as err:
        parse_config(_minimal(**overrides))
    assert message in str(err.value)


def test_plaintext_password_hint_mentions_credential_manager():
    with pytest.raises(ConfigError) as err:
        parse_config(_minimal(password="x"))
    assert "password_credential" in str(err.value)
