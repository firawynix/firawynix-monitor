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
