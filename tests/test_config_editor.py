"""Edição do servers.json pelo diálogo "Servidores e conexões"."""

import json

import pytest

from config import editor
from config.settings import ConfigError, load_config


def _raw():
    return {"settings": {"poll_interval_seconds": 5}, "servers": [
        {"name": "web", "host": "10.0.0.5", "username": "monitor", "key_file": "id_web",
         "docker": "on", "docker_sudo": True, "endpoints": ["https://loja.exemplo.com.br/"],
         "_comment": "produção"},
    ]}


def test_editing_connection_keeps_everything_else(tmp_path):
    (tmp_path / "id_web").write_text("x")
    raw = _raw()
    existing = editor.find_entry(raw, "web")
    entry = editor.build_entry({
        "name": "web", "host": "ssh.exemplo.com.br", "port": "22", "username": "deploy", "auth": "key+password",
        "key_file": "id_web", "password_source": "credential", "passphrase_source": "none",
        "connector": {"type": "cloudflared", "hostname": "ssh.exemplo.com.br", "token_source": "credential"},
    }, existing)
    assert entry["docker"] == "on" and entry["docker_sudo"] is True and entry["_comment"] == "produção"
    assert entry["endpoints"] == ["https://loja.exemplo.com.br/"]
    assert (entry["auth"], entry["password_credential"]) == ("key+password", True)
    assert entry["connector"] == {"type": "cloudflared", "hostname": "ssh.exemplo.com.br",
                                  "service_token_credential": True}
    assert "port" not in entry  # 22 é o padrão
    updated = editor.upsert_server(raw, entry, "web")
    config = editor.validate(updated, tmp_path)
    server = config.servers[0]
    assert (server.host, server.username, server.auth, server.connector.type) == (
        "ssh.exemplo.com.br", "deploy", "key+password", "cloudflared")
    assert server.password_credential == "FirawynixMonitor/web"
    assert raw["servers"][0]["host"] == "10.0.0.5"  # original intacto


def test_secret_sources_never_store_the_secret():
    for source, expected in (("credential", {"password_credential": True}), ("prompt", {"password_prompt": True}),
                             ("env", {"password_env": "WEB_PASS"}), ("none", {})):
        entry = editor.build_entry({"name": "w", "host": "h", "username": "u", "auth": "password" if expected
                                    else "auto", "password_source": source, "password_env": "WEB_PASS"})
        assert {k: v for k, v in entry.items() if k.startswith("password")} == expected
        assert editor.secret_source(entry, "password")[0] == source
    with pytest.raises(ValueError):
        editor.build_entry({"name": "w", "host": "h", "username": "u", "password_source": "env"})


def test_connector_forms():
    jump = editor.build_connector({"type": "jump", "host": "bastion", "port": "2222", "username": "ops",
                                   "auth": "password", "password_source": "prompt"})
    assert jump == {"type": "jump", "host": "bastion", "port": 2222, "username": "ops", "auth": "password",
                    "password_prompt": True}
    vpn = editor.build_connector({"type": "vpn", "name": "Tailscale", "check": "100.64.0.1:22",
                                  "up_command": ["C:\\Program Files\\Tailscale\\tailscale.exe", "up", " "]})
    assert vpn["up_command"] == ["C:\\Program Files\\Tailscale\\tailscale.exe", "up"]
    assert editor.build_connector({"type": "direct"}) is None
    with pytest.raises(ValueError):
        editor.build_connector({"type": "cloudflared", "token_source": "env", "token_id_env": "A"})


def test_invalid_edit_is_rejected_before_saving(tmp_path):
    raw = _raw()
    entry = editor.build_entry({"name": "web", "host": "h", "username": "u", "auth": "password",
                                "password_source": "none"})
    with pytest.raises(ConfigError) as info:
        editor.validate(editor.upsert_server(raw, entry, "web"), tmp_path)
    assert "exige uma senha" in str(info.value)


def test_save_is_atomic_with_backup_and_loads_back(tmp_path):
    path = tmp_path / "servers.json"
    (tmp_path / "id_web").write_text("x")
    path.write_text(json.dumps(_raw()), encoding="utf-8")
    raw = editor.load_raw(path)
    new = editor.build_entry({"name": "db", "host": "10.0.0.9", "username": "monitor", "auth": "password",
                              "password_source": "prompt", "connector": {"type": "vpn", "name": "WireGuard"}})
    raw = editor.upsert_server(raw, new)
    editor.validate(raw, tmp_path)
    backup = editor.save_raw(path, raw)
    assert backup is not None and json.loads(backup.read_text())["servers"][0]["name"] == "web"
    config = load_config(path, load_env=False)
    assert [s.name for s in config.servers] == ["web", "db"]
    assert config.servers[1].password_prompt and config.servers[1].connector.name == "WireGuard"
    removed = editor.remove_server(raw, "db")
    assert [s["name"] for s in removed["servers"]] == ["web"]
