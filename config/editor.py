"""Edição do ``servers.json`` pela interface (diálogo "Servidores e conexões").

Só os campos de conexão são reescritos (endereço, usuário, autenticação e
conector); o resto de cada servidor (motores, endpoints, sudo, alertas…) é
preservado. Antes de gravar, a configuração inteira é validada; o arquivo
anterior vira ``servers.json.bak`` e a gravação é atômica. Segredos nunca vão
para o arquivo: só o nome da variável de ambiente, a referência à credencial do
Windows ou "pedir ao conectar".
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from config.settings import CONNECTOR_TYPES, Config, parse_config

#: Chaves de conexão controladas pelo formulário (as demais são preservadas).
CONNECTION_KEYS = ("host", "port", "username", "auth", "key_file", "password_env", "password_credential",
                   "password_prompt", "key_passphrase_env", "key_passphrase_credential", "key_passphrase_prompt",
                   "host_key_policy", "connector", "allow_agent", "look_for_keys")
SECRET_SOURCES = ("none", "credential", "prompt", "env")
SECRET_SOURCE_LABELS = {"none": "Nenhuma", "credential": "Gerenciador de Credenciais do Windows",
                        "prompt": "Pedir ao conectar (só em memória)", "env": "Variável de ambiente"}


def load_raw(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def secret_source(entry: dict, prefix: str) -> tuple[str, str]:
    """Origem do segredo de ``entry`` (``prefix``: "password" ou "key_passphrase") e o nome da variável."""
    if entry.get(f"{prefix}_credential"):
        return "credential", ""
    if entry.get(f"{prefix}_prompt"):
        return "prompt", ""
    if entry.get(f"{prefix}_env"):
        return "env", str(entry[f"{prefix}_env"])
    return "none", ""


def _apply_secret(entry: dict, prefix: str, source: str, env_name: str = "") -> None:
    for suffix in ("_credential", "_prompt", "_env"):
        entry.pop(prefix + suffix, None)
    if source == "credential":
        entry[f"{prefix}_credential"] = True
    elif source == "prompt":
        entry[f"{prefix}_prompt"] = True
    elif source == "env":
        if not env_name.strip():
            raise ValueError("Informe o nome da variável de ambiente.")
        entry[f"{prefix}_env"] = env_name.strip()


def build_entry(form: dict[str, Any], existing: dict | None = None) -> dict:
    """Entrada do servidor a partir do formulário, preservando o que não é de conexão."""
    entry = {k: copy.deepcopy(v) for k, v in (existing or {}).items() if k not in CONNECTION_KEYS}
    entry["name"] = str(form.get("name", "")).strip()
    for key in ("host", "username"):
        entry[key] = str(form.get(key, "")).strip()
    port = str(form.get("port", "22")).strip() or "22"
    if not port.isdigit():
        raise ValueError(f"Porta inválida: {port}")
    if int(port) != 22:
        entry["port"] = int(port)
    auth = form.get("auth", "auto")
    if auth != "auto":
        entry["auth"] = auth
    if form.get("key_file"):
        entry["key_file"] = str(form["key_file"]).strip()
    if form.get("host_key_policy", "accept-new") != "accept-new":
        entry["host_key_policy"] = form["host_key_policy"]
    for key in ("allow_agent", "look_for_keys"):
        if existing and key in existing:
            entry[key] = existing[key]
    _apply_secret(entry, "password", form.get("password_source", "none"), form.get("password_env", ""))
    _apply_secret(entry, "key_passphrase", form.get("passphrase_source", "none"), form.get("passphrase_env", ""))
    connector = build_connector(form.get("connector") or {})
    if connector:
        entry["connector"] = connector
    return {k: entry[k] for k in _ordered_keys(entry)}


def _ordered_keys(entry: dict) -> list[str]:
    first = ["name", "host", "port", "username", "auth", "key_file", "password_credential", "password_prompt",
             "password_env", "key_passphrase_credential", "key_passphrase_prompt", "key_passphrase_env",
             "host_key_policy", "connector"]
    return [k for k in first if k in entry] + [k for k in entry if k not in first]


def build_connector(form: dict[str, Any]) -> dict | None:
    kind = form.get("type", "direct")
    if kind not in CONNECTOR_TYPES:
        raise ValueError(f"Conector inválido: {kind}")
    if kind == "direct":
        return None
    out: dict[str, Any] = {"type": kind}
    if form.get("name"):
        out["name"] = str(form["name"]).strip()
    if kind == "vpn":
        if form.get("check"):
            out["check"] = str(form["check"]).strip()
        argv = [a for a in form.get("up_command", []) if a.strip()]
        if argv:
            out["up_command"] = argv
    elif kind == "cloudflared":
        for key in ("hostname", "destination", "cloudflared_path"):
            if form.get(key):
                out[key] = str(form[key]).strip()
        token = form.get("token_source", "none")
        if token == "credential":
            out["service_token_credential"] = True
        elif token == "env":
            if not form.get("token_id_env") or not form.get("token_secret_env"):
                raise ValueError("Informe as duas variáveis do token de serviço (ID e segredo).")
            out["service_token_id_env"] = form["token_id_env"].strip()
            out["service_token_secret_env"] = form["token_secret_env"].strip()
    elif kind in ("socks5", "http"):
        out["host"] = str(form.get("host", "")).strip()
        if str(form.get("port", "")).strip():
            out["port"] = int(str(form["port"]).strip())
        if form.get("username"):
            out["username"] = str(form["username"]).strip()
            source = form.get("password_source", "none")
            if source == "credential":
                out["password_credential"] = True
            elif source == "env" and form.get("password_env"):
                out["password_env"] = form["password_env"].strip()
    elif kind == "command":
        out["command"] = [a for a in form.get("command", []) if a.strip()]
    elif kind == "jump":
        out["host"] = str(form.get("host", "")).strip()
        port = str(form.get("port", "22")).strip() or "22"
        if port != "22":
            out["port"] = int(port)
        if form.get("username"):
            out["username"] = str(form["username"]).strip()
        if form.get("auth", "auto") != "auto":
            out["auth"] = form["auth"]
        if form.get("key_file"):
            out["key_file"] = str(form["key_file"]).strip()
        source = form.get("password_source", "none")
        if source == "credential":
            out["password_credential"] = True
        elif source == "prompt":
            out["password_prompt"] = True
        elif source == "env" and form.get("password_env"):
            out["password_env"] = form["password_env"].strip()
    return out


def upsert_server(raw: dict, entry: dict, original_name: str | None = None) -> dict:
    result = copy.deepcopy(raw)
    servers = result.setdefault("servers", [])
    target = original_name or entry["name"]
    for index, item in enumerate(servers):
        if isinstance(item, dict) and item.get("name") == target:
            servers[index] = entry
            return result
    servers.append(entry)
    return result


def remove_server(raw: dict, name: str) -> dict:
    result = copy.deepcopy(raw)
    result["servers"] = [s for s in result.get("servers", []) if not (isinstance(s, dict) and s.get("name") == name)]
    return result


def find_entry(raw: dict, name: str) -> dict | None:
    return next((s for s in raw.get("servers", []) if isinstance(s, dict) and s.get("name") == name), None)


def validate(raw: dict, base_dir: Path | None) -> Config:
    """Mesma validação do carregamento (lança ConfigError com todos os problemas)."""
    return parse_config(raw, base_dir=base_dir)


def save_raw(path: Path, raw: dict) -> Path | None:
    """Grava de forma atômica; a versão anterior fica em ``servers.json.bak``."""
    path = Path(path)
    backup = None
    if path.is_file():
        backup = path.with_suffix(path.suffix + ".bak")
        backup.write_bytes(path.read_bytes())
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return backup
