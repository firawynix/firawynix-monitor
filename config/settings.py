"""Carregador e validador do arquivo ``servers.json`` (e ``.env`` opcional).

O arquivo de configuração nunca contém segredos: senhas e passphrases são
referenciadas pelo *nome* de uma variável de ambiente (``password_env`` /
``key_passphrase_env``), que pode ser definida no sistema ou em um ``.env``
localizado ao lado do ``servers.json``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

APP_NAME = "FirawynixMonitor"
CONFIG_FILENAME = "servers.json"
CONFIG_ENV_VAR = "FIRAWYNIX_CONFIG"

#: Limite rígido do requisito: nenhum comando SSH pode passar de 5 segundos.
MAX_COMMAND_TIMEOUT = 5.0
MIN_POLL_INTERVAL = 2.0
MAX_POLL_INTERVAL = 3600.0

HOST_KEY_POLICIES = ("accept-new", "strict")
DOCKER_MODES = ("auto", "on", "off")
APPEARANCE_MODES = ("dark", "light", "system")


class ConfigError(Exception):
    """Arquivo de configuração ausente ou inválido."""


@dataclass(frozen=True)
class NotificationSettings:
    enabled: bool = True
    notify_on_recovery: bool = True
    notify_on_disconnect: bool = True
    alert_on_stop: bool = False
    cooldown_seconds: float = 120.0
    #: AppUserModelID usado nos toasts do Windows (None = padrão do win11toast).
    app_id: str | None = None


@dataclass(frozen=True)
class AppSettings:
    poll_interval_seconds: float = 5.0
    command_timeout_seconds: float = MAX_COMMAND_TIMEOUT
    connect_timeout_seconds: float = 5.0
    minimize_to_tray: bool = True
    start_minimized: bool = False
    appearance_mode: str = "dark"
    log_lines: int = 50
    known_hosts_file: Path | None = None
    notifications: NotificationSettings = field(default_factory=NotificationSettings)


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    username: str
    port: int = 22
    key_file: Path | None = None
    key_passphrase_env: str | None = None
    password_env: str | None = None
    allow_agent: bool = True
    look_for_keys: bool = True
    host_key_policy: str = "accept-new"
    use_sudo: bool = True
    docker: str = "auto"
    docker_sudo: bool = False
    logs_sudo: bool = False
    poll_interval_seconds: float | None = None
    critical_services: tuple[str, ...] = ("*",)
    exclude_services: tuple[str, ...] = ()

    @property
    def address(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    def resolve_password(self) -> str | None:
        return _read_secret(self.password_env)

    def resolve_passphrase(self) -> str | None:
        return _read_secret(self.key_passphrase_env)


@dataclass(frozen=True)
class Config:
    settings: AppSettings
    servers: tuple[ServerConfig, ...]
    source: Path | None = None

    def server(self, name: str) -> ServerConfig:
        for server in self.servers:
            if server.name == name:
                return server
        raise KeyError(name)


# ---------------------------------------------------------------------------
# Diretórios da aplicação
# ---------------------------------------------------------------------------

def app_base_dir() -> Path:
    """Diretório do executável (PyInstaller) ou raiz do projeto (código-fonte)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def user_config_dir() -> Path:
    if sys.platform == "win32":
        root = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(root) / APP_NAME
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "firawynix-monitor"


def user_data_dir() -> Path:
    """Logs, known_hosts próprio e arquivos gerados em tempo de execução."""
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(root) / APP_NAME
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "firawynix-monitor"


def config_search_paths(explicit: str | os.PathLike[str] | None = None) -> list[Path]:
    """Ordem de busca: ``--config`` > ``$FIRAWYNIX_CONFIG`` > ao lado do .exe > %APPDATA%."""
    candidates: list[Path] = []
    if explicit:
        return [Path(explicit).expanduser()]
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        candidates.append(Path(env_path).expanduser())
    candidates.append(app_base_dir() / CONFIG_FILENAME)
    candidates.append(Path.cwd() / CONFIG_FILENAME)
    candidates.append(user_config_dir() / CONFIG_FILENAME)
    unique: list[Path] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def find_config(explicit: str | os.PathLike[str] | None = None) -> Path:
    paths = config_search_paths(explicit)
    for path in paths:
        if path.is_file():
            return path
    searched = "\n".join(f"  - {p}" for p in paths)
    raise ConfigError(
        "Arquivo de configuração não encontrado. Locais verificados:\n"
        f"{searched}\n\n"
        "Copie 'servers.example.json' para um desses locais como 'servers.json' "
        "e ajuste os servidores."
    )


# ---------------------------------------------------------------------------
# Carregamento
# ---------------------------------------------------------------------------

def load_dotenv_files(config_path: Path | None) -> list[Path]:
    """Carrega ``.env`` ao lado do ``servers.json`` e do executável (sem sobrescrever)."""
    candidates = []
    if config_path is not None:
        candidates.append(config_path.parent / ".env")
    candidates.append(app_base_dir() / ".env")
    loaded: list[Path] = []
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - dependência declarada em requirements.txt
        log.warning("python-dotenv não instalado; arquivos .env serão ignorados")
        return loaded
    for candidate in dict.fromkeys(candidates):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            loaded.append(candidate)
            log.info("Variáveis de ambiente carregadas de %s", candidate)
    return loaded


def load_config(path: str | os.PathLike[str], *, load_env: bool = True) -> Config:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Arquivo não encontrado: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON inválido em {path} (linha {exc.lineno}, coluna {exc.colno}): {exc.msg}") from exc
    if load_env:
        load_dotenv_files(path)
    config = parse_config(raw, base_dir=path.parent)
    return Config(settings=config.settings, servers=config.servers, source=path)


def parse_config(raw: Any, *, base_dir: Path | None = None) -> Config:
    """Valida o conteúdo já decodificado do JSON. Acumula todos os erros antes de falhar."""
    errors: list[str] = []
    if not isinstance(raw, dict):
        raise ConfigError("A raiz do servers.json deve ser um objeto JSON com a chave 'servers'.")

    _reject_unknown(raw, {"settings", "servers", "$schema", "_comment"}, "raiz", errors)
    settings = _parse_settings(raw.get("settings", {}), base_dir, errors)

    servers_raw = raw.get("servers")
    servers: list[ServerConfig] = []
    if not isinstance(servers_raw, list) or not servers_raw:
        errors.append("'servers' deve ser uma lista com pelo menos um servidor.")
    else:
        seen: set[str] = set()
        for index, item in enumerate(servers_raw):
            server = _parse_server(item, index, base_dir, errors)
            if server is None:
                continue
            if server.name in seen:
                errors.append(f"servers[{index}]: nome duplicado '{server.name}'.")
                continue
            seen.add(server.name)
            servers.append(server)

    if errors:
        raise ConfigError("Configuração inválida:\n" + "\n".join(f"  - {e}" for e in errors))
    return Config(settings=settings, servers=tuple(servers))


# ---------------------------------------------------------------------------
# Helpers de validação
# ---------------------------------------------------------------------------

_SETTINGS_KEYS = {
    "poll_interval_seconds", "command_timeout_seconds", "connect_timeout_seconds",
    "minimize_to_tray", "start_minimized", "appearance_mode", "log_lines",
    "known_hosts_file", "notifications",
}
_NOTIFICATION_KEYS = {
    "enabled", "notify_on_recovery", "notify_on_disconnect", "alert_on_stop",
    "cooldown_seconds", "app_id",
}
_SERVER_KEYS = {
    "name", "host", "port", "username", "key_file", "key_passphrase_env", "password_env",
    "allow_agent", "look_for_keys", "host_key_policy", "use_sudo", "docker", "docker_sudo",
    "logs_sudo", "poll_interval_seconds", "critical_services", "exclude_services",
}
_PLAINTEXT_SECRET_KEYS = {"password", "passphrase", "key_passphrase", "sudo_password"}


def _read_secret(env_name: str | None) -> str | None:
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if value is None:
        log.warning("Variável de ambiente %s não definida", env_name)
    return value


def _reject_unknown(obj: dict, allowed: set[str], ctx: str, errors: list[str]) -> None:
    for key in obj:
        if key == "sudo_password":
            errors.append(
                f"{ctx}: '{key}' não é suportado — o monitor nunca envia senha ao sudo. "
                "Libere apenas os comandos necessários com NOPASSWD no sudoers "
                "(veja docs/sudoers.example)."
            )
        elif key in _PLAINTEXT_SECRET_KEYS:
            replacement = "password_env" if key == "password" else "key_passphrase_env"
            errors.append(
                f"{ctx}: a chave '{key}' não é permitida — segredos em texto plano não são "
                f"suportados. Use '{replacement}' com o nome de uma variável de ambiente (ou .env)."
            )
        elif key not in allowed and not key.startswith("_"):
            errors.append(f"{ctx}: chave desconhecida '{key}'.")


def _get(obj: dict, key: str, kind: type | tuple[type, ...], default: Any, ctx: str, errors: list[str]) -> Any:
    if key not in obj or obj[key] is None:
        return default
    value = obj[key]
    # bool é subclasse de int: não aceitar true/false onde se espera número.
    if isinstance(value, bool) and kind is not bool and (kind is int or kind == (int, float)):
        errors.append(f"{ctx}.{key}: esperado número, recebido booleano.")
        return default
    if not isinstance(value, kind):
        expected = kind.__name__ if isinstance(kind, type) else "/".join(k.__name__ for k in kind)
        errors.append(f"{ctx}.{key}: tipo inválido (esperado {expected}).")
        return default
    return value


def _get_number(obj: dict, key: str, default: float | None, lo: float, hi: float,
                ctx: str, errors: list[str]) -> float | None:
    value = _get(obj, key, (int, float), default, ctx, errors)
    if value is None:
        return None
    if not lo <= value <= hi:
        errors.append(f"{ctx}.{key}: {value} fora do intervalo permitido [{lo:g}, {hi:g}].")
        return default
    return float(value)


def _get_choice(obj: dict, key: str, choices: tuple[str, ...], default: str, ctx: str, errors: list[str]) -> str:
    value = _get(obj, key, str, default, ctx, errors)
    value = value.strip().lower()
    if value not in choices:
        errors.append(f"{ctx}.{key}: '{value}' inválido (use: {', '.join(choices)}).")
        return default
    return value


def _get_patterns(obj: dict, key: str, default: tuple[str, ...], ctx: str, errors: list[str]) -> tuple[str, ...]:
    value = _get(obj, key, list, None, ctx, errors)
    if value is None:
        return default
    patterns: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{ctx}.{key}[{i}]: deve ser um texto não vazio.")
            continue
        patterns.append(item.strip())
    return tuple(patterns)


def _expand_path(value: str, base_dir: Path | None) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(value)))
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    return path


def _parse_settings(raw: Any, base_dir: Path | None, errors: list[str]) -> AppSettings:
    if not isinstance(raw, dict):
        errors.append("'settings' deve ser um objeto.")
        return AppSettings()
    ctx = "settings"
    _reject_unknown(raw, _SETTINGS_KEYS, ctx, errors)

    notif_raw = raw.get("notifications", {})
    if not isinstance(notif_raw, dict):
        errors.append("settings.notifications deve ser um objeto.")
        notif_raw = {}
    nctx = "settings.notifications"
    _reject_unknown(notif_raw, _NOTIFICATION_KEYS, nctx, errors)
    defaults_n = NotificationSettings()
    notifications = NotificationSettings(
        enabled=_get(notif_raw, "enabled", bool, defaults_n.enabled, nctx, errors),
        notify_on_recovery=_get(notif_raw, "notify_on_recovery", bool, defaults_n.notify_on_recovery, nctx, errors),
        notify_on_disconnect=_get(notif_raw, "notify_on_disconnect", bool, defaults_n.notify_on_disconnect,
                                  nctx, errors),
        alert_on_stop=_get(notif_raw, "alert_on_stop", bool, defaults_n.alert_on_stop, nctx, errors),
        cooldown_seconds=_get_number(notif_raw, "cooldown_seconds", defaults_n.cooldown_seconds, 0, 86400,
                                     nctx, errors),
        app_id=_get(notif_raw, "app_id", str, None, nctx, errors),
    )

    defaults = AppSettings()
    known_hosts = _get(raw, "known_hosts_file", str, None, ctx, errors)
    return AppSettings(
        poll_interval_seconds=_get_number(raw, "poll_interval_seconds", defaults.poll_interval_seconds,
                                          MIN_POLL_INTERVAL, MAX_POLL_INTERVAL, ctx, errors),
        command_timeout_seconds=_get_number(raw, "command_timeout_seconds", defaults.command_timeout_seconds,
                                            0.5, MAX_COMMAND_TIMEOUT, ctx, errors),
        connect_timeout_seconds=_get_number(raw, "connect_timeout_seconds", defaults.connect_timeout_seconds,
                                            1, 30, ctx, errors),
        minimize_to_tray=_get(raw, "minimize_to_tray", bool, defaults.minimize_to_tray, ctx, errors),
        start_minimized=_get(raw, "start_minimized", bool, defaults.start_minimized, ctx, errors),
        appearance_mode=_get_choice(raw, "appearance_mode", APPEARANCE_MODES, defaults.appearance_mode, ctx, errors),
        log_lines=int(_get_number(raw, "log_lines", defaults.log_lines, 10, 5000, ctx, errors)),
        known_hosts_file=_expand_path(known_hosts, base_dir) if known_hosts else None,
        notifications=notifications,
    )


def _parse_server(raw: Any, index: int, base_dir: Path | None, errors: list[str]) -> ServerConfig | None:
    ctx = f"servers[{index}]"
    if not isinstance(raw, dict):
        errors.append(f"{ctx}: deve ser um objeto.")
        return None
    if isinstance(raw.get("name"), str) and raw["name"].strip():
        ctx = f"servers[{index}] ('{raw['name'].strip()}')"
    _reject_unknown(raw, _SERVER_KEYS, ctx, errors)
    error_count = len(errors)

    name = _get(raw, "name", str, "", ctx, errors).strip()
    host = _get(raw, "host", str, "", ctx, errors).strip()
    username = _get(raw, "username", str, "", ctx, errors).strip()
    for key, value in (("name", name), ("host", host), ("username", username)):
        if not value:
            errors.append(f"{ctx}: '{key}' é obrigatório.")

    port = _get(raw, "port", int, 22, ctx, errors)
    if not 1 <= port <= 65535:
        errors.append(f"{ctx}.port: {port} inválida.")

    key_file = None
    key_file_raw = _get(raw, "key_file", str, None, ctx, errors)
    if key_file_raw:
        key_file = _expand_path(key_file_raw, base_dir)
        if not key_file.is_file():
            errors.append(f"{ctx}.key_file: arquivo não encontrado: {key_file}")

    docker_raw = raw.get("docker", "auto")
    if isinstance(docker_raw, bool):
        docker = "on" if docker_raw else "off"
    else:
        docker = _get_choice(raw, "docker", DOCKER_MODES, "auto", ctx, errors)

    server = ServerConfig(
        name=name,
        host=host,
        username=username,
        port=port,
        key_file=key_file,
        key_passphrase_env=_get(raw, "key_passphrase_env", str, None, ctx, errors),
        password_env=_get(raw, "password_env", str, None, ctx, errors),
        allow_agent=_get(raw, "allow_agent", bool, True, ctx, errors),
        look_for_keys=_get(raw, "look_for_keys", bool, True, ctx, errors),
        host_key_policy=_get_choice(raw, "host_key_policy", HOST_KEY_POLICIES, "accept-new", ctx, errors),
        use_sudo=_get(raw, "use_sudo", bool, True, ctx, errors),
        docker=docker,
        docker_sudo=_get(raw, "docker_sudo", bool, False, ctx, errors),
        logs_sudo=_get(raw, "logs_sudo", bool, False, ctx, errors),
        poll_interval_seconds=_get_number(raw, "poll_interval_seconds", None,
                                          MIN_POLL_INTERVAL, MAX_POLL_INTERVAL, ctx, errors),
        critical_services=_get_patterns(raw, "critical_services", ("*",), ctx, errors),
        exclude_services=_get_patterns(raw, "exclude_services", (), ctx, errors),
    )
    if len(errors) > error_count:
        return None
    return server
