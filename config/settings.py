"""Carregador e validador do arquivo ``servers.json`` (e ``.env`` opcional).

O arquivo de configuração nunca contém segredos: senhas e passphrases são
referenciadas pelo *nome* de uma variável de ambiente (``password_env`` /
``key_passphrase_env``, definida no sistema ou em um ``.env`` ao lado do
``servers.json``) ou ficam no Gerenciador de Credenciais do Windows
(``password_credential`` / ``key_passphrase_credential``).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.commands import validate_kubectl_command, validate_libvirt_uri

log = logging.getLogger(__name__)

APP_NAME = "FirawynixMonitor"
CONFIG_FILENAME = "servers.json"
CONFIG_ENV_VAR = "FIRAWYNIX_CONFIG"

#: Limite rígido do requisito: nenhum comando SSH pode passar de 5 segundos.
MAX_COMMAND_TIMEOUT = 5.0
MIN_POLL_INTERVAL = 2.0
MAX_POLL_INTERVAL = 3600.0

HOST_KEY_POLICIES = ("accept-new", "strict")
RUNTIME_MODES = ("auto", "on", "off")
APPEARANCE_MODES = ("dark", "light", "system")
EVENT_PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice")
UNIT_TYPES = ("service", "timer", "socket", "mount", "path")
LATENCY_PROBES = ("auto", "icmp", "ssh", "off")
LOGIN_NOTIFY = ("root", "all", "off")
BANDWIDTH_COUNT = ("tx", "total")


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
    #: Alertas de novas falhas críticas de segurança, SMART e endpoints.
    security_alerts: bool = True
    #: Logins SSH aceitos que geram alerta: só do root, de qualquer usuário ou nenhum.
    notify_on_ssh_login: str = "root"


@dataclass(frozen=True)
class HistorySettings:
    enabled: bool = True
    retention_days: float = 7.0
    #: None = %LOCALAPPDATA%\FirawynixMonitor\history.sqlite3
    file: Path | None = None


@dataclass(frozen=True)
class ThresholdSettings:
    """Alertas de recursos do host. 0 desativa o limite."""

    cpu_percent: float = 90.0
    mem_percent: float = 90.0
    disk_percent: float = 90.0
    #: CPU "roubada" pelo hipervisor (VPS sobrecarregada pelo provedor).
    steal_percent: float = 10.0
    #: Latência Windows → servidor (0 = sem alerta).
    latency_ms: float = 0.0
    #: Coletas seguidas acima do limite antes de alertar (evita picos momentâneos).
    sustain_polls: int = 3


@dataclass(frozen=True)
class EventSettings:
    priority: str = "err"
    limit: int = 100
    since_hours: int = 24


@dataclass(frozen=True)
class WindowsSettings:
    """Integrações com a API do Windows (ignoradas em outros sistemas)."""

    #: Alertas e ações no Visualizador de Eventos (log "Aplicativo").
    event_log: bool = True
    #: Pisca o botão na barra de tarefas em alertas críticos.
    flash_taskbar: bool = True
    #: Impede a suspensão do PC enquanto o monitor estiver aberto.
    prevent_sleep: bool = False
    #: Barra de título com a cor do tema (Windows 11).
    accent_title_bar: bool = True


@dataclass(frozen=True)
class AppSettings:
    poll_interval_seconds: float = 5.0
    #: Processos, portas e estatísticas de contêineres.
    detail_interval_seconds: float = 15.0
    #: Inventário: sistema, timers, cron, eventos do journal.
    inventory_interval_seconds: float = 60.0
    #: Contagem de atualizações pendentes (somente cache local).
    updates_interval_seconds: float = 1800.0
    #: Auditoria de segurança, fail2ban, logins/sudo e SMART.
    security_interval_seconds: float = 300.0
    #: Verificações HTTP/TLS/TCP feitas a partir do Windows.
    endpoint_interval_seconds: float = 60.0
    #: Certificados que expiram em até N dias ficam em "Atenção".
    cert_warning_days: float = 14.0
    #: Latência: ICMP pela API do Windows, abertura de canal SSH ou desativada.
    latency_probe: str = "auto"
    command_timeout_seconds: float = MAX_COMMAND_TIMEOUT
    connect_timeout_seconds: float = 5.0
    minimize_to_tray: bool = True
    start_minimized: bool = False
    appearance_mode: str = "dark"
    log_lines: int = 50
    process_limit: int = 200
    known_hosts_file: Path | None = None
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    history: HistorySettings = field(default_factory=HistorySettings)
    thresholds: ThresholdSettings = field(default_factory=ThresholdSettings)
    events: EventSettings = field(default_factory=EventSettings)
    windows: WindowsSettings = field(default_factory=WindowsSettings)


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    username: str
    port: int = 22
    key_file: Path | None = None
    key_passphrase_env: str | None = None
    password_env: str | None = None
    #: Nome da credencial genérica no Gerenciador de Credenciais do Windows.
    password_credential: str | None = None
    key_passphrase_credential: str | None = None
    allow_agent: bool = True
    look_for_keys: bool = True
    host_key_policy: str = "accept-new"
    use_sudo: bool = True
    docker: str = "auto"
    docker_sudo: bool = False
    podman: str = "auto"
    podman_sudo: bool = False
    kubernetes: str = "auto"
    kubectl_command: str = "kubectl"
    kubectl_sudo: bool = False
    libvirt: str = "auto"
    libvirt_uri: str = "qemu:///system"
    libvirt_sudo: bool = False
    lxd: str = "auto"
    lxd_sudo: bool = False
    smart: str = "auto"
    smart_sudo: bool = False
    #: Auditoria de segurança (somente leitura).
    security: bool = True
    #: sudo -n para sshd -T, ufw/iptables/nft e fail2ban-client status.
    security_sudo: bool = False
    #: Permite banir/desbanir IPs no fail2ban pela interface (exige security_sudo).
    security_actions: bool = False
    endpoints: tuple[str, ...] = ()
    #: Franquia mensal de tráfego do provedor, em GB (None = sem acompanhamento).
    bandwidth_quota_gb: float | None = None
    bandwidth_count: str = "tx"
    logs_sudo: bool = False
    network_sudo: bool = False
    process_actions: bool = False
    process_sudo: bool = False
    unit_types: tuple[str, ...] = UNIT_TYPES
    poll_interval_seconds: float | None = None
    critical_services: tuple[str, ...] = ("*",)
    exclude_services: tuple[str, ...] = ()

    @property
    def address(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    @property
    def uses_password(self) -> bool:
        return bool(self.password_env or self.password_credential)

    def resolve_password(self) -> str | None:
        return _read_secret(self.password_env) or _read_credential(self.password_credential)

    def resolve_passphrase(self) -> str | None:
        return _read_secret(self.key_passphrase_env) or _read_credential(self.key_passphrase_credential)


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
    "poll_interval_seconds", "detail_interval_seconds", "inventory_interval_seconds",
    "updates_interval_seconds", "security_interval_seconds", "endpoint_interval_seconds",
    "cert_warning_days", "latency_probe", "command_timeout_seconds", "connect_timeout_seconds",
    "minimize_to_tray", "start_minimized", "appearance_mode", "log_lines", "process_limit",
    "known_hosts_file", "notifications", "history", "thresholds", "events", "windows",
}
_HISTORY_KEYS = {"enabled", "retention_days", "file"}
_THRESHOLD_KEYS = {"cpu_percent", "mem_percent", "disk_percent", "steal_percent", "latency_ms", "sustain_polls"}
_EVENT_KEYS = {"priority", "limit", "since_hours"}
_WINDOWS_KEYS = {"event_log", "flash_taskbar", "prevent_sleep", "accent_title_bar"}
_NOTIFICATION_KEYS = {
    "enabled", "notify_on_recovery", "notify_on_disconnect", "alert_on_stop",
    "cooldown_seconds", "app_id", "security_alerts", "notify_on_ssh_login",
}
_SERVER_KEYS = {
    "name", "host", "port", "username", "key_file", "key_passphrase_env", "password_env",
    "password_credential", "key_passphrase_credential",
    "allow_agent", "look_for_keys", "host_key_policy", "use_sudo", "docker", "docker_sudo",
    "podman", "podman_sudo", "kubernetes", "kubectl_command", "kubectl_sudo", "libvirt",
    "libvirt_uri", "libvirt_sudo", "lxd", "lxd_sudo", "smart", "smart_sudo", "security", "security_sudo",
    "security_actions", "endpoints", "bandwidth_quota_gb", "bandwidth_count", "logs_sudo", "network_sudo",
    "process_actions", "process_sudo", "unit_types", "poll_interval_seconds", "critical_services",
    "exclude_services",
}
_PLAINTEXT_SECRET_KEYS = {"password", "passphrase", "key_passphrase", "sudo_password"}


def _read_secret(env_name: str | None) -> str | None:
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if value is None:
        log.warning("Variável de ambiente %s não definida", env_name)
    return value


def _read_credential(target: str | None) -> str | None:
    if not target:
        return None
    from core.winapi import IS_WINDOWS, cred_read

    if not IS_WINDOWS:
        log.warning("Credencial %s ignorada: o Gerenciador de Credenciais só existe no Windows", target)
        return None
    value = cred_read(target)
    if value is None:
        log.warning("Credencial %s não encontrada no Gerenciador de Credenciais do Windows", target)
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
                f"suportados. Use '{replacement}' com o nome de uma variável de ambiente (ou .env) "
                f"ou '{replacement.replace('_env', '_credential')}' (Gerenciador de Credenciais do Windows)."
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


def _get_section(raw: dict, key: str, allowed: set[str], ctx: str, errors: list[str]) -> tuple[dict, str]:
    section = raw.get(key, {})
    sctx = f"{ctx}.{key}"
    if not isinstance(section, dict):
        errors.append(f"{sctx} deve ser um objeto.")
        return {}, sctx
    _reject_unknown(section, allowed, sctx, errors)
    return section, sctx


def _get_mode(raw: dict, key: str, ctx: str, errors: list[str]) -> str:
    """``auto``/``on``/``off`` (também aceita true/false)."""
    value = raw.get(key, "auto")
    if isinstance(value, bool):
        return "on" if value else "off"
    return _get_choice(raw, key, RUNTIME_MODES, "auto", ctx, errors)


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
        security_alerts=_get(notif_raw, "security_alerts", bool, defaults_n.security_alerts, nctx, errors),
        notify_on_ssh_login=_get_choice(notif_raw, "notify_on_ssh_login", LOGIN_NOTIFY,
                                        defaults_n.notify_on_ssh_login, nctx, errors),
    )

    hist_raw, hctx = _get_section(raw, "history", _HISTORY_KEYS, ctx, errors)
    defaults_h = HistorySettings()
    history_file = _get(hist_raw, "file", str, None, hctx, errors)
    history = HistorySettings(
        enabled=_get(hist_raw, "enabled", bool, defaults_h.enabled, hctx, errors),
        retention_days=_get_number(hist_raw, "retention_days", defaults_h.retention_days, 0.1, 3650, hctx, errors),
        file=_expand_path(history_file, base_dir) if history_file else None,
    )

    thr_raw, tctx = _get_section(raw, "thresholds", _THRESHOLD_KEYS, ctx, errors)
    defaults_t = ThresholdSettings()
    thresholds = ThresholdSettings(
        cpu_percent=_get_number(thr_raw, "cpu_percent", defaults_t.cpu_percent, 0, 100, tctx, errors),
        mem_percent=_get_number(thr_raw, "mem_percent", defaults_t.mem_percent, 0, 100, tctx, errors),
        disk_percent=_get_number(thr_raw, "disk_percent", defaults_t.disk_percent, 0, 100, tctx, errors),
        steal_percent=_get_number(thr_raw, "steal_percent", defaults_t.steal_percent, 0, 100, tctx, errors),
        latency_ms=_get_number(thr_raw, "latency_ms", defaults_t.latency_ms, 0, 60000, tctx, errors),
        sustain_polls=int(_get_number(thr_raw, "sustain_polls", defaults_t.sustain_polls, 1, 100, tctx, errors)),
    )

    ev_raw, ectx = _get_section(raw, "events", _EVENT_KEYS, ctx, errors)
    defaults_e = EventSettings()
    events = EventSettings(
        priority=_get_choice(ev_raw, "priority", EVENT_PRIORITIES, defaults_e.priority, ectx, errors),
        limit=int(_get_number(ev_raw, "limit", defaults_e.limit, 10, 1000, ectx, errors)),
        since_hours=int(_get_number(ev_raw, "since_hours", defaults_e.since_hours, 1, 24 * 30, ectx, errors)),
    )

    win_raw, wctx = _get_section(raw, "windows", _WINDOWS_KEYS, ctx, errors)
    defaults_w = WindowsSettings()
    windows = WindowsSettings(**{
        key: _get(win_raw, key, bool, getattr(defaults_w, key), wctx, errors) for key in sorted(_WINDOWS_KEYS)
    })

    defaults = AppSettings()
    known_hosts = _get(raw, "known_hosts_file", str, None, ctx, errors)
    return AppSettings(
        poll_interval_seconds=_get_number(raw, "poll_interval_seconds", defaults.poll_interval_seconds,
                                          MIN_POLL_INTERVAL, MAX_POLL_INTERVAL, ctx, errors),
        detail_interval_seconds=_get_number(raw, "detail_interval_seconds", defaults.detail_interval_seconds,
                                            MIN_POLL_INTERVAL, MAX_POLL_INTERVAL, ctx, errors),
        inventory_interval_seconds=_get_number(raw, "inventory_interval_seconds",
                                               defaults.inventory_interval_seconds, 10, 86400, ctx, errors),
        updates_interval_seconds=_get_number(raw, "updates_interval_seconds", defaults.updates_interval_seconds,
                                             60, 86400 * 7, ctx, errors),
        security_interval_seconds=_get_number(raw, "security_interval_seconds",
                                              defaults.security_interval_seconds, 30, 86400, ctx, errors),
        endpoint_interval_seconds=_get_number(raw, "endpoint_interval_seconds",
                                              defaults.endpoint_interval_seconds, 10, 86400, ctx, errors),
        cert_warning_days=_get_number(raw, "cert_warning_days", defaults.cert_warning_days, 1, 365, ctx, errors),
        latency_probe=_get_choice(raw, "latency_probe", LATENCY_PROBES, defaults.latency_probe, ctx, errors),
        windows=windows,
        process_limit=int(_get_number(raw, "process_limit", defaults.process_limit, 10, 5000, ctx, errors)),
        history=history,
        thresholds=thresholds,
        events=events,
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

    kubectl_command = _get(raw, "kubectl_command", str, "kubectl", ctx, errors).strip()
    libvirt_uri = _get(raw, "libvirt_uri", str, "qemu:///system", ctx, errors).strip()
    for key, value, validate in (("kubectl_command", kubectl_command, validate_kubectl_command),
                                 ("libvirt_uri", libvirt_uri, validate_libvirt_uri)):
        try:
            validate(value)
        except ValueError:
            errors.append(f"{ctx}.{key}: valor inválido {value!r}.")

    endpoints = _get_patterns(raw, "endpoints", (), ctx, errors)
    from core.endpoints import parse_endpoint

    for index, endpoint in enumerate(endpoints):
        try:
            parse_endpoint(endpoint)
        except ValueError as exc:
            errors.append(f"{ctx}.endpoints[{index}]: {endpoint!r} inválido ({exc}).")

    credentials = {}
    for key, kind in (("password_credential", "password"), ("key_passphrase_credential", "passphrase")):
        value = raw.get(key)
        if value is True:
            from core.winapi import credential_target

            credentials[key] = credential_target(name or "?", kind)
        elif value in (None, False):
            credentials[key] = None
        elif isinstance(value, str) and value.strip():
            credentials[key] = value.strip()
        else:
            errors.append(f"{ctx}.{key}: use true (nome padrão) ou o nome da credencial.")

    quota = _get_number(raw, "bandwidth_quota_gb", None, 0.001, 10_000_000, ctx, errors)

    unit_types = _get_patterns(raw, "unit_types", UNIT_TYPES, ctx, errors)
    invalid_types = [t for t in unit_types if t not in UNIT_TYPES]
    if invalid_types:
        errors.append(f"{ctx}.unit_types: {', '.join(invalid_types)} inválido(s) (use: {', '.join(UNIT_TYPES)}).")

    server = ServerConfig(
        name=name,
        host=host,
        username=username,
        port=port,
        key_file=key_file,
        key_passphrase_env=_get(raw, "key_passphrase_env", str, None, ctx, errors),
        password_env=_get(raw, "password_env", str, None, ctx, errors),
        password_credential=credentials.get("password_credential"),
        key_passphrase_credential=credentials.get("key_passphrase_credential"),
        allow_agent=_get(raw, "allow_agent", bool, True, ctx, errors),
        look_for_keys=_get(raw, "look_for_keys", bool, True, ctx, errors),
        host_key_policy=_get_choice(raw, "host_key_policy", HOST_KEY_POLICIES, "accept-new", ctx, errors),
        use_sudo=_get(raw, "use_sudo", bool, True, ctx, errors),
        docker=_get_mode(raw, "docker", ctx, errors),
        docker_sudo=_get(raw, "docker_sudo", bool, False, ctx, errors),
        podman=_get_mode(raw, "podman", ctx, errors),
        podman_sudo=_get(raw, "podman_sudo", bool, False, ctx, errors),
        kubernetes=_get_mode(raw, "kubernetes", ctx, errors),
        kubectl_command=kubectl_command,
        kubectl_sudo=_get(raw, "kubectl_sudo", bool, False, ctx, errors),
        libvirt=_get_mode(raw, "libvirt", ctx, errors),
        libvirt_uri=libvirt_uri,
        libvirt_sudo=_get(raw, "libvirt_sudo", bool, False, ctx, errors),
        lxd=_get_mode(raw, "lxd", ctx, errors),
        lxd_sudo=_get(raw, "lxd_sudo", bool, False, ctx, errors),
        smart=_get_mode(raw, "smart", ctx, errors),
        smart_sudo=_get(raw, "smart_sudo", bool, False, ctx, errors),
        security=_get(raw, "security", bool, True, ctx, errors),
        security_sudo=_get(raw, "security_sudo", bool, False, ctx, errors),
        security_actions=_get(raw, "security_actions", bool, False, ctx, errors),
        endpoints=endpoints,
        bandwidth_quota_gb=quota,
        bandwidth_count=_get_choice(raw, "bandwidth_count", BANDWIDTH_COUNT, "tx", ctx, errors),
        logs_sudo=_get(raw, "logs_sudo", bool, False, ctx, errors),
        network_sudo=_get(raw, "network_sudo", bool, False, ctx, errors),
        process_actions=_get(raw, "process_actions", bool, False, ctx, errors),
        process_sudo=_get(raw, "process_sudo", bool, False, ctx, errors),
        unit_types=tuple(t for t in unit_types if t in UNIT_TYPES) or UNIT_TYPES,
        poll_interval_seconds=_get_number(raw, "poll_interval_seconds", None,
                                          MIN_POLL_INTERVAL, MAX_POLL_INTERVAL, ctx, errors),
        critical_services=_get_patterns(raw, "critical_services", ("*",), ctx, errors),
        exclude_services=_get_patterns(raw, "exclude_services", (), ctx, errors),
    )
    if len(errors) > error_count:
        return None
    return server
