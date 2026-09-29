"""Conexão SSH (Paramiko), execução de comandos com timeout rígido e parsers.

Organização do módulo:

1. Exceções
2. Construção/validação de comandos remotos (sem efeitos colaterais)
3. Parsers das saídas de ``systemctl``, ``docker``, ``/proc``, ``free`` e ``df``
4. :class:`SSHClient` — conexão, timeout por comando e operações de alto nível

Os parsers e os construtores de comando são funções puras e testáveis sem rede.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from config.settings import MAX_COMMAND_TIMEOUT, ServerConfig
from core.models import (
    ActionOutcome,
    ActionResult,
    DiskUsage,
    DockerResult,
    DockerState,
    HostMetrics,
    ServiceAction,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
)

log = logging.getLogger(__name__)

#: Limite de saída lida por comando (proteção de memória).
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
#: Intervalo de keepalive SSH (detecta conexões mortas sem esperar o TCP).
KEEPALIVE_SECONDS = 15


# ---------------------------------------------------------------------------
# 1. Exceções
# ---------------------------------------------------------------------------

class SSHError(Exception):
    """Erro base de comunicação SSH."""


class SSHConnectionError(SSHError):
    """Falha de rede/transporte: a conexão precisa ser refeita."""


class SSHAuthError(SSHConnectionError):
    """Credenciais recusadas (chave, agente ou senha)."""


class SSHHostKeyError(SSHConnectionError):
    """Chave do host desconhecida (modo strict) ou divergente (possível MITM)."""


class SSHCommandTimeout(SSHError):
    """O comando excedeu o timeout configurado (máximo de 5 s)."""


class SSHCommandError(SSHError):
    """O comando executou mas retornou erro."""

    def __init__(self, message: str, result: CommandResult | None = None):
        super().__init__(message)
        self.result = result


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        """stdout + stderr (útil para exibir mensagens de erro)."""
        return "\n".join(part for part in (self.stdout.strip(), self.stderr.strip()) if part)


# ---------------------------------------------------------------------------
# 2. Construção e validação de comandos
# ---------------------------------------------------------------------------

# Nomes de unidade systemd: letras, dígitos e ":-_.\@" (o "\" aparece em nomes
# escapados, ex.: systemd-fsck@dev-disk-by\x2duuid-....service). Não pode começar
# com "-" para nunca ser interpretado como opção.
_UNIT_NAME_RE = re.compile(r"[A-Za-z0-9_@:.\\][A-Za-z0-9_@:.\\-]{0,255}")
# Nomes de contêiner Docker: [a-zA-Z0-9][a-zA-Z0-9_.-]+ (ou ID hexadecimal).
_CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")

SYSTEMCTL_JSON_CMD = "systemctl list-units --type=service --all --no-pager --output=json"
SYSTEMCTL_TABLE_CMD = "systemctl list-units --type=service --all --no-pager --plain --no-legend"
DOCKER_PS_ARGS = "ps -a --format '{{json .}}'"

_SECTION = "__FWX_SECTION__"


def validate_unit_name(name: str) -> str:
    if not _UNIT_NAME_RE.fullmatch(name or ""):
        raise ValueError(f"Nome de serviço inválido: {name!r}")
    return name


def validate_container_name(name: str) -> str:
    if not _CONTAINER_NAME_RE.fullmatch(name or ""):
        raise ValueError(f"Nome de contêiner inválido: {name!r}")
    return name


def _sudo(use_sudo: bool) -> str:
    # -n (non-interactive): nunca pede senha; falha imediatamente se o sudoers
    # não liberar o comando com NOPASSWD.
    return "sudo -n " if use_sudo else ""


def build_service_action_command(unit: str, action: ServiceAction, use_sudo: bool) -> str:
    """``systemctl --no-block <ação> <unidade>``.

    ``--no-block`` enfileira o job e retorna imediatamente: serviços lentos
    aparecem como "Iniciando" na próxima coleta sem estourar o timeout de 5 s.
    """
    unit = validate_unit_name(unit)
    return f"{_sudo(use_sudo)}systemctl --no-block {action.value} {shlex.quote(unit)}"


def build_journal_command(unit: str, lines: int, use_sudo: bool) -> str:
    unit = validate_unit_name(unit)
    return f"{_sudo(use_sudo)}journalctl -u {shlex.quote(unit)} -n {int(lines)} --no-pager"


def build_docker_action_command(container: str, action: ServiceAction, use_sudo: bool) -> str:
    container = validate_container_name(container)
    # -t 3: aguarda no máximo 3 s pelo SIGTERM antes do SIGKILL (cabe no timeout).
    stop_timeout = "" if action is ServiceAction.START else " -t 3"
    return f"{_sudo(use_sudo)}docker {action.value}{stop_timeout} {shlex.quote(container)}"


def build_docker_logs_command(container: str, lines: int, use_sudo: bool) -> str:
    container = validate_container_name(container)
    return f"{_sudo(use_sudo)}docker logs --tail {int(lines)} --timestamps {shlex.quote(container)} 2>&1"


def build_docker_ps_command(use_sudo: bool) -> str:
    return f"{_sudo(use_sudo)}docker {DOCKER_PS_ARGS}"


def build_metrics_command(sample_cpu_twice: bool) -> str:
    """Um único round-trip para uptime, load, CPU, memória e disco."""
    cpu = "grep '^cpu ' /proc/stat"
    if sample_cpu_twice:
        # Primeira coleta: duas amostras para já exibir o uso de CPU.
        cpu = f"{cpu}; sleep 0.5; {cpu}"
    parts = [
        "cat /proc/uptime",
        "cat /proc/loadavg",
        "nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo",
        cpu,
        "free -m",
        # timeout: um mount de rede travado (NFS) não pode segurar a coleta inteira.
        "if command -v timeout >/dev/null 2>&1; then timeout 2 df -kP; else df -kP; fi 2>/dev/null",
    ]
    return f"; echo {_SECTION}; ".join(f"{{ {part}; }}" for part in parts)


def wrap_remote_command(command: str) -> str:
    """Executa via ``sh -c`` com locale C: saída previsível para os parsers
    independentemente do shell de login (bash, zsh, fish...)."""
    return f"env LC_ALL=C LANG=C sh -c {shlex.quote(command)}"


# ---------------------------------------------------------------------------
# 3. Parsers
# ---------------------------------------------------------------------------

_SYSTEMD_TRANSITIONAL = {"activating", "reloading", "refreshing"}


def classify_systemd(active: str, sub: str) -> ServiceStatus:
    active = active.lower()
    if active == "failed":
        return ServiceStatus.FAILED
    if active in _SYSTEMD_TRANSITIONAL:
        return ServiceStatus.ACTIVATING
    if active == "active":
        return ServiceStatus.ACTIVE
    if active in {"inactive", "deactivating"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def _make_unit(unit: str, load: str, active: str, sub: str, description: str) -> ServiceInfo | None:
    if not unit or load == "not-found":
        # Unidades referenciadas mas inexistentes poluem a lista (--all).
        return None
    return ServiceInfo(
        kind=ServiceKind.SYSTEMD,
        name=unit,
        description=description,
        status=classify_systemd(active, sub),
        active_state=active,
        sub_state=sub,
        load_state=load,
    )


def parse_systemctl_json(output: str) -> list[ServiceInfo]:
    data = json.loads(output)
    if not isinstance(data, list):
        raise ValueError("Saída JSON do systemctl não é uma lista")
    services: list[ServiceInfo] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        entry = {str(k).lower(): ("" if v is None else str(v)) for k, v in item.items()}
        service = _make_unit(
            entry.get("unit") or entry.get("name", ""),
            entry.get("load", ""),
            entry.get("active", ""),
            entry.get("sub", ""),
            entry.get("description", ""),
        )
        if service is not None:
            services.append(service)
    return services


def parse_systemctl_table(output: str) -> list[ServiceInfo]:
    """Fallback para systemd antigos (sem ``--output=json`` em list-units)."""
    services: list[ServiceInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        # Marcador de falha: "●" (UTF-8) ou "*" (locale C).
        line = line.lstrip("●*").strip()
        if not line or line.startswith(("UNIT ", "LOAD ", "To show all")):
            continue
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue
        unit, load, active, sub = parts[:4]
        description = parts[4] if len(parts) > 4 else ""
        service = _make_unit(unit, load, active, sub, description)
        if service is not None:
            services.append(service)
    return services


# Códigos de saída típicos de parada intencional (docker stop / Ctrl+C):
# 0, SIGINT (130), SIGKILL após timeout do stop (137) e SIGTERM (143).
_DOCKER_CLEAN_EXIT_CODES = {0, 130, 137, 143}
_EXIT_CODE_RE = re.compile(r"\((-?\d+)\)")


def classify_docker(state: str, status_text: str) -> ServiceStatus:
    state = (state or "").lower()
    status_lower = (status_text or "").lower()
    if not state:
        # Versões antigas do Docker não expõem .State: deduz pelo texto.
        for prefix, derived in (("up", "running"), ("exited", "exited"), ("restarting", "restarting"),
                                ("created", "created"), ("dead", "dead"), ("removal", "removing")):
            if status_lower.startswith(prefix):
                state = derived
                break
        if "(paused)" in status_lower:
            state = "paused"

    code_match = _EXIT_CODE_RE.search(status_text or "")
    exit_code = int(code_match.group(1)) if code_match else None

    if state == "running":
        if "(unhealthy)" in status_lower:
            return ServiceStatus.FAILED
        if "health: starting" in status_lower:
            return ServiceStatus.ACTIVATING
        return ServiceStatus.ACTIVE
    if state == "restarting":
        # Reiniciando com código de erro = loop de crash.
        return ServiceStatus.FAILED if exit_code not in (None, 0) else ServiceStatus.ACTIVATING
    if state == "exited":
        return ServiceStatus.STOPPED if exit_code in _DOCKER_CLEAN_EXIT_CODES else ServiceStatus.FAILED
    if state == "dead":
        return ServiceStatus.FAILED
    if state in {"created", "paused", "removing"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def parse_docker_ps(output: str) -> list[ServiceInfo]:
    containers: list[ServiceInfo] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            log.debug("Linha do docker ps ignorada: %r", line)
            continue
        names = str(item.get("Names") or item.get("ID") or "").split(",")
        name = names[0].strip().lstrip("/")
        if not name:
            continue
        state = str(item.get("State") or "")
        status_text = str(item.get("Status") or "")
        containers.append(ServiceInfo(
            kind=ServiceKind.DOCKER,
            name=name,
            description=str(item.get("Image") or ""),
            status=classify_docker(state, status_text),
            active_state=state or "?",
            sub_state=status_text,
        ))
    return containers


def classify_docker_error(result: CommandResult) -> tuple[DockerState, str]:
    text = result.output
    lower = text.lower()
    if result.exit_code == 127 or "command not found" in lower or ("not found" in lower and "docker:" in lower):
        return DockerState.NOT_INSTALLED, "Docker não instalado neste host."
    if "permission denied" in lower and "docker" in lower:
        return DockerState.PERMISSION, (
            "Sem permissão no socket do Docker. Adicione o usuário ao grupo 'docker' "
            "ou habilite \"docker_sudo\" (com NOPASSWD no sudoers)."
        )
    if "a password is required" in lower or "a terminal is required" in lower:
        return DockerState.PERMISSION, "sudo exige senha para o docker; configure NOPASSWD no sudoers."
    if ("cannot connect to the docker daemon" in lower or "daemon running" in lower
            or "daemon is running" in lower or "failed to connect to the docker api" in lower):
        return DockerState.DAEMON_DOWN, "Daemon do Docker não está em execução."
    first_line = text.splitlines()[0] if text else f"código de saída {result.exit_code}"
    return DockerState.ERROR, f"Erro ao consultar o Docker: {first_line}"


def parse_uptime(text: str) -> float | None:
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def parse_loadavg(text: str) -> tuple[float, float, float] | None:
    try:
        one, five, fifteen = (float(v) for v in text.split()[:3])
    except ValueError:
        return None
    return one, five, fifteen


def parse_cpu_count(text: str) -> int | None:
    try:
        return int(text.strip().splitlines()[0])
    except (IndexError, ValueError):
        return None


def parse_cpu_samples(text: str) -> list[tuple[int, int]]:
    """Linhas ``cpu ...`` de /proc/stat → lista de (ocioso, total) em jiffies."""
    samples: list[tuple[int, int]] = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != "cpu":
            continue
        try:
            values = [int(v) for v in fields[1:]]
        except ValueError:
            continue
        if len(values) < 4:
            continue
        # user nice system idle iowait irq softirq steal (guest já está em user)
        core = values[:8]
        idle = core[3] + (core[4] if len(core) > 4 else 0)
        samples.append((idle, sum(core)))
    return samples


def cpu_percent_between(previous: tuple[int, int], current: tuple[int, int]) -> float | None:
    idle_delta = current[0] - previous[0]
    total_delta = current[1] - previous[1]
    if total_delta <= 0 or idle_delta < 0:
        return None
    return max(0.0, min(100.0, 100.0 * (1 - idle_delta / total_delta)))


def parse_free(text: str) -> dict[str, int]:
    """Saída de ``free -m`` → total/used/available (+ swap).

    Suporta o procps moderno (coluna ``available``) e o antigo (linha
    ``-/+ buffers/cache``, ex.: CentOS 6).
    """
    result: dict[str, int] = {}
    header: list[str] = ["total", "used", "free"]
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "total":
            header = fields
            continue
        if fields[0] == "-/+":
            numbers = [int(v) for v in fields[2:] if v.isdigit()]
            if len(numbers) >= 2:
                result["used"], result["available"] = numbers[0], numbers[1]
            continue
        label = fields[0].rstrip(":").lower()
        try:
            values = [int(v) for v in fields[1:]]
        except ValueError:
            continue
        columns = dict(zip(header, values, strict=False))
        if label == "mem":
            result["total"] = columns.get("total", 0)
            result["used"] = columns.get("used", 0)
            if "available" in columns:
                result["available"] = columns["available"]
            else:
                result["available"] = (columns.get("free", 0) + columns.get("buffers", 0)
                                       + columns.get("cached", 0))
        elif label == "swap":
            result["swap_total"] = columns.get("total", 0)
            result["swap_used"] = columns.get("used", 0)
    return result


_PSEUDO_FILESYSTEMS = {"tmpfs", "devtmpfs", "udev", "overlay", "shm", "none", "squashfs",
                       "efivarfs", "proc", "sysfs", "cgroup", "cgroup2", "nsfs", "rootfs"}
_IGNORED_MOUNT_PREFIXES = ("/dev", "/proc", "/sys", "/run", "/snap/", "/var/lib/docker/",
                           "/var/snap/", "/boot/efi")


def parse_df(text: str) -> list[DiskUsage]:
    """Saída de ``df -kP`` (POSIX, blocos de 1 KiB), sem pseudo-sistemas de arquivos."""
    disks: list[DiskUsage] = []
    seen_mounts: set[str] = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        filesystem = fields[0]
        mount = " ".join(fields[5:])
        if filesystem in _PSEUDO_FILESYSTEMS or mount.startswith(_IGNORED_MOUNT_PREFIXES):
            continue
        if filesystem.startswith("/dev/loop") or mount in seen_mounts:
            continue
        try:
            size, used, avail = int(fields[1]), int(fields[2]), int(fields[3])
            use_percent = float(fields[4].rstrip("%"))
        except ValueError:
            continue
        if size <= 0:
            continue
        seen_mounts.add(mount)
        disks.append(DiskUsage(filesystem, mount, size, used, avail, use_percent))
    return disks


def parse_metrics(output: str, previous_cpu: tuple[int, int] | None) -> tuple[HostMetrics, tuple[int, int] | None]:
    """Interpreta a saída de :func:`build_metrics_command`.

    Retorna as métricas e a última amostra de CPU (para o próximo delta).
    """
    sections = [s.strip("\n") for s in output.split(_SECTION)]
    sections += [""] * (6 - len(sections))
    uptime_s, load_s, nproc_s, cpu_s, free_s, df_s = sections[:6]

    samples = parse_cpu_samples(cpu_s)
    cpu_pct = None
    if len(samples) >= 2:
        cpu_pct = cpu_percent_between(samples[-2], samples[-1])
    elif samples and previous_cpu is not None:
        cpu_pct = cpu_percent_between(previous_cpu, samples[-1])
    last_sample = samples[-1] if samples else previous_cpu

    memory = parse_free(free_s)
    metrics = HostMetrics(
        uptime_seconds=parse_uptime(uptime_s),
        load_avg=parse_loadavg(load_s),
        cpu_count=parse_cpu_count(nproc_s),
        cpu_percent=cpu_pct,
        mem_total_mb=memory.get("total"),
        mem_used_mb=memory.get("used"),
        mem_available_mb=memory.get("available"),
        swap_total_mb=memory.get("swap_total"),
        swap_used_mb=memory.get("swap_used"),
        disks=tuple(parse_df(df_s)),
    )
    return metrics, last_sample


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def describe_sudo_failure(output: str) -> str | None:
    lower = output.lower()
    if "a password is required" in lower or "a terminal is required" in lower:
        return ("O sudo exigiu senha. Libere o comando com NOPASSWD no sudoers "
                "(veja docs/sudoers.example) — o monitor nunca envia senhas ao sudo.")
    if "not in the sudoers file" in lower or "is not allowed to execute" in lower:
        return "O usuário SSH não tem permissão no sudoers para este comando."
    if "interactive authentication required" in lower or "access denied" in lower:
        return ("O systemd/polkit negou a operação. Habilite \"use_sudo\" e configure o "
                "sudoers com NOPASSWD para os comandos permitidos.")
    return None


# ---------------------------------------------------------------------------
# 4. Cliente SSH
# ---------------------------------------------------------------------------

class SSHClient:
    """Conexão agentless com um servidor Linux.

    Thread-safety: ``connect``/``close`` são serializados por lock; comandos
    podem ser executados concorrentemente (cada um abre seu próprio canal no
    mesmo transporte SSH, que o Paramiko multiplexa com segurança).
    """

    def __init__(
        self,
        server: ServerConfig,
        *,
        command_timeout: float = MAX_COMMAND_TIMEOUT,
        connect_timeout: float = 5.0,
        known_hosts_file: Path | None = None,
    ) -> None:
        self.server = server
        self.command_timeout = min(float(command_timeout), MAX_COMMAND_TIMEOUT)
        self.connect_timeout = float(connect_timeout)
        self.known_hosts_file = known_hosts_file
        self._lock = threading.RLock()
        self._client: paramiko.SSHClient | None = None
        self._systemctl_json: bool | None = None
        self._prev_cpu: tuple[int, int] | None = None

    # -- conexão ----------------------------------------------------------

    @property
    def connected(self) -> bool:
        client = self._client
        transport = client.get_transport() if client is not None else None
        return bool(transport and transport.is_active() and transport.is_authenticated())

    @property
    def _is_root(self) -> bool:
        return self.server.username == "root"

    def connect(self) -> None:
        with self._lock:
            self._close_locked()
            client = paramiko.SSHClient()
            # known_hosts do usuário (~/.ssh/known_hosts) é somente leitura.
            client.load_system_host_keys()
            if self.known_hosts_file is not None:
                self.known_hosts_file.parent.mkdir(parents=True, exist_ok=True)
                self.known_hosts_file.touch(exist_ok=True)
                client.load_host_keys(str(self.known_hosts_file))
            if self.server.host_key_policy == "strict":
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                # "accept-new" (TOFU): aceita e grava a chave na primeira conexão;
                # chave divergente depois disso é SEMPRE rejeitada (BadHostKeyException).
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            server = self.server
            try:
                client.connect(
                    hostname=server.host,
                    port=server.port,
                    username=server.username,
                    password=server.resolve_password(),
                    key_filename=str(server.key_file) if server.key_file else None,
                    passphrase=server.resolve_passphrase(),
                    timeout=self.connect_timeout,
                    banner_timeout=self.connect_timeout,
                    auth_timeout=self.connect_timeout,
                    channel_timeout=self.command_timeout,
                    allow_agent=server.allow_agent,
                    look_for_keys=server.look_for_keys,
                )
            except paramiko.BadHostKeyException as exc:
                client.close()
                raise SSHHostKeyError(
                    f"A chave SSH de {server.host} MUDOU (possível ataque man-in-the-middle). "
                    "Conexão recusada. Se a troca foi legítima, remova a entrada antiga do "
                    "known_hosts."
                ) from exc
            except paramiko.AuthenticationException as exc:
                client.close()
                raise SSHAuthError(f"Autenticação recusada para {server.address}: {exc}") from exc
            except paramiko.SSHException as exc:
                client.close()
                if "not found in known_hosts" in str(exc):
                    raise SSHHostKeyError(
                        f"Host {server.host} ausente do known_hosts (host_key_policy=strict). "
                        f"Conecte uma vez com 'ssh {server.username}@{server.host}' para registrá-lo."
                    ) from exc
                raise SSHConnectionError(f"Erro SSH com {server.host}: {exc}") from exc
            except (OSError, EOFError) as exc:  # TimeoutError é subclasse de OSError
                client.close()
                if isinstance(exc, TimeoutError):
                    reason = "tempo esgotado"
                elif isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
                    reason = "conexão recusada (sshd parado, porta fechada ou firewall)"
                else:
                    reason = exc
                raise SSHConnectionError(f"Não foi possível conectar a {server.host}:{server.port}: {reason}") from exc

            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(KEEPALIVE_SECONDS)
            self._client = client
            self._prev_cpu = None
            log.info("[%s] conectado a %s", server.name, server.address)

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001 - fechamento best-effort
                log.debug("Erro ao fechar conexão", exc_info=True)
            self._client = None

    def _transport(self) -> paramiko.Transport:
        client = self._client
        transport = client.get_transport() if client is not None else None
        if transport is None or not transport.is_active():
            raise SSHConnectionError(f"Sem conexão ativa com {self.server.host}")
        return transport

    # -- execução ---------------------------------------------------------

    def run(self, command: str, timeout: float | None = None) -> CommandResult:
        """Executa ``command`` com timeout total (conexão do canal + execução + leitura).

        Nunca bloqueia mais que ``timeout`` (máx. 5 s): além do prazo no laço de
        leitura, um watchdog derruba o transporte se o servidor travar no meio
        do protocolo — o monitor então reconecta com backoff.
        """
        timeout = min(timeout or self.command_timeout, MAX_COMMAND_TIMEOUT)
        transport = self._transport()
        started = time.monotonic()
        deadline = started + timeout
        watchdog = threading.Timer(timeout + 1.0, self._abort_transport, args=(transport, command))
        watchdog.daemon = True
        watchdog.start()
        channel: paramiko.Channel | None = None
        try:
            try:
                channel = transport.open_session(timeout=timeout)
                channel.exec_command(wrap_remote_command(command))
                channel.shutdown_write()  # EOF no stdin: nada fica esperando entrada
            except (paramiko.SSHException, OSError, EOFError) as exc:
                if time.monotonic() >= deadline:
                    raise SSHCommandTimeout(f"Timeout ({timeout:g}s) ao abrir canal: {command}") from exc
                raise SSHConnectionError(f"Falha ao abrir canal SSH: {exc}") from exc

            stdout, stderr = bytearray(), bytearray()
            while True:
                progressed = False
                while channel.recv_ready():
                    stdout += channel.recv(65536)
                    progressed = True
                while channel.recv_stderr_ready():
                    stderr += channel.recv_stderr(65536)
                    progressed = True
                if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
                    raise SSHCommandError(f"Saída excedeu {MAX_OUTPUT_BYTES} bytes: {command}")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() >= deadline:
                    raise SSHCommandTimeout(f"Comando excedeu {timeout:g}s: {command}")
                if not transport.is_active():
                    raise SSHConnectionError("Conexão SSH perdida durante o comando")
                if not progressed:
                    time.sleep(0.01)
            exit_code = channel.recv_exit_status()
        finally:
            watchdog.cancel()
            if channel is not None:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001
                    pass

        result = CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration=time.monotonic() - started,
        )
        log.debug("[%s] %s → %s em %.2fs", self.server.name, command, exit_code, result.duration)
        return result

    def _abort_transport(self, transport: paramiko.Transport, command: str) -> None:
        log.warning("[%s] watchdog: servidor não respondeu a %r; derrubando conexão", self.server.name, command)
        try:
            transport.close()
        except Exception:  # noqa: BLE001
            pass

    # -- coleta -----------------------------------------------------------

    def list_services(self) -> list[ServiceInfo]:
        if self._systemctl_json is not False:
            result = self.run(SYSTEMCTL_JSON_CMD)
            if result.ok and result.stdout.lstrip().startswith("["):
                try:
                    services = parse_systemctl_json(result.stdout)
                except ValueError:
                    log.info("[%s] JSON do systemctl inválido; usando saída tabular", self.server.name)
                else:
                    self._systemctl_json = True
                    return services
            elif not result.ok and not re.search(r"unrecognized|invalid|unknown|json", result.stderr, re.I):
                # systemd presente mas inoperante (ex.: "System has not been booted with systemd").
                raise SSHCommandError(f"systemctl indisponível: {result.output or result.exit_code}", result)
            # systemd antigo: ignora ou rejeita --output=json em list-units.
            log.info("[%s] systemctl sem suporte a JSON; usando saída tabular", self.server.name)
            self._systemctl_json = False
        result = self.run(SYSTEMCTL_TABLE_CMD)
        if not result.ok:
            raise SSHCommandError(f"systemctl indisponível: {result.output or result.exit_code}", result)
        return parse_systemctl_table(result.stdout)

    def list_containers(self) -> DockerResult:
        if self.server.docker == "off":
            return DockerResult(DockerState.DISABLED)
        result = self.run(build_docker_ps_command(self.server.docker_sudo and not self._is_root))
        if result.ok:
            return DockerResult(DockerState.OK, tuple(parse_docker_ps(result.stdout)))
        state, message = classify_docker_error(result)
        return DockerResult(state, (), message)

    def host_metrics(self) -> HostMetrics:
        result = self.run(build_metrics_command(sample_cpu_twice=self._prev_cpu is None))
        metrics, self._prev_cpu = parse_metrics(result.stdout, self._prev_cpu)
        return metrics

    # -- ações ------------------------------------------------------------

    def service_action(self, service: ServiceInfo, action: ServiceAction) -> ActionResult:
        if service.kind is ServiceKind.DOCKER:
            command = build_docker_action_command(service.name, action, self.server.docker_sudo and not self._is_root)
        else:
            command = build_service_action_command(service.name, action, self.server.use_sudo and not self._is_root)
        try:
            result = self.run(command)
        except SSHCommandTimeout:
            return ActionResult(
                ActionOutcome.PENDING,
                f"'{action.label}' em {service.name} ainda em andamento após {self.command_timeout:g}s; "
                "acompanhe o status na tabela.",
            )
        if result.ok:
            verb = {"start": "Início", "stop": "Parada", "restart": "Reinício"}[action.value]
            return ActionResult(ActionOutcome.OK, f"{verb} de {service.name} solicitado com sucesso.")
        hint = describe_sudo_failure(result.output)
        detail = hint or result.output or f"código de saída {result.exit_code}"
        return ActionResult(ActionOutcome.ERROR, f"Falha ao {action.label.lower()} {service.name}: {detail}")

    def service_logs(self, service: ServiceInfo, lines: int) -> str:
        if service.kind is ServiceKind.DOCKER:
            command = build_docker_logs_command(service.name, lines, self.server.docker_sudo and not self._is_root)
        else:
            command = build_journal_command(service.name, lines, self.server.logs_sudo and not self._is_root)
        result = self.run(command)
        text = strip_ansi(result.stdout if service.kind is ServiceKind.DOCKER else result.output).rstrip()
        if not result.ok:
            hint = describe_sudo_failure(result.output)
            prefix = f"[código de saída {result.exit_code}]"
            return f"{prefix} {hint}\n\n{text}" if hint else f"{prefix}\n{text}"
        return text or "(sem entradas de log)"
