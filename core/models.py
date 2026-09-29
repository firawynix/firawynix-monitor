"""Modelos imutáveis compartilhados entre o núcleo e a interface."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class ServiceKind(StrEnum):
    """Origem de uma carga de trabalho. O valor é o prefixo usado nas chaves e
    nos padrões de ``critical_services`` (ex.: ``docker:web``, ``k8s:prod/*``)."""

    SYSTEMD = "systemd"
    DOCKER = "docker"
    PODMAN = "podman"
    KUBERNETES = "k8s"
    LIBVIRT = "vm"
    LXD = "lxd"

    @property
    def label(self) -> str:
        return _KIND_LABELS[self]

    @property
    def is_container(self) -> bool:
        return self in (ServiceKind.DOCKER, ServiceKind.PODMAN)


_KIND_LABELS = {
    ServiceKind.SYSTEMD: "systemd",
    ServiceKind.DOCKER: "Docker",
    ServiceKind.PODMAN: "Podman",
    ServiceKind.KUBERNETES: "Kubernetes",
    ServiceKind.LIBVIRT: "VM",
    ServiceKind.LXD: "LXD/Incus",
}

#: Tipos de unidade systemd coletados por padrão.
SYSTEMD_UNIT_TYPES = ("service", "timer", "socket", "mount", "path")


class ServiceStatus(StrEnum):
    ACTIVE = "active"
    ACTIVATING = "activating"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return _STATUS_LABELS[self]

    @property
    def severity(self) -> int:
        """Menor = mais grave. Usado para ordenar falhas no topo da tabela."""
        return _STATUS_SEVERITY[self]


_STATUS_LABELS = {
    ServiceStatus.ACTIVE: "Ativo",
    ServiceStatus.ACTIVATING: "Iniciando",
    ServiceStatus.DEGRADED: "Degradado",
    ServiceStatus.STOPPED: "Parado",
    ServiceStatus.FAILED: "Falha",
    ServiceStatus.UNKNOWN: "Desconhecido",
}
_STATUS_SEVERITY = {
    ServiceStatus.FAILED: 0,
    ServiceStatus.DEGRADED: 1,
    ServiceStatus.ACTIVATING: 2,
    ServiceStatus.UNKNOWN: 3,
    ServiceStatus.STOPPED: 4,
    ServiceStatus.ACTIVE: 5,
}


class ServiceAction(StrEnum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"

    @property
    def label(self) -> str:
        return {"start": "Iniciar", "stop": "Parar", "restart": "Reiniciar"}[self.value]

    @property
    def progress_label(self) -> str:
        return {"start": "Iniciando", "stop": "Parando", "restart": "Reiniciando"}[self.value]


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    """Uma carga de trabalho: unidade systemd, contêiner, pod ou VM."""

    kind: ServiceKind
    name: str
    description: str
    status: ServiceStatus
    #: systemd: ACTIVE · contêiner: State · pod: phase · VM: estado do libvirt
    active_state: str
    #: systemd: SUB · contêiner: Status ("Up 2 hours") · pod: prontos/reinícios
    sub_state: str
    load_state: str = ""
    critical: bool = False
    #: Projeto do Compose (contêineres) ou namespace (pods).
    group: str = ""
    cpu_percent: float | None = None
    mem_bytes: int | None = None
    #: Metadados extras exibidos em detalhes (ex.: diretório do Compose, nó do pod).
    meta: tuple[tuple[str, str], ...] = ()

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"

    @property
    def unit_type(self) -> str:
        """``service``/``timer``/... para systemd; o tipo da carga nos demais casos."""
        if self.kind is ServiceKind.SYSTEMD:
            return self.name.rsplit(".", 1)[-1] if "." in self.name else "service"
        if self.kind is ServiceKind.LXD:
            return "vm" if self.meta_value("type") == "virtual-machine" else "container"
        return {ServiceKind.KUBERNETES: "pod", ServiceKind.LIBVIRT: "vm"}.get(self.kind, "container")

    @property
    def type_label(self) -> str:
        if self.kind is ServiceKind.SYSTEMD:
            return self.unit_type
        if self.kind is ServiceKind.LXD:
            return "VM LXD" if self.unit_type == "vm" else "LXC"
        return {ServiceKind.KUBERNETES: "Pod", ServiceKind.LIBVIRT: "VM"}.get(self.kind, self.kind.label)

    @property
    def state_text(self) -> str:
        if self.kind is not ServiceKind.SYSTEMD:
            return self.sub_state or self.active_state
        return f"{self.active_state}/{self.sub_state}" if self.sub_state else self.active_state

    def meta_value(self, name: str, default: str = "") -> str:
        for key, value in self.meta:
            if key == name:
                return value
        return default

    def supports(self, action: ServiceAction) -> bool:
        if self.kind is ServiceKind.KUBERNETES:
            # Pods não "iniciam/param": reiniciar = excluir e deixar o controlador recriar.
            return action is ServiceAction.RESTART
        return True


@dataclass(frozen=True, slots=True)
class DiskUsage:
    filesystem: str
    mount: str
    size_kb: int
    used_kb: int
    avail_kb: int
    use_percent: float
    inode_percent: float | None = None


@dataclass(frozen=True, slots=True)
class InterfaceStats:
    name: str
    rx_bytes: int
    tx_bytes: int
    rx_bps: float | None = None
    tx_bps: float | None = None
    #: loopback, veth, bridges de contêiner etc. — fora do total de tráfego do host.
    virtual: bool = False


@dataclass(frozen=True, slots=True)
class DiskIO:
    device: str
    read_bps: float | None
    write_bps: float | None


@dataclass(frozen=True, slots=True)
class HostMetrics:
    uptime_seconds: float | None = None
    load_avg: tuple[float, float, float] | None = None
    cpu_count: int | None = None
    cpu_percent: float | None = None
    #: Tempo "roubado" pelo hipervisor (VPS com vizinhos barulhentos) e espera de E/S, em %.
    cpu_steal: float | None = None
    cpu_iowait: float | None = None
    mem_total_mb: int | None = None
    mem_used_mb: int | None = None
    mem_available_mb: int | None = None
    swap_total_mb: int | None = None
    swap_used_mb: int | None = None
    disks: tuple[DiskUsage, ...] = ()
    interfaces: tuple[InterfaceStats, ...] = ()
    disk_io: tuple[DiskIO, ...] = ()

    @property
    def mem_percent(self) -> float | None:
        if not self.mem_total_mb or self.mem_used_mb is None:
            return None
        return 100.0 * self.mem_used_mb / self.mem_total_mb

    @property
    def swap_percent(self) -> float | None:
        if not self.swap_total_mb or self.swap_used_mb is None:
            return None
        return 100.0 * self.swap_used_mb / self.swap_total_mb

    @property
    def root_disk(self) -> DiskUsage | None:
        for disk in self.disks:
            if disk.mount == "/":
                return disk
        return self.disks[0] if self.disks else None

    @property
    def fullest_disk(self) -> DiskUsage | None:
        return max(self.disks, key=lambda d: d.use_percent, default=None)

    @property
    def net_rx_bps(self) -> float | None:
        return _sum_optional(i.rx_bps for i in self.interfaces if not i.virtual)

    @property
    def net_tx_bps(self) -> float | None:
        return _sum_optional(i.tx_bps for i in self.interfaces if not i.virtual)

    @property
    def disk_read_bps(self) -> float | None:
        return _sum_optional(d.read_bps for d in self.disk_io)

    @property
    def disk_write_bps(self) -> float | None:
        return _sum_optional(d.write_bps for d in self.disk_io)


def _sum_optional(values) -> float | None:
    total, seen = 0.0, False
    for value in values:
        if value is not None:
            total += value
            seen = True
    return total if seen else None


class RuntimeState(StrEnum):
    OK = "ok"
    DISABLED = "disabled"
    NOT_INSTALLED = "not_installed"
    DAEMON_DOWN = "daemon_down"
    PERMISSION = "permission"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    """Resultado da consulta a um runtime (Docker, Podman, Kubernetes, libvirt)."""

    kind: ServiceKind
    state: RuntimeState
    items: tuple[ServiceInfo, ...] = ()
    message: str = ""


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    user: str
    cpu_percent: float | None
    mem_percent: float
    rss_kb: int
    elapsed_seconds: int
    state: str
    command: str
    args: str


@dataclass(frozen=True, slots=True)
class ListeningSocket:
    proto: str
    address: str
    port: int
    process: str = ""
    pid: int | None = None


@dataclass(frozen=True, slots=True)
class NetworkInfo:
    listening: tuple[ListeningSocket, ...] = ()
    tcp_inuse: int | None = None
    tcp_timewait: int | None = None
    udp_inuse: int | None = None
    #: False quando o ``ss`` não pôde mostrar os processos (falta de sudo).
    process_info: bool = True


@dataclass(frozen=True, slots=True)
class TimerInfo:
    name: str
    activates: str
    next_run: str
    last_run: str
    active_state: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class CronEntry:
    source: str
    schedule: str
    user: str
    command: str


JOURNAL_PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


@dataclass(frozen=True, slots=True)
class JournalEntry:
    timestamp: float
    priority: int
    unit: str
    identifier: str
    message: str

    @property
    def priority_label(self) -> str:
        if 0 <= self.priority < len(JOURNAL_PRIORITIES):
            return JOURNAL_PRIORITIES[self.priority]
        return str(self.priority)


@dataclass(frozen=True, slots=True)
class SystemInfo:
    hostname: str = ""
    os_name: str = ""
    kernel: str = ""
    arch: str = ""
    cpu_model: str = ""
    virtualization: str = ""
    boot_time: str = ""
    timezone: str = ""
    logged_users: int | None = None
    reboot_required: bool = False
    ip_addresses: tuple[str, ...] = ()
    failed_units: int | None = None
    temperatures: tuple[tuple[str, float], ...] = ()
    #: None = desconhecido; False = usuário sem acesso ao journal completo.
    journal_access: bool | None = None
    ssh_failed_logins_24h: int | None = None


@dataclass(frozen=True, slots=True)
class UpdatesInfo:
    manager: str
    pending: int | None
    security: int | None = None


# ---------------------------------------------------------------------------
# VPS, SMART, endpoints e segurança
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class BandwidthUsage:
    """Tráfego acumulado no mês (vnStat) — base da franquia cobrada pelo provedor."""

    interface: str
    period: str
    rx_bytes: int
    tx_bytes: int
    today_rx: int | None = None
    today_tx: int | None = None

    @property
    def total_bytes(self) -> int:
        return self.rx_bytes + self.tx_bytes


@dataclass(frozen=True, slots=True)
class OomKill:
    timestamp: float
    process: str


@dataclass(frozen=True, slots=True)
class VpsInfo:
    provider: str = ""
    product: str = ""
    ntp_synchronized: bool | None = None
    ntp_service: str = ""
    #: Diferença para a referência NTP (chrony), em segundos.
    clock_offset: float | None = None
    dns_servers: tuple[str, ...] = ()
    default_gateway: str = ""
    swappiness: int | None = None
    oom_kills: tuple[OomKill, ...] = ()
    #: None = sem acesso ao journal do kernel.
    oom_kills_24h: int | None = None
    bandwidth: tuple[BandwidthUsage, ...] = ()
    #: "" = vnStat ausente (o tráfego mensal não é contabilizado).
    bandwidth_source: str = ""

    def bandwidth_total(self, count: str = "tx") -> int | None:
        if not self.bandwidth:
            return None
        return sum(b.tx_bytes if count == "tx" else b.total_bytes for b in self.bandwidth)


@dataclass(frozen=True, slots=True)
class SmartDisk:
    device: str
    model: str = ""
    serial: str = ""
    capacity_bytes: int | None = None
    #: True = aprovado, False = reprovado (disco condenado), None = não informado.
    passed: bool | None = None
    temperature: float | None = None
    power_on_hours: int | None = None
    reallocated: int | None = None
    pending: int | None = None
    uncorrectable: int | None = None
    media_errors: int | None = None
    percentage_used: int | None = None
    critical_warning: int | None = None
    message: str = ""

    @property
    def status(self) -> ServiceStatus:
        if self.passed is False or self.critical_warning:
            return ServiceStatus.FAILED
        if self.passed is None:
            return ServiceStatus.UNKNOWN
        if any(v for v in (self.reallocated, self.pending, self.uncorrectable, self.media_errors)) \
                or (self.percentage_used or 0) >= 90:
            return ServiceStatus.DEGRADED
        return ServiceStatus.ACTIVE

    @property
    def problems(self) -> list[str]:
        items = []
        if self.passed is False:
            items.append("autoteste SMART REPROVADO")
        if self.critical_warning:
            items.append(f"alerta crítico NVMe 0x{self.critical_warning:02x}")
        for value, label in ((self.reallocated, "setores realocados"), (self.pending, "setores pendentes"),
                             (self.uncorrectable, "setores irrecuperáveis"), (self.media_errors, "erros de mídia")):
            if value:
                items.append(f"{value} {label}")
        if (self.percentage_used or 0) >= 90:
            items.append(f"desgaste {self.percentage_used}%")
        return items


@dataclass(frozen=True, slots=True)
class SmartReport:
    state: RuntimeState
    disks: tuple[SmartDisk, ...] = ()
    message: str = ""


@dataclass(frozen=True, slots=True)
class EndpointResult:
    """Verificação feita a partir do Windows (HTTP, certificado TLS ou porta TCP)."""

    target: str
    scheme: str
    status: ServiceStatus
    latency_ms: float | None = None
    http_status: int | None = None
    cert_expires: float | None = None
    cert_days_left: float | None = None
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_valid: bool | None = None
    detail: str = ""
    checked_at: float = field(default_factory=time.time)


class CheckLevel(StrEnum):
    OK = "ok"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {"ok": "OK", "info": "Info", "warn": "Atenção", "fail": "Crítico", "unknown": "Indeterminado"}[
            self.value]

    @property
    def status(self) -> ServiceStatus:
        """Reaproveita as cores/ícones de status da interface."""
        return {"ok": ServiceStatus.ACTIVE, "info": ServiceStatus.STOPPED, "warn": ServiceStatus.DEGRADED,
                "fail": ServiceStatus.FAILED, "unknown": ServiceStatus.UNKNOWN}[self.value]


@dataclass(frozen=True, slots=True)
class SecurityCheck:
    id: str
    category: str
    title: str
    level: CheckLevel
    detail: str
    recommendation: str = ""


@dataclass(frozen=True, slots=True)
class Fail2banJail:
    name: str
    currently_failed: int | None = None
    total_failed: int | None = None
    currently_banned: int | None = None
    total_banned: int | None = None
    banned_ips: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LoginEvent:
    timestamp: float
    user: str
    source: str
    method: str


@dataclass(frozen=True, slots=True)
class FailedLoginSource:
    source: str
    count: int
    last_seen: float
    last_user: str = ""


@dataclass(frozen=True, slots=True)
class SshLoginReport:
    accepted: tuple[LoginEvent, ...] = ()
    failed_sources: tuple[FailedLoginSource, ...] = ()
    failed_total: int = 0
    #: False = usuário sem acesso ao journal completo (contagens parciais).
    complete: bool = True


@dataclass(frozen=True, slots=True)
class SudoEvent:
    timestamp: float
    user: str
    command: str
    #: "ok", "negado" (fora do sudoers) ou "senha incorreta".
    outcome: str = "ok"
    run_as: str = ""
    tty: str = ""


@dataclass(frozen=True, slots=True)
class SessionInfo:
    user: str
    tty: str
    source: str
    since: str


@dataclass(frozen=True, slots=True)
class AuthorizedKey:
    key_type: str
    bits: int | None
    fingerprint: str
    comment: str
    restricted: bool


@dataclass(frozen=True, slots=True)
class SecurityRaw:
    """Dados brutos da auditoria (interpretados por :mod:`core.security`)."""

    sshd: dict[str, str] = field(default_factory=dict)
    #: "sshd -T" (configuração efetiva) ou "arquivos" (sshd_config lido sem root).
    sshd_source: str = ""
    #: Estado (``systemctl is-active``) de firewall, fail2ban, auditd, sshd...
    services: dict[str, str] = field(default_factory=dict)
    binaries: frozenset[str] = frozenset()
    #: IP do próprio monitor visto pelo servidor ($SSH_CLIENT): nunca pode ser banido.
    ssh_client: str = ""
    ufw_enabled: bool | None = None
    ufw_status: str = ""
    iptables_rules: int | None = None
    iptables_input_policy: str = ""
    nft_rules: int | None = None
    uid0_users: tuple[str, ...] = ()
    login_users: tuple[str, ...] = ()
    sudo_users: tuple[str, ...] = ()
    sysctl: dict[str, str] = field(default_factory=dict)
    apparmor: bool | None = None
    selinux: str = ""
    #: Valor de APT::Periodic::Unattended-Upgrade (None = não é Debian/Ubuntu).
    auto_updates: str | None = None
    tmp_mode: str = ""
    sessions: tuple[SessionInfo, ...] = ()
    authorized_keys: tuple[AuthorizedKey, ...] = ()
    fail2ban: tuple[Fail2banJail, ...] = ()
    #: None = sem dados (fail2ban ausente ou sem sudo), "" = OK, texto = erro.
    fail2ban_error: str | None = None


@dataclass(frozen=True)
class SecurityReport:
    checks: tuple[SecurityCheck, ...]
    score: int | None
    raw: SecurityRaw
    logins: SshLoginReport | None = None
    sudo: tuple[SudoEvent, ...] = ()

    def count(self, level: CheckLevel) -> int:
        return sum(1 for check in self.checks if check.level is level)

    def check(self, check_id: str) -> SecurityCheck | None:
        return next((c for c in self.checks if c.id == check_id), None)


@dataclass(frozen=True, slots=True)
class Stack:
    """Projeto do Docker/Podman Compose ou namespace do Kubernetes."""

    name: str
    kind: ServiceKind
    members: tuple[ServiceInfo, ...]
    working_dir: str = ""
    config_files: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"

    @property
    def running(self) -> int:
        return sum(1 for m in self.members if m.status is ServiceStatus.ACTIVE)

    @property
    def status(self) -> ServiceStatus:
        statuses = {m.status for m in self.members}
        if statuses == {ServiceStatus.ACTIVE}:
            return ServiceStatus.ACTIVE
        if ServiceStatus.ACTIVE not in statuses and ServiceStatus.FAILED in statuses:
            return ServiceStatus.FAILED
        if ServiceStatus.ACTIVE in statuses:
            has_problem = statuses & {ServiceStatus.FAILED, ServiceStatus.STOPPED, ServiceStatus.UNKNOWN}
            return ServiceStatus.DEGRADED if has_problem else ServiceStatus.ACTIVATING
        if ServiceStatus.ACTIVATING in statuses:
            return ServiceStatus.ACTIVATING
        return ServiceStatus.STOPPED

    @property
    def cpu_percent(self) -> float | None:
        return _sum_optional(m.cpu_percent for m in self.members)

    @property
    def mem_bytes(self) -> int | None:
        total = _sum_optional(m.mem_bytes for m in self.members)
        return None if total is None else int(total)

    @property
    def critical(self) -> bool:
        return any(m.critical for m in self.members)


def build_stacks(services: tuple[ServiceInfo, ...] | list[ServiceInfo]) -> list[Stack]:
    """Agrupa contêineres por projeto do Compose e pods por namespace."""
    groups: dict[tuple[ServiceKind, str], list[ServiceInfo]] = defaultdict(list)
    for service in services:
        if service.group and (service.kind.is_container or service.kind is ServiceKind.KUBERNETES):
            groups[(service.kind, service.group)].append(service)
    stacks = []
    for (kind, name), members in groups.items():
        first = members[0]
        stacks.append(Stack(
            name=name,
            kind=kind,
            members=tuple(sorted(members, key=lambda m: m.name)),
            working_dir=first.meta_value("working_dir"),
            config_files=first.meta_value("config_files"),
        ))
    return sorted(stacks, key=lambda s: (s.status.severity, s.name))


@dataclass(frozen=True)
class HostSnapshot:
    server: str
    services: tuple[ServiceInfo, ...]
    metrics: HostMetrics | None
    runtimes: tuple[RuntimeResult, ...] = ()
    processes: tuple[ProcessInfo, ...] = ()
    network: NetworkInfo | None = None
    timers: tuple[TimerInfo, ...] = ()
    cron: tuple[CronEntry, ...] = ()
    events: tuple[JournalEntry, ...] = ()
    system: SystemInfo | None = None
    updates: UpdatesInfo | None = None
    vps: VpsInfo | None = None
    smart: SmartReport | None = None
    security: SecurityReport | None = None
    endpoints: tuple[EndpointResult, ...] = ()
    #: Latência medida a partir do Windows (ICMP) ou pela abertura de canais SSH.
    latency_ms: float | None = None
    latency_method: str = ""
    warnings: tuple[str, ...] = ()
    #: Limites de recurso atualmente excedidos (ex.: "CPU 97%").
    resource_alerts: tuple[str, ...] = ()
    collected_at: float = field(default_factory=time.time)
    duration: float = 0.0
    #: Momento da última coleta de detalhes (processos, portas) e de inventário.
    detail_at: float | None = None
    inventory_at: float | None = None
    security_at: float | None = None
    endpoints_at: float | None = None

    def counts(self) -> Counter[ServiceStatus]:
        return Counter(service.status for service in self.services)

    def count_kind(self, kind: ServiceKind) -> int:
        return sum(1 for service in self.services if service.kind is kind)

    def failed_critical(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.critical and s.status is ServiceStatus.FAILED]

    def runtime(self, kind: ServiceKind) -> RuntimeResult | None:
        for runtime in self.runtimes:
            if runtime.kind is kind:
                return runtime
        return None

    def stacks(self) -> list[Stack]:
        return build_stacks(self.services)

    def failing_endpoints(self) -> list[EndpointResult]:
        return [e for e in self.endpoints if e.status in (ServiceStatus.FAILED, ServiceStatus.DEGRADED)]


class ConnectionState(StrEnum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    STOPPED = "stopped"

    @property
    def label(self) -> str:
        return {
            "connecting": "Conectando…",
            "connected": "Conectado",
            "reconnecting": "Desconectado",
            "stopped": "Parado",
        }[self.value]


class HealthLevel(IntEnum):
    """Saúde agregada (servidor ou aplicação). Valor maior = pior."""

    OK = 0
    UNKNOWN = 1
    WARNING = 2
    CRITICAL = 3


class AlertKind(StrEnum):
    FAILED = "failed"
    STOPPED = "stopped"
    RECOVERED = "recovered"


class ActionOutcome(StrEnum):
    OK = "ok"
    PENDING = "pending"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ActionResult:
    outcome: ActionOutcome
    message: str


# ---------------------------------------------------------------------------
# Eventos emitidos pelo monitor (consumidos pela UI via queue.Queue)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, kw_only=True)
class MonitorEvent:
    server: str
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, kw_only=True)
class ConnectionEvent(MonitorEvent):
    state: ConnectionState
    message: str = ""
    retry_in: float | None = None
    attempt: int = 0


@dataclass(frozen=True, kw_only=True)
class SnapshotEvent(MonitorEvent):
    snapshot: HostSnapshot


@dataclass(frozen=True, kw_only=True)
class ServiceAlertEvent(MonitorEvent):
    service: ServiceInfo
    alert: AlertKind
    previous: ServiceStatus | None = None


@dataclass(frozen=True, kw_only=True)
class ThresholdAlertEvent(MonitorEvent):
    """Métrica do host acima (ou de volta abaixo) do limite configurado."""

    metric: str
    label: str
    value: float
    threshold: float
    recovered: bool = False
    unit: str = "%"


@dataclass(frozen=True, kw_only=True)
class HostAlertEvent(MonitorEvent):
    """Alertas diversos: endpoints, SMART, segurança, franquia de tráfego, logins."""

    category: str
    key: str
    title: str
    message: str
    #: "critical", "warning" ou "info".
    level: str = "warning"
    recovered: bool = False


@dataclass(frozen=True, kw_only=True)
class ActionResultEvent(MonitorEvent):
    target: str
    action_label: str
    result: ActionResult
    #: Chave da carga/stack/processo afetado (para liberar os botões na UI).
    busy_key: str = ""
