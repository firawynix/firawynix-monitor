"""Modelos imutáveis compartilhados entre o núcleo e a interface."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class ServiceKind(StrEnum):
    SYSTEMD = "systemd"
    DOCKER = "docker"

    @property
    def label(self) -> str:
        return "systemd" if self is ServiceKind.SYSTEMD else "Docker"


class ServiceStatus(StrEnum):
    ACTIVE = "active"
    ACTIVATING = "activating"
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
    ServiceStatus.STOPPED: "Parado",
    ServiceStatus.FAILED: "Falha",
    ServiceStatus.UNKNOWN: "Desconhecido",
}
_STATUS_SEVERITY = {
    ServiceStatus.FAILED: 0,
    ServiceStatus.ACTIVATING: 1,
    ServiceStatus.UNKNOWN: 2,
    ServiceStatus.STOPPED: 3,
    ServiceStatus.ACTIVE: 4,
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
    kind: ServiceKind
    name: str
    description: str
    status: ServiceStatus
    #: systemd: ACTIVE (active/inactive/failed...) · Docker: State (running/exited...)
    active_state: str
    #: systemd: SUB (running/dead/exited...) · Docker: Status ("Up 2 hours")
    sub_state: str
    load_state: str = ""
    critical: bool = False

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"

    @property
    def state_text(self) -> str:
        if self.kind is ServiceKind.DOCKER:
            return self.sub_state or self.active_state
        return f"{self.active_state}/{self.sub_state}" if self.sub_state else self.active_state


@dataclass(frozen=True, slots=True)
class DiskUsage:
    filesystem: str
    mount: str
    size_kb: int
    used_kb: int
    avail_kb: int
    use_percent: float


@dataclass(frozen=True, slots=True)
class HostMetrics:
    uptime_seconds: float | None = None
    load_avg: tuple[float, float, float] | None = None
    cpu_count: int | None = None
    cpu_percent: float | None = None
    mem_total_mb: int | None = None
    mem_used_mb: int | None = None
    mem_available_mb: int | None = None
    swap_total_mb: int | None = None
    swap_used_mb: int | None = None
    disks: tuple[DiskUsage, ...] = ()

    @property
    def mem_percent(self) -> float | None:
        if not self.mem_total_mb or self.mem_used_mb is None:
            return None
        return 100.0 * self.mem_used_mb / self.mem_total_mb

    @property
    def root_disk(self) -> DiskUsage | None:
        for disk in self.disks:
            if disk.mount == "/":
                return disk
        return self.disks[0] if self.disks else None

    @property
    def fullest_disk(self) -> DiskUsage | None:
        return max(self.disks, key=lambda d: d.use_percent, default=None)


class DockerState(StrEnum):
    OK = "ok"
    DISABLED = "disabled"
    NOT_INSTALLED = "not_installed"
    DAEMON_DOWN = "daemon_down"
    PERMISSION = "permission"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class DockerResult:
    state: DockerState
    containers: tuple[ServiceInfo, ...] = ()
    message: str = ""


@dataclass(frozen=True)
class HostSnapshot:
    server: str
    services: tuple[ServiceInfo, ...]
    metrics: HostMetrics | None
    docker: DockerResult
    warnings: tuple[str, ...] = ()
    collected_at: float = field(default_factory=time.time)
    duration: float = 0.0

    def counts(self) -> Counter[ServiceStatus]:
        return Counter(service.status for service in self.services)

    def failed_critical(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.critical and s.status is ServiceStatus.FAILED]


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
class ActionResultEvent(MonitorEvent):
    service: ServiceInfo
    action: ServiceAction
    result: ActionResult
