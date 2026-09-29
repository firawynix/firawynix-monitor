"""Loop de monitoramento (uma thread por servidor) e emissão de eventos.

Fluxo de dados::

    ServerMonitor (thread) --eventos--> queue.Queue --after()--> Dashboard (thread da UI)

Cada ciclo executa, em paralelo (canais SSH distintos na mesma conexão), os
coletores que estiverem "vencidos":

* rápido (todo ciclo): unidades systemd, contêineres, pods, VMs, LXD, métricas
  e latência (ICMP pela API do Windows ou tempo de abertura de canal SSH);
* detalhes (``detail_interval_seconds``): processos, portas, stats de contêineres;
* inventário (``inventory_interval_seconds``): sistema, VPS, timers, cron, eventos;
* segurança (``security_interval_seconds``): auditoria, fail2ban, logins, sudo, SMART;
* atualizações (``updates_interval_seconds``): pacotes pendentes;
* endpoints (``endpoint_interval_seconds``): HTTP/TLS/TCP a partir do Windows, em
  segundo plano (um site lento nunca atrasa a coleta SSH).

Cada comando continua limitado a 5 s. A interface nunca chama SSH diretamente:
ações e logs rodam em um ``ThreadPoolExecutor`` e devolvem ``Future``/eventos.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
import queue
import random
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Protocol

from config.settings import AppSettings, Config, NotificationSettings, ServerConfig, ThresholdSettings, user_data_dir
from core import containers as engines
from core import security as security_rules
from core import winapi
from core import changes
from core.alerts import HostAlertPolicy
from core.backups import BackupStore, ChangeRecord
from core.change_runner import ChangeRequest, ChangeRunner, new_change_id
from core.changes import Assessment, ChangeAction, ContainerSpec, InspectInfo
from core.endpoints import check_endpoint, parse_endpoint
from core.history import HistoryStore
from core.models import (
    ActionOutcome,
    ActionResult,
    ActionResultEvent,
    AlertKind,
    ContainerImage,
    ConnectionEvent,
    ConnectionState,
    CronEntry,
    EndpointResult,
    Fail2banJail,
    HostMetrics,
    HostSnapshot,
    ImageUpdate,
    JournalEntry,
    MonitorEvent,
    NetworkInfo,
    ProcessInfo,
    RuntimeResult,
    RuntimeState,
    SecurityRaw,
    ServiceAction,
    ServiceAlertEvent,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SmartReport,
    SnapshotEvent,
    SshLoginReport,
    Stack,
    SudoEvent,
    SystemInfo,
    ThresholdAlertEvent,
    TimerInfo,
    UpdatesInfo,
    VpsInfo,
)
from core.ssh_client import (
    SSHAuthError,
    SSHClient,
    SSHCommandError,
    SSHCommandTimeout,
    SSHConnectionError,
    SSHHostKeyError,
)

log = logging.getLogger(__name__)

#: Após N ciclos seguidos com timeout nos coletores rápidos a conexão é refeita.
MAX_CONSECUTIVE_TIMEOUTS = 3
#: Quantos ciclos esperar antes de testar de novo um runtime ausente (modo auto).
RUNTIME_RECHECK_POLLS = 12
#: Janela em que uma parada solicitada pelo usuário não gera alerta.
EXPECTED_STOP_WINDOW = 90.0
#: Histerese dos alertas de recurso: só "normaliza" abaixo de limite − 5 pontos.
THRESHOLD_HYSTERESIS = 5.0
#: Coletores em paralelo por servidor (sshd permite 10 sessões por conexão).
COLLECTOR_WORKERS = 4
#: Endpoints verificados em paralelo (a partir do Windows).
ENDPOINT_WORKERS = 6
#: No modo "auto", após N pings ICMP sem resposta usa só a latência do SSH.
ICMP_MAX_FAILURES = 3
ICMP_RETRY_POLLS = 120

_FAST_TASKS = {"units", "metrics"}


class HostClient(Protocol):
    """Interface usada pelo monitor (implementada por SSHClient e DemoClient)."""

    @property
    def connected(self) -> bool: ...
    def connect(self) -> None: ...
    def close(self) -> None: ...
    def list_units(self) -> list[ServiceInfo]: ...
    def service_resources(self) -> dict[str, tuple[float | None, int | None]]: ...
    def list_containers(self, runtime: ServiceKind) -> RuntimeResult: ...
    def container_stats(self, runtime: ServiceKind) -> dict[str, tuple[float | None, int | None]]: ...
    def list_pods(self) -> RuntimeResult: ...
    def list_vms(self) -> RuntimeResult: ...
    def list_lxd(self) -> RuntimeResult: ...
    def host_metrics(self) -> HostMetrics: ...
    def processes(self) -> list[ProcessInfo]: ...
    def network(self) -> NetworkInfo: ...
    def timers(self) -> list[TimerInfo]: ...
    def cron(self) -> list[CronEntry]: ...
    def journal_events(self, priority: str, limit: int, since_hours: int) -> list[JournalEntry]: ...
    def system_info(self) -> tuple[SystemInfo, dict[str, float]]: ...
    def updates(self) -> UpdatesInfo | None: ...
    def vps_info(self) -> VpsInfo: ...
    def smart(self) -> SmartReport: ...
    def security_raw(self) -> SecurityRaw: ...
    def fail2ban_status(self) -> tuple[tuple[Fail2banJail, ...], str]: ...
    def ssh_logins(self) -> SshLoginReport: ...
    def sudo_log(self) -> tuple[SudoEvent, ...]: ...
    def take_rtt(self) -> float | None: ...
    def fail2ban_action(self, jail: str, ip: str, ban: bool) -> ActionResult: ...
    def discover_engines(self) -> engines.Discovery: ...
    def engine_inventory(self, engine_id: str) -> engines.EngineData: ...
    def buildah_inventory(self) -> tuple: ...
    def container_op(self, service: ServiceInfo, op: str) -> ActionResult: ...
    def inspect_container(self, service: ServiceInfo) -> str: ...
    def image_op(self, engine_id: str, image: ContainerImage | None, op: str) -> ActionResult: ...
    def inspect_image(self, engine_id: str, image: ContainerImage) -> str: ...
    def volume_op(self, engine_id: str, name: str, op: str) -> ActionResult: ...
    def inspect_volume(self, engine_id: str, name: str) -> str: ...
    def check_image_update(self, image: ContainerImage) -> ImageUpdate: ...
    def console_command(self, service: ServiceInfo) -> str: ...
    def change_backend(self) -> Any: ...
    def service_action(self, service: ServiceInfo, action: ServiceAction) -> ActionResult: ...
    def stack_action(self, stack: Stack, action: ServiceAction) -> ActionResult: ...
    def kill_process(self, pid: int, force: bool) -> ActionResult: ...
    def logs_command(self, service: ServiceInfo, lines: int) -> str: ...
    def service_logs(self, service: ServiceInfo, lines: int) -> str: ...
    def stack_logs(self, stack: Stack, lines: int) -> str: ...


ClientFactory = Callable[[ServerConfig, AppSettings], HostClient]


def default_client_factory(server: ServerConfig, settings: AppSettings) -> HostClient:
    return SSHClient(
        server,
        command_timeout=settings.command_timeout_seconds,
        connect_timeout=settings.connect_timeout_seconds,
        known_hosts_file=settings.known_hosts_file or user_data_dir() / "known_hosts",
    )


# ---------------------------------------------------------------------------
# Backoff exponencial
# ---------------------------------------------------------------------------

class ExponentialBackoff:
    """1s, 2s, 4s, 8s ... até ``maximum``, com jitter para evitar rajadas sincronizadas."""

    def __init__(self, base: float = 1.0, factor: float = 2.0, maximum: float = 60.0,
                 jitter: float = 0.2, rng: Callable[[], float] = random.random) -> None:
        self.base = base
        self.factor = factor
        self.maximum = maximum
        self.jitter = jitter
        self._rng = rng
        self.attempts = 0

    def next_delay(self) -> float:
        delay = min(self.maximum, self.base * (self.factor ** self.attempts))
        self.attempts += 1
        spread = delay * self.jitter
        return max(0.0, delay + (self._rng() * 2 - 1) * spread)

    def reset(self) -> None:
        self.attempts = 0


# ---------------------------------------------------------------------------
# Regras de criticidade e alertas
# ---------------------------------------------------------------------------

_PREFIX_ALIASES = {"kubernetes": ServiceKind.KUBERNETES.value, "libvirt": ServiceKind.LIBVIRT.value,
                   "incus": ServiceKind.LXD.value, "lxc": ServiceKind.LXD.value,
                   "containerd": ServiceKind.NERDCTL.value, "crio": ServiceKind.CRI.value,
                   "cri-o": ServiceKind.CRI.value}
_KIND_PREFIXES = {kind.value for kind in ServiceKind} | set(_PREFIX_ALIASES)


def matches_patterns(service: ServiceInfo, patterns: Iterable[str]) -> bool:
    """Padrões glob (``nginx*``), opcionalmente prefixados pelo tipo
    (``docker:web-*``, ``podman:*``, ``k8s:prod/*``, ``vm:db*``, ``lxd:web*``).

    Para unidades systemd o sufixo ``.service`` é opcional: ``nginx`` casa com
    ``nginx.service``.
    """
    names = [service.name.lower()]
    if service.kind is ServiceKind.SYSTEMD and names[0].endswith(".service"):
        names.append(names[0][: -len(".service")])
    for raw in patterns:
        pattern = raw.strip().lower()
        if ":" in pattern:
            prefix, rest = pattern.split(":", 1)
            if prefix in _KIND_PREFIXES:
                if _PREFIX_ALIASES.get(prefix, prefix) != service.kind.value:
                    continue
                pattern = rest
        if any(fnmatch.fnmatchcase(name, pattern) for name in names):
            return True
    return False


class AlertPolicy:
    """Decide quais mudanças de estado de serviços geram notificação."""

    def __init__(self, notifications: NotificationSettings) -> None:
        self.notifications = notifications
        self._alerted_failed: set[str] = set()
        self._expected_stop: dict[str, float] = {}

    def expect_stop(self, service_key: str, window: float = EXPECTED_STOP_WINDOW) -> None:
        self._expected_stop[service_key] = time.monotonic() + window

    def evaluate(self, server: str, previous: Mapping[str, ServiceInfo] | None,
                 current: Sequence[ServiceInfo]) -> list[ServiceAlertEvent]:
        now = time.monotonic()
        self._expected_stop = {k: t for k, t in self._expected_stop.items() if t > now}
        alerts: list[ServiceAlertEvent] = []
        present: set[str] = set()
        for service in current:
            present.add(service.key)
            if not service.critical:
                self._alerted_failed.discard(service.key)
                continue
            old = previous.get(service.key) if previous is not None else None
            old_status = old.status if old is not None else None

            if service.status is ServiceStatus.FAILED:
                if service.key not in self._alerted_failed:
                    self._alerted_failed.add(service.key)
                    alerts.append(ServiceAlertEvent(server=server, service=service,
                                                    alert=AlertKind.FAILED, previous=old_status))
            elif service.status is ServiceStatus.ACTIVE and service.key in self._alerted_failed:
                self._alerted_failed.discard(service.key)
                if self.notifications.notify_on_recovery:
                    alerts.append(ServiceAlertEvent(server=server, service=service,
                                                    alert=AlertKind.RECOVERED, previous=old_status))
            elif service.status is ServiceStatus.STOPPED:
                self._alerted_failed.discard(service.key)
                if (self.notifications.alert_on_stop
                        and old_status in (ServiceStatus.ACTIVE, ServiceStatus.ACTIVATING)
                        and service.key not in self._expected_stop):
                    alerts.append(ServiceAlertEvent(server=server, service=service,
                                                    alert=AlertKind.STOPPED, previous=old_status))
        self._alerted_failed &= present
        return alerts


class ThresholdPolicy:
    """Alertas de CPU, memória e disco com persistência mínima e histerese."""

    def __init__(self, thresholds: ThresholdSettings) -> None:
        self.thresholds = thresholds
        self._streak: dict[str, int] = defaultdict(int)
        self._active: dict[str, str] = {}

    @property
    def active(self) -> tuple[str, ...]:
        return tuple(self._active.values())

    def evaluate(self, server: str, metrics: HostMetrics | None,
                 latency: float | None = None) -> list[ThresholdAlertEvent]:
        if metrics is None:
            return []
        t = self.thresholds
        checks: list[tuple[str, str, float | None, float, int, str]] = [
            ("cpu", "CPU", metrics.cpu_percent, t.cpu_percent, t.sustain_polls, "%"),
            ("mem", "Memória", metrics.mem_percent, t.mem_percent, t.sustain_polls, "%"),
            ("steal", "CPU steal", metrics.cpu_steal, t.steal_percent, t.sustain_polls, "%"),
            ("latency", "Latência", latency, t.latency_ms, t.sustain_polls, " ms"),
        ]
        # Disco não oscila como CPU: alerta na primeira leitura acima do limite.
        checks += [(f"disk:{d.mount}", f"Disco {d.mount}", d.use_percent, t.disk_percent, 1, "%")
                   for d in metrics.disks]
        events = []
        seen = set()
        for metric, label, value, limit, sustain, unit in checks:
            seen.add(metric)
            if not limit or value is None:
                continue
            hysteresis = THRESHOLD_HYSTERESIS if unit == "%" else limit * 0.1
            if value >= limit:
                self._streak[metric] += 1
                if self._streak[metric] >= sustain and metric not in self._active:
                    events.append(ThresholdAlertEvent(server=server, metric=metric, label=label,
                                                      value=value, threshold=limit, unit=unit))
                if metric in self._active or self._streak[metric] >= sustain:
                    self._active[metric] = f"{label} {value:.0f}{unit}"
            else:
                self._streak[metric] = 0
                if metric in self._active and value < limit - hysteresis:
                    del self._active[metric]
                    events.append(ThresholdAlertEvent(server=server, metric=metric, label=label,
                                                      value=value, threshold=limit, recovered=True, unit=unit))
                elif metric in self._active:
                    self._active[metric] = f"{label} {value:.0f}{unit}"
        for gone in set(self._active) - seen:  # disco desmontado
            del self._active[gone]
        if latency is None:
            self._streak["latency"] = 0
        return events


# ---------------------------------------------------------------------------
# Monitor de um servidor
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Latest:
    """Últimos valores de cada coletor (as camadas lentas não rodam todo ciclo)."""

    units: list[ServiceInfo] = dataclasses.field(default_factory=list)
    resources: dict[str, tuple[float | None, int | None]] = dataclasses.field(default_factory=dict)
    runtimes: dict[ServiceKind, RuntimeResult] = dataclasses.field(default_factory=dict)
    stats: dict[ServiceKind, dict[str, tuple[float | None, int | None]]] = dataclasses.field(default_factory=dict)
    metrics: HostMetrics | None = None
    processes: list[ProcessInfo] = dataclasses.field(default_factory=list)
    network: NetworkInfo | None = None
    timers: list[TimerInfo] = dataclasses.field(default_factory=list)
    cron: list[CronEntry] = dataclasses.field(default_factory=list)
    events: list[JournalEntry] = dataclasses.field(default_factory=list)
    system: SystemInfo | None = None
    inodes: dict[str, float] = dataclasses.field(default_factory=dict)
    updates: UpdatesInfo | None = None
    vps: VpsInfo | None = None
    smart: SmartReport | None = None
    security_raw: SecurityRaw | None = None
    fail2ban: tuple[tuple[Fail2banJail, ...], str] | None = None
    logins: SshLoginReport | None = None
    sudo: tuple[SudoEvent, ...] = ()
    endpoints: list[EndpointResult] = dataclasses.field(default_factory=list)
    discovery: engines.Discovery | None = None
    discovered_at: float | None = None
    engine_data: dict[str, engines.EngineData] = dataclasses.field(default_factory=dict)
    buildah: tuple | None = None
    containers_at: float | None = None
    latency_ms: float | None = None
    latency_method: str = ""
    detail_at: float | None = None
    inventory_at: float | None = None
    security_at: float | None = None
    endpoints_at: float | None = None


_RUNTIME_KINDS = (ServiceKind.DOCKER, ServiceKind.PODMAN, ServiceKind.NERDCTL, ServiceKind.CRI,
                  ServiceKind.KUBERNETES, ServiceKind.LIBVIRT, ServiceKind.LXD)
_STATS_KINDS = (ServiceKind.DOCKER, ServiceKind.PODMAN, ServiceKind.NERDCTL)
_INVENTORY_ENGINES = ("docker", "podman", "nerdctl", "cri")


class ServerMonitor:
    """Coleta periódica de um servidor em thread própria, com reconexão automática."""

    def __init__(self, server: ServerConfig, settings: AppSettings,
                 emit: Callable[[MonitorEvent], None],
                 client_factory: ClientFactory = default_client_factory,
                 history: HistoryStore | None = None) -> None:
        self.server = server
        self.settings = settings
        self._emit = emit
        self.client: HostClient = client_factory(server, settings)
        self.history = history
        self.interval = server.poll_interval_seconds or settings.poll_interval_seconds
        self.policy = AlertPolicy(settings.notifications)
        self.thresholds = ThresholdPolicy(settings.thresholds)
        self.host_alerts = HostAlertPolicy(server, settings.notifications)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=COLLECTOR_WORKERS,
                                        thread_name_prefix=f"collect-{server.name}")
        # Endpoints e ICMP não usam SSH: pool próprio para não disputar canais.
        self._probe_pool = ThreadPoolExecutor(max_workers=ENDPOINT_WORKERS,
                                              thread_name_prefix=f"probe-{server.name}")
        self._endpoint_future: Future[list[EndpointResult]] | None = None
        self._endpoint_specs = [parse_endpoint(e) for e in server.endpoints]
        self._icmp_failures = 0
        self._icmp_skip = 0
        self._backoff = ExponentialBackoff(base=1.0, maximum=60.0)
        # Credenciais/host key erradas: espaçar bem as tentativas (evita fail2ban).
        self._auth_backoff = ExponentialBackoff(base=30.0, maximum=600.0)
        self._previous: dict[str, ServiceInfo] | None = None
        self._latest = _Latest()
        self._due = {"detail": 0.0, "inventory": 0.0, "updates": 0.0, "security": 0.0, "endpoints": 0.0,
                     "containers": 0.0}
        self._runtime_skip: dict[ServiceKind, int] = defaultdict(int)
        #: Motores que já funcionaram nesta sessão (se pararem, é problema real).
        self._seen_ok: set[ServiceKind] = set()
        self._consecutive_timeouts = 0
        self.state = ConnectionState.STOPPED
        #: Último snapshot emitido (base da análise de risco das mudanças).
        self.last_snapshot: HostSnapshot | None = None

    # -- ciclo de vida -----------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"monitor-{self.server.name}", daemon=True)
        self._thread.start()

    def signal_stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def stop(self, timeout: float = 2.0) -> None:
        self.signal_stop()
        if self._thread is not None:
            self._thread.join(timeout)
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._probe_pool.shutdown(wait=False, cancel_futures=True)
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            log.debug("Erro ao fechar cliente", exc_info=True)

    def refresh_now(self, full: bool = False) -> None:
        """Acorda o loop: coleta imediata (``full`` inclui processos, inventário etc.)."""
        if full:
            self._due = dict.fromkeys(self._due, 0.0)
        self._wake.set()

    def set_interval(self, seconds: float) -> None:
        self.interval = seconds
        self._wake.set()

    def set_engine_modes(self, modes: Mapping[str, str]) -> None:
        """Troca os motores de contêiner em uso (diálogo "Motores de contêiner")."""
        server = dataclasses.replace(self.server, **{k: v for k, v in modes.items() if k in engines.ENGINES})
        self.server = server
        if hasattr(self.client, "server"):
            self.client.server = server
        self._runtime_skip.clear()
        self.refresh_now(full=True)

    def reconnect(self) -> None:
        """Reconecta já (ex.: credencial atualizada), sem esperar o backoff de autenticação."""
        self._backoff.reset()
        self._auth_backoff.reset()
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            log.debug("Erro ao fechar cliente", exc_info=True)
        self._wake.set()

    def _sleep(self, seconds: float) -> None:
        self._wake.wait(timeout=max(0.0, seconds))
        self._wake.clear()

    def _set_state(self, state: ConnectionState, message: str = "", retry_in: float | None = None,
                   attempt: int = 0, needs: str = "", needs_target: str = "") -> None:
        self.state = state
        self._emit(ConnectionEvent(server=self.server.name, state=state, message=message,
                                   retry_in=retry_in, attempt=attempt, needs=needs, needs_target=needs_target))

    # -- loop principal ------------------------------------------------------

    def _run(self) -> None:
        self._set_state(ConnectionState.CONNECTING, f"Conectando a {self.server.address}…")
        while not self._stop.is_set():
            if not self.client.connected and not self._try_connect():
                continue
            started = time.monotonic()
            try:
                snapshot = self._collect()
            except SSHConnectionError as exc:
                log.warning("[%s] conexão perdida: %s", self.server.name, exc)
                self.client.close()
                self._set_state(ConnectionState.RECONNECTING, f"Conexão perdida: {exc}", retry_in=0.0)
                continue
            except Exception as exc:  # noqa: BLE001 - o loop nunca pode morrer
                log.exception("[%s] erro inesperado na coleta", self.server.name)
                snapshot = self._build_snapshot([], [f"Erro inesperado na coleta: {exc}"], 0.0)
            if self._stop.is_set():
                break
            self.last_snapshot = snapshot
            self._emit(SnapshotEvent(server=self.server.name, snapshot=snapshot))
            self._sleep(self.interval - (time.monotonic() - started))
        self.state = ConnectionState.STOPPED

    def _try_connect(self) -> bool:
        try:
            self.client.connect()
        except SSHConnectionError as exc:
            fatal = isinstance(exc, (SSHAuthError, SSHHostKeyError))
            backoff = self._auth_backoff if fatal else self._backoff
            attempt = backoff.attempts + 1
            delay = backoff.next_delay()
            log.warning("[%s] falha ao conectar (tentativa %d, nova em %.1fs): %s",
                        self.server.name, attempt, delay, exc)
            self._set_state(ConnectionState.RECONNECTING, str(exc), retry_in=delay, attempt=attempt,
                            needs=getattr(exc, "needs", ""), needs_target=getattr(exc, "target", ""))
            self._sleep(delay)
            return False
        except Exception as exc:  # noqa: BLE001
            log.exception("[%s] erro inesperado ao conectar", self.server.name)
            delay = self._backoff.next_delay()
            self._set_state(ConnectionState.RECONNECTING, f"Erro inesperado: {exc}", retry_in=delay)
            self._sleep(delay)
            return False
        self._backoff.reset()
        self._auth_backoff.reset()
        self._consecutive_timeouts = 0
        self._runtime_skip.clear()
        self._due = dict.fromkeys(self._due, 0.0)
        self._set_state(ConnectionState.CONNECTED, f"Conectado a {self.server.address}")
        return True

    # -- coleta ----------------------------------------------------------------

    def _plan(self, now: float) -> dict[str, Callable[[], Any]]:
        client, settings = self.client, self.settings
        tasks: dict[str, Callable[[], Any]] = {
            "units": client.list_units,
            "resources": client.service_resources,
            "metrics": client.host_metrics,
        }
        for kind in _RUNTIME_KINDS:
            engine_id = engines.ENGINE_OF_KIND.get(kind)
            if self._runtime_mode(kind) == "off":
                self._latest.runtimes[kind] = RuntimeResult(kind, RuntimeState.DISABLED)
            elif engine_id and not self._engine_allowed(engine_id):
                # Auto-detecção: o motor não existe neste host (nada é executado).
                self._latest.runtimes[kind] = RuntimeResult(kind, RuntimeState.NOT_INSTALLED, (),
                                                            f"{kind.label} não detectado neste host.")
            elif self._runtime_skip[kind] > 0:
                self._runtime_skip[kind] -= 1
            elif kind.is_container:
                tasks[kind.value] = (lambda k=kind: client.list_containers(k))
            elif kind is ServiceKind.KUBERNETES:
                tasks[kind.value] = client.list_pods
            elif kind is ServiceKind.LXD:
                tasks[kind.value] = client.list_lxd
            else:
                tasks[kind.value] = client.list_vms
        if self._icmp_enabled():
            tasks["icmp"] = (lambda: winapi.icmp_ping(self.server.host, 1000))

        detail_due = now >= self._due["detail"]
        if detail_due:
            self._due["detail"] = now + settings.detail_interval_seconds
            tasks["processes"] = client.processes
            tasks["network"] = client.network
        for kind in _STATS_KINDS:
            runtime = self._latest.runtimes.get(kind)
            # Stats também no ciclo seguinte à descoberta do runtime (sem esperar o intervalo).
            if runtime is not None and runtime.state is RuntimeState.OK and runtime.items \
                    and (detail_due or kind not in self._latest.stats):
                tasks[f"stats:{kind.value}"] = (lambda k=kind: client.container_stats(k))
        if now >= self._due["inventory"]:
            self._due["inventory"] = now + settings.inventory_interval_seconds
            events = settings.events
            tasks["discovery"] = client.discover_engines
            tasks["system"] = client.system_info
            tasks["vps"] = client.vps_info
            tasks["timers"] = client.timers
            tasks["cron"] = client.cron
            tasks["events"] = (lambda: client.journal_events(events.priority, events.limit, events.since_hours))
        # Imagens/volumes/redes: só depois que a auto-detecção disse quais motores existem.
        if now >= self._due["containers"] and self._latest.discovery is not None:
            self._due["containers"] = now + settings.inventory_interval_seconds
            for engine_id in _INVENTORY_ENGINES:
                runtime = self._latest.runtimes.get(engines.ENGINES[engine_id].kind)
                if runtime is not None and runtime.state is RuntimeState.OK and self._engine_allowed(engine_id):
                    tasks[f"inv:{engine_id}"] = (lambda e=engine_id: client.engine_inventory(e))
            if self._engine_ready("buildah"):
                tasks["buildah"] = client.buildah_inventory
        if now >= self._due["updates"]:
            self._due["updates"] = now + settings.updates_interval_seconds
            tasks["updates"] = client.updates
        if now >= self._due["security"]:
            self._due["security"] = now + settings.security_interval_seconds
            server = self.server
            if server.security:
                tasks["security"] = client.security_raw
                tasks["ssh_logins"] = client.ssh_logins
                tasks["sudo_log"] = client.sudo_log
                if server.security_sudo or server.username == "root":
                    tasks["fail2ban"] = client.fail2ban_status
            if server.smart != "off":
                tasks["smart"] = client.smart
        if self._endpoint_specs and now >= self._due["endpoints"] and (
                self._endpoint_future is None or self._endpoint_future.done()):
            self._due["endpoints"] = now + settings.endpoint_interval_seconds
            self._endpoint_future = self._probe_pool.submit(self._check_endpoints)
        return tasks

    def _icmp_enabled(self) -> bool:
        probe = self.settings.latency_probe
        if probe not in ("auto", "icmp") or not winapi.IS_WINDOWS:
            return False
        if probe == "auto" and self._icmp_failures >= ICMP_MAX_FAILURES:
            self._icmp_skip -= 1
            if self._icmp_skip > 0:
                return False
            self._icmp_failures = ICMP_MAX_FAILURES - 1  # uma nova tentativa
        return True

    def _check_endpoints(self) -> list[EndpointResult]:
        timeout = min(self.settings.command_timeout_seconds, 5.0)
        warning = self.settings.cert_warning_days
        # O modo demonstração fornece o próprio verificador (sem acessar a internet).
        check = getattr(self.client, "check_endpoint", check_endpoint)
        with ThreadPoolExecutor(max_workers=min(ENDPOINT_WORKERS, len(self._endpoint_specs)),
                                thread_name_prefix=f"endpoint-{self.server.name}") as pool:
            return list(pool.map(lambda spec: check(spec, timeout=timeout, cert_warning_days=warning),
                                 self._endpoint_specs))

    def _runtime_mode(self, kind: ServiceKind) -> str:
        engine_id = engines.ENGINE_OF_KIND.get(kind)
        if engine_id:
            return engines.engine_mode(self.server, engine_id)
        return {ServiceKind.KUBERNETES: self.server.kubernetes, ServiceKind.LIBVIRT: self.server.libvirt}[kind]

    def _runtime_warns(self, kind: ServiceKind, runtime: RuntimeResult) -> bool:
        """Aviso na faixa amarela: motor exigido ("on"), ou que funcionava e parou.

        Em "auto", um motor instalado mas nunca usado neste servidor (ex.: CLI do
        Docker que sobrou depois da troca para o Podman) não gera aviso: o estado
        aparece só na aba Contêineres.
        """
        if runtime.state is RuntimeState.OK:
            return False
        if self._runtime_mode(kind) == "on":
            return True
        if runtime.state is RuntimeState.DAEMON_DOWN:
            return kind in self._seen_ok
        return runtime.state is RuntimeState.PERMISSION and kind is not ServiceKind.CRI

    def _engine_allowed(self, engine_id: str) -> bool:
        """"on" sempre; "auto" enquanto não houver detecção ou se ela encontrou o binário."""
        mode = engines.engine_mode(self.server, engine_id)
        if mode == "off":
            return False
        discovery = self._latest.discovery
        return mode == "on" or discovery is None or discovery.has(engine_id)

    def _engine_ready(self, engine_id: str) -> bool:
        """Ferramentas sem daemon (Buildah): só com detecção positiva ou modo "on"."""
        mode = engines.engine_mode(self.server, engine_id)
        discovery = self._latest.discovery
        return mode == "on" or (mode == "auto" and discovery is not None and discovery.has(engine_id))

    def _collect(self) -> HostSnapshot:
        started = time.monotonic()
        tasks = self._plan(started)
        futures = {name: self._pool.submit(fn) for name, fn in tasks.items()}
        results: dict[str, Any] = {}
        warnings: list[str] = []
        timed_out: set[str] = set()
        connection_error: SSHConnectionError | None = None
        for name, future in futures.items():
            try:
                results[name] = future.result()
            except SSHConnectionError as exc:
                connection_error = connection_error or exc
            except SSHCommandTimeout:
                timed_out.add(name)
                warnings.append(f"Coleta '{_TASK_LABELS.get(name, name)}' não respondeu a tempo; "
                                "exibindo dados anteriores.")
            except SSHCommandError as exc:
                results[name] = exc
                warnings.append(str(exc))
            except Exception as exc:  # noqa: BLE001 - um coletor com defeito não derruba os outros
                log.exception("[%s] coletor %s falhou", self.server.name, name)
                warnings.append(f"Falha na coleta '{_TASK_LABELS.get(name, name)}': {exc}")
        if connection_error is not None:
            raise connection_error
        future = self._endpoint_future
        if future is not None and future.done() and "endpoints" not in results:
            self._endpoint_future = None
            try:
                results["endpoints"] = future.result()
            except Exception:  # noqa: BLE001
                log.exception("[%s] verificação de endpoints falhou", self.server.name)

        self._consecutive_timeouts = self._consecutive_timeouts + 1 if timed_out & _FAST_TASKS else 0
        if self._consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
            self._consecutive_timeouts = 0
            raise SSHConnectionError(f"{MAX_CONSECUTIVE_TIMEOUTS} coletas seguidas com timeout")

        self._apply(results)
        stale = "units" in timed_out
        return self._build_snapshot(timed_out, warnings, time.monotonic() - started, evaluate=not stale)

    def _apply(self, results: dict[str, Any]) -> None:
        latest = self._latest
        now = time.time()
        if isinstance(results.get("units"), list):
            latest.units = results["units"]
        elif isinstance(results.get("units"), SSHCommandError):
            latest.units = []
        if isinstance(results.get("resources"), dict):
            latest.resources = results["resources"]
        if isinstance(results.get("metrics"), HostMetrics):
            latest.metrics = results["metrics"]
        for kind in _RUNTIME_KINDS:
            runtime = results.get(kind.value)
            if isinstance(runtime, RuntimeResult):
                latest.runtimes[kind] = runtime
                if runtime.state is RuntimeState.OK:
                    self._seen_ok.add(kind)
                quiet = runtime.state in (RuntimeState.NOT_INSTALLED, RuntimeState.DAEMON_DOWN) or (
                    kind is ServiceKind.CRI and runtime.state is RuntimeState.PERMISSION)
                if quiet and self._runtime_mode(kind) == "auto":
                    self._runtime_skip[kind] = RUNTIME_RECHECK_POLLS
            stats = results.get(f"stats:{kind.value}")
            if isinstance(stats, dict):
                latest.stats[kind] = stats
        if "processes" in results or "network" in results:
            latest.detail_at = now
        if isinstance(results.get("processes"), list):
            latest.processes = results["processes"][: self.settings.process_limit]
        if isinstance(results.get("network"), NetworkInfo):
            latest.network = results["network"]
        if "system" in results:
            latest.inventory_at = now
        if isinstance(results.get("system"), tuple):
            latest.system, latest.inodes = results["system"]
        if isinstance(results.get("vps"), VpsInfo):
            latest.vps = results["vps"]
        if "security" in results or "smart" in results:
            latest.security_at = now
        for name, kind in (("smart", SmartReport), ("security", SecurityRaw), ("ssh_logins", SshLoginReport)):
            if isinstance(results.get(name), kind):
                setattr(latest, {"security": "security_raw", "ssh_logins": "logins"}.get(name, name), results[name])
        if isinstance(results.get("fail2ban"), tuple):
            latest.fail2ban = results["fail2ban"]
        if isinstance(results.get("sudo_log"), tuple):
            latest.sudo = results["sudo_log"]
        if isinstance(results.get("endpoints"), list):
            latest.endpoints = results["endpoints"]
            latest.endpoints_at = now
        if isinstance(results.get("discovery"), engines.Discovery):
            if latest.discovery is None:
                self._due["containers"] = 0.0  # inventário logo no ciclo seguinte
            latest.discovery, latest.discovered_at = results["discovery"], now
        for engine_id in _INVENTORY_ENGINES:
            data = results.get(f"inv:{engine_id}")
            if isinstance(data, engines.EngineData):
                latest.engine_data[engine_id] = data
                latest.containers_at = now
        if isinstance(results.get("buildah"), tuple):
            latest.buildah = results["buildah"]
        self._apply_latency(results)
        for name in ("timers", "cron", "events"):
            if isinstance(results.get(name), list):
                setattr(latest, name, results[name])
        if "updates" in results and not isinstance(results["updates"], Exception):
            latest.updates = results["updates"]

    def _apply_latency(self, results: dict[str, Any]) -> None:
        probe = self.settings.latency_probe
        rtt = self.client.take_rtt()
        latest = self._latest
        if probe == "off":
            latest.latency_ms, latest.latency_method = None, ""
            return
        if "icmp" in results:
            icmp = results["icmp"]
            if isinstance(icmp, float):
                self._icmp_failures = 0
                latest.latency_ms, latest.latency_method = icmp, "ICMP"
                return
            self._icmp_failures += 1
            if self._icmp_failures >= ICMP_MAX_FAILURES:
                self._icmp_skip = ICMP_RETRY_POLLS
                log.info("[%s] sem resposta ICMP; usando a latência medida pelo SSH", self.server.name)
            if probe == "icmp":
                latest.latency_ms, latest.latency_method = None, "ICMP sem resposta"
                return
        if rtt is not None and probe != "icmp":
            latest.latency_ms, latest.latency_method = rtt, "SSH"

    def _security_report(self, system: SystemInfo | None):
        latest = self._latest
        raw = latest.security_raw
        if raw is None:
            return None
        if latest.fail2ban is not None:
            jails, error = latest.fail2ban
            raw = dataclasses.replace(raw, fail2ban=jails, fail2ban_error=error)
        logins = latest.logins
        if logins is not None and system is not None and system.journal_access is False:
            logins = dataclasses.replace(logins, complete=False)
        return security_rules.evaluate(
            raw, ssh_user=self.server.username, logins=logins, sudo_events=latest.sudo, network=latest.network,
            updates=latest.updates, system=system, vps=latest.vps, monitor_uses_password=self.server.uses_password)

    def _build_snapshot(self, timed_out: Iterable[str], warnings: list[str], duration: float,
                        evaluate: bool = False) -> HostSnapshot:
        latest = self._latest
        units = [
            dataclasses.replace(u, cpu_percent=latest.resources[u.name][0], mem_bytes=latest.resources[u.name][1])
            if u.name in latest.resources else u
            for u in latest.units
        ]
        workloads: list[ServiceInfo] = list(units)
        runtimes = []
        for kind in _RUNTIME_KINDS:
            runtime = latest.runtimes.get(kind)
            if runtime is None:
                continue
            runtimes.append(runtime)
            stats = latest.stats.get(kind, {})
            workloads += [
                dataclasses.replace(item, cpu_percent=stats[item.name][0], mem_bytes=stats[item.name][1])
                if item.name in stats and item.status is ServiceStatus.ACTIVE else item
                for item in runtime.items
            ]
            if runtime.message and self._runtime_warns(kind, runtime):
                warnings.append(runtime.message)

        visible = [
            dataclasses.replace(s, critical=matches_patterns(s, self.server.critical_services))
            for s in workloads
            if not matches_patterns(s, self.server.exclude_services)
        ]

        metrics = latest.metrics
        if metrics is not None and latest.inodes:
            metrics = dataclasses.replace(metrics, disks=tuple(
                dataclasses.replace(d, inode_percent=latest.inodes.get(d.mount)) for d in metrics.disks))

        system = latest.system
        if system is not None and latest.logins is not None and system.journal_access is not False:
            system = dataclasses.replace(system, ssh_failed_logins_24h=latest.logins.failed_total)
        vps = latest.vps
        if vps is not None and system is not None and system.journal_access is False:
            vps = dataclasses.replace(vps, oom_kills_24h=None, oom_kills=())
        smart = latest.smart
        if smart is not None and smart.state is RuntimeState.NOT_INSTALLED and self.server.smart == "on":
            warnings.append(smart.message)
        security = self._security_report(system)
        containers = engines.build_inventory(
            self.server, latest.discovery, latest.runtimes,
            {e: d for e, d in latest.engine_data.items() if self._engine_allowed(e)},
            latest.buildah if self._engine_ready("buildah") else None, visible,
            latest.discovered_at, latest.containers_at)

        if evaluate:
            for alert in self.policy.evaluate(self.server.name, self._previous, visible):
                self._emit(alert)
            self._previous = {s.key: s for s in visible}
            for alert in self.thresholds.evaluate(self.server.name, latest.metrics, latest.latency_ms):
                self._emit(alert)
            host_alerts = self.host_alerts
            for alert in (host_alerts.endpoints(latest.endpoints) + host_alerts.smart(smart)
                          + host_alerts.security(security) + host_alerts.vps(vps)):
                self._emit(alert)
            if self.history is not None and latest.metrics is not None:
                failed = sum(1 for s in visible if s.status is ServiceStatus.FAILED)
                active = sum(1 for s in visible if s.status is ServiceStatus.ACTIVE)
                self.history.record(self.server.name, time.time(), latest.metrics, failed, active,
                                    latest.latency_ms)

        return HostSnapshot(
            server=self.server.name,
            services=tuple(visible),
            metrics=metrics,
            runtimes=tuple(runtimes),
            processes=tuple(latest.processes),
            network=latest.network,
            timers=tuple(latest.timers),
            cron=tuple(latest.cron),
            events=tuple(latest.events),
            system=system,
            updates=latest.updates,
            vps=vps,
            smart=smart,
            security=security,
            endpoints=tuple(latest.endpoints),
            containers=containers,
            latency_ms=latest.latency_ms,
            latency_method=latest.latency_method,
            warnings=tuple(dict.fromkeys(w for w in warnings if w)),
            resource_alerts=self.thresholds.active,
            duration=duration,
            detail_at=latest.detail_at,
            inventory_at=latest.inventory_at,
            security_at=latest.security_at,
            endpoints_at=latest.endpoints_at,
        )


_TASK_LABELS = {
    "units": "unidades systemd", "resources": "recursos por serviço", "metrics": "métricas",
    "docker": "Docker", "podman": "Podman", "k8s": "Kubernetes", "vm": "VMs", "lxd": "LXD/Incus",
    "processes": "processos", "network": "rede", "stats:docker": "stats do Docker", "stats:podman": "stats do Podman",
    "system": "sistema", "vps": "VPS", "timers": "timers", "cron": "cron", "events": "eventos do journal",
    "updates": "atualizações", "security": "auditoria de segurança", "ssh_logins": "logins SSH",
    "sudo_log": "log do sudo", "fail2ban": "fail2ban", "smart": "SMART", "icmp": "ping ICMP",
    "nerdctl": "containerd (nerdctl)", "cri": "CRI (crictl)", "discovery": "auto-detecção de motores",
    "inv:docker": "imagens/volumes do Docker", "inv:podman": "imagens/volumes do Podman",
    "inv:nerdctl": "imagens/volumes do containerd", "inv:cri": "imagens do CRI", "buildah": "Buildah",
    "stats:nerdctl": "stats do containerd",
}


# ---------------------------------------------------------------------------
# Gerenciador (fachada usada pela UI)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class PreparedChange:
    """Resultado da análise (mostrado ao usuário antes de confirmar)."""

    assessment: Assessment
    inspect: InspectInfo | None
    spec: ContainerSpec | None
    stop_timeout: int = 10
    record: ChangeRecord | None = None
    use_snapshot: bool = False


class MonitorManager:
    def __init__(self, config: Config, client_factory: ClientFactory = default_client_factory,
                 history: HistoryStore | None = None, max_workers: int = 4,
                 backups: BackupStore | None = None) -> None:
        self.config = config
        self.history = history
        #: Backups locais e histórico das mudanças seguras (None = só em memória).
        self.backups = backups or BackupStore(None)
        self.events: queue.Queue[MonitorEvent] = queue.Queue()
        self._client_factory = client_factory
        self.monitors: dict[str, ServerMonitor] = {
            server.name: ServerMonitor(server, config.settings, self.events.put, client_factory, history)
            for server in config.servers
        }
        self._started = False
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ssh-action")

    @property
    def server_names(self) -> list[str]:
        return list(self.monitors)

    def start(self) -> None:
        self._started = True
        for monitor in self.monitors.values():
            monitor.start()

    def apply_config(self, config: Config) -> dict[str, list[str]]:
        """Aplica servidores novos/alterados/removidos sem reiniciar o app (diálogo de conexões).

        Só recria o monitor do servidor cuja configuração mudou; os demais continuam como estão."""
        changes: dict[str, list[str]] = {"added": [], "updated": [], "removed": []}
        wanted = {server.name: server for server in config.servers}
        for name in [n for n in self.monitors if n not in wanted]:
            self.monitors.pop(name).stop(timeout=1.0)
            changes["removed"].append(name)
        rebuilt: dict[str, ServerMonitor] = {}
        for name, server in wanted.items():
            current = self.monitors.get(name)
            if current is not None and current.server == server:
                rebuilt[name] = current
                continue
            if current is not None:
                current.stop(timeout=1.0)
                changes["updated"].append(name)
            else:
                changes["added"].append(name)
            monitor = ServerMonitor(server, config.settings, self.events.put, self._client_factory, self.history)
            rebuilt[name] = monitor
            if self._started:
                monitor.start()
        self.monitors = rebuilt
        self.config = config
        return changes

    def stop(self) -> None:
        for monitor in self.monitors.values():
            monitor.signal_stop()
        for monitor in self.monitors.values():
            monitor.stop(timeout=1.0)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def refresh(self, server: str | None = None, full: bool = False) -> None:
        targets = [self.monitors[server]] if server else self.monitors.values()
        for monitor in targets:
            monitor.refresh_now(full=full)

    def set_poll_interval(self, seconds: float) -> None:
        for monitor in self.monitors.values():
            monitor.set_interval(seconds)

    def reconnect(self, server: str) -> None:
        self.monitors[server].reconnect()

    def is_connected(self, server: str) -> bool:
        return self.monitors[server].client.connected

    # -- ações -------------------------------------------------------------

    def _submit_action(self, server: str, target: str, label: str, busy_key: str,
                       call: Callable[[HostClient], ActionResult]) -> Future[ActionResult]:
        monitor = self.monitors[server]

        def task() -> ActionResult:
            try:
                if not monitor.client.connected:
                    raise SSHConnectionError("servidor desconectado")
                result = call(monitor.client)
            except (SSHConnectionError, SSHCommandError, ValueError) as exc:
                result = ActionResult(ActionOutcome.ERROR, f"Não foi possível executar '{label}' em {target}: {exc}")
            except Exception as exc:  # noqa: BLE001
                log.exception("[%s] erro inesperado na ação %s", server, label)
                result = ActionResult(ActionOutcome.ERROR, f"Erro inesperado: {exc}")
            log.info("[%s] ação '%s' em %s: %s — %s", server, label, target, result.outcome.value, result.message)
            self.events.put(ActionResultEvent(server=server, target=target, action_label=label,
                                              result=result, busy_key=busy_key))
            monitor.refresh_now(full=True)
            return result

        return self._executor.submit(task)

    def run_action(self, server: str, service: ServiceInfo, action: ServiceAction) -> Future[ActionResult]:
        monitor = self.monitors[server]
        if action is ServiceAction.STOP:
            monitor.policy.expect_stop(service.key)
        return self._submit_action(server, service.name, action.label, service.key,
                                   lambda client: client.service_action(service, action))

    def run_stack_action(self, server: str, stack: Stack, action: ServiceAction) -> Future[ActionResult]:
        monitor = self.monitors[server]
        if action is ServiceAction.STOP:
            for member in stack.members:
                monitor.policy.expect_stop(member.key)
        return self._submit_action(server, f"stack {stack.name}", action.label, stack.key,
                                   lambda client: client.stack_action(stack, action))

    def kill_process(self, server: str, pid: int, force: bool) -> Future[ActionResult]:
        label = "Forçar encerramento" if force else "Encerrar"
        return self._submit_action(server, f"PID {pid}", label, f"pid:{pid}",
                                   lambda client: client.kill_process(pid, force))

    # -- motores de contêiner -------------------------------------------------

    def set_engine_modes(self, server: str, modes: Mapping[str, str]) -> None:
        self.monitors[server].set_engine_modes(modes)

    def server_config(self, server: str) -> ServerConfig:
        """Configuração em vigor (pode ter sido alterada pelo diálogo de motores)."""
        return self.monitors[server].server

    def container_op(self, server: str, service: ServiceInfo, op: str) -> Future[ActionResult]:
        label = {"pause": "Pausar", "unpause": "Retomar", "rm": "Remover"}.get(op, op)
        return self._submit_action(server, service.name, label, service.key,
                                   lambda client: client.container_op(service, op))

    def image_op(self, server: str, engine_id: str, image: ContainerImage | None, op: str) -> Future[ActionResult]:
        target = image.reference if image else engines.ENGINES[engine_id].label
        busy = f"image:{image.key}" if image else f"prune:{engine_id}"
        label = {"rmi": "Remover imagem", "prune": "Limpar imagens órfãs"}.get(op, op)
        return self._submit_action(server, target, label, busy, lambda client: client.image_op(engine_id, image, op))

    def volume_op(self, server: str, engine_id: str, name: str, op: str) -> Future[ActionResult]:
        return self._submit_action(server, name, "Remover volume", f"volume:{engine_id}:{name}",
                                   lambda client: client.volume_op(engine_id, name, op))

    def inspect(self, server: str, what: str, engine_id: str, target) -> Future[str]:
        """``what``: "container" (ServiceInfo), "image" (ContainerImage) ou "volume" (nome)."""
        calls = {"container": lambda c: c.inspect_container(target),
                 "image": lambda c: c.inspect_image(engine_id, target),
                 "volume": lambda c: c.inspect_volume(engine_id, target)}
        return self._submit_read(server, calls[what])

    def check_image_updates(self, server: str, images: Sequence[ContainerImage]) -> Future[list[ImageUpdate]]:
        """Uma consulta skopeo por imagem (cada uma limitada a 5 s), em segundo plano."""
        monitor = self.monitors[server]

        def task() -> list[ImageUpdate]:
            if not monitor.client.connected:
                raise SSHConnectionError(f"{server} está desconectado")
            results = []
            for image in images:
                try:
                    results.append(monitor.client.check_image_update(image))
                except SSHConnectionError:
                    raise
                except Exception as exc:  # noqa: BLE001 - uma imagem com erro não interrompe as demais
                    results.append(ImageUpdate(image.reference, "erro", detail=str(exc)[:200]))
            return results

        return self._executor.submit(task)

    def console_command(self, server: str, service: ServiceInfo) -> str:
        return self.monitors[server].client.console_command(service)

    # -- mudanças seguras ------------------------------------------------------

    def prepare_change(self, server: str, action: ChangeAction, service: ServiceInfo | None = None,
                       spec: ContainerSpec | None = None, record: ChangeRecord | None = None,
                       use_snapshot: bool = False) -> Future[PreparedChange]:
        """Análise de risco com o estado real (inspect) — nada é alterado."""
        monitor = self.monitors[server]

        def task() -> PreparedChange:
            if not monitor.client.connected:
                raise SSHConnectionError(f"{server} está desconectado")
            backend = monitor.client.change_backend()
            ctx = changes.context_from_snapshot(monitor.last_snapshot, monitor.server)
            engine = engines.ENGINE_OF_KIND.get(service.kind, "") if service is not None else (
                spec.engine if spec is not None else record.engine if record is not None else "")
            current_spec = spec
            data = None
            if service is not None:
                data = backend.inspect(engine, service.name)
            if action is ChangeAction.RESTORE and record is not None:
                definition = self.backups.load_definition(record)
                if definition is None:
                    raise ValueError("a definição salva desta mudança não foi encontrada neste PC")
                image = str((definition.get("Config") or {}).get("Image") or "")
                image_config = backend.image_config(engine, image) if image else None
                current_spec = changes.spec_from_inspect(definition, engine, image_config)
                if use_snapshot and record.snapshot_image:
                    current_spec = dataclasses.replace(current_spec, image=record.snapshot_image)
            inspect_info = changes.parse_inspect(data) if data else None
            assessment = changes.assess(action, service, ctx, inspect=inspect_info, spec=current_spec)
            role = changes.container_role(inspect_info.image if inspect_info else
                                          (current_spec.image if current_spec else ""))
            return PreparedChange(assessment=assessment, inspect=inspect_info, spec=current_spec,
                                  stop_timeout=30 if role == "banco" else 10, record=record,
                                  use_snapshot=use_snapshot)

        return self._executor.submit(task)

    def run_change(self, server: str, prepared: PreparedChange, protections: Iterable[str],
                   service: ServiceInfo | None = None) -> tuple[str, Future[ChangeRecord]]:
        """Executa a mudança analisada; o andamento chega como ChangeProgressEvent."""
        monitor = self.monitors[server]
        assessment = prepared.assessment
        if assessment.blockers:
            raise ValueError("; ".join(assessment.blockers))
        chosen = {p.id for p in assessment.protections if p.required} | set(protections)
        spec = prepared.spec
        name = service.name if service is not None else spec.name if spec is not None else assessment.target
        request = ChangeRequest(
            id=new_change_id(assessment.action), server=server, action=assessment.action, engine=assessment.engine,
            name=name, risk=assessment.risk, service=service, spec=spec, protections=frozenset(chosen),
            stop_timeout=prepared.stop_timeout, source_record=prepared.record, use_snapshot=prepared.use_snapshot,
            steps=changes.plan_steps(assessment.action, assessment.protections, service, chosen))

        def task() -> ChangeRecord:
            runner = ChangeRunner(monitor.client.change_backend(), self.backups, self.events.put, request,
                                  expect_stop=monitor.policy.expect_stop)
            try:
                return runner.run()
            finally:
                monitor.refresh_now(full=True)

        return request.id, self._executor.submit(task)

    def change_records(self, server: str | None = None) -> list[ChangeRecord]:
        return self.backups.records(server)

    def fail2ban_action(self, server: str, jail: str, ip: str, ban: bool) -> Future[ActionResult]:
        label = "Banir" if ban else "Desbanir"
        return self._submit_action(server, f"{ip} (jail {jail})", label, f"ip:{ip}",
                                   lambda client: client.fail2ban_action(jail, ip, ban))

    # -- logs ----------------------------------------------------------------

    def logs_command(self, server: str, service: ServiceInfo, lines: int) -> str:
        return self.monitors[server].client.logs_command(service, lines)

    def fetch_logs(self, server: str, service: ServiceInfo, lines: int) -> Future[str]:
        return self._submit_read(server, lambda client: client.service_logs(service, lines))

    def fetch_stack_logs(self, server: str, stack: Stack, lines: int) -> Future[str]:
        return self._submit_read(server, lambda client: client.stack_logs(stack, lines))

    def _submit_read(self, server: str, call: Callable[[HostClient], str]) -> Future[str]:
        monitor = self.monitors[server]

        def task() -> str:
            if not monitor.client.connected:
                raise SSHConnectionError(f"{server} está desconectado")
            return call(monitor.client)

        return self._executor.submit(task)
