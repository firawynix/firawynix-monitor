"""Loop de monitoramento (uma thread por servidor) e emissão de eventos.

Fluxo de dados::

    ServerMonitor (thread) --eventos--> queue.Queue --after()--> Dashboard (thread da UI)

Cada ciclo executa, em paralelo (canais SSH distintos na mesma conexão), os
coletores que estiverem "vencidos":

* rápido (todo ciclo): unidades systemd, contêineres, pods, VMs, métricas;
* detalhes (``detail_interval_seconds``): processos, portas, stats de contêineres;
* inventário (``inventory_interval_seconds``): sistema, timers, cron, eventos;
* atualizações (``updates_interval_seconds``): pacotes pendentes.

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
from core.history import HistoryStore
from core.models import (
    ActionOutcome,
    ActionResult,
    ActionResultEvent,
    AlertKind,
    ConnectionEvent,
    ConnectionState,
    CronEntry,
    HostMetrics,
    HostSnapshot,
    JournalEntry,
    MonitorEvent,
    NetworkInfo,
    ProcessInfo,
    RuntimeResult,
    RuntimeState,
    ServiceAction,
    ServiceAlertEvent,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SnapshotEvent,
    Stack,
    SystemInfo,
    ThresholdAlertEvent,
    TimerInfo,
    UpdatesInfo,
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
    def host_metrics(self) -> HostMetrics: ...
    def processes(self) -> list[ProcessInfo]: ...
    def network(self) -> NetworkInfo: ...
    def timers(self) -> list[TimerInfo]: ...
    def cron(self) -> list[CronEntry]: ...
    def journal_events(self, priority: str, limit: int, since_hours: int) -> list[JournalEntry]: ...
    def system_info(self) -> tuple[SystemInfo, dict[str, float]]: ...
    def ssh_failed_logins(self) -> int | None: ...
    def updates(self) -> UpdatesInfo | None: ...
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

_KIND_PREFIXES = {kind.value for kind in ServiceKind} | {"kubernetes", "libvirt"}
_PREFIX_ALIASES = {"kubernetes": ServiceKind.KUBERNETES.value, "libvirt": ServiceKind.LIBVIRT.value}


def matches_patterns(service: ServiceInfo, patterns: Iterable[str]) -> bool:
    """Padrões glob (``nginx*``), opcionalmente prefixados pelo tipo
    (``docker:web-*``, ``podman:*``, ``k8s:prod/*``, ``vm:db*``).

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

    def evaluate(self, server: str, metrics: HostMetrics | None) -> list[ThresholdAlertEvent]:
        if metrics is None:
            return []
        t = self.thresholds
        checks: list[tuple[str, str, float | None, float, int]] = [
            ("cpu", "CPU", metrics.cpu_percent, t.cpu_percent, t.sustain_polls),
            ("mem", "Memória", metrics.mem_percent, t.mem_percent, t.sustain_polls),
        ]
        # Disco não oscila como CPU: alerta na primeira leitura acima do limite.
        checks += [(f"disk:{d.mount}", f"Disco {d.mount}", d.use_percent, t.disk_percent, 1) for d in metrics.disks]
        events = []
        seen = set()
        for metric, label, value, limit, sustain in checks:
            seen.add(metric)
            if not limit or value is None:
                continue
            if value >= limit:
                self._streak[metric] += 1
                if self._streak[metric] >= sustain and metric not in self._active:
                    events.append(ThresholdAlertEvent(server=server, metric=metric, label=label,
                                                      value=value, threshold=limit))
                if metric in self._active or self._streak[metric] >= sustain:
                    self._active[metric] = f"{label} {value:.0f}%"
            else:
                self._streak[metric] = 0
                if metric in self._active and value < limit - THRESHOLD_HYSTERESIS:
                    del self._active[metric]
                    events.append(ThresholdAlertEvent(server=server, metric=metric, label=label,
                                                      value=value, threshold=limit, recovered=True))
                elif metric in self._active:
                    self._active[metric] = f"{label} {value:.0f}%"
        for gone in set(self._active) - seen:  # disco desmontado
            del self._active[gone]
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
    ssh_failures: int | None = None
    updates: UpdatesInfo | None = None
    detail_at: float | None = None
    inventory_at: float | None = None


_RUNTIME_KINDS = (ServiceKind.DOCKER, ServiceKind.PODMAN, ServiceKind.KUBERNETES, ServiceKind.LIBVIRT)


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
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=COLLECTOR_WORKERS,
                                        thread_name_prefix=f"collect-{server.name}")
        self._backoff = ExponentialBackoff(base=1.0, maximum=60.0)
        # Credenciais/host key erradas: espaçar bem as tentativas (evita fail2ban).
        self._auth_backoff = ExponentialBackoff(base=30.0, maximum=600.0)
        self._previous: dict[str, ServiceInfo] | None = None
        self._latest = _Latest()
        self._due = {"detail": 0.0, "inventory": 0.0, "updates": 0.0}
        self._runtime_skip: dict[ServiceKind, int] = defaultdict(int)
        self._consecutive_timeouts = 0
        self.state = ConnectionState.STOPPED

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

    def _sleep(self, seconds: float) -> None:
        self._wake.wait(timeout=max(0.0, seconds))
        self._wake.clear()

    def _set_state(self, state: ConnectionState, message: str = "", retry_in: float | None = None,
                   attempt: int = 0) -> None:
        self.state = state
        self._emit(ConnectionEvent(server=self.server.name, state=state, message=message,
                                   retry_in=retry_in, attempt=attempt))

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
            self._set_state(ConnectionState.RECONNECTING, str(exc), retry_in=delay, attempt=attempt)
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
            if self._runtime_mode(kind) == "off":
                self._latest.runtimes[kind] = RuntimeResult(kind, RuntimeState.DISABLED)
            elif self._runtime_skip[kind] > 0:
                self._runtime_skip[kind] -= 1
            elif kind.is_container:
                tasks[kind.value] = (lambda k=kind: client.list_containers(k))
            elif kind is ServiceKind.KUBERNETES:
                tasks[kind.value] = client.list_pods
            else:
                tasks[kind.value] = client.list_vms

        detail_due = now >= self._due["detail"]
        if detail_due:
            self._due["detail"] = now + settings.detail_interval_seconds
            tasks["processes"] = client.processes
            tasks["network"] = client.network
        for kind in (ServiceKind.DOCKER, ServiceKind.PODMAN):
            runtime = self._latest.runtimes.get(kind)
            # Stats também no ciclo seguinte à descoberta do runtime (sem esperar o intervalo).
            if runtime is not None and runtime.state is RuntimeState.OK and runtime.items \
                    and (detail_due or kind not in self._latest.stats):
                tasks[f"stats:{kind.value}"] = (lambda k=kind: client.container_stats(k))
        if now >= self._due["inventory"]:
            self._due["inventory"] = now + settings.inventory_interval_seconds
            events = settings.events
            tasks["system"] = client.system_info
            tasks["ssh_failures"] = client.ssh_failed_logins
            tasks["timers"] = client.timers
            tasks["cron"] = client.cron
            tasks["events"] = (lambda: client.journal_events(events.priority, events.limit, events.since_hours))
        if now >= self._due["updates"]:
            self._due["updates"] = now + settings.updates_interval_seconds
            tasks["updates"] = client.updates
        return tasks

    def _runtime_mode(self, kind: ServiceKind) -> str:
        return {
            ServiceKind.DOCKER: self.server.docker,
            ServiceKind.PODMAN: self.server.podman,
            ServiceKind.KUBERNETES: self.server.kubernetes,
            ServiceKind.LIBVIRT: self.server.libvirt,
        }[kind]

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
                if runtime.state in (RuntimeState.NOT_INSTALLED, RuntimeState.DAEMON_DOWN) \
                        and self._runtime_mode(kind) == "auto":
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
        if "ssh_failures" in results and not isinstance(results["ssh_failures"], Exception):
            latest.ssh_failures = results["ssh_failures"]
        for name in ("timers", "cron", "events"):
            if isinstance(results.get(name), list):
                setattr(latest, name, results[name])
        if "updates" in results and not isinstance(results["updates"], Exception):
            latest.updates = results["updates"]

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
            mode = self._runtime_mode(kind)
            if runtime.message and (
                    (mode == "on" and runtime.state is not RuntimeState.OK)
                    or runtime.state in (RuntimeState.PERMISSION, RuntimeState.DAEMON_DOWN)):
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
        if system is not None and latest.ssh_failures is not None and system.journal_access is not False:
            system = dataclasses.replace(system, ssh_failed_logins_24h=latest.ssh_failures)

        if evaluate:
            for alert in self.policy.evaluate(self.server.name, self._previous, visible):
                self._emit(alert)
            self._previous = {s.key: s for s in visible}
            for alert in self.thresholds.evaluate(self.server.name, latest.metrics):
                self._emit(alert)
            if self.history is not None and latest.metrics is not None:
                failed = sum(1 for s in visible if s.status is ServiceStatus.FAILED)
                active = sum(1 for s in visible if s.status is ServiceStatus.ACTIVE)
                self.history.record(self.server.name, time.time(), latest.metrics, failed, active)

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
            warnings=tuple(dict.fromkeys(w for w in warnings if w)),
            resource_alerts=self.thresholds.active,
            duration=duration,
            detail_at=latest.detail_at,
            inventory_at=latest.inventory_at,
        )


_TASK_LABELS = {
    "units": "unidades systemd", "resources": "recursos por serviço", "metrics": "métricas",
    "docker": "Docker", "podman": "Podman", "k8s": "Kubernetes", "vm": "VMs", "processes": "processos",
    "network": "rede", "stats:docker": "stats do Docker", "stats:podman": "stats do Podman",
    "system": "sistema", "ssh_failures": "falhas de login SSH", "timers": "timers", "cron": "cron",
    "events": "eventos do journal", "updates": "atualizações",
}


# ---------------------------------------------------------------------------
# Gerenciador (fachada usada pela UI)
# ---------------------------------------------------------------------------

class MonitorManager:
    def __init__(self, config: Config, client_factory: ClientFactory = default_client_factory,
                 history: HistoryStore | None = None, max_workers: int = 4) -> None:
        self.config = config
        self.history = history
        self.events: queue.Queue[MonitorEvent] = queue.Queue()
        self.monitors: dict[str, ServerMonitor] = {
            server.name: ServerMonitor(server, config.settings, self.events.put, client_factory, history)
            for server in config.servers
        }
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ssh-action")

    @property
    def server_names(self) -> list[str]:
        return list(self.monitors)

    def start(self) -> None:
        for monitor in self.monitors.values():
            monitor.start()

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
