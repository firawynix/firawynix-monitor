"""Loop de monitoramento (uma thread por servidor) e emissão de eventos.

Fluxo de dados::

    ServerMonitor (thread) --eventos--> queue.Queue --after()--> Dashboard (thread da UI)

A interface nunca chama SSH diretamente: ações e leitura de logs rodam em um
``ThreadPoolExecutor`` e devolvem ``Future``/eventos, mantendo a UI fluida.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
import queue
import random
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Protocol

from config.settings import AppSettings, Config, NotificationSettings, ServerConfig, user_data_dir
from core.models import (
    ActionOutcome,
    ActionResult,
    ActionResultEvent,
    AlertKind,
    ConnectionEvent,
    ConnectionState,
    DockerResult,
    DockerState,
    HostMetrics,
    HostSnapshot,
    MonitorEvent,
    ServiceAction,
    ServiceAlertEvent,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SnapshotEvent,
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

#: Após N timeouts seguidos a conexão é considerada zumbi e é refeita.
MAX_CONSECUTIVE_TIMEOUTS = 3
#: Quantas coletas esperar antes de testar de novo um Docker ausente.
DOCKER_RECHECK_POLLS = 12
#: Janela em que uma parada solicitada pelo usuário não gera alerta.
EXPECTED_STOP_WINDOW = 90.0


class HostClient(Protocol):
    """Interface usada pelo monitor (implementada por SSHClient e DemoClient)."""

    @property
    def connected(self) -> bool: ...
    def connect(self) -> None: ...
    def close(self) -> None: ...
    def list_services(self) -> list[ServiceInfo]: ...
    def list_containers(self) -> DockerResult: ...
    def host_metrics(self) -> HostMetrics: ...
    def service_action(self, service: ServiceInfo, action: ServiceAction) -> ActionResult: ...
    def service_logs(self, service: ServiceInfo, lines: int) -> str: ...


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

def matches_patterns(service: ServiceInfo, patterns: Iterable[str]) -> bool:
    """Padrões glob (``nginx*``), opcionalmente prefixados pelo tipo (``docker:web-*``).

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
            if prefix in (ServiceKind.SYSTEMD.value, ServiceKind.DOCKER.value):
                if prefix != service.kind.value:
                    continue
                pattern = rest
        if any(fnmatch.fnmatchcase(name, pattern) for name in names):
            return True
    return False


class AlertPolicy:
    """Decide quais mudanças de estado geram notificação."""

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


# ---------------------------------------------------------------------------
# Monitor de um servidor
# ---------------------------------------------------------------------------

class ServerMonitor:
    """Coleta periódica de um servidor em thread própria, com reconexão automática."""

    def __init__(self, server: ServerConfig, settings: AppSettings,
                 emit: Callable[[MonitorEvent], None],
                 client_factory: ClientFactory = default_client_factory) -> None:
        self.server = server
        self.settings = settings
        self._emit = emit
        self.client: HostClient = client_factory(server, settings)
        self.interval = server.poll_interval_seconds or settings.poll_interval_seconds
        self.policy = AlertPolicy(settings.notifications)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._backoff = ExponentialBackoff(base=1.0, maximum=60.0)
        # Credenciais/host key erradas: espaçar bem as tentativas (evita fail2ban).
        self._auth_backoff = ExponentialBackoff(base=30.0, maximum=600.0)
        self._previous: dict[str, ServiceInfo] | None = None
        self._last_services: list[ServiceInfo] = []
        self._last_docker = DockerResult(DockerState.DISABLED)
        self._last_metrics: HostMetrics | None = None
        self._docker_skip = 0
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
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            log.debug("Erro ao fechar cliente", exc_info=True)

    def refresh_now(self) -> None:
        """Acorda o loop: coleta imediata (ou reconexão imediata, se desconectado)."""
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
                snapshot = self._stale_snapshot(f"Erro inesperado na coleta: {exc}")
            self._emit(SnapshotEvent(server=self.server.name, snapshot=snapshot))
            elapsed = time.monotonic() - started
            self._sleep(self.interval - elapsed)
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
        self._docker_skip = 0
        self._set_state(ConnectionState.CONNECTED, f"Conectado a {self.server.address}")
        return True

    def _collect(self) -> HostSnapshot:
        started = time.monotonic()
        warnings: list[str] = []
        timed_out = False
        stale = False

        # 1) systemd
        try:
            services = self.client.list_services()
        except SSHCommandTimeout as exc:
            timed_out = stale = True
            warnings.append(f"systemctl não respondeu a tempo ({exc}); exibindo dados anteriores.")
            services = [s for s in self._last_services if s.kind is ServiceKind.SYSTEMD]
        except SSHCommandError as exc:
            warnings.append(str(exc))
            services = []

        # 2) Docker (re-testado periodicamente quando ausente)
        docker = self._last_docker
        if self.server.docker == "off":
            docker = DockerResult(DockerState.DISABLED)
        elif self._docker_skip > 0:
            self._docker_skip -= 1
        else:
            try:
                docker = self.client.list_containers()
            except SSHCommandTimeout:
                timed_out = stale = True
                warnings.append("docker ps não respondeu a tempo; exibindo dados anteriores.")
            if docker.state in (DockerState.NOT_INSTALLED, DockerState.DAEMON_DOWN) and self.server.docker == "auto":
                self._docker_skip = DOCKER_RECHECK_POLLS
        if docker.state in (DockerState.PERMISSION, DockerState.DAEMON_DOWN, DockerState.ERROR) or (
                docker.state is DockerState.NOT_INSTALLED and self.server.docker == "on"):
            warnings.append(docker.message)

        # 3) Métricas do host
        metrics = self._last_metrics
        try:
            metrics = self.client.host_metrics()
        except SSHCommandTimeout:
            timed_out = True
            warnings.append("Coleta de métricas excedeu o timeout.")

        self._consecutive_timeouts = self._consecutive_timeouts + 1 if timed_out else 0
        if self._consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
            self._consecutive_timeouts = 0
            raise SSHConnectionError(f"{MAX_CONSECUTIVE_TIMEOUTS} coletas seguidas com timeout")

        all_services = [*services, *docker.containers]
        visible = [
            dataclasses.replace(s, critical=matches_patterns(s, self.server.critical_services))
            for s in all_services
            if not matches_patterns(s, self.server.exclude_services)
        ]

        if not stale:
            for alert in self.policy.evaluate(self.server.name, self._previous, visible):
                self._emit(alert)
            self._previous = {s.key: s for s in visible}

        self._last_services = visible
        self._last_docker = docker
        self._last_metrics = metrics
        return HostSnapshot(
            server=self.server.name,
            services=tuple(visible),
            metrics=metrics,
            docker=docker,
            warnings=tuple(w for w in warnings if w),
            duration=time.monotonic() - started,
        )

    def _stale_snapshot(self, warning: str) -> HostSnapshot:
        return HostSnapshot(
            server=self.server.name,
            services=tuple(self._last_services),
            metrics=self._last_metrics,
            docker=self._last_docker,
            warnings=(warning,),
        )


# ---------------------------------------------------------------------------
# Gerenciador (fachada usada pela UI)
# ---------------------------------------------------------------------------

class MonitorManager:
    def __init__(self, config: Config, client_factory: ClientFactory = default_client_factory,
                 max_workers: int = 4) -> None:
        self.config = config
        self.events: queue.Queue[MonitorEvent] = queue.Queue()
        self.monitors: dict[str, ServerMonitor] = {
            server.name: ServerMonitor(server, config.settings, self.events.put, client_factory)
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

    def refresh(self, server: str | None = None) -> None:
        targets = [self.monitors[server]] if server else self.monitors.values()
        for monitor in targets:
            monitor.refresh_now()

    def set_poll_interval(self, seconds: float) -> None:
        for monitor in self.monitors.values():
            monitor.set_interval(seconds)

    def is_connected(self, server: str) -> bool:
        return self.monitors[server].client.connected

    def run_action(self, server: str, service: ServiceInfo, action: ServiceAction) -> Future[ActionResult]:
        monitor = self.monitors[server]

        def task() -> ActionResult:
            if action is ServiceAction.STOP:
                monitor.policy.expect_stop(service.key)
            try:
                if not monitor.client.connected:
                    raise SSHConnectionError("servidor desconectado")
                result = monitor.client.service_action(service, action)
            except (SSHConnectionError, SSHCommandError, ValueError) as exc:
                result = ActionResult(ActionOutcome.ERROR, f"Não foi possível {action.label.lower()} "
                                                           f"{service.name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                log.exception("[%s] erro inesperado na ação %s", server, action.value)
                result = ActionResult(ActionOutcome.ERROR, f"Erro inesperado: {exc}")
            log.info("[%s] ação %s em %s: %s — %s", server, action.value, service.name,
                     result.outcome.value, result.message)
            self.events.put(ActionResultEvent(server=server, service=service, action=action, result=result))
            monitor.refresh_now()
            return result

        return self._executor.submit(task)

    def fetch_logs(self, server: str, service: ServiceInfo, lines: int) -> Future[str]:
        monitor = self.monitors[server]

        def task() -> str:
            if not monitor.client.connected:
                raise SSHConnectionError(f"{server} está desconectado")
            return monitor.client.service_logs(service, lines)

        return self._executor.submit(task)
