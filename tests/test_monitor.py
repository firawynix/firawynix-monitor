"""Testes do loop de monitoramento com um cliente falso (sem rede)."""

import queue
import threading
import time

import pytest

from config.settings import AppSettings, Config, NotificationSettings, ServerConfig
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
    ServiceAction,
    ServiceAlertEvent,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SnapshotEvent,
)
from core.monitor import AlertPolicy, ExponentialBackoff, MonitorManager, matches_patterns
from core.ssh_client import SSHCommandTimeout, SSHConnectionError


def svc(name, status=ServiceStatus.ACTIVE, kind=ServiceKind.SYSTEMD, critical=True):
    return ServiceInfo(kind, name, "", status, status.value, "", critical=critical)


# ---------------------------------------------------------------------------
# Backoff e padrões
# ---------------------------------------------------------------------------

def test_exponential_backoff_grows_caps_and_resets():
    backoff = ExponentialBackoff(base=1, factor=2, maximum=10, jitter=0)
    assert [backoff.next_delay() for _ in range(6)] == [1, 2, 4, 8, 10, 10]
    backoff.reset()
    assert backoff.next_delay() == 1


def test_exponential_backoff_jitter_stays_in_range():
    low = ExponentialBackoff(base=10, jitter=0.2, rng=lambda: 0.0).next_delay()
    high = ExponentialBackoff(base=10, jitter=0.2, rng=lambda: 1.0).next_delay()
    assert (low, high) == (pytest.approx(8.0), pytest.approx(12.0))


@pytest.mark.parametrize(("service", "patterns", "expected"), [
    (svc("nginx.service"), ["nginx"], True),
    (svc("nginx.service"), ["NGINX.service"], True),
    (svc("postgresql@16-main.service"), ["postgresql*"], True),
    (svc("nginx.service"), ["docker:nginx"], False),
    (svc("web", kind=ServiceKind.DOCKER), ["docker:web*"], True),
    (svc("web", kind=ServiceKind.DOCKER), ["systemd:*"], False),
    (svc("cron.service"), ["*"], True),
    (svc("cron.service"), [], False),
])
def test_matches_patterns(service, patterns, expected):
    assert matches_patterns(service, patterns) is expected


# ---------------------------------------------------------------------------
# Política de alertas
# ---------------------------------------------------------------------------

def _evaluate(policy, previous, current):
    prev_map = None if previous is None else {s.key: s for s in previous}
    return [(a.alert, a.service.name) for a in policy.evaluate("srv", prev_map, current)]


def test_alert_policy_failed_once_and_recovery_through_activating():
    policy = AlertPolicy(NotificationSettings())
    first = [svc("a.service", ServiceStatus.FAILED), svc("b.service")]
    assert _evaluate(policy, None, first) == [(AlertKind.FAILED, "a.service")]
    assert _evaluate(policy, first, first) == []  # sem repetição
    activating = [svc("a.service", ServiceStatus.ACTIVATING), svc("b.service")]
    assert _evaluate(policy, first, activating) == []
    recovered = [svc("a.service"), svc("b.service")]
    assert _evaluate(policy, activating, recovered) == [(AlertKind.RECOVERED, "a.service")]


def test_alert_policy_ignores_non_critical_and_respects_recovery_flag():
    policy = AlertPolicy(NotificationSettings(notify_on_recovery=False))
    current = [svc("x.service", ServiceStatus.FAILED, critical=False), svc("y.service", ServiceStatus.FAILED)]
    assert _evaluate(policy, None, current) == [(AlertKind.FAILED, "y.service")]
    assert _evaluate(policy, current, [svc("y.service")]) == []


def test_alert_on_stop_skips_user_requested_stops():
    policy = AlertPolicy(NotificationSettings(alert_on_stop=True))
    running = [svc("a.service"), svc("b.service")]
    policy.expect_stop("systemd:b.service")
    stopped = [svc("a.service", ServiceStatus.STOPPED), svc("b.service", ServiceStatus.STOPPED)]
    assert _evaluate(policy, running, stopped) == [(AlertKind.STOPPED, "a.service")]
    assert _evaluate(AlertPolicy(NotificationSettings()), running, stopped) == []


# ---------------------------------------------------------------------------
# Loop do monitor
# ---------------------------------------------------------------------------

class FakeClient:
    """Cliente programável: listas de exceções/valores consumidas a cada chamada."""

    def __init__(self, *, connect_errors=0, service_errors=()):
        self._connected = False
        self.connect_errors = connect_errors
        self.service_errors = list(service_errors)
        self.connect_calls = 0
        self.services = [
            ServiceInfo(ServiceKind.SYSTEMD, "nginx.service", "", ServiceStatus.ACTIVE, "active", "running"),
            ServiceInfo(ServiceKind.SYSTEMD, "app.service", "", ServiceStatus.FAILED, "failed", "failed"),
            ServiceInfo(ServiceKind.SYSTEMD, "noise.service", "", ServiceStatus.FAILED, "failed", "failed"),
        ]
        self.actions = []
        self.lock = threading.Lock()

    @property
    def connected(self):
        return self._connected

    def connect(self):
        self.connect_calls += 1
        if self.connect_errors > 0:
            self.connect_errors -= 1
            raise SSHConnectionError("recusado")
        self._connected = True

    def close(self):
        self._connected = False

    def list_services(self):
        if self.service_errors:
            error = self.service_errors.pop(0)
            if isinstance(error, SSHConnectionError):
                self._connected = False
            raise error
        return list(self.services)

    def list_containers(self):
        return DockerResult(DockerState.NOT_INSTALLED, (), "Docker não instalado neste host.")

    def host_metrics(self):
        return HostMetrics(cpu_percent=12.0)

    def service_action(self, service, action):
        self.actions.append((service.name, action))
        return ActionResult(ActionOutcome.OK, "ok")

    def service_logs(self, service, lines):
        return f"{lines} linhas de {service.name}"


def _manager(client, **server_kwargs):
    server = ServerConfig(name="srv", host="h", username="u", **server_kwargs)
    config = Config(settings=AppSettings(poll_interval_seconds=2.0), servers=(server,))
    manager = MonitorManager(config, client_factory=lambda _s, _a: client)
    monitor = manager.monitors["srv"]
    monitor._backoff = ExponentialBackoff(base=0.01, maximum=0.05, jitter=0)
    monitor.interval = 0.05
    return manager


def _collect(manager, predicate, timeout=5.0):
    events = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = manager.events.get(timeout=0.05)
        except queue.Empty:
            continue
        events.append(event)
        if predicate(events):
            return events
    raise AssertionError(f"condição não atingida; eventos: {events}")


def _count(events, cls, **attrs):
    return sum(1 for e in events if isinstance(e, cls) and all(getattr(e, k) == v for k, v in attrs.items()))


def test_monitor_reconnects_with_backoff_then_emits_snapshot():
    client = FakeClient(connect_errors=2)
    manager = _manager(client, critical_services=("app*",), exclude_services=("noise*",))
    manager.start()
    try:
        events = _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 2)
    finally:
        manager.stop()
    states = [e.state for e in events if isinstance(e, ConnectionEvent)]
    assert states[:4] == [ConnectionState.CONNECTING, ConnectionState.RECONNECTING,
                          ConnectionState.RECONNECTING, ConnectionState.CONNECTED]
    retry = [e.retry_in for e in events if isinstance(e, ConnectionEvent) and e.retry_in]
    assert retry == [0.01, 0.02]
    snapshot = next(e.snapshot for e in events if isinstance(e, SnapshotEvent))
    names = {s.name: s for s in snapshot.services}
    assert set(names) == {"nginx.service", "app.service"}  # noise.service excluído
    assert names["app.service"].critical and not names["nginx.service"].critical
    assert snapshot.docker.state is DockerState.NOT_INSTALLED and snapshot.warnings == ()
    alerts = [e for e in events if isinstance(e, ServiceAlertEvent)]
    assert [(a.alert, a.service.name) for a in alerts] == [(AlertKind.FAILED, "app.service")]


def test_monitor_recovers_from_connection_loss_during_collect():
    client = FakeClient(service_errors=[SSHConnectionError("reset by peer")])
    manager = _manager(client)
    manager.start()
    try:
        events = _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 1)
    finally:
        manager.stop()
    assert _count(events, ConnectionEvent, state=ConnectionState.RECONNECTING) >= 1
    assert _count(events, ConnectionEvent, state=ConnectionState.CONNECTED) == 2
    assert client.connect_calls == 2


def test_monitor_keeps_stale_data_on_timeout_and_reconnects_after_three():
    timeouts = [SSHCommandTimeout("lento")] * 3
    client = FakeClient(service_errors=timeouts)
    manager = _manager(client)
    manager.start()
    try:
        events = _collect(manager, lambda ev: _count(ev, ConnectionEvent, state=ConnectionState.CONNECTED) >= 2
                          and _count(ev, SnapshotEvent) >= 3)
    finally:
        manager.stop()
    first = next(e.snapshot for e in events if isinstance(e, SnapshotEvent))
    assert any("não respondeu a tempo" in w for w in first.warnings)
    assert client.connect_calls >= 2


def test_run_action_emits_result_and_fetch_logs():
    client = FakeClient()
    manager = _manager(client)
    manager.start()
    try:
        _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 1)
        service = client.services[0]
        result = manager.run_action("srv", service, ServiceAction.RESTART).result(timeout=5)
        assert result.outcome is ActionOutcome.OK
        assert client.actions == [("nginx.service", ServiceAction.RESTART)]
        _collect(manager, lambda ev: _count(ev, ActionResultEvent) >= 1)
        assert manager.fetch_logs("srv", service, 25).result(timeout=5) == "25 linhas de nginx.service"
    finally:
        manager.stop()


def test_run_action_when_disconnected_returns_error():
    client = FakeClient()
    manager = _manager(client)  # não iniciado: cliente nunca conectou
    result = manager.run_action("srv", client.services[0], ServiceAction.STOP).result(timeout=5)
    assert result.outcome is ActionOutcome.ERROR
    assert "desconectado" in result.message
    with pytest.raises(SSHConnectionError):
        manager.fetch_logs("srv", client.services[0], 10).result(timeout=5)
    manager.stop()
