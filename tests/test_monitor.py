"""Testes do loop de monitoramento com um cliente falso (sem rede)."""

import queue
import time

import pytest

from config.settings import AppSettings, Config, NotificationSettings, ServerConfig, ThresholdSettings
from core.history import HistoryStore
from core.models import (
    ActionOutcome,
    ActionResult,
    ActionResultEvent,
    AlertKind,
    ConnectionEvent,
    ConnectionState,
    DiskUsage,
    HostAlertEvent,
    HostMetrics,
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
    SystemInfo,
    ThresholdAlertEvent,
    VpsInfo,
)
from core.monitor import AlertPolicy, ExponentialBackoff, MonitorManager, ThresholdPolicy, matches_patterns
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
    (svc("db", kind=ServiceKind.PODMAN), ["podman:db"], True),
    (svc("prod/api-1", kind=ServiceKind.KUBERNETES), ["k8s:prod/*"], True),
    (svc("prod/api-1", kind=ServiceKind.KUBERNETES), ["kubernetes:prod/*"], True),
    (svc("dev/api-1", kind=ServiceKind.KUBERNETES), ["k8s:prod/*"], False),
    (svc("win-ad", kind=ServiceKind.LIBVIRT), ["vm:win*"], True),
    (svc("apt-daily.timer"), ["*.timer"], True),
    (svc("cron.service"), ["*"], True),
    (svc("cron.service"), [], False),
])
def test_matches_patterns(service, patterns, expected):
    assert matches_patterns(service, patterns) is expected


# ---------------------------------------------------------------------------
# Políticas de alerta
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


def _metrics(cpu=10.0, mem_used=1000, disks=(("/", 50.0),)):
    return HostMetrics(cpu_percent=cpu, mem_total_mb=10_000, mem_used_mb=mem_used,
                       disks=tuple(DiskUsage("/dev/x", m, 100, 50, 50, p) for m, p in disks))


def _thresholds(policy, metrics):
    return [(e.metric, e.recovered) for e in policy.evaluate("srv", metrics)]


def test_threshold_policy_sustain_hysteresis_and_disk():
    policy = ThresholdPolicy(ThresholdSettings(cpu_percent=90, mem_percent=90, disk_percent=90, sustain_polls=3))
    assert _thresholds(policy, _metrics(cpu=95)) == []
    assert _thresholds(policy, _metrics(cpu=95)) == []
    assert _thresholds(policy, _metrics(cpu=95)) == [("cpu", False)]
    assert policy.active == ("CPU 95%",)
    assert _thresholds(policy, _metrics(cpu=96)) == []  # já alertado
    assert _thresholds(policy, _metrics(cpu=87)) == []  # histerese: ainda acima de 85
    assert _thresholds(policy, _metrics(cpu=80)) == [("cpu", True)]
    assert policy.active == ()
    # Disco alerta na primeira leitura; montagem que some limpa o estado.
    assert _thresholds(policy, _metrics(disks=(("/", 50.0), ("/data", 97.0)))) == [("disk:/data", False)]
    assert policy.active == ("Disco /data 97%",)
    assert _thresholds(policy, _metrics(disks=(("/", 50.0),))) == []
    assert policy.active == ()


def test_threshold_zero_disables():
    policy = ThresholdPolicy(ThresholdSettings(cpu_percent=0, mem_percent=0, disk_percent=0, sustain_polls=1))
    assert _thresholds(policy, _metrics(cpu=100, mem_used=10_000, disks=(("/", 100.0),))) == []


# ---------------------------------------------------------------------------
# Loop do monitor
# ---------------------------------------------------------------------------

class FakeClient:
    """Cliente programável: listas de exceções/valores consumidas a cada chamada."""

    def __init__(self, *, connect_errors=0, unit_errors=(), docker_state=RuntimeState.NOT_INSTALLED):
        self._connected = False
        self.connect_errors = connect_errors
        self.unit_errors = list(unit_errors)
        self.connect_calls = 0
        self.calls: dict[str, int] = {}
        self.docker_state = docker_state
        self.units = [
            ServiceInfo(ServiceKind.SYSTEMD, "nginx.service", "", ServiceStatus.ACTIVE, "active", "running"),
            ServiceInfo(ServiceKind.SYSTEMD, "app.service", "", ServiceStatus.FAILED, "failed", "failed"),
            ServiceInfo(ServiceKind.SYSTEMD, "noise.service", "", ServiceStatus.FAILED, "failed", "failed"),
        ]
        self.cpu = 10.0
        self.actions = []

    def _count(self, name):
        self.calls[name] = self.calls.get(name, 0) + 1

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

    def list_units(self):
        self._count("units")
        if self.unit_errors:
            error = self.unit_errors.pop(0)
            if isinstance(error, SSHConnectionError):
                self._connected = False
            raise error
        return list(self.units)

    def service_resources(self):
        return {"nginx.service": (1.5, 50 * 1024 ** 2)}

    def list_containers(self, runtime):
        self._count(runtime.value)
        if runtime is ServiceKind.DOCKER and self.docker_state is RuntimeState.OK:
            web = ServiceInfo(ServiceKind.DOCKER, "shop-web-1", "nginx", ServiceStatus.ACTIVE, "running", "Up",
                              group="shop")
            return RuntimeResult(runtime, RuntimeState.OK, (web,))
        return RuntimeResult(runtime, self.docker_state if runtime is ServiceKind.DOCKER
                             else RuntimeState.NOT_INSTALLED, (), f"{runtime.label} indisponível")

    def container_stats(self, runtime):
        self._count("stats")
        return {"shop-web-1": (12.5, 100 * 1024 ** 2)}

    def list_pods(self):
        self._count("k8s")
        return RuntimeResult(ServiceKind.KUBERNETES, RuntimeState.NOT_INSTALLED)

    def list_vms(self):
        return RuntimeResult(ServiceKind.LIBVIRT, RuntimeState.NOT_INSTALLED)

    def host_metrics(self):
        return HostMetrics(cpu_percent=self.cpu, mem_total_mb=1000, mem_used_mb=100,
                           disks=(DiskUsage("/dev/sda1", "/", 100, 10, 90, 10.0),))

    def processes(self):
        self._count("processes")
        return [ProcessInfo(i, "root", 1.0, 0.1, 100, 10, "S", f"p{i}", f"p{i}") for i in range(5)]

    def network(self):
        return NetworkInfo(tcp_inuse=3)

    def timers(self):
        return []

    def cron(self):
        return []

    def journal_events(self, priority, limit, since_hours):
        self._count("events")
        return []

    def system_info(self):
        self._count("system")
        return SystemInfo(hostname="fake", journal_access=True), {"/": 42.0}

    def ssh_logins(self):
        self._count("ssh_logins")
        return SshLoginReport(failed_total=5)

    def list_lxd(self):
        self._count("lxd")
        return RuntimeResult(ServiceKind.LXD, RuntimeState.NOT_INSTALLED)

    def vps_info(self):
        self._count("vps")
        return VpsInfo(provider="Hetzner Cloud", ntp_synchronized=True)

    def smart(self):
        self._count("smart")
        return SmartReport(RuntimeState.NOT_INSTALLED, (), "smartctl não instalado")

    def security_raw(self):
        self._count("security")
        return SecurityRaw(sshd={"permitrootlogin": "yes", "passwordauthentication": "no"})

    def fail2ban_status(self):
        self._count("fail2ban")
        return (), ""

    def sudo_log(self):
        self._count("sudo")
        return ()

    def take_rtt(self):
        return 12.5

    def fail2ban_action(self, jail, ip, ban):
        self.actions.append((jail, ip, ban))
        return ActionResult(ActionOutcome.OK, "ok")

    def updates(self):
        self._count("updates")
        return None

    def service_action(self, service, action):
        self.actions.append((service.name, action))
        return ActionResult(ActionOutcome.OK, "ok")

    def stack_action(self, stack, action):
        self.actions.append((stack.name, action))
        return ActionResult(ActionOutcome.OK, "ok")

    def kill_process(self, pid, force):
        self.actions.append((pid, force))
        return ActionResult(ActionOutcome.OK, "ok")

    def logs_command(self, service, lines):
        return f"logs {service.name}"

    def service_logs(self, service, lines):
        return f"{lines} linhas de {service.name}"

    def stack_logs(self, stack, lines):
        return f"stack {stack.name}"


def _manager(client, settings=None, history=None, **server_kwargs):
    server = ServerConfig(name="srv", host="h", username="u", **server_kwargs)
    settings = settings or AppSettings(poll_interval_seconds=2.0, process_limit=3)
    config = Config(settings=settings, servers=(server,))
    manager = MonitorManager(config, client_factory=lambda _s, _a: client, history=history)
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


def _snapshots(events):
    return [e.snapshot for e in events if isinstance(e, SnapshotEvent)]


def test_monitor_reconnects_with_backoff_then_emits_full_snapshot():
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
    assert [e.retry_in for e in events if isinstance(e, ConnectionEvent) and e.retry_in] == [0.01, 0.02]
    snapshot = _snapshots(events)[0]
    names = {s.name: s for s in snapshot.services}
    assert set(names) == {"nginx.service", "app.service"}  # noise.service excluído
    assert names["app.service"].critical and not names["nginx.service"].critical
    assert names["nginx.service"].mem_bytes == 50 * 1024 ** 2  # recursos do cgroup mesclados
    assert len(snapshot.processes) == 3  # process_limit
    assert snapshot.metrics.disks[0].inode_percent == 42.0
    assert snapshot.system.ssh_failed_logins_24h == 5
    assert snapshot.warnings == ()  # runtimes ausentes em modo auto não geram aviso
    alerts = [e for e in events if isinstance(e, ServiceAlertEvent)]
    assert [(a.alert, a.service.name) for a in alerts] == [(AlertKind.FAILED, "app.service")]


def test_monitor_collection_tiers_and_runtime_recheck():
    client = FakeClient()
    manager = _manager(client)
    manager.start()
    try:
        _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 5)
    finally:
        manager.stop()
    assert client.calls["units"] >= 5
    assert client.calls["processes"] == 1  # detalhes: 15 s por padrão
    assert client.calls["system"] == 1 and client.calls["events"] == 1  # inventário: 60 s
    assert client.calls["updates"] == 1
    assert client.calls["docker"] == 1 and client.calls["k8s"] == 1  # ausentes: re-teste só após 12 ciclos


def test_monitor_merges_container_stats_and_warns_when_runtime_forced():
    client = FakeClient(docker_state=RuntimeState.OK)
    manager = _manager(client, podman="on")
    manager.start()
    try:
        events = _collect(manager, lambda ev: any(
            any(s.cpu_percent == 12.5 for s in snap.services) for snap in _snapshots(ev)))
    finally:
        manager.stop()
    snapshot = _snapshots(events)[-1]
    web = next(s for s in snapshot.services if s.name == "shop-web-1")
    assert web.mem_bytes == 100 * 1024 ** 2
    assert [st.name for st in snapshot.stacks()] == ["shop"]
    assert "Podman indisponível" in snapshot.warnings  # modo "on" exige o runtime


def test_monitor_recovers_from_connection_loss_during_collect():
    client = FakeClient(unit_errors=[SSHConnectionError("reset by peer")])
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
    client = FakeClient(unit_errors=[SSHCommandTimeout("lento")] * 3)
    manager = _manager(client)
    manager.start()
    try:
        events = _collect(manager, lambda ev: _count(ev, ConnectionEvent, state=ConnectionState.CONNECTED) >= 2
                          and _count(ev, SnapshotEvent) >= 3)
    finally:
        manager.stop()
    first = _snapshots(events)[0]
    assert any("não respondeu a tempo" in w for w in first.warnings)
    assert client.connect_calls >= 2


def test_monitor_records_history_and_emits_threshold_alerts():
    client = FakeClient()
    client.cpu = 99.0
    history = HistoryStore(None)
    settings = AppSettings(poll_interval_seconds=2.0, thresholds=ThresholdSettings(sustain_polls=2))
    manager = _manager(client, settings=settings, history=history)
    manager.start()
    try:
        events = _collect(manager, lambda ev: _count(ev, ThresholdAlertEvent) >= 1)
    finally:
        manager.stop()
    alert = next(e for e in events if isinstance(e, ThresholdAlertEvent))
    assert (alert.metric, alert.value, alert.recovered) == ("cpu", 99.0, False)
    series = history.query("srv", 3600)
    assert len(series) >= 1 and series.values["cpu"][-1] == pytest.approx(99.0)


def test_actions_emit_results_and_fetch_logs():
    client = FakeClient()
    manager = _manager(client, process_actions=True)
    manager.start()
    try:
        _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 1)
        service = client.units[0]
        result = manager.run_action("srv", service, ServiceAction.RESTART).result(timeout=5)
        assert result.outcome is ActionOutcome.OK
        stack = Stack("shop", ServiceKind.DOCKER, (svc("web", kind=ServiceKind.DOCKER),))
        assert manager.run_stack_action("srv", stack, ServiceAction.STOP).result(timeout=5).outcome is ActionOutcome.OK
        assert manager.kill_process("srv", 1234, True).result(timeout=5).outcome is ActionOutcome.OK
        assert client.actions == [("nginx.service", ServiceAction.RESTART), ("shop", ServiceAction.STOP), (1234, True)]
        events = _collect(manager, lambda ev: _count(ev, ActionResultEvent) >= 3)
        keys = [e.busy_key for e in events if isinstance(e, ActionResultEvent)]
        assert keys == ["systemd:nginx.service", "docker:shop", "pid:1234"]
        assert manager.fetch_logs("srv", service, 25).result(timeout=5) == "25 linhas de nginx.service"
        assert manager.fetch_stack_logs("srv", stack, 25).result(timeout=5) == "stack shop"
        assert manager.logs_command("srv", service, 10) == "logs nginx.service"
    finally:
        manager.stop()


def test_run_action_when_disconnected_returns_error():
    client = FakeClient()
    manager = _manager(client)  # não iniciado: cliente nunca conectou
    result = manager.run_action("srv", client.units[0], ServiceAction.STOP).result(timeout=5)
    assert result.outcome is ActionOutcome.ERROR
    assert "desconectado" in result.message
    with pytest.raises(SSHConnectionError):
        manager.fetch_logs("srv", client.units[0], 10).result(timeout=5)
    manager.stop()


# ---------------------------------------------------------------------------
# v3: segurança, VPS, latência, endpoints e fail2ban
# ---------------------------------------------------------------------------

def test_monitor_security_vps_latency_and_host_alerts():
    client = FakeClient()
    manager = _manager(client)
    manager.start()
    try:
        events = _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 3)
    finally:
        manager.stop()
    snapshot = _snapshots(events)[-1]
    assert snapshot.vps.provider == "Hetzner Cloud"
    assert snapshot.latency_ms == 12.5 and snapshot.latency_method == "SSH"
    assert snapshot.security is not None and snapshot.security.check("ssh_root").level.value == "fail"
    assert snapshot.smart.state is RuntimeState.NOT_INSTALLED and snapshot.warnings == ()
    assert snapshot.system.ssh_failed_logins_24h == 5
    assert client.calls["security"] == 1 and client.calls["ssh_logins"] == 1 and client.calls["smart"] == 1
    assert "fail2ban" not in client.calls  # sem security_sudo o fail2ban-client não é consultado
    alerts = [e for e in events if isinstance(e, HostAlertEvent)]
    assert [(a.category, a.key) for a in alerts] == [("security", "srv:security:ssh_root")]


def test_monitor_skips_security_when_disabled_and_queries_fail2ban_with_sudo():
    client = FakeClient()
    manager = _manager(client, security=False, smart="off")
    manager.start()
    try:
        _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 2)
    finally:
        manager.stop()
    assert not {"security", "ssh_logins", "smart", "fail2ban"} & set(client.calls)

    client = FakeClient()
    manager = _manager(client, security_sudo=True, security_actions=True)
    manager.start()
    try:
        _collect(manager, lambda ev: _count(ev, SnapshotEvent) >= 1)
        result = manager.fail2ban_action("srv", "sshd", "203.0.113.9", True).result(timeout=5)
    finally:
        manager.stop()
    assert client.calls["fail2ban"] >= 1  # a ação força nova coleta completa
    assert result.outcome is ActionOutcome.OK and ("sshd", "203.0.113.9", True) in client.actions


def test_monitor_checks_endpoints_in_background():
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = FakeClient()
    manager = _manager(client, endpoints=(f"http://127.0.0.1:{server.server_address[1]}/",))
    manager.start()
    try:
        events = _collect(manager, lambda ev: any(snap.endpoints for snap in _snapshots(ev)))
    finally:
        manager.stop()
        server.shutdown()
    snapshot = next(snap for snap in _snapshots(events) if snap.endpoints)
    (result,) = snapshot.endpoints
    assert result.status is ServiceStatus.FAILED and result.http_status == 503
    assert snapshot.failing_endpoints() == [result]
    alerts = [e for e in events if isinstance(e, HostAlertEvent) and e.category == "endpoint"]
    assert [a.level for a in alerts] == ["critical"]  # emitido junto com o snapshot
