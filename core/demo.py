"""Modo demonstração (``main.py --demo``): servidores simulados, sem SSH.

Útil para conhecer a interface, testar notificações e gerar capturas de tela.
Implementa a mesma interface de :class:`core.ssh_client.SSHClient`.
"""

from __future__ import annotations

import random
import threading
import time

from config.settings import AppSettings, Config, NotificationSettings, ServerConfig
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
from core.ssh_client import SSHConnectionError, classify_docker, classify_systemd

_SYSTEMD_UNITS = [
    ("nginx.service", "A high performance web server and a reverse proxy server"),
    ("postgresql@16-main.service", "PostgreSQL Cluster 16-main"),
    ("redis-server.service", "Advanced key-value store"),
    ("ssh.service", "OpenBSD Secure Shell server"),
    ("cron.service", "Regular background program processing daemon"),
    ("docker.service", "Docker Application Container Engine"),
    ("containerd.service", "containerd container runtime"),
    ("systemd-journald.service", "Journal Service"),
    ("systemd-resolved.service", "Network Name Resolution"),
    ("systemd-timesyncd.service", "Network Time Synchronization"),
    ("rsyslog.service", "System Logging Service"),
    ("fail2ban.service", "Fail2Ban Service"),
    ("node-exporter.service", "Prometheus Node Exporter"),
    ("celery-worker.service", "Celery background workers"),
    ("gunicorn.service", "Gunicorn application server"),
    ("unattended-upgrades.service", "Unattended Upgrades Shutdown"),
    ("apt-daily.service", "Daily apt download activities"),
    ("logrotate.service", "Rotate log files"),
    ("ufw.service", "Uncomplicated firewall"),
    ("snapd.service", "Snap Daemon"),
]
_CONTAINERS = [
    ("api", "ghcr.io/acme/api:2.14.1"),
    ("worker", "ghcr.io/acme/worker:2.14.1"),
    ("traefik", "traefik:v3.1"),
    ("grafana", "grafana/grafana:11.2.0"),
    ("prometheus", "prom/prometheus:v2.54.1"),
    ("backup-job", "restic/restic:0.17.1"),
]
_ONESHOT = {"apt-daily.service", "logrotate.service", "unattended-upgrades.service"}


def demo_config() -> Config:
    settings = AppSettings(poll_interval_seconds=3.0,
                           notifications=NotificationSettings(cooldown_seconds=30))
    servers = (
        ServerConfig(name="prod-web-01", host="10.0.10.21", username="monitor",
                     critical_services=("nginx", "postgresql*", "redis*", "docker:api", "docker:worker")),
        ServerConfig(name="prod-db-01", host="10.0.10.31", username="monitor",
                     critical_services=("postgresql*",)),
        ServerConfig(name="legacy-erp", host="offline.demo.invalid", username="monitor"),
    )
    return Config(settings=settings, servers=servers)


class DemoClient:
    def __init__(self, server: ServerConfig, settings: AppSettings) -> None:
        self.server = server
        self._rng = random.Random(server.name)
        self._connected = False
        self._lock = threading.Lock()
        self._polls = 0
        self._cpu = self._rng.uniform(10, 35)
        self._mem = self._rng.uniform(0.35, 0.6)
        self._units: dict[str, list[str]] = {}
        for name, description in _SYSTEMD_UNITS:
            if name in _ONESHOT:
                state = ["inactive", "dead"]
            else:
                state = ["active", "running"]
            self._units[name] = [state[0], state[1], description]
        self._units["snapd.service"][:2] = ["inactive", "dead"]
        self._containers = {name: ["running", "Up 3 days", image] for name, image in _CONTAINERS}
        self._containers["backup-job"][:2] = ["exited", "Exited (0) 6 hours ago"]
        if server.name == "prod-web-01":
            self._units["celery-worker.service"][:2] = ["failed", "failed"]

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        time.sleep(0.4)
        if self.server.host.endswith(".invalid"):
            raise SSHConnectionError(f"Não foi possível conectar a {self.server.host}:22: tempo esgotado (simulado)")
        self._connected = True

    def close(self) -> None:
        self._connected = False

    def list_services(self) -> list[ServiceInfo]:
        with self._lock:
            self._polls += 1
            self._evolve()
            return [
                ServiceInfo(ServiceKind.SYSTEMD, name, description, classify_systemd(active, sub),
                            active, sub, "loaded")
                for name, (active, sub, description) in self._units.items()
            ]

    def list_containers(self) -> DockerResult:
        with self._lock:
            return DockerResult(DockerState.OK, tuple(
                ServiceInfo(ServiceKind.DOCKER, name, image, classify_docker(state, status), state, status)
                for name, (state, status, image) in self._containers.items()
            ))

    def host_metrics(self) -> HostMetrics:
        self._cpu = max(2.0, min(98.0, self._cpu + self._rng.uniform(-8, 8)))
        self._mem = max(0.2, min(0.95, self._mem + self._rng.uniform(-0.02, 0.02)))
        total = 15_872
        gib = 1024 * 1024
        return HostMetrics(
            uptime_seconds=1_234_567 + self._polls * 3,
            load_avg=(self._cpu / 25, self._cpu / 28, self._cpu / 30),
            cpu_count=4,
            cpu_percent=self._cpu,
            mem_total_mb=total,
            mem_used_mb=int(total * self._mem),
            mem_available_mb=int(total * (1 - self._mem)),
            swap_total_mb=2047,
            swap_used_mb=112,
            disks=(
                DiskUsage("/dev/sda1", "/", 80 * gib, 51 * gib, 29 * gib, 64.0),
                DiskUsage("/dev/sdb1", "/var/lib/postgresql", 200 * gib, 172 * gib, 28 * gib, 86.0),
            ),
        )

    def service_action(self, service: ServiceInfo, action: ServiceAction) -> ActionResult:
        time.sleep(0.6)
        with self._lock:
            if service.kind is ServiceKind.DOCKER:
                entry = self._containers[service.name]
                entry[:2] = (["exited", "Exited (0) 1 second ago"] if action is ServiceAction.STOP
                             else ["running", "Up 1 second"])
            else:
                entry = self._units[service.name]
                entry[:2] = ["inactive", "dead"] if action is ServiceAction.STOP else ["activating", "start"]
        return ActionResult(ActionOutcome.OK, f"{action.label} {service.name}: solicitado (demo).")

    def service_logs(self, service: ServiceInfo, lines: int) -> str:
        time.sleep(0.3)
        now = time.time()
        rows = []
        for i in range(lines):
            stamp = time.strftime("%b %d %H:%M:%S", time.localtime(now - (lines - i) * 17))
            level = "ERROR" if service.status is ServiceStatus.FAILED and i > lines - 4 else "INFO"
            rows.append(f"{stamp} {self.server.name} {service.name.split('.')[0]}[{1200 + i}]: "
                        f"{level} request handled in {self._rng.randint(3, 250)}ms")
        return "\n".join(rows)

    def _evolve(self) -> None:
        # "activating" vira "running" na coleta seguinte.
        for entry in self._units.values():
            if entry[0] == "activating":
                entry[:2] = ["active", "running"]
        # A cada ~20 coletas um serviço crítico falha no prod-web-01 (exercita os alertas).
        if self.server.name == "prod-web-01" and self._polls % 20 == 10:
            self._units["redis-server.service"][:2] = ["failed", "failed"]
        if self.server.name == "prod-web-01" and self._polls % 20 == 15:
            self._units["redis-server.service"][:2] = ["active", "running"]


def demo_client_factory(server: ServerConfig, settings: AppSettings) -> DemoClient:
    return DemoClient(server, settings)
