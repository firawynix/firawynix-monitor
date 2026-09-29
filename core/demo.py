"""Modo demonstração (``main.py --demo``): servidores simulados, sem SSH.

Útil para conhecer a interface, testar notificações e gerar capturas de tela.
Implementa a mesma interface de :class:`core.ssh_client.SSHClient` e exercita
todos os tipos de carga: systemd, Docker Compose, Podman, Kubernetes e VMs.
"""

from __future__ import annotations

import math
import random
import threading
import time

from config.settings import AppSettings, Config, NotificationSettings, ServerConfig
from core import commands as cmd
from core.history import HistoryStore
from core.models import (
    ActionOutcome,
    ActionResult,
    CronEntry,
    DiskIO,
    DiskUsage,
    HostMetrics,
    InterfaceStats,
    JournalEntry,
    ListeningSocket,
    NetworkInfo,
    ProcessInfo,
    RuntimeResult,
    RuntimeState,
    ServiceAction,
    ServiceInfo,
    ServiceKind,
    Stack,
    SystemInfo,
    TimerInfo,
    UpdatesInfo,
)
from core.parsers import classify_container, classify_pod, classify_systemd, classify_vm
from core.ssh_client import SSHConnectionError

MIB = 1024 ** 2

_COMMON_UNITS = [
    ("ssh.service", "OpenBSD Secure Shell server"),
    ("cron.service", "Regular background program processing daemon"),
    ("systemd-journald.service", "Journal Service"),
    ("systemd-resolved.service", "Network Name Resolution"),
    ("systemd-timesyncd.service", "Network Time Synchronization"),
    ("rsyslog.service", "System Logging Service"),
    ("fail2ban.service", "Fail2Ban Service"),
    ("node-exporter.service", "Prometheus Node Exporter"),
    ("unattended-upgrades.service", "Unattended Upgrades Shutdown"),
    ("apt-daily.service", "Daily apt download activities"),
    ("logrotate.service", "Rotate log files"),
    ("apt-daily.timer", "Daily apt download activities"),
    ("logrotate.timer", "Daily rotation of log files"),
    ("fstrim.timer", "Discard unused blocks once a week"),
    ("certbot.timer", "Run certbot twice daily"),
    ("backup-nightly.timer", "Nightly restic backup"),
    ("ssh.socket", "OpenBSD Secure Shell server socket"),
    ("systemd-journald.socket", "Journal Socket"),
    ("-.mount", "Root Mount"),
    ("boot.mount", "/boot"),
    ("systemd-ask-password-wall.path", "Forward Password Requests to Wall Directory Watch"),
]
_ONESHOT = {"apt-daily.service", "logrotate.service", "unattended-upgrades.service"}

_SERVER_UNITS = {
    "prod-web-01": [
        ("nginx.service", "A high performance web server and a reverse proxy server"),
        ("docker.service", "Docker Application Container Engine"),
        ("containerd.service", "containerd container runtime"),
        ("celery-worker.service", "Celery background workers"),
        ("gunicorn.service", "Gunicorn application server"),
        ("docker.socket", "Docker Socket for the API"),
    ],
    "prod-db-01": [
        ("postgresql@16-main.service", "PostgreSQL Cluster 16-main"),
        ("pgbackrest.service", "pgBackRest archive push"),
        ("podman.socket", "Podman API Socket"),
        ("var-lib-postgresql.mount", "/var/lib/postgresql"),
        ("pg-backup.timer", "Hourly WAL backup"),
    ],
    "k3s-edge": [
        ("k3s.service", "Lightweight Kubernetes"),
        ("containerd.service", "containerd container runtime"),
        ("iscsid.socket", "Open-iSCSI iscsid Socket"),
    ],
    "hv-01": [
        ("libvirtd.service", "Virtualization daemon"),
        ("virtlogd.service", "Virtual machine log manager"),
        ("libvirtd.socket", "Libvirt local socket"),
        ("ksm.service", "Kernel Samepage Merging"),
    ],
}

_DOCKER = {
    "prod-web-01": [
        ("shop-api-1", "ghcr.io/acme/shop-api:2.14.1", "shop", "api"),
        ("shop-worker-1", "ghcr.io/acme/shop-worker:2.14.1", "shop", "worker"),
        ("shop-worker-2", "ghcr.io/acme/shop-worker:2.14.1", "shop", "worker"),
        ("shop-redis-1", "redis:7.4-alpine", "shop", "redis"),
        ("edge-traefik-1", "traefik:v3.1", "edge", "traefik"),
        ("monitoring-grafana-1", "grafana/grafana:11.2.0", "monitoring", "grafana"),
        ("monitoring-prometheus-1", "prom/prometheus:v2.54.1", "monitoring", "prometheus"),
        ("monitoring-loki-1", "grafana/loki:3.1.1", "monitoring", "loki"),
        ("backup-job", "restic/restic:0.17.1", "", ""),
    ],
}
_PODMAN = {
    "prod-db-01": [
        ("pgbouncer", "docker.io/edoburu/pgbouncer:1.23", "db-sidecars"),
        ("postgres-exporter", "quay.io/prometheuscommunity/postgres-exporter:v0.15", "db-sidecars"),
        ("pgadmin", "docker.io/dpage/pgadmin4:8.11", ""),
    ],
}
_PODS = [
    ("kube-system", "coredns-7b98449c4-x2k9d", "ReplicaSet"),
    ("kube-system", "local-path-provisioner-6795b5f9d8-4qz7m", "ReplicaSet"),
    ("kube-system", "metrics-server-cdcc87586-j8r2t", "ReplicaSet"),
    ("kube-system", "traefik-d7c9c5778-pl5wx", "ReplicaSet"),
    ("prod", "storefront-6c8d9f7b5-2hxkq", "ReplicaSet"),
    ("prod", "storefront-6c8d9f7b5-9zv4n", "ReplicaSet"),
    ("prod", "checkout-5f7b8c6d4-tt8wr", "ReplicaSet"),
    ("prod", "payments-7d4f5b9c8-kq2mz", "ReplicaSet"),
    ("prod", "nightly-report-28791440-6hk2p", "Job"),
    ("monitoring", "prometheus-0", "StatefulSet"),
    ("monitoring", "alertmanager-0", "StatefulSet"),
]
_VMS = [("win2022-ad", "running"), ("ubuntu-ci-runner", "running"), ("pfsense-lab", "running"),
        ("legacy-centos7", "shut off"), ("kali-sandbox", "paused")]

_PORTS = {
    "prod-web-01": [(22, "sshd"), (80, "nginx"), (443, "nginx"), (8080, "traefik"), (9100, "node_exporter"),
                    (3000, "grafana"), (9090, "prometheus"), (6379, "redis-server")],
    "prod-db-01": [(22, "sshd"), (5432, "postgres"), (6432, "pgbouncer"), (9187, "postgres_export"),
                   (9100, "node_exporter")],
    "k3s-edge": [(22, "sshd"), (6443, "k3s-server"), (10250, "k3s-server"), (80, "traefik"), (443, "traefik")],
    "hv-01": [(22, "sshd"), (16509, "libvirtd"), (5900, "qemu-system-x86"), (5901, "qemu-system-x86")],
}
_PROCESS_NAMES = {
    "prod-web-01": ["gunicorn", "celery", "nginx", "dockerd", "containerd", "node", "redis-server", "traefik",
                    "grafana", "prometheus", "loki", "python3"],
    "prod-db-01": ["postgres", "postgres", "postgres", "pgbouncer", "pgbackrest", "conmon", "postgres_exporter"],
    "k3s-edge": ["k3s-server", "containerd", "coredns", "traefik", "java", "node", "prometheus"],
    "hv-01": ["qemu-system-x86", "qemu-system-x86", "qemu-system-x86", "libvirtd", "virtlogd", "ksmd"],
}
_COMMON_PROCESSES = ["systemd-journal", "sshd", "rsyslogd", "cron", "systemd-resolve", "fail2ban-server",
                     "node_exporter", "bash", "agetty"]
_PROCESS_USERS = {"postgres": "postgres", "nginx": "www-data", "gunicorn": "app", "celery": "app",
                  "grafana": "472", "redis-server": "redis"}


def demo_config() -> Config:
    settings = AppSettings(poll_interval_seconds=3.0, detail_interval_seconds=6.0, inventory_interval_seconds=30.0,
                           notifications=NotificationSettings(cooldown_seconds=30))
    servers = (
        ServerConfig(name="prod-web-01", host="10.0.10.21", username="monitor",
                     critical_services=("nginx", "gunicorn", "celery*", "docker:shop-*", "docker:edge-*")),
        ServerConfig(name="prod-db-01", host="10.0.10.31", username="monitor",
                     critical_services=("postgresql*", "podman:pgbouncer")),
        ServerConfig(name="k3s-edge", host="10.0.20.11", username="monitor", process_actions=True,
                     critical_services=("k3s", "k8s:prod/*")),
        ServerConfig(name="hv-01", host="10.0.30.5", username="monitor",
                     critical_services=("libvirtd", "vm:win2022-ad", "vm:pfsense-lab")),
        ServerConfig(name="legacy-erp", host="offline.demo.invalid", username="monitor"),
    )
    return Config(settings=settings, servers=servers)


class DemoClient:
    def __init__(self, server: ServerConfig, settings: AppSettings) -> None:
        self.server = server
        self.name = server.name
        self._rng = random.Random(server.name)
        self._connected = False
        self._lock = threading.Lock()
        self._polls = 0
        self._cpu = self._rng.uniform(12, 35)
        self._mem = self._rng.uniform(0.4, 0.65)
        self._rx_total = self._rng.randint(10 ** 9, 10 ** 11)
        self._tx_total = self._rng.randint(10 ** 9, 10 ** 11)
        self._units: dict[str, list[str]] = {}
        for name, description in _COMMON_UNITS + _SERVER_UNITS.get(server.name, []):
            if name in _ONESHOT:
                state = ["inactive", "dead"]
            elif name.endswith(".timer"):
                state = ["active", "waiting"]
            elif name.endswith(".socket"):
                state = ["active", "listening"]
            elif name.endswith(".path"):
                state = ["active", "waiting"]
            elif name.endswith(".mount"):
                state = ["active", "mounted"]
            else:
                state = ["active", "running"]
            self._units[name] = [*state, description]
        if server.name == "prod-web-01":
            self._units["celery-worker.service"][:2] = ["failed", "failed"]
        self._docker = {name: ["running", "Up 3 days", image, group, service]
                        for name, image, group, service in _DOCKER.get(server.name, [])}
        if "backup-job" in self._docker:
            self._docker["backup-job"][:2] = ["exited", "Exited (0) 6 hours ago"]
        if "monitoring-loki-1" in self._docker:
            self._docker["monitoring-loki-1"][:2] = ["restarting", "Restarting (1) 12 seconds ago"]
        self._podman = {name: ["running", "Up 12 days", image, pod]
                        for name, image, pod in _PODMAN.get(server.name, [])}
        if "pgadmin" in self._podman:
            self._podman["pgadmin"][:2] = ["exited", "Exited (0) 2 days ago"]
        self._pods: dict[str, list] = {}
        if server.name == "k3s-edge":
            for ns, pod, owner in _PODS:
                self._pods[f"{ns}/{pod}"] = ["Running", ["true"], 0, "", owner]
            self._pods["prod/payments-7d4f5b9c8-kq2mz"] = ["Running", ["false"], 14, "CrashLoopBackOff", "ReplicaSet"]
            self._pods["prod/nightly-report-28791440-6hk2p"] = ["Succeeded", ["false"], 0, "", "Job"]
        self._vms = dict(_VMS) if server.name == "hv-01" else {}
        self._processes = self._make_processes()

    # -- conexão ----------------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        time.sleep(0.3)
        if self.server.host.endswith(".invalid"):
            raise SSHConnectionError(f"Não foi possível conectar a {self.server.host}:22: tempo esgotado (simulado)")
        self._connected = True

    def close(self) -> None:
        self._connected = False

    # -- coleta -----------------------------------------------------------------

    def list_units(self) -> list[ServiceInfo]:
        with self._lock:
            self._polls += 1
            self._evolve()
            return [ServiceInfo(ServiceKind.SYSTEMD, name, description, classify_systemd(active), active, sub,
                                "loaded")
                    for name, (active, sub, description) in self._units.items()]

    def service_resources(self) -> dict[str, tuple[float | None, int | None]]:
        rng = random.Random(self._polls)
        return {name: (rng.uniform(0, 8), rng.randint(8, 900) * MIB)
                for name, (active, _sub, _desc) in self._units.items()
                if name.endswith(".service") and active == "active"}

    def list_containers(self, runtime: ServiceKind) -> RuntimeResult:
        with self._lock:
            if runtime is ServiceKind.DOCKER:
                if not self._docker:
                    return RuntimeResult(runtime, RuntimeState.NOT_INSTALLED, (), "Docker não instalado neste host.")
                items = tuple(
                    ServiceInfo(ServiceKind.DOCKER, name, image, classify_container(state, status), state, status,
                                group=group, meta=(("working_dir", f"/opt/{group}"),
                                                   ("config_files", f"/opt/{group}/compose.yaml"),
                                                   ("compose_service", service)) if group else ())
                    for name, (state, status, image, group, service) in self._docker.items())
            else:
                if not self._podman:
                    return RuntimeResult(runtime, RuntimeState.NOT_INSTALLED, (), "Podman não instalado neste host.")
                items = tuple(
                    ServiceInfo(ServiceKind.PODMAN, name, image, classify_container(state, status), state, status,
                                group=pod, meta=(("pod", pod),) if pod else ())
                    for name, (state, status, image, pod) in self._podman.items())
            return RuntimeResult(runtime, RuntimeState.OK, items)

    def container_stats(self, runtime: ServiceKind) -> dict[str, tuple[float | None, int | None]]:
        names = self._docker if runtime is ServiceKind.DOCKER else self._podman
        rng = random.Random(self._polls * 7)
        return {name: (rng.uniform(0.2, 35), rng.randint(40, 1400) * MIB) for name in names}

    def list_pods(self) -> RuntimeResult:
        kind = ServiceKind.KUBERNETES
        if not self._pods:
            return RuntimeResult(kind, RuntimeState.NOT_INSTALLED, (), "Kubernetes não instalado neste host.")
        items = []
        with self._lock:
            for ref, (phase, ready, restarts, reason, owner) in self._pods.items():
                ready_count = sum(r == "true" for r in ready)
                sub = f"{ready_count}/{len(ready)} prontos · {restarts} reinício{'s' if restarts != 1 else ''}"
                if reason:
                    sub = f"{reason} · {sub}"
                items.append(ServiceInfo(kind, ref, f"{owner} · nó k3s-edge",
                                         classify_pod(phase, ready, [reason] if reason else [], False),
                                         phase, sub, group=ref.split("/", 1)[0], meta=(("node", "k3s-edge"),)))
        return RuntimeResult(kind, RuntimeState.OK, tuple(items))

    def list_vms(self) -> RuntimeResult:
        kind = ServiceKind.LIBVIRT
        if not self._vms:
            return RuntimeResult(kind, RuntimeState.NOT_INSTALLED, (), "libvirt não instalado neste host.")
        with self._lock:
            return RuntimeResult(kind, RuntimeState.OK, tuple(
                ServiceInfo(kind, name, "domínio libvirt (KVM)", classify_vm(state), state, state)
                for name, state in self._vms.items()))

    def host_metrics(self) -> HostMetrics:
        self._cpu = max(3.0, min(97.0, self._cpu + self._rng.uniform(-7, 7)))
        self._mem = max(0.25, min(0.93, self._mem + self._rng.uniform(-0.02, 0.02)))
        rx, tx = self._rng.uniform(2e5, 6e6), self._rng.uniform(1e5, 3e6)
        self._rx_total += int(rx * 3)
        self._tx_total += int(tx * 3)
        total = 32_000 if self.name == "hv-01" else 15_872
        root_pct = 41.0 if self.name == "hv-01" else 64.0
        size = 80 * 1024 ** 2
        disks = [DiskUsage("/dev/sda1", "/", size, int(size * root_pct / 100), int(size * (1 - root_pct / 100)),
                           root_pct, 7.0)]
        if self.name == "prod-db-01":
            disks.append(DiskUsage("/dev/sdb1", "/var/lib/postgresql", 400 * 1024 ** 2, 369 * 1024 ** 2,
                                   31 * 1024 ** 2, 92.0, 3.0))
        if self.name == "hv-01":
            disks.append(DiskUsage("/dev/nvme0n1p1", "/var/lib/libvirt/images", 1800 * 1024 ** 2,
                                   1220 * 1024 ** 2, 580 * 1024 ** 2, 68.0, 1.0))
        return HostMetrics(
            uptime_seconds=1_234_567 + self._polls * 3,
            load_avg=(self._cpu / 25, self._cpu / 28, self._cpu / 30),
            cpu_count=16 if self.name == "hv-01" else 4,
            cpu_percent=self._cpu,
            mem_total_mb=total,
            mem_used_mb=int(total * self._mem),
            mem_available_mb=int(total * (1 - self._mem)),
            swap_total_mb=2047,
            swap_used_mb=112,
            disks=tuple(disks),
            interfaces=(
                InterfaceStats("eth0", self._rx_total, self._tx_total, rx, tx),
                InterfaceStats("lo", 10 ** 8, 10 ** 8, 2e4, 2e4, virtual=True),
                InterfaceStats("docker0", 10 ** 7, 10 ** 7, 5e4, 3e4, virtual=True),
            ),
            disk_io=(DiskIO("sda", self._rng.uniform(1e4, 4e6), self._rng.uniform(5e4, 8e6)),),
        )

    def processes(self) -> list[ProcessInfo]:
        rng = random.Random(self._polls)
        busy = set(_PROCESS_NAMES.get(self.name, []))
        result = []
        for pid, user, name, args, rss, elapsed in self._processes:
            cpu = rng.expovariate(1 / 3) if name in busy else rng.uniform(0, 0.4)
            result.append(ProcessInfo(pid, user, min(cpu, 180.0), round(rss / 16_000_000 * 100, 1), rss, elapsed,
                                      "R" if cpu > 5 else "S", name, args))
        return sorted(result, key=lambda p: -(p.cpu_percent or 0))

    def network(self) -> NetworkInfo:
        ports = _PORTS.get(self.name, [(22, "sshd")])
        listening = tuple(ListeningSocket("tcp", "127.0.0.1" if port in (6379, 9090) else "0.0.0.0", port,
                                          process, 1000 + i) for i, (port, process) in enumerate(ports))
        listening += (ListeningSocket("udp", "127.0.0.53", 53, "systemd-resolve", 512),)
        return NetworkInfo(listening=listening, tcp_inuse=40 + self._polls % 25, tcp_timewait=12, udp_inuse=3)

    def timers(self) -> list[TimerInfo]:
        now = time.time()
        timers = [(name, active, description) for name, (active, _sub, description) in self._units.items()
                  if name.endswith(".timer")]
        return [TimerInfo(name=name, activates=name.replace(".timer", ".service"),
                          next_run=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now + 1800 * (i + 1))),
                          last_run=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now - 3600 * (i + 2))),
                          active_state=active, description=description)
                for i, (name, active, description) in enumerate(timers)]

    def cron(self) -> list[CronEntry]:
        return [
            CronEntry("/etc/crontab", "17 * * * *", "root", "cd / && run-parts --report /etc/cron.hourly"),
            CronEntry("/etc/cron.d/certbot", "0 */12 * * *", "root", "certbot -q renew --no-random-sleep-on-renew"),
            CronEntry("/etc/cron.d/app", "*/5 * * * *", "www-data", "/opt/app/bin/cleanup-sessions"),
            CronEntry("crontab do usuário", "@reboot", "monitor", "/home/monitor/bin/notify-boot.sh"),
            CronEntry("/etc/cron.daily", "@daily", "root", "/etc/cron.daily/logrotate"),
            CronEntry("/etc/cron.daily", "@daily", "root", "/etc/cron.daily/apt-compat"),
            CronEntry("/etc/cron.weekly", "@weekly", "root", "/etc/cron.weekly/man-db"),
        ]

    def journal_events(self, priority: str, limit: int, since_hours: int) -> list[JournalEntry]:
        now = time.time()
        samples = {
            "prod-web-01": [("celery-worker.service", "celery", 3, "Worker exited prematurely: signal 9 (SIGKILL)."),
                            ("nginx.service", "nginx", 3, "upstream timed out (110: Connection timed out) while "
                                                          "reading response header from upstream"),
                            ("docker.service", "dockerd", 3, "Container monitoring-loki-1 exited with code 1")],
            "prod-db-01": [("postgresql@16-main.service", "postgres", 3,
                            "could not extend file \"base/16384/2619\": No space left on device"),
                           ("pgbackrest.service", "pgbackrest", 2, "archive-push command end: aborted with exception")],
            "k3s-edge": [("k3s.service", "k3s", 3, "Error syncing pod prod/payments-7d4f5b9c8-kq2mz: "
                                                   "CrashLoopBackOff: back-off 5m0s restarting failed container")],
            "hv-01": [("libvirtd.service", "libvirtd", 3, "internal error: End of file from qemu monitor")],
        }.get(self.name, [("kernel", "kernel", 3, "demo")])
        entries = [JournalEntry(now - i * 1900 - 120, samples[i % len(samples)][2], samples[i % len(samples)][0],
                                samples[i % len(samples)][1], samples[i % len(samples)][3]) for i in range(12)]
        return entries[:limit]

    def system_info(self) -> tuple[SystemInfo, dict[str, float]]:
        os_name = {"hv-01": "Debian GNU/Linux 12 (bookworm)", "k3s-edge": "Rocky Linux 9.4 (Blue Onyx)"}.get(
            self.name, "Ubuntu 24.04.1 LTS")
        return SystemInfo(
            hostname=self.name, os_name=os_name, kernel="6.8.0-45-generic", arch="x86_64",
            cpu_model="AMD EPYC 7543P 32-Core Processor" if self.name == "hv-01" else "Intel(R) Xeon(R) Silver 4314",
            virtualization="none" if self.name == "hv-01" else "kvm", boot_time="2026-09-14 06:12:03",
            timezone="America/Sao_Paulo", logged_users=1, reboot_required=self.name == "prod-web-01",
            ip_addresses=(self.server.host, "172.17.0.1") if self.name == "prod-web-01" else (self.server.host,),
            failed_units=sum(1 for unit in self._units.values() if unit[0] == "failed"),
            temperatures=(("x86_pkg_temp", 54.0), ("acpitz", 41.0)) if self.name == "hv-01" else (),
            journal_access=True,
        ), {}

    def ssh_failed_logins(self) -> int | None:
        return {"prod-web-01": 1432, "k3s-edge": 12}.get(self.name, 0)

    def updates(self) -> UpdatesInfo | None:
        return {"prod-web-01": UpdatesInfo("apt", 23, 7), "prod-db-01": UpdatesInfo("apt", 4, 1),
                "k3s-edge": UpdatesInfo("dnf", 11), "hv-01": UpdatesInfo("apt", 0, 0)}.get(self.name)

    # -- ações ------------------------------------------------------------------

    def service_action(self, service: ServiceInfo, action: ServiceAction) -> ActionResult:
        time.sleep(0.5)
        stop = action is ServiceAction.STOP
        container_state = ["exited", "Exited (0) 1 second ago"] if stop else ["running", "Up 1 second"]
        with self._lock:
            if service.kind is ServiceKind.SYSTEMD:
                self._units[service.name][:2] = ["inactive", "dead"] if stop else ["activating", "start"]
            elif service.kind is ServiceKind.DOCKER:
                self._docker[service.name][:2] = container_state
            elif service.kind is ServiceKind.PODMAN:
                self._podman[service.name][:2] = container_state
            elif service.kind is ServiceKind.KUBERNETES:
                self._pods[service.name][:4] = ["Running", ["true"], 0, ""]
            else:
                self._vms[service.name] = "in shutdown" if stop else "running"
        return ActionResult(ActionOutcome.OK, f"{action.label}: {service.name} — solicitado (demo).")

    def stack_action(self, stack: Stack, action: ServiceAction) -> ActionResult:
        for member in stack.members:
            self.service_action(member, action)
        return ActionResult(ActionOutcome.OK, f"{action.label}: stack {stack.name} — solicitado (demo).")

    def kill_process(self, pid: int, force: bool) -> ActionResult:
        self._processes = [p for p in self._processes if p[0] != pid]
        return ActionResult(ActionOutcome.OK, f"{'KILL' if force else 'TERM'} enviado ao PID {pid} (demo).")

    # -- logs ---------------------------------------------------------------------

    def logs_command(self, service: ServiceInfo, lines: int) -> str:
        if service.kind is ServiceKind.SYSTEMD:
            return cmd.build_journal_command(service.name, lines, False)
        if service.kind.is_container:
            return cmd.build_container_logs_command(service.kind.value, service.name, lines, False)
        if service.kind is ServiceKind.KUBERNETES:
            return cmd.build_pod_logs_command("kubectl", service.name, lines, False)
        return cmd.build_vm_info_command("qemu:///system", service.name, False)

    def service_logs(self, service: ServiceInfo, lines: int) -> str:
        time.sleep(0.2)
        if service.kind is ServiceKind.LIBVIRT:
            return (f"Id:             3\nName:           {service.name}\nOS Type:        hvm\n"
                    f"State:          {service.active_state}\nCPU(s):         4\nMax memory:     8388608 KiB\n"
                    "Autostart:      enable\n\n Target   Source\n------------------------------------------------\n"
                    f" vda      /var/lib/libvirt/images/{service.name}.qcow2")
        now = time.time()
        failing = service.status.value == "failed"
        short = service.name.split("/")[-1].split(".")[0]
        rows = []
        for i in range(lines):
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - (lines - i) * 17))
            level = "ERROR" if failing and i > lines - 4 else "INFO"
            rows.append(f"{stamp} {self.name} {short}[{1200 + i}]: {level} request handled in "
                        f"{self._rng.randint(3, 250)}ms")
        return "\n".join(rows)

    def stack_logs(self, stack: Stack, lines: int) -> str:
        per = max(5, lines // max(1, len(stack.members)))
        return "\n\n".join(f"===== {m.name} =====\n{self.service_logs(m, per)}" for m in stack.members)

    # -- simulação -----------------------------------------------------------------

    def _make_processes(self) -> list[tuple[int, str, str, str, int, int]]:
        rng = random.Random(self.name + "proc")
        processes = [(1, "root", "systemd", "/sbin/init", 12_000, 1_300_000)]
        names = _PROCESS_NAMES.get(self.name, []) + _COMMON_PROCESSES
        for i, name in enumerate(names * 2):
            processes.append((200 + i * 37, _PROCESS_USERS.get(name, "root"), name,
                              f"/usr/bin/{name} --config /etc/{name}/{name}.conf",
                              rng.randint(4_000, 2_400_000), rng.randint(60, 1_200_000)))
        return processes

    def _evolve(self) -> None:
        # "activating" vira "running" na coleta seguinte.
        for entry in self._units.values():
            if entry[0] == "activating":
                entry[:2] = ["active", "running"]
        for name, state in list(self._vms.items()):
            if state == "in shutdown":
                self._vms[name] = "shut off"
        # A cada ~20 coletas um serviço crítico falha no prod-web-01 (exercita os alertas).
        if self.name == "prod-web-01" and self._polls % 20 == 10:
            self._units["nginx.service"][:2] = ["failed", "failed"]
        if self.name == "prod-web-01" and self._polls % 20 == 15:
            self._units["nginx.service"][:2] = ["active", "running"]


def demo_client_factory(server: ServerConfig, settings: AppSettings) -> DemoClient:
    return DemoClient(server, settings)


def seed_demo_history(store: HistoryStore, config: Config, hours: float = 24.0, step: float = 120.0) -> None:
    """Preenche o histórico com curvas plausíveis para os gráficos já terem conteúdo."""
    now = time.time()
    for index, server in enumerate(config.servers):
        if server.host.endswith(".invalid"):
            continue
        rng = random.Random(server.name)
        base_cpu, base_mem = rng.uniform(15, 30), rng.uniform(40, 60)
        t = now - hours * 3600
        while t < now - step:
            day = math.sin((t % 86400) / 86400 * 2 * math.pi - index)
            cpu = max(1.0, min(99.0, base_cpu + 18 * day + rng.gauss(0, 4)))
            mem = max(5.0, min(97.0, base_mem + 6 * day + rng.gauss(0, 1)))
            rx = max(0.0, 2.5e6 + 2e6 * day + rng.gauss(0, 4e5))
            disk_pct = 60.0 + 4 * (1 - (now - t) / (hours * 3600))
            metrics = HostMetrics(
                cpu_percent=cpu, mem_total_mb=10_000, mem_used_mb=int(mem * 100), swap_total_mb=2000,
                swap_used_mb=100, load_avg=(cpu / 25, cpu / 28, cpu / 30),
                disks=(DiskUsage("/dev/sda1", "/", 100, 64, 36, disk_pct),),
                interfaces=(InterfaceStats("eth0", 0, 0, rx, rx * 0.45),),
                disk_io=(DiskIO("sda", max(0.0, 1.5e6 + rng.gauss(0, 6e5)), max(0.0, 3e6 + 2e6 * day)),),
            )
            store.record(server.name, t, metrics, failed=1 if rng.random() < 0.05 else 0, active=40)
            t += step
