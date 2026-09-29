"""Modo demonstração (``main.py --demo``): servidores simulados, sem SSH.

Útil para conhecer a interface, testar notificações e gerar capturas de tela.
Implementa a mesma interface de :class:`core.ssh_client.SSHClient` e exercita
todos os tipos de carga: systemd, Docker Compose, Podman, Kubernetes e VMs.
"""

from __future__ import annotations

import json
import math
import random
import shlex
import threading
import time

from config.settings import AppSettings, Config, ConnectorConfig, NotificationSettings, ServerConfig
from core import commands as cmd
from core import containers as engines
from core.history import HistoryStore
from core.models import (
    ActionOutcome,
    ActionResult,
    AuthorizedKey,
    BandwidthUsage,
    BuildContainer,
    ContainerImage,
    ContainerNetwork,
    ContainerVolume,
    DetectedTool,
    EngineDiskUsage,
    ImageUpdate,
    CronEntry,
    DiskIO,
    DiskUsage,
    EndpointResult,
    Fail2banJail,
    FailedLoginSource,
    HostMetrics,
    InterfaceStats,
    JournalEntry,
    ListeningSocket,
    LoginEvent,
    NetworkInfo,
    OomKill,
    ProcessInfo,
    RuntimeResult,
    RuntimeState,
    SecurityRaw,
    ServiceAction,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SessionInfo,
    SmartDisk,
    SmartReport,
    SshLoginReport,
    Stack,
    SudoEvent,
    SystemInfo,
    TimerInfo,
    UpdatesInfo,
    VpsInfo,
)
from core.parsers import classify_container, classify_lxd, classify_pod, classify_systemd, classify_vm
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
        ("portainer", "portainer/portainer-ce:2.21.3", "", ""),
        ("watchtower", "containrrr/watchtower:1.7.1", "", ""),
        ("cloudflared", "cloudflare/cloudflared:2024.9.1", "", ""),
    ],
}
#: depends_on do Compose (rótulo com.docker.compose.depends_on) por serviço.
_DEPENDS = {"api": "redis:service_started:false", "worker": "redis:service_started:false,api:service_started:false",
            "grafana": "prometheus:service_started:false,loki:service_started:false"}
#: Volumes nomeados por contêiner (para a análise de risco e os backups).
_DEMO_VOLUMES = {"shop-redis-1": ("shop_redis-data",), "monitoring-grafana-1": ("monitoring_grafana-data",),
                 "monitoring-prometheus-1": ("monitoring_prometheus-data",), "portainer": ("portainer_data",),
                 "pgbouncer": ("pgbouncer-config",), "site-cache": ("site-cache-data",),
                 "edge-traefik-1": ("edge_letsencrypt",)}
_DEMO_PORTS = {
    "portainer": "0.0.0.0:9443->9443/tcp, [::]:9443->9443/tcp, 8000/tcp",
    "edge-traefik-1": "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp",
    "monitoring-grafana-1": "127.0.0.1:3000->3000/tcp",
    "shop-redis-1": "6379/tcp",
    "pgbouncer": "0.0.0.0:6432->6432/tcp",
    "site-web": "0.0.0.0:8080->80/tcp",
}
#: containerd (nerdctl) e CRI no nó k3s-edge.
_NERDCTL = [("site-web", "docker.io/library/nginx:1.27-alpine", "site", "running", "Up 5 days"),
            ("site-cache", "docker.io/library/redis:7.4", "site", "running", "Up 5 days"),
            ("registry-mirror", "docker.io/library/registry:2", "", "exited", "Exited (0) 3 days ago")]
_CRI = [("coredns", "registry.k8s.io/coredns/coredns:v1.11.3", "kube-system/coredns-7b98449c4-x2k9d", "running", 0),
        ("storefront", "ghcr.io/acme/storefront:4.2.0", "prod/storefront-6c8d9f7b5-2hxkq", "running", 0),
        ("payments", "ghcr.io/acme/payments:1.9.3", "prod/payments-7d4f5b9c8-kq2mz", "exited", 14),
        ("traefik", "rancher/mirrored-library-traefik:2.11.8", "kube-system/traefik-d7c9c5778-pl5wx", "running", 0)]
_ENGINES = {
    "prod-web-01": {"docker": "27.3.1", "skopeo": "1.16.1"},
    "prod-db-01": {"podman": "5.2.2", "buildah": "1.37.3", "skopeo": "1.16.1"},
    "k3s-edge": {"nerdctl": "2.0.0", "crictl": "1.31.0", "kubectl": "1.30.4", "k3s": "1.30.4+k3s1"},
    "hv-01": {"incus": "6.5"},
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
_LXD = [("web-lxc", "Running", "container", "Ubuntu noble amd64", "10.44.0.11"),
        ("gitea", "Running", "container", "Debian bookworm amd64", "10.44.0.12"),
        ("dev-box", "Stopped", "container", "Alpine 3.20 amd64", ""),
        ("win11-test", "Running", "virtual-machine", "Windows 11 (VM)", "10.44.0.30")]

# Dados da aba VPS / Segurança (endereços das faixas reservadas para documentação).
_VPS = {
    "prod-web-01": ("DigitalOcean", "DigitalOcean Droplet", 4.2, 1000, 830),
    "prod-db-01": ("Hetzner Cloud", "Hetzner vServer", 0.6, None, 212),
    "k3s-edge": ("Vultr", "Vultr VC2", 11.5, 2000, 380),
    "hv-01": ("", "Supermicro X12", 0.0, None, 95),
}
_ENDPOINTS = {
    "prod-web-01": [("https://loja.exemplo.com.br/", ServiceStatus.ACTIVE, 200, 58, 142.0),
                    ("https://api.exemplo.com.br/health", ServiceStatus.ACTIVE, 200, 58, 96.0),
                    ("https://painel.exemplo.com.br/", ServiceStatus.DEGRADED, 200, 9, 188.0),
                    ("tls://mail.exemplo.com.br:993", ServiceStatus.ACTIVE, None, 71, 61.0)],
    "k3s-edge": [("https://edge.exemplo.com.br/", ServiceStatus.ACTIVE, 200, 33, 212.0),
                 ("https://status.exemplo.com.br/", ServiceStatus.FAILED, 503, 33, 305.0)],
}
_ATTACKERS = ["203.0.113.9", "198.51.100.7", "192.0.2.44", "203.0.113.77", "198.51.100.23", "192.0.2.201",
              "203.0.113.150", "198.51.100.99"]

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
                           security_interval_seconds=60.0, endpoint_interval_seconds=30.0,
                           notifications=NotificationSettings(cooldown_seconds=30))
    servers = (
        ServerConfig(name="prod-web-01", host="ssh.exemplo.com.br", username="monitor", security_sudo=True,
                     connector=ConnectorConfig(type="cloudflared", hostname="ssh.exemplo.com.br",
                                               token_credential="FirawynixMonitor/prod-web-01/cloudflared"),
                     security_actions=True, bandwidth_quota_gb=1000, container_admin=True,
                     endpoints=tuple(e[0] for e in _ENDPOINTS["prod-web-01"]),
                     critical_services=("nginx", "gunicorn", "celery*", "docker:shop-*", "docker:edge-*")),
        ServerConfig(name="prod-db-01", host="10.0.10.31", username="monitor", password_env="DEMO_DB_PASSWORD",
                     auth="key+password", container_admin=True,
                     connector=ConnectorConfig(type="vpn", name="WireGuard escritório", check_host="10.0.10.1",
                                               check_port=22),
                     critical_services=("postgresql*", "podman:pgbouncer")),
        ServerConfig(name="k3s-edge", host="10.0.20.11", username="monitor", process_actions=True,
                     security_sudo=True, bandwidth_quota_gb=2000,
                     endpoints=tuple(e[0] for e in _ENDPOINTS["k3s-edge"]),
                     critical_services=("k3s", "k8s:prod/*")),
        ServerConfig(name="hv-01", host="10.0.30.5", username="monitor", smart_sudo=True,
                     connector=ConnectorConfig(type="jump", jump=ServerConfig(
                         name="hv-01 (salto)", host="bastion.exemplo.com.br", username="monitor", auth="key")),
                     critical_services=("libvirtd", "vm:win2022-ad", "vm:pfsense-lab", "lxd:gitea")),
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
        self._nerdctl = {n: [state, status, image, group] for n, image, group, state, status in _NERDCTL} \
            if server.name == "k3s-edge" else {}
        self._removed: set[str] = set()
        self._demo_images: set[str] = set()
        self._demo_jobs: dict[str, list] = {}
        self._lxd = {name: [status, kind, image, ip] for name, status, kind, image, ip in _LXD} \
            if server.name == "hv-01" else {}
        self._banned = {"sshd": ["203.0.113.9", "198.51.100.7"]} if server.name == "prod-web-01" else \
            {"sshd": ["192.0.2.44"]} if server.name == "k3s-edge" else {}
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
        if runtime in (ServiceKind.NERDCTL, ServiceKind.CRI):
            return self._list_k3s_containers(runtime)
        with self._lock:
            if runtime is ServiceKind.DOCKER:
                if not self._docker:
                    return RuntimeResult(runtime, RuntimeState.NOT_INSTALLED, (), "Docker não instalado neste host.")
                items = tuple(
                    ServiceInfo(ServiceKind.DOCKER, name, image, classify_container(state, status), state, status,
                                group=group, meta=((("working_dir", f"/opt/{group}"),
                                                    ("config_files", f"/opt/{group}/compose.yaml"),
                                                    ("compose_service", service)) if group else ())
                                + ((("depends_on", _DEPENDS[service]),) if service in _DEPENDS else ())
                                + ((("ports", _DEMO_PORTS[name]),) if name in _DEMO_PORTS else ()))
                    for name, (state, status, image, group, service) in self._docker.items())
            else:
                if not self._podman:
                    return RuntimeResult(runtime, RuntimeState.NOT_INSTALLED, (), "Podman não instalado neste host.")
                items = tuple(
                    ServiceInfo(ServiceKind.PODMAN, name, image, classify_container(state, status), state, status,
                                group=pod, meta=((("pod", pod),) if pod else ())
                                + ((("ports", _DEMO_PORTS[name]),) if name in _DEMO_PORTS else ()))
                    for name, (state, status, image, pod) in self._podman.items())
            return RuntimeResult(runtime, RuntimeState.OK, items)

    def container_stats(self, runtime: ServiceKind) -> dict[str, tuple[float | None, int | None]]:
        names = {ServiceKind.DOCKER: self._docker, ServiceKind.PODMAN: self._podman,
                 ServiceKind.NERDCTL: self._nerdctl}.get(runtime, {})
        rng = random.Random(self._polls * 7)
        return {name: (rng.uniform(0.2, 35), rng.randint(40, 1400) * MIB) for name in names}

    def _list_k3s_containers(self, runtime: ServiceKind) -> RuntimeResult:
        if self.name != "k3s-edge":
            return RuntimeResult(runtime, RuntimeState.NOT_INSTALLED, (), f"{runtime.label} não instalado.")
        if runtime is ServiceKind.NERDCTL:
            with self._lock:
                items = tuple(ServiceInfo(runtime, name, image, classify_container(state, status), state, status,
                                          group=group, meta=(("ports", _DEMO_PORTS[name]),) if name in _DEMO_PORTS
                                          else ())
                              for name, (state, status, image, group) in self._nerdctl.items())
            return RuntimeResult(runtime, RuntimeState.OK, items)
        items = []
        for index, (name, image, pod, state, attempts) in enumerate(_CRI):
            container_id = f"{index + 1:x}" * 64
            status = ServiceStatus.ACTIVE if state == "running" else ServiceStatus.STOPPED
            items.append(ServiceInfo(runtime, f"{name}-{container_id[:8]}", image, status, state,
                                     state.capitalize() + (f" · {attempts} reinício(s)" if attempts else "")
                                     + f" · pod {pod}",
                                     meta=(("id", container_id), ("pod", pod), ("container", name))))
        return RuntimeResult(runtime, RuntimeState.OK, tuple(items))

    # -- motores de contêiner -------------------------------------------------

    def discover_engines(self) -> engines.Discovery:
        tools = {name: DetectedTool(name, f"/usr/bin/{name}", version)
                 for name, version in _ENGINES.get(self.name, {}).items()}
        return engines.Discovery(
            tools=tools, compose={"docker": "2.29.7"} if "docker" in tools else {},
            rootless={"podman": True} if "podman" in tools else {},
            services={"cockpit.socket": "active" if self.name == "prod-db-01" else "inactive"})

    def engine_inventory(self, engine_id: str) -> engines.EngineData:
        mb = 1000 ** 2
        refs = {"docker": [(image, "") for _n, image, _g, _s in _DOCKER.get(self.name, [])],
                "podman": [(image, "") for _n, image, _p in _PODMAN.get(self.name, [])],
                "nerdctl": [(image, "") for _n, image, _g, _s, _st in _NERDCTL],
                "cri": [(image, "") for _n, image, _p, _s, _a in _CRI]}.get(engine_id, [])
        rng = random.Random(self.name + engine_id)
        images = []
        for ref, _ in dict.fromkeys(refs):
            repo, _, tag = ref.rpartition(":")
            image_id = f"{rng.getrandbits(48):012x}"
            if f"image:{engine_id}:{ref}" in self._removed:
                continue
            images.append(ContainerImage(engine_id, image_id, repo, tag, rng.randint(20, 900) * mb,
                                         f"há {rng.randint(1, 60)} dias",
                                         digests=(f"{repo}@sha256:{rng.getrandbits(256):064x}",)))
        if engine_id in ("docker", "podman"):
            for extra in ("node:20-bookworm", "python:3.12-slim"):
                repo, _, tag = extra.partition(":")
                images.append(ContainerImage(engine_id, f"{rng.getrandbits(48):012x}", repo, tag,
                                             rng.randint(100, 1100) * mb, "há 4 meses", in_use=False,
                                             digests=(f"{repo}@sha256:{rng.getrandbits(256):064x}",)))
            if f"prune:{engine_id}" not in self._removed:
                images.append(ContainerImage(engine_id, f"{rng.getrandbits(48):012x}", "<none>", "<none>",
                                             380 * mb, "há 2 meses", in_use=False))
        volumes, networks, disk = [], [], []
        if engine_id == "docker":
            volumes = [ContainerVolume(engine_id, name, "local", f"/var/lib/docker/volumes/{name}/_data", stack, used)
                       for name, stack, used in (("shop_redis-data", "shop", True), ("monitoring_grafana", "monitoring",
                                                                                           True),
                                                 ("monitoring_prometheus", "monitoring", True),
                                                 ("portainer_data", "", True), ("old_uploads", "", False))
                       if f"volume:{engine_id}:{name}" not in self._removed]
            networks = [ContainerNetwork(engine_id, "bridge", "bridge", "local", ("172.17.0.0/16",), 2),
                        ContainerNetwork(engine_id, "shop_default", "bridge", "local", ("172.20.0.0/16",), 4),
                        ContainerNetwork(engine_id, "monitoring_default", "bridge", "local", ("172.21.0.0/16",), 3),
                        ContainerNetwork(engine_id, "edge", "bridge", "local", ("172.22.0.0/16",), 1),
                        ContainerNetwork(engine_id, "host", "host", "local", (), 0),
                        ContainerNetwork(engine_id, "none", "null", "local", (), 0)]
            disk = [EngineDiskUsage(engine_id, "Images", len(images), len(images) - 3, "6.4GB", "1.7GB (26%)"),
                    EngineDiskUsage(engine_id, "Local Volumes", len(volumes), len(volumes) - 1, "3.1GB",
                                    "812MB (25%)"),
                    EngineDiskUsage(engine_id, "Build Cache", 41, 0, "2.3GB", "2.3GB")]
        elif engine_id == "podman":
            volumes = [ContainerVolume(engine_id, "pgbouncer-conf", "local", "~/.local/share/containers/storage/"
                                       "volumes/pgbouncer-conf/_data", "", True),
                       ContainerVolume(engine_id, "pgadmin-data", "local", "", "", False)]
            networks = [ContainerNetwork(engine_id, "podman", "bridge", "", ("10.88.0.0/16",)),
                        ContainerNetwork(engine_id, "db-net", "bridge", "", ("10.89.0.0/24",))]
            disk = [EngineDiskUsage(engine_id, "Images", len(images), 2, "1.9GB", "1.1GB (57%)"),
                    EngineDiskUsage(engine_id, "Local Volumes", 2, 1, "240MB", "90MB (37%)")]
        elif engine_id == "nerdctl":
            volumes = [ContainerVolume(engine_id, "site-cache-data", "local", "", "site", True)]
            networks = [ContainerNetwork(engine_id, "bridge", "bridge", "", ("10.4.0.0/24",)),
                        ContainerNetwork(engine_id, "site_default", "bridge", "", ("10.4.1.0/24",))]
        return engines.EngineData(tuple(images), tuple(volumes), tuple(networks), tuple(disk))

    def buildah_inventory(self) -> tuple:
        if self.name != "prod-db-01":
            return (), ()
        return (BuildContainer("5c1d9e0a7b2f", "pg-tools-working-container", "docker.io/library/alpine:3.20"),), ()

    def container_op(self, service: ServiceInfo, op: str) -> ActionResult:
        if op == "rm" and not self.server.container_admin:
            return ActionResult(ActionOutcome.ERROR, "Remoções pelo painel estão desativadas (container_admin).")
        new_state = {"pause": ["paused", "Up 3 days (Paused)"], "unpause": ["running", "Up 3 days"]}.get(op)
        with self._lock:
            for table in (self._docker, self._podman, self._nerdctl):
                if service.name in table:
                    if op == "rm":
                        del table[service.name]
                    elif new_state:
                        table[service.name][:2] = new_state
        return ActionResult(ActionOutcome.OK, f"{op}: {service.name} — solicitado (demo).")

    def inspect_container(self, service: ServiceInfo) -> str:
        return json.dumps([{"Name": f"/{service.name}", "Image": service.description,
                            "State": {"Status": service.active_state, "Running": service.active_state == "running"},
                            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
                            "Config": {"Labels": {"com.docker.compose.project": service.group}}}],
                          indent=2, ensure_ascii=False)

    def image_op(self, engine_id: str, image: ContainerImage | None, op: str) -> ActionResult:
        if not self.server.container_admin:
            return ActionResult(ActionOutcome.ERROR, "Remoções pelo painel estão desativadas (container_admin).")
        self._removed.add(f"prune:{engine_id}" if op == "prune" else f"image:{engine_id}:{image.reference}")
        return ActionResult(ActionOutcome.OK, f"{op} — solicitado (demo).")

    def inspect_image(self, engine_id: str, image: ContainerImage) -> str:
        return json.dumps([{"Id": f"sha256:{image.id}", "RepoTags": [image.reference], "Architecture": "amd64",
                            "Os": "linux", "Size": image.size_bytes}], indent=2)

    def volume_op(self, engine_id: str, name: str, op: str) -> ActionResult:
        if not self.server.container_admin:
            return ActionResult(ActionOutcome.ERROR, "Remoções pelo painel estão desativadas (container_admin).")
        self._removed.add(f"volume:{engine_id}:{name}")
        return ActionResult(ActionOutcome.OK, f"Volume {name} removido (demo).")

    def inspect_volume(self, engine_id: str, name: str) -> str:
        return json.dumps([{"Name": name, "Driver": "local", "Scope": "local",
                            "Mountpoint": f"/var/lib/docker/volumes/{name}/_data"}], indent=2)

    def check_image_update(self, image: ContainerImage) -> ImageUpdate:
        time.sleep(0.15)
        if not engines.updatable(image):
            return ImageUpdate(image.reference, "ignorada", detail="imagem local, órfã ou sem digest de registro")
        if "ghcr.io/acme" in image.repository:
            return ImageUpdate(image.reference, "erro", detail="registro exige login (skopeo login no servidor)")
        newer = sum(map(ord, image.reference)) % 3 == 0
        return ImageUpdate(image.reference, "nova versão" if newer else "atualizada", "sha256:" + "0" * 64)

    def console_command(self, service: ServiceInfo) -> str:
        return engines.build_console_command(service, False)

    def change_backend(self) -> DemoChangeBackend:
        return DemoChangeBackend(self)

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

    def list_lxd(self) -> RuntimeResult:
        kind = ServiceKind.LXD
        if not self._lxd:
            return RuntimeResult(kind, RuntimeState.NOT_INSTALLED, (), "LXD/Incus não instalado neste host.")
        rng = random.Random(self._polls * 3)
        with self._lock:
            items = tuple(
                ServiceInfo(kind, name, image, classify_lxd(status), status.lower(),
                            status + (f" · {ip}" if ip else ""),
                            cpu_percent=rng.uniform(0.5, 12) if status == "Running" else None,
                            mem_bytes=rng.randint(200, 4000) * MIB if status == "Running" else None,
                            meta=(("type", kind_text), ("cli", "incus"), ("ipv4", ip), ("project", "default")))
                for name, (status, kind_text, image, ip) in self._lxd.items())
        return RuntimeResult(kind, RuntimeState.OK, items)

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
        steal_base = _VPS.get(self.name, ("", "", 0.0, None, 0))[2]
        return HostMetrics(
            uptime_seconds=1_234_567 + self._polls * 3,
            load_avg=(self._cpu / 25, self._cpu / 28, self._cpu / 30),
            cpu_count=16 if self.name == "hv-01" else 4,
            cpu_percent=self._cpu,
            cpu_steal=max(0.0, steal_base + self._rng.uniform(-1.5, 1.5)) if steal_base else 0.0,
            cpu_iowait=self._rng.uniform(0.2, 9.0 if self.name == "prod-db-01" else 2.5),
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

    def take_rtt(self) -> float | None:
        base = {"prod-web-01": 18.0, "prod-db-01": 34.0, "k3s-edge": 142.0, "hv-01": 2.0}.get(self.name, 20.0)
        return max(0.5, base + self._rng.uniform(-3, 6))

    def vps_info(self) -> VpsInfo:
        provider, product, _steal, _quota, tx_gb = _VPS.get(self.name, ("", "", 0.0, None, 50))
        gb = 1024 ** 3
        month = time.strftime("%Y-%m")
        oom = (OomKill(time.time() - 5400, "java"),) if self.name == "k3s-edge" else ()
        return VpsInfo(
            provider=provider, product=product, ntp_synchronized=self.name != "prod-db-01",
            ntp_service="ativo" if self.name != "prod-db-01" else "inativo",
            clock_offset=0.0021 if self.name == "k3s-edge" else None,
            dns_servers=("1.1.1.1", "9.9.9.9") if provider else ("10.0.30.1",),
            default_gateway="10.0.0.1 (eth0)", swappiness=60, oom_kills=oom, oom_kills_24h=len(oom),
            bandwidth=(BandwidthUsage("eth0", month, int(tx_gb * 0.35 * gb), int((tx_gb + self._polls * 0.01) * gb),
                                      int(3.2 * gb), int(28.5 * gb)),) if self.name != "hv-01" else (),
            bandwidth_source="vnstat" if self.name != "hv-01" else "",
        )

    def smart(self) -> SmartReport:
        if self.name == "hv-01":
            return SmartReport(RuntimeState.OK, (
                SmartDisk("/dev/nvme0", "Samsung SSD 990 PRO 2TB", "S7KH", 2_000_398_934_016, True, 44.0, 9120,
                          media_errors=0, percentage_used=6, critical_warning=0),
                SmartDisk("/dev/sda", "WDC WD4003FRYZ-01F0DB0", "V1J9", 4_000_787_030_016, True, 38.0, 31_450,
                          reallocated=0, pending=0, uncorrectable=0),
            ))
        if self.name == "prod-db-01":
            return SmartReport(RuntimeState.OK, (
                SmartDisk("/dev/sda", "SAMSUNG MZ7LH960HAJR", "S45N", 960_197_124_096, True, 31.0, 22_104,
                          reallocated=0, pending=0, uncorrectable=0),
                SmartDisk("/dev/sdb", "SAMSUNG MZ7LH960HAJR", "S45P", 960_197_124_096, True, 33.0, 22_101,
                          reallocated=12, pending=0, uncorrectable=0),
            ))
        return SmartReport(RuntimeState.OK, (), "Nenhum disco físico com SMART (discos virtuais de VPS não têm).")

    def security_raw(self) -> SecurityRaw:
        hardened = self.name in ("prod-web-01", "k3s-edge", "hv-01")
        sshd = ({"permitrootlogin": "prohibit-password", "passwordauthentication": "no", "maxauthtries": "3",
                 "port": "22", "x11forwarding": "no", "usepam": "yes", "kbdinteractiveauthentication": "no"}
                if hardened else
                {"permitrootlogin": "yes", "passwordauthentication": "yes", "maxauthtries": "6", "port": "22",
                 "x11forwarding": "yes"})
        services = {"ufw": "active" if self.name == "prod-web-01" else "inactive",
                    "firewalld": "active" if self.name == "k3s-edge" else "inactive",
                    "fail2ban": "active" if self.name == "prod-web-01" else "inactive",
                    "crowdsec": "active" if self.name == "k3s-edge" else "inactive",
                    "auditd": "active" if self.name == "k3s-edge" else "inactive",
                    "nftables": "active" if self.name == "hv-01" else "inactive"}
        jails = tuple(Fail2banJail(jail, 2, 1542, len(ips), 87, tuple(ips)) for jail, ips in self._banned.items())
        rng = random.Random(self.name + "keys")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(rng.choice(alphabet) for _ in range(43))
        return SecurityRaw(
            sshd=sshd, sshd_source="sshd -T" if hardened else "arquivos", services=services,
            binaries=frozenset({"fail2ban-client", "ufw"} if self.name != "hv-01" else {"nft", "smartctl"}),
            ssh_client="198.51.100.20", ufw_enabled=self.name == "prod-web-01",
            ufw_status="Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)"
            if self.name == "prod-web-01" else "",
            iptables_rules=None if self.name == "prod-db-01" else 0, nft_rules=14 if self.name == "hv-01" else None,
            uid0_users=("root",), login_users=("root", "monitor", "ana", "deploy"), sudo_users=("ana",),
            sysctl={"kernel.randomize_va_space": "2", "net.ipv4.tcp_syncookies": "1",
                    "fs.protected_hardlinks": "1", "fs.protected_symlinks": "1",
                    "net.ipv4.conf.all.accept_redirects": "0" if hardened else "1",
                    "kernel.dmesg_restrict": "1" if hardened else "0"},
            apparmor=self.name != "k3s-edge", selinux="Enforcing" if self.name == "k3s-edge" else "",
            auto_updates="1" if hardened else "0", tmp_mode="1777",
            sessions=(SessionInfo("ana", "pts/0", "198.51.100.61", time.strftime("%Y-%m-%d %H:%M")),)
            if self.name == "prod-web-01" else (),
            authorized_keys=(AuthorizedKey("ssh-ed25519", 256, f"SHA256:{blob}", "monitor@firawynix", False),
                             AuthorizedKey("ssh-ed25519", 256, f"SHA256:{blob[::-1]}", "ana@notebook", False))
            + ((AuthorizedKey("ssh-rsa", 1024, f"SHA256:{blob[5:]}xyz12", "backup-antigo", True),)
               if self.name == "prod-db-01" else ()),
            fail2ban=jails, fail2ban_error=None,
        )

    def fail2ban_status(self) -> tuple[tuple[Fail2banJail, ...], str]:
        return self.security_raw().fail2ban, ""

    def ssh_logins(self) -> SshLoginReport:
        now = time.time()
        volume = {"prod-web-01": 1432, "prod-db-01": 4210, "k3s-edge": 96}.get(self.name, 0)
        rng = random.Random(self.name + "ssh")
        sources = []
        remaining = volume
        for index, ip in enumerate(_ATTACKERS if volume else ()):
            count = remaining if index == len(_ATTACKERS) - 1 else int(remaining * rng.uniform(0.3, 0.5))
            remaining -= count
            sources.append(FailedLoginSource(ip, count, now - rng.uniform(60, 80000),
                                             rng.choice(["root", "admin", "ubuntu", "test", "oracle"])))
        accepted = [LoginEvent(now - 3600 * 3, "monitor", "198.51.100.20", "publickey"),
                    LoginEvent(now - 3600 * 5, "ana", "198.51.100.61", "publickey")]
        if self.name == "prod-db-01":
            accepted.append(LoginEvent(now - 3600 * 9, "root", "203.0.113.200", "password"))
        sources.sort(key=lambda s: -s.count)
        return SshLoginReport(tuple(sorted(accepted, key=lambda e: -e.timestamp)), tuple(sources), volume)

    def sudo_log(self) -> tuple[SudoEvent, ...]:
        now = time.time()
        events = [SudoEvent(now - 4000, "ana", "/usr/bin/systemctl reload nginx", "ok", "root", "pts/0"),
                  SudoEvent(now - 9000, "ana", "/usr/bin/apt upgrade", "ok", "root", "pts/0")]
        if self.name == "prod-db-01":
            events.append(SudoEvent(now - 20000, "deploy", "/bin/bash", "senha incorreta", "root", "pts/2"))
        return tuple(events)

    def check_endpoint(self, spec, *, timeout: float = 5.0, cert_warning_days: float = 14) -> EndpointResult:
        for url, status, http_status, days, latency in _ENDPOINTS.get(self.name, []):
            if url == spec.raw:
                detail = f"{http_status} {'OK' if http_status == 200 else 'Service Unavailable'}" if http_status else \
                    "handshake TLS OK"
                if days <= cert_warning_days:
                    detail += f" · certificado expira em {days} dia(s)"
                return EndpointResult(url, spec.scheme, status, latency + self._rng.uniform(-10, 25), http_status,
                                      cert_expires=time.time() + days * 86400, cert_days_left=days,
                                      cert_issuer="Let's Encrypt (R11)", cert_subject=spec.host, cert_valid=True,
                                      detail=detail)
        return EndpointResult(spec.raw, spec.scheme, ServiceStatus.FAILED, detail="desconhecido (demo)")

    def fail2ban_action(self, jail: str, ip: str, ban: bool) -> ActionResult:
        with self._lock:
            banned = self._banned.setdefault(jail, [])
            if ban and ip not in banned:
                banned.append(ip)
            elif not ban and ip in banned:
                banned.remove(ip)
        return ActionResult(ActionOutcome.OK, f"{'Banir' if ban else 'Desbanir'}: {ip} (jail {jail}) — demo.")

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
            elif service.kind is ServiceKind.LXD:
                self._lxd[service.name][0] = "Stopped" if stop else "Running"
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
        if service.kind is ServiceKind.LXD:
            return cmd.build_lxd_info_command("incus", service.name, False)
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
            steal = max(0.0, _VPS.get(server.name, ("", "", 0.0))[2] * (1 + 0.6 * day) + rng.gauss(0, 0.8))
            metrics = HostMetrics(
                cpu_percent=cpu, cpu_steal=steal, cpu_iowait=max(0.0, 1.5 + rng.gauss(0, 0.7)),
                mem_total_mb=10_000, mem_used_mb=int(mem * 100), swap_total_mb=2000,
                swap_used_mb=100, load_avg=(cpu / 25, cpu / 28, cpu / 30),
                disks=(DiskUsage("/dev/sda1", "/", 100, 64, 36, disk_pct),),
                interfaces=(InterfaceStats("eth0", 0, 0, rx, rx * 0.45),),
                disk_io=(DiskIO("sda", max(0.0, 1.5e6 + rng.gauss(0, 6e5)), max(0.0, 3e6 + 2e6 * day)),),
            )
            latency = {"prod-web-01": 18.0, "prod-db-01": 34.0, "k3s-edge": 142.0, "hv-01": 2.0}.get(server.name, 20)
            store.record(server.name, t, metrics, failed=1 if rng.random() < 0.05 else 0, active=40,
                         latency=max(0.5, latency * (1 + 0.15 * day) + rng.gauss(0, latency * 0.08)))
            t += step


# ---------------------------------------------------------------------------
# Mudanças seguras simuladas (inspect, tarefas demoradas, backups)
# ---------------------------------------------------------------------------

class DemoChangeBackend:
    """Simula o motor para o fluxo de mudanças seguras no modo demonstração."""

    _DURATIONS = {"stop": 2.5, "restart": 3.0, "commit": 2.0, "pull": 3.5, "run": 3.0}

    def __init__(self, client: DemoClient) -> None:
        self.client = client

    def _table(self, engine: str) -> dict:
        return {"docker": self.client._docker, "podman": self.client._podman,
                "nerdctl": self.client._nerdctl}.get(engine, {})

    def executable(self, engine: str) -> str:
        return engine

    def inspect(self, engine: str, name: str) -> dict | None:
        with self.client._lock:
            row = self._table(engine).get(name)
            if row is None:
                return None
            state, status, image = row[0], row[1], row[2]
            group = row[3] if len(row) > 3 else ""
            service = row[4] if len(row) > 4 else ""
        ports = {}
        for host_port, container_port in engines.published_ports(_DEMO_PORTS.get(name, "")):
            ports[f"{container_port}/tcp"] = [{"HostIp": "", "HostPort": str(host_port)}]
        labels = {"com.docker.compose.project": group, "com.docker.compose.service": service,
                  "com.docker.compose.project.working_dir": f"/opt/{group}"} if group and engine == "docker" else {}
        if service in _DEPENDS:
            labels["com.docker.compose.depends_on"] = _DEPENDS[service]
        code = 0
        if "(" in status:
            inner = status.split("(", 1)[1].split(")", 1)[0]
            code = int(inner) if inner.lstrip("-").isdigit() else 0
        network = f"{group}_default" if group else "bridge"
        return {
            "Id": f"{abs(hash(name)):064x}"[:64], "Name": f"/{name}", "RestartCount": 0,
            "State": {"Status": state, "Running": state == "running", "ExitCode": code},
            "Config": {"Image": image, "Env": ["PATH=/usr/local/bin:/usr/bin", "TZ=America/Sao_Paulo",
                                                "APP_SECRET_KEY=demo-segredo"],
                       "Cmd": None, "Labels": labels, "Hostname": name[:12]},
            "HostConfig": {"PortBindings": ports, "RestartPolicy": {"Name": "unless-stopped"},
                           "NetworkMode": network},
            "Mounts": [{"Type": "volume", "Name": v, "Destination": "/data", "RW": True}
                       for v in _DEMO_VOLUMES.get(name, ())],
            "NetworkSettings": {"Networks": {network: {}}},
            "SizeRw": 23 * MIB if name == "backup-job" else 0,
        }

    def image_config(self, engine: str, image: str) -> dict | None:
        with self.client._lock:
            known = {row[2] for table in (self.client._docker, self.client._podman, self.client._nerdctl)
                     for row in table.values()} | self.client._demo_images
        return {"Env": ["PATH=/usr/local/bin:/usr/bin"]} if image in known else None

    def _apply(self, engine: str, args: list[str]):
        from core.change_runner import ShellResult

        op, name = args[0], args[-1]
        table = self._table(engine)
        needs_container = op in ("stop", "start", "restart", "pause", "unpause", "rm")
        with self.client._lock:
            if needs_container and name not in table:
                return ShellResult(False, f"Error: No such container: {name}")
            if op == "stop":
                table[name][:2] = ["exited", "Exited (0) 1 second ago"]
            elif op in ("start", "restart", "unpause"):
                table[name][:2] = ["running", "Up 1 second"]
            elif op == "pause":
                table[name][:2] = ["paused", "Up 3 days (Paused)"]
            elif op == "rm":
                if table[name][0] == "running":
                    return ShellResult(False, "Error: cannot remove a running container")
                del table[name]
            elif op in ("commit", "pull"):
                self.client._demo_images.add(name)
            elif op == "run" and "--rm" in args:
                return ShellResult(True, "")
            elif op == "run":
                new = args[args.index("--name") + 1]
                known = {row[2] for tbl in (self.client._docker, self.client._podman, self.client._nerdctl)
                         for row in tbl.values()} | self.client._demo_images
                image = next((a for a in args if a in known), args[-1])
                row = ["running", "Up 1 second", image] + (["", ""] if engine == "docker" else [""])
                table[new] = row
                return ShellResult(True, f"{abs(hash(new)):064x}"[:64])
        return ShellResult(True, name)

    def exec(self, engine: str, args):
        return self._apply(engine, list(args))

    def start_job(self, job_id: str, command: str):
        from core.change_runner import ShellResult

        argv = shlex.split(command)
        engine = argv[0] if argv[0] in ("docker", "podman", "nerdctl") else "docker"
        args = argv[1:]
        duration = 4.0 if "--rm" in args else self._DURATIONS.get(args[0] if args else "", 2.0)
        self.client._demo_jobs[job_id] = [time.monotonic() + duration, engine, args, None]
        return ShellResult(True, "started")

    def poll_job(self, job_id: str):
        from core.changes import JobState

        job = self.client._demo_jobs.get(job_id)
        if job is None:
            return JobState(True, None, "", missing=True)
        due, engine, args, result = job
        if time.monotonic() < due:
            return JobState(False, None, "")
        if result is None:
            job[3] = result = self._apply(engine, args)
        return JobState(True, 0 if result.ok else 1, result.output)

    def cleanup_job(self, job_id: str) -> None:
        self.client._demo_jobs.pop(job_id, None)

    def file_size(self, path: str) -> int | None:
        return 48 * MIB + len(path) * 1024

    def logs_tail(self, engine: str, name: str, lines: int = 20) -> str:
        return f"2026-09-29T12:00:01Z {name} iniciado\n2026-09-29T12:00:02Z pronto para conexões"

    def backup_target(self, engine: str):
        from core.change_runner import BackupTarget

        return BackupTarget(directory="/home/monitor/firawynix-backups", owner="1000:1000")
