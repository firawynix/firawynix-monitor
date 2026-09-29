"""Parsers das saídas dos comandos remotos (funções puras, testáveis sem rede).

Todos toleram saídas parciais ou de versões antigas: linhas que não podem ser
interpretadas são ignoradas em vez de derrubar a coleta inteira.
"""

from __future__ import annotations

import base64
import datetime as dt
import fnmatch
import hashlib
import ipaddress
import json
import logging
import re
import struct
from dataclasses import dataclass, field

from core.commands import SECTION
from core.models import (
    SYSTEMD_UNIT_TYPES,
    AuthorizedKey,
    BandwidthUsage,
    CronEntry,
    DiskIO,
    DiskUsage,
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
    RuntimeState,
    SecurityRaw,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SessionInfo,
    SmartDisk,
    SmartReport,
    SshLoginReport,
    SudoEvent,
    SystemInfo,
    TimerInfo,
    UpdatesInfo,
    VpsInfo,
)

log = logging.getLogger(__name__)

_SECTION_RE = re.compile(rf"^{SECTION}$", re.M)


def split_sections(output: str, expected: int = 0) -> list[str]:
    """Divide pela linha EXATA do marcador (o texto pode aparecer dentro de
    outras linhas, ex.: na linha de comando do próprio coletor no ``ps``)."""
    parts = [part.strip("\n") for part in _SECTION_RE.split(output)]
    if len(parts) < expected:
        parts += [""] * (expected - len(parts))
    return parts


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------

_SYSTEMD_TRANSITIONAL = {"activating", "reloading", "refreshing"}


def classify_systemd(active: str, sub: str = "") -> ServiceStatus:
    active = active.lower()
    if active == "failed":
        return ServiceStatus.FAILED
    if active in _SYSTEMD_TRANSITIONAL:
        return ServiceStatus.ACTIVATING
    if active == "active":
        return ServiceStatus.ACTIVE
    if active in {"inactive", "deactivating"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def _unit_type(unit: str) -> str:
    return unit.rsplit(".", 1)[-1] if "." in unit else ""


def _make_unit(unit: str, load: str, active: str, sub: str, description: str) -> ServiceInfo | None:
    if not unit or load == "not-found" or _unit_type(unit) not in SYSTEMD_UNIT_TYPES:
        # Unidades referenciadas mas inexistentes poluem a lista (--all).
        return None
    return ServiceInfo(
        kind=ServiceKind.SYSTEMD,
        name=unit,
        description=description,
        status=classify_systemd(active, sub),
        active_state=active,
        sub_state=sub,
        load_state=load,
    )


def parse_systemctl_json(output: str) -> list[ServiceInfo]:
    data = json.loads(output)
    if not isinstance(data, list):
        raise ValueError("Saída JSON do systemctl não é uma lista")
    services: list[ServiceInfo] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        entry = {str(k).lower(): ("" if v is None else str(v)) for k, v in item.items()}
        service = _make_unit(entry.get("unit") or entry.get("name", ""), entry.get("load", ""),
                             entry.get("active", ""), entry.get("sub", ""), entry.get("description", ""))
        if service is not None:
            services.append(service)
    return services


def parse_systemctl_table(output: str) -> list[ServiceInfo]:
    """Fallback para systemd antigos (sem ``--output=json`` em list-units)."""
    services: list[ServiceInfo] = []
    for raw_line in output.splitlines():
        # Marcador de falha: "●" (UTF-8) ou "*" (locale C).
        line = raw_line.strip().lstrip("●*").strip()
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[:4]
        service = _make_unit(unit, load, active, sub, parts[4] if len(parts) > 4 else "")
        if service is not None:
            services.append(service)
    return services


@dataclass
class CgroupSample:
    uptime: float
    usage_usec: dict[str, int]


def parse_cgroup_services(output: str, previous: CgroupSample | None
                          ) -> tuple[dict[str, tuple[float | None, int | None]], CgroupSample | None]:
    """Memória atual e CPU (delta de ``usage_usec``) por serviço, via cgroup v2.

    Retorna ``{unidade: (cpu_percent, mem_bytes)}`` — CPU em % de um núcleo.
    """
    lines = output.splitlines()
    if not lines:
        return {}, previous
    try:
        uptime = float(lines[0].split()[0])
    except (IndexError, ValueError):
        return {}, previous
    usage: dict[str, int] = {}
    result: dict[str, tuple[float | None, int | None]] = {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 2 or not fields[0].endswith(".service"):
            continue
        name = fields[0]
        mem = int(fields[1]) if fields[1].isdigit() else None
        cpu_pct = None
        if len(fields) > 2 and fields[2].isdigit():
            usage[name] = int(fields[2])
            if previous is not None and name in previous.usage_usec:
                elapsed = uptime - previous.uptime
                delta = usage[name] - previous.usage_usec[name]
                if elapsed > 0 and delta >= 0:
                    cpu_pct = 100.0 * delta / (elapsed * 1_000_000)
        result[name] = (cpu_pct, mem)
    return result, CgroupSample(uptime, usage)


def parse_timers(output: str) -> list[TimerInfo]:
    """Blocos ``chave=valor`` de ``systemctl show '*.timer'``."""
    timers = []
    for block in re.split(r"\n\s*\n", output.strip()):
        props = {}
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props[key.strip()] = value.strip()
        name = props.get("Id", "")
        if not name or "*" in name or not name.endswith(".timer"):
            continue
        timers.append(TimerInfo(
            name=name,
            activates=props.get("Unit", ""),
            next_run=_clean_systemd_timestamp(props.get("NextElapseUSecRealtime", "")),
            last_run=_clean_systemd_timestamp(props.get("LastTriggerUSec", "")),
            active_state=props.get("ActiveState", ""),
            description=props.get("Description", ""),
        ))
    return sorted(timers, key=lambda t: (t.next_run or "9999", t.name))


def _clean_systemd_timestamp(value: str) -> str:
    value = value.strip()
    if value in {"", "n/a", "0"}:
        return ""
    # "Tue 2026-09-29 18:12:47 UTC" → "2026-09-29 18:12:47 UTC"
    return re.sub(r"^[A-Z][a-z]{2} ", "", value)


# ---------------------------------------------------------------------------
# Docker / Podman
# ---------------------------------------------------------------------------

# Códigos de saída típicos de parada intencional (docker stop / Ctrl+C):
# 0, SIGINT (130), SIGKILL após timeout do stop (137) e SIGTERM (143).
_CLEAN_EXIT_CODES = {0, 130, 137, 143}
_EXIT_CODE_RE = re.compile(r"\((-?\d+)\)")

COMPOSE_PROJECT_LABELS = ("com.docker.compose.project", "io.podman.compose.project")


def classify_container(state: str, status_text: str) -> ServiceStatus:
    state = (state or "").lower()
    status_lower = (status_text or "").lower()
    if not state:
        # Versões antigas não expõem .State: deduz pelo texto.
        for prefix, derived in (("up", "running"), ("exited", "exited"), ("restarting", "restarting"),
                                ("created", "created"), ("dead", "dead"), ("removal", "removing")):
            if status_lower.startswith(prefix):
                state = derived
                break
        if "(paused)" in status_lower:
            state = "paused"

    code_match = _EXIT_CODE_RE.search(status_text or "")
    exit_code = int(code_match.group(1)) if code_match else None

    if state == "running":
        if "(unhealthy)" in status_lower:
            return ServiceStatus.FAILED
        if "health: starting" in status_lower or "(starting)" in status_lower:
            return ServiceStatus.ACTIVATING
        return ServiceStatus.ACTIVE
    if state == "restarting":
        # Reiniciando com código de erro = loop de crash.
        return ServiceStatus.FAILED if exit_code not in (None, 0) else ServiceStatus.ACTIVATING
    if state in {"exited", "stopped"}:
        if exit_code is None:
            return ServiceStatus.STOPPED
        return ServiceStatus.STOPPED if exit_code in _CLEAN_EXIT_CODES else ServiceStatus.FAILED
    if state == "dead":
        return ServiceStatus.FAILED
    if state in {"created", "paused", "removing", "configured", "initialized"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def parse_docker_labels(text: str) -> dict[str, str]:
    """``k=v,k2=v2`` do ``docker ps``; valores podem conter vírgulas
    (ex.: ``config_files=/a.yml,/b.yml``)."""
    labels: dict[str, str] = {}
    last_key = None
    for segment in (text or "").split(","):
        if "=" in segment:
            key, _, value = segment.partition("=")
            last_key = key.strip()
            labels[last_key] = value
        elif last_key is not None:
            labels[last_key] += "," + segment
    return labels


def _container_meta(labels: dict[str, str]) -> tuple[str, tuple[tuple[str, str], ...]]:
    group = next((labels[k] for k in COMPOSE_PROJECT_LABELS if labels.get(k)), "")
    meta = []
    for key, name in (("com.docker.compose.project.working_dir", "working_dir"),
                      ("com.docker.compose.project.config_files", "config_files"),
                      ("com.docker.compose.service", "compose_service")):
        if labels.get(key):
            meta.append((name, labels[key]))
    return group, tuple(meta)


def parse_docker_ps(output: str) -> list[ServiceInfo]:
    containers: list[ServiceInfo] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            log.debug("Linha do docker ps ignorada: %r", line)
            continue
        name = str(item.get("Names") or item.get("ID") or "").split(",")[0].strip().lstrip("/")
        if not name:
            continue
        state = str(item.get("State") or "")
        status_text = str(item.get("Status") or "")
        group, meta = _container_meta(parse_docker_labels(str(item.get("Labels") or "")))
        containers.append(ServiceInfo(
            kind=ServiceKind.DOCKER,
            name=name,
            description=str(item.get("Image") or ""),
            status=classify_container(state, status_text),
            active_state=state or "?",
            sub_state=status_text,
            group=group,
            meta=meta,
        ))
    return containers


def parse_podman_ps(output: str) -> list[ServiceInfo]:
    """``podman ps -a --format json`` (lista JSON; campos variam entre versões)."""
    text = output.strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("Saída do podman ps não é uma lista")
    containers = []
    for item in data:
        if not isinstance(item, dict):
            continue
        names = item.get("Names") or [item.get("Id", "")[:12]]
        name = (names[0] if isinstance(names, list) and names else str(names)).lstrip("/")
        if not name:
            continue
        state = item.get("State")
        state = state if isinstance(state, str) else ""
        status_text = str(item.get("Status") or "")
        if not status_text:
            exit_code = item.get("ExitCode", 0)
            status_text = "Up" if state == "running" else f"Exited ({exit_code})" if state == "exited" else state
        labels = item.get("Labels") if isinstance(item.get("Labels"), dict) else {}
        group, meta = _container_meta({str(k): str(v) for k, v in labels.items()})
        if not group and item.get("PodName"):
            group = str(item["PodName"])
            meta += (("pod", group),)
        containers.append(ServiceInfo(
            kind=ServiceKind.PODMAN,
            name=name,
            description=str(item.get("Image") or ""),
            status=classify_container(state, status_text),
            active_state=state or "?",
            sub_state=status_text,
            group=group,
            meta=meta,
        ))
    return containers


_SIZE_RE = re.compile(r"([\d.]+)\s*([kKMGTP]?i?B)")
_SIZE_UNITS = {
    "B": 1, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4, "PB": 1000 ** 5,
    "KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4, "PIB": 1024 ** 5,
}


def parse_size(text: str) -> int | None:
    match = _SIZE_RE.search(text or "")
    if not match:
        return None
    try:
        return int(float(match.group(1)) * _SIZE_UNITS[match.group(2).upper()])
    except (KeyError, ValueError):
        return None


def parse_container_stats(output: str) -> dict[str, tuple[float | None, int | None]]:
    """Linhas ``nome|12.5%|10MiB / 1GiB`` → ``{nome: (cpu_percent, mem_bytes)}``."""
    stats = {}
    for line in output.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 3 or not parts[0]:
            continue
        try:
            cpu = float(parts[1].strip().rstrip("%"))
        except ValueError:
            cpu = None
        stats[parts[0].strip().lstrip("/")] = (cpu, parse_size(parts[2].split("/")[0]))
    return stats


# ---------------------------------------------------------------------------
# Kubernetes / libvirt
# ---------------------------------------------------------------------------

_POD_FAILURE_REASONS = {
    "CrashLoopBackOff", "Error", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
    "CreateContainerError", "InvalidImageName", "OOMKilled", "RunContainerError", "ContainerCannotRun",
}


def _csv_values(value: str) -> list[str]:
    return [] if value in ("", "<none>") else value.split(",")


def classify_pod(phase: str, ready: list[str], reasons: list[str], deleting: bool) -> ServiceStatus:
    if deleting:
        return ServiceStatus.STOPPED
    if any(r in _POD_FAILURE_REASONS for r in reasons):
        return ServiceStatus.FAILED
    if phase == "Running":
        return ServiceStatus.ACTIVE if ready and all(r == "true" for r in ready) else ServiceStatus.ACTIVATING
    if phase == "Pending":
        return ServiceStatus.ACTIVATING
    if phase == "Succeeded":
        return ServiceStatus.STOPPED
    if phase == "Failed":
        return ServiceStatus.FAILED
    return ServiceStatus.UNKNOWN


def parse_pods(output: str) -> list[ServiceInfo]:
    """Saída de ``kubectl get pods -A -o custom-columns=...`` (ver commands.py)."""
    pods = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 11 or fields[0] == "NS":
            continue
        ns, name, phase, ready_s, restarts_s, waiting_s, terminated_s, node, created, deleting, owner = fields[:11]
        ready = _csv_values(ready_s)
        restarts = sum(int(v) for v in _csv_values(restarts_s) if v.isdigit())
        reasons = _csv_values(waiting_s) + _csv_values(terminated_s)
        is_deleting = deleting != "<none>"
        status = classify_pod(phase, ready, reasons, is_deleting)
        ready_count = sum(1 for r in ready if r == "true")
        sub = f"{ready_count}/{len(ready)} prontos · {restarts} reinício{'s' if restarts != 1 else ''}"
        problem = next((r for r in reasons if r in _POD_FAILURE_REASONS), "")
        if is_deleting:
            sub = "Terminating · " + sub
        elif problem:
            sub = f"{problem} · {sub}"
        owner = "" if owner == "<none>" else owner
        node = "" if node == "<none>" else node
        pods.append(ServiceInfo(
            kind=ServiceKind.KUBERNETES,
            name=f"{ns}/{name}",
            description=" · ".join(p for p in (owner, f"nó {node}" if node else "") if p),
            status=status,
            active_state=phase,
            sub_state=sub,
            group=ns,
            meta=(("node", node), ("created", created), ("restarts", str(restarts))),
        ))
    return pods


_VM_STATES = ("shut off", "in shutdown", "no state", "running", "paused", "idle", "crashed",
              "pmsuspended", "blocked", "dying")


def classify_vm(state: str) -> ServiceStatus:
    if state in {"running", "idle", "blocked"}:
        return ServiceStatus.ACTIVE
    if state in {"in shutdown", "dying"}:
        return ServiceStatus.ACTIVATING
    if state == "crashed":
        return ServiceStatus.FAILED
    if state in {"shut off", "paused", "pmsuspended"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def parse_virsh_list(output: str) -> list[ServiceInfo]:
    """``virsh -q list --all``: ``" 1    web01    running"`` / ``" -    db    shut off"``."""
    vms = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith(("Id ", "---")):
            continue
        dom_id, _, rest = line.partition(" ")
        rest = rest.strip()
        state = next((s for s in _VM_STATES if rest.endswith(s)), "")
        name = rest[: len(rest) - len(state)].strip() if state else rest.rsplit(None, 1)[0]
        if not name:
            continue
        vms.append(ServiceInfo(
            kind=ServiceKind.LIBVIRT,
            name=name,
            description=f"domínio libvirt{' · id ' + dom_id if dom_id != '-' else ''}",
            status=classify_vm(state),
            active_state=state or "?",
            sub_state=state,
        ))
    return vms


def classify_lxd(status: str) -> ServiceStatus:
    status = (status or "").lower()
    if status == "running":
        return ServiceStatus.ACTIVE
    if status in {"stopped", "frozen"}:
        return ServiceStatus.STOPPED
    if status == "error":
        return ServiceStatus.FAILED
    if status in {"starting", "stopping", "freezing", "thawed", "restarting"}:
        return ServiceStatus.ACTIVATING
    return ServiceStatus.UNKNOWN


def parse_lxd_list(output: str) -> tuple[str, list[ServiceInfo], dict[str, int]]:
    """``CLI=<cliente>`` + JSON de ``incus/lxc list`` → (cliente, instâncias, uso de CPU em ns)."""
    cli, _, rest = output.lstrip().partition("\n")
    cli = cli.removeprefix("CLI=").strip() if cli.startswith("CLI=") else "lxc"
    text = rest.strip() if output.lstrip().startswith("CLI=") else output.strip()
    if not text:
        return cli, [], {}
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("Saída do list não é uma lista")
    instances, cpu_usage = [], {}
    for item in data:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        name = str(item["name"])
        status = str(item.get("status") or "")
        state = item.get("state") if isinstance(item.get("state"), dict) else {}
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        memory = (state.get("memory") or {}).get("usage") if isinstance(state.get("memory"), dict) else None
        cpu = (state.get("cpu") or {}).get("usage") if isinstance(state.get("cpu"), dict) else None
        running = status.lower() == "running"
        if isinstance(cpu, int) and running:
            cpu_usage[name] = cpu
        ipv4 = ""
        for iface, net in (state.get("network") or {}).items():
            if iface == "lo" or not isinstance(net, dict):
                continue
            for address in net.get("addresses") or []:
                if isinstance(address, dict) and address.get("family") == "inet" and address.get("scope") == "global":
                    ipv4 = ipv4 or str(address.get("address", ""))
        kind_text = str(item.get("type") or "container")
        project = str(item.get("project") or "default")
        instances.append(ServiceInfo(
            kind=ServiceKind.LXD,
            name=name,
            description=str(config.get("image.description") or item.get("description") or kind_text),
            status=classify_lxd(status),
            active_state=status.lower() or "?",
            sub_state=status + (f" · {ipv4}" if ipv4 else ""),
            group="" if project == "default" else project,
            mem_bytes=memory if isinstance(memory, int) and running else None,
            meta=(("type", kind_text), ("cli", cli), ("ipv4", ipv4), ("project", project)),
        ))
    return cli, instances, cpu_usage


def classify_runtime_error(kind: ServiceKind, exit_code: int, output: str) -> tuple[RuntimeState, str]:
    """Traduz a falha de um runtime (docker, podman, kubectl, virsh) em estado + dica."""
    label = kind.label
    lower = output.lower()
    first_line = output.strip().splitlines()[0] if output.strip() else f"código de saída {exit_code}"
    if exit_code == 127 or "command not found" in lower or re.search(r": (\S+: )?not found", lower):
        return RuntimeState.NOT_INSTALLED, f"{label} não instalado neste host."
    if "a password is required" in lower or "a terminal is required" in lower:
        return RuntimeState.PERMISSION, f"sudo exige senha para o {label}; configure NOPASSWD no sudoers."
    if kind.is_container:
        if "permission denied" in lower:
            return RuntimeState.PERMISSION, (
                f"Sem permissão no socket do {label}. Adicione o usuário ao grupo apropriado "
                f"ou habilite \"{kind.value}_sudo\" (com NOPASSWD no sudoers).")
        if ("cannot connect to the docker daemon" in lower or "daemon running" in lower
                or "daemon is running" in lower or "failed to connect to the docker api" in lower
                or "cannot connect to podman" in lower):
            return RuntimeState.DAEMON_DOWN, f"Serviço do {label} não está em execução."
    elif kind is ServiceKind.KUBERNETES:
        if "no configuration has been provided" in lower or "kubeconfig" in lower and "no such file" in lower:
            return RuntimeState.ERROR, "kubectl sem kubeconfig para este usuário (defina KUBECONFIG ou use k3s)."
        if "permission denied" in lower or "forbidden" in lower:
            return RuntimeState.PERMISSION, f"Sem permissão no cluster: {first_line}"
        if "connection to the server" in lower or "unable to connect to the server" in lower:
            return RuntimeState.DAEMON_DOWN, f"API do Kubernetes inacessível: {first_line}"
    elif kind is ServiceKind.LXD:
        if "permission denied" in lower or "needed permissions" in lower:
            return RuntimeState.PERMISSION, ("Sem permissão no LXD/Incus. Adicione o usuário ao grupo 'lxd' "
                                             "(ou 'incus-admin') ou habilite \"lxd_sudo\".")
        if "unix.socket" in lower or "daemon" in lower or "connection refused" in lower:
            return RuntimeState.DAEMON_DOWN, "O serviço do LXD/Incus não está acessível."
    elif kind is ServiceKind.LIBVIRT:
        if "permission denied" in lower or "authentication" in lower:
            return RuntimeState.PERMISSION, ("Sem permissão no libvirt. Adicione o usuário ao grupo 'libvirt' "
                                             "ou habilite \"libvirt_sudo\".")
        if "failed to connect" in lower:
            return RuntimeState.DAEMON_DOWN, "libvirtd não está acessível."
    return RuntimeState.ERROR, f"Erro ao consultar {label}: {first_line}"


# ---------------------------------------------------------------------------
# Métricas do host
# ---------------------------------------------------------------------------

def parse_uptime(text: str) -> float | None:
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def parse_loadavg(text: str) -> tuple[float, float, float] | None:
    try:
        one, five, fifteen = (float(v) for v in text.split()[:3])
    except ValueError:
        return None
    return one, five, fifteen


def parse_cpu_count(text: str) -> int | None:
    try:
        return int(text.strip().splitlines()[0])
    except (IndexError, ValueError):
        return None


CpuSample = tuple[int, ...]


def parse_cpu_samples(text: str) -> list[CpuSample]:
    """Linhas ``cpu ...`` de /proc/stat → (ocioso+iowait, total, iowait, steal) em jiffies."""
    samples: list[CpuSample] = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != "cpu":
            continue
        try:
            values = [int(v) for v in fields[1:]]
        except ValueError:
            continue
        if len(values) < 4:
            continue
        # user nice system idle iowait irq softirq steal (guest já está em user)
        core = values[:8]
        iowait = core[4] if len(core) > 4 else 0
        steal = core[7] if len(core) > 7 else 0
        samples.append((core[3] + iowait, sum(core), iowait, steal))
    return samples


def cpu_breakdown_between(previous: CpuSample, current: CpuSample) -> tuple[float | None, float | None]:
    """(% iowait, % steal) entre duas amostras; None se a amostra não trouxer os campos."""
    if len(previous) < 4 or len(current) < 4:
        return None, None
    total = current[1] - previous[1]
    if total <= 0:
        return None, None
    iowait, steal = current[2] - previous[2], current[3] - previous[3]
    clamp = lambda v: max(0.0, min(100.0, 100.0 * v / total))  # noqa: E731
    return clamp(iowait), clamp(steal)


def cpu_percent_between(previous: CpuSample, current: CpuSample) -> float | None:
    idle_delta = current[0] - previous[0]
    total_delta = current[1] - previous[1]
    if total_delta <= 0 or idle_delta < 0:
        return None
    return max(0.0, min(100.0, 100.0 * (1 - idle_delta / total_delta)))


def parse_free(text: str) -> dict[str, int]:
    """Saída de ``free -m`` → total/used/available (+ swap).

    Suporta o procps moderno (coluna ``available``) e o antigo (linha
    ``-/+ buffers/cache``, ex.: CentOS 6).
    """
    result: dict[str, int] = {}
    header: list[str] = ["total", "used", "free"]
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "total":
            header = fields
            continue
        if fields[0] == "-/+":
            numbers = [int(v) for v in fields[2:] if v.isdigit()]
            if len(numbers) >= 2:
                result["used"], result["available"] = numbers[0], numbers[1]
            continue
        label = fields[0].rstrip(":").lower()
        try:
            values = [int(v) for v in fields[1:]]
        except ValueError:
            continue
        columns = dict(zip(header, values, strict=False))
        if label == "mem":
            result["total"] = columns.get("total", 0)
            result["used"] = columns.get("used", 0)
            if "available" in columns:
                result["available"] = columns["available"]
            else:
                result["available"] = (columns.get("free", 0) + columns.get("buffers", 0)
                                       + columns.get("cached", 0))
        elif label == "swap":
            result["swap_total"] = columns.get("total", 0)
            result["swap_used"] = columns.get("used", 0)
    return result


_PSEUDO_FILESYSTEMS = {"tmpfs", "devtmpfs", "udev", "overlay", "shm", "none", "squashfs",
                       "efivarfs", "proc", "sysfs", "cgroup", "cgroup2", "nsfs", "rootfs"}
_IGNORED_MOUNT_PREFIXES = ("/dev", "/proc", "/sys", "/run", "/snap/", "/var/lib/docker/",
                           "/var/snap/", "/boot/efi", "/var/lib/kubelet/", "/var/lib/containers/")


def _df_rows(text: str):
    seen: set[str] = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        filesystem, mount = fields[0], " ".join(fields[5:])
        if filesystem in _PSEUDO_FILESYSTEMS or mount.startswith(_IGNORED_MOUNT_PREFIXES):
            continue
        if filesystem.startswith("/dev/loop") or mount in seen:
            continue
        seen.add(mount)
        yield filesystem, mount, fields


def parse_df(text: str) -> list[DiskUsage]:
    """Saída de ``df -kP`` (POSIX, blocos de 1 KiB), sem pseudo-sistemas de arquivos."""
    disks: list[DiskUsage] = []
    for filesystem, mount, fields in _df_rows(text):
        try:
            size, used, avail = int(fields[1]), int(fields[2]), int(fields[3])
            use_percent = float(fields[4].rstrip("%"))
        except ValueError:
            continue
        if size > 0:
            disks.append(DiskUsage(filesystem, mount, size, used, avail, use_percent))
    return disks


def parse_df_inodes(text: str) -> dict[str, float]:
    """``df -iP`` → ``{montagem: uso de inodes em %}``."""
    inodes = {}
    for _filesystem, mount, fields in _df_rows(text):
        value = fields[4].rstrip("%")
        if value.replace(".", "", 1).isdigit():
            inodes[mount] = float(value)
    return inodes


_VIRTUAL_IFACE_PREFIXES = ("lo", "veth", "docker", "br-", "virbr", "vnet", "cni", "flannel", "cali",
                           "kube-", "tap", "podman", "tun", "wg", "ifb", "dummy", "vxlan", "genev")


def is_virtual_interface(name: str) -> bool:
    return name.startswith(_VIRTUAL_IFACE_PREFIXES)


def parse_net_dev(text: str) -> dict[str, tuple[int, int]]:
    """``/proc/net/dev`` → ``{interface: (bytes_rx, bytes_tx)}``."""
    counters = {}
    for line in text.splitlines():
        if ":" not in line or "|" in line:
            continue
        name, _, data = line.partition(":")
        fields = data.split()
        if len(fields) >= 9 and fields[0].isdigit() and fields[8].isdigit():
            counters[name.strip()] = (int(fields[0]), int(fields[8]))
    return counters


_WHOLE_DISK_RE = re.compile(r"(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)")


def parse_diskstats(text: str) -> dict[str, tuple[int, int]]:
    """``/proc/diskstats`` → ``{disco: (bytes_lidos, bytes_escritos)}`` (só discos inteiros)."""
    counters = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or not _WHOLE_DISK_RE.fullmatch(fields[2]):
            continue
        try:
            counters[fields[2]] = (int(fields[5]) * 512, int(fields[9]) * 512)
        except ValueError:
            continue
    return counters


@dataclass
class MetricsState:
    """Amostras anteriores usadas para calcular taxas (CPU, rede, disco)."""

    cpu: CpuSample | None = None
    uptime: float | None = None
    net: dict[str, tuple[int, int]] = field(default_factory=dict)
    disk: dict[str, tuple[int, int]] = field(default_factory=dict)


def _rate(current: int, previous: int | None, elapsed: float | None) -> float | None:
    if previous is None or not elapsed or elapsed <= 0 or current < previous:
        return None
    return (current - previous) / elapsed


def parse_metrics(output: str, previous: MetricsState | None) -> tuple[HostMetrics, MetricsState]:
    """Interpreta a saída de :func:`core.commands.build_metrics_command`."""
    previous = previous or MetricsState()
    uptime_s, load_s, nproc_s, cpu_s, free_s, df_s, net_s, disk_s = split_sections(output, 8)[:8]

    samples = parse_cpu_samples(cpu_s)
    cpu_pct = iowait = steal = None
    baseline = samples[-2] if len(samples) >= 2 else previous.cpu if samples else None
    if baseline is not None:
        cpu_pct = cpu_percent_between(baseline, samples[-1])
        iowait, steal = cpu_breakdown_between(baseline, samples[-1])

    uptime = parse_uptime(uptime_s)
    elapsed = uptime - previous.uptime if uptime is not None and previous.uptime is not None else None

    net = parse_net_dev(net_s)
    interfaces = tuple(
        InterfaceStats(
            name=name, rx_bytes=rx, tx_bytes=tx,
            rx_bps=_rate(rx, previous.net.get(name, (None, None))[0], elapsed),
            tx_bps=_rate(tx, previous.net.get(name, (None, None))[1], elapsed),
            virtual=is_virtual_interface(name),
        )
        for name, (rx, tx) in sorted(net.items())
    )
    disk = parse_diskstats(disk_s)
    disk_io = tuple(
        DiskIO(device=name,
               read_bps=_rate(read, previous.disk.get(name, (None, None))[0], elapsed),
               write_bps=_rate(written, previous.disk.get(name, (None, None))[1], elapsed))
        for name, (read, written) in sorted(disk.items())
    )

    memory = parse_free(free_s)
    metrics = HostMetrics(
        uptime_seconds=uptime,
        load_avg=parse_loadavg(load_s),
        cpu_count=parse_cpu_count(nproc_s),
        cpu_percent=cpu_pct,
        cpu_steal=steal,
        cpu_iowait=iowait,
        mem_total_mb=memory.get("total"),
        mem_used_mb=memory.get("used"),
        mem_available_mb=memory.get("available"),
        swap_total_mb=memory.get("swap_total"),
        swap_used_mb=memory.get("swap_used"),
        disks=tuple(parse_df(df_s)),
        interfaces=interfaces,
        disk_io=disk_io,
    )
    state = MetricsState(
        cpu=samples[-1] if samples else previous.cpu,
        uptime=uptime if uptime is not None else previous.uptime,
        net=net or previous.net,
        disk=disk or previous.disk,
    )
    return metrics, state


# ---------------------------------------------------------------------------
# Processos
# ---------------------------------------------------------------------------

@dataclass
class ProcessSample:
    uptime: float
    clk_tck: int
    ticks: dict[int, int]


def _parse_proc_stat_block(text: str) -> tuple[ProcessSample | None, dict[int, tuple[str, str]]]:
    lines = text.splitlines()
    if len(lines) < 2:
        return None, {}
    try:
        uptime = float(lines[0].split()[0])
        clk_tck = int(lines[1].strip()) or 100
    except (IndexError, ValueError):
        return None, {}
    ticks: dict[int, int] = {}
    names: dict[int, tuple[str, str]] = {}
    for line in lines[2:]:
        open_paren, close_paren = line.find("("), line.rfind(")")
        if open_paren < 0 or close_paren < open_paren:
            continue
        try:
            pid = int(line[:open_paren].strip())
            rest = line[close_paren + 1:].split()
            ticks[pid] = int(rest[11]) + int(rest[12])  # utime + stime
            names[pid] = (line[open_paren + 1:close_paren], rest[0])
        except (ValueError, IndexError):
            continue
    return ProcessSample(uptime, clk_tck, ticks), names


def parse_processes(output: str, previous: ProcessSample | None
                    ) -> tuple[list[ProcessInfo], ProcessSample | None]:
    """``ps`` + ``/proc/*/stat`` → processos com CPU instantânea (% de um núcleo).

    Oculta threads do kernel e os processos do próprio coletor.
    """
    parts = split_sections(output)
    ps_text, stat_blocks = parts[0], parts[1:]
    samples = [_parse_proc_stat_block(block) for block in stat_blocks]
    samples = [(s, names) for s, names in samples if s is not None]
    current, names = samples[-1] if samples else (None, {})
    baseline = samples[-2][0] if len(samples) >= 2 else previous

    processes: list[ProcessInfo] = []
    for line in ps_text.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 6 or not fields[0].isdigit():
            continue
        pid = int(fields[0])
        args = fields[6] if len(fields) > 6 else ""
        try:
            mem_pct, rss, elapsed = float(fields[2]), int(fields[3]), int(fields[4])
        except ValueError:
            continue
        if SECTION in args or (rss == 0 and args.startswith("[") and args.endswith("]")):
            continue
        command, state = names.get(pid, ("", fields[5]))
        if not command:
            command = args.split(None, 1)[0].rsplit("/", 1)[-1] if args else "?"
        cpu = None
        if current is not None and baseline is not None and pid in current.ticks and pid in baseline.ticks:
            wall = current.uptime - baseline.uptime
            if wall > 0:
                cpu = 100.0 * (current.ticks[pid] - baseline.ticks[pid]) / current.clk_tck / wall
        processes.append(ProcessInfo(pid=pid, user=fields[1], cpu_percent=cpu, mem_percent=mem_pct,
                                     rss_kb=rss, elapsed_seconds=elapsed, state=fields[5] or state,
                                     command=command, args=args[:500]))
    processes.sort(key=lambda p: (-(p.cpu_percent or 0.0), -p.mem_percent, p.pid))
    return processes, current or previous


# ---------------------------------------------------------------------------
# Rede
# ---------------------------------------------------------------------------

_SS_PROCESS_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def _split_host_port(value: str) -> tuple[str, int] | None:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.strip("[]").split("%", 1)[0]
    return host or "*", int(port)


def parse_ss(text: str) -> list[ListeningSocket]:
    sockets = []
    seen = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in {"tcp", "udp"}:
            continue
        local = _split_host_port(fields[4])
        if local is None:
            continue
        process_match = _SS_PROCESS_RE.search(line)
        entry = ListeningSocket(
            proto=fields[0], address=local[0], port=local[1],
            process=process_match.group(1) if process_match else "",
            pid=int(process_match.group(2)) if process_match else None,
        )
        identity = (entry.proto, entry.address, entry.port)
        if identity not in seen:
            seen.add(identity)
            sockets.append(entry)
    return sorted(sockets, key=lambda s: (s.port, s.proto, s.address))


def _decode_proc_address(hex_addr: str) -> str:
    raw = bytes.fromhex(hex_addr)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    # IPv6: quatro palavras de 32 bits em little-endian.
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return str(ipaddress.IPv6Address(words))


def parse_proc_net(text: str) -> list[ListeningSocket]:
    """Fallback sem ``ss``: ``/proc/net/{tcp,tcp6,udp,udp6}`` (sem nomes de processo)."""
    sockets = []
    proto = ""
    seen = set()
    for line in text.splitlines():
        if line.startswith("## "):
            proto = "tcp" if line[3:].startswith("tcp") else "udp"
            continue
        fields = line.split()
        if len(fields) < 4 or ":" not in fields[1] or fields[0] == "sl":
            continue
        listening_state = "0A" if proto == "tcp" else "07"
        if fields[3] != listening_state:
            continue
        address_hex, _, port_hex = fields[1].partition(":")
        try:
            address, port = _decode_proc_address(address_hex), int(port_hex, 16)
        except ValueError:
            continue
        if (proto, address, port) not in seen:
            seen.add((proto, address, port))
            sockets.append(ListeningSocket(proto=proto, address=address, port=port))
    return sorted(sockets, key=lambda s: (s.port, s.proto, s.address))


def parse_ports(output: str) -> NetworkInfo:
    ports_text, sockstat = split_sections(output, 2)[:2]
    lines = ports_text.splitlines()
    marker = lines[0].strip() if lines else ""
    body = "\n".join(lines[1:])
    if marker == "SS":
        listening = parse_ss(body)
        has_process = any(s.process for s in listening)
    else:
        listening, has_process = parse_proc_net(body), False
    stats: dict[str, dict[str, int]] = {}
    for line in sockstat.splitlines():
        proto, _, rest = line.partition(":")
        values = rest.split()
        stats[proto.strip()] = {values[i]: int(values[i + 1]) for i in range(0, len(values) - 1, 2)
                                if values[i + 1].isdigit()}
    return NetworkInfo(
        listening=tuple(listening),
        tcp_inuse=stats.get("TCP", {}).get("inuse"),
        tcp_timewait=stats.get("TCP", {}).get("tw"),
        udp_inuse=stats.get("UDP", {}).get("inuse"),
        process_info=has_process,
    )


# ---------------------------------------------------------------------------
# Agendamentos, eventos, inventário
# ---------------------------------------------------------------------------

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


def parse_cron(output: str, ssh_user: str = "") -> list[CronEntry]:
    entries = []
    source = ""
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("#@ "):
            parts = line.split(None, 2)
            if len(parts) == 3:
                entries.append(CronEntry(f"/etc/cron.{parts[1]}", f"@{parts[1]}", "root", parts[2]))
            continue
        if line.startswith("## "):
            source = line[3:]
            continue
        if not line or line.startswith("#") or _ENV_ASSIGNMENT_RE.match(line):
            continue
        system_file = not source.startswith("crontab")
        if line.startswith("@"):
            parts = line.split(None, 2 if system_file else 1)
            schedule, rest = parts[0], parts[1:]
        else:
            parts = line.split(None, 6 if system_file else 5)
            schedule, rest = " ".join(parts[:5]), parts[5:]
        if system_file:
            if len(rest) < 2:
                continue
            user, command = rest[0], rest[1]
        else:
            if not rest:
                continue
            user, command = ssh_user or "(usuário SSH)", rest[0]
        entries.append(CronEntry(source or "crontab", schedule, user, command))
    return entries


def parse_journal_json(output: str) -> list[JournalEntry]:
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = item.get("MESSAGE")
        if isinstance(message, list):  # mensagens binárias vêm como lista de bytes
            message = bytes(v for v in message if isinstance(v, int) and 0 <= v < 256).decode("utf-8", "replace")
        try:
            timestamp = int(item.get("__REALTIME_TIMESTAMP", "0")) / 1_000_000
            priority = int(item.get("PRIORITY", "6"))
        except (TypeError, ValueError):
            continue
        entries.append(JournalEntry(
            timestamp=timestamp,
            priority=priority,
            unit=str(item.get("_SYSTEMD_UNIT") or item.get("UNIT") or ""),
            identifier=str(item.get("SYSLOG_IDENTIFIER") or item.get("_COMM") or ""),
            message=str(message or "").strip(),
        ))
    entries.sort(key=lambda e: e.timestamp, reverse=True)
    return entries


_JOURNAL_GROUPS = {"systemd-journal", "adm", "wheel"}


def parse_system_info(output: str, ssh_failures: str = "") -> tuple[SystemInfo, dict[str, float]]:
    info_text, inode_text = split_sections(output, 2)[:2]
    values: dict[str, str] = {}
    temperatures = []
    for line in info_text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "temp":
            label, _, milli = value.rpartition(":")
            if milli.strip().lstrip("-").isdigit():
                temperatures.append((label or "sensor", int(milli) / 1000))
        else:
            values[key] = value.strip()
    groups = values.get("groups", "").split()
    journal_access = None
    if groups:
        journal_access = groups[0] == "root" or bool(_JOURNAL_GROUPS & set(groups[1:]))
    ssh_failed = int(ssh_failures.strip()) if ssh_failures.strip().isdigit() else None

    def to_int(name: str) -> int | None:
        value = values.get(name, "")
        return int(value) if value.isdigit() else None

    info = SystemInfo(
        hostname=values.get("hostname", ""),
        os_name=values.get("os", ""),
        kernel=values.get("kernel", ""),
        arch=values.get("arch", ""),
        cpu_model=values.get("cpu_model", ""),
        virtualization=values.get("virt", "") or "none",
        boot_time=values.get("boot", ""),
        timezone=values.get("timezone", ""),
        logged_users=to_int("users"),
        reboot_required=values.get("reboot_required") == "yes",
        ip_addresses=tuple(values.get("ips", "").split()),
        failed_units=to_int("failed_units"),
        temperatures=tuple(temperatures),
        journal_access=journal_access,
        ssh_failed_logins_24h=ssh_failed if journal_access is not False else None,
    )
    return info, parse_df_inodes(inode_text)


def parse_updates(output: str) -> UpdatesInfo | None:
    text = output.strip().splitlines()[-1].strip() if output.strip() else ""
    manager, _, rest = text.partition(" ")
    if not manager or manager == "unknown":
        return None
    if manager == "apt-check":
        pending, _, security = rest.partition(";")
        return UpdatesInfo("apt", int(pending) if pending.isdigit() else None,
                           int(security) if security.strip().isdigit() else None)
    return UpdatesInfo(manager, int(rest) if rest.strip().isdigit() else None)


# ---------------------------------------------------------------------------
# VPS
# ---------------------------------------------------------------------------

_PROVIDERS = (
    ("digitalocean", "DigitalOcean"), ("hetzner", "Hetzner Cloud"), ("vultr", "Vultr"),
    ("linode", "Akamai/Linode"), ("akamai", "Akamai/Linode"), ("amazon ec2", "AWS EC2"), ("amazon", "AWS"),
    ("google", "Google Cloud"), ("alibaba", "Alibaba Cloud"), ("tencent", "Tencent Cloud"),
    ("oracle", "Oracle Cloud"), ("scaleway", "Scaleway"), ("ovh", "OVHcloud"), ("upcloud", "UpCloud"),
    ("contabo", "Contabo"), ("magalu", "Magalu Cloud"), ("locaweb", "Locaweb"), ("hostinger", "Hostinger"),
    ("openstack", "OpenStack"), ("vmware", "VMware"), ("proxmox", "Proxmox VE"), ("innotek", "VirtualBox"),
    ("xen", "Xen"), ("bochs", "KVM/QEMU"), ("qemu", "KVM/QEMU"),
)


def detect_provider(vendor: str, product: str, bios: str = "", hypervisor: str = "") -> str:
    """Nome amigável da plataforma a partir do DMI (legível sem root)."""
    haystack = " ".join((vendor, product, bios, hypervisor)).lower()
    if "microsoft" in haystack and "virtual machine" in haystack:
        return "Azure / Hyper-V"
    for needle, label in _PROVIDERS:
        if needle in haystack:
            return label
    return vendor.strip() or ("Xen" if hypervisor.strip() == "xen" else "")


def _vnstat_entry_date(entry: dict) -> tuple[int, int, int]:
    date = entry.get("date") if isinstance(entry.get("date"), dict) else {}
    return int(date.get("year") or 0), int(date.get("month") or 0), int(date.get("day") or 0)


def parse_vnstat(month_text: str, day_text: str = "") -> tuple[BandwidthUsage, ...]:
    """JSON do vnStat 2.x (bytes, "month"/"day") ou 1.x (KiB, "months"/"days")."""
    def load(text: str) -> dict:
        text = text.strip()
        if not text.startswith("{"):
            return {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    months, days = load(month_text), load(day_text)
    scale = 1024 if str(months.get("jsonversion", "2")) == "1" else 1
    today: dict[str, tuple[int, int]] = {}
    for iface in days.get("interfaces") or []:
        traffic = iface.get("traffic") or {}
        entries = [e for e in (traffic.get("day") or traffic.get("days") or []) if isinstance(e, dict)]
        if entries:
            latest = max(entries, key=_vnstat_entry_date)
            day_scale = 1024 if str(days.get("jsonversion", "2")) == "1" else 1
            today[str(iface.get("name") or iface.get("id") or "")] = (int(latest.get("rx", 0)) * day_scale,
                                             int(latest.get("tx", 0)) * day_scale)
    usage = []
    for iface in months.get("interfaces") or []:
        name = str(iface.get("name") or iface.get("id") or "")
        if not name or is_virtual_interface(name):
            continue
        traffic = iface.get("traffic") or {}
        entries = [e for e in (traffic.get("month") or traffic.get("months") or []) if isinstance(e, dict)]
        if not entries:
            continue
        latest = max(entries, key=_vnstat_entry_date)
        year, month, _ = _vnstat_entry_date(latest)
        rx_today, tx_today = today.get(name, (None, None))
        usage.append(BandwidthUsage(interface=name, period=f"{year:04d}-{month:02d}",
                                    rx_bytes=int(latest.get("rx", 0)) * scale,
                                    tx_bytes=int(latest.get("tx", 0)) * scale,
                                    today_rx=rx_today, today_tx=tx_today))
    return tuple(usage)


_OOM_PROCESS_RE = re.compile(r"Kill(?:ed)? process \d+ \(([^)]*)\)")


def parse_vps(output: str) -> VpsInfo:
    """Saída de :data:`core.commands.VPS_CMD`."""
    host_s, time_s, oom_s, vnstat_s = split_sections(output, 4)[:4]
    values: dict[str, str] = {}
    dns, gateway = [], ""
    for line in host_s.splitlines():
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) > 1:
                dns.append(parts[1])
        elif line.startswith("default ") and not gateway:
            parts = line.split()
            gateway = " ".join(parts[1:5]) if len(parts) > 2 else ""
            if "via" in parts and "dev" in parts:
                gateway = f"{parts[parts.index('via') + 1]} ({parts[parts.index('dev') + 1]})"
        else:
            key, sep, value = line.partition("=")
            if sep:
                values[key.strip()] = value.strip()

    synced, ntp_service, offset = None, "", None
    for line in time_s.splitlines():
        key, sep, value = line.partition("=") if "=" in line else line.partition(":")
        key, value = key.strip().lower(), value.strip().lower()
        if key in {"ntpsynchronized", "system clock synchronized", "ntp synchronized"}:
            synced = value == "yes"
        elif key in {"ntp", "ntp service", "network time on"}:
            ntp_service = {"yes": "ativo", "active": "ativo", "no": "inativo", "inactive": "inativo"}.get(value, value)
        elif key == "system time":
            match = re.match(r"([\d.]+) seconds (fast|slow)", value)
            if match:
                offset = float(match.group(1)) * (1 if match.group(2) == "fast" else -1)

    oom_total, kills = None, []
    for line in oom_s.splitlines():
        if line.startswith("OOM_TOTAL"):
            parts = line.split()
            oom_total = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            continue
        match = _OOM_PROCESS_RE.search(line)
        stamp = line.split(None, 1)[0] if line.strip() else ""
        if match:
            try:
                kills.append(OomKill(float(stamp), match.group(1)))
            except ValueError:
                continue

    bandwidth, source = (), ""
    if vnstat_s.strip() and not vnstat_s.strip().startswith("NOVNSTAT"):
        month_text, _, day_text = vnstat_s.partition("#DAY")
        bandwidth = parse_vnstat(month_text, day_text)
        source = "vnstat"
    swappiness = values.get("swappiness", "")
    return VpsInfo(
        provider=detect_provider(values.get("sys_vendor", ""), values.get("product_name", ""),
                                 values.get("bios_vendor", ""), values.get("hypervisor", "")),
        product=" ".join(v for v in (values.get("sys_vendor", ""), values.get("product_name", "")) if v),
        ntp_synchronized=synced,
        ntp_service=ntp_service,
        clock_offset=offset,
        dns_servers=tuple(dns),
        default_gateway=gateway,
        swappiness=int(swappiness) if swappiness.isdigit() else None,
        oom_kills=tuple(sorted(kills, key=lambda k: k.timestamp, reverse=True)),
        oom_kills_24h=oom_total,
        bandwidth=bandwidth,
        bandwidth_source=source,
    )


# ---------------------------------------------------------------------------
# SMART
# ---------------------------------------------------------------------------

_ATA_ATTRIBUTES = {5: "reallocated", 197: "pending", 198: "uncorrectable"}


def _smart_disk(device: str, text: str) -> SmartDisk:
    start = text.find("{")
    try:
        data = json.loads(text[start:]) if start >= 0 else None
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        first = next((line.strip() for line in text.splitlines() if line.strip()), "sem resposta")
        if "unrecognized option" in text.lower() or "unknown option" in text.lower():
            first = "smartctl sem suporte a JSON (-j): atualize para smartmontools 7 ou superior"
        return SmartDisk(device=device, message=first[:200])
    status = data.get("smart_status") if isinstance(data.get("smart_status"), dict) else {}
    nvme = data.get("nvme_smart_health_information_log")
    nvme = nvme if isinstance(nvme, dict) else {}
    attributes: dict[str, int] = {}
    table = (data.get("ata_smart_attributes") or {}).get("table") if isinstance(
        data.get("ata_smart_attributes"), dict) else None
    for row in table or []:
        if isinstance(row, dict) and row.get("id") in _ATA_ATTRIBUTES:
            raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
            if isinstance(raw.get("value"), int):
                attributes[_ATA_ATTRIBUTES[row["id"]]] = raw["value"]
    temperature = (data.get("temperature") or {}).get("current") if isinstance(data.get("temperature"), dict) \
        else None
    if temperature is None and isinstance(nvme.get("temperature"), int | float):
        temperature = nvme["temperature"]
    hours = (data.get("power_on_time") or {}).get("hours") if isinstance(data.get("power_on_time"), dict) else None
    capacity = (data.get("user_capacity") or {}).get("bytes") if isinstance(data.get("user_capacity"), dict) \
        else data.get("nvme_total_capacity")
    message = ""
    if "passed" not in status:
        messages = (data.get("smartctl") or {}).get("messages") if isinstance(data.get("smartctl"), dict) else None
        errors = [m.get("string", "") for m in messages or [] if isinstance(m, dict)]
        message = next((m for m in errors if m), "SMART indisponível neste dispositivo")
    return SmartDisk(
        device=str((data.get("device") or {}).get("name") or device) if isinstance(data.get("device"), dict)
        else device,
        model=str(data.get("model_name") or data.get("model_family") or ""),
        serial=str(data.get("serial_number") or ""),
        capacity_bytes=capacity if isinstance(capacity, int) else None,
        passed=status.get("passed") if isinstance(status.get("passed"), bool) else None,
        temperature=float(temperature) if isinstance(temperature, int | float) else None,
        power_on_hours=hours if isinstance(hours, int) else nvme.get("power_on_hours"),
        reallocated=attributes.get("reallocated"),
        pending=attributes.get("pending"),
        uncorrectable=attributes.get("uncorrectable"),
        media_errors=nvme.get("media_errors") if isinstance(nvme.get("media_errors"), int) else None,
        percentage_used=nvme.get("percentage_used") if isinstance(nvme.get("percentage_used"), int) else None,
        critical_warning=nvme.get("critical_warning") if isinstance(nvme.get("critical_warning"), int) else None,
        message=message[:200],
    )


def parse_smart(output: str) -> SmartReport:
    blocks = re.split(r"^## (\S+)\s*$", output, flags=re.M)
    disks = tuple(_smart_disk(blocks[i], blocks[i + 1]) for i in range(1, len(blocks) - 1, 2))
    if not disks:
        return SmartReport(RuntimeState.OK, (), "Nenhum disco físico com SMART (discos virtuais de VPS não têm).")
    lowered = " ".join(d.message.lower() for d in disks)
    if all(d.message for d in disks) and ("permission denied" in lowered or "a password is required" in lowered
                                          or "operation not permitted" in lowered):
        return SmartReport(RuntimeState.PERMISSION, disks,
                           "O smartctl precisa de root: habilite \"smart_sudo\" (NOPASSWD no sudoers).")
    return SmartReport(RuntimeState.OK, disks)


# ---------------------------------------------------------------------------
# Segurança
# ---------------------------------------------------------------------------

_SSHD_MULTI = {"port", "listenaddress", "allowusers", "allowgroups", "denyusers", "denygroups"}
_SSHD_SPLIT_RE = re.compile(r"\s*=\s*|\s+")


def _sshd_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = _SSHD_SPLIT_RE.split(line, maxsplit=1)
    if len(parts) < 2:
        return None
    return parts[0].lower(), parts[1].strip().strip('"')


def parse_sshd_effective(text: str) -> dict[str, str]:
    """``sshd -T``: uma opção por linha, chaves já minúsculas e valores efetivos."""
    config: dict[str, str] = {}
    for line in text.splitlines():
        parsed = _sshd_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key in _SSHD_MULTI and key in config:
            config[key] += " " + value
        else:
            config.setdefault(key, value)
    return config


def parse_sshd_files(text: str) -> dict[str, str]:
    """Emula a leitura do sshd sem root: ``Include`` (glob, ordem alfabética), primeira
    ocorrência vence e tudo após ``Match`` é condicional (ignorado)."""
    files: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("#FILE "):
            current = line[6:].strip()
            files[current] = []
        elif current is not None:
            files[current].append(line)
    config: dict[str, str] = {}
    visited: set[str] = set()

    def process(path: str, depth: int) -> None:
        if path in visited or depth > 8:
            return
        visited.add(path)
        for raw in files.get(path, ()):
            parsed = _sshd_line(raw)
            if parsed is None:
                continue
            key, value = parsed
            if key == "match":
                return
            if key == "include":
                for pattern in value.split():
                    pattern = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                    for candidate in sorted(p for p in files if fnmatch.fnmatchcase(p, pattern)):
                        process(candidate, depth + 1)
                continue
            if key in _SSHD_MULTI and key in config:
                config[key] += " " + value
            else:
                config.setdefault(key, value)

    main = "/etc/ssh/sshd_config"
    for path in ([main] if main in files else list(files)):
        process(path, 0)
    return config


_KEY_RE = re.compile(r"(?:^|\s)((?:ssh|ecdsa|sk)-[A-Za-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$")
_KEY_BITS = {"ssh-ed25519": 256, "sk-ssh-ed25519@openssh.com": 256, "ssh-dss": 1024}


def _rsa_bits(blob: bytes) -> int | None:
    try:
        offset, fields = 0, []
        for _ in range(3):  # "ssh-rsa", e, n
            (length,) = struct.unpack(">I", blob[offset:offset + 4])
            fields.append(blob[offset + 4:offset + 4 + length])
            offset += 4 + length
        return int.from_bytes(fields[2], "big").bit_length()
    except (struct.error, IndexError):
        return None


def parse_authorized_keys(text: str) -> tuple[AuthorizedKey, ...]:
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _KEY_RE.search(line)
        if not match:
            continue
        key_type, encoded, comment = match.group(1), match.group(2), (match.group(3) or "").strip()
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            continue
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        bits = _rsa_bits(blob) if key_type == "ssh-rsa" else _KEY_BITS.get(key_type)
        if bits is None and "nistp" in key_type:
            bits = int(re.search(r"nistp(\d+)", key_type).group(1))
        options = line[:match.start(1)].strip()
        keys.append(AuthorizedKey(key_type, bits, fingerprint, comment,
                                  restricted=any(o in options for o in ("from=", "command=", "restrict"))))
    return tuple(keys)


def parse_who(text: str) -> tuple[SessionInfo, ...]:
    sessions = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        source = ""
        if fields[-1].startswith("(") and fields[-1].endswith(")"):
            source = fields[-1][1:-1]
            fields = fields[:-1]
        sessions.append(SessionInfo(user=fields[0], tty=fields[1], source=source, since=" ".join(fields[2:])))
    return tuple(sessions)


def parse_security(output: str) -> SecurityRaw:
    """Saída de :func:`core.commands.build_security_command` (sem o fail2ban)."""
    sshd_s, kv_s, who_s, keys_s = split_sections(output, 4)[:4]
    if sshd_s.lstrip().startswith("#FILES"):
        sshd = parse_sshd_files(sshd_s)
        sshd_source = "arquivos" if sshd else ""
    else:
        sshd = parse_sshd_effective(sshd_s)
        sshd_source = "sshd -T" if sshd else ""
    services, binaries, sysctl = {}, set(), {}
    uid0, logins, sudoers = [], [], []
    values: dict[str, str] = {}
    ufw_lines: list[str] | None = None
    for line in kv_s.splitlines():
        if ufw_lines is not None:
            ufw_lines.append(line)
            continue
        if line.strip() == "#UFW":
            ufw_lines = []
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "svc":
            name, _, state = value.partition("=")
            services[name] = state.strip()
        elif key == "bin":
            binaries.add(value.strip())
        elif key == "sysctl":
            name, _, setting = value.partition("=")
            sysctl[name.replace("/", ".")] = setting.strip()
        elif key == "uid0":
            uid0.append(value.strip())
        elif key == "login":
            logins.append(value.strip())
        elif key == "sudoer":
            sudoers.append(value.strip())
        else:
            values[key] = value.strip()

    def to_int(name: str) -> int | None:
        return int(values[name]) if values.get(name, "").isdigit() else None

    ufw_status = "\n".join(ufw_lines or []).strip()
    ufw_enabled = {"yes": True, "no": False}.get(values.get("ufw_enabled", "").lower())
    if ufw_status.lower().startswith("status: active"):
        ufw_enabled = True
    elif ufw_status.lower().startswith("status: inactive"):
        ufw_enabled = False
    apparmor = {"y": True, "n": False}.get(values.get("apparmor", "").lower())
    return SecurityRaw(
        sshd=sshd, sshd_source=sshd_source, services=services, binaries=frozenset(binaries),
        ssh_client=values.get("ssh_client", ""), ufw_enabled=ufw_enabled, ufw_status=ufw_status,
        iptables_rules=to_int("ipt_rules"), iptables_input_policy=values.get("ipt_policy", ""),
        nft_rules=to_int("nft_rules"), uid0_users=tuple(uid0), login_users=tuple(logins),
        sudo_users=tuple(dict.fromkeys(sudoers)), sysctl=sysctl, apparmor=apparmor,
        selinux=values.get("selinux", ""), auto_updates=values.get("auto_apt"),
        tmp_mode=values.get("tmp_mode", ""), sessions=parse_who(who_s),
        authorized_keys=parse_authorized_keys(keys_s),
    )


_F2B_NUMBER_RE = {
    "currently_failed": re.compile(r"Currently failed:\s*(\d+)"),
    "total_failed": re.compile(r"Total failed:\s*(\d+)"),
    "currently_banned": re.compile(r"Currently banned:\s*(\d+)"),
    "total_banned": re.compile(r"Total banned:\s*(\d+)"),
}
_F2B_BANNED_RE = re.compile(r"Banned IP list:[ \t]*(.*)")


def parse_fail2ban(output: str) -> tuple[Fail2banJail, ...]:
    jails = []
    for block in re.split(r"^## ", output, flags=re.M)[1:]:
        name, _, body = block.partition("\n")
        numbers = {}
        for field_name, pattern in _F2B_NUMBER_RE.items():
            match = pattern.search(body)
            numbers[field_name] = int(match.group(1)) if match else None
        banned = _F2B_BANNED_RE.search(body)
        ips = tuple(ip for ip in (banned.group(1).split() if banned else ()) if ip)[:500]
        jails.append(Fail2banJail(name=name.strip(), banned_ips=ips, **numbers))
    return tuple(jails)


_ACCEPTED_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+")


def parse_ssh_logins(output: str, complete: bool = True) -> SshLoginReport:
    total, sources, accepted = 0, [], []
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "TOTAL" and len(fields) > 1 and fields[1].isdigit():
            total = int(fields[1])
        elif fields[0] == "F" and len(fields) >= 4 and fields[1].isdigit():
            try:
                sources.append(FailedLoginSource(source=fields[3], count=int(fields[1]),
                                                 last_seen=float(fields[2]),
                                                 last_user=fields[4] if len(fields) > 4 else ""))
            except ValueError:
                continue
        else:
            match = _ACCEPTED_RE.search(line)
            if match:
                try:
                    accepted.append(LoginEvent(float(fields[0]), match.group(2), match.group(3), match.group(1)))
                except ValueError:
                    continue
    sources.sort(key=lambda s: (-s.count, -s.last_seen))
    accepted.sort(key=lambda e: e.timestamp, reverse=True)
    return SshLoginReport(tuple(accepted), tuple(sources[:500]), total, complete)


_SUDO_LINE_RE = re.compile(r"^(\S+)\s+\S+\s+\S+\s+(\S+) : (.*)$")


def parse_sudo_log(output: str) -> tuple[SudoEvent, ...]:
    events = []
    for line in output.splitlines():
        match = _SUDO_LINE_RE.match(line.strip())
        if not match:
            continue
        stamp, user, body = match.groups()
        _, _, command = body.partition("COMMAND=")
        fields = {}
        for part in body.split(" ; "):
            key, sep, value = part.partition("=")
            if sep and key.isupper():
                fields[key] = value
        lower = body.lower()
        outcome = "senha incorreta" if "incorrect password" in lower else "negado" if "not in sudoers" in lower \
            else "ok"
        try:
            events.append(SudoEvent(float(stamp), user, command.strip(), outcome, fields.get("USER", ""),
                                    fields.get("TTY", "")))
        except ValueError:
            continue
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return tuple(events)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def describe_sudo_failure(output: str) -> str | None:
    lower = output.lower()
    if "a password is required" in lower or "a terminal is required" in lower:
        return ("O sudo exigiu senha. Libere o comando com NOPASSWD no sudoers "
                "(veja docs/sudoers.example) — o monitor nunca envia senhas ao sudo.")
    if "not in the sudoers file" in lower or "is not allowed to execute" in lower:
        return "O usuário SSH não tem permissão no sudoers para este comando."
    if "interactive authentication required" in lower or "access denied" in lower:
        return ("O systemd/polkit negou a operação. Habilite \"use_sudo\" e configure o "
                "sudoers com NOPASSWD para os comandos permitidos.")
    if "operation not permitted" in lower:
        return "Operação não permitida para o usuário SSH (processo de outro usuário?)."
    if "you must be root" in lower or "permission denied to socket" in lower:
        return "O fail2ban-client exige root: habilite \"security_sudo\" e libere o comando no sudoers."
    return None


def format_timestamp(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%d/%m %H:%M:%S")
