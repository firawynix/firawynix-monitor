"""Construção e validação de comandos remotos (funções puras, sem rede).

Regras de segurança aplicadas a TODOS os comandos:

* nomes vindos do servidor (unidades, contêineres, pods, VMs) passam por uma
  whitelist e nunca podem começar com ``-`` (não viram opções);
* todo valor variável passa por ``shlex.quote``;
* ``sudo`` é sempre ``sudo -n`` (não interativo — nunca pede senha);
* o comando final roda via ``sh -c`` com ``LC_ALL=C`` para saída previsível.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence

from core.models import SYSTEMD_UNIT_TYPES, ServiceAction

#: Separador de seções em comandos compostos (um round-trip, várias saídas).
SECTION = "__FWX_SECTION__"

# Unidades systemd: letras, dígitos e ":-_.\@" ("\" aparece em nomes escapados,
# ex.: systemd-fsck@dev-disk-by\x2duuid-....service).
_UNIT_NAME_RE = re.compile(r"[A-Za-z0-9_@:.\\][A-Za-z0-9_@:.\\-]{0,255}")
# Contêineres Docker/Podman: [a-zA-Z0-9][a-zA-Z0-9_.-]+ (ou ID hexadecimal).
_CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
# Kubernetes: nomes DNS-1123 (namespace e pod).
_K8S_NAME_RE = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
# libvirt: nomes de domínio sem "/" nem espaços.
_VM_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+:-]{0,127}")
_KUBECTL_RE = re.compile(r"[A-Za-z0-9_./-]+( [A-Za-z0-9_./-]+)?")
_LIBVIRT_URI_RE = re.compile(r"[a-z+]+://[A-Za-z0-9_./@:-]*")


def _validate(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{what} inválido: {value!r}")
    return value


def validate_unit_name(name: str) -> str:
    return _validate(_UNIT_NAME_RE, name, "Nome de unidade")


def validate_container_name(name: str) -> str:
    return _validate(_CONTAINER_NAME_RE, name, "Nome de contêiner")


def validate_pod_ref(ref: str) -> tuple[str, str]:
    namespace, _, pod = (ref or "").partition("/")
    _validate(_K8S_NAME_RE, namespace, "Namespace")
    _validate(_K8S_NAME_RE, pod, "Nome de pod")
    return namespace, pod


def validate_vm_name(name: str) -> str:
    return _validate(_VM_NAME_RE, name, "Nome de VM")


def validate_kubectl_command(command: str) -> str:
    """Aceita ``kubectl``, ``k3s kubectl``, ``microk8s kubectl`` ou um caminho absoluto."""
    return _validate(_KUBECTL_RE, command, "Comando kubectl")


def validate_libvirt_uri(uri: str) -> str:
    return _validate(_LIBVIRT_URI_RE, uri, "URI do libvirt")


def validate_pid(pid: int) -> int:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        raise ValueError(f"PID inválido: {pid!r}")
    return pid


def sudo(use_sudo: bool) -> str:
    return "sudo -n " if use_sudo else ""


def wrap_remote_command(command: str) -> str:
    """Executa via ``sh -c`` com locale C: saída previsível independentemente do
    shell de login (bash, zsh, fish...)."""
    return f"env LC_ALL=C LANG=C sh -c {shlex.quote(command)}"


def with_timeout(command: str, seconds: int) -> str:
    """Usa ``timeout`` do coreutils quando existir (evita travar em NFS etc.)."""
    return f"if command -v timeout >/dev/null 2>&1; then timeout {int(seconds)} {command}; else {command}; fi"


def sections(*parts: str) -> str:
    """Junta comandos em um único round-trip, separados por :data:`SECTION`."""
    return f"; echo {SECTION}; ".join(f"{{ {part}; }}" for part in parts)


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------

def build_list_units_command(unit_types: Sequence[str], json_output: bool) -> str:
    types = ",".join(t for t in unit_types if t in SYSTEMD_UNIT_TYPES) or "service"
    base = f"systemctl list-units --type={types} --all --no-pager"
    return f"{base} --output=json" if json_output else f"{base} --plain --no-legend"


def build_unit_action_command(unit: str, action: ServiceAction, use_sudo: bool) -> str:
    """``--no-block`` enfileira o job e retorna na hora: unidades lentas aparecem
    como "Iniciando" na coleta seguinte sem estourar o limite de 5 s."""
    return f"{sudo(use_sudo)}systemctl --no-block {action.value} {shlex.quote(validate_unit_name(unit))}"


def build_journal_command(unit: str, lines: int, use_sudo: bool) -> str:
    return f"{sudo(use_sudo)}journalctl -u {shlex.quote(validate_unit_name(unit))} -n {int(lines)} --no-pager"


#: Uso de CPU/memória por serviço lido do cgroup v2 (sem custo extra no servidor).
CGROUP_SERVICES_CMD = (
    "cat /proc/uptime; "
    "if [ -f /sys/fs/cgroup/cgroup.controllers ] && cd /sys/fs/cgroup/system.slice 2>/dev/null; then "
    "for d in *.service; do [ -d \"$d\" ] || continue; "
    "printf '%s %s %s\\n' \"$d\" \"$(cat \"$d/memory.current\" 2>/dev/null || echo -)\" "
    "\"$(sed -n 's/^usage_usec //p' \"$d/cpu.stat\" 2>/dev/null)\"; done; fi"
)

#: Timers: ``systemctl show`` com padrão funciona em versões antigas e novas.
TIMERS_CMD = (
    "systemctl show --no-pager "
    "--property=Id,Description,Unit,NextElapseUSecRealtime,LastTriggerUSec,ActiveState -- '*.timer'"
)


# ---------------------------------------------------------------------------
# Docker / Podman
# ---------------------------------------------------------------------------

def _runtime(runtime: str) -> str:
    if runtime not in ("docker", "podman"):
        raise ValueError(f"Runtime inválido: {runtime!r}")
    return runtime


def build_container_ps_command(runtime: str, use_sudo: bool) -> str:
    if _runtime(runtime) == "podman":
        return f"{sudo(use_sudo)}podman ps -a --format json"
    return f"{sudo(use_sudo)}docker ps -a --format '{{{{json .}}}}'"


def build_container_stats_command(runtime: str, use_sudo: bool) -> str:
    # "|" como separador: não aparece em nomes de contêiner e dispensa escapes.
    fmt = "'{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}'"
    return f"{sudo(use_sudo)}{_runtime(runtime)} stats --no-stream --format {fmt}"


def build_container_action_command(runtime: str, names: Sequence[str], action: ServiceAction,
                                   use_sudo: bool) -> str:
    """Aceita vários contêineres (ações em uma stack inteira em um só comando)."""
    if not names:
        raise ValueError("Nenhum contêiner informado")
    quoted = " ".join(shlex.quote(validate_container_name(n)) for n in names)
    # -t 3: no máximo 3 s de espera pelo SIGTERM antes do SIGKILL (cabe no timeout).
    stop_timeout = "" if action is ServiceAction.START else " -t 3"
    return f"{sudo(use_sudo)}{_runtime(runtime)} {action.value}{stop_timeout} {quoted}"


def build_container_logs_command(runtime: str, name: str, lines: int, use_sudo: bool) -> str:
    quoted = shlex.quote(validate_container_name(name))
    return f"{sudo(use_sudo)}{_runtime(runtime)} logs --tail {int(lines)} --timestamps {quoted} 2>&1"


def build_stack_logs_command(runtime: str, names: Sequence[str], lines: int, use_sudo: bool) -> str:
    """Logs de todos os contêineres de uma stack, com cabeçalho por contêiner."""
    parts = []
    for name in names:
        quoted = shlex.quote(validate_container_name(name))
        parts.append(f"printf '===== %s =====\\n' {quoted}; "
                     f"{sudo(use_sudo)}{_runtime(runtime)} logs --tail {int(lines)} --timestamps {quoted} 2>&1")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------

_POD_COLUMNS = ",".join([
    "NS:.metadata.namespace",
    "NAME:.metadata.name",
    "PHASE:.status.phase",
    "READY:.status.containerStatuses[*].ready",
    "RESTARTS:.status.containerStatuses[*].restartCount",
    "WAITING:.status.containerStatuses[*].state.waiting.reason",
    "TERMINATED:.status.containerStatuses[*].state.terminated.reason",
    "NODE:.spec.nodeName",
    "CREATED:.metadata.creationTimestamp",
    "DELETING:.metadata.deletionTimestamp",
    "OWNER:.metadata.ownerReferences[0].kind",
])


def _kubectl(command: str, use_sudo: bool) -> str:
    return f"{sudo(use_sudo)}{validate_kubectl_command(command)}"


def build_pods_command(kubectl: str, use_sudo: bool) -> str:
    columns = shlex.quote(f"custom-columns={_POD_COLUMNS}")  # "[*]" não pode virar glob
    return f"{_kubectl(kubectl, use_sudo)} get pods -A --no-headers --request-timeout=4s -o {columns}"


def build_pod_restart_command(kubectl: str, ref: str, use_sudo: bool) -> str:
    namespace, pod = validate_pod_ref(ref)
    return (f"{_kubectl(kubectl, use_sudo)} delete pod -n {shlex.quote(namespace)} {shlex.quote(pod)} "
            "--wait=false --request-timeout=4s")


def build_pod_logs_command(kubectl: str, ref: str, lines: int, use_sudo: bool) -> str:
    namespace, pod = validate_pod_ref(ref)
    return (f"{_kubectl(kubectl, use_sudo)} logs -n {shlex.quote(namespace)} {shlex.quote(pod)} "
            f"--tail={int(lines)} --all-containers=true --timestamps --request-timeout=4s 2>&1")


# ---------------------------------------------------------------------------
# libvirt
# ---------------------------------------------------------------------------

def _virsh(uri: str, use_sudo: bool) -> str:
    return f"{sudo(use_sudo)}virsh -c {shlex.quote(validate_libvirt_uri(uri))}"


def build_vm_list_command(uri: str, use_sudo: bool) -> str:
    return f"{_virsh(uri, use_sudo)} -q list --all"


def build_vm_action_command(uri: str, name: str, action: ServiceAction, use_sudo: bool) -> str:
    # stop = desligamento ACPI gracioso (shutdown), nunca "destroy".
    verb = {"start": "start", "stop": "shutdown", "restart": "reboot"}[action.value]
    return f"{_virsh(uri, use_sudo)} {verb} {shlex.quote(validate_vm_name(name))}"


def build_vm_info_command(uri: str, name: str, use_sudo: bool) -> str:
    quoted = shlex.quote(validate_vm_name(name))
    virsh = _virsh(uri, use_sudo)
    return f"{virsh} dominfo {quoted}; echo; {virsh} domblklist {quoted}; echo; {virsh} domifaddr {quoted} 2>&1"


# ---------------------------------------------------------------------------
# Host: métricas, processos, rede, inventário
# ---------------------------------------------------------------------------

def build_metrics_command(sample_cpu_twice: bool) -> str:
    """Um único round-trip: uptime, load, CPU, memória, discos, rede e E/S."""
    cpu = "grep '^cpu ' /proc/stat"
    if sample_cpu_twice:
        # Primeira coleta: duas amostras para já exibir o uso de CPU.
        cpu = f"{cpu}; sleep 0.5; {cpu}"
    return sections(
        "cat /proc/uptime",
        "cat /proc/loadavg",
        "nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo",
        cpu,
        "free -m",
        with_timeout("df -kP", 2) + " 2>/dev/null",
        "cat /proc/net/dev",
        "cat /proc/diskstats",
    )


def build_processes_command(sample_twice: bool) -> str:
    """``ps`` para os metadados + ``/proc/*/stat`` para a CPU instantânea (delta)."""
    stat = "cat /proc/uptime; getconf CLK_TCK 2>/dev/null || echo 100; cat /proc/[0-9]*/stat 2>/dev/null"
    if sample_twice:
        stat = f"{stat}; echo {SECTION}; sleep 0.5; {stat}"
    return sections(
        # Sem "comm": pode conter espaços; o nome vem do /proc/<pid>/stat.
        "ps -eo pid=,user:32=,pmem=,rss=,etimes=,stat=,args=",
        stat,
    )


def build_ports_command(use_sudo: bool) -> str:
    """``ss`` quando disponível; senão lê ``/proc/net`` diretamente."""
    return sections(
        # Sem -H (ausente em iproute2 antigos): o parser ignora o cabeçalho.
        f"if command -v ss >/dev/null 2>&1; then echo SS; {sudo(use_sudo)}ss -tulnp 2>/dev/null || ss -tulnp; "
        "else echo PROC; for f in tcp tcp6 udp udp6; do echo \"## $f\"; cat /proc/net/$f 2>/dev/null; done; fi",
        "cat /proc/net/sockstat",
    )


def build_kill_command(pid: int, force: bool, use_sudo: bool) -> str:
    signal = "KILL" if force else "TERM"
    return f"{sudo(use_sudo)}kill -{signal} {validate_pid(pid)}"


SYSTEM_INFO_CMD = sections(
    # os-release é lido em subshell para não vazar variáveis.
    "( . /etc/os-release 2>/dev/null; echo \"os=${PRETTY_NAME:-$(uname -s)}\" ); "
    "echo \"kernel=$(uname -r)\"; echo \"arch=$(uname -m)\"; "
    "echo \"hostname=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)\"; "
    "echo \"cpu_model=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n 1)\"; "
    "echo \"virt=$(systemd-detect-virt 2>/dev/null)\"; "
    "echo \"boot=$(uptime -s 2>/dev/null)\"; "
    "tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||'); "
    "[ -n \"$tz\" ] || tz=$(cat /etc/timezone 2>/dev/null); echo \"timezone=$tz\"; "
    "echo \"users=$(who 2>/dev/null | wc -l)\"; "
    "echo \"reboot_required=$([ -f /var/run/reboot-required ] && echo yes || echo no)\"; "
    "echo \"ips=$(hostname -I 2>/dev/null)\"; "
    "echo \"failed_units=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | wc -l)\"; "
    "echo \"groups=$(id -un) $(id -nG)\"; "
    "for z in /sys/class/thermal/thermal_zone*; do [ -r \"$z/temp\" ] && "
    "echo \"temp=$(cat \"$z/type\" 2>/dev/null):$(cat \"$z/temp\")\"; done; true",
    with_timeout("df -iP", 2) + " 2>/dev/null",
)

SSH_FAILURES_CMD = with_timeout(
    "journalctl _COMM=sshd --since=-24h -o cat --no-pager", 3
) + " 2>/dev/null | grep -ciE 'failed password|invalid user|authentication failure'"


def build_events_command(priority: str, limit: int, since_hours: int) -> str:
    return (f"journalctl -p {shlex.quote(priority)} -n {int(limit)} --since=-{int(since_hours)}h "
            "-o json --no-pager 2>/dev/null")


CRON_CMD = (
    "echo '## crontab do usuário'; crontab -l 2>/dev/null; "
    "echo '## /etc/crontab'; cat /etc/crontab 2>/dev/null; "
    "for f in /etc/cron.d/*; do [ -f \"$f\" ] && { echo \"## $f\"; cat \"$f\"; }; done; "
    "for p in hourly daily weekly monthly; do for f in /etc/cron.$p/*; do "
    "[ -f \"$f\" ] && echo \"#@ $p $f\"; done; done; true"
)

_UPDATES_SCRIPT = r"""
if [ -x /usr/lib/update-notifier/apt-check ]; then
  echo "apt-check $(/usr/lib/update-notifier/apt-check 2>&1)"
elif command -v apt-get >/dev/null 2>&1; then
  echo "apt $(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -c '^Inst')"
elif command -v dnf >/dev/null 2>&1; then
  echo "dnf $(dnf -q -C check-update 2>/dev/null | grep -cE '^[[:alnum:]_.+-]+ +[^ ]+ +[^ ]+$')"
elif command -v yum >/dev/null 2>&1; then
  echo "yum $(yum -q -C check-update 2>/dev/null | grep -cE '^[[:alnum:]_.+-]+ +[^ ]+ +[^ ]+$')"
elif command -v apk >/dev/null 2>&1; then
  echo "apk $(apk -u list 2>/dev/null | wc -l)"
elif command -v zypper >/dev/null 2>&1; then
  echo "zypper $(zypper -q --no-refresh lu 2>/dev/null | grep -c '^v ')"
else
  echo unknown
fi
"""
#: Atualizações pendentes somente a partir do cache local (nunca acessa a rede).
UPDATES_CMD = with_timeout("sh -c " + shlex.quote(_UPDATES_SCRIPT.strip()), 4)
