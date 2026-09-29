"""Construção e validação de comandos remotos (funções puras, sem rede).

Regras de segurança aplicadas a TODOS os comandos:

* nomes vindos do servidor (unidades, contêineres, pods, VMs) passam por uma
  whitelist e nunca podem começar com ``-`` (não viram opções);
* todo valor variável passa por ``shlex.quote``;
* ``sudo`` é sempre ``sudo -n`` (não interativo — nunca pede senha);
* o comando final roda via ``sh -c`` com ``LC_ALL=C`` para saída previsível.
"""

from __future__ import annotations

import ipaddress
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
# LXD/Incus: letras, dígitos e hífens, começando por letra (até 63).
_LXD_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,62}")
# fail2ban: nomes de jail ("sshd", "nginx-http-auth", "recidive").
_JAIL_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
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


def validate_lxd_name(name: str) -> str:
    return _validate(_LXD_NAME_RE, name, "Nome de instância LXD/Incus")


def validate_jail(name: str) -> str:
    return _validate(_JAIL_RE, name, "Jail do fail2ban")


def validate_ip(value: str) -> str:
    """Endereço IPv4/IPv6 canônico (rejeita nomes, máscaras e opções)."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValueError(f"Endereço IP inválido: {value!r}") from None


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

#: Motores com CLI no formato do Docker (os mesmos comandos servem para os três).
CLI_RUNTIMES = ("docker", "podman", "nerdctl")
_NAMESPACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def validate_namespace(namespace: str) -> str:
    if not isinstance(namespace, str) or not _NAMESPACE_RE.fullmatch(namespace):
        raise ValueError(f"Namespace do containerd inválido: {namespace!r}")
    return namespace


def container_cli(runtime: str, use_sudo: bool, namespace: str = "") -> str:
    """``docker`` / ``podman`` / ``nerdctl [--namespace ns]``, com ``sudo -n`` se pedido."""
    if runtime not in CLI_RUNTIMES:
        raise ValueError(f"Runtime inválido: {runtime!r}")
    prefix = f"{sudo(use_sudo)}{runtime}"
    if runtime == "nerdctl" and namespace:
        prefix += f" --namespace {shlex.quote(validate_namespace(namespace))}"
    return prefix


def build_container_ps_command(runtime: str, use_sudo: bool, namespace: str = "") -> str:
    base = container_cli(runtime, use_sudo, namespace)
    if runtime == "podman":
        return f"{base} ps -a --format json"
    return f"{base} ps -a --format '{{{{json .}}}}'"


def build_container_stats_command(runtime: str, use_sudo: bool, namespace: str = "") -> str:
    # "|" como separador: não aparece em nomes de contêiner e dispensa escapes.
    fmt = "'{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}'"
    return f"{container_cli(runtime, use_sudo, namespace)} stats --no-stream --format {fmt}"


def build_container_action_command(runtime: str, names: Sequence[str], action: ServiceAction,
                                   use_sudo: bool, namespace: str = "") -> str:
    """Aceita vários contêineres (ações em uma stack inteira em um só comando)."""
    if not names:
        raise ValueError("Nenhum contêiner informado")
    quoted = " ".join(shlex.quote(validate_container_name(n)) for n in names)
    # -t 3: no máximo 3 s de espera pelo SIGTERM antes do SIGKILL (cabe no timeout).
    stop_timeout = "" if action is ServiceAction.START else " -t 3"
    return f"{container_cli(runtime, use_sudo, namespace)} {action.value}{stop_timeout} {quoted}"


def build_container_logs_command(runtime: str, name: str, lines: int, use_sudo: bool, namespace: str = "") -> str:
    quoted = shlex.quote(validate_container_name(name))
    return f"{container_cli(runtime, use_sudo, namespace)} logs --tail {int(lines)} --timestamps {quoted} 2>&1"


def build_stack_logs_command(runtime: str, names: Sequence[str], lines: int, use_sudo: bool,
                             namespace: str = "") -> str:
    """Logs de todos os contêineres de uma stack, com cabeçalho por contêiner."""
    base = container_cli(runtime, use_sudo, namespace)
    parts = []
    for name in names:
        quoted = shlex.quote(validate_container_name(name))
        parts.append(f"printf '===== %s =====\\n' {quoted}; {base} logs --tail {int(lines)} --timestamps {quoted} 2>&1")
    return "; ".join(parts)


def build_cri_logs_command(container_id: str, lines: int, use_sudo: bool) -> str:
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id or ""):
        raise ValueError(f"ID de contêiner CRI inválido: {container_id!r}")
    return f"{sudo(use_sudo)}crictl logs --tail {int(lines)} --timestamps {container_id} 2>&1"


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
# LXD / Incus
# ---------------------------------------------------------------------------

#: Clientes aceitos: Incus, LXD (snap ou pacote) — detectados no servidor.
LXD_CLIS = ("incus", "lxc", "/snap/bin/lxc")


def _lxd_cli(cli: str) -> str:
    if cli not in LXD_CLIS:
        raise ValueError(f"Cliente LXD/Incus inválido: {cli!r}")
    return cli


def build_lxd_list_command(use_sudo: bool) -> str:
    """Primeira linha ``CLI=<cliente>``; depois o JSON de ``list`` (inclui o estado)."""
    return (
        "if command -v incus >/dev/null 2>&1; then c=incus; "
        "elif command -v lxc >/dev/null 2>&1; then c=lxc; "
        "elif [ -x /snap/bin/lxc ]; then c=/snap/bin/lxc; "
        "else echo 'lxd: command not found' >&2; exit 127; fi; "
        f'echo "CLI=$c"; {sudo(use_sudo)}"$c" list --format json'
    )


def build_lxd_action_command(cli: str, name: str, action: ServiceAction, use_sudo: bool) -> str:
    return f"{sudo(use_sudo)}{_lxd_cli(cli)} {action.value} {shlex.quote(validate_lxd_name(name))}"


def build_lxd_info_command(cli: str, name: str, use_sudo: bool) -> str:
    return f"{sudo(use_sudo)}{_lxd_cli(cli)} info --show-log {shlex.quote(validate_lxd_name(name))} 2>&1"


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

# Logins SSH das últimas 24 h, agregados NO SERVIDOR (VPS expostos recebem
# dezenas de milhares de tentativas por dia): uma linha "F" por IP de origem,
# o total e os últimos 100 logins aceitos. Cada conexão (ip:porta) conta uma
# vez, mesmo que gere várias linhas ("Invalid user" + "Failed password").
# OpenSSH >= 9.8 registra a autenticação como "sshd-session".
_SSH_LOGINS_AWK = r"""
{
  if ($0 ~ /Accepted [a-z-]+(\/[a-z]+)? for /) { na++; acc[na % 100] = $0; next }
  user = ""; ip = ""; port = ""
  if ($0 ~ /Invalid user /) {
    for (i = 1; i < NF; i++) if ($i == "user") { user = $(i + 1); break }
  } else if ($0 ~ /Failed (password|keyboard-interactive\/pam) for /) {
    for (i = 1; i < NF; i++) if ($i == "for") { user = $(i + 1); if (user == "invalid") user = $(i + 3); break }
  } else if ($0 ~ /(Connection closed by|Disconnected from) authenticating user /) {
    for (i = 1; i < NF; i++) if ($i == "user") { user = $(i + 1); ip = $(i + 2); break }
  } else next
  for (i = 1; i < NF; i++) { if ($i == "from" && ip == "") ip = $(i + 1); if ($i == "port") port = $(i + 1) }
  if (user == "from") user = ""
  if (ip == "") next
  key = ip ":" port
  if (key in seen) next
  seen[key] = 1; total++; count[ip]++; last[ip] = $1; lastuser[ip] = user
}
END {
  print "TOTAL", total + 0
  for (ip in count) print "F", count[ip], last[ip], ip, lastuser[ip]
  start = na - 99; if (start < 1) start = 1
  for (i = start; i <= na; i++) print acc[i % 100]
}
"""
SSH_LOGINS_CMD = (
    with_timeout("journalctl _COMM=sshd _COMM=sshd-session --since=-24h -o short-unix --no-pager", 3)
    + " 2>/dev/null | awk " + shlex.quote(_SSH_LOGINS_AWK.strip())
)

# Comandos executados com sudo nas últimas 24 h. As chamadas "sudo -n" do próprio
# monitor (usuário SSH, sem terminal) são descartadas para não poluir a lista.
_SUDO_AWK = r"""
{
  if ($0 !~ /COMMAND=|incorrect password attempt|NOT in sudoers/) next
  if ($4 == me && $0 !~ /TTY=(pts|tty|\/dev)/) next
  total++; n++; ev[n % 100] = $0
}
END {
  print "TOTAL", total + 0
  start = n - 99; if (start < 1) start = 1
  for (i = start; i <= n; i++) print ev[i % 100]
}
"""


def build_sudo_log_command(ssh_user: str) -> str:
    return (with_timeout("journalctl _COMM=sudo --since=-24h -o short-unix --no-pager", 3)
            + f" 2>/dev/null | awk -v me={shlex.quote(ssh_user)} " + shlex.quote(_SUDO_AWK.strip()))


# ---------------------------------------------------------------------------
# VPS: provedor, horário, DNS, OOM killer e franquia de tráfego (vnStat)
# ---------------------------------------------------------------------------

_OOM_AWK = r"""
tolower($0) ~ /out of memory: kill/ { n++; l[n % 20] = $0 }
END { print "OOM_TOTAL", n + 0; s = n - 19; if (s < 1) s = 1; for (i = s; i <= n; i++) print l[i % 20] }
"""

VPS_CMD = sections(
    "for f in sys_vendor product_name bios_vendor; do printf '%s=' \"$f\"; "
    "cat \"/sys/class/dmi/id/$f\" 2>/dev/null || echo; done; "
    "printf 'hypervisor='; cat /sys/hypervisor/type 2>/dev/null || echo; "
    "echo \"swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null)\"; "
    "grep -E '^nameserver' /etc/resolv.conf 2>/dev/null; ip route show default 2>/dev/null | head -n 2; true",
    "timedatectl show 2>/dev/null || timedatectl status 2>/dev/null; "
    "if command -v chronyc >/dev/null 2>&1; then chronyc -n tracking 2>/dev/null "
    "| grep -E '^(System time|Leap status)'; fi; true",
    with_timeout("journalctl -k --since=-24h -o short-unix --no-pager", 2)
    + " 2>/dev/null | awk " + shlex.quote(_OOM_AWK.strip()),
    # "m 1"/"d 1" (vnStat >= 2.6) limitam a saída; versões antigas caem no JSON completo.
    "if command -v vnstat >/dev/null 2>&1; then vnstat --json m 1 2>/dev/null || vnstat --json 2>/dev/null; "
    "echo; echo '#DAY'; vnstat --json d 1 2>/dev/null; else echo NOVNSTAT; fi; true",
)


# ---------------------------------------------------------------------------
# SMART (saúde dos discos físicos)
# ---------------------------------------------------------------------------

def build_smart_command(use_sudo: bool) -> str:
    """``smartctl --scan`` + ``smartctl -j`` (JSON, smartmontools >= 7) por disco.

    "scsi" vira "auto": discos SATA atrás do libata aparecem como scsi no scan,
    mas só mostram os atributos ATA com a detecção automática (SAT).
    """
    smartctl = with_timeout(sudo(use_sudo) + 'smartctl -j -H -A -i -d "$type" "$dev"', 3)
    return (
        "command -v smartctl >/dev/null 2>&1 || [ -x /usr/sbin/smartctl ] || "
        "{ echo 'smartctl: command not found' >&2; exit 127; }; PATH=\"$PATH:/usr/sbin:/sbin\"; "
        "smartctl --scan 2>/dev/null | head -n 6 | while read -r dev _ type _; do "
        "[ \"$type\" = scsi ] && type=auto; echo \"## $dev\"; "
        f"{smartctl} 2>&1; done"
    )


# ---------------------------------------------------------------------------
# Segurança (auditoria sem agente)
# ---------------------------------------------------------------------------

_SERVICES_TO_CHECK = ("ufw", "firewalld", "nftables", "netfilter-persistent", "iptables", "fail2ban",
                      "crowdsec", "auditd", "unattended-upgrades", "dnf-automatic.timer",
                      "dnf-automatic-install.timer", "ssh", "sshd")
_BINARIES_TO_CHECK = ("ufw", "fail2ban-client", "cscli", "nft", "iptables", "firewall-cmd", "smartctl", "vnstat")
_SYSCTLS = ("kernel/randomize_va_space", "net/ipv4/tcp_syncookies", "net/ipv4/conf/all/accept_redirects",
            "net/ipv6/conf/all/accept_redirects", "net/ipv4/conf/all/send_redirects",
            "net/ipv4/conf/all/accept_source_route", "net/ipv4/conf/all/rp_filter", "net/ipv4/ip_forward",
            "kernel/kptr_restrict", "kernel/dmesg_restrict", "fs/protected_hardlinks", "fs/protected_symlinks")


def build_security_command(use_sudo: bool, privileged: bool | None = None) -> str:
    """Um round-trip, 4 seções: sshd, chave=valor, ``who`` e ``authorized_keys``.

    Sem sudo, tudo é lido de arquivos públicos (sshd_config, ufw.conf, /proc/sys,
    /etc/passwd...). Com ``security_sudo`` também usa ``sshd -T`` (configuração
    efetiva), ``ufw status``, ``iptables -S INPUT`` e ``nft list ruleset``.
    """
    s = sudo(use_sudo)
    # Conectado como root: as leituras privilegiadas dispensam o sudo.
    privileged = use_sudo if privileged is None else privileged
    files = ("echo '#FILES'; for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do "
             "[ -r \"$f\" ] && { echo \"#FILE $f\"; cat \"$f\"; }; done; true")
    sshd = f"if {s}sshd -T 2>/dev/null; then :; else {files}; fi" if privileged else files
    kv = [
        f"for s in {' '.join(_SERVICES_TO_CHECK)}; do "
        "printf 'svc=%s=%s\\n' \"$s\" \"$(systemctl is-active \"$s\" 2>/dev/null)\"; done",
        f"for c in {' '.join(_BINARIES_TO_CHECK)}; do for d in /usr/sbin /usr/bin /sbin /bin /usr/local/sbin "
        "/usr/local/bin; do [ -x \"$d/$c\" ] && { echo \"bin=$c\"; break; }; done; done",
        "echo \"ufw_enabled=$(sed -n 's/^ENABLED=//p' /etc/ufw/ufw.conf 2>/dev/null | head -n 1)\"",
        "awk -F: '$3 == 0 { print \"uid0=\" $1 } $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7 != \"\" "
        "{ print \"login=\" $1 }' /etc/passwd 2>/dev/null",
        "for g in sudo wheel admin; do getent group \"$g\" | cut -d: -f4 | tr ',' '\\n' "
        "| sed -n 's/^\\(..*\\)$/sudoer=\\1/p'; done",
        f"for k in {' '.join(_SYSCTLS)}; do printf 'sysctl=%s=%s\\n' \"$k\" \"$(cat /proc/sys/$k 2>/dev/null)\"; "
        "done",
        "echo \"apparmor=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)\"; "
        "echo \"selinux=$(getenforce 2>/dev/null)\"",
        "command -v apt-config >/dev/null 2>&1 && echo \"auto_apt=$(apt-config dump "
        "APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n 's/.*\"\\(.*\\)\".*/\\1/p' | tail -n 1)\"",
        "echo \"tmp_mode=$(stat -c %a /tmp 2>/dev/null)\"; echo \"ssh_client=${SSH_CLIENT%% *}\"",
    ]
    if privileged:
        kv += [
            f"out=$({s}iptables -S INPUT 2>/dev/null) && {{ "
            "echo \"ipt_policy=$(echo \"$out\" | sed -n 's/^-P INPUT //p')\"; "
            "echo \"ipt_rules=$(echo \"$out\" | grep -c '^-A')\"; }",
            f"out=$({s}nft list ruleset 2>/dev/null) && "
            "echo \"nft_rules=$(echo \"$out\" | grep -cE '(accept|drop|reject)$')\"",
            f"echo '#UFW'; {s}ufw status verbose 2>/dev/null",
        ]
    return sections(sshd, "; ".join(kv) + "; true", "who 2>/dev/null; true",
                    "cat ~/.ssh/authorized_keys ~/.ssh/authorized_keys2 2>/dev/null; true")


def build_fail2ban_status_command(use_sudo: bool) -> str:
    s = sudo(use_sudo)
    return (
        f"out=$({s}fail2ban-client status 2>&1) || {{ echo \"$out\" >&2; exit 1; }}; echo \"$out\"; n=0; "
        "for j in $(echo \"$out\" | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do "
        "n=$((n + 1)); [ \"$n\" -gt 10 ] && break; "
        f'echo "## $j"; {s}fail2ban-client status "$j" 2>&1; done'
    )


def build_fail2ban_ban_command(jail: str, ip: str, ban: bool, use_sudo: bool) -> str:
    verb = "banip" if ban else "unbanip"
    return f"{sudo(use_sudo)}fail2ban-client set {shlex.quote(validate_jail(jail))} {verb} {validate_ip(ip)}"


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
