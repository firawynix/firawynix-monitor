"""Auditoria de segurança sem agente: transforma os dados brutos coletados via SSH
(sshd, firewall, fail2ban, usuários, sysctl, portas, logins, sudo...) em uma
lista de verificações com nível, explicação e recomendação, e em uma nota 0–100.

Funções puras: nenhuma chamada de rede, fáceis de testar.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence

from core.models import (
    CheckLevel,
    ListeningSocket,
    NetworkInfo,
    SecurityCheck,
    SecurityRaw,
    SecurityReport,
    SshLoginReport,
    SudoEvent,
    SystemInfo,
    UpdatesInfo,
    VpsInfo,
)

#: Portas que nunca deveriam estar abertas para a internet sem filtro.
SENSITIVE_PORTS: dict[int, str] = {
    1433: "SQL Server", 1521: "Oracle DB", 2375: "API do Docker SEM TLS", 2376: "API do Docker",
    2379: "etcd", 3306: "MySQL/MariaDB", 3389: "RDP", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5901: "VNC", 5984: "CouchDB", 6379: "Redis", 8086: "InfluxDB", 9042: "Cassandra",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch (cluster)", 10250: "kubelet",
    11211: "Memcached", 15672: "RabbitMQ (painel)", 27017: "MongoDB",
}
#: Exposição que equivale a entregar o servidor (root remoto ou amplificação DDoS).
CRITICAL_PORTS = {2375, 11211}

_LEVEL_POINTS = {CheckLevel.OK: 1.0, CheckLevel.WARN: 0.5, CheckLevel.FAIL: 0.0}
_LEVEL_ORDER = {CheckLevel.FAIL: 0, CheckLevel.WARN: 1, CheckLevel.UNKNOWN: 2, CheckLevel.INFO: 3,
                CheckLevel.OK: 4}

# sysctl: (valor esperado, crítico?)
_SYSCTL_EXPECTED: dict[str, tuple[set[str], bool]] = {
    "kernel.randomize_va_space": ({"2"}, True),
    "net.ipv4.tcp_syncookies": ({"1"}, True),
    "fs.protected_hardlinks": ({"1"}, True),
    "fs.protected_symlinks": ({"1"}, True),
    "net.ipv4.conf.all.accept_redirects": ({"0"}, False),
    "net.ipv6.conf.all.accept_redirects": ({"0"}, False),
    "net.ipv4.conf.all.accept_source_route": ({"0"}, False),
    "net.ipv4.conf.all.rp_filter": ({"1", "2"}, False),
    "kernel.kptr_restrict": ({"1", "2"}, False),
    "kernel.dmesg_restrict": ({"1"}, False),
}


def is_exposed(address: str) -> bool:
    """Escuta em todas as interfaces ou em um IP público."""
    if address in {"*", "0.0.0.0", "::", "[::]", ""}:
        return True
    try:
        ip = ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return False
    return ip.is_global


def _active(raw: SecurityRaw, *services: str) -> bool:
    return any(raw.services.get(s) == "active" for s in services)


def _yes(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in {"yes", "true", "1"}


def firewall_summary(raw: SecurityRaw) -> tuple[bool | None, str]:
    """(ativo?, descrição). None = não foi possível determinar."""
    found = []
    if raw.ufw_enabled:
        incoming = re.search(r"(\w+) \(incoming\)", raw.ufw_status)
        found.append("UFW ativo" + (f" (entrada padrão: {incoming.group(1)})" if incoming else ""))
    if _active(raw, "firewalld"):
        found.append("firewalld")
    if raw.nft_rules:
        found.append(f"nftables ({raw.nft_rules} regras)")
    if raw.iptables_input_policy in {"DROP", "REJECT"} or raw.iptables_rules:
        found.append(f"iptables (INPUT {raw.iptables_input_policy or '?'}, {raw.iptables_rules or 0} regras)")
    if not found and _active(raw, "nftables", "netfilter-persistent", "iptables"):
        found.append("regras carregadas no boot (nftables/iptables)")
    if found:
        return True, ", ".join(dict.fromkeys(found))
    inspected = raw.iptables_rules is not None or raw.nft_rules is not None or raw.ufw_status
    return (False if inspected else None), ""


def evaluate(raw: SecurityRaw, *, ssh_user: str = "", logins: SshLoginReport | None = None,
             sudo_events: Sequence[SudoEvent] = (), network: NetworkInfo | None = None,
             updates: UpdatesInfo | None = None, system: SystemInfo | None = None,
             vps: VpsInfo | None = None, monitor_uses_password: bool = False) -> SecurityReport:
    checks: list[SecurityCheck] = []

    def add(check_id: str, category: str, title: str, level: CheckLevel, detail: str,
            recommendation: str = "") -> None:
        checks.append(SecurityCheck(check_id, category, title, level, detail, recommendation))

    _ssh_checks(raw, add, logins, ssh_user, monitor_uses_password)
    protected = _firewall_checks(raw, add, network, logins)
    _system_checks(raw, add, updates, system, vps, sudo_events, ssh_user)
    if raw.sshd:
        # Força bruta + senha habilitada + nada bloqueando = pior combinação possível.
        password = _yes(raw.sshd.get("passwordauthentication", "yes"))
        if password and logins is not None and logins.failed_total >= 100 and not protected:
            for index, check in enumerate(checks):
                if check.id == "ssh_password":
                    checks[index] = SecurityCheck(
                        check.id, check.category, check.title, CheckLevel.FAIL,
                        check.detail + f" — e {logins.failed_total} tentativas nas últimas 24 h sem fail2ban.",
                        check.recommendation)

    checks.sort(key=lambda c: (_LEVEL_ORDER[c.level], c.category, c.title))
    scored = [_LEVEL_POINTS[c.level] for c in checks if c.level in _LEVEL_POINTS]
    score = round(100 * sum(scored) / len(scored)) if scored else None
    return SecurityReport(tuple(checks), score, raw, logins, tuple(sudo_events))


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

def _ssh_checks(raw: SecurityRaw, add, logins: SshLoginReport | None, ssh_user: str,
                monitor_uses_password: bool) -> None:
    sshd = raw.sshd
    source = f"(fonte: {raw.sshd_source})" if raw.sshd_source else ""
    if not sshd:
        add("ssh_config", "SSH", "Configuração do sshd", CheckLevel.UNKNOWN,
            "sshd_config ilegível para o usuário SSH (comum em RHEL/Rocky, arquivo 0600).",
            "Habilite \"security_sudo\" e libere 'sshd -T' no sudoers (docs/sudoers.example).")
    else:
        root = sshd.get("permitrootlogin", "prohibit-password").lower()
        if root == "yes":
            add("ssh_root", "SSH", "Login do root", CheckLevel.FAIL,
                f"PermitRootLogin yes: root pode entrar COM SENHA {source}.",
                "Use 'PermitRootLogin no' e um usuário comum com sudo.")
        elif root in {"prohibit-password", "without-password"}:
            add("ssh_root", "SSH", "Login do root", CheckLevel.WARN,
                f"root pode entrar com chave (PermitRootLogin {root}) {source}.",
                "Prefira 'PermitRootLogin no' e um usuário comum com sudo (trilha de auditoria por pessoa).")
        else:
            add("ssh_root", "SSH", "Login do root", CheckLevel.OK, f"PermitRootLogin {root} {source}.")

        password = _yes(sshd.get("passwordauthentication", "yes"))
        if password:
            add("ssh_password", "SSH", "Login por senha", CheckLevel.WARN,
                "PasswordAuthentication yes: o SSH aceita senha (alvo de força bruta).",
                "Use apenas chaves: 'PasswordAuthentication no' (teste antes em outra sessão).")
        else:
            add("ssh_password", "SSH", "Login por senha", CheckLevel.OK, "Somente chaves (PasswordAuthentication no).")
            kbd = sshd.get("kbdinteractiveauthentication", sshd.get("challengeresponseauthentication", ""))
            if _yes(kbd) and _yes(sshd.get("usepam", "no")):
                add("ssh_kbd", "SSH", "Keyboard-interactive + PAM", CheckLevel.WARN,
                    "KbdInteractiveAuthentication yes com UsePAM: o PAM ainda pode pedir senha.",
                    "Defina 'KbdInteractiveAuthentication no'.")

        if _yes(sshd.get("permitemptypasswords", "no")):
            add("ssh_empty", "SSH", "Senhas vazias", CheckLevel.FAIL, "PermitEmptyPasswords yes.",
                "Defina 'PermitEmptyPasswords no' imediatamente.")
        else:
            add("ssh_empty", "SSH", "Senhas vazias", CheckLevel.OK, "Contas sem senha não entram por SSH.")

        tries = sshd.get("maxauthtries", "6")
        if tries.isdigit() and int(tries) > 6:
            add("ssh_maxauth", "SSH", "Tentativas por conexão", CheckLevel.WARN, f"MaxAuthTries {tries}.",
                "Use 'MaxAuthTries 3' ou 4.")
        else:
            add("ssh_maxauth", "SSH", "Tentativas por conexão", CheckLevel.OK, f"MaxAuthTries {tries}.")

        if _yes(sshd.get("x11forwarding", "no")):
            add("ssh_x11", "SSH", "Encaminhamento X11", CheckLevel.INFO,
                "X11Forwarding yes (desnecessário em servidores).", "Defina 'X11Forwarding no'.")
        ports = sshd.get("port", "22").split()
        if "22" in ports:
            add("ssh_port", "SSH", "Porta do SSH", CheckLevel.INFO,
                "Porta padrão 22: recebe varreduras constantes de bots (trocar a porta reduz ruído, não é proteção).")
        else:
            add("ssh_port", "SSH", "Porta do SSH", CheckLevel.OK, f"Porta(s) {', '.join(ports)}.")
        restricted = [k for k in ("allowusers", "allowgroups") if sshd.get(k)]
        if restricted:
            add("ssh_allow", "SSH", "Usuários permitidos", CheckLevel.OK,
                "; ".join(f"{k.replace('allow', 'Allow').replace('users', 'Users').replace('groups', 'Groups')} "
                          f"{sshd[k]}" for k in restricted))

    keys = raw.authorized_keys
    weak = [k for k in keys if k.key_type == "ssh-dss" or (k.key_type == "ssh-rsa" and (k.bits or 0) < 2048)]
    if weak:
        add("ssh_weak_keys", "SSH", "Chaves autorizadas fracas", CheckLevel.FAIL,
            ", ".join(f"{k.key_type} {k.bits or '?'} bits ({k.comment or k.fingerprint})" for k in weak),
            "Substitua por chaves ed25519 (ssh-keygen -t ed25519) e remova as antigas do authorized_keys.")
    elif keys:
        add("ssh_keys", "SSH", f"Chaves autorizadas ({ssh_user or 'usuário SSH'})", CheckLevel.INFO,
            f"{len(keys)} chave(s): " + ", ".join(f"{k.key_type.removeprefix('ssh-')}"
                                                   f"{' ' + k.comment if k.comment else ''}" for k in keys[:6]))

    if logins is not None:
        root_logins = [e for e in logins.accepted if e.user == "root"]
        by_password = [e for e in root_logins if e.method in {"password", "keyboard-interactive/pam"}]
        if by_password:
            add("ssh_root_login", "SSH", "Logins do root (24 h)", CheckLevel.FAIL,
                f"{len(by_password)} login(s) do root POR SENHA, último de {by_password[0].source}.",
                "Desative a senha do root no SSH e investigue a origem.")
        elif root_logins:
            add("ssh_root_login", "SSH", "Logins do root (24 h)", CheckLevel.INFO,
                f"{len(root_logins)} login(s) do root com chave, último de {root_logins[0].source}.")
    if monitor_uses_password:
        add("monitor_password", "Monitor", "Autenticação do monitor", CheckLevel.INFO,
            "Este servidor é acessado pelo monitor com senha.",
            "Prefira uma chave ed25519 dedicada ao monitor (key_file).")


# ---------------------------------------------------------------------------
# Firewall, portas e proteção contra força bruta
# ---------------------------------------------------------------------------

def _exposed_sensitive(listening: Iterable[ListeningSocket]) -> list[ListeningSocket]:
    return [s for s in listening if s.port in SENSITIVE_PORTS and is_exposed(s.address)]


def _firewall_checks(raw: SecurityRaw, add, network: NetworkInfo | None,
                     logins: SshLoginReport | None) -> bool:
    """Retorna True quando há proteção ativa contra força bruta (fail2ban/CrowdSec)."""
    active, description = firewall_summary(raw)
    if active:
        allow_in = "allow (incoming)" in raw.ufw_status.lower()
        add("firewall", "Firewall", "Firewall local", CheckLevel.WARN if allow_in else CheckLevel.OK,
            description + (" — política padrão de entrada é ALLOW." if allow_in else ""),
            "Use 'ufw default deny incoming'." if allow_in else "")
    elif active is False:
        add("firewall", "Firewall", "Firewall local", CheckLevel.FAIL,
            "Nenhum firewall ativo (UFW, firewalld, nftables e iptables sem regras de entrada).",
            "Ative o UFW ('ufw allow OpenSSH' e depois 'ufw enable') ou use o firewall do provedor da VPS.")
    else:
        add("firewall", "Firewall", "Firewall local", CheckLevel.WARN,
            "Nenhum firewall detectado (sem \"security_sudo\" não dá para ler iptables/nftables).",
            "Habilite \"security_sudo\" para confirmar, ou verifique o firewall no painel do provedor.")

    if network is None:
        add("exposed_ports", "Firewall", "Serviços sensíveis expostos", CheckLevel.UNKNOWN,
            "Aguardando a coleta de portas (aba Rede).")
    else:
        exposed = _exposed_sensitive(network.listening)
        if not exposed:
            public = sum(1 for s in network.listening if is_exposed(s.address))
            add("exposed_ports", "Firewall", "Serviços sensíveis expostos", CheckLevel.OK,
                f"Nenhum banco/cache/API administrativa em todas as interfaces ({public} porta(s) pública(s)).")
        else:
            critical = [s for s in exposed if s.port in CRITICAL_PORTS]
            docker = [s for s in exposed if s.process.startswith("docker-proxy")]
            items = ", ".join(f"{SENSITIVE_PORTS[s.port]} {s.port}/{s.proto}"
                              + (f" ({s.process})" if s.process else "") for s in exposed[:8])
            level = CheckLevel.FAIL if (critical or docker or not active) else CheckLevel.WARN
            note = " Portas publicadas pelo Docker IGNORAM o UFW." if docker else ""
            add("exposed_ports", "Firewall", "Serviços sensíveis expostos", level,
                f"Escutando em todas as interfaces: {items}.{note}",
                "Faça o serviço escutar em 127.0.0.1 (ou publique no Docker como 127.0.0.1:porta:porta) "
                "e acesse por túnel SSH/VPN.")

    fail2ban = raw.services.get("fail2ban")
    crowdsec = raw.services.get("crowdsec") == "active"
    banned = sum(j.currently_banned or 0 for j in raw.fail2ban)
    failed = logins.failed_total if logins is not None else None
    protected = fail2ban == "active" or crowdsec
    if fail2ban == "active":
        detail = "fail2ban ativo"
        if raw.fail2ban:
            detail += f" · {len(raw.fail2ban)} jail(s), {banned} IP(s) banido(s) agora"
        elif raw.fail2ban_error:
            detail += f" · {raw.fail2ban_error}"
        add("bruteforce", "Firewall", "Proteção contra força bruta", CheckLevel.OK, detail + ".")
    elif crowdsec:
        add("bruteforce", "Firewall", "Proteção contra força bruta", CheckLevel.OK, "CrowdSec ativo.")
    else:
        installed = "fail2ban-client" in raw.binaries
        level = CheckLevel.WARN if (installed or (failed or 0) >= 100) else CheckLevel.INFO
        add("bruteforce", "Firewall", "Proteção contra força bruta", level,
            ("fail2ban instalado mas PARADO" if installed else "Sem fail2ban/CrowdSec")
            + (f"; {failed} tentativas de login SSH nas últimas 24 h." if failed else "."),
            "Instale e ative o fail2ban (jail sshd) ou o CrowdSec.")

    if logins is not None:
        if not logins.complete:
            add("ssh_attempts", "SSH", "Tentativas de login (24 h)", CheckLevel.UNKNOWN,
                "Sem acesso ao journal completo.", "Adicione o usuário SSH ao grupo systemd-journal (ou adm).")
        elif logins.failed_total == 0:
            add("ssh_attempts", "SSH", "Tentativas de login (24 h)", CheckLevel.OK, "Nenhuma tentativa falha.")
        else:
            top = ", ".join(f"{s.source} ({s.count})" for s in logins.failed_sources[:3])
            level = CheckLevel.INFO if protected or logins.failed_total < 100 else CheckLevel.WARN
            add("ssh_attempts", "SSH", "Tentativas de login (24 h)", level,
                f"{logins.failed_total} conexão(ões) com falha de {len(logins.failed_sources)} origem(ns). "
                f"Principais: {top}.",
                "" if protected else "Ative o fail2ban e desative o login por senha.")
    return protected


# ---------------------------------------------------------------------------
# Sistema
# ---------------------------------------------------------------------------

def _system_checks(raw: SecurityRaw, add, updates: UpdatesInfo | None, system: SystemInfo | None,
                   vps: VpsInfo | None, sudo_events: Sequence[SudoEvent], ssh_user: str) -> None:
    if updates is not None and updates.security:
        add("updates_security", "Atualizações", "Atualizações de segurança", CheckLevel.WARN,
            f"{updates.security} pacote(s) com correção de segurança pendente(s) ({updates.manager}).",
            "Aplique as atualizações (apt upgrade / dnf upgrade --security).")
    elif updates is not None and updates.security == 0:
        add("updates_security", "Atualizações", "Atualizações de segurança", CheckLevel.OK,
            "Nenhuma correção de segurança pendente.")
    elif updates is not None and updates.pending:
        add("updates_security", "Atualizações", "Atualizações pendentes", CheckLevel.INFO,
            f"{updates.pending} pacote(s) pendente(s) ({updates.manager}; o gerenciador não separa as de segurança).")

    automatic = raw.auto_updates == "1" or _active(raw, "dnf-automatic.timer", "dnf-automatic-install.timer")
    rpm_based = updates is not None and updates.manager in {"dnf", "yum"}
    if automatic:
        add("auto_updates", "Atualizações", "Atualizações automáticas", CheckLevel.OK,
            "unattended-upgrades/dnf-automatic habilitado.")
    elif raw.auto_updates is not None or rpm_based:
        add("auto_updates", "Atualizações", "Atualizações automáticas", CheckLevel.WARN,
            "Correções de segurança não são aplicadas automaticamente.",
            "Debian/Ubuntu: 'dpkg-reconfigure -plow unattended-upgrades'; RHEL/Rocky: "
            "'dnf install dnf-automatic' e 'systemctl enable --now dnf-automatic-install.timer'.")

    if system is not None and system.reboot_required:
        add("reboot", "Atualizações", "Reinício pendente", CheckLevel.WARN,
            "Kernel/bibliotecas atualizados só passam a valer após reiniciar.",
            "Agende uma janela de manutenção e reinicie.")

    if raw.apparmor:
        add("mac", "Sistema", "Controle de acesso obrigatório", CheckLevel.OK, "AppArmor ativo.")
    elif raw.selinux.lower() == "enforcing":
        add("mac", "Sistema", "Controle de acesso obrigatório", CheckLevel.OK, "SELinux em modo enforcing.")
    elif raw.selinux.lower() == "permissive":
        add("mac", "Sistema", "Controle de acesso obrigatório", CheckLevel.WARN,
            "SELinux em modo permissive (só registra, não bloqueia).", "Use 'setenforce 1' e SELINUX=enforcing.")
    elif raw.apparmor is False or raw.selinux:
        add("mac", "Sistema", "Controle de acesso obrigatório", CheckLevel.INFO, "Sem AppArmor/SELinux ativo.")

    if raw.sysctl:
        critical, advisory = [], []
        forwarding = raw.sysctl.get("net.ipv4.ip_forward") == "1"
        for key, (expected, is_critical) in _SYSCTL_EXPECTED.items():
            value = raw.sysctl.get(key, "")
            if not value or value in expected:
                continue
            if forwarding and key in {"net.ipv4.conf.all.rp_filter"}:
                continue  # roteadores/hosts de contêiner podem precisar
            (critical if is_critical else advisory).append(f"{key}={value}")
        if critical:
            add("sysctl", "Sistema", "Hardening do kernel (sysctl)", CheckLevel.WARN, ", ".join(critical + advisory),
                "Ajuste em /etc/sysctl.d/99-hardening.conf e aplique com 'sysctl --system'.")
        elif advisory:
            add("sysctl", "Sistema", "Hardening do kernel (sysctl)", CheckLevel.INFO, ", ".join(advisory),
                "Opcional: ajuste em /etc/sysctl.d/99-hardening.conf.")
        else:
            add("sysctl", "Sistema", "Hardening do kernel (sysctl)", CheckLevel.OK, "Parâmetros recomendados ativos.")

    extra_root = [u for u in raw.uid0_users if u != "root"]
    if extra_root:
        add("uid0", "Contas", "Contas com UID 0", CheckLevel.FAIL,
            f"Além do root: {', '.join(extra_root)} (equivalem a root).", "Remova ou altere o UID dessas contas.")
    elif raw.uid0_users:
        add("uid0", "Contas", "Contas com UID 0", CheckLevel.OK, "Somente o root.")
    if raw.sudo_users:
        add("sudo_users", "Contas", "Membros de sudo/wheel", CheckLevel.INFO, ", ".join(raw.sudo_users))
    if raw.login_users:
        add("login_users", "Contas", "Contas com shell de login", CheckLevel.INFO,
            f"{len(raw.login_users)}: " + ", ".join(raw.login_users[:12])
            + ("…" if len(raw.login_users) > 12 else ""))

    if raw.tmp_mode:
        if raw.tmp_mode == "1777":
            add("tmp", "Sistema", "Permissões do /tmp", CheckLevel.OK, "1777 (sticky bit).")
        else:
            add("tmp", "Sistema", "Permissões do /tmp", CheckLevel.WARN, f"Modo {raw.tmp_mode} (esperado 1777).",
                "chmod 1777 /tmp")

    if vps is not None and vps.ntp_synchronized is not None:
        if vps.ntp_synchronized:
            add("time_sync", "Sistema", "Relógio sincronizado (NTP)", CheckLevel.OK,
                "Sincronizado" + (f" ({vps.ntp_service})" if vps.ntp_service else "") + ".")
        else:
            add("time_sync", "Sistema", "Relógio sincronizado (NTP)", CheckLevel.WARN,
                "Relógio NÃO sincronizado: afeta TLS, tokens e a correlação de logs.",
                "Ative o systemd-timesyncd ou o chrony ('timedatectl set-ntp true').")

    if "auditd" in raw.services and raw.services.get("auditd") != "active":
        add("auditd", "Sistema", "Auditoria (auditd)", CheckLevel.INFO, "auditd inativo ou ausente.")
    elif raw.services.get("auditd") == "active":
        add("auditd", "Sistema", "Auditoria (auditd)", CheckLevel.OK, "auditd ativo.")

    denied = [e for e in sudo_events if e.outcome != "ok"]
    if denied:
        users = ", ".join(dict.fromkeys(f"{e.user} ({e.outcome})" for e in denied))
        add("sudo_denied", "Contas", "sudo negado (24 h)", CheckLevel.WARN,
            f"{len(denied)} tentativa(s) de sudo recusada(s): {users}.", "Confirme se foram tentativas legítimas.")
    elif sudo_events:
        others = {e.user for e in sudo_events} - {ssh_user}
        add("sudo_denied", "Contas", "Uso de sudo (24 h)", CheckLevel.OK,
            f"{len(sudo_events)} comando(s) com sudo" + (f" por {', '.join(sorted(others))}" if others else "")
            + "; nenhuma recusa.")
