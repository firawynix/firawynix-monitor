"""Auditoria de segurança: parsers (sshd, chaves, fail2ban, logins, sudo) e regras."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from core.commands import SECTION
from core.models import (
    CheckLevel,
    ListeningSocket,
    NetworkInfo,
    SecurityRaw,
    SshLoginReport,
    SudoEvent,
    SystemInfo,
    UpdatesInfo,
    VpsInfo,
)
from core.parsers import (
    parse_authorized_keys,
    parse_fail2ban,
    parse_security,
    parse_sshd_effective,
    parse_sshd_files,
    parse_ssh_logins,
    parse_sudo_log,
    parse_who,
)
from core.security import evaluate, firewall_summary, is_exposed


def _openssh(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


ED25519 = _openssh(ed25519.Ed25519PrivateKey.generate())
RSA1024 = _openssh(rsa.generate_private_key(public_exponent=65537, key_size=1024))

SSHD_FILES = """#FILES
#FILE /etc/ssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
PasswordAuthentication yes
Port 22
Port 2222
Match User deploy
    PasswordAuthentication yes
    X11Forwarding yes
#FILE /etc/ssh/sshd_config.d/60-hardening.conf
PermitRootLogin prohibit-password
MaxAuthTries=10
#FILE /etc/ssh/sshd_config.d/50-cloud-init.conf
PasswordAuthentication no
"""


def test_sshd_files_follow_include_order_first_value_and_match():
    config = parse_sshd_files(SSHD_FILES)
    assert config["passwordauthentication"] == "no"  # 50-cloud-init vem antes (ordem alfabética)
    assert config["permitrootlogin"] == "prohibit-password"
    assert config["maxauthtries"] == "10"
    assert config["port"] == "22 2222"
    assert "x11forwarding" not in config  # só dentro do Match


def test_sshd_effective():
    config = parse_sshd_effective("port 22\nport 443\npermitrootlogin without-password\nusepam yes\n")
    assert config == {"port": "22 443", "permitrootlogin": "without-password", "usepam": "yes"}


def test_authorized_keys_fingerprint_bits_and_options():
    blob = ED25519.split()[1]
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")
    text = (f"# comentário\n{ED25519} ana@notebook\n"
            f'from="10.0.0.0/8",command="/usr/bin/backup" {RSA1024} backup job\nlixo\n')
    ed, weak = parse_authorized_keys(text)
    assert (ed.key_type, ed.bits, ed.fingerprint, ed.comment, ed.restricted) == (
        "ssh-ed25519", 256, expected, "ana@notebook", False)
    assert (weak.key_type, weak.bits, weak.comment, weak.restricted) == ("ssh-rsa", 1024, "backup job", True)


def test_parse_who():
    sessions = parse_who("ana      pts/0        2026-09-29 10:01 (203.0.113.5)\n"
                         "root     tty1         2026-09-28 08:00\n")
    assert [(s.user, s.tty, s.source, s.since) for s in sessions] == [
        ("ana", "pts/0", "203.0.113.5", "2026-09-29 10:01"), ("root", "tty1", "", "2026-09-28 08:00")]


FAIL2BAN = """Status
|- Number of jail:\t2
`- Jail list:\tnginx-http-auth, sshd
## nginx-http-auth
Status for the jail: nginx-http-auth
|- Filter
|  |- Currently failed:\t0
|  |- Total failed:\t0
|  `- File list:\t/var/log/nginx/error.log
`- Actions
   |- Currently banned:\t0
   |- Total banned:\t0
   `- Banned IP list:\t
## sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed:\t3
|  |- Total failed:\t1542
|  `- Journal matches:\t_SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned:\t2
   |- Total banned:\t87
   `- Banned IP list:\t203.0.113.9 198.51.100.7
"""


def test_parse_fail2ban():
    nginx, sshd = parse_fail2ban(FAIL2BAN)
    assert (nginx.name, nginx.currently_banned, nginx.banned_ips) == ("nginx-http-auth", 0, ())
    assert (sshd.currently_failed, sshd.total_failed, sshd.currently_banned, sshd.total_banned) == (3, 1542, 2, 87)
    assert sshd.banned_ips == ("203.0.113.9", "198.51.100.7")


def test_parse_ssh_logins_from_awk_output():
    output = ("TOTAL 5\nF 1 1727600005.0 192.0.2.1 \nF 2 1727600006.0 198.51.100.7 root\n"
              "F 2 1727600001.0 203.0.113.9 root\n"
              "1727600003.0 web sshd-session[103]: Accepted publickey for monitor from 10.0.0.5 port 51000 ssh2: "
              "ED25519 SHA256:abc\n"
              "1727600004.0 web sshd[104]: Accepted password for root from 2001:db8::7 port 5 ssh2\n")
    report = parse_ssh_logins(output)
    assert report.failed_total == 5
    assert [(s.source, s.count) for s in report.failed_sources] == [
        ("198.51.100.7", 2), ("203.0.113.9", 2), ("192.0.2.1", 1)]
    assert [(e.user, e.source, e.method) for e in report.accepted] == [
        ("root", "2001:db8::7", "password"), ("monitor", "10.0.0.5", "publickey")]


def test_parse_sudo_log():
    output = ("TOTAL 3\n"
              "1727600002.0 web sudo[202]:  monitor : TTY=pts/0 ; PWD=/home/monitor ; USER=root ; "
              "COMMAND=/usr/bin/vim /etc/hosts\n"
              "1727600003.0 web sudo[203]:      bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; "
              "USER=root ; COMMAND=/bin/bash\n"
              "1727600004.0 web sudo[204]:      eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; "
              "COMMAND=/usr/bin/id\n")
    events = parse_sudo_log(output)
    assert [(e.user, e.outcome, e.command, e.tty) for e in events] == [
        ("eve", "negado", "/usr/bin/id", "pts/2"), ("bob", "senha incorreta", "/bin/bash", "pts/1"),
        ("monitor", "ok", "/usr/bin/vim /etc/hosts", "pts/0")]
    assert events[0].run_as == "root"


def _security_output(kv: str, sshd: str = SSHD_FILES, who: str = "", keys: str = "") -> str:
    return f"\n{SECTION}\n".join([sshd, kv, who, keys])


KV = """svc=ufw=active
svc=fail2ban=active
svc=crowdsec=inactive
svc=auditd=inactive
bin=ufw
bin=fail2ban-client
ufw_enabled=yes
uid0=root
uid0=toor
login=root
login=ana
sudoer=ana
sudoer=ana
sysctl=kernel/randomize_va_space=2
sysctl=net/ipv4/tcp_syncookies=1
sysctl=net/ipv4/conf/all/accept_redirects=1
apparmor=Y
selinux=
auto_apt=1
tmp_mode=1777
ssh_client=198.51.100.20
ipt_policy=DROP
ipt_rules=4
nft_rules=0
#UFW
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
"""


def test_parse_security():
    raw = parse_security(_security_output(KV, who="ana pts/0 2026-09-29 10:01 (1.2.3.4)", keys=ED25519 + " ana"))
    assert raw.sshd_source == "arquivos" and raw.sshd["passwordauthentication"] == "no"
    assert raw.services["ufw"] == "active" and "fail2ban-client" in raw.binaries
    assert raw.ufw_enabled is True and raw.ufw_status.startswith("Status: active")
    assert raw.uid0_users == ("root", "toor") and raw.sudo_users == ("ana",)
    assert raw.sysctl["kernel.randomize_va_space"] == "2"
    assert (raw.apparmor, raw.auto_updates, raw.tmp_mode, raw.ssh_client) == (True, "1", "1777", "198.51.100.20")
    assert (raw.iptables_input_policy, raw.iptables_rules, raw.nft_rules) == ("DROP", 4, 0)
    assert len(raw.sessions) == 1 and len(raw.authorized_keys) == 1


def test_parse_security_with_sshd_t_and_no_apt():
    raw = parse_security(_security_output("svc=ufw=inactive\nufw_enabled=no", sshd="permitrootlogin no\nport 22"))
    assert raw.sshd_source == "sshd -T" and raw.sshd["permitrootlogin"] == "no"
    assert raw.auto_updates is None and raw.ufw_enabled is False


# ---------------------------------------------------------------------------
# Regras
# ---------------------------------------------------------------------------

def _levels(report):
    return {c.id: c.level for c in report.checks}


def test_is_exposed():
    assert is_exposed("0.0.0.0") and is_exposed("::") and is_exposed("*") and is_exposed("8.8.8.8")
    assert not is_exposed("127.0.0.1") and not is_exposed("10.0.0.5") and not is_exposed("::1")


def test_evaluate_hardened_server_scores_high():
    raw = parse_security(_security_output(KV.replace("uid0=toor\n", "")))
    report = evaluate(raw, ssh_user="monitor", logins=SshLoginReport(failed_total=0),
                      network=NetworkInfo(listening=(ListeningSocket("tcp", "127.0.0.1", 5432, "postgres"),)),
                      updates=UpdatesInfo("apt", 3, 0), system=SystemInfo(), vps=VpsInfo(ntp_synchronized=True))
    levels = _levels(report)
    assert levels["ssh_password"] is CheckLevel.OK and levels["firewall"] is CheckLevel.OK
    assert levels["ssh_root"] is CheckLevel.WARN  # prohibit-password
    assert levels["exposed_ports"] is CheckLevel.OK and levels["bruteforce"] is CheckLevel.OK
    assert levels["auto_updates"] is CheckLevel.OK and levels["time_sync"] is CheckLevel.OK
    assert levels["sysctl"] is CheckLevel.INFO  # só accept_redirects (consultivo)
    assert report.score is not None and report.score >= 85
    assert report.checks[0].level is CheckLevel.WARN  # ordenado: piores primeiro


def test_evaluate_exposed_vps_fails_hard():
    raw = SecurityRaw(
        sshd={"permitrootlogin": "yes", "passwordauthentication": "yes", "permitemptypasswords": "yes"},
        sshd_source="sshd -T", services={"ufw": "inactive", "fail2ban": "inactive"},
        binaries=frozenset({"fail2ban-client"}), ufw_enabled=False, iptables_rules=0, iptables_input_policy="ACCEPT",
        uid0_users=("root", "toor"), auto_updates="0", selinux="Permissive", tmp_mode="0777",
    )
    network = NetworkInfo(listening=(ListeningSocket("tcp", "0.0.0.0", 6379, "redis-server"),
                                     ListeningSocket("tcp", "::", 2375, "dockerd"),
                                     ListeningSocket("tcp", "0.0.0.0", 3306, "docker-proxy")))
    logins = SshLoginReport(failed_total=4200)
    sudo = (SudoEvent(1.0, "eve", "/usr/bin/id", "negado"),)
    report = evaluate(raw, logins=logins, sudo_events=sudo, network=network, updates=UpdatesInfo("apt", 30, 12),
                      system=SystemInfo(reboot_required=True), vps=VpsInfo(ntp_synchronized=False),
                      monitor_uses_password=True)
    levels = _levels(report)
    for check_id in ("ssh_root", "ssh_empty", "firewall", "exposed_ports", "uid0", "ssh_password"):
        assert levels[check_id] is CheckLevel.FAIL, check_id
    for check_id in ("updates_security", "auto_updates", "reboot", "mac", "tmp", "time_sync", "bruteforce",
                     "ssh_attempts", "sudo_denied"):
        assert levels[check_id] is CheckLevel.WARN, check_id
    assert levels["monitor_password"] is CheckLevel.INFO
    exposed = report.check("exposed_ports")
    assert "API do Docker SEM TLS" in exposed.detail and "IGNORAM o UFW" in exposed.detail
    assert report.score is not None and report.score < 35


def test_evaluate_without_sshd_access_is_unknown_and_firewall_undetermined():
    report = evaluate(SecurityRaw(services={"ufw": "inactive"}))
    levels = _levels(report)
    assert levels["ssh_config"] is CheckLevel.UNKNOWN
    assert levels["firewall"] is CheckLevel.WARN and "security_sudo" in report.check("firewall").recommendation


def test_evaluate_root_password_login_and_partial_journal():
    from core.models import LoginEvent

    logins = SshLoginReport(accepted=(LoginEvent(10.0, "root", "203.0.113.5", "password"),), complete=False)
    levels = _levels(evaluate(SecurityRaw(sshd={"permitrootlogin": "no"}), logins=logins))
    assert levels["ssh_root_login"] is CheckLevel.FAIL and levels["ssh_attempts"] is CheckLevel.UNKNOWN


@pytest.mark.parametrize(("raw", "expected"), [
    (SecurityRaw(ufw_enabled=True, ufw_status="Status: active\nDefault: deny (incoming)"), True),
    (SecurityRaw(services={"firewalld": "active"}), True),
    (SecurityRaw(nft_rules=12), True),
    (SecurityRaw(iptables_rules=0, iptables_input_policy="ACCEPT", nft_rules=0), False),
    (SecurityRaw(), None),
])
def test_firewall_summary(raw, expected):
    assert firewall_summary(raw)[0] is expected


def test_ban_guards_and_jail_choice():
    from core.models import Fail2banJail, SecurityReport

    tkinter = pytest.importorskip("tkinter")  # noqa: F841 - a aba importa customtkinter
    from ui.security_tab import ban_block_reason, pick_jail

    raw = SecurityRaw(ssh_client="198.51.100.20",
                      fail2ban=(Fail2banJail("recidive"), Fail2banJail("sshd", banned_ips=("203.0.113.9",))))
    report = SecurityReport((), None, raw)
    assert pick_jail(report) == "sshd" and pick_jail(None) is None
    assert "monitor" in ban_block_reason("198.51.100.20", report)
    assert ban_block_reason("127.0.0.1", report) == "endereço local"
    assert ban_block_reason("203.0.113.9", report) == "já está banido"
    assert ban_block_reason("1.2.3.4; reboot", report) == "endereço inválido"
    assert ban_block_reason("192.0.2.77", report) is None
