"""API do Windows (layouts e helpers puros; as chamadas reais só existem no Windows)
e políticas de alertas de host (endpoints, SMART, segurança, logins, OOM, franquia)."""

import ctypes
import sqlite3
import sys

import pytest

from config.settings import NotificationSettings, ServerConfig
from core import winapi
from core.alerts import HostAlertPolicy
from core.history import HistoryStore
from core.models import (
    BandwidthUsage,
    CheckLevel,
    EndpointResult,
    HostMetrics,
    LoginEvent,
    OomKill,
    RuntimeState,
    SecurityCheck,
    SecurityRaw,
    SecurityReport,
    ServiceStatus,
    SmartDisk,
    SmartReport,
    SshLoginReport,
    VpsInfo,
)

# ---------------------------------------------------------------------------
# winapi
# ---------------------------------------------------------------------------


def test_struct_layouts_match_windows_x64():
    # Tamanhos documentados do Windows x64 (tipos de tamanho fixo tornam o layout portável).
    assert ctypes.sizeof(winapi.CREDENTIALW) == 80
    assert winapi.CREDENTIALW.CredentialBlob.offset == 40 and winapi.CREDENTIALW.UserName.offset == 72
    assert ctypes.sizeof(winapi.FLASHWINFO) == 32 and winapi.FLASHWINFO.hwnd.offset == 8
    assert ctypes.sizeof(winapi.IP_OPTION_INFORMATION) == 16
    assert ctypes.sizeof(winapi.ICMP_ECHO_REPLY) == 40 and winapi.ICMP_ECHO_REPLY.Data.offset == 16


def test_colorref_and_ipaddr():
    assert winapi.colorref("#0e7490") == 0x0090740E
    assert winapi.colorref("ffffff") == 0x00FFFFFF
    assert winapi.ipv4_to_ipaddr("10.0.0.1") == 0x0100000A


def test_secret_encoding_matches_cmdkey():
    assert winapi.encode_secret("sênha") == "sênha".encode("utf-16-le")
    assert winapi.decode_secret(winapi.encode_secret("p@ss wörd")) == "p@ss wörd"
    assert winapi.decode_secret(b"abc") == "abc"  # blob ímpar gravado por outro programa (UTF-8)
    with pytest.raises(winapi.CredentialError):
        winapi.encode_secret("x" * 2000)
    assert winapi.credential_target("staging") == "FirawynixMonitor/staging"
    assert winapi.credential_target("staging", "passphrase") == "FirawynixMonitor/staging/passphrase"


def test_autostart_command_is_minimized_and_absolute(tmp_path):
    command = winapi.autostart_command(tmp_path / "servers.json")
    assert "--minimized" in command and "main.py" in command and str(tmp_path) in command


@pytest.mark.skipif(sys.platform == "win32", reason="comportamento fora do Windows")
def test_windows_calls_are_safe_noops_elsewhere():
    assert winapi.cred_read("x") is None and winapi.cred_list() == [] and not winapi.cred_delete("x")
    with pytest.raises(winapi.CredentialError):
        winapi.cred_write("x", "y")
    assert winapi.icmp_ping("127.0.0.1") is None
    assert not winapi.prevent_sleep(True) and not winapi.autostart_enabled()
    assert not winapi.set_autostart(True, "x")
    log = winapi.EventLog()
    assert not log.available and not log.write("teste")
    log.close()


# ---------------------------------------------------------------------------
# Histórico: migração de bancos antigos
# ---------------------------------------------------------------------------

def test_history_migrates_old_database(tmp_path):
    path = tmp_path / "history.sqlite3"
    old_fields = ("cpu", "mem", "swap", "load1", "disk", "net_rx", "net_tx", "disk_read", "disk_write", "failed",
                  "active")
    with sqlite3.connect(path) as conn:
        conn.execute(f"CREATE TABLE samples (server TEXT NOT NULL, ts REAL NOT NULL, "
                     f"{', '.join(f + ' REAL' for f in old_fields)}, PRIMARY KEY (server, ts)) WITHOUT ROWID")
        conn.execute("INSERT INTO samples (server, ts, cpu) VALUES ('srv', 1000, 10)")
    store = HistoryStore(path)
    store.record("srv", 1001, HostMetrics(cpu_percent=20, cpu_steal=7.5, cpu_iowait=2.0), latency=31.0)
    series = store.query("srv", 100, now=1002)
    assert series.values["steal"][-1] == pytest.approx(7.5) and series.values["latency"][-1] == pytest.approx(31)
    store.close()


# ---------------------------------------------------------------------------
# Alertas de host
# ---------------------------------------------------------------------------

def _policy(**server_kwargs):
    server = ServerConfig(name="vps1", host="h", username="monitor", **server_kwargs)
    return HostAlertPolicy(server, NotificationSettings())


def _endpoint(status, days=None, detail=""):
    return EndpointResult("https://loja", "https", status, 50.0, 200, cert_days_left=days, detail=detail)


def test_endpoint_alerts_on_transitions_and_cert_once_per_day():
    policy = _policy()
    assert policy.endpoints([_endpoint(ServiceStatus.ACTIVE)]) == []
    down = policy.endpoints([_endpoint(ServiceStatus.FAILED, detail="tempo esgotado")])
    assert [(e.level, e.title) for e in down] == [("critical", "Fora do ar: https://loja")]
    assert policy.endpoints([_endpoint(ServiceStatus.FAILED)]) == []
    back = policy.endpoints([_endpoint(ServiceStatus.ACTIVE)])
    assert back[0].recovered and back[0].level == "info"
    soon = _endpoint(ServiceStatus.DEGRADED, days=5, detail="200 OK · certificado expira em 5 dia(s)")
    assert len(policy.endpoints([soon], now=1_000_000)) == 1
    assert policy.endpoints([soon], now=1_000_100) == []


def test_smart_alerts_once_per_status():
    policy = _policy()
    report = SmartReport(RuntimeState.OK, (SmartDisk("/dev/sda", model="HDD", passed=True, pending=3),))
    first = policy.smart(report)
    assert len(first) == 1 and first[0].level == "warning" and "3 setores pendentes" in first[0].message
    assert policy.smart(report) == []
    failed = SmartReport(RuntimeState.OK, (SmartDisk("/dev/sda", passed=False),))
    assert policy.smart(failed)[0].level == "critical"


def _report(*failing, logins=()):
    checks = tuple(SecurityCheck(c, "SSH", f"Título {c}", CheckLevel.FAIL, "detalhe") for c in failing)
    return SecurityReport(checks, 50, SecurityRaw(ssh_client="198.51.100.20"),
                          logins=SshLoginReport(accepted=tuple(logins)))


def test_security_alerts_summary_first_then_new_only():
    policy = _policy()
    first = policy.security(_report("firewall", "uid0"))
    assert len(first) == 1 and first[0].title.startswith("2 problemas críticos")
    assert policy.security(_report("firewall", "uid0")) == []
    new = policy.security(_report("firewall", "uid0", "ssh_root"))
    assert [e.key for e in new] == ["vps1:security:ssh_root"]


def test_login_alerts_skip_history_and_own_reconnections():
    policy = _policy()
    assert policy.security(_report(logins=[LoginEvent(100, "root", "1.2.3.4", "publickey")])) == []
    fresh = [LoginEvent(100, "root", "1.2.3.4", "publickey"), LoginEvent(200, "root", "5.6.7.8", "password"),
             LoginEvent(250, "monitor", "198.51.100.20", "publickey"), LoginEvent(260, "ana", "5.6.7.8", "publickey")]
    events = policy.security(_report(logins=fresh))
    assert [(e.title, e.level) for e in events] == [("Login SSH de root em vps1", "critical")]


def test_oom_and_bandwidth_alerts():
    policy = _policy(bandwidth_quota_gb=100)
    gb = 1024 ** 3
    base = VpsInfo(oom_kills=(OomKill(100, "java"),),
                   bandwidth=(BandwidthUsage("eth0", "2026-09", 10 * gb, 50 * gb),))
    assert policy.vps(base) == []
    more = VpsInfo(oom_kills=(OomKill(300, "node"), OomKill(100, "java")),
                   bandwidth=(BandwidthUsage("eth0", "2026-09", 10 * gb, 85 * gb),))
    events = policy.vps(more)
    assert [e.category for e in events] == ["oom", "bandwidth"]
    assert "node" in events[0].message and "85%" in events[1].title and events[1].level == "warning"
    assert policy.vps(more) == []
    over = VpsInfo(bandwidth=(BandwidthUsage("eth0", "2026-09", 0, 101 * gb),))
    assert policy.vps(over)[0].level == "critical"
