"""Parsers da v3: LXD/Incus, VPS (DMI, NTP, OOM, vnStat), SMART e CPU steal/iowait."""

import json

import pytest

from core.commands import SECTION
from core.models import RuntimeState, ServiceKind, ServiceStatus
from core.parsers import (
    classify_lxd,
    classify_runtime_error,
    cpu_breakdown_between,
    detect_provider,
    parse_cpu_samples,
    parse_lxd_list,
    parse_metrics,
    parse_smart,
    parse_vnstat,
    parse_vps,
)

# ---------------------------------------------------------------------------
# CPU steal / iowait
# ---------------------------------------------------------------------------

def test_cpu_steal_and_iowait_between_samples():
    #         user nice system idle iowait irq softirq steal
    first = parse_cpu_samples("cpu  100 0 100 700 50 0 0 50 0 0")[0]
    second = parse_cpu_samples("cpu  150 0 150 800 70 0 0 130 0 0")[0]
    iowait, steal = cpu_breakdown_between(first, second)
    assert iowait == pytest.approx(20 / 300 * 100)
    assert steal == pytest.approx(80 / 300 * 100)
    assert cpu_breakdown_between((1, 2), (3, 4)) == (None, None)


def test_parse_metrics_exposes_steal():
    stat = "cpu  100 0 100 700 50 0 0 50 0 0\ncpu  150 0 150 800 70 0 0 130 0 0"
    output = f"\n{SECTION}\n".join(["100.0 50.0", "0.1 0.2 0.3 1/2 3", "2", stat, "", "", "", ""])
    metrics, _state = parse_metrics(output, None)
    assert metrics.cpu_steal == pytest.approx(26.67, abs=0.01)
    assert metrics.cpu_iowait == pytest.approx(6.67, abs=0.01)


# ---------------------------------------------------------------------------
# LXD / Incus
# ---------------------------------------------------------------------------

LXD_JSON = json.dumps([
    {"name": "web01", "status": "Running", "type": "container", "project": "default",
     "config": {"image.description": "Ubuntu noble amd64"},
     "state": {"cpu": {"usage": 123_000_000_000}, "memory": {"usage": 268435456},
               "network": {"lo": {"addresses": [{"family": "inet", "address": "127.0.0.1", "scope": "local"}]},
                           "eth0": {"addresses": [{"family": "inet6", "address": "fd42::5", "scope": "global"},
                                                  {"family": "inet", "address": "10.10.10.5", "scope": "global"}]}}}},
    {"name": "win-vm", "status": "Stopped", "type": "virtual-machine", "project": "lab", "config": {},
     "state": {"cpu": {"usage": 0}, "memory": {"usage": 0}}},
    {"name": "broken", "status": "Error", "type": "container"},
])


def test_parse_lxd_list():
    cli, instances, usage = parse_lxd_list(f"CLI=incus\n{LXD_JSON}\n")
    assert cli == "incus"
    web, vm, broken = instances
    assert (web.kind, web.status, web.mem_bytes, web.group) == (ServiceKind.LXD, ServiceStatus.ACTIVE, 268435456, "")
    assert web.sub_state == "Running · 10.10.10.5" and web.description == "Ubuntu noble amd64"
    assert (web.type_label, vm.type_label) == ("LXC", "VM LXD")
    assert vm.group == "lab" and vm.status is ServiceStatus.STOPPED and vm.mem_bytes is None
    assert broken.status is ServiceStatus.FAILED
    assert web.meta_value("cli") == "incus" and usage == {"web01": 123_000_000_000}
    assert parse_lxd_list("CLI=lxc\n") == ("lxc", [], {})


@pytest.mark.parametrize(("status", "expected"), [
    ("Running", ServiceStatus.ACTIVE), ("Frozen", ServiceStatus.STOPPED), ("Starting", ServiceStatus.ACTIVATING),
    ("Error", ServiceStatus.FAILED), ("weird", ServiceStatus.UNKNOWN),
])
def test_classify_lxd(status, expected):
    assert classify_lxd(status) is expected


def test_lxd_runtime_errors():
    state, message = classify_runtime_error(ServiceKind.LXD, 1, 'Error: Get "http://unix.socket/1.0": dial unix '
                                            "/var/lib/incus/unix.socket: connect: permission denied")
    assert state is RuntimeState.PERMISSION and "lxd_sudo" in message
    state, _ = classify_runtime_error(ServiceKind.LXD, 1, "Error: LXD unix socket not accessible: connect: "
                                      "no such file or directory (unix.socket)")
    assert state is RuntimeState.DAEMON_DOWN
    assert classify_runtime_error(ServiceKind.LXD, 127, "lxd: command not found")[0] is RuntimeState.NOT_INSTALLED


# ---------------------------------------------------------------------------
# VPS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("vendor", "product", "expected"), [
    ("DigitalOcean", "Droplet", "DigitalOcean"),
    ("Hetzner", "vServer", "Hetzner Cloud"),
    ("Amazon EC2", "t3.micro", "AWS EC2"),
    ("Microsoft Corporation", "Virtual Machine", "Azure / Hyper-V"),
    ("QEMU", "Standard PC (i440FX + PIIX, 1996)", "KVM/QEMU"),
    ("Acme Hosting", "Box", "Acme Hosting"),
])
def test_detect_provider(vendor, product, expected):
    assert detect_provider(vendor, product) == expected


VNSTAT_V2_MONTH = json.dumps({"vnstatversion": "2.12", "jsonversion": "2", "interfaces": [
    {"name": "eth0", "traffic": {"month": [{"date": {"year": 2026, "month": 8}, "rx": 1, "tx": 1},
                                           {"date": {"year": 2026, "month": 9}, "rx": 123_000_000_000,
                                            "tx": 45_000_000_000}]}},
    {"name": "docker0", "traffic": {"month": [{"date": {"year": 2026, "month": 9}, "rx": 5, "tx": 5}]}},
]})
VNSTAT_V2_DAY = json.dumps({"jsonversion": "2", "interfaces": [
    {"name": "eth0", "traffic": {"day": [{"date": {"year": 2026, "month": 9, "day": 29}, "rx": 1000, "tx": 2000}]}}]})
VNSTAT_V1 = json.dumps({"vnstatversion": "1.18", "jsonversion": "1", "interfaces": [
    {"id": "ens3", "traffic": {"days": [{"id": 0, "date": {"year": 2026, "month": 9, "day": 29}, "rx": 1, "tx": 2}],
                               "months": [{"id": 0, "date": {"year": 2026, "month": 9}, "rx": 1024, "tx": 2048},
                                          {"id": 1, "date": {"year": 2026, "month": 8}, "rx": 9, "tx": 9}]}}]})


def test_parse_vnstat_v2_skips_virtual_interfaces():
    (eth0,) = parse_vnstat(VNSTAT_V2_MONTH, VNSTAT_V2_DAY)
    assert (eth0.interface, eth0.period, eth0.rx_bytes, eth0.tx_bytes) == ("eth0", "2026-09", 123e9, 45e9)
    assert (eth0.today_rx, eth0.today_tx) == (1000, 2000)
    assert eth0.total_bytes == 168_000_000_000


def test_parse_vnstat_v1_uses_kib():
    (ens3,) = parse_vnstat(VNSTAT_V1, VNSTAT_V1)
    assert (ens3.interface, ens3.rx_bytes, ens3.tx_bytes) == ("ens3", 1024 * 1024, 2048 * 1024)
    assert (ens3.today_rx, ens3.today_tx) == (1024, 2048)
    assert parse_vnstat("garbage") == ()


VPS_OUTPUT = f"\n{SECTION}\n".join([
    "sys_vendor=Hetzner\nproduct_name=vServer\nbios_vendor=Hetzner\nhypervisor=\nswappiness=60\n"
    "nameserver 185.12.64.1\nnameserver 185.12.64.2\n"
    "default via 172.31.1.1 dev eth0 proto dhcp src 5.75.1.2 metric 100",
    "Timezone=Europe/Berlin\nNTP=yes\nNTPSynchronized=yes\n"
    "System time     : 0.000012500 seconds slow of NTP time\nLeap status     : Normal",
    "OOM_TOTAL 2\n1727600000.5 web kernel: Out of memory: Killed process 1234 (java) total-vm:1kB\n"
    "1727600100.5 web kernel: Memory cgroup out of memory: Killed process 99 (node) total-vm:1kB",
    f"{VNSTAT_V2_MONTH}\n\n#DAY\n{VNSTAT_V2_DAY}",
])


def test_parse_vps():
    vps = parse_vps(VPS_OUTPUT)
    assert (vps.provider, vps.product) == ("Hetzner Cloud", "Hetzner vServer")
    assert vps.ntp_synchronized is True and vps.ntp_service == "ativo"
    assert vps.clock_offset == pytest.approx(-0.0000125)
    assert vps.dns_servers == ("185.12.64.1", "185.12.64.2")
    assert vps.default_gateway == "172.31.1.1 (eth0)" and vps.swappiness == 60
    assert vps.oom_kills_24h == 2 and [k.process for k in vps.oom_kills] == ["node", "java"]
    assert vps.bandwidth_source == "vnstat" and vps.bandwidth_total("tx") == 45e9
    assert vps.bandwidth_total("total") == 168e9


def test_parse_vps_old_timedatectl_and_no_vnstat():
    output = f"\n{SECTION}\n".join(["sys_vendor=QEMU\nproduct_name=Standard PC",
                                    "      System clock synchronized: no\n              NTP service: inactive",
                                    "OOM_TOTAL 0", "NOVNSTAT"])
    vps = parse_vps(output)
    assert vps.provider == "KVM/QEMU" and vps.ntp_synchronized is False and vps.ntp_service == "inativo"
    assert vps.oom_kills_24h == 0 and vps.bandwidth == () and vps.bandwidth_source == ""
    assert vps.bandwidth_total() is None


# ---------------------------------------------------------------------------
# SMART
# ---------------------------------------------------------------------------

ATA = {
    "smartctl": {"version": [7, 4], "exit_status": 0},
    "device": {"name": "/dev/sda", "type": "sat"}, "model_name": "Samsung SSD 870 EVO 1TB",
    "serial_number": "S6PN", "user_capacity": {"bytes": 1000204886016}, "smart_status": {"passed": True},
    "ata_smart_attributes": {"table": [
        {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
        {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 2}},
        {"id": 198, "name": "Offline_Uncorrectable", "raw": {"value": 0}}]},
    "power_on_time": {"hours": 12345}, "temperature": {"current": 34},
}
NVME = {
    "device": {"name": "/dev/nvme0", "type": "nvme"}, "model_name": "WD Black SN850X", "smart_status": {"passed": True},
    "nvme_total_capacity": 2000398934016,
    "nvme_smart_health_information_log": {"critical_warning": 0, "temperature": 41, "percentage_used": 3,
                                          "power_on_hours": 5000, "media_errors": 0},
}
DENIED = {"smartctl": {"messages": [{"string": "Smartctl open device: /dev/sdb failed: Permission denied",
                                     "severity": "error"}], "exit_status": 2},
          "device": {"name": "/dev/sdb", "type": "sat"}}


def test_parse_smart_ata_and_nvme():
    report = parse_smart(f"## /dev/sda\n{json.dumps(ATA)}\n## /dev/nvme0\n{json.dumps(NVME)}\n")
    sda, nvme = report.disks
    assert report.state is RuntimeState.OK
    assert (sda.model, sda.passed, sda.pending, sda.temperature, sda.power_on_hours) == (
        "Samsung SSD 870 EVO 1TB", True, 2, 34.0, 12345)
    assert sda.status is ServiceStatus.DEGRADED and sda.problems == ["2 setores pendentes"]
    assert (nvme.percentage_used, nvme.temperature, nvme.capacity_bytes) == (3, 41.0, 2000398934016)
    assert nvme.status is ServiceStatus.ACTIVE


def test_parse_smart_failed_and_permission():
    failed = dict(ATA, smart_status={"passed": False})
    (disk,) = parse_smart(f"## /dev/sda\n{json.dumps(failed)}").disks
    assert disk.status is ServiceStatus.FAILED and "REPROVADO" in disk.problems[0]
    report = parse_smart(f"## /dev/sdb\n{json.dumps(DENIED)}")
    assert report.state is RuntimeState.PERMISSION and "smart_sudo" in report.message
    assert report.disks[0].status is ServiceStatus.UNKNOWN


def test_parse_smart_without_disks_and_old_smartctl():
    assert "virtuais" in parse_smart("").message
    (disk,) = parse_smart("## /dev/sda\n=======> UNRECOGNIZED OPTION: j\n").disks
    assert "smartmontools 7" in disk.message
