"""Testes dos parsers (sem rede). Amostras baseadas em saídas reais."""

import json

import pytest

from core.commands import SECTION
from core.models import RuntimeState, ServiceKind, ServiceStatus
from core.parsers import (
    CgroupSample,
    MetricsState,
    ProcessSample,
    classify_container,
    classify_runtime_error,
    classify_systemd,
    cpu_percent_between,
    describe_sudo_failure,
    parse_cgroup_services,
    parse_container_stats,
    parse_cpu_samples,
    parse_cron,
    parse_df,
    parse_df_inodes,
    parse_diskstats,
    parse_docker_labels,
    parse_docker_ps,
    parse_free,
    parse_journal_json,
    parse_metrics,
    parse_net_dev,
    parse_pods,
    parse_podman_ps,
    parse_ports,
    parse_proc_net,
    parse_processes,
    parse_size,
    parse_ss,
    parse_system_info,
    parse_systemctl_json,
    parse_systemctl_table,
    parse_timers,
    parse_updates,
    parse_virsh_list,
    split_sections,
    strip_ansi,
)


def join_sections(*parts: str) -> str:
    return f"\n{SECTION}\n".join(parts)


def test_split_sections_ignores_marker_inside_lines():
    output = f"a\n  123 root sh -c 'x; echo {SECTION}; y'\n{SECTION}\nb\n"
    parts = split_sections(output, 3)
    assert parts[0].endswith("y'")
    assert parts[1] == "b"
    assert parts[2] == ""


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------

SYSTEMCTL_JSON = json.dumps([
    {"unit": "nginx.service", "load": "loaded", "active": "active", "sub": "running", "description": "nginx"},
    {"unit": "apache2.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Apache"},
    {"unit": "app.service", "load": "loaded", "active": "activating", "sub": "auto-restart", "description": "App"},
    {"unit": "cron.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Cron"},
    {"unit": "syslog.service", "load": "not-found", "active": "inactive", "sub": "dead", "description": ""},
    {"unit": "apt-daily.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": "apt"},
    {"unit": "docker.socket", "load": "loaded", "active": "active", "sub": "listening", "description": "sock"},
    {"unit": "mnt-nfs.mount", "load": "loaded", "active": "failed", "sub": "failed", "description": "/mnt/nfs"},
    {"unit": "multi-user.target", "load": "loaded", "active": "active", "sub": "active", "description": "tgt"},
])

SYSTEMCTL_TABLE = """\
  accounts-daemon.service  loaded    active   running Accounts Service
● apache2.service          loaded    failed   failed  The Apache HTTP Server
* nginx.service            loaded    active   running A high performance web server and a reverse proxy server
  plymouth-quit.service    loaded    inactive dead    Terminate Plymouth Boot Screen
  syslog.service           not-found inactive dead    syslog.service
  fstrim.timer             loaded    active   waiting Discard unused blocks once a week

LOAD   = Reflects whether the unit definition was properly loaded.
42 loaded units listed.
"""


def test_parse_systemctl_json_all_supported_types():
    units = {u.name: u for u in parse_systemctl_json(SYSTEMCTL_JSON)}
    assert set(units) == {"nginx.service", "apache2.service", "app.service", "cron.service",
                          "apt-daily.timer", "docker.socket", "mnt-nfs.mount"}  # sem not-found nem target
    assert units["apache2.service"].status is ServiceStatus.FAILED
    assert units["app.service"].status is ServiceStatus.ACTIVATING
    assert units["cron.service"].status is ServiceStatus.STOPPED
    assert units["mnt-nfs.mount"].status is ServiceStatus.FAILED
    assert units["apt-daily.timer"].unit_type == "timer"
    assert units["nginx.service"].state_text == "active/running"


def test_parse_systemctl_json_rejects_non_list():
    with pytest.raises(ValueError):
        parse_systemctl_json('{"unit": "x"}')


def test_parse_systemctl_table_handles_markers_and_legend():
    units = {u.name: u for u in parse_systemctl_table(SYSTEMCTL_TABLE)}
    assert set(units) == {"accounts-daemon.service", "apache2.service", "nginx.service",
                          "plymouth-quit.service", "fstrim.timer"}
    assert units["apache2.service"].status is ServiceStatus.FAILED
    assert units["nginx.service"].description.startswith("A high performance web server and")


@pytest.mark.parametrize(("active", "expected"), [
    ("active", ServiceStatus.ACTIVE), ("failed", ServiceStatus.FAILED),
    ("activating", ServiceStatus.ACTIVATING), ("reloading", ServiceStatus.ACTIVATING),
    ("inactive", ServiceStatus.STOPPED), ("deactivating", ServiceStatus.STOPPED),
    ("maintenance", ServiceStatus.UNKNOWN),
])
def test_classify_systemd(active, expected):
    assert classify_systemd(active) is expected


def test_parse_cgroup_services_computes_cpu_from_delta():
    first = "1000.00 4000.00\nnginx.service 52428800 1000000\ncron.service - \nfoo.scope 1 1\n"
    resources, sample = parse_cgroup_services(first, None)
    assert resources["nginx.service"] == (None, 52428800)
    assert resources["cron.service"] == (None, None)
    assert "foo.scope" not in resources
    second = "1002.00 4000.00\nnginx.service 60000000 1500000\n"
    resources, sample = parse_cgroup_services(second, sample)
    assert resources["nginx.service"][0] == pytest.approx(25.0)  # 0,5 s de CPU em 2 s
    assert isinstance(sample, CgroupSample)
    assert parse_cgroup_services("", sample) == ({}, sample)


TIMERS = """\
Unit=apt-daily.service
NextElapseUSecRealtime=Tue 2026-09-29 18:12:47 UTC
LastTriggerUSec=Mon 2026-09-28 18:40:06 UTC
Id=apt-daily.timer
Description=Daily apt download activities
ActiveState=active

Id=fstrim.timer
Unit=fstrim.service
NextElapseUSecRealtime=
LastTriggerUSec=n/a
ActiveState=inactive
Description=Discard unused blocks once a week

Id=*.timer
ActiveState=inactive
"""


def test_parse_timers():
    timers = {t.name: t for t in parse_timers(TIMERS)}
    assert set(timers) == {"apt-daily.timer", "fstrim.timer"}
    apt = timers["apt-daily.timer"]
    assert apt.activates == "apt-daily.service"
    assert apt.next_run == "2026-09-29 18:12:47 UTC"
    assert apt.last_run == "2026-09-28 18:40:06 UTC"
    assert timers["fstrim.timer"].next_run == "" and timers["fstrim.timer"].last_run == ""


# ---------------------------------------------------------------------------
# Docker / Podman
# ---------------------------------------------------------------------------

DOCKER_PS = "\n".join(json.dumps(item) for item in [
    {"ID": "a1", "Names": "shop-web-1", "Image": "nginx:1.27", "State": "running", "Status": "Up 2 hours",
     "Labels": "com.docker.compose.project=shop,com.docker.compose.service=web,"
               "com.docker.compose.project.working_dir=/opt/shop,"
               "com.docker.compose.project.config_files=/opt/shop/compose.yml,/opt/shop/override.yml"},
    {"ID": "a2", "Names": "api", "Image": "acme/api", "State": "running", "Status": "Up 5 minutes (unhealthy)"},
    {"ID": "a3", "Names": "db", "Image": "postgres", "State": "running", "Status": "Up 3 seconds (health: starting)"},
    {"ID": "a4", "Names": "job", "Image": "busybox", "State": "exited", "Status": "Exited (0) 1 hour ago"},
    {"ID": "a5", "Names": "crash", "Image": "busybox", "State": "exited", "Status": "Exited (1) 3 minutes ago"},
    {"ID": "a6", "Names": "loop", "Image": "busybox", "State": "restarting", "Status": "Restarting (2) 4 seconds ago"},
    {"ID": "a7", "Names": "stopped", "Image": "busybox", "State": "exited", "Status": "Exited (137) 2 days ago"},
    {"ID": "a8", "Names": "legacy,alias", "Image": "old", "Status": "Up 3 days"},  # sem .State
])


def test_parse_docker_ps_with_compose_labels():
    containers = {c.name: c for c in parse_docker_ps(DOCKER_PS + "\nWARNING: not json\n")}
    web = containers["shop-web-1"]
    assert web.status is ServiceStatus.ACTIVE and web.kind is ServiceKind.DOCKER
    assert web.group == "shop"
    assert web.meta_value("config_files") == "/opt/shop/compose.yml,/opt/shop/override.yml"
    assert web.meta_value("working_dir") == "/opt/shop"
    assert containers["api"].status is ServiceStatus.FAILED
    assert containers["db"].status is ServiceStatus.ACTIVATING
    assert containers["job"].status is ServiceStatus.STOPPED
    assert containers["crash"].status is ServiceStatus.FAILED
    assert containers["loop"].status is ServiceStatus.FAILED
    assert containers["stopped"].status is ServiceStatus.STOPPED
    assert containers["legacy"].status is ServiceStatus.ACTIVE
    assert containers["api"].group == ""


def test_parse_docker_labels_keeps_commas_inside_values():
    labels = parse_docker_labels("a=1,files=/x.yml,/y.yml,b=2")
    assert labels == {"a": "1", "files": "/x.yml,/y.yml", "b": "2"}


PODMAN_PS = json.dumps([
    {"Id": "8d0b1c", "Names": ["db_postgres_1"], "Image": "docker.io/library/postgres:16", "State": "running",
     "Status": "Up 4 days", "ExitCode": 0, "Labels": {"io.podman.compose.project": "db"}, "PodName": ""},
    {"Id": "9e1c2d", "Names": ["sidecar"], "Image": "busybox", "State": "exited", "Status": "",
     "ExitCode": 2, "Labels": None, "PodName": "web-pod"},
    {"Id": "ffff00", "Names": ["old"], "Image": "busybox", "State": 3, "ExitCode": 0},
], indent=2)


def test_parse_podman_ps():
    containers = {c.name: c for c in parse_podman_ps(PODMAN_PS)}
    assert containers["db_postgres_1"].kind is ServiceKind.PODMAN
    assert containers["db_postgres_1"].group == "db"
    assert containers["db_postgres_1"].status is ServiceStatus.ACTIVE
    assert containers["sidecar"].sub_state == "Exited (2)"
    assert containers["sidecar"].status is ServiceStatus.FAILED
    assert containers["sidecar"].group == "web-pod"
    assert containers["old"].status is ServiceStatus.UNKNOWN
    assert parse_podman_ps("") == []


@pytest.mark.parametrize(("state", "status", "expected"), [
    ("", "Exited (3) 2 minutes ago", ServiceStatus.FAILED),
    ("", "Up 1 minute (Paused)", ServiceStatus.STOPPED),
    ("created", "Created", ServiceStatus.STOPPED),
    ("dead", "Dead", ServiceStatus.FAILED),
    ("restarting", "Restarting (0) 1 second ago", ServiceStatus.ACTIVATING),
    ("stopped", "", ServiceStatus.STOPPED),
])
def test_classify_container_edge_cases(state, status, expected):
    assert classify_container(state, status) is expected


def test_parse_container_stats_and_sizes():
    stats = parse_container_stats("web|12.50%|120.5MiB / 1.944GiB\nold|--|-- / --\n|x|y\ndb|0.00%|1.2GB / 8GB\n")
    assert stats["web"] == (12.5, int(120.5 * 1024 ** 2))
    assert stats["old"] == (None, None)
    assert stats["db"] == (0.0, 1_200_000_000)
    assert parse_size("648B") == 648
    assert parse_size("1.5kB") == 1500
    assert parse_size("nada") is None


# ---------------------------------------------------------------------------
# Kubernetes / libvirt / erros de runtime
# ---------------------------------------------------------------------------

PODS = """\
kube-system   coredns-7b98449c4-x2k9d    Running     true         0     <none>             <none>      node1    2026-09-20T10:00:00Z   <none>                 ReplicaSet
prod          payments-7d4f5b9c8-kq2mz   Running     false        14    CrashLoopBackOff   Error       node1    2026-09-28T10:00:00Z   <none>                 ReplicaSet
prod          web-0                      Running     true,false   0,3   <none>             <none>      node2    2026-09-28T10:00:00Z   <none>                 StatefulSet
prod          report-28791440-6hk2p      Succeeded   false        0     <none>             Completed   node1    2026-09-28T02:00:00Z   <none>                 Job
prod          pending-xyz                Pending     <none>       <none> <none>            <none>      <none>   2026-09-29T10:00:00Z   <none>                 <none>
prod          old-abc                    Running     true         0     <none>             <none>      node1    2026-09-20T10:00:00Z   2026-09-29T10:01:00Z   ReplicaSet
"""  # noqa: E501


def test_parse_pods():
    pods = {p.name: p for p in parse_pods(PODS)}
    assert pods["kube-system/coredns-7b98449c4-x2k9d"].status is ServiceStatus.ACTIVE
    payments = pods["prod/payments-7d4f5b9c8-kq2mz"]
    assert payments.status is ServiceStatus.FAILED
    assert payments.sub_state.startswith("CrashLoopBackOff · 0/1 prontos · 14 reinícios")
    assert payments.group == "prod" and payments.kind is ServiceKind.KUBERNETES
    assert pods["prod/web-0"].status is ServiceStatus.ACTIVATING
    assert "3 reinícios" in pods["prod/web-0"].sub_state
    assert pods["prod/report-28791440-6hk2p"].status is ServiceStatus.STOPPED
    assert pods["prod/pending-xyz"].status is ServiceStatus.ACTIVATING
    assert pods["prod/old-abc"].sub_state.startswith("Terminating")
    assert pods["prod/web-0"].description == "StatefulSet · nó node2"


def test_parse_virsh_list():
    vms = {v.name: v for v in parse_virsh_list(
        " 1    win2022-ad         running\n -    legacy-centos7     shut off\n 3    kali sandbox   paused\n"
        " 4    broken             crashed\n 5    going              in shutdown\n")}
    assert vms["win2022-ad"].status is ServiceStatus.ACTIVE
    assert vms["legacy-centos7"].status is ServiceStatus.STOPPED
    assert vms["kali sandbox"].status is ServiceStatus.STOPPED
    assert vms["broken"].status is ServiceStatus.FAILED
    assert vms["going"].status is ServiceStatus.ACTIVATING
    assert vms["win2022-ad"].kind is ServiceKind.LIBVIRT


@pytest.mark.parametrize(("kind", "code", "output", "state"), [
    (ServiceKind.DOCKER, 127, "sh: 1: docker: not found", RuntimeState.NOT_INSTALLED),
    (ServiceKind.PODMAN, 127, "sh: podman: command not found", RuntimeState.NOT_INSTALLED),
    (ServiceKind.DOCKER, 1, "permission denied while trying to connect to the Docker daemon socket",
     RuntimeState.PERMISSION),
    (ServiceKind.DOCKER, 1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                            "Is the docker daemon running?", RuntimeState.DAEMON_DOWN),
    (ServiceKind.DOCKER, 1, "failed to connect to the docker API at unix:///var/run/docker.sock; check if the "
                            "path is correct and if the daemon is running", RuntimeState.DAEMON_DOWN),
    (ServiceKind.DOCKER, 1, "sudo: a password is required", RuntimeState.PERMISSION),
    (ServiceKind.KUBERNETES, 1, "The connection to the server localhost:8080 was refused - did you specify "
                                "the right host or port?", RuntimeState.DAEMON_DOWN),
    (ServiceKind.KUBERNETES, 1, "error: error loading config file \"/etc/rancher/k3s/k3s.yaml\": open "
                                "/etc/rancher/k3s/k3s.yaml: permission denied", RuntimeState.PERMISSION),
    (ServiceKind.LIBVIRT, 1, "error: failed to connect to the hypervisor\nerror: authentication unavailable",
     RuntimeState.PERMISSION),
    (ServiceKind.LIBVIRT, 1, "error: failed to connect to the hypervisor", RuntimeState.DAEMON_DOWN),
    (ServiceKind.DOCKER, 1, "something odd", RuntimeState.ERROR),
])
def test_classify_runtime_error(kind, code, output, state):
    assert classify_runtime_error(kind, code, output)[0] is state


# ---------------------------------------------------------------------------
# Métricas
# ---------------------------------------------------------------------------

FREE_MODERN = """\
               total        used        free      shared  buff/cache   available
Mem:           15876        4523        6789         345        4563       10987
Swap:           2047          12        2035
"""

FREE_OLD = """\
             total       used       free     shared    buffers     cached
Mem:          7872       7684        188          0        265       5795
-/+ buffers/cache:       1623       6249
Swap:         4095         13       4082
"""


def test_parse_free_modern_and_old():
    assert parse_free(FREE_MODERN) == {"total": 15876, "used": 4523, "available": 10987,
                                       "swap_total": 2047, "swap_used": 12}
    old = parse_free(FREE_OLD)
    assert (old["total"], old["used"], old["available"], old["swap_used"]) == (7872, 1623, 6249, 13)


DF = """\
Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1         41152736  26214400  12832916      68% /
tmpfs              8123456         0   8123456       0% /dev/shm
/dev/loop3           65536     65536         0     100% /snap/core/123
overlay           41152736  26214400  12832916      68% /var/lib/docker/overlay2/abc/merged
/dev/sdb1        205374440 176000000  29374440      86% /var/lib/postgresql
//nas/share      976762584 100000000 876762584      11% /mnt/nas share
"""

DF_INODES = """\
Filesystem       Inodes  IUsed    IFree IUse% Mounted on
/dev/sda1       2621440 262144  2359296   10% /
tmpfs           2060121      2  2060119    1% /dev/shm
/dev/sdb1      13107200 131072 12976128    1% /var/lib/postgresql
"""


def test_parse_df_and_inodes():
    disks = parse_df(DF)
    assert [d.mount for d in disks] == ["/", "/var/lib/postgresql", "/mnt/nas share"]
    assert disks[0].use_percent == 68.0 and disks[1].avail_kb == 29374440
    assert parse_df_inodes(DF_INODES) == {"/": 10.0, "/var/lib/postgresql": 1.0}


NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  586732    2312    0    0    0     0          0         0   586732    2312    0    0    0     0       0          0
  eth0:1000000    9000    0    0    0     0          0         0   500000    4000    0    0    0     0       0          0
veth1a2b:  2000      10    0    0    0     0          0         0     3000      12    0    0    0     0       0          0
"""  # noqa: E501

DISKSTATS = """\
   7       0 loop0 10 0 80 0 0 0 0 0 0 0 0
   8       0 sda 1000 0 20000 500 2000 0 40000 800 0 900 1300
   8       1 sda1 900 0 18000 400 1900 0 38000 700 0 800 1100
 259       0 nvme0n1 10 0 1000 1 20 0 2000 2 0 3 3
 253       0 dm-0 50 0 400 1 60 0 480 2 0 3 3
"""


def test_parse_net_dev_and_diskstats():
    net = parse_net_dev(NET_DEV)
    assert net["eth0"] == (1_000_000, 500_000)
    assert net["lo"] == (586732, 586732) and "veth1a2b" in net
    disks = parse_diskstats(DISKSTATS)
    assert set(disks) == {"sda", "nvme0n1"}  # sem partições, loop ou device-mapper
    assert disks["sda"] == (20000 * 512, 40000 * 512)


def _metrics_output(uptime: str, cpu_lines: str, net: str = NET_DEV, disks: str = DISKSTATS) -> str:
    return join_sections(uptime, "0.52 0.58 0.59 1/467 12345", "4", cpu_lines, FREE_MODERN, DF, net, disks)


def test_parse_metrics_rates_between_polls():
    first, state = parse_metrics(_metrics_output("1000.0 1", "cpu  100 0 100 800 0 0 0 0\n"
                                                             "cpu  130 0 130 840 0 0 0 0"), None)
    assert first.cpu_percent == pytest.approx(60.0)
    assert first.net_rx_bps is None  # primeira amostra: sem taxa
    assert first.load_avg == (0.52, 0.58, 0.59) and first.cpu_count == 4
    assert first.fullest_disk.mount == "/var/lib/postgresql"

    net2 = NET_DEV.replace("eth0:1000000", "eth0:1500000").replace("500000    4000", "700000    4000")
    disk2 = DISKSTATS.replace("sda 1000 0 20000", "sda 1000 0 21000")
    second, state = parse_metrics(_metrics_output("1010.0 1", "cpu  230 0 230 940 0 0 0 0", net2, disk2), state)
    assert second.cpu_percent == pytest.approx(66.67, abs=0.01)
    eth0 = next(i for i in second.interfaces if i.name == "eth0")
    assert eth0.rx_bps == pytest.approx(50_000) and eth0.tx_bps == pytest.approx(20_000)
    assert next(i for i in second.interfaces if i.name == "veth1a2b").virtual
    assert second.net_rx_bps == pytest.approx(50_000)  # lo e veth fora do total
    assert second.disk_read_bps == pytest.approx(1000 * 512 / 10)
    assert state.uptime == 1010.0


def test_parse_metrics_tolerates_garbage():
    metrics, state = parse_metrics("garbage", MetricsState(cpu=(1, 2)))
    assert metrics.cpu_percent is None and metrics.disks == () and state.cpu == (1, 2)


def test_cpu_samples_and_percent():
    samples = parse_cpu_samples("cpu  100 0 100 800 0 0 0 0 0 0\ncpu  150 0 150 900 0 0 0 0 0 0\n")
    assert samples == [(800, 1000, 0, 0), (900, 1200, 0, 0)]
    assert cpu_percent_between(samples[0], samples[1]) == pytest.approx(50.0)
    assert cpu_percent_between((10, 10), (10, 10)) is None


# ---------------------------------------------------------------------------
# Processos
# ---------------------------------------------------------------------------

PS = f"""\
    1 root                               0.0  11000 90000 Ss   /sbin/init splash
    2 root                               0.0      0 90000 S    [kthreadd]
  812 postgres                           3.2 512000  8000 Ss   postgres: checkpointer
  990 www-data                           0.5  64000  7000 S    nginx: worker process
 1234 monitor                            0.0   2000     1 S    sh -c {{ ps; }}; echo {SECTION}; cat /proc/uptime
"""
STAT_1 = """\
1000.00 3000.00
100
1 (systemd) S 0 1 1 0 -1 4194560 1 1 0 0 100 50 0 0 20 0 1 0 1 0 0
812 (postgres) S 1 812 812 0 -1 4194560 1 1 0 0 1000 200 0 0 20 0 1 0 1 0 0
990 (nginx (worker)) S 1 990 990 0 -1 4194560 1 1 0 0 10 10 0 0 20 0 1 0 1 0 0
"""
STAT_2 = """\
1000.50 3001.00
100
1 (systemd) S 0 1 1 0 -1 4194560 1 1 0 0 100 50 0 0 20 0 1 0 1 0 0
812 (postgres) R 1 812 812 0 -1 4194560 1 1 0 0 1040 210 0 0 20 0 1 0 1 0 0
990 (nginx (worker)) S 1 990 990 0 -1 4194560 1 1 0 0 11 10 0 0 20 0 1 0 1 0 0
"""


def test_parse_processes_two_samples():
    processes, sample = parse_processes(join_sections(PS, STAT_1, STAT_2), None)
    by_pid = {p.pid: p for p in processes}
    assert set(by_pid) == {1, 812, 990}  # sem thread do kernel nem o próprio coletor
    assert by_pid[812].cpu_percent == pytest.approx(100.0)  # 50 ticks em 0,5 s = 1 núcleo
    assert by_pid[990].cpu_percent == pytest.approx(2.0)
    assert by_pid[990].command == "nginx (worker)"  # nome com espaço e parênteses
    assert by_pid[812].user == "postgres" and by_pid[812].rss_kb == 512000
    assert by_pid[1].args == "/sbin/init splash"
    assert processes[0].pid == 812  # ordenado por CPU
    assert isinstance(sample, ProcessSample) and sample.uptime == 1000.5


def test_parse_processes_uses_previous_sample():
    _processes, sample = parse_processes(join_sections(PS, STAT_1), None)
    processes, _ = parse_processes(join_sections(PS, STAT_2), sample)
    assert {p.pid: p.cpu_percent for p in processes}[812] == pytest.approx(100.0)
    first, _ = parse_processes(join_sections(PS, STAT_1), None)
    assert all(p.cpu_percent is None for p in first)


# ---------------------------------------------------------------------------
# Rede
# ---------------------------------------------------------------------------

SS = """\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=812,fd=4))
tcp   LISTEN 0      511                *:80               *:*
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=13))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
"""


def test_parse_ss():
    sockets = parse_ss(SS)
    assert [(s.proto, s.address, s.port, s.process, s.pid) for s in sockets] == [
        ("tcp", "0.0.0.0", 22, "sshd", 812),
        ("tcp", "::", 22, "sshd", 812),
        ("udp", "127.0.0.53", 53, "systemd-resolve", 600),
        ("tcp", "*", 80, "", None),
    ]


PROC_NET = """\
## tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0
## tcp6
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0
   1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 0
## udp
   0: 00000000:0044 00000000:0000 07 0
"""


def test_parse_proc_net_fallback_decodes_addresses():
    sockets = parse_proc_net(PROC_NET)
    assert [(s.proto, s.address, s.port) for s in sockets] == [
        ("tcp", "::", 22), ("udp", "0.0.0.0", 68), ("tcp", "::1", 3306), ("tcp", "127.0.0.1", 8080)]


def test_parse_ports_with_sockstat():
    sockstat = "sockets: used 41\nTCP: inuse 27 orphan 0 tw 3 alloc 27 mem 255\nUDP: inuse 2 mem 0\n"
    info = parse_ports(join_sections("SS\n" + SS, sockstat))
    assert info.process_info and len(info.listening) == 4
    assert (info.tcp_inuse, info.tcp_timewait, info.udp_inuse) == (27, 3, 2)
    fallback = parse_ports(join_sections("PROC\n" + PROC_NET, sockstat))
    assert not fallback.process_info and len(fallback.listening) == 4


# ---------------------------------------------------------------------------
# Agendamentos, eventos, inventário
# ---------------------------------------------------------------------------

CRON = """\
## crontab do usuário
MAILTO=ops@example.com
# comentário
*/5 * * * * /home/monitor/bin/check.sh --quiet
@reboot /home/monitor/bin/boot.sh
## /etc/crontab
SHELL=/bin/sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
## /etc/cron.d/certbot
0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew
@daily www-data /opt/app/cleanup
#@ daily /etc/cron.daily/logrotate
"""


def test_parse_cron():
    entries = parse_cron(CRON, "monitor")
    assert [(e.source, e.schedule, e.user, e.command) for e in entries] == [
        ("crontab do usuário", "*/5 * * * *", "monitor", "/home/monitor/bin/check.sh --quiet"),
        ("crontab do usuário", "@reboot", "monitor", "/home/monitor/bin/boot.sh"),
        ("/etc/crontab", "17 * * * *", "root", "cd / && run-parts --report /etc/cron.hourly"),
        ("/etc/cron.d/certbot", "0 */12 * * *", "root", "test -x /usr/bin/certbot && certbot -q renew"),
        ("/etc/cron.d/certbot", "@daily", "www-data", "/opt/app/cleanup"),
        ("/etc/cron.daily", "@daily", "root", "/etc/cron.daily/logrotate"),
    ]


def test_parse_journal_json():
    lines = [
        json.dumps({"__REALTIME_TIMESTAMP": "1759140000000000", "PRIORITY": "3", "_SYSTEMD_UNIT": "nginx.service",
                    "SYSLOG_IDENTIFIER": "nginx", "MESSAGE": "upstream timed out"}),
        json.dumps({"__REALTIME_TIMESTAMP": "1759140100000000", "PRIORITY": "2", "_COMM": "kernel",
                    "MESSAGE": [104, 105]}),
        "not json",
    ]
    entries = parse_journal_json("\n".join(lines))
    assert [e.message for e in entries] == ["hi", "upstream timed out"]  # mais recente primeiro
    assert entries[0].priority_label == "crit" and entries[0].identifier == "kernel"
    assert entries[1].unit == "nginx.service" and entries[1].timestamp == pytest.approx(1759140000.0)


SYSTEM = join_sections(
    "os=Ubuntu 24.04.1 LTS\nkernel=6.8.0-45-generic\narch=x86_64\nhostname=web01\n"
    "cpu_model=Intel(R) Xeon(R)\nvirt=kvm\nboot=2026-09-14 06:12:03\ntimezone=America/Sao_Paulo\nusers=2\n"
    "reboot_required=yes\nips=10.0.0.5 172.17.0.1 \nfailed_units=1\ngroups=monitor monitor adm\n"
    "temp=x86_pkg_temp:54000\ntemp=acpitz:41500",
    DF_INODES,
)


def test_parse_system_info():
    info, inodes = parse_system_info(SYSTEM, "7\n")
    assert info.os_name == "Ubuntu 24.04.1 LTS" and info.hostname == "web01"
    assert info.reboot_required and info.logged_users == 2 and info.failed_units == 1
    assert info.ip_addresses == ("10.0.0.5", "172.17.0.1")
    assert info.temperatures == (("x86_pkg_temp", 54.0), ("acpitz", 41.5))
    assert info.journal_access is True and info.ssh_failed_logins_24h == 7
    assert inodes["/"] == 10.0
    limited, _ = parse_system_info(SYSTEM.replace("groups=monitor monitor adm", "groups=monitor monitor"), "0")
    assert limited.journal_access is False and limited.ssh_failed_logins_24h is None


@pytest.mark.parametrize(("output", "expected"), [
    ("apt-check 12;3\n", ("apt", 12, 3)),
    ("apt 194\n", ("apt", 194, None)),
    ("dnf 5\n", ("dnf", 5, None)),
    ("unknown\n", None),
    ("", None),
])
def test_parse_updates(output, expected):
    info = parse_updates(output)
    if expected is None:
        assert info is None
    else:
        assert (info.manager, info.pending, info.security) == expected


def test_strip_ansi_and_sudo_hints():
    assert strip_ansi("\x1b[32mOK\x1b[0m done") == "OK done"
    assert "NOPASSWD" in describe_sudo_failure("sudo: a password is required")
    assert describe_sudo_failure("sudo: a terminal is required to read the password") is not None
    assert describe_sudo_failure("Failed to restart x: Interactive authentication required.") is not None
    assert describe_sudo_failure("kill: (1234) - Operation not permitted") is not None
    assert describe_sudo_failure("all good") is None
