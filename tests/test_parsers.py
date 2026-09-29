"""Testes dos parsers e construtores de comando (sem rede)."""

import json

import pytest

from core.models import DockerState, ServiceAction, ServiceKind, ServiceStatus
from core.ssh_client import (
    _SECTION,
    CommandResult,
    build_docker_action_command,
    build_docker_logs_command,
    build_journal_command,
    build_metrics_command,
    build_service_action_command,
    classify_docker,
    classify_docker_error,
    classify_systemd,
    cpu_percent_between,
    describe_sudo_failure,
    parse_cpu_samples,
    parse_df,
    parse_docker_ps,
    parse_free,
    parse_metrics,
    parse_systemctl_json,
    parse_systemctl_table,
    strip_ansi,
    validate_unit_name,
    wrap_remote_command,
)

SYSTEMCTL_JSON = json.dumps([
    {"unit": "nginx.service", "load": "loaded", "active": "active", "sub": "running",
     "description": "A high performance web server"},
    {"unit": "apache2.service", "load": "loaded", "active": "failed", "sub": "failed",
     "description": "The Apache HTTP Server"},
    {"unit": "app.service", "load": "loaded", "active": "activating", "sub": "auto-restart",
     "description": "App"},
    {"unit": "cron.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Cron"},
    {"unit": "syslog.service", "load": "not-found", "active": "inactive", "sub": "dead",
     "description": "syslog.service"},
])

SYSTEMCTL_TABLE = """\
  accounts-daemon.service  loaded    active   running Accounts Service
● apache2.service          loaded    failed   failed  The Apache HTTP Server
* nginx.service            loaded    active   running A high performance web server and a reverse proxy server
  plymouth-quit.service    loaded    inactive dead    Terminate Plymouth Boot Screen
  syslog.service           not-found inactive dead    syslog.service

LOAD   = Reflects whether the unit definition was properly loaded.
42 loaded units listed.
"""


def test_parse_systemctl_json_classifies_and_skips_not_found():
    services = {s.name: s for s in parse_systemctl_json(SYSTEMCTL_JSON)}
    assert set(services) == {"nginx.service", "apache2.service", "app.service", "cron.service"}
    assert services["nginx.service"].status is ServiceStatus.ACTIVE
    assert services["apache2.service"].status is ServiceStatus.FAILED
    assert services["app.service"].status is ServiceStatus.ACTIVATING
    assert services["cron.service"].status is ServiceStatus.STOPPED
    assert services["nginx.service"].kind is ServiceKind.SYSTEMD
    assert services["nginx.service"].state_text == "active/running"


def test_parse_systemctl_json_rejects_non_list():
    with pytest.raises(ValueError):
        parse_systemctl_json('{"unit": "x"}')


def test_parse_systemctl_table_handles_markers_and_legend():
    services = {s.name: s for s in parse_systemctl_table(SYSTEMCTL_TABLE)}
    assert set(services) == {"accounts-daemon.service", "apache2.service", "nginx.service",
                             "plymouth-quit.service"}
    assert services["apache2.service"].status is ServiceStatus.FAILED
    assert services["nginx.service"].description.startswith("A high performance web server and")
    assert services["plymouth-quit.service"].status is ServiceStatus.STOPPED


@pytest.mark.parametrize(("active", "expected"), [
    ("active", ServiceStatus.ACTIVE),
    ("failed", ServiceStatus.FAILED),
    ("activating", ServiceStatus.ACTIVATING),
    ("reloading", ServiceStatus.ACTIVATING),
    ("inactive", ServiceStatus.STOPPED),
    ("deactivating", ServiceStatus.STOPPED),
    ("maintenance", ServiceStatus.UNKNOWN),
])
def test_classify_systemd(active, expected):
    assert classify_systemd(active, "") is expected


DOCKER_PS = "\n".join(json.dumps(item) for item in [
    {"ID": "a1", "Names": "web", "Image": "nginx:1.27", "State": "running", "Status": "Up 2 hours"},
    {"ID": "a2", "Names": "api", "Image": "acme/api", "State": "running", "Status": "Up 5 minutes (unhealthy)"},
    {"ID": "a3", "Names": "db", "Image": "postgres", "State": "running", "Status": "Up 3 seconds (health: starting)"},
    {"ID": "a4", "Names": "job", "Image": "busybox", "State": "exited", "Status": "Exited (0) 1 hour ago"},
    {"ID": "a5", "Names": "crash", "Image": "busybox", "State": "exited", "Status": "Exited (1) 3 minutes ago"},
    {"ID": "a6", "Names": "loop", "Image": "busybox", "State": "restarting", "Status": "Restarting (2) 4 seconds ago"},
    {"ID": "a7", "Names": "stopped", "Image": "busybox", "State": "exited", "Status": "Exited (137) 2 days ago"},
    {"ID": "a8", "Names": "legacy,alias", "Image": "old", "Status": "Up 3 days"},  # sem .State
])


def test_parse_docker_ps():
    containers = {c.name: c for c in parse_docker_ps(DOCKER_PS + "\nWARNING: not json\n")}
    assert containers["web"].status is ServiceStatus.ACTIVE
    assert containers["api"].status is ServiceStatus.FAILED
    assert containers["db"].status is ServiceStatus.ACTIVATING
    assert containers["job"].status is ServiceStatus.STOPPED
    assert containers["crash"].status is ServiceStatus.FAILED
    assert containers["loop"].status is ServiceStatus.FAILED
    assert containers["stopped"].status is ServiceStatus.STOPPED
    assert containers["legacy"].status is ServiceStatus.ACTIVE
    assert containers["web"].kind is ServiceKind.DOCKER
    assert containers["web"].description == "nginx:1.27"
    assert containers["web"].state_text == "Up 2 hours"


@pytest.mark.parametrize(("state", "status", "expected"), [
    ("", "Exited (3) 2 minutes ago", ServiceStatus.FAILED),
    ("", "Up 1 minute (Paused)", ServiceStatus.STOPPED),
    ("created", "Created", ServiceStatus.STOPPED),
    ("dead", "Dead", ServiceStatus.FAILED),
    ("restarting", "Restarting (0) 1 second ago", ServiceStatus.ACTIVATING),
])
def test_classify_docker_edge_cases(state, status, expected):
    assert classify_docker(state, status) is expected


def _result(code, stdout="", stderr=""):
    return CommandResult("docker ps", code, stdout, stderr, 0.1)


@pytest.mark.parametrize(("result", "state"), [
    (_result(127, stderr="sh: 1: docker: not found"), DockerState.NOT_INSTALLED),
    (_result(1, stderr="permission denied while trying to connect to the Docker daemon socket at "
                       "unix:///var/run/docker.sock"), DockerState.PERMISSION),
    (_result(1, stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                       "Is the docker daemon running?"), DockerState.DAEMON_DOWN),
    (_result(1, stderr="failed to connect to the docker API at unix:///var/run/docker.sock; check if the "
                       "path is correct and if the daemon is running"), DockerState.DAEMON_DOWN),
    (_result(1, stderr="sudo: a password is required"), DockerState.PERMISSION),
    (_result(1, stderr="something odd"), DockerState.ERROR),
])
def test_classify_docker_error(result, state):
    assert classify_docker_error(result)[0] is state


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


def test_parse_free_modern():
    assert parse_free(FREE_MODERN) == {"total": 15876, "used": 4523, "available": 10987,
                                       "swap_total": 2047, "swap_used": 12}


def test_parse_free_old_procps_uses_buffers_cache_line():
    memory = parse_free(FREE_OLD)
    assert memory["total"] == 7872
    assert memory["used"] == 1623
    assert memory["available"] == 6249
    assert memory["swap_used"] == 13


DF = """\
Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1         41152736  26214400  12832916      68% /
tmpfs              8123456         0   8123456       0% /dev/shm
/dev/loop3           65536     65536         0     100% /snap/core/123
overlay           41152736  26214400  12832916      68% /var/lib/docker/overlay2/abc/merged
/dev/sdb1        205374440 176000000  29374440      86% /var/lib/postgresql
//nas/share      976762584 100000000 876762584      11% /mnt/nas share
"""


def test_parse_df_filters_pseudo_filesystems():
    disks = parse_df(DF)
    assert [d.mount for d in disks] == ["/", "/var/lib/postgresql", "/mnt/nas share"]
    assert disks[0].use_percent == 68.0
    assert disks[1].avail_kb == 29374440


def test_cpu_samples_and_percent():
    samples = parse_cpu_samples("cpu  100 0 100 800 0 0 0 0 0 0\ncpu  150 0 150 900 0 0 0 0 0 0\n")
    assert samples == [(800, 1000), (900, 1200)]
    assert cpu_percent_between(samples[0], samples[1]) == pytest.approx(50.0)
    assert cpu_percent_between((10, 10), (10, 10)) is None


def _metrics_output(cpu_lines: str) -> str:
    sections = [
        "12345.67 45678.90",
        "0.52 0.58 0.59 1/467 12345",
        "4",
        cpu_lines,
        FREE_MODERN,
        DF,
    ]
    return f"\n{_SECTION}\n".join(sections)


def test_parse_metrics_with_two_cpu_samples():
    output = _metrics_output("cpu  100 0 100 800 0 0 0 0\ncpu  130 0 130 840 0 0 0 0")
    metrics, last = parse_metrics(output, None)
    assert metrics.uptime_seconds == pytest.approx(12345.67)
    assert metrics.load_avg == (0.52, 0.58, 0.59)
    assert metrics.cpu_count == 4
    assert metrics.cpu_percent == pytest.approx(60.0)
    assert metrics.mem_total_mb == 15876
    assert metrics.mem_percent == pytest.approx(100 * 4523 / 15876)
    assert metrics.root_disk.mount == "/"
    assert metrics.fullest_disk.mount == "/var/lib/postgresql"
    assert last == (840, 1100)


def test_parse_metrics_uses_previous_sample_and_tolerates_garbage():
    metrics, last = parse_metrics(_metrics_output("cpu  250 0 250 900 0 0 0 0"), (800, 1000))
    assert metrics.cpu_percent == pytest.approx(75.0)
    assert last == (900, 1400)
    empty, prev = parse_metrics("garbage", (1, 2))
    assert empty.cpu_percent is None and empty.disks == () and prev == (1, 2)


def test_metrics_command_samples_cpu_twice_only_on_first_poll():
    assert build_metrics_command(True).count("/proc/stat") == 2
    assert build_metrics_command(False).count("/proc/stat") == 1
    assert build_metrics_command(False).count(_SECTION) == 5


def test_service_commands_use_non_interactive_sudo_and_no_block():
    assert (build_service_action_command("nginx.service", ServiceAction.RESTART, True)
            == "sudo -n systemctl --no-block restart nginx.service")
    assert (build_service_action_command("nginx.service", ServiceAction.STOP, False)
            == "systemctl --no-block stop nginx.service")
    assert build_journal_command("nginx.service", 50, False) == "journalctl -u nginx.service -n 50 --no-pager"
    assert build_docker_action_command("web", ServiceAction.STOP, False) == "docker stop -t 3 web"
    assert build_docker_action_command("web", ServiceAction.START, True) == "sudo -n docker start web"
    assert build_docker_logs_command("web", 100, False) == "docker logs --tail 100 --timestamps web 2>&1"


def test_escaped_unit_names_are_quoted():
    unit = r"systemd-fsck@dev-disk-by\x2duuid-1234.service"
    assert validate_unit_name(unit) == unit
    assert build_journal_command(unit, 10, False) == f"journalctl -u '{unit}' -n 10 --no-pager"


@pytest.mark.parametrize("name", [
    "nginx; rm -rf /", "$(id)", "`id`", "-H", "--root=/tmp", "a b", "", "nginx|cat", "x\ny",
])
def test_command_injection_is_rejected(name):
    with pytest.raises(ValueError):
        build_service_action_command(name, ServiceAction.RESTART, True)
    with pytest.raises(ValueError):
        build_docker_logs_command(name, 10, False)


def test_wrap_remote_command_forces_c_locale_and_quotes():
    wrapped = wrap_remote_command("echo 'a' && df -kP")
    assert wrapped.startswith("env LC_ALL=C LANG=C sh -c ")
    assert "'\"'\"'" in wrapped  # aspas simples escapadas pelo shlex


def test_strip_ansi_and_sudo_hints():
    assert strip_ansi("\x1b[32mOK\x1b[0m done") == "OK done"
    assert "NOPASSWD" in describe_sudo_failure("sudo: a password is required")
    assert describe_sudo_failure("sudo: a terminal is required to read the password") is not None
    assert describe_sudo_failure("Failed to restart x: Interactive authentication required.") is not None
    assert describe_sudo_failure("all good") is None
