"""Testes dos construtores de comando: formato exato e resistência a injeção."""

import shlex
import subprocess

import pytest

from core import commands as cmd
from core.models import ServiceAction


def test_unit_commands_use_non_interactive_sudo_and_no_block():
    assert (cmd.build_unit_action_command("nginx.service", ServiceAction.RESTART, True)
            == "sudo -n systemctl --no-block restart nginx.service")
    assert (cmd.build_unit_action_command("apt-daily.timer", ServiceAction.STOP, False)
            == "systemctl --no-block stop apt-daily.timer")
    assert cmd.build_journal_command("nginx.service", 50, False) == "journalctl -u nginx.service -n 50 --no-pager"
    assert (cmd.build_list_units_command(("service", "timer", "bogus"), True)
            == "systemctl list-units --type=service,timer --all --no-pager --output=json")


def test_container_commands():
    assert cmd.build_container_action_command("docker", ["web"], ServiceAction.STOP, False) == "docker stop -t 3 web"
    assert (cmd.build_container_action_command("podman", ["a", "b"], ServiceAction.START, True)
            == "sudo -n podman start a b")
    assert (cmd.build_container_logs_command("docker", "web", 100, False)
            == "docker logs --tail 100 --timestamps web 2>&1")
    assert cmd.build_container_ps_command("podman", False) == "podman ps -a --format json"
    assert "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}" in cmd.build_container_stats_command("docker", False)
    stack_logs = cmd.build_stack_logs_command("docker", ["a", "b"], 20, False)
    assert stack_logs.count("docker logs --tail 20") == 2
    with pytest.raises(ValueError):
        cmd.build_container_action_command("docker", [], ServiceAction.STOP, False)
    with pytest.raises(ValueError):
        cmd.build_container_ps_command("lxc", False)


def test_kubernetes_and_libvirt_commands():
    pods = cmd.build_pods_command("k3s kubectl", True)
    assert pods.startswith("sudo -n k3s kubectl get pods -A --no-headers --request-timeout=4s -o 'custom-columns=")
    assert (cmd.build_pod_restart_command("kubectl", "prod/web-0", False)
            == "kubectl delete pod -n prod web-0 --wait=false --request-timeout=4s")
    assert "logs -n prod web-0 --tail=50" in cmd.build_pod_logs_command("kubectl", "prod/web-0", 50, False)
    assert cmd.build_vm_list_command("qemu:///system", False) == "virsh -c qemu:///system -q list --all"
    assert (cmd.build_vm_action_command("qemu:///system", "db01", ServiceAction.STOP, True)
            == "sudo -n virsh -c qemu:///system shutdown db01")
    assert "reboot db01" in cmd.build_vm_action_command("qemu:///system", "db01", ServiceAction.RESTART, False)


def test_kill_command_validates_pid():
    assert cmd.build_kill_command(1234, False, False) == "kill -TERM 1234"
    assert cmd.build_kill_command(1234, True, True) == "sudo -n kill -KILL 1234"
    for pid in (0, 1, -5, True, "12"):
        with pytest.raises(ValueError):
            cmd.build_kill_command(pid, False, False)


def test_escaped_unit_names_are_quoted():
    unit = r"systemd-fsck@dev-disk-by\x2duuid-1234.service"
    assert cmd.validate_unit_name(unit) == unit
    assert cmd.build_journal_command(unit, 10, False) == f"journalctl -u '{unit}' -n 10 --no-pager"


@pytest.mark.parametrize("name", [
    "nginx; rm -rf /", "$(id)", "`id`", "-H", "--root=/tmp", "a b", "", "nginx|cat", "x\ny", "nginx\n",
])
def test_command_injection_is_rejected(name):
    with pytest.raises(ValueError):
        cmd.build_unit_action_command(name, ServiceAction.RESTART, True)
    with pytest.raises(ValueError):
        cmd.build_container_logs_command("docker", name, 10, False)
    with pytest.raises(ValueError):
        cmd.build_vm_action_command("qemu:///system", name, ServiceAction.START, False)
    with pytest.raises(ValueError):
        cmd.build_pod_restart_command("kubectl", f"prod/{name}", False)


@pytest.mark.parametrize("value", ["kubectl; id", "$(id)", "kubectl --kubeconfig x", "a b c"])
def test_kubectl_command_validation(value):
    with pytest.raises(ValueError):
        cmd.validate_kubectl_command(value)


def test_libvirt_uri_validation():
    assert cmd.validate_libvirt_uri("qemu+ssh://root@hv/system") == "qemu+ssh://root@hv/system"
    with pytest.raises(ValueError):
        cmd.validate_libvirt_uri("qemu:///system; id")


def test_wrap_remote_command_forces_c_locale_and_quotes():
    wrapped = cmd.wrap_remote_command("echo 'a' && df -kP")
    assert wrapped.startswith("env LC_ALL=C LANG=C sh -c ")
    assert shlex.split(wrapped)[-1] == "echo 'a' && df -kP"


def test_metrics_command_samples_cpu_twice_only_on_first_poll():
    assert cmd.build_metrics_command(True).count("/proc/stat") == 2
    assert cmd.build_metrics_command(False).count("/proc/stat") == 1
    assert cmd.build_metrics_command(False).count(cmd.SECTION) == 7


@pytest.mark.parametrize("command", [
    cmd.SYSTEM_INFO_CMD, cmd.CRON_CMD, cmd.UPDATES_CMD, cmd.CGROUP_SERVICES_CMD, cmd.TIMERS_CMD,
    cmd.SSH_FAILURES_CMD, cmd.build_metrics_command(True), cmd.build_processes_command(True),
    cmd.build_ports_command(True), cmd.build_pods_command("kubectl", False), cmd.build_events_command("err", 100, 24),
    cmd.build_stack_logs_command("podman", ["a", "b"], 10, True), cmd.build_vm_info_command("qemu:///system", "x", 0),
])
def test_composite_commands_are_valid_posix_shell(command):
    result = subprocess.run(["sh", "-n", "-c", cmd.wrap_remote_command(command)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
