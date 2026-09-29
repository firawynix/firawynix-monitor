"""Mudanças seguras: análise de risco/impacto, definição do contêiner, tarefas em
segundo plano e o executor (com um motor simulado)."""

import copy
import json
import os
import shlex
import subprocess
import sys
import time

import pytest

from core import changes
from core.backups import BackupStore, ChangeRecord
from core.change_runner import BackupTarget, ChangeRequest, ChangeRunner, ShellResult
from core.changes import ChangeAction, ChangeContext, ContainerSpec, MountSpec, PortMap, Risk
from core.models import ServiceInfo, ServiceKind, ServiceStatus


def _svc(name, image="nginx:1.27", status=ServiceStatus.ACTIVE, ports="", group="", service="", depends="",
         kind=ServiceKind.DOCKER, sub="Up 2 hours"):
    meta = tuple((k, v) for k, v in (("ports", ports), ("compose_service", service), ("depends_on", depends)) if v)
    state = "running" if status is ServiceStatus.ACTIVE else "exited"
    return ServiceInfo(kind, name, image, status, state, sub, group=group, meta=meta)


def _inspect(name, image="nginx:1.27", *, running=True, ports=None, volumes=(), anon=(), size_rw=None,
             restart="unless-stopped", labels=None, env=("PATH=/usr/bin", "NGINX_VERSION=1.27", "DB_PASSWORD=s3nh@"),
             networks=("shop_default",)):
    mounts = [{"Type": "volume", "Name": v, "Destination": f"/data/{v}", "RW": True} for v in volumes]
    mounts += [{"Type": "volume", "Name": a, "Destination": "/anon", "RW": True} for a in anon]
    bindings = {f"{cp}/tcp": [{"HostIp": "", "HostPort": str(hp)}] for hp, cp in (ports or [])}
    data = {
        "Id": "abc123def4567890" * 4, "Name": f"/{name}", "RestartCount": 0,
        "State": {"Status": "running" if running else "exited", "Running": running, "ExitCode": 0},
        "Config": {"Image": image, "Env": list(env), "Cmd": ["nginx", "-g", "daemon off;"], "Entrypoint": None,
                   "Labels": dict(labels or {}), "Hostname": "abc123def456", "User": "", "WorkingDir": ""},
        "HostConfig": {"PortBindings": bindings, "RestartPolicy": {"Name": restart}, "NetworkMode": networks[0]
                       if networks else "bridge", "Memory": 0, "NanoCpus": 0, "Privileged": False},
        "Mounts": mounts, "NetworkSettings": {"Networks": {n: {} for n in networks}},
    }
    if size_rw is not None:
        data["SizeRw"] = size_rw
    return data


# ---------------------------------------------------------------------------
# Análise de risco e impacto
# ---------------------------------------------------------------------------

def test_stopping_a_reverse_proxy_warns_about_sites_and_requires_saving():
    proxy = _svc("edge-traefik-1", "traefik:v3.1", ports="0.0.0.0:443->443/tcp")
    ctx = ChangeContext(services=(proxy,), endpoints=("https://loja.exemplo.com.br/",), container_admin=True)
    info = changes.parse_inspect(_inspect("edge-traefik-1", "traefik:v3.1", ports=[(443, 443)]))
    result = changes.assess(ChangeAction.STOP, proxy, ctx, inspect=info)
    titles = " | ".join(i.title for i in result.impacts)
    assert result.risk is Risk.HIGH
    assert "Proxy reverso" in titles and "https://loja.exemplo.com.br/ usa a porta 443" in titles
    assert "0.0.0.0:443→443/tcp" in titles
    definition = result.protection("definition")
    assert definition.required and definition.default
    assert result.steps[:3] == ("Conferir o estado atual e as pré-condições",
                                "Salvar a definição do contêiner neste PC", "Parar com desligamento gracioso")


def test_stopping_the_tunnel_that_carries_the_panel_is_critical():
    tunnel = _svc("cloudflared", "cloudflare/cloudflared:2024.9.1")
    ctx = ChangeContext(services=(tunnel,), connector_type="cloudflared", connector_label="Cloudflare Tunnel (ssh.x)")
    result = changes.assess(ChangeAction.STOP, tunnel, ctx)
    assert result.risk is Risk.CRITICAL
    assert "PERDER o acesso" in result.impacts[0].title and "Cloudflare Tunnel" in result.impacts[0].detail


def test_compose_dependents_are_listed():
    db = _svc("shop-db-1", "postgres:16", group="shop", service="db")
    api = _svc("shop-api-1", group="shop", service="api", depends="db:service_healthy:true,redis:service_started:false")
    worker = _svc("shop-worker-1", group="shop", service="worker")
    result = changes.assess(ChangeAction.STOP, db, ChangeContext(services=(db, api, worker)))
    by_area = {i.area: i for i in result.impacts if i.level >= Risk.HIGH}
    assert "shop-api-1" in by_area["Dependências"].title and "shop-worker-1" not in by_area["Dependências"].title
    assert by_area["Dados"].title.startswith("Banco de dados")
    assert result.protection("volumes").available is False  # sem inspect: não sabe dos volumes


def test_database_stop_offers_cold_volume_backup_by_default():
    db = _svc("pg", "postgres:16")
    info = changes.parse_inspect(_inspect("pg", "postgres:16", volumes=("pgdata",)))
    result = changes.assess(ChangeAction.STOP, db, ChangeContext(services=(db,)), inspect=info)
    volumes = result.protection("volumes")
    assert volumes.available and volumes.default and "PARADO" in volumes.detail
    assert result.steps.index("Parar com desligamento gracioso") < result.steps.index(
        "Backup dos volumes com o contêiner parado")


def test_start_detects_port_conflicts_and_stopped_dependencies():
    web = _svc("web", status=ServiceStatus.STOPPED, ports="0.0.0.0:8080->80/tcp", group="site", service="web",
               depends="db:service_started:false", sub="Exited (1) 3 minutes ago")
    other = _svc("other", ports="0.0.0.0:8080->80/tcp")
    db = _svc("site-db", "postgres:16", status=ServiceStatus.STOPPED, group="site", service="db")
    result = changes.assess(ChangeAction.START, web, ChangeContext(services=(web, other, db)))
    assert result.blockers == ("porta 8080 em uso por other",)
    titles = " | ".join(i.title for i in result.impacts)
    assert "Depende de contêineres parados: site-db" in titles and "Parou com erro" in titles


def test_remove_warns_about_data_inside_the_container_and_needs_admin():
    web = _svc("web")
    info = changes.parse_inspect(_inspect("web", size_rw=50 * 1024 ** 2, volumes=("uploads",), anon=("f" * 64,)))
    blocked = changes.assess(ChangeAction.REMOVE, web, ChangeContext(services=(web,)), inspect=info)
    assert any("container_admin" in b for b in blocked.blockers)
    result = changes.assess(ChangeAction.REMOVE, web, ChangeContext(services=(web,), container_admin=True),
                            inspect=info)
    assert not result.blockers and result.risk is Risk.HIGH
    titles = " | ".join(i.title for i in result.impacts)
    assert "50,0 MB gravados DENTRO do contêiner serão perdidos" in titles
    assert "volume(s) anônimo(s)" in titles and "Volumes mantidos: uploads" in titles
    assert result.protection("snapshot").default


def test_cri_containers_are_read_only():
    cri = _svc("coredns-1", kind=ServiceKind.CRI)
    assert "somente leitura" in changes.assess(ChangeAction.STOP, cri, ChangeContext()).blockers[0]


def test_new_container_security_checks():
    spec = ContainerSpec("docker", "tool", "alpine:3.20", privileged=True, network="host",
                         mounts=(MountSpec("bind", "/", "/host"), MountSpec("bind", "/var/run/docker.sock",
                                                                             "/var/run/docker.sock")),
                         ports=(PortMap(80, 8081),))
    existing = _svc("tool")
    result = changes.assess(ChangeAction.CREATE, None, ChangeContext(services=(existing,), container_admin=True),
                            spec=spec)
    assert result.risk is Risk.CRITICAL
    titles = " | ".join(i.title for i in result.impacts)
    assert "--privileged" in titles and "Monta / do host" in titles and "socket do motor" in titles
    assert "já existe um contêiner chamado tool" in result.blockers


def test_container_roles():
    assert changes.container_role("docker.io/library/postgres:16-alpine") == "banco"
    assert changes.container_role("jc21/nginx-proxy-manager:latest") == "proxy"
    assert changes.container_role("cloudflare/cloudflared:latest") == "acesso"
    assert changes.container_role("portainer/portainer-ce:2.21.3") == "painel"
    assert changes.container_role("ghcr.io/acme/shop-api:2.14.1") == ""


# ---------------------------------------------------------------------------
# Definição do contêiner
# ---------------------------------------------------------------------------

def test_spec_from_inspect_round_trip_skips_what_comes_from_the_image():
    data = _inspect("shop-api-1", ports=[(8080, 80)], volumes=("uploads",), restart="always",
                    labels={"com.docker.compose.project": "shop", "maintainer": "nginx"},
                    networks=("shop_default", "monitoring"))
    data["HostConfig"]["ExtraHosts"] = ["db.local:10.0.0.9"]
    data["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/fuse"}]
    image = {"Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27"], "Cmd": ["nginx", "-g", "daemon off;"],
             "Labels": {"maintainer": "nginx"}}
    spec = changes.spec_from_inspect(data, "docker", image)
    assert spec.env == (("DB_PASSWORD", "s3nh@"),) and spec.command == () and spec.hostname == ""
    assert spec.labels == (("com.docker.compose.project", "shop"),)
    assert (spec.network, spec.extra_networks, spec.restart) == ("shop_default", ("monitoring",), "always")
    assert "dispositivos não são recriados" in spec.notes
    args = changes.run_args(spec)
    assert args[:4] == ["run", "-d", "--name", "shop-api-1"]
    assert args[args.index("-p"):args.index("-p") + 2] == ["-p", "8080:80"]
    assert "uploads:/data/uploads" in args and "--add-host" in args and args[-1] == "nginx:1.27"
    masked = changes.masked_args(args)
    assert "DB_PASSWORD=<oculto>" in masked and "DB_PASSWORD=s3nh@" not in masked


@pytest.mark.parametrize("bad", [
    {"name": "x; rm -rf /"}, {"image": "nginx:1.27 && reboot"}, {"env": (("A B", "1"),)},
    {"mounts": (MountSpec("bind", "relativo", "/data"),)}, {"mounts": (MountSpec("bind", "/srv/../etc", "/x"),)},
    {"mounts": (MountSpec("volume", "a/b", "/x"),)}, {"network": "rede $(id)"}, {"memory": "512m; ls"},
    {"restart": "sempre"}, {"ports": (PortMap(80, 70000),)}, {"extra_hosts": ("x:not-an-ip",)},
    {"user": "root; id"}, {"engine": "cri"},
])
def test_spec_validation_rejects_injection(bad):
    spec = ContainerSpec(**{"engine": "docker", "name": "ok", "image": "nginx:1.27", **bad})
    with pytest.raises(ValueError):
        changes.run_args(spec)


def test_run_args_are_quoted_for_the_shell():
    spec = ContainerSpec("docker", "web", "nginx:1.27", env=(("MOTD", "olá $(whoami); `id`"),),
                         command=("sh", "-c", "echo 'oi' && sleep 1"))
    command = changes.shell_join("sudo -n docker", changes.run_args(spec))
    assert shlex.split(command)[-3:] == ["sh", "-c", "echo 'oi' && sleep 1"]
    assert "MOTD=olá $(whoami); `id`" in shlex.split(command)


# ---------------------------------------------------------------------------
# Tarefas em segundo plano (sh real)
# ---------------------------------------------------------------------------

@pytest.mark.posix_shell
def test_background_job_survives_and_reports_exit_code(tmp_path):
    env = {"HOME": str(tmp_path), "PATH": os.environ["PATH"]}
    job = "fwx-20260929-120000-stop-ab12"
    start = subprocess.run(["sh", "-c", changes.build_job_start(job, "sleep 0.3; echo feito; exit 3")],
                           capture_output=True, text=True, env=env, timeout=5)
    assert start.stdout.strip() == "started"
    first = changes.parse_job_poll(subprocess.run(["sh", "-c", changes.build_job_poll(job)], capture_output=True,
                                                  text=True, env=env).stdout)
    assert not first.done
    for _ in range(50):
        state = changes.parse_job_poll(subprocess.run(["sh", "-c", changes.build_job_poll(job)],
                                                      capture_output=True, text=True, env=env).stdout)
        if state.done:
            break
        time.sleep(0.05)
    assert (state.done, state.exit_code, state.log) == (True, 3, "feito")
    subprocess.run(["sh", "-c", changes.build_job_cleanup(job)], env=env)
    missing = changes.parse_job_poll(subprocess.run(["sh", "-c", changes.build_job_poll(job)],
                                                    capture_output=True, text=True, env=env).stdout)
    assert missing.missing
    with pytest.raises(ValueError):
        changes.build_job_start("../../etc", "true")


def test_volume_backup_command_is_read_only_and_offline():
    args = changes.volume_backup_args("pgdata", "/home/monitor/firawynix-backups",
                                      changes.backup_file_name("pg", "pgdata", "20260929-120000"), "1001:1001")
    assert args[:4] == ["run", "--rm", "--network", "none"] and "pgdata:/data:ro" in args
    assert args[-1].startswith("tar czf /backup/pg_pgdata_20260929-120000.tar.gz -C /data .")
    assert args[-1].endswith("chown 1001:1001 /backup/pg_pgdata_20260929-120000.tar.gz")
    with pytest.raises(ValueError):
        changes.volume_backup_args("x;rm", "/b", "f.tar.gz")


def test_state_from_inspect_handles_every_engine():
    assert changes.state_from_inspect({"State": {"Status": "running", "ExitCode": 0,
                                                 "Health": {"Status": "healthy"}}, "RestartCount": 2}) == \
        changes.ContainerState("running", 0, 2, "healthy")
    assert changes.state_from_inspect({"State": {"Running": False, "Paused": True}}).status == "paused"
    assert changes.state_from_inspect(None) is None


# ---------------------------------------------------------------------------
# Executor com motor simulado
# ---------------------------------------------------------------------------

class FakeEngine:
    def __init__(self):
        self.containers: dict[str, dict] = {}
        self.images = {"nginx:1.27": {"Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27"],
                                      "Cmd": ["nginx", "-g", "daemon off;"]},
                       "docker.io/library/alpine:3.20": {}}
        self.jobs = {}
        self.commands: list[list[str]] = []
        self.fail_backup = False
        self.crash_on_start: set[str] = set()

    def executable(self, engine):
        return engine

    def inspect(self, engine, name):
        data = self.containers.get(name)
        return copy.deepcopy(data) if data else None

    def image_config(self, engine, image):
        return self.images.get(image)

    def exec(self, engine, args):
        return self._do(list(args))

    def start_job(self, job_id, command):
        argv = shlex.split(command)
        result = self._do(argv[1:])
        self.jobs[job_id] = changes.JobState(True, 0 if result.ok else 1, result.output)
        return ShellResult(True, "started")

    def poll_job(self, job_id):
        return self.jobs[job_id]

    def cleanup_job(self, job_id):
        self.jobs.pop(job_id)

    def file_size(self, path):
        return 4096

    def logs_tail(self, engine, name, lines=20):
        return "iniciando\nFATAL: arquivo de configuração inválido"

    def backup_target(self, engine):
        return BackupTarget(directory="/home/monitor/firawynix-backups", owner="1001:1001")

    def _state(self, name, status, code=0):
        state = self.containers[name]["State"]
        state.update(Status=status, Running=status == "running", ExitCode=code)

    def _do(self, args):
        self.commands.append(args)
        op, name = args[0], args[-1]
        if op == "stop":
            self._state(name, "exited")
        elif op in ("start", "restart", "unpause"):
            self._state(name, "exited", 1) if name in self.crash_on_start else self._state(name, "running")
        elif op == "pause":
            self._state(name, "paused")
        elif op == "rm":
            if self.containers[name]["State"]["Running"]:
                return ShellResult(False, "cannot remove a running container")
            del self.containers[name]
        elif op == "commit":
            self.images[args[2]] = {}
        elif op == "pull":
            self.images[name] = {}
        elif op == "run" and "--rm" in args:
            if self.fail_backup:
                return ShellResult(False, "tar: /data: Permission denied")
        elif op == "run":
            new = args[args.index("--name") + 1]
            image = next(a for a in args if a in self.images)
            self.containers[new] = _inspect(new, image)
            if new in self.crash_on_start:
                self._state(new, "exited", 1)
        return ShellResult(True, "ok")


def _run(engine, action, *, service=None, spec=None, protections=(), store=None, record=None, snapshot=False,
         service_status=ServiceStatus.ACTIVE):
    store = store or BackupStore(None)
    service = service or (_svc("web", status=service_status) if spec is None else None)
    events = []
    request = ChangeRequest(id="20260929-120000-" + action.value + "-ab12", server="srv", action=action,
                            engine="docker", name=spec.name if spec else service.name, service=service, spec=spec,
                            protections=frozenset(protections), source_record=record, use_snapshot=snapshot,
                            steps=changes.plan_steps(action, (), service, protections))
    runner = ChangeRunner(engine, store, events.append, request, sleep=lambda s: None)
    return runner.run(), events, store


def test_runner_handles_every_planned_step():
    runner = ChangeRunner(FakeEngine(), BackupStore(None), lambda e: None,
                          ChangeRequest(id="x", server="s", action=ChangeAction.STOP, engine="docker", name="web"))
    for action in ChangeAction:
        for chosen in ((), ("definition",), ("definition", "snapshot", "volumes")):
            for status in (ServiceStatus.ACTIVE, ServiceStatus.STOPPED):
                for label in changes.plan_steps(action, (), _svc("web", status=status), chosen):
                    assert label in runner._handlers, label


def test_stop_with_definition_and_cold_volume_backup(tmp_path):
    engine = FakeEngine()
    engine.containers["web"] = _inspect("web", volumes=("uploads",))
    store = BackupStore(tmp_path)
    record, events, _ = _run(engine, ChangeAction.STOP, protections=("definition", "volumes"), store=store)
    assert record.outcome == "ok", record.steps
    ops = [c[0] for c in engine.commands]
    assert ops.index("stop") < ops.index("run")  # backup só com o contêiner parado
    assert engine.containers["web"]["State"]["Status"] == "exited"
    assert record.volume_backups == ["/home/monitor/firawynix-backups/web_uploads_20260929-120000.tar.gz (4,0 KB)"]
    definition = next(tmp_path.rglob("inspect.json")) if sys.platform != "win32" else None
    if definition is not None:
        assert oct(definition.stat().st_mode & 0o777) == "0o600"
    text = next(tmp_path.rglob("recriar.txt")).read_text(encoding="utf-8")
    assert "DB_PASSWORD=<oculto>" in text and "s3nh@" not in text
    assert events[0].steps == record_steps(record) and events[-1].finished and events[-1].outcome == "ok"
    assert [r.id for r in store.records()] == [record.id] and store.records()[0].outcome == "ok"
    assert store.load_definition(store.records()[0])["Name"] == "/web"


def record_steps(record):
    return tuple(label for label, _status, _message in record.steps)


def test_stop_of_already_stopped_container_does_nothing():
    engine = FakeEngine()
    engine.containers["web"] = _inspect("web", running=False)
    record, _events, _ = _run(engine, ChangeAction.STOP, protections=("definition",))
    assert record.outcome == "ok" and engine.commands == []
    assert [s for _l, s, _m in record.steps] == ["ok", "skipped", "skipped", "skipped", "ok"]


def test_remove_is_cancelled_when_the_backup_fails():
    engine = FakeEngine()
    engine.fail_backup = True
    engine.containers["web"] = _inspect("web", volumes=("uploads",))
    record, _events, _ = _run(engine, ChangeAction.REMOVE, protections=("definition", "snapshot", "volumes"))
    assert record.outcome == "error"
    assert "web" in engine.containers  # NÃO removido
    assert engine.containers["web"]["State"]["Status"] == "exited"
    failed = next(m for _l, s, m in record.steps if s == "error")
    assert "remoção cancelada" in failed and "Permission denied" in failed
    assert record.snapshot_image == "firawynix/backup-web:20260929-120000"


def test_remove_then_restore_from_the_saved_definition():
    engine = FakeEngine()
    engine.containers["web"] = _inspect("web", ports=[(8080, 80)])
    store = BackupStore(None)
    removed, _events, _ = _run(engine, ChangeAction.REMOVE, protections=("definition",), store=store)
    assert removed.outcome == "ok" and "web" not in engine.containers
    definition = store.load_definition(removed)
    spec = changes.spec_from_inspect(definition, "docker", engine.images["nginx:1.27"])
    restored, _events, _ = _run(engine, ChangeAction.RESTORE, spec=spec, record=removed, store=store)
    assert restored.outcome == "ok", restored.steps
    run = next(c for c in engine.commands if c[0] == "run")
    assert run[run.index("-p") + 1] == "8080:80" and "DB_PASSWORD=s3nh@" in run
    assert engine.containers["web"]["State"]["Status"] == "running"


def test_start_that_crashes_reports_the_log():
    engine = FakeEngine()
    engine.containers["web"] = _inspect("web", running=False)
    engine.crash_on_start.add("web")
    record, _events, _ = _run(engine, ChangeAction.START, service_status=ServiceStatus.STOPPED)
    assert record.outcome == "error"
    assert "arquivo de configuração inválido" in record.message


def test_create_pulls_the_image_and_confirms_it_runs():
    engine = FakeEngine()
    spec = ContainerSpec("docker", "cache", "redis:7.4", ports=(PortMap(6379, 6379, "127.0.0.1"),))
    record, events, _ = _run(engine, ChangeAction.CREATE, spec=spec)
    assert record.outcome == "ok", record.steps
    assert [c[0] for c in engine.commands] == ["pull", "run"]
    assert engine.containers["cache"]["State"]["Status"] == "running"
    assert record_steps(record) == changes.plan_steps(ChangeAction.CREATE, (), None)


def test_restart_with_volume_backup_ends_running_even_if_backup_fails():
    engine = FakeEngine()
    engine.fail_backup = True
    engine.containers["web"] = _inspect("web", volumes=("uploads",))
    record, _events, _ = _run(engine, ChangeAction.RESTART, protections=("definition", "volumes"))
    assert record.outcome == "warning"
    assert engine.containers["web"]["State"]["Status"] == "running"


def test_change_record_serialization():
    record = ChangeRecord(id="a", time=1.0, server="s", target="t", engine="docker", action="stop", risk="alto",
                          steps=[("Parar", "ok", "parado")])
    again = ChangeRecord.from_dict(json.loads(json.dumps(record.__dict__)))
    assert again == record and again.restorable is False


def test_new_container_form_parsers():
    ports = changes.parse_ports("8080:80, 127.0.0.1:5432:5432/tcp\n53:53/udp, 9000")
    assert [p.arg() for p in ports] == ["8080:80", "127.0.0.1:5432:5432", "53:53/udp", "9000"]
    assert changes.parse_ports("[::1]:8443:443")[0].host_ip == "::1"
    with pytest.raises(ValueError):
        changes.parse_ports("80:80:80:80")
    assert changes.parse_env("# comentário\nTZ=America/Sao_Paulo\nURL=postgres://u:p@db/x?a=b\n") == (
        ("TZ", "America/Sao_Paulo"), ("URL", "postgres://u:p@db/x?a=b"))
    with pytest.raises(ValueError):
        changes.parse_env("SEM_IGUAL")
    mounts = changes.parse_mounts("dados:/var/lib/app, /srv/site:/usr/share/nginx/html:ro")
    assert mounts == (MountSpec("volume", "dados", "/var/lib/app"),
                      MountSpec("bind", "/srv/site", "/usr/share/nginx/html", True))
    with pytest.raises(ValueError):
        changes.parse_mounts("/só-origem")
    assert changes.parse_command('sh -c "echo oi && sleep 1"') == ("sh", "-c", "echo oi && sleep 1")


def test_systemd_unit_impacts():
    stop_ssh = changes.unit_impacts("ssh.service", "stop")
    assert stop_ssh[0].level is Risk.CRITICAL and "perdem o acesso" in stop_ssh[0].title
    assert changes.unit_impacts("ssh.service", "restart")[0].level is Risk.HIGH
    assert changes.unit_impacts("cloudflared.service", "stop", "cloudflared")[0].level is Risk.CRITICAL
    assert changes.unit_impacts("cloudflared.service", "stop", "direct")[0].level is Risk.HIGH
    assert changes.unit_impacts("postgresql@16-main.service", "stop")[0].area == "Dados"
    assert changes.unit_impacts("docker.service", "restart")[0].level is Risk.MEDIUM
    assert changes.unit_impacts("nginx.service", "start") == []
    assert changes.unit_impacts("meu-app.service", "stop") == []
