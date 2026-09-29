"""Camada única de motores: auto-detecção, parsers de cada motor, inventário,
painéis de terceiros, verificação de atualizações e comandos."""

import json
import subprocess

import pytest

from config.settings import ServerConfig
from core import commands as cmd
from core import containers as eng
from core.commands import SECTION
from core.models import (
    ContainerImage,
    RuntimeResult,
    RuntimeState,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
)
from core.parsers import classify_runtime_error, parse_docker_ps, parse_podman_ps

DISCOVERY = """bin|docker|/usr/bin/docker|Docker version 27.3.1, build ce12230
bin|podman|/usr/bin/podman|podman version 5.2.2
bin|nerdctl|/usr/local/bin/nerdctl|nerdctl version 2.0.0
bin|crictl|/usr/local/bin/crictl|crictl version v1.31.0
bin|buildah|/usr/bin/buildah|buildah version 1.37.3 (image-spec 1.1.0, runtime-spec 1.2.0)
bin|skopeo|/usr/bin/skopeo|skopeo version 1.16.1
bin|lxc|/snap/bin/lxc|5.21.2 LTS
bin|kubectl|/usr/local/bin/kubectl|Client Version: v1.31.0
bin|k3s|/usr/local/bin/k3s|k3s version v1.30.4+k3s1 (98262b5d)
compose|docker|2.29.7
rootless|podman|true
svc|docker|active
svc|cockpit.socket|active
svc|portainer|inactive
"""


def test_parse_discovery_versions_and_engines():
    discovery = eng.parse_discovery(DISCOVERY)
    versions = {k: v.version for k, v in discovery.tools.items()}
    assert versions == {"docker": "27.3.1", "podman": "5.2.2", "nerdctl": "2.0.0", "crictl": "1.31.0",
                        "buildah": "1.37.3", "skopeo": "1.16.1", "lxc": "5.21.2", "kubectl": "1.31.0",
                        "k3s": "1.30.4+k3s1"}
    assert all(discovery.has(e) for e in eng.ENGINE_ORDER)
    assert discovery.tool_for("lxd").id == "lxc" and discovery.tool_for("cri").id == "crictl"
    assert discovery.compose == {"docker": "2.29.7"} and discovery.rootless == {"podman": True}
    assert discovery.services["cockpit.socket"] == "active"
    empty = eng.parse_discovery("svc|docker|\n")
    assert not empty.has("docker") and empty.tool_for("podman") is None


def test_discovery_command_runs_in_a_real_shell():
    result = subprocess.run(["sh", "-c", cmd.wrap_remote_command(eng.DISCOVERY_CMD)], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0
    parsed = eng.parse_discovery(result.stdout)
    assert set(parsed.services) == {"docker", "containerd", "crio", "podman.socket", "cockpit.socket", "portainer"}


# ---------------------------------------------------------------------------
# Contêineres de todos os motores → o mesmo modelo
# ---------------------------------------------------------------------------

NERDCTL_PS = json.dumps({"Command": "\"/docker-entrypoint.sh nginx\"", "CreatedAt": "2026-09-29 10:00:00 +0000 UTC",
                         "ID": "0a1b2c3d4e5f", "Image": "docker.io/library/nginx:alpine", "Names": "web",
                         "Ports": "0.0.0.0:8080->80/tcp", "Status": "Up 2 hours",
                         "Labels": "com.docker.compose.project=site,com.docker.compose.service=web"})

CRICTL_PS = json.dumps({"containers": [
    {"id": "4f2a9c8e1b3d7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f", "podSandboxId": "x",
     "metadata": {"name": "api", "attempt": 3}, "image": {"image": "registry.k8s.io/api:1.2"},
     "imageRef": "sha256:abc", "state": "CONTAINER_RUNNING", "createdAt": "1727600000000000000",
     "labels": {"io.kubernetes.pod.name": "api-7d9f", "io.kubernetes.pod.namespace": "prod"}},
    {"id": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f4f2a9c8e1b3d7a6f5e4d3c2b1a0f", "podSandboxId": "y",
     "metadata": {"name": "migrate", "attempt": 0}, "image": {"image": "app:1"}, "state": "CONTAINER_EXITED",
     "labels": {}},
]})


def test_nerdctl_uses_docker_parser_with_its_own_kind():
    (web,) = parse_docker_ps(NERDCTL_PS, ServiceKind.NERDCTL)
    assert (web.kind, web.status, web.group, web.meta_value("ports")) == (
        ServiceKind.NERDCTL, ServiceStatus.ACTIVE, "site", "0.0.0.0:8080->80/tcp")
    assert web.kind.is_container and web.kind.manageable and web.type_label == "containerd"


def test_nerdctl_real_output_without_state_field():
    """nerdctl 2.x não tem .State: o estado vem do Status ("Up", "Paused", "Created", "Exited (2) …")."""
    rows = [
        {"Command": "\"sleep 100000\"", "ID": "12e8aca90171", "Image": "docker.io/library/alpine:3.20",
         "Names": "site-web", "Ports": "", "Status": "Up", "Labels": "com.docker.compose.project=site"},
        {"ID": "12e8aca90172", "Image": "docker.io/library/alpine:3.20", "Names": "site-paused", "Status": "Paused",
         "Labels": ""},
        {"ID": "12e8aca90173", "Image": "docker.io/library/alpine:3.20", "Names": "site-new", "Status": "Created",
         "Labels": ""},
        {"ID": "166806ba4492", "Image": "docker.io/library/alpine:3.20", "Names": "site-job",
         "Status": "Exited (2) 1 second ago", "Labels": "nerdctl/networks=[\"none\"]"},
    ]
    output = "\n".join(json.dumps(r) for r in rows)
    web, paused, new, job = parse_docker_ps(output, ServiceKind.NERDCTL)
    assert (web.active_state, web.status, web.group) == ("running", ServiceStatus.ACTIVE, "site")
    assert (paused.active_state, paused.status) == ("paused", ServiceStatus.STOPPED)
    assert (new.active_state, new.status) == ("created", ServiceStatus.STOPPED)
    assert (job.active_state, job.status) == ("exited", ServiceStatus.FAILED)


def test_podman_ports_and_image_id_meta():
    output = json.dumps([{"Names": ["db"], "Id": "f00dcafe1234567", "ImageID": "abcdef1234567890",
                          "Image": "docker.io/library/postgres:16", "State": "running", "Status": "Up 1 hour",
                          "Ports": [{"host_ip": "", "container_port": 5432, "host_port": 5433, "range": 1,
                                     "protocol": "tcp"}, {"container_port": 9187, "protocol": "tcp"}]}])
    (db,) = parse_podman_ps(output)
    assert db.meta_value("ports") == "0.0.0.0:5433->5432/tcp, 9187/tcp"
    assert db.meta_value("image_id") == "abcdef123456" and db.meta_value("id") == "f00dcafe1234"


def test_crictl_containers_are_read_only():
    api, migrate = eng.parse_crictl_ps(CRICTL_PS)
    assert (api.kind, api.status, api.description) == (ServiceKind.CRI, ServiceStatus.ACTIVE, "registry.k8s.io/api:1.2")
    assert api.name == "api-4f2a9c8e" and "pod prod/api-7d9f" in api.sub_state and "3 reinício" in api.sub_state
    assert migrate.status is ServiceStatus.STOPPED
    assert api.kind.is_container and not api.kind.manageable
    from core.models import ServiceAction

    assert not any(api.supports(action) for action in ServiceAction)
    assert eng.parse_crictl_ps("") == []
    with pytest.raises(ValueError):
        eng.parse_crictl_ps('{"x": 1}')


@pytest.mark.parametrize(("kind", "output", "state"), [
    (ServiceKind.NERDCTL, "time=... level=fatal msg=\"cannot access containerd socket \\\"/run/containerd/"
                          "containerd.sock\\\": permission denied\"", RuntimeState.PERMISSION),
    (ServiceKind.CRI, "validate service connection: validate CRI v1 runtime API for endpoint "
                      "\"unix:///run/containerd/containerd.sock\": rpc error: connect: no such file or directory",
     RuntimeState.DAEMON_DOWN),
    (ServiceKind.CRI, "crictl: command not found", RuntimeState.NOT_INSTALLED),
])
def test_runtime_errors_for_new_engines(kind, output, state):
    assert classify_runtime_error(kind, 1 if "not found" not in output else 127, output)[0] is state


# ---------------------------------------------------------------------------
# Inventário: imagens, volumes, redes, uso de disco, Buildah
# ---------------------------------------------------------------------------

DOCKER_IMAGES = "\n".join(json.dumps(d) for d in [
    {"Containers": "N/A", "CreatedSince": "3 weeks ago", "Digest": "sha256:" + "a" * 64, "ID": "a1b2c3d4e5f6",
     "Repository": "nginx", "Size": "188MB", "Tag": "1.27"},
    {"CreatedSince": "2 months ago", "Digest": "<none>", "ID": "0f0f0f0f0f0f", "Repository": "<none>",
     "Size": "95.1MB", "Tag": "<none>"},
    {"CreatedSince": "1 day ago", "Digest": "sha256:" + "b" * 64, "ID": "b2c3d4e5f6a7", "Repository": "redis",
     "Size": "41.2MB", "Tag": "7"},
])
DOCKER_VOLUMES = "\n".join(json.dumps(d) for d in [
    {"Driver": "local", "Labels": "com.docker.compose.project=shop,com.docker.compose.volume=data",
     "Mountpoint": "/var/lib/docker/volumes/shop_data/_data", "Name": "shop_data", "Scope": "local"},
    {"Driver": "local", "Labels": "", "Name": "old_cache", "Scope": "local"},
])
DOCKER_NETWORKS = "\n".join(json.dumps(d) for d in [
    {"Driver": "bridge", "ID": "f1e2d3c4b5a6", "Internal": "false", "Name": "bridge", "Scope": "local"},
    {"Driver": "bridge", "ID": "0a0b0c0d0e0f", "Internal": "true", "Name": "shop_backend", "Scope": "local"},
])
DOCKER_DF = "\n".join(json.dumps(d) for d in [
    {"Active": "2", "Reclaimable": "95.1MB (29%)", "Size": "324.3MB", "TotalCount": "3", "Type": "Images"},
    {"Active": "1", "Reclaimable": "0B", "Size": "1.2GB", "TotalCount": "2", "Type": "Local Volumes"},
])


def _inventory_output(images, volumes, dangling, networks, details="", disk=""):
    return f"\n{SECTION}\n".join([images, volumes, dangling, networks, details, disk])


def test_docker_inventory():
    data = eng.parse_engine_inventory("docker", _inventory_output(
        DOCKER_IMAGES, DOCKER_VOLUMES, "#OK\nold_cache", DOCKER_NETWORKS,
        "bridge|172.17.0.0/16 |3\nshop_backend|172.20.0.0/16 |2", DOCKER_DF))
    nginx, orphan, redis = data.images
    assert (nginx.reference, nginx.size_bytes) == ("nginx:1.27", 188_000_000)
    assert nginx.digests == ("nginx@sha256:" + "a" * 64,)
    assert orphan.dangling and orphan.reference == "0f0f0f0f0f0f" and redis.tag == "7"
    shop, old = data.volumes
    assert (shop.stack, shop.in_use, shop.mountpoint) == ("shop", True, "/var/lib/docker/volumes/shop_data/_data")
    assert old.in_use is False
    bridge, backend = data.networks
    assert (bridge.subnets, bridge.containers, backend.internal) == (("172.17.0.0/16",), 3, True)
    assert [(d.kind, d.total, d.active, d.reclaimable) for d in data.disk] == [
        ("Images", 3, 2, "95.1MB (29%)"), ("Local Volumes", 2, 1, "0B")]


def test_volume_usage_unknown_when_filter_unsupported():
    data = eng.parse_engine_inventory("nerdctl", _inventory_output("", DOCKER_VOLUMES, "", ""))
    assert [v.in_use for v in data.volumes] == [None, None]


PODMAN_IMAGES = json.dumps([
    {"Id": "d" * 64, "Names": ["docker.io/library/postgres:16"], "RepoDigests":
        ["docker.io/library/postgres@sha256:" + "c" * 64], "Size": 432_000_000, "Containers": 1,
     "CreatedAt": "2026-09-01T10:00:00Z"},
    {"Id": "e" * 64, "Names": [], "Size": 1000, "Containers": 0},
])
PODMAN_NETWORKS = json.dumps([{"name": "podman", "driver": "bridge", "subnets": [{"subnet": "10.88.0.0/16"}],
                               "internal": False, "id": "2f25"}])


def test_podman_inventory_with_json_arrays():
    data = eng.parse_engine_inventory("podman", _inventory_output(
        PODMAN_IMAGES, json.dumps([{"Name": "pgdata", "Driver": "local", "Labels": {}}]), "#OK\n", PODMAN_NETWORKS,
        "", json.dumps([{"Type": "Images", "Total": 2, "Active": 1, "Size": "432MB", "Reclaimable": "1kB (0%)"}])))
    postgres, orphan = data.images
    assert (postgres.repository, postgres.tag, postgres.in_use) == ("docker.io/library/postgres", "16", True)
    assert orphan.dangling and orphan.in_use is False
    assert data.volumes[0].in_use is True and data.networks[0].subnets == ("10.88.0.0/16",)
    assert data.disk[0].total == 2


def test_crictl_images_and_buildah():
    images = eng.parse_images("cri", json.dumps({"images": [
        {"id": "sha256:" + "1" * 64, "repoTags": ["registry.k8s.io/pause:3.9"], "repoDigests": [], "size": "321000"}]}))
    assert (images[0].reference, images[0].size_bytes) == ("registry.k8s.io/pause:3.9", 321000)
    builds, buildah_images = eng.parse_buildah(f"""[{{"id": "{"9" * 64}", "builder": true, "imageid": "x",
"imagename": "docker.io/library/alpine:latest", "containername": "alpine-working-container"}}]
{SECTION}
[{{"id": "{"8" * 64}", "names": ["localhost/app:dev"], "digest": "sha256:{"7" * 64}", "size": "5.6 MB",
"createdat": "2026-09-29 10:00:00 +0000 UTC"}}]""")
    assert builds[0].name == "alpine-working-container" and builds[0].image.endswith("alpine:latest")
    assert buildah_images[0].reference == "localhost/app:dev" and buildah_images[0].size_bytes == 5_600_000


def test_build_inventory_marks_usage_detects_tools_and_merges_engines():
    server = ServerConfig(name="s", host="10.0.0.5", username="u", podman="on", nerdctl="off")
    discovery = eng.parse_discovery(DISCOVERY)
    web = ServiceInfo(ServiceKind.DOCKER, "shop-web-1", "nginx:1.27", ServiceStatus.ACTIVE, "running", "Up")
    portainer = ServiceInfo(ServiceKind.DOCKER, "portainer", "portainer/portainer-ce:2.21.3", ServiceStatus.ACTIVE,
                            "running", "Up", meta=(("ports", "0.0.0.0:9443->9443/tcp, 0.0.0.0:8000->8000/tcp"),))
    tower = ServiceInfo(ServiceKind.PODMAN, "watchtower", "docker.io/containrrr/watchtower:latest",
                        ServiceStatus.ACTIVE, "running", "Up")
    docker_data = eng.parse_engine_inventory("docker", _inventory_output(DOCKER_IMAGES, "", "", ""))
    runtimes = {ServiceKind.DOCKER: RuntimeResult(ServiceKind.DOCKER, RuntimeState.OK, (web, portainer)),
                ServiceKind.PODMAN: RuntimeResult(ServiceKind.PODMAN, RuntimeState.OK, (tower,)),
                ServiceKind.CRI: RuntimeResult(ServiceKind.CRI, RuntimeState.PERMISSION, (), "sem permissão")}
    inventory = eng.build_inventory(server, discovery, runtimes, {"docker": docker_data},
                                    ((), (ContainerImage("buildah", "x", "localhost/app", "dev"),)),
                                    [web, portainer, tower], 1.0, 2.0)
    by_id = {e.id: e for e in inventory.engines}
    assert [e.id for e in inventory.engines] == list(eng.ENGINE_ORDER)
    assert (by_id["docker"].version, by_id["docker"].containers, by_id["docker"].running) == ("27.3.1", 2, 2)
    assert by_id["podman"].rootless is True and by_id["podman"].mode == "on"
    assert by_id["cri"].state is RuntimeState.PERMISSION and by_id["cri"].message == "sem permissão"
    assert by_id["nerdctl"].mode == "off" and not by_id["nerdctl"].active
    usage = {i.reference: i.in_use for i in inventory.images}
    assert usage["nginx:1.27"] is True and usage["redis:7"] is False
    assert "localhost/app:dev" in usage  # Buildah sem Podman no inventário: imagens próprias aparecem
    tools = {t.name: t for t in inventory.tools}
    assert tools["Portainer"].url == "https://10.0.0.5:9443"
    assert "atualiza contêineres sozinho" in tools["Watchtower"].detail and tools["Watchtower"].url == ""
    assert tools["Cockpit"].url == "https://10.0.0.5:9090"


def test_published_ports_and_normalize_ref():
    assert eng.published_ports("0.0.0.0:9443->9443/tcp, [::]:9443->9443/tcp, 8000/tcp") == [(9443, 9443)]
    assert eng.normalize_ref("docker.io/library/nginx") == "nginx:latest"
    assert eng.normalize_ref("nginx:1.27") == "nginx:1.27"
    assert eng.normalize_ref("ghcr.io/acme/api:2") == "ghcr.io/acme/api:2"
    assert eng.normalize_ref("localhost:5000/app") == "localhost:5000/app:latest"


# ---------------------------------------------------------------------------
# Atualizações de imagem (skopeo) e comandos
# ---------------------------------------------------------------------------

def test_image_update_comparison():
    local = ["nginx@sha256:" + "a" * 64]
    assert eng.parse_image_update("nginx:1.27", "a" * 64 + "\n", local).status == "atualizada"
    newer = eng.parse_image_update("nginx:1.27", "b" * 64, local)
    assert newer.status == "nova versão" and newer.remote_digest == "sha256:" + "b" * 64
    denied = eng.parse_image_update("ghcr.io/x/y:1", "ERR FATA[0001] ... unauthorized: authentication required", local)
    assert denied.status == "erro" and "login" in denied.detail
    assert "não encontrada" in eng.parse_image_update("x:9", "ERR manifest unknown", local).detail
    # Arquivo de credenciais ilegível não é "exige login" (o registro nem foi consultado).
    unreadable = eng.parse_image_update("alpine:3.20", 'ERR level=fatal msg="Error parsing image name: getting '
                                        'username and password: reading JSON file \\"/run/containers/1001/auth.json\\":'
                                        ' permission denied"', local)
    assert "auth.json" in unreadable.detail and "exige login" not in unreadable.detail
    # Mensagens reais do skopeo (ghcr.io e Docker Hub para repositórios privados/inexistentes).
    for raw in ('ERR time="2026-09-29T12:09:02Z" level=fatal msg="Error parsing image name \\"docker://ghcr.io/a/b:1'
                '\\": Requesting bearer token: invalid status code from registry 403 (Forbidden)"',
                'ERR time="x" level=fatal msg="Error parsing image name \\"docker://docker.io/a/b:1\\": reading '
                'manifest 1 in docker.io/a/b: requested access to the resource is denied"'):
        assert "exige login" in eng.parse_image_update("a/b:1", raw, local).detail
    assert "a tempo" in eng.parse_image_update("x:1", "ERR ", local).detail
    other = eng.parse_image_update("x:1", 'ERR time="x" level=fatal msg="pinging container registry: dial tcp: '
                                          'lookup registry.local: no such host"', local)
    assert other.detail.startswith("pinging container registry") and "level=" not in other.detail
    raw = ('ERR time="x" level=fatal msg="Error parsing image name \\"docker://reg.local/a:1\\": '
           'pinging container registry reg.local: no such host"')
    quoted = eng.parse_image_update("x:1", raw, local)
    assert quoted.detail == ('Error parsing image name "docker://reg.local/a:1": pinging container registry '
                             'reg.local: no such host')
    image = ContainerImage("docker", "1", "nginx", "1.27", digests=tuple(local))
    assert eng.updatable(image)
    assert not eng.updatable(ContainerImage("docker", "1", "<none>", "<none>"))
    assert not eng.updatable(ContainerImage("podman", "1", "localhost/app", "dev", digests=("x",)))
    assert not eng.updatable(ContainerImage("docker", "1", "app", "1"))  # sem digest de registro


def test_image_update_command_digest_matches_sha256sum(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b'{"schemaVersion":2,"manifests":[]}')
    fake = tmp_path / "skopeo"
    fake.write_text(f"#!/bin/sh\ncat {manifest}\n")
    fake.chmod(0o755)
    command = eng.build_image_update_command("nginx:1.27")
    result = subprocess.run(["sh", "-c", command], capture_output=True, text=True,
                            env={"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path)})
    import hashlib

    assert result.stdout.strip() == hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_image_update_command_without_skopeo_exits_127(tmp_path):
    """Sem skopeo o cliente precisa ver 127 ("não instalado"), não um "tag não encontrada"."""
    (tmp_path / "bin").mkdir()
    for tool in ("sh", "mktemp", "rm", "head", "tr", "timeout", "sha256sum", "cut"):
        target = subprocess.run(["sh", "-c", f"command -v {tool}"], capture_output=True, text=True).stdout.strip()
        if target:
            (tmp_path / "bin" / tool).symlink_to(target)
    result = subprocess.run(["sh", "-c", eng.build_image_update_command("nginx:1.27")], capture_output=True,
                            text=True, env={"PATH": str(tmp_path / "bin"), "HOME": str(tmp_path)})
    assert result.returncode == 127 and result.stdout == ""


def test_image_update_command_picks_a_readable_auth_file(tmp_path):
    """O skopeo recebe --authfile: o do usuário se existir, senão um vazio (anônimo), sempre apagado."""
    fake = tmp_path / "skopeo"
    fake.write_text('#!/bin/sh\nwhile [ "$1" != --authfile ]; do shift; done\necho "$2" >&2; cat "$2" >&2; exit 1\n')
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path), "TMPDIR": str(tmp_path)}
    command = eng.build_image_update_command("nginx:1.27")
    anonymous = subprocess.run(["sh", "-c", command], capture_output=True, text=True, env=env).stdout
    assert anonymous.startswith("ERR ") and '{"auths":{}}' in anonymous
    assert not list(tmp_path.glob("tmp.*"))  # temporários removidos
    docker_config = tmp_path / ".docker" / "config.json"
    docker_config.parent.mkdir()
    docker_config.write_text('{"auths":{"ghcr.io":{"auth":"eDp5"}}}')
    logged = subprocess.run(["sh", "-c", command], capture_output=True, text=True, env=env).stdout
    assert str(docker_config) in logged and "ghcr.io" in logged


@pytest.mark.parametrize(("engine_id", "use_sudo", "namespace"), [
    ("docker", True, ""), ("podman", False, ""), ("nerdctl", False, "k8s.io"), ("cri", True, ""),
])
def test_inventory_commands_are_valid_posix_shell(engine_id, use_sudo, namespace):
    command = eng.build_engine_inventory_command(engine_id, use_sudo, namespace)
    for shell in ("sh", "bash"):
        result = subprocess.run([shell, "-n", "-c", cmd.wrap_remote_command(command)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


def test_engine_commands():
    web = ServiceInfo(ServiceKind.NERDCTL, "web", "nginx", ServiceStatus.ACTIVE, "running", "Up")
    assert eng.build_container_op_command(web, "pause", True, "default") == \
        "sudo -n nerdctl --namespace default pause web"
    podman = ServiceInfo(ServiceKind.PODMAN, "db", "postgres", ServiceStatus.STOPPED, "exited", "Exited")
    assert eng.build_container_op_command(podman, "rm", False) == "podman rm db"
    assert cmd.build_container_ps_command("nerdctl", False, "k8s.io") == \
        "nerdctl --namespace k8s.io ps -a --format '{{json .}}'"
    image = ContainerImage("docker", "a1b2c3d4e5f6", "nginx", "1.27")
    assert eng.build_image_op_command("docker", image, "rmi", False) == "docker rmi nginx:1.27"
    assert eng.build_image_op_command("docker", None, "prune", True) == "sudo -n docker image prune -f"
    orphan = ContainerImage("podman", "0f0f0f0f0f0f", "<none>", "<none>")
    assert eng.build_image_op_command("podman", orphan, "inspect", False) == "podman image inspect 0f0f0f0f0f0f"
    assert eng.build_volume_op_command("docker", "shop_data", "rm", False) == "docker volume rm shop_data"
    console = eng.build_console_command(podman, True)
    assert console.startswith("sudo -n podman exec -it db sh -c ") and "exec bash || exec sh" in console
    cri = eng.parse_crictl_ps(CRICTL_PS)[0]
    assert eng.build_container_op_command(cri, "inspect", True).startswith("sudo -n crictl inspect 4f2a9c8e")
    assert cmd.build_cri_logs_command(cri.meta_value("id"), 20, False).startswith("crictl logs --tail 20")


@pytest.mark.parametrize("call", [
    lambda: cmd.container_cli("dockerd", False),
    lambda: cmd.container_cli("nerdctl", False, "--all"),
    lambda: cmd.container_cli("nerdctl", False, "ns;reboot"),
    lambda: eng.build_container_op_command(
        ServiceInfo(ServiceKind.DOCKER, "-rf", "", ServiceStatus.ACTIVE, "", ""), "rm", False),
    lambda: eng.build_container_op_command(
        ServiceInfo(ServiceKind.DOCKER, "web", "", ServiceStatus.ACTIVE, "", ""), "exec", False),
    lambda: eng.build_container_op_command(eng.parse_crictl_ps(CRICTL_PS)[0], "rm", True),
    lambda: eng.build_image_op_command("docker", ContainerImage("docker", "x", "-evil", "1"), "rmi", False),
    lambda: eng.build_image_op_command("docker", ContainerImage("docker", "x", "a;b", "1"), "rmi", False),
    lambda: eng.build_image_op_command("docker", None, "rmi", False),
    lambda: eng.build_volume_op_command("podman", "$(id)", "rm", False),
    lambda: eng.build_image_update_command("nginx:1.27; rm -rf /"),
    lambda: cmd.build_cri_logs_command("abc; id", 10, False),
])
def test_engine_builders_reject_injection(call):
    with pytest.raises(ValueError):
        call()


def test_engine_selection_round_trip_and_preferences(tmp_path):
    from config.preferences import Preferences, apply_engine_preferences, engine_preference_key
    from config.settings import Config

    assert set(eng.selection_to_modes({"mode": "auto"}).values()) == {"auto"}
    manual = eng.selection_to_modes({"mode": "manual", "enabled": ["podman", "skopeo", "nope"]})
    assert manual["podman"] == "on" and manual["skopeo"] == "on" and manual["docker"] == "off"
    assert eng.selection_to_modes(None) == {} and eng.selection_to_modes({"mode": "x"}) == {}
    server = ServerConfig(name="web", host="h", username="u")
    assert eng.modes_to_selection(server) == {"mode": "auto"}
    import dataclasses

    switched = dataclasses.replace(server, **manual)
    assert eng.modes_to_selection(switched) == {"mode": "manual", "enabled": ["podman", "skopeo"]}
    # Auto-detecção com exclusões (ex.: "lxd": "off" no servers.json) continua sendo auto-detecção.
    partial = dataclasses.replace(server, lxd="off", cri="off")
    assert eng.modes_to_selection(partial) == {"mode": "auto", "disabled": ["cri", "lxd"]}
    modes = eng.selection_to_modes({"mode": "auto", "disabled": ["lxd"]})
    assert modes["lxd"] == "off" and modes["docker"] == "auto"
    assert eng.modes_to_selection(dataclasses.replace(server, **modes)) == {"mode": "auto", "disabled": ["lxd"]}

    prefs = Preferences(tmp_path / "preferences.json")
    prefs.set(engine_preference_key("web"), {"mode": "manual", "enabled": ["podman"]})
    reloaded = Preferences(tmp_path / "preferences.json")
    config = apply_engine_preferences(Config(settings=None, servers=(server,)), reloaded)
    assert (config.servers[0].podman, config.servers[0].docker) == ("on", "off")


class _ScriptedClient:
    """SSHClient de verdade com ``run`` roteirizado (sem rede)."""

    @staticmethod
    def make(server: ServerConfig, exit_code: int, stderr: str):
        from core.ssh_client import CommandResult, SSHClient

        class Client(SSHClient):
            def run(self, command, timeout=None):
                return CommandResult(command, exit_code, "", stderr, 0.01)

        return Client(server)


@pytest.mark.parametrize(("kind", "stderr", "state", "needle"), [
    (ServiceKind.DOCKER, "sh: 1: docker: not found", RuntimeState.NOT_INSTALLED, "não instalado"),
    (ServiceKind.DOCKER, "sudo: a password is required", RuntimeState.PERMISSION, "NOPASSWD"),
    (ServiceKind.PODMAN, "sh: 1: podman: not found", RuntimeState.NOT_INSTALLED, "não instalado"),
    (ServiceKind.NERDCTL, "sh: 1: nerdctl: not found", RuntimeState.NOT_INSTALLED, "não instalado"),
    (ServiceKind.CRI, "sh: 1: crictl: not found", RuntimeState.NOT_INSTALLED, "não instalado"),
])
def test_runtime_errors_keep_the_hint_in_message_not_in_items(kind, stderr, state, needle):
    server = ServerConfig(name="s", host="h", username="monitor", docker_sudo=True)
    code = 127 if "not found" in stderr else 1
    result = _ScriptedClient.make(server, code, stderr).list_containers(kind)
    assert result.state is state
    assert result.items == ()
    assert needle in result.message


def test_other_runtimes_keep_the_hint_too():
    server = ServerConfig(name="s", host="h", username="monitor", kubernetes="on", libvirt="on", lxd="on")
    client = _ScriptedClient.make(server, 127, "sh: 1: x: not found")
    for result in (client.list_pods(), client.list_vms(), client.list_lxd()):
        assert result.state is RuntimeState.NOT_INSTALLED and result.items == () and result.message
