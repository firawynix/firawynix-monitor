"""Regras da aba Contêineres e do diálogo de motores (sem abrir janelas)."""

import pytest

pytest.importorskip("tkinter")
pytest.importorskip("customtkinter")

from core.models import (  # noqa: E402
    ContainerImage,
    ContainerInventory,
    EngineDiskUsage,
    EngineStatus,
    ImageUpdate,
    RuntimeState,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
)
from ui.containers_tab import (  # noqa: E402
    container_counts,
    engine_badge,
    engine_of,
    engine_short,
    fmt_created,
    is_paused,
    ports_text,
    reclaimable_bytes,
    selection_summary,
    update_targets,
    update_text,
    visible_engines,
)
from ui.engines_dialog import build_selection, detection_text  # noqa: E402
from ui.widgets import GRAY, GREEN, RED, YELLOW  # noqa: E402


def _engine(engine_id="docker", **kwargs):
    base = {"label": engine_id, "role": "runtime", "mode": "auto", "installed": True, "version": "27.3.1",
            "state": RuntimeState.OK, "containers": 11, "running": 9}
    base.update(kwargs)
    return EngineStatus(id=engine_id, **base)


def _container(name="web", kind=ServiceKind.DOCKER, status=ServiceStatus.ACTIVE, state="running",
               sub="Up 3 days", meta=()):
    return ServiceInfo(kind, name, "nginx:1.27", status, state, sub, meta=meta)


def test_engine_badge_is_the_same_for_every_engine():
    assert engine_badge(_engine()) == ("v27.3.1 · 9/11 rodando", GREEN)
    podman = _engine("podman", version="5.2.2", rootless=True, containers=3, running=2)
    assert engine_badge(podman) == ("v5.2.2 · rootless · 2/3 rodando", GREEN)
    assert engine_badge(_engine(state=RuntimeState.DAEMON_DOWN)) == ("v27.3.1 · daemon parado", RED)
    assert engine_badge(_engine(state=RuntimeState.PERMISSION))[1] == YELLOW
    assert engine_badge(_engine(mode="off"))[0].endswith("desativado")
    assert engine_badge(_engine("skopeo", role="registry", state=None)) == ("v27.3.1 · registros", GREEN)
    assert engine_badge(_engine("buildah", role="build", state=None, version=""))[0] == "builds"
    # Ligado à mão mas ausente no servidor: destaca; na auto-detecção só informa.
    assert engine_badge(_engine(mode="on", installed=False, state=RuntimeState.NOT_INSTALLED)) == (
        "não instalado", RED)
    assert engine_badge(_engine(installed=False, state=None)) == ("não encontrado", GRAY)
    assert engine_badge(_engine(installed=None, state=None)) == ("aguardando detecção", GRAY)


def test_visible_engines_shows_detected_and_forced_ones():
    inventory = ContainerInventory(engines=(
        _engine("docker"), _engine("podman", installed=False), _engine("nerdctl", installed=False, mode="on"),
        _engine("buildah", installed=None)))
    assert [e.id for e in visible_engines(inventory)] == ["docker", "nerdctl"]
    assert visible_engines(None) == []


def test_selection_summary_and_dialog_selection():
    assert selection_summary({"mode": "auto"}) == "Auto-detecção"
    assert selection_summary({"mode": "manual", "enabled": ["podman", "cri"]}) == "Manual: Podman, CRI · Kubernetes"
    assert selection_summary({"mode": "manual", "enabled": []}) == "Manual: nenhum motor"
    assert selection_summary({"mode": "auto", "disabled": ["lxd"]}) == "Auto-detecção · ignorando LXD/Incus"
    everything = ["docker", "podman", "nerdctl", "cri", "lxd", "buildah", "skopeo"]
    assert build_selection(True, everything) == {"mode": "auto"}
    # Na auto-detecção, desmarcar = ignorar o motor mesmo que esteja instalado.
    assert build_selection(True, [e for e in everything if e != "lxd"]) == {"mode": "auto", "disabled": ["lxd"]}
    # Ordem canônica e sem ids desconhecidos.
    assert build_selection(False, ["skopeo", "podman", "bogus"]) == {"mode": "manual",
                                                                     "enabled": ["podman", "skopeo"]}


def test_detection_text():
    assert detection_text(None) == ("aguardando detecção", GRAY)
    assert detection_text(_engine(installed=False)) == ("não encontrado", GRAY)
    assert detection_text(_engine("podman", version="5.2.2", rootless=True)) == (
        "detectado · v5.2.2 · rootless", GREEN)
    assert detection_text(_engine(state=RuntimeState.DAEMON_DOWN)) == ("detectado · v27.3.1 · daemon parado", RED)
    assert detection_text(_engine(mode="off")) == ("detectado · v27.3.1 · desativado", GRAY)


def test_engine_labels_and_kinds():
    assert engine_of(_container(kind=ServiceKind.NERDCTL)) == "nerdctl"
    assert engine_of(_container(kind=ServiceKind.CRI)) == "cri"
    assert engine_short("nerdctl") == "containerd"
    assert engine_short("docker") == "Docker"


def test_paused_and_counts():
    paused = _container("a", status=ServiceStatus.STOPPED, state="paused", sub="Up 3 days (Paused)")
    services = [_container("b"), paused, _container("c", status=ServiceStatus.STOPPED, state="exited"),
                _container("d", status=ServiceStatus.FAILED, state="restarting")]
    assert is_paused(paused) and not is_paused(services[0])
    assert container_counts(services) == {"total": 4, "running": 1, "paused": 1, "failed": 1, "stopped": 1}


def test_ports_text_dedupes_ipv4_and_ipv6():
    service = _container(meta=(("ports", "0.0.0.0:9443->9443/tcp, [::]:9443->9443/tcp, 8000/tcp"),))
    assert ports_text(service) == "9443→9443"
    assert ports_text(_container(meta=(("ports", "8000/tcp"),))) == "8000/tcp"


def test_fmt_created_handles_every_engine_format():
    assert fmt_created("3 weeks ago") == "há 3 semanas"
    assert fmt_created("About an hour ago") == "há 1 hora"
    assert fmt_created("2 months ago") == "há 2 meses"
    # Podman/containerd informam data absoluta: vira a mesma escala relativa do Docker.
    now = 1_790_000_000.0  # 2026-09-21
    assert fmt_created("2026-04-16T23:53:26Z", now) == "há 5 meses"
    assert fmt_created("2026-09-20 12:30:00 +0000 UTC", now) == "há 1 dia"
    assert fmt_created(str(int(now - 3 * 3600)), now) == "há 3 horas"
    assert fmt_created("2026-09-21T00:00:00", now).startswith("há ")
    assert fmt_created("") == ""
    assert fmt_created("ontem") == "ontem"


def test_update_text_and_targets():
    assert update_text(None) == ("", None)
    assert update_text(ImageUpdate("nginx:1.27", "nova versão")) == ("nova versão disponível", "warn")
    assert update_text(ImageUpdate("nginx:1.27", "atualizada")) == ("em dia", None)
    text, tag = update_text(ImageUpdate("x", "erro", detail="registro exige login"))
    assert text == "não verificada: registro exige login" and tag == "muted"
    digest = ("docker.io/library/nginx@sha256:" + "a" * 64,)
    images = [ContainerImage("docker", "1", "nginx", "1.27", digests=digest),
              ContainerImage("podman", "2", "docker.io/library/nginx", "1.27", digests=digest),
              ContainerImage("docker", "3", "<none>", "<none>"),
              ContainerImage("podman", "4", "localhost/app", "dev", digests=digest)]
    # A mesma referência em dois motores é consultada uma vez; órfãs e locais ficam de fora.
    assert [i.id for i in update_targets(images)] == ["1"]


def test_reclaimable_bytes_sums_engines():
    inventory = ContainerInventory(disk=(
        EngineDiskUsage("docker", "Images", 13, 9, "6.9GB", "1.5GB (21%)"),
        EngineDiskUsage("podman", "Images", 6, 2, "1.9GB", "512MB (26%)"),
        EngineDiskUsage("docker", "Local Volumes", 5, 4, "300MB", "90MB (30%)")))
    # Docker/Podman usam unidades decimais no system df (GB = 10^9).
    assert reclaimable_bytes(inventory) == 1_500_000_000 + 512_000_000
    assert reclaimable_bytes(ContainerInventory()) is None
