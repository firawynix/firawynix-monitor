"""Camada única de motores de contêiner.

O painel mostra SEMPRE a mesma interface — contêineres, imagens, volumes, redes,
builds e ações — qualquer que seja o motor instalado no servidor: Docker,
Podman, containerd (nerdctl), CRI-O/containerd via crictl, LXD/Incus, com
Buildah e Skopeo como ferramentas auxiliares. Cada motor é traduzido para os
mesmos modelos (``ServiceInfo``, ``ContainerImage``...), e a auto-detecção
descobre o que existe em cada servidor: trocar Docker por Podman não exige
mudar nada na configuração.

Painéis web de terceiros (Portainer, Cockpit, Dockge...) são apenas detectados
e podem ser abertos no navegador; o layout do Firawynix não depende deles.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from core.commands import CLI_RUNTIMES as CLI_ENGINES
from core.commands import container_cli as cli
from core.commands import sections, sudo, validate_container_name
from core.models import (
    BuildContainer,
    ContainerImage,
    ContainerInventory,
    ContainerNetwork,
    ContainerVolume,
    DetectedTool,
    EngineDiskUsage,
    EngineStatus,
    ImageUpdate,
    ManagementTool,
    RuntimeResult,
    RuntimeState,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
)

# ---------------------------------------------------------------------------
# Registro de motores
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineSpec:
    id: str
    label: str
    #: "runtime" (executa contêineres), "build" (constrói imagens) ou "registry".
    role: str
    kind: ServiceKind | None
    binaries: tuple[str, ...]
    description: str


ENGINES: dict[str, EngineSpec] = {
    "docker": EngineSpec("docker", "Docker", "runtime", ServiceKind.DOCKER, ("docker",),
                         "Docker Engine (CE/EE), inclusive rootless"),
    "podman": EngineSpec("podman", "Podman", "runtime", ServiceKind.PODMAN, ("podman",),
                         "Podman rootless ou root, pods e Quadlet"),
    "nerdctl": EngineSpec("nerdctl", "containerd (nerdctl)", "runtime", ServiceKind.NERDCTL, ("nerdctl",),
                          "containerd com a CLI nerdctl (compatível com o Docker)"),
    "cri": EngineSpec("cri", "CRI-O / containerd (crictl)", "runtime", ServiceKind.CRI, ("crictl",),
                      "Contêineres do Kubernetes direto no runtime CRI (somente leitura)"),
    "lxd": EngineSpec("lxd", "LXD / Incus", "runtime", ServiceKind.LXD, ("incus", "lxc"),
                      "Contêineres de sistema e VMs"),
    "buildah": EngineSpec("buildah", "Buildah", "build", None, ("buildah",),
                          "Construção de imagens OCI sem daemon"),
    "skopeo": EngineSpec("skopeo", "Skopeo", "registry", None, ("skopeo",),
                         "Consulta registros sem baixar imagens (verificação de atualizações)"),
}
ENGINE_ORDER = tuple(ENGINES)
ENGINE_OF_KIND = {spec.kind: spec.id for spec in ENGINES.values() if spec.kind is not None}

_EXTRA_TOOLS = ("kubectl", "k3s", "microk8s", "podman-compose", "docker-compose")
_DISCOVERY_BINARIES = ("docker", "podman", "nerdctl", "crictl", "buildah", "skopeo", "incus", "lxc") + _EXTRA_TOOLS
_DISCOVERY_SERVICES = ("docker", "containerd", "crio", "podman.socket", "cockpit.socket", "portainer")

_IMAGE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}")
_CRI_ID_RE = re.compile(r"[0-9a-f]{12,64}")


def engine_mode(server, engine_id: str) -> str:
    return getattr(server, engine_id, "off")


def engine_sudo(server, engine_id: str) -> bool:
    return bool(getattr(server, f"{engine_id}_sudo", False)) and server.username != "root"


def validate_image_ref(ref: str) -> str:
    if not isinstance(ref, str) or not _IMAGE_REF_RE.fullmatch(ref):
        raise ValueError(f"Referência de imagem inválida: {ref!r}")
    return ref


def validate_cri_id(value: str) -> str:
    if not isinstance(value, str) or not _CRI_ID_RE.fullmatch(value):
        raise ValueError(f"ID de contêiner CRI inválido: {value!r}")
    return value


# ---------------------------------------------------------------------------
# Auto-detecção
# ---------------------------------------------------------------------------

_DISCOVERY_SCRIPT = f"""
t() {{ if command -v timeout >/dev/null 2>&1; then timeout 3 "$@"; else "$@"; fi; }}
for c in {' '.join(_DISCOVERY_BINARIES)}; do
  p=$(command -v "$c" 2>/dev/null)
  if [ -z "$p" ]; then
    for d in /usr/local/bin /usr/bin /usr/sbin /usr/local/sbin /snap/bin; do
      [ -x "$d/$c" ] && {{ p="$d/$c"; break; }}
    done
  fi
  [ -n "$p" ] || continue
  if [ "$c" = kubectl ]; then v=$(t "$p" version --client 2>/dev/null | head -n 1)
  else v=$(t "$p" --version 2>/dev/null | head -n 1); fi
  echo "bin|$c|$p|$v"
done
command -v docker >/dev/null 2>&1 && echo "compose|docker|$(t docker compose version --short 2>/dev/null)"
if command -v podman >/dev/null 2>&1; then
  echo "rootless|podman|$(t podman info --format '{{{{.Host.Security.Rootless}}}}' 2>/dev/null)"
fi
for s in {' '.join(_DISCOVERY_SERVICES)}; do echo "svc|$s|$(systemctl is-active "$s" 2>/dev/null)"; done
true
"""
#: Um round-trip: binários (com versão), compose, Podman rootless e serviços relacionados.
DISCOVERY_CMD = "sh -c " + shlex.quote(_DISCOVERY_SCRIPT.strip())

_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.+-]+)?)")


@dataclass(frozen=True)
class Discovery:
    tools: dict[str, DetectedTool] = field(default_factory=dict)
    compose: dict[str, str] = field(default_factory=dict)
    rootless: dict[str, bool] = field(default_factory=dict)
    services: dict[str, str] = field(default_factory=dict)

    def has(self, engine_id: str) -> bool:
        spec = ENGINES.get(engine_id)
        return spec is not None and any(b in self.tools for b in spec.binaries)

    def tool_for(self, engine_id: str) -> DetectedTool | None:
        spec = ENGINES.get(engine_id)
        return next((self.tools[b] for b in spec.binaries if b in self.tools), None) if spec else None


def extract_version(text: str) -> str:
    match = _VERSION_RE.search(text or "")
    return match.group(1) if match else ""


def parse_discovery(output: str) -> Discovery:
    tools, compose, rootless, services = {}, {}, {}, {}
    for line in output.splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) < 3:
            continue
        kind, name = parts[0], parts[1]
        if kind == "bin" and len(parts) >= 3:
            tools[name] = DetectedTool(name, parts[2], extract_version(parts[3] if len(parts) > 3 else ""))
        elif kind == "compose" and parts[2].strip():
            compose[name] = extract_version(parts[2]) or parts[2].strip()
        elif kind == "rootless" and parts[2].strip() in ("true", "false"):
            rootless[name] = parts[2].strip() == "true"
        elif kind == "svc":
            services[name] = parts[2].strip()
    return Discovery(tools, compose, rootless, services)


# ---------------------------------------------------------------------------
# Listagem de contêineres (motores além de Docker/Podman)
# ---------------------------------------------------------------------------

_CRI_STATES = {"CONTAINER_RUNNING": ("running", ServiceStatus.ACTIVE),
               "CONTAINER_CREATED": ("created", ServiceStatus.STOPPED),
               "CONTAINER_EXITED": ("exited", ServiceStatus.STOPPED),
               "CONTAINER_UNKNOWN": ("unknown", ServiceStatus.UNKNOWN)}


def build_cri_ps_command(use_sudo: bool) -> str:
    return f"{sudo(use_sudo)}crictl ps -a -o json"


def parse_crictl_ps(output: str) -> list[ServiceInfo]:
    """``crictl ps -a -o json`` → contêineres (somente leitura; o kubelet os gerencia)."""
    text = output.strip()
    if not text:
        return []
    data = json.loads(text)
    items = data.get("containers") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("Saída do crictl sem a lista 'containers'")
    containers = []
    for item in items:
        if not isinstance(item, dict):
            continue
        container_id = str(item.get("id") or "")
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
        name = str(metadata.get("name") or container_id[:12])
        state, status = _CRI_STATES.get(str(item.get("state") or ""), ("unknown", ServiceStatus.UNKNOWN))
        attempt = metadata.get("attempt") or 0
        pod = str(labels.get("io.kubernetes.pod.name") or "")
        namespace = str(labels.get("io.kubernetes.pod.namespace") or "")
        image = item.get("image") if isinstance(item.get("image"), dict) else {}
        sub = state.capitalize() + (f" · {attempt} reinício(s)" if attempt else "")
        containers.append(ServiceInfo(
            kind=ServiceKind.CRI,
            name=f"{name}-{container_id[:8]}" if container_id else name,
            description=str(image.get("image") or item.get("imageRef") or ""),
            status=status,
            active_state=state,
            sub_state=sub + (f" · pod {namespace}/{pod}" if pod else ""),
            meta=(("id", container_id), ("pod", f"{namespace}/{pod}" if pod else ""), ("container", name)),
        ))
    return containers


# ---------------------------------------------------------------------------
# Inventário por motor: imagens, volumes, redes, uso de disco
# ---------------------------------------------------------------------------

def build_engine_inventory_command(engine_id: str, use_sudo: bool, namespace: str = "") -> str:
    """Um round-trip, 6 seções: imagens, volumes, volumes órfãos, redes, detalhes de redes, uso de disco."""
    if engine_id == "cri":
        return sections(f"{sudo(use_sudo)}crictl images -o json 2>/dev/null", *(["true"] * 5))
    base = cli(engine_id, use_sudo, namespace)
    json_list = engine_id == "podman"
    images = f"{base} images --format json" if json_list else f"{base} images --digests --format '{{{{json .}}}}'"
    volumes = f"{base} volume ls --format json" if json_list else f"{base} volume ls --format '{{{{json .}}}}'"
    networks = f"{base} network ls --format json" if json_list else f"{base} network ls --format '{{{{json .}}}}'"
    details = ""
    if engine_id == "docker":
        details = (f"ids=$({base} network ls -q 2>/dev/null) && [ -n \"$ids\" ] && {base} network inspect --format "
                   "'{{.Name}}|{{range .IPAM.Config}}{{.Subnet}} {{end}}|{{len .Containers}}' $ids")
    disk = ""
    if engine_id in ("docker", "podman"):
        disk = f"{base} system df --format json" if json_list else f"{base} system df --format '{{{{json .}}}}'"
    # "#OK" distingue "nenhum volume órfão" de "filtro não suportado" (versões antigas).
    dangling = f"out=$({base} volume ls -q --filter dangling=true 2>/dev/null) && {{ echo '#OK'; echo \"$out\"; }}"
    return sections(*(f"{part} 2>/dev/null" if part else "true" for part in (images, volumes)), dangling,
                    *(f"{part} 2>/dev/null" if part else "true" for part in (networks, details, disk)))


@dataclass(frozen=True)
class EngineData:
    images: tuple[ContainerImage, ...] = ()
    volumes: tuple[ContainerVolume, ...] = ()
    networks: tuple[ContainerNetwork, ...] = ()
    disk: tuple[EngineDiskUsage, ...] = ()


def _json_lines(text: str) -> list[dict]:
    items = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                items.append(value)
    return items


def _json_array(text: str) -> list[dict]:
    text = text.strip()
    if not text.startswith("["):
        return _json_lines(text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _labels(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    from core.parsers import parse_docker_labels

    return parse_docker_labels(str(value or ""))


def _split_ref(name: str) -> tuple[str, str]:
    """``docker.io/library/nginx:1.27`` → (``docker.io/library/nginx``, ``1.27``)."""
    if "@" in name:
        return name.split("@", 1)[0], "<digest>"
    repo, sep, tag = name.rpartition(":")
    if sep and "/" not in tag:
        return repo, tag
    return name, "latest"


def parse_images(engine_id: str, text: str) -> list[ContainerImage]:
    from core.parsers import parse_size

    images = []
    if engine_id == "cri":
        data = json.loads(text) if text.strip().startswith("{") else {}
        for item in data.get("images", []) if isinstance(data, dict) else []:
            tags = item.get("repoTags") or []
            size = item.get("size")
            size_bytes = int(size) if str(size or "").isdigit() else None
            names = tags or ["<none>:<none>"]
            for name in names:
                repo, tag = _split_ref(name) if name != "<none>:<none>" else ("<none>", "<none>")
                images.append(ContainerImage(engine_id, str(item.get("id", ""))[:19].removeprefix("sha256:")[:12],
                                             repo, tag, size_bytes, digests=tuple(item.get("repoDigests") or ())))
        return images
    if engine_id == "podman":
        for item in _json_array(text):
            image_id = str(item.get("Id") or item.get("ID") or "")[:12]
            names = item.get("Names") or item.get("RepoTags") or []
            size = item.get("Size")
            created = item.get("CreatedAt") or item.get("Created") or ""
            digests = tuple(item.get("RepoDigests") or ())
            for name in names or ["<none>:<none>"]:
                repo, tag = _split_ref(name) if name != "<none>:<none>" else ("<none>", "<none>")
                images.append(ContainerImage(engine_id, image_id, repo, tag,
                                             size if isinstance(size, int) else None, str(created)[:19],
                                             digests=digests,
                                             in_use=bool(item["Containers"]) if isinstance(item.get("Containers"),
                                                                                           int) else None))
        return images
    for item in _json_lines(text):  # docker / nerdctl
        repo, tag = str(item.get("Repository") or "<none>"), str(item.get("Tag") or "<none>")
        digest = str(item.get("Digest") or "")
        digests = (f"{repo}@{digest}",) if digest.startswith("sha256:") and repo != "<none>" else ()
        images.append(ContainerImage(engine_id, str(item.get("ID") or "")[:12], repo, tag,
                                     parse_size(str(item.get("Size") or "")),
                                     str(item.get("CreatedSince") or item.get("CreatedAt") or ""), digests=digests))
    # O --digests do Docker repete a imagem por digest; mantém uma linha por referência.
    unique: dict[str, ContainerImage] = {}
    for image in images:
        unique.setdefault(image.key, image)
    return list(unique.values())


def parse_volumes(engine_id: str, text: str, dangling_text: str) -> list[ContainerVolume]:
    lines = [line.strip() for line in dangling_text.splitlines() if line.strip()]
    known = bool(lines) and lines[0] == "#OK"
    dangling = set(lines[1:]) if known else set()
    volumes = []
    for item in _json_array(text):
        name = str(item.get("Name") or item.get("name") or "")
        if not name:
            continue
        labels = _labels(item.get("Labels"))
        volumes.append(ContainerVolume(
            engine=engine_id, name=name, driver=str(item.get("Driver") or item.get("driver") or "local"),
            mountpoint=str(item.get("Mountpoint") or ""), stack=labels.get("com.docker.compose.project", ""),
            in_use=(name not in dangling) if known else None,
        ))
    return volumes


def parse_networks(engine_id: str, text: str, details_text: str = "") -> list[ContainerNetwork]:
    details: dict[str, tuple[tuple[str, ...], int | None]] = {}
    for line in details_text.splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            count = int(parts[2]) if parts[2].strip().isdigit() else None
            details[parts[0].strip()] = (tuple(parts[1].split()), count)
    networks = []
    for item in _json_array(text):
        name = str(item.get("Name") or item.get("name") or "")
        if not name:
            continue
        subnets = tuple(str(s.get("subnet")) for s in item.get("subnets") or [] if isinstance(s, dict)
                        and s.get("subnet"))
        extra_subnets, count = details.get(name, ((), None))
        internal = item.get("Internal", item.get("internal", False))
        networks.append(ContainerNetwork(
            engine=engine_id, name=name, driver=str(item.get("Driver") or item.get("driver") or ""),
            scope=str(item.get("Scope") or ""), subnets=subnets or extra_subnets, containers=count,
            internal=str(internal).lower() == "true", id=str(item.get("ID") or item.get("id") or "")[:12],
        ))
    return networks


def parse_system_df(engine_id: str, text: str) -> list[EngineDiskUsage]:
    rows = []
    for item in _json_array(text):
        kind = str(item.get("Type") or "")
        if not kind:
            continue

        rows.append(EngineDiskUsage(engine_id, kind, _number(item, "TotalCount", "Total"), _number(item, "Active"),
                                    str(item.get("Size") or ""), str(item.get("Reclaimable") or "")))
    return rows


def _number(item: dict, *keys: str) -> int | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def parse_engine_inventory(engine_id: str, output: str) -> EngineData:
    from core.parsers import split_sections

    images_s, volumes_s, dangling_s, networks_s, details_s, disk_s = split_sections(output, 6)[:6]
    try:
        images = parse_images(engine_id, images_s)
    except (ValueError, TypeError):
        images = []
    return EngineData(tuple(images), tuple(parse_volumes(engine_id, volumes_s, dangling_s)),
                      tuple(parse_networks(engine_id, networks_s, details_s)),
                      tuple(parse_system_df(engine_id, disk_s)))


# ---------------------------------------------------------------------------
# Buildah
# ---------------------------------------------------------------------------

def build_buildah_command(use_sudo: bool) -> str:
    s = sudo(use_sudo)
    return sections(f"{s}buildah containers --json 2>/dev/null", f"{s}buildah images --json 2>/dev/null")


def parse_buildah(output: str) -> tuple[tuple[BuildContainer, ...], tuple[ContainerImage, ...]]:
    from core.parsers import parse_size, split_sections

    containers_s, images_s = split_sections(output, 2)[:2]
    builds = tuple(BuildContainer(str(c.get("id", ""))[:12], str(c.get("containername") or ""),
                                  str(c.get("imagename") or ""))
                   for c in _json_array(containers_s))
    images = []
    for item in _json_array(images_s):
        for name in item.get("names") or ["<none>:<none>"]:
            repo, tag = _split_ref(name) if name != "<none>:<none>" else ("<none>", "<none>")
            images.append(ContainerImage("buildah", str(item.get("id", ""))[:12], repo, tag,
                                         parse_size(str(item.get("size") or "")),
                                         str(item.get("createdat") or "")[:19],
                                         digests=(f"{repo}@{item['digest']}",) if item.get("digest") else ()))
    return builds, tuple(images)


# ---------------------------------------------------------------------------
# Ações e consultas no mesmo formato para todos os motores
# ---------------------------------------------------------------------------

CONTAINER_OPS = ("pause", "unpause", "rm", "inspect")
IMAGE_OPS = ("inspect", "rmi", "prune")
VOLUME_OPS = ("inspect", "rm")
#: Operações que apagam algo: exigem "container_admin": true.
DESTRUCTIVE_OPS = {"rm", "rmi", "prune"}


def build_container_op_command(service: ServiceInfo, op: str, use_sudo: bool, namespace: str = "") -> str:
    if op not in CONTAINER_OPS:
        raise ValueError(f"Operação inválida: {op!r}")
    if service.kind is ServiceKind.CRI:
        if op != "inspect":
            raise ValueError("Contêineres CRI são somente leitura (gerenciados pelo kubelet).")
        return f"{sudo(use_sudo)}crictl inspect {validate_cri_id(service.meta_value('id'))}"
    engine_id = ENGINE_OF_KIND.get(service.kind)
    name = shlex.quote(validate_container_name(service.name))
    return f"{cli(engine_id, use_sudo, namespace)} {op} {name}"


def build_image_op_command(engine_id: str, image: ContainerImage | None, op: str, use_sudo: bool,
                           namespace: str = "") -> str:
    if op not in IMAGE_OPS:
        raise ValueError(f"Operação inválida: {op!r}")
    if engine_id == "cri":
        if op != "inspect" or image is None:
            raise ValueError("Imagens CRI são somente leitura.")
        return f"{sudo(use_sudo)}crictl inspecti {shlex.quote(validate_image_ref(image.reference))}"
    base = cli(engine_id, use_sudo, namespace)
    if op == "prune":
        return f"{base} image prune -f"  # somente imagens órfãs (sem tag)
    if image is None:
        raise ValueError("Imagem não informada")
    ref = shlex.quote(validate_image_ref(image.id if image.dangling else image.reference))
    return f"{base} image inspect {ref}" if op == "inspect" else f"{base} rmi {ref}"


def build_volume_op_command(engine_id: str, name: str, op: str, use_sudo: bool, namespace: str = "") -> str:
    if op not in VOLUME_OPS:
        raise ValueError(f"Operação inválida: {op!r}")
    return f"{cli(engine_id, use_sudo, namespace)} volume {op} {shlex.quote(validate_container_name(name))}"


def build_console_command(service: ServiceInfo, use_sudo: bool, namespace: str = "") -> str:
    """Shell interativo no contêiner (aberto com ``ssh -t`` no terminal do Windows)."""
    engine_id = ENGINE_OF_KIND.get(service.kind)
    if engine_id not in CLI_ENGINES:
        raise ValueError(f"Console não disponível para {service.kind.label}")
    name = shlex.quote(validate_container_name(service.name))
    shell = shlex.quote("command -v bash >/dev/null 2>&1 && exec bash || exec sh")
    return f"{cli(engine_id, use_sudo, namespace)} exec -it {name} sh -c {shell}"


def normalize_ref(ref: str) -> str:
    """Compara referências de motores diferentes (``nginx`` = ``docker.io/library/nginx:latest``)."""
    ref = ref.strip()
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/", "localhost/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
            break
    if "@" not in ref and ":" not in ref.rsplit("/", 1)[-1]:
        ref += ":latest"
    return ref


def updatable(image: ContainerImage) -> bool:
    """Imagens verificáveis no registro: com tag, digest conhecido e não locais."""
    return (not image.dangling and image.tag not in ("<digest>", "") and bool(image.digests)
            and not image.repository.startswith("localhost/") and image.engine != "buildah")


def build_image_update_command(reference: str) -> str:
    """Digest do manifesto remoto (lista multi-arquitetura) sem baixar a imagem.

    ``sha256sum`` do manifesto bruto = o digest que o Docker/Podman grava em
    RepoDigests ao baixar pela tag; se forem iguais, a imagem local está em dia.
    """
    ref = shlex.quote("docker://" + validate_image_ref(reference))
    # Credenciais: o primeiro auth.json legível (skopeo/podman login ou docker login). Sem sessão de login
    # (XDG_RUNTIME_DIR vazio) o skopeo cairia em /run/containers/<uid>, que pode ser ilegível e aborta a
    # consulta; sem arquivo algum, usa um vazio (acesso anônimo, suficiente para registros públicos).
    return ("command -v skopeo >/dev/null 2>&1 || exit 127; t=$(mktemp) || exit 1; a=''; "
            "for f in \"$REGISTRY_AUTH_FILE\" \"${XDG_RUNTIME_DIR:+$XDG_RUNTIME_DIR/containers/auth.json}\" "
            "\"$HOME/.config/containers/auth.json\" \"$HOME/.docker/config.json\"; do "
            "[ -n \"$f\" ] && [ -r \"$f\" ] && { a=$f; break; }; done; "
            "[ -n \"$a\" ] || { a=\"$t.auth\"; echo '{\"auths\":{}}' >\"$a\"; }; "
            f"if timeout 4 skopeo inspect --raw --authfile \"$a\" {ref} >\"$t\" 2>\"$t.err\"; "
            "then sha256sum \"$t\" | cut -d' ' -f1; "
            "else echo \"ERR $(head -c 300 \"$t.err\" | tr '\\n' ' ')\"; fi; rm -f \"$t\" \"$t.err\" \"$t.auth\"")


_SKOPEO_MSG_RE = re.compile(r'msg="((?:[^"\\]|\\.)*)"')


def parse_image_update(reference: str, output: str, local_digests: Iterable[str]) -> ImageUpdate:
    text = output.strip()
    if text.startswith("ERR") or not re.fullmatch(r"[0-9a-f]{64}", text.splitlines()[-1] if text else ""):
        detail = text[3:].strip() if text.startswith("ERR") else (text or "sem resposta")
        message = _SKOPEO_MSG_RE.search(detail)
        if message:  # time="..." level=fatal msg="..." → só a mensagem
            detail = message.group(1).replace('\\"', '"')
        lower = detail.lower()
        if not detail:
            detail = "o registro não respondeu a tempo (4 s)"
        elif "auth.json" in lower or "getting username and password" in lower:
            detail = "não foi possível ler as credenciais do registro (auth.json) no servidor"
        elif any(k in lower for k in ("unauthorized", "authentication required", "denied", "forbidden",
                                      "status code from registry 401", "status code from registry 403")):
            detail = "registro exige login (skopeo login / docker login no servidor)"
        elif "manifest unknown" in lower or "not found" in lower:
            detail = "tag não encontrada no registro"
        return ImageUpdate(reference, "erro", detail=detail[:200])
    remote = "sha256:" + text.splitlines()[-1]
    local = {d.rsplit("@", 1)[-1] for d in local_digests}
    if remote in local:
        return ImageUpdate(reference, "atualizada", remote)
    return ImageUpdate(reference, "nova versão", remote, "o registro tem outro digest para esta tag")


# ---------------------------------------------------------------------------
# Painéis de terceiros
# ---------------------------------------------------------------------------

#: (trecho da imagem, nome, portas preferidas do contêiner, observação)
_MANAGEMENT_IMAGES = (
    ("portainer/portainer", "Portainer", (9443, 9000), ""),
    ("portainer/agent", "Portainer Agent", (9001,), "este servidor é administrado por um Portainer remoto"),
    ("louislam/dockge", "Dockge", (5001,), ""),
    ("selfhostedpro/yacht", "Yacht", (8000,), ""),
    ("amir20/dozzle", "Dozzle", (8080,), "visualizador de logs"),
    ("rancher/rancher", "Rancher", (443, 80), ""),
    ("containrrr/watchtower", "Watchtower", (), "atualiza contêineres sozinho: mudanças podem aparecer sem ação sua"),
    ("cockpit/ws", "Cockpit", (9090,), ""),
)
_PORT_RE = re.compile(r"(?:[0-9.]+|\[[0-9a-fA-F:]*\]|):(\d+)->(\d+)/(tcp|udp)")


def published_ports(ports: str) -> list[tuple[int, int]]:
    """``0.0.0.0:9443->9443/tcp, 8000/tcp`` → ``[(9443, 9443)]`` (porta do host, porta do contêiner)."""
    return list(dict.fromkeys((int(h), int(c)) for h, c, _proto in _PORT_RE.findall(ports or "")))


def _url(host: str, host_port: int, container_port: int) -> str:
    # Portainer (9443) e Cockpit (9090) usam HTTPS por padrão.
    scheme = "https" if {container_port, host_port} & {443, 9443, 9090} else "http"
    host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host}:{host_port}"


def detect_management_tools(services: Iterable[ServiceInfo], discovery: Discovery | None,
                            host: str) -> tuple[ManagementTool, ...]:
    tools: dict[str, ManagementTool] = {}
    for service in services:
        if not service.kind.is_container:
            continue
        image = service.description.lower()
        for needle, name, preferred, note in _MANAGEMENT_IMAGES:
            if needle not in image:
                continue
            ports = published_ports(service.meta_value("ports"))
            chosen = next((p for p in ports if p[1] in preferred), ports[0] if ports else None)
            url = _url(host, *chosen) if chosen else ""
            state = "em execução" if service.status is ServiceStatus.ACTIVE else service.status.label.lower()
            detail = f"contêiner {service.name} ({service.kind.label}) · {state}"
            if note:
                detail += f" · {note}"
            elif not url:
                detail += " · sem porta publicada"
            tools.setdefault(name, ManagementTool(name, f"{service.kind.label}: {service.name}", url, detail))
    services_state = discovery.services if discovery else {}
    if services_state.get("cockpit.socket") == "active" and "Cockpit" not in tools:
        tools["Cockpit"] = ManagementTool("Cockpit", "systemd: cockpit.socket", _url(host, 9090, 9090),
                                          "console web do sistema (com o plugin de Podman)")
    if services_state.get("portainer") == "active" and "Portainer" not in tools:
        tools["Portainer"] = ManagementTool("Portainer", "systemd: portainer", _url(host, 9443, 9443),
                                            "instalado como serviço")
    return tuple(tools.values())


# ---------------------------------------------------------------------------
# Montagem do inventário exibido na aba Contêineres
# ---------------------------------------------------------------------------

def _mark_in_use(images: Sequence[ContainerImage], containers: Sequence[ServiceInfo]) -> list[ContainerImage]:
    used_refs = {normalize_ref(c.description) for c in containers if c.description}
    used_ids = {c.meta_value("image_id")[:12] for c in containers if c.meta_value("image_id")}
    marked = []
    for image in images:
        if image.in_use is None and image.engine != "buildah":
            in_use = normalize_ref(image.reference) in used_refs or (image.id and (
                image.id[:12] in used_ids or any(ref.startswith(("sha256:" + image.id, image.id)) for ref in
                                                 used_refs)))
            image = ContainerImage(image.engine, image.id, image.repository, image.tag, image.size_bytes,
                                   image.created, image.digests, bool(in_use))
        marked.append(image)
    return marked


def build_inventory(server, discovery: Discovery | None, runtimes: dict[ServiceKind, RuntimeResult],
                    engine_data: dict[str, EngineData], buildah: tuple | None, services: Sequence[ServiceInfo],
                    detected_at: float | None, collected_at: float | None) -> ContainerInventory:
    engines = []
    for engine_id in ENGINE_ORDER:
        spec = ENGINES[engine_id]
        runtime = runtimes.get(spec.kind) if spec.kind else None
        tool = discovery.tool_for(engine_id) if discovery else None
        installed = None if discovery is None else tool is not None
        state = runtime.state if runtime is not None and runtime.state is not RuntimeState.DISABLED else None
        if state is RuntimeState.OK:
            installed = True
        elif state is RuntimeState.NOT_INSTALLED and installed is None:
            installed = False
        members = [s for s in services if spec.kind is not None and s.kind is spec.kind]
        engines.append(EngineStatus(
            id=engine_id, label=spec.label, role=spec.role, mode=engine_mode(server, engine_id),
            installed=installed, version=tool.version if tool else "", state=state,
            message=runtime.message if runtime is not None and state not in (None, RuntimeState.OK) else "",
            rootless=discovery.rootless.get(engine_id) if discovery else None,
            containers=len(members), running=sum(1 for s in members if s.status is ServiceStatus.ACTIVE),
        ))
    containers = [s for s in services if s.kind.is_container]
    images, volumes, networks, disk = [], [], [], []
    for engine_id in ENGINE_ORDER:
        data = engine_data.get(engine_id)
        if data is None:
            continue
        kind = ENGINES[engine_id].kind
        images += _mark_in_use(data.images, [c for c in containers if c.kind is kind])
        volumes += data.volumes
        networks += data.networks
        disk += data.disk
    builds: tuple[BuildContainer, ...] = ()
    if buildah is not None:
        builds, buildah_images = buildah
        # Buildah e Podman compartilham o armazenamento (containers/storage): sem duplicar.
        if "podman" not in engine_data:
            images += buildah_images
    return ContainerInventory(
        engines=tuple(engines), images=tuple(images), volumes=tuple(volumes), networks=tuple(networks),
        builds=builds, disk=tuple(disk), tools=detect_management_tools(services, discovery, server.host),
        detected_at=detected_at, collected_at=collected_at,
    )


# ---------------------------------------------------------------------------
# Escolha de motores feita no painel (preferences.json)
# ---------------------------------------------------------------------------

def selection_to_modes(selection: dict | None) -> dict[str, str]:
    """``{"mode": "auto"}`` → todos em "auto" (auto-detecção), exceto os de ``"disabled"``
    (ignorados mesmo se instalados); ``{"mode": "manual", "enabled": ["podman", ...]}`` →
    escolhidos "on" (avisa se faltarem), demais "off"."""
    if not isinstance(selection, dict):
        return {}
    if selection.get("mode") == "auto":
        disabled = set(selection.get("disabled") or ())
        return {engine_id: "off" if engine_id in disabled else "auto" for engine_id in ENGINE_ORDER}
    if selection.get("mode") == "manual":
        enabled = {e for e in selection.get("enabled") or [] if e in ENGINES}
        return {engine_id: "on" if engine_id in enabled else "off" for engine_id in ENGINE_ORDER}
    return {}


def modes_to_selection(server) -> dict:
    """Inverso de :func:`selection_to_modes` (sem "on" algum = auto-detecção com exclusões)."""
    modes = {engine_id: engine_mode(server, engine_id) for engine_id in ENGINE_ORDER}
    if "on" not in modes.values():
        disabled = [e for e, mode in modes.items() if mode == "off"]
        return {"mode": "auto", "disabled": disabled} if disabled else {"mode": "auto"}
    return {"mode": "manual", "enabled": [e for e, mode in modes.items() if mode != "off"]}
