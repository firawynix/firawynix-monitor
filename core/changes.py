"""Mudanças seguras em contêineres: antes de agir, o painel analisa o risco e
diz o que pode ser afetado; se houver risco, salva o que for preciso para
voltar atrás; executa; confere o resultado; e registra tudo para permitir
iniciar de novo ou restaurar.

Este módulo é puro (sem SSH): regras de impacto, proteções recomendadas,
definição do contêiner (``inspect`` → especificação → comando ``run``) e os
comandos que o executor (:mod:`core.change_runner`) roda no servidor.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum

from core import containers as engines
from core.commands import validate_container_name
from core.models import ContainerInventory, ServiceInfo, ServiceKind, ServiceStatus

# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------


class Risk(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return ("sem risco", "baixo", "médio", "alto", "crítico")[self]


class ChangeAction(StrEnum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    PAUSE = "pause"
    UNPAUSE = "unpause"
    REMOVE = "remove"
    CREATE = "create"
    RESTORE = "restore"

    @property
    def label(self) -> str:
        return {"start": "Iniciar", "stop": "Parar", "restart": "Reiniciar", "pause": "Pausar",
                "unpause": "Retomar", "remove": "Remover", "create": "Criar", "restore": "Restaurar"}[self.value]

    @property
    def disruptive(self) -> bool:
        """Interrompe um serviço que está atendendo."""
        return self in (ChangeAction.STOP, ChangeAction.RESTART, ChangeAction.PAUSE, ChangeAction.REMOVE)


@dataclass(frozen=True)
class Impact:
    level: Risk
    area: str
    title: str
    detail: str = ""


@dataclass(frozen=True)
class Protection:
    id: str
    label: str
    detail: str
    default: bool
    #: Obrigatória (não pode ser desmarcada) — ex.: salvar a definição quando há risco.
    required: bool = False
    available: bool = True
    reason: str = ""


@dataclass(frozen=True)
class Assessment:
    action: ChangeAction
    target: str
    engine: str
    risk: Risk
    impacts: tuple[Impact, ...]
    protections: tuple[Protection, ...]
    steps: tuple[str, ...]
    #: Impede a execução (ex.: contêiner somente leitura, nome já em uso).
    blockers: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        if self.blockers:
            return "Não é possível executar: " + "; ".join(self.blockers)
        worst = [i for i in self.impacts if i.level == self.risk and i.level >= Risk.MEDIUM]
        if not worst:
            return f"Risco {self.risk.label}: nenhum impacto relevante encontrado."
        return f"Risco {self.risk.label}: " + "; ".join(i.title for i in worst[:3])

    def protection(self, protection_id: str) -> Protection | None:
        return next((p for p in self.protections if p.id == protection_id), None)


# ---------------------------------------------------------------------------
# Leitura do inspect (Docker, Podman e nerdctl usam o mesmo formato)
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class InspectInfo:
    """O que a análise de risco usa do ``inspect`` do contêiner."""

    name: str
    image: str
    status: str = ""
    restart_policy: str = ""
    network_mode: str = ""
    networks: tuple[str, ...] = ()
    #: (ip do host, porta do host, porta do contêiner, protocolo)
    ports: tuple[tuple[str, int, int, str], ...] = ()
    volumes: tuple[str, ...] = ()
    anonymous_volumes: tuple[str, ...] = ()
    binds: tuple[tuple[str, str], ...] = ()
    labels: tuple[tuple[str, str], ...] = ()
    size_rw: int | None = None
    health: str = ""
    privileged: bool = False

    def label(self, key: str) -> str:
        return next((v for k, v in self.labels if k == key), "")


def parse_inspect(data: dict) -> InspectInfo:
    config = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    state = data.get("State") or {}
    settings = data.get("NetworkSettings") or {}
    ports = []
    for key, bindings in sorted((host.get("PortBindings") or {}).items()):
        container_port, _, proto = str(key).partition("/")
        for binding in bindings or []:
            host_port = str((binding or {}).get("HostPort") or "")
            if host_port.isdigit() and container_port.isdigit():
                ports.append((str(binding.get("HostIp") or ""), int(host_port), int(container_port),
                              proto or "tcp"))
    volumes, anonymous, binds = [], [], []
    for mount in data.get("Mounts") or []:
        kind = mount.get("Type")
        if kind == "volume" and mount.get("Name"):
            (anonymous if _HEX64.fullmatch(mount["Name"]) else volumes).append(mount["Name"])
        elif kind == "bind":
            binds.append((str(mount.get("Source") or ""), str(mount.get("Destination") or "")))
    health = state.get("Health") or {}
    size = data.get("SizeRw")
    return InspectInfo(
        name=str(data.get("Name") or "").lstrip("/"),
        image=str(config.get("Image") or data.get("ImageName") or ""),
        status=str(state.get("Status") or ""),
        restart_policy=str((host.get("RestartPolicy") or {}).get("Name") or ""),
        network_mode=str(host.get("NetworkMode") or ""),
        networks=tuple(sorted((settings.get("Networks") or {}).keys())),
        ports=tuple(dict.fromkeys(ports)),
        volumes=tuple(dict.fromkeys(volumes)),
        anonymous_volumes=tuple(dict.fromkeys(anonymous)),
        binds=tuple(binds),
        labels=tuple(sorted((str(k), str(v)) for k, v in (config.get("Labels") or {}).items())),
        size_rw=size if isinstance(size, int) else None,
        health=str(health.get("Status") or "") if isinstance(health, dict) else "",
        privileged=bool(host.get("Privileged")),
    )


# ---------------------------------------------------------------------------
# Papéis conhecidos (pela imagem)
# ---------------------------------------------------------------------------

_ROLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("banco", ("postgres", "postgis", "timescale", "mysql", "mariadb", "percona", "mongo", "redis", "valkey",
               "keydb", "elasticsearch", "opensearch", "clickhouse", "influxdb", "cassandra", "scylla", "couchdb",
               "neo4j", "mssql", "cockroach", "etcd", "minio", "rabbitmq", "kafka", "zookeeper", "nats",
               "memcached")),
    ("proxy", ("traefik", "nginx", "caddy", "haproxy", "envoy", "nginx-proxy-manager", "swag", "httpd",
               "apache", "varnish")),
    ("acesso", ("cloudflared", "tailscale", "wireguard", "wg-easy", "openvpn", "netbird", "zerotier",
                "headscale", "frpc", "ngrok", "pritunl")),
    ("painel", ("portainer",)),
    ("atualizador", ("watchtower",)),
    ("monitoramento", ("prometheus", "grafana", "loki", "alertmanager", "node-exporter", "cadvisor",
                       "uptime-kuma", "zabbix", "netdata", "promtail")),
)


def container_role(image: str) -> str:
    name = image.lower().rsplit("/", 1)[-1].split("@")[0].split(":")[0]
    full = image.lower()
    for role, needles in _ROLES:
        if any(needle == name or name.startswith(needle + "-") or name.startswith(needle)
               or f"/{needle}" in full for needle in needles):
            return role
    return ""


# ---------------------------------------------------------------------------
# Análise de risco
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChangeContext:
    """Estado conhecido do servidor no momento da análise."""

    services: tuple[ServiceInfo, ...] = ()
    inventory: ContainerInventory | None = None
    listening_ports: tuple[tuple[int, str], ...] = ()  # (porta, processo)
    endpoints: tuple[str, ...] = ()
    critical_marked: bool = False
    connector_type: str = "direct"
    connector_label: str = "direto"
    mem_percent: float | None = None
    disk_percent: float | None = None
    container_admin: bool = False


def _depends_on(service: ServiceInfo) -> set[str]:
    """Serviços do Compose de que ``service`` depende (rótulo com.docker.compose.depends_on)."""
    raw = service.meta_value("depends_on")
    return {part.split(":", 1)[0].strip() for part in raw.split(",") if part.strip()}


def _endpoint_ports(endpoints: Iterable[str]) -> list[tuple[str, int]]:
    from core.endpoints import parse_endpoint

    result = []
    for endpoint in endpoints:
        try:
            spec = parse_endpoint(endpoint)
        except ValueError:
            continue
        result.append((spec.raw, spec.port))
    return result


def _port_text(ports: Sequence[tuple[str, int, int, str]]) -> str:
    return ", ".join(f"{(ip or '0.0.0.0')}:{hp}→{cp}/{proto}" for ip, hp, cp, proto in ports[:6])


def assess(action: ChangeAction, service: ServiceInfo | None, ctx: ChangeContext, *,
           inspect: InspectInfo | None = None, spec: ContainerSpec | None = None) -> Assessment:
    """O que pode acontecer se ``action`` for executada — antes de executar."""
    impacts: list[Impact] = []
    blockers: list[str] = []
    engine = (engines.ENGINE_OF_KIND.get(service.kind, "") if service is not None
              else spec.engine if spec is not None else "")
    target = service.name if service is not None else spec.name if spec is not None else "?"
    image = (inspect.image if inspect and inspect.image else service.description if service else
             spec.image if spec else "")
    role = container_role(image)

    if service is not None and not service.kind.manageable:
        blockers.append(f"{service.kind.label}: somente leitura (o kubelet gerencia estes contêineres)")
    if action in (ChangeAction.REMOVE, ChangeAction.CREATE, ChangeAction.RESTORE) and not ctx.container_admin:
        blockers.append("criar, restaurar e remover exigem \"container_admin\": true no servers.json")

    ports = list(inspect.ports) if inspect else [
        ("", h, c, "tcp") for h, c in engines.published_ports(service.meta_value("ports") if service else "")]
    if spec is not None and not ports:
        ports = [(p.host_ip, p.host_port, p.container_port, p.protocol) for p in spec.ports if p.host_port]

    if action.disruptive and service is not None:
        _availability(action, ports, ctx, role, impacts)
        _dependents(action, service, ctx, impacts)
        _role_impacts(action, role, ctx, impacts)
        if service.critical and ctx.critical_marked:
            impacts.append(Impact(Risk.HIGH, "Criticidade", "Marcado como CRÍTICO em critical_services",
                                  "Alertas e rotinas que dependem dele vão disparar."))
        if inspect is not None:
            _policy_and_orchestration(action, inspect, impacts)
    if action is ChangeAction.REMOVE and inspect is not None:
        _data_on_remove(inspect, service, impacts)
    if action in (ChangeAction.START, ChangeAction.CREATE, ChangeAction.RESTORE):
        _start_checks(action, service, ports, ctx, impacts, blockers, spec)
    if action is ChangeAction.PAUSE:
        impacts.append(Impact(Risk.MEDIUM, "Disponibilidade", "Conexões ficam penduradas até retomar",
                              "Pausar congela os processos: clientes não recebem erro, esperam até o timeout; "
                              "a memória continua ocupada e os healthchecks falham."))
    if spec is not None:
        _spec_checks(spec, impacts, blockers)

    if action.disruptive and service is not None and service.status is ServiceStatus.ACTIVE and not impacts:
        impacts.append(Impact(Risk.LOW, "Disponibilidade", f"{target} fica indisponível durante a mudança"))
    risk = max((i.level for i in impacts), default=Risk.LOW if action is not ChangeAction.UNPAUSE else Risk.NONE)
    protections = _protections(action, risk, role, inspect, service, engine)
    return Assessment(action=action, target=target, engine=engine, risk=risk,
                      impacts=tuple(sorted(impacts, key=lambda i: -i.level)), protections=protections,
                      steps=plan_steps(action, protections, service), blockers=tuple(blockers))


def _availability(action: ChangeAction, ports, ctx: ChangeContext, role: str, impacts: list[Impact]) -> None:
    if not ports:
        return
    brief = action is ChangeAction.RESTART
    impacts.append(Impact(
        Risk.LOW if brief else Risk.MEDIUM, "Disponibilidade",
        f"Portas publicadas {'caem por alguns segundos' if brief else 'ficam fora do ar'}: {_port_text(ports)}",
        "Quem acessa estes endereços recebe erro de conexão durante a mudança."))
    host_ports = {hp for _ip, hp, _cp, _proto in ports}
    proxy = role == "proxy"
    for raw, port in _endpoint_ports(ctx.endpoints):
        if port in host_ports or (proxy and port in (80, 443)):
            impacts.append(Impact(Risk.HIGH if not brief else Risk.MEDIUM, "Sites e APIs monitorados",
                                  f"{raw} usa a porta {port} deste contêiner", "O endpoint vai falhar e alertar."))


def _dependents(action: ChangeAction, service: ServiceInfo, ctx: ChangeContext, impacts: list[Impact]) -> None:
    compose_service = service.meta_value("compose_service")
    siblings = [s for s in ctx.services if s.kind.is_container and s.key != service.key and service.group
                and s.group == service.group]
    dependents = [s.name for s in siblings if compose_service and compose_service in _depends_on(s)]
    if dependents:
        impacts.append(Impact(
            Risk.HIGH if action is not ChangeAction.RESTART else Risk.MEDIUM, "Dependências",
            f"{len(dependents)} contêiner(es) dependem dele: {', '.join(dependents[:5])}",
            "Declarados com depends_on no Compose: podem falhar, reiniciar em loop ou devolver erro 5xx."))
    others = [s.name for s in siblings if s.name not in dependents and s.status is ServiceStatus.ACTIVE]
    if others:
        impacts.append(Impact(Risk.LOW, "Dependências", f"Mesma stack ({service.group}): {', '.join(others[:5])}",
                              "Podem usá-lo pela rede interna da stack."))


def _role_impacts(action: ChangeAction, role: str, ctx: ChangeContext, impacts: list[Impact]) -> None:
    brief = action is ChangeAction.RESTART
    if role == "banco":
        impacts.append(Impact(Risk.HIGH if not brief else Risk.MEDIUM, "Dados",
                              "Banco de dados / fila: aplicações conectadas perdem a conexão",
                              "Transações em andamento são interrompidas. O painel para com tempo de "
                              "desligamento maior (30 s) e recomenda backup dos volumes."))
    elif role == "proxy":
        impacts.append(Impact(Risk.HIGH if not brief else Risk.MEDIUM, "Disponibilidade",
                              "Proxy reverso: TODOS os sites e serviços atrás dele ficam fora",
                              "Rotas HTTP/HTTPS (e certificados) dependem dele."))
    elif role == "acesso":
        lockout = ctx.connector_type in ("cloudflared", "vpn", "jump", "socks5", "http", "command")
        impacts.append(Impact(
            Risk.CRITICAL if lockout else Risk.HIGH, "Acesso ao servidor",
            "Túnel/VPN: " + ("você pode PERDER o acesso a este servidor pelo painel"
                             if lockout else "o acesso remoto que passa por ele cai"),
            f"O painel chega a este servidor por: {ctx.connector_label}. Se este contêiner fizer parte do "
            "caminho, a conexão cai no meio da mudança e só volta com acesso por outro meio."))
    elif role == "painel":
        impacts.append(Impact(Risk.MEDIUM, "Gestão", "O painel web do Portainer fica indisponível"))
    elif role == "atualizador":
        impacts.append(Impact(Risk.LOW, "Gestão", "Atualizações automáticas (Watchtower) param"))
    elif role == "monitoramento":
        impacts.append(Impact(Risk.LOW, "Monitoramento", "Métricas, logs ou alertas deixam de ser coletados",
                              "Incidentes que ocorrerem durante a mudança podem passar despercebidos."))


def _policy_and_orchestration(action: ChangeAction, inspect: InspectInfo, impacts: list[Impact]) -> None:
    if inspect.label("com.docker.swarm.service.name"):
        impacts.append(Impact(Risk.HIGH, "Orquestração",
                              f"Gerenciado pelo Swarm ({inspect.label('com.docker.swarm.service.name')})",
                              "O Swarm recria a tarefa: para mudanças definitivas use docker service."))
    unit = inspect.label("PODMAN_SYSTEMD_UNIT")
    if unit:
        impacts.append(Impact(Risk.MEDIUM, "Orquestração", f"Gerenciado pelo systemd ({unit})",
                              "O systemd pode reiniciá-lo; para parar de vez, pare a unit na aba Serviços."))
    if action is ChangeAction.STOP:
        if inspect.restart_policy == "always":
            impacts.append(Impact(Risk.MEDIUM, "Orquestração", "Política de reinício \"always\"",
                                  "Ele volta sozinho quando o Docker reiniciar (ex.: reboot do servidor)."))
        elif inspect.restart_policy == "unless-stopped":
            impacts.append(Impact(Risk.LOW, "Orquestração", "Fica parado até você iniciar de novo",
                                  "Política \"unless-stopped\": nem um reboot o traz de volta."))
    if inspect.network_mode.startswith("container:"):
        impacts.append(Impact(Risk.MEDIUM, "Rede", "Compartilha a rede de outro contêiner",
                              f"network_mode {inspect.network_mode}."))


def _data_on_remove(inspect: InspectInfo, service: ServiceInfo | None, impacts: list[Impact]) -> None:
    if inspect.size_rw:
        impacts.append(Impact(Risk.HIGH, "Dados",
                              f"{_fmt_size(inspect.size_rw)} gravados DENTRO do contêiner serão perdidos",
                              "Arquivos fora de volumes somem com o contêiner. O snapshot (commit) os preserva."))
    if inspect.anonymous_volumes:
        impacts.append(Impact(Risk.MEDIUM, "Dados", f"{len(inspect.anonymous_volumes)} volume(s) anônimo(s) "
                              "ficam órfãos", "Os dados continuam no disco, mas sem nome fácil de achar. A "
                              "restauração os religa pelo identificador."))
    if inspect.volumes:
        impacts.append(Impact(Risk.LOW, "Dados", f"Volumes mantidos: {', '.join(inspect.volumes[:5])}",
                              "Remover o contêiner não apaga volumes nomeados."))
    project = inspect.label("com.docker.compose.project")
    if project:
        workdir = inspect.label("com.docker.compose.project.working_dir")
        impacts.append(Impact(Risk.MEDIUM, "Orquestração", f"Criado pelo Compose (projeto {project})",
                              f"Para recriar como o Compose faria: docker compose up -d em {workdir or 'seu diretório'}"
                              ". A restauração do painel recria o contêiner com a mesma definição."))


def _start_checks(action: ChangeAction, service: ServiceInfo | None, ports, ctx: ChangeContext,
                  impacts: list[Impact], blockers: list[str], spec: ContainerSpec | None) -> None:
    listening = {port: process for port, process in ctx.listening_ports}
    used_by_containers: dict[int, str] = {}
    for other in ctx.services:
        if other.kind.is_container and other.status is ServiceStatus.ACTIVE and (service is None
                                                                                  or other.key != service.key):
            for host_port, _cp in engines.published_ports(other.meta_value("ports")):
                used_by_containers[host_port] = other.name
    for _ip, host_port, _cp, _proto in ports:
        owner = used_by_containers.get(host_port) or (listening.get(host_port) if host_port in listening else None)
        if owner is not None:
            detail = f"em uso por {owner}" if owner else "já está em uso no servidor"
            blockers.append(f"porta {host_port} {detail}")
            impacts.append(Impact(Risk.HIGH, "Conflito", f"Porta {host_port} {detail}",
                                  "O motor recusaria iniciar: libere a porta ou troque o mapeamento."))
    if service is not None and service.group:
        needed = _depends_on(service)
        stopped = [s.name for s in ctx.services if s.group == service.group and s.status is not ServiceStatus.ACTIVE
                   and s.meta_value("compose_service") in needed]
        if stopped:
            impacts.append(Impact(Risk.MEDIUM, "Dependências", f"Depende de contêineres parados: {', '.join(stopped)}",
                                  "Inicie-os antes, ou ele pode falhar ao subir."))
    if service is not None and "exited (" in service.sub_state.lower() and "(0)" not in service.sub_state:
        impacts.append(Impact(Risk.LOW, "Histórico", f"Parou com erro: {service.sub_state}",
                              "Se voltar a cair, o painel mostra as últimas linhas do log."))
    if ctx.mem_percent is not None and ctx.mem_percent >= 90:
        impacts.append(Impact(Risk.MEDIUM, "Recursos", f"Memória do servidor em {ctx.mem_percent:.0f}%",
                              "Um contêiner novo pode acionar o OOM killer e derrubar outros processos."))
    if ctx.disk_percent is not None and ctx.disk_percent >= 90:
        impacts.append(Impact(Risk.MEDIUM, "Recursos", f"Disco raiz em {ctx.disk_percent:.0f}%",
                              "Imagens e logs novos podem encher o disco."))
    if action in (ChangeAction.CREATE, ChangeAction.RESTORE) and spec is not None:
        existing = {s.name for s in ctx.services if s.kind.is_container}
        if spec.name in existing:
            blockers.append(f"já existe um contêiner chamado {spec.name}"
                            + (" — remova-o antes de restaurar" if action is ChangeAction.RESTORE else ""))


def _spec_checks(spec: ContainerSpec, impacts: list[Impact], blockers: list[str]) -> None:
    if spec.privileged:
        impacts.append(Impact(Risk.CRITICAL, "Segurança", "Modo privilegiado (--privileged)",
                              "O contêiner terá acesso total ao host."))
    for mount in spec.mounts:
        if mount.kind != "bind":
            continue
        source = mount.source.rstrip("/") or "/"
        if source in ("/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev") or source.startswith(("/etc/",
                                                                                                    "/root/")):
            impacts.append(Impact(Risk.CRITICAL, "Segurança", f"Monta {mount.source} do host",
                                  "Acesso a arquivos do sistema: equivale a acesso root ao servidor."))
        if source.endswith("docker.sock") or source.endswith("podman.sock"):
            impacts.append(Impact(Risk.CRITICAL, "Segurança", f"Monta o socket do motor ({mount.source})",
                                  "Quem controla o contêiner controla todos os outros e o host."))
    if spec.network == "host":
        impacts.append(Impact(Risk.MEDIUM, "Rede", "Rede do host (--network host)",
                              "As portas do contêiner abrem direto no servidor, sem isolamento."))
    exposed = [p for p in spec.ports if p.host_port and p.host_ip in ("", "0.0.0.0", "::")]
    if exposed:
        impacts.append(Impact(Risk.LOW, "Rede", "Portas abertas em todas as interfaces: "
                              + ", ".join(str(p.host_port) for p in exposed[:6]),
                              "O Docker publica portas por fora do UFW: use 127.0.0.1: para acesso só local."))


def _fmt_size(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}".replace(".", ",")
        value /= 1024
    return str(value)


def _protections(action: ChangeAction, risk: Risk, role: str, inspect: InspectInfo | None,
                 service: ServiceInfo | None, engine: str) -> tuple[Protection, ...]:
    if action in (ChangeAction.CREATE, ChangeAction.RESTORE, ChangeAction.UNPAUSE) or service is None:
        return ()
    protections = [Protection(
        "definition", "Salvar a definição do contêiner neste PC",
        "inspect completo + comando para recriar (variáveis sensíveis protegidas pelo Windows). "
        "Permite restaurar o contêiner se algo der errado.",
        default=True, required=risk >= Risk.MEDIUM)]
    has_volumes = bool(inspect and (inspect.volumes or inspect.anonymous_volumes))
    if action is ChangeAction.REMOVE:
        rw = inspect.size_rw if inspect else None
        protections.append(Protection(
            "snapshot", "Snapshot do contêiner (commit) no servidor",
            "Cria a imagem firawynix/backup-<nome>:<data> com os arquivos gravados dentro do contêiner.",
            default=rw is None or rw > 0, available=engine in engines.CLI_ENGINES))
    if action in (ChangeAction.STOP, ChangeAction.REMOVE, ChangeAction.RESTART):
        protections.append(Protection(
            "volumes", "Backup dos volumes (tar.gz no servidor)",
            "Feito com o contêiner PARADO, para os dados ficarem consistentes"
            + (" (o reinício acontece depois do backup)." if action is ChangeAction.RESTART else "."),
            default=role == "banco" and has_volumes, available=has_volumes and engine in engines.CLI_ENGINES,
            reason="" if has_volumes else "sem volumes"))
    return tuple(protections)


def plan_steps(action: ChangeAction, protections: Sequence[Protection], service: ServiceInfo | None,
               chosen: Iterable[str] | None = None) -> tuple[str, ...]:
    """Roteiro exibido antes de executar (o executor segue a mesma ordem)."""
    ids = set(chosen) if chosen is not None else {p.id for p in protections if p.default and p.available}
    ids |= {p.id for p in protections if p.required}
    running = service is not None and service.status in (ServiceStatus.ACTIVE, ServiceStatus.ACTIVATING)
    steps = ["Conferir o estado atual e as pré-condições"]
    if "definition" in ids:
        steps.append("Salvar a definição do contêiner neste PC")
    if action is ChangeAction.STOP:
        steps += ["Parar com desligamento gracioso", "Confirmar que parou"]
    elif action is ChangeAction.RESTART:
        steps += ["Parar com desligamento gracioso"] if "volumes" in ids else []
    elif action is ChangeAction.REMOVE and running:
        steps += ["Parar com desligamento gracioso", "Confirmar que parou"]
    if "snapshot" in ids:
        steps.append("Snapshot do contêiner (commit)")
    if "volumes" in ids:
        steps.append("Backup dos volumes com o contêiner parado")
    steps += {
        ChangeAction.START: ["Iniciar", "Confirmar que está rodando e estável"],
        ChangeAction.RESTART: ["Iniciar" if "volumes" in ids else "Reiniciar",
                               "Confirmar que está rodando e estável"],
        ChangeAction.PAUSE: ["Pausar", "Confirmar o estado"],
        ChangeAction.UNPAUSE: ["Retomar", "Confirmar o estado"],
        ChangeAction.REMOVE: ["Remover o contêiner (volumes são mantidos)", "Confirmar a remoção"],
        ChangeAction.CREATE: ["Baixar a imagem, se necessário", "Criar e iniciar",
                              "Confirmar que está rodando e estável"],
        ChangeAction.RESTORE: ["Conferir a imagem (original ou snapshot)", "Recriar com a definição salva",
                               "Confirmar que está rodando e estável"],
        ChangeAction.STOP: [],
    }[action]
    steps.append("Registrar no histórico de mudanças (com opção de iniciar/restaurar)")
    return tuple(steps)


# ---------------------------------------------------------------------------
# Especificação de contêiner (criar / restaurar)
# ---------------------------------------------------------------------------

RESTART_POLICIES = ("no", "always", "unless-stopped", "on-failure")
_ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,254}")
_VOLUME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
_NETWORK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
_LABEL_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,254}")
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})?")
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}")
_MEMORY_RE = re.compile(r"[1-9][0-9]{0,12}[bkmg]?", re.IGNORECASE)
_CPUS_RE = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3})?")
_CAP_RE = re.compile(r"[A-Z_]{2,32}")
_SECRET_KEY_RE = re.compile(r"PASS|SECRET|TOKEN|KEY|PWD|CREDENTIAL|AUTH|PRIVATE|CERT", re.IGNORECASE)


@dataclass(frozen=True)
class PortMap:
    container_port: int
    host_port: int | None = None
    host_ip: str = ""
    protocol: str = "tcp"

    def arg(self) -> str:
        suffix = "" if self.protocol == "tcp" else f"/{self.protocol}"
        if self.host_port is None:
            return f"{self.container_port}{suffix}"
        ip = f"[{self.host_ip}]:" if ":" in self.host_ip else (f"{self.host_ip}:" if self.host_ip else "")
        return f"{ip}{self.host_port}:{self.container_port}{suffix}"


@dataclass(frozen=True)
class MountSpec:
    kind: str  # volume | bind
    source: str
    target: str
    read_only: bool = False

    def arg(self) -> str:
        return f"{self.source}:{self.target}" + (":ro" if self.read_only else "")


@dataclass(frozen=True)
class ContainerSpec:
    engine: str
    name: str
    image: str
    ports: tuple[PortMap, ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    mounts: tuple[MountSpec, ...] = ()
    restart: str = "unless-stopped"
    network: str = ""
    extra_networks: tuple[str, ...] = ()
    command: tuple[str, ...] = ()
    entrypoint: tuple[str, ...] | None = None
    labels: tuple[tuple[str, str], ...] = ()
    user: str = ""
    workdir: str = ""
    hostname: str = ""
    memory: str = ""
    cpus: str = ""
    extra_hosts: tuple[str, ...] = ()
    privileged: bool = False
    cap_add: tuple[str, ...] = ()
    #: O que o inspect tinha e a recriação não reproduz (exibido ao usuário).
    notes: tuple[str, ...] = field(default=(), compare=False)


def _absolute_path(value: str, what: str) -> str:
    if not value.startswith("/") or "\n" in value or "\0" in value or "/../" in f"{value}/" or ":" in value:
        raise ValueError(f"{what} inválido: {value!r} (use um caminho absoluto, sem '..' nem ':')")
    return value


def validate_spec(spec: ContainerSpec) -> ContainerSpec:
    """Tudo o que vai para a linha de comando passa por aqui (além do shlex.quote)."""
    if spec.engine not in engines.CLI_ENGINES:
        raise ValueError(f"Motor sem suporte a criar contêineres: {spec.engine}")
    validate_container_name(spec.name)
    engines.validate_image_ref(spec.image)
    if spec.restart not in RESTART_POLICIES and not re.fullmatch(r"on-failure:[0-9]{1,3}", spec.restart):
        raise ValueError(f"Política de reinício inválida: {spec.restart}")
    for port in spec.ports:
        if not 1 <= port.container_port <= 65535 or (port.host_port is not None and not 1 <= port.host_port <= 65535):
            raise ValueError(f"Porta inválida: {port.arg()}")
        if port.protocol not in ("tcp", "udp", "sctp"):
            raise ValueError(f"Protocolo inválido: {port.protocol}")
        if port.host_ip:
            ipaddress.ip_address(port.host_ip)
    for key, _value in spec.env:
        if not _ENV_KEY_RE.fullmatch(key):
            raise ValueError(f"Variável inválida: {key!r}")
    for mount in spec.mounts:
        _absolute_path(mount.target, "Destino do volume")
        if mount.kind == "volume":
            if not _VOLUME_RE.fullmatch(mount.source):
                raise ValueError(f"Nome de volume inválido: {mount.source!r}")
        elif mount.kind == "bind":
            _absolute_path(mount.source, "Pasta do host")
        else:
            raise ValueError(f"Tipo de montagem inválido: {mount.kind}")
    for name in (spec.network, *spec.extra_networks):
        if name and not _NETWORK_RE.fullmatch(name):
            raise ValueError(f"Rede inválida: {name!r}")
    for key, _value in spec.labels:
        if not _LABEL_KEY_RE.fullmatch(key):
            raise ValueError(f"Rótulo inválido: {key!r}")
    checks = ((spec.user, _USER_RE, "Usuário"), (spec.hostname, _HOSTNAME_RE, "Hostname"),
              (spec.memory, _MEMORY_RE, "Memória"), (spec.cpus, _CPUS_RE, "CPUs"))
    for value, regex, what in checks:
        if value and not regex.fullmatch(value):
            raise ValueError(f"{what} inválido: {value!r}")
    if spec.workdir:
        _absolute_path(spec.workdir, "Diretório de trabalho")
    for cap in spec.cap_add:
        if not _CAP_RE.fullmatch(cap):
            raise ValueError(f"Capability inválida: {cap!r}")
    for entry in spec.extra_hosts:
        host, _, address = entry.partition(":")
        if not _HOSTNAME_RE.fullmatch(host) or not address:
            raise ValueError(f"extra_hosts inválido: {entry!r}")
        if address != "host-gateway":
            ipaddress.ip_address(address)
    for arg in (*spec.command, *(spec.entrypoint or ())):
        if "\0" in arg:
            raise ValueError("Comando com caractere nulo")
    return spec


def run_args(spec: ContainerSpec) -> list[str]:
    """Argumentos do ``<motor> run -d`` (sem o executável), já validados."""
    validate_spec(spec)
    args = ["run", "-d", "--name", spec.name]
    if spec.restart and spec.restart != "no":
        args += ["--restart", spec.restart]
    for port in spec.ports:
        args += ["-p", port.arg()]
    for key, value in spec.env:
        args += ["-e", f"{key}={value}"]
    for mount in spec.mounts:
        args += ["-v", mount.arg()]
    if spec.network:
        args += ["--network", spec.network]
    for key, value in spec.labels:
        args += ["--label", f"{key}={value}"]
    for flag, value in (("--user", spec.user), ("--workdir", spec.workdir), ("--hostname", spec.hostname),
                        ("--memory", spec.memory), ("--cpus", spec.cpus)):
        if value:
            args += [flag, value]
    for entry in spec.extra_hosts:
        args += ["--add-host", entry]
    if spec.privileged:
        args.append("--privileged")
    for cap in spec.cap_add:
        args += ["--cap-add", cap]
    if spec.entrypoint is not None:
        args += ["--entrypoint", spec.entrypoint[0] if spec.entrypoint else ""]
    args.append(spec.image)
    if spec.entrypoint and len(spec.entrypoint) > 1:
        args += list(spec.entrypoint[1:])
    args += list(spec.command)
    return args


def shell_join(executable: str, args: Sequence[str]) -> str:
    return executable + " " + " ".join(shlex.quote(a) for a in args)


def masked_args(args: Sequence[str]) -> list[str]:
    """Para exibir/gravar em texto: esconde valores de variáveis com cara de segredo."""
    masked = []
    for index, arg in enumerate(args):
        if index and args[index - 1] == "-e" and "=" in arg:
            key, _, _value = arg.partition("=")
            if _SECRET_KEY_RE.search(key):
                arg = f"{key}=<oculto>"
        masked.append(arg)
    return masked


def spec_from_inspect(data: dict, engine: str, image_config: dict | None = None) -> ContainerSpec:
    """Definição para recriar o contêiner a partir do ``inspect`` (runlike).

    ``image_config`` (``Config`` do inspect da imagem) evita repetir o que já vem
    da imagem (ENV, CMD, ENTRYPOINT e rótulos), para a recriação acompanhar a imagem."""
    config = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    image_config = image_config or {}
    notes: list[str] = []
    name = str(data.get("Name") or "").lstrip("/")
    image = str(config.get("Image") or data.get("ImageName") or "")

    image_env = set(image_config.get("Env") or [])
    env = []
    for item in config.get("Env") or []:
        if item in image_env or "=" not in item:
            continue
        key, _, value = item.partition("=")
        if _ENV_KEY_RE.fullmatch(key):
            env.append((key, value))

    ports = []
    for key, bindings in sorted((host.get("PortBindings") or {}).items()):
        container_port, _, proto = str(key).partition("/")
        if not container_port.isdigit():
            continue
        for binding in bindings or [{}]:
            host_port = str((binding or {}).get("HostPort") or "")
            ports.append(PortMap(int(container_port), int(host_port) if host_port.isdigit() else None,
                                 str((binding or {}).get("HostIp") or ""), proto or "tcp"))

    mounts = []
    for mount in data.get("Mounts") or []:
        kind, target = mount.get("Type"), str(mount.get("Destination") or "")
        read_only = mount.get("RW") is False
        if kind == "volume" and mount.get("Name"):
            mounts.append(MountSpec("volume", str(mount["Name"]), target, read_only))
        elif kind == "bind" and mount.get("Source"):
            mounts.append(MountSpec("bind", str(mount["Source"]), target, read_only))
        else:
            notes.append(f"montagem {kind or '?'} em {target} não é recriada")

    policy = host.get("RestartPolicy") or {}
    restart = str(policy.get("Name") or "no")
    if restart == "on-failure" and policy.get("MaximumRetryCount"):
        restart = f"on-failure:{int(policy['MaximumRetryCount'])}"
    if restart not in RESTART_POLICIES and not restart.startswith("on-failure"):
        restart = "no"

    mode = str(host.get("NetworkMode") or "")
    networks = list(((data.get("NetworkSettings") or {}).get("Networks") or {}).keys())
    network, extra = "", []
    if mode in ("host", "none"):
        network = mode
    elif mode.startswith("container:"):
        notes.append(f"network_mode {mode} não é recriado")
    elif mode and mode not in ("default", "bridge", "slirp4netns", "pasta", "private"):
        network = mode
    elif networks and networks[0] not in ("bridge", "podman"):
        network = networks[0]
    extra = [n for n in networks if n != network and n not in ("bridge", "podman", "host", "none")]

    image_labels = image_config.get("Labels") or {}
    labels = tuple((str(k), str(v)) for k, v in sorted((config.get("Labels") or {}).items())
                   if image_labels.get(k) != v and _LABEL_KEY_RE.fullmatch(str(k)))
    command = tuple(config.get("Cmd") or ())
    if image_config and list(command) == list(image_config.get("Cmd") or []):
        command = ()
    entrypoint = config.get("Entrypoint")
    entry: tuple[str, ...] | None = tuple(entrypoint) if isinstance(entrypoint, list) else None
    if image_config and entry is not None and list(entry) == list(image_config.get("Entrypoint") or []):
        entry = None
    container_id = str(data.get("Id") or "")
    hostname = str(config.get("Hostname") or "")
    if hostname and (container_id.startswith(hostname) or hostname == name):
        hostname = ""
    memory = int(host.get("Memory") or 0)
    nano = int(host.get("NanoCpus") or 0)
    for key, label in (("Devices", "dispositivos"), ("Tmpfs", "tmpfs"), ("Sysctls", "sysctls"),
                       ("SecurityOpt", "opções de segurança"), ("Ulimits", "ulimits"), ("Dns", "DNS")):
        if host.get(key):
            notes.append(f"{label} não são recriados")
    if (config.get("Healthcheck") or None) and config.get("Healthcheck") != image_config.get("Healthcheck"):
        notes.append("healthcheck personalizado não é recriado")
    user = str(config.get("User") or "")
    workdir = str(config.get("WorkingDir") or "")
    if image_config:
        user = "" if user == str(image_config.get("User") or "") else user
        workdir = "" if workdir == str(image_config.get("WorkingDir") or "") else workdir
    spec = ContainerSpec(
        engine=engine, name=name, image=image, ports=tuple(ports), env=tuple(env), mounts=tuple(mounts),
        restart=restart, network=network, extra_networks=tuple(extra), command=command, entrypoint=entry,
        labels=labels, user=user if _USER_RE.fullmatch(user or "x") else "", workdir=workdir if workdir.startswith("/")
        else "", hostname=hostname if _HOSTNAME_RE.fullmatch(hostname or "x") else "",
        memory=f"{memory}b" if memory else "", cpus=f"{nano / 1e9:g}" if nano else "",
        extra_hosts=tuple(h for h in host.get("ExtraHosts") or [] if isinstance(h, str) and ":" in h),
        privileged=bool(host.get("Privileged")),
        cap_add=tuple(c.upper().removeprefix("CAP_") for c in host.get("CapAdd") or [] if isinstance(c, str)),
        notes=tuple(notes))
    return spec


def with_image(spec: ContainerSpec, image: str) -> ContainerSpec:
    return replace(spec, image=image)


# ---------------------------------------------------------------------------
# Campos do formulário "Novo contêiner"
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r"(?:(?P<ip>\[[0-9a-fA-F:]+\]|[0-9]+\.[0-9.]+):)?"
                      r"(?:(?P<host>[0-9]{1,5}):)?(?P<container>[0-9]{1,5})(?:/(?P<proto>tcp|udp|sctp))?")


def parse_ports(text: str) -> tuple[PortMap, ...]:
    """``8080:80, 127.0.0.1:5432:5432/tcp, 53:53/udp`` (vírgulas ou linhas)."""
    ports = []
    for item in re.split(r"[,\n]+", text or ""):
        item = item.strip()
        if not item:
            continue
        match = _PORT_RE.fullmatch(item)
        if not match:
            raise ValueError(f"Porta inválida: {item!r} (use host:contêiner, ex.: 8080:80)")
        ip = (match["ip"] or "").strip("[]")
        ports.append(PortMap(int(match["container"]), int(match["host"]) if match["host"] else None, ip,
                             match["proto"] or "tcp"))
    return tuple(ports)


def parse_env(text: str) -> tuple[tuple[str, str], ...]:
    """Uma variável por linha: ``CHAVE=valor`` (linhas vazias e # são ignoradas)."""
    env = []
    for number, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not _ENV_KEY_RE.fullmatch(key.strip()):
            raise ValueError(f"Variável inválida na linha {number}: {line!r} (use CHAVE=valor)")
        env.append((key.strip(), value))
    return tuple(env)


def parse_mounts(text: str) -> tuple[MountSpec, ...]:
    """``dados:/var/lib/app, /srv/site:/usr/share/nginx/html:ro`` — nome = volume, / = pasta do host."""
    mounts = []
    for item in re.split(r"[,\n]+", text or ""):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        read_only = parts[-1] in ("ro", "rw") and parts.pop() == "ro"
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"Volume inválido: {item!r} (use origem:destino[:ro])")
        source, target = parts
        mounts.append(MountSpec("bind" if source.startswith("/") else "volume", source, target, read_only))
    return tuple(mounts)


def parse_command(text: str) -> tuple[str, ...]:
    try:
        return tuple(shlex.split(text or ""))
    except ValueError as exc:
        raise ValueError(f"Comando inválido: {exc}") from exc


# ---------------------------------------------------------------------------
# Comandos auxiliares (executados pelo change_runner)
# ---------------------------------------------------------------------------

HELPER_IMAGE = "docker.io/library/alpine:3.20"
#: Script opcional instalado pelo administrador para backups via sudo (docs/firawynix-volume-backup).
BACKUP_SCRIPT = "/usr/local/sbin/firawynix-volume-backup"
_JOB_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{3,63}")
JOBS_DIR = "$HOME/.cache/firawynix/jobs"


@dataclass(frozen=True)
class ContainerState:
    status: str
    exit_code: int | None
    restarts: int | None
    health: str = ""

    @property
    def running(self) -> bool:
        return self.status == "running"


def state_from_inspect(data: dict | None) -> ContainerState | None:
    """Estado a partir do JSON do inspect (Docker, Podman e nerdctl; sem templates Go, que
    variam entre os motores)."""
    if not data:
        return None
    state = data.get("State") or {}
    health = state.get("Health") or state.get("Healthcheck") or {}
    exit_code = state.get("ExitCode")
    restarts = data.get("RestartCount")
    status = str(state.get("Status") or "").lower()
    if not status:
        status = "running" if state.get("Running") else "paused" if state.get("Paused") else "exited"
    return ContainerState(status, exit_code if isinstance(exit_code, int) else None,
                          restarts if isinstance(restarts, int) else None,
                          str(health.get("Status") or "") if isinstance(health, dict) else "")


def validate_job_id(job_id: str) -> str:
    if not _JOB_ID_RE.fullmatch(job_id or ""):
        raise ValueError(f"Identificador de tarefa inválido: {job_id!r}")
    return job_id


def build_job_start(job_id: str, command: str) -> str:
    """Roda ``command`` em segundo plano no servidor (sobrevive ao canal SSH) — para passos
    que passam do limite de 5 s por comando (parada graciosa, backup, pull)."""
    job = validate_job_id(job_id)
    # Subshell: um "exit" dentro do comando não pode pular a gravação do código de saída.
    body = shlex.quote(f'( {command} ); echo $? > "$0/exit"')
    return (f'd="{JOBS_DIR}/{job}"; rm -rf "$d"; mkdir -p "$d" || exit 1; '
            'if command -v setsid >/dev/null 2>&1; then S=setsid; else S=; fi; '
            f'nohup $S sh -c {body} "$d" > "$d/log" 2>&1 < /dev/null & echo started')


def build_job_poll(job_id: str) -> str:
    job = validate_job_id(job_id)
    return (f'd="{JOBS_DIR}/{job}"; if [ -f "$d/exit" ]; then echo "EXIT $(cat "$d/exit")"; '
            'elif [ -d "$d" ]; then echo RUNNING; else echo MISSING; fi; tail -c 1500 "$d/log" 2>/dev/null')


def build_job_cleanup(job_id: str) -> str:
    return f'rm -rf "{JOBS_DIR}/{validate_job_id(job_id)}"'


@dataclass(frozen=True)
class JobState:
    done: bool
    exit_code: int | None
    log: str
    missing: bool = False


def parse_job_poll(text: str) -> JobState:
    first, _, rest = text.partition("\n")
    first = first.strip()
    if first.startswith("EXIT"):
        code = first[4:].strip()
        return JobState(True, int(code) if code.lstrip("-").isdigit() else None, rest.strip())
    if first == "MISSING":
        return JobState(True, None, "", missing=True)
    return JobState(False, None, rest.strip())


def backup_file_name(container: str, volume: str, stamp: str) -> str:
    name = f"{container}_{volume}_{stamp}.tar.gz"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\.tar\.gz", name):
        raise ValueError(f"Nome de backup inválido: {name!r}")
    return name


def volume_backup_args(volume: str, directory: str, file_name: str, owner: str = "") -> list[str]:
    """``run`` do contêiner auxiliar (alpine) que compacta o volume, somente leitura, sem rede."""
    if not _VOLUME_RE.fullmatch(volume):
        raise ValueError(f"Volume inválido: {volume!r}")
    _absolute_path(directory, "Pasta de backup")
    script = f"tar czf /backup/{shlex.quote(file_name)} -C /data ."
    if owner and re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", owner):
        script += f" && chown {owner} /backup/{shlex.quote(file_name)}"
    return ["run", "--rm", "--network", "none", "-v", f"{volume}:/data:ro", "-v", f"{directory}:/backup",
            HELPER_IMAGE, "sh", "-c", script]


def snapshot_image(container: str, stamp: str) -> str:
    return engines.validate_image_ref(f"firawynix/backup-{container.lower()}:{stamp}")


def compose_hint(labels: Iterable[tuple[str, str]]) -> str:
    data = dict(labels)
    project = data.get("com.docker.compose.project")
    service = data.get("com.docker.compose.service")
    workdir = data.get("com.docker.compose.project.working_dir")
    if not project:
        return ""
    return f"cd {shlex.quote(workdir or '.')} && docker compose -p {shlex.quote(project)} up -d " \
           f"{shlex.quote(service or '')}".rstrip()


def context_from_snapshot(snapshot, server) -> ChangeContext:
    """Monta o contexto da análise a partir do último snapshot e da configuração."""
    services = tuple(snapshot.services) if snapshot else ()
    listening = ()
    if snapshot is not None and snapshot.network is not None:
        listening = tuple(dict.fromkeys((s.port, s.process) for s in snapshot.network.listening
                                        if s.proto.startswith("tcp") and not s.address.startswith("127.")))
    metrics = snapshot.metrics if snapshot else None
    root = metrics.root_disk if metrics else None
    connector = getattr(server, "connector", None)
    return ChangeContext(
        services=services, inventory=snapshot.containers if snapshot else None, listening_ports=listening,
        endpoints=tuple(server.endpoints), critical_marked=tuple(server.critical_services) != ("*",),
        connector_type=connector.type if connector else "direct",
        connector_label=connector.label(server.host) if connector else "direto",
        mem_percent=metrics.mem_percent if metrics else None, disk_percent=root.use_percent if root else None,
        container_admin=server.container_admin)


def kind_is_container(kind: ServiceKind) -> bool:
    return kind.manageable


# ---------------------------------------------------------------------------
# Unidades systemd (aviso antes de parar/reiniciar)
# ---------------------------------------------------------------------------

_UNIT_RULES: tuple[tuple[tuple[str, ...], Risk, str, str], ...] = (
    (("ssh", "sshd", "openssh-server"), Risk.CRITICAL, "Acesso ao servidor",
     "O SSH para: o painel e você perdem o acesso a este servidor"),
    (("networking", "systemd-networkd", "networkmanager", "network"), Risk.CRITICAL, "Acesso ao servidor",
     "A rede do servidor reinicia: a conexão pode cair e não voltar se a configuração estiver errada"),
    (("docker", "containerd", "podman", "crio", "k3s", "k3s-agent", "kubelet", "snap.microk8s.daemon-kubelite"),
     Risk.HIGH, "Contêineres", "Todos os contêineres/pods deste motor param junto"),
    (("nginx", "apache2", "httpd", "caddy", "haproxy", "traefik", "lighttpd", "varnish"), Risk.HIGH,
     "Disponibilidade", "Os sites servidos por ele ficam fora do ar"),
    (("postgresql", "mysql", "mariadb", "mongod", "redis", "redis-server", "elasticsearch", "rabbitmq-server",
      "memcached", "clickhouse-server"), Risk.HIGH, "Dados", "Aplicações que usam o banco perdem a conexão"),
    (("ufw", "firewalld", "nftables", "iptables", "netfilter-persistent"), Risk.HIGH, "Segurança",
     "O firewall é desligado/recarregado: portas podem ficar expostas (ou o acesso bloqueado)"),
    (("cloudflared", "tailscaled", "wg-quick", "openvpn", "openvpn-server", "zerotier-one", "netbird"),
     Risk.HIGH, "Acesso ao servidor", "Túnel/VPN: o acesso remoto que passa por ele cai"),
    (("fail2ban", "crowdsec"), Risk.MEDIUM, "Segurança", "A proteção contra força bruta fica desligada"),
    (("libvirtd", "virtqemud"), Risk.HIGH, "VMs", "A gerência das VMs fica indisponível"),
    (("cron", "crond"), Risk.LOW, "Agendamentos", "Tarefas agendadas não rodam enquanto estiver parado"),
)


def unit_impacts(unit: str, action: str, connector_type: str = "direct") -> list[Impact]:
    """Riscos conhecidos de parar/reiniciar uma unidade systemd (``action``: stop | restart | start)."""
    if action == "start":
        return []
    base = unit.rsplit(".", 1)[0].split("@", 1)[0].lower()
    impacts = []
    for names, risk, area, title in _UNIT_RULES:
        if base not in names:
            continue
        level = risk
        if area == "Acesso ao servidor" and base not in ("ssh", "sshd", "openssh-server", "networking",
                                                          "systemd-networkd", "networkmanager", "network"):
            level = Risk.CRITICAL if connector_type in ("cloudflared", "vpn", "jump") else Risk.HIGH
            if level is Risk.CRITICAL:
                title = "Túnel/VPN: o painel chega a este servidor por ele — você pode PERDER o acesso"
        if action == "restart":
            level = Risk(max(Risk.MEDIUM, level - 1)) if level < Risk.CRITICAL else Risk.HIGH
            title += " (por alguns segundos — se a configuração estiver inválida, não volta)"
        impacts.append(Impact(level, area, title))
    return impacts
