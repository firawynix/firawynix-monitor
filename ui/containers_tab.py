"""Aba "Contêineres": painel próprio e idêntico para qualquer motor — Docker,
Podman, containerd (nerdctl), CRI-O/containerd (crictl), Buildah e Skopeo.

As diferenças entre os motores ficam em ``core/containers.py``; aqui tudo chega
no mesmo modelo (contêineres, imagens, volumes, redes, builds e uso de disco),
com as mesmas colunas e os mesmos botões. Painéis web de terceiros (Portainer,
Cockpit, Dockge...) são apenas detectados e abertos no navegador: nunca mudam
este layout.
"""

from __future__ import annotations

import datetime as dt
import re
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future
from typing import TYPE_CHECKING

import customtkinter as ctk

from core import containers as engines
from core.changes import ChangeAction
from core.models import (
    ContainerImage,
    ContainerInventory,
    EngineStatus,
    HostSnapshot,
    ImageUpdate,
    RuntimeState,
    ServiceAction,
    ServiceInfo,
    ServiceStatus,
)
from ui import theme
from ui.change_dialog import open_folder
from ui.tabs import Tab, _button, _matches, _search_entry, _set_state
from ui.widgets import (
    CARD_BG,
    GRAY,
    GREEN,
    RED,
    STATUS_COLORS,
    TEXT,
    YELLOW,
    Column,
    DataTable,
    Row,
    fmt_ago,
    fmt_bytes,
    fmt_pct,
)

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

VIEWS = ("Contêineres", "Imagens", "Volumes", "Redes", "Builds", "Disco", "Mudanças")
_OUTCOME_STATUS = {"ok": ServiceStatus.ACTIVE, "warning": ServiceStatus.DEGRADED, "error": ServiceStatus.FAILED,
                   "running": ServiceStatus.ACTIVATING}
_OUTCOME_TEXT = {"ok": "Concluída", "warning": "Com avisos", "error": "Falhou", "running": "Em andamento"}
_ACTION_TEXT = {"start": "Iniciar", "stop": "Parar", "restart": "Reiniciar", "pause": "Pausar", "unpause": "Retomar",
                "remove": "Remover", "create": "Criar", "restore": "Restaurar"}
ALL_ENGINES = "Todos os motores"
_CHIPS_PER_ROW = 3
_SELECTION_MAX = 90

# ---------------------------------------------------------------------------
# Funções puras (testadas sem abrir janelas)
# ---------------------------------------------------------------------------


def engine_of(service: ServiceInfo) -> str:
    return engines.ENGINE_OF_KIND.get(service.kind, service.kind.value)


def engine_label(engine_id: str) -> str:
    spec = engines.ENGINES.get(engine_id)
    return spec.label if spec else engine_id


_SHORT_LABELS = {"nerdctl": "containerd", "cri": "CRI · Kubernetes", "lxd": "LXD/Incus"}


def engine_short(engine_id: str) -> str:
    """Rótulo curto para colunas de tabela e filtros."""
    return _SHORT_LABELS.get(engine_id) or engine_label(engine_id)


def plural(count: int, singular: str, plural_form: str) -> str:
    return f"{count} {singular if count == 1 else plural_form}"


def is_paused(service: ServiceInfo) -> bool:
    return service.active_state.lower() == "paused" or "(paused)" in service.sub_state.lower()


def engine_badge(status: EngineStatus) -> tuple[str, tuple[str, str]]:
    """Texto e cor do "chip" de um motor na faixa superior (igual para todos)."""
    parts = [f"v{status.version}"] if status.version else []
    if status.rootless:
        parts.append("rootless")
    if status.mode == "off":
        return " · ".join([*parts, "desativado"]), GRAY
    if status.state is RuntimeState.DAEMON_DOWN:
        return " · ".join([*parts, "daemon parado"]), RED
    if status.state is RuntimeState.PERMISSION:
        return " · ".join([*parts, "sem permissão"]), YELLOW
    if status.state is RuntimeState.ERROR:
        return " · ".join([*parts, "erro"]), RED
    if status.installed is False or status.state is RuntimeState.NOT_INSTALLED:
        return "não instalado" if status.mode == "on" else "não encontrado", RED if status.mode == "on" else GRAY
    if status.installed is None:
        return "aguardando detecção", GRAY
    if status.role == "runtime":
        if status.state is RuntimeState.OK:
            parts.append(f"{status.running}/{status.containers} rodando")
        return " · ".join(parts) or "detectado", GREEN
    parts.append("builds" if status.role == "build" else "registros")
    return " · ".join(parts), GREEN


def visible_engines(inventory: ContainerInventory | None) -> list[EngineStatus]:
    """Motores exibidos: os detectados e os ligados à mão (mesmo se ausentes)."""
    if inventory is None:
        return []
    return [e for e in inventory.engines if e.installed or e.mode == "on"]


def selection_summary(selection: dict) -> str:
    if selection.get("mode") == "auto":
        disabled = [engine_short(e) for e in selection.get("disabled", ())]
        return "Auto-detecção" + (f" · ignorando {', '.join(disabled)}" if disabled else "")
    enabled = [engine_short(e) for e in selection.get("enabled", ())]
    return "Manual: " + (", ".join(enabled) if enabled else "nenhum motor")


_AGO_RE = re.compile(r"^(?:about\s+)?(\d+|an?|less than a)\s+(second|minute|hour|day|week|month|year)s?\s+ago$",
                     re.IGNORECASE)
_UNITS = {"second": ("segundo", "segundos"), "minute": ("minuto", "minutos"), "hour": ("hora", "horas"),
          "day": ("dia", "dias"), "week": ("semana", "semanas"), "month": ("mês", "meses"), "year": ("ano", "anos")}


def _ago(count: int, unit: str) -> str:
    singular, plural_form = _UNITS[unit]
    return f"há {count} {singular if count == 1 else plural_form}"


def fmt_age(seconds: float) -> str:
    """Idade relativa ("há 5 meses"), a mesma escala do Docker."""
    seconds = max(0.0, seconds)
    for unit, size in (("year", 365 * 86400), ("month", 30 * 86400), ("week", 7 * 86400), ("day", 86400),
                       ("hour", 3600), ("minute", 60)):
        if seconds >= size * (2 if unit in ("year", "month", "week") else 1):
            return _ago(int(seconds // size), unit)
    return "há instantes"


def fmt_created(value: str, now: float | None = None) -> str:
    """Criação da imagem no mesmo formato para todos os motores: o Docker informa
    "3 weeks ago"; Podman e containerd, data ISO 8601 ou timestamp."""
    value = (value or "").strip()
    if not value:
        return ""
    match = _AGO_RE.match(value)
    if match:
        amount, unit = match.group(1).lower(), match.group(2).lower()
        return _ago(1 if not amount.isdigit() else int(amount), unit)
    now = time.time() if now is None else now
    if value.isdigit():
        return fmt_age(now - int(value))
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00").replace(" +0000 UTC", "+00:00")
                                           .replace(" UTC", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return fmt_age(now - parsed.timestamp())


def update_text(update: ImageUpdate | None) -> tuple[str, str | None]:
    """Texto da coluna "Atualização" e a tag de cor da linha."""
    if update is None:
        return "", None
    if update.status == "nova versão":
        return "nova versão disponível", "warn"
    if update.status == "atualizada":
        return "em dia", None
    if update.status == "ignorada":
        return "não verificável", "muted"
    return f"não verificada: {update.detail}" if update.detail else "não verificada", "muted"


def update_targets(images: Sequence[ContainerImage]) -> list[ContainerImage]:
    """Uma consulta por referência (a mesma imagem pode estar em vários motores)."""
    unique: dict[str, ContainerImage] = {}
    for image in images:
        if engines.updatable(image):
            unique.setdefault(engines.normalize_ref(image.reference), image)
    return list(unique.values())


def ports_text(service: ServiceInfo) -> str:
    ports = engines.published_ports(service.meta_value("ports"))
    if ports:
        shown = ", ".join(f"{host}→{container}" for host, container in ports[:4])
        return shown + ("…" if len(ports) > 4 else "")
    return service.meta_value("ports")


def container_counts(services: Sequence[ServiceInfo]) -> dict[str, int]:
    running = sum(1 for s in services if s.status is ServiceStatus.ACTIVE)
    paused = sum(1 for s in services if is_paused(s))
    failed = sum(1 for s in services if s.status in (ServiceStatus.FAILED, ServiceStatus.DEGRADED))
    return {"total": len(services), "running": running, "paused": paused, "failed": failed,
            "stopped": len(services) - running - paused - failed}


def _truncate(text: str, limit: int = _SELECTION_MAX) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Aba
# ---------------------------------------------------------------------------


class _Tile(ctk.CTkFrame):
    """Bloco clicável de resumo (troca a visão), no estilo dos painéis de contêineres."""

    def __init__(self, master, title: str, command: Callable[[], None]) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG, border_width=2, border_color=CARD_BG)
        self._command = command
        self.title = ctk.CTkLabel(self, text=title.upper(), anchor="w", text_color=GRAY,
                                  font=ctk.CTkFont(size=11, weight="bold"))
        self.title.pack(fill="x", padx=14, pady=(6, 0))
        self.value = ctk.CTkLabel(self, text="—", anchor="w", height=26, font=ctk.CTkFont(size=20, weight="bold"))
        self.value.pack(fill="x", padx=14)
        self.detail = ctk.CTkLabel(self, text="", anchor="w", text_color=GRAY, font=ctk.CTkFont(size=12))
        self.detail.pack(fill="x", padx=14, pady=(0, 6))
        for widget in (self, self.title, self.value, self.detail):
            widget.bind("<Button-1>", lambda _e: self._command())
            widget.configure(cursor="hand2")

    def set(self, value: str, detail: str, color: tuple[str, str] | None = None) -> None:
        self.value.configure(text=value, text_color=color or TEXT)
        self.detail.configure(text=detail)

    def set_selected(self, selected: bool) -> None:
        self.configure(border_color=theme.ACCENT_BRIGHT if selected else CARD_BG)




_DISK_KINDS = {"Images": "Imagens", "Containers": "Contêineres", "Local Volumes": "Volumes locais",
               "Build Cache": "Cache de build"}
_DEFAULT_NETWORKS = {"bridge", "host", "none", "podman", "default"}


def reclaimable_bytes(inventory: ContainerInventory | None) -> int | None:
    """Espaço recuperável de imagens somado entre os motores (``system df``)."""
    from core.parsers import parse_size

    values = [parse_size(d.reclaimable.split("(")[0]) for d in (inventory.disk if inventory else ())
              if d.kind == "Images"]
    values = [v for v in values if v is not None]
    return sum(values) if values else None


class ContainersTab(Tab):
    title = "Contêineres"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._server: str | None = None
        self._inventory: ContainerInventory | None = None
        self._view = VIEWS[0]
        self._services: dict[str, ServiceInfo] = {}
        self._images: dict[str, ContainerImage] = {}
        self._volumes: dict[str, tuple[str, str, bool | None]] = {}
        self._names: dict[str, str] = {}
        #: servidor → referência normalizada → último resultado do skopeo
        self._updates: dict[str, dict[str, ImageUpdate]] = {}
        self._updates_at: dict[str, float] = {}
        self._update_future: Future | None = None
        self._update_server: str | None = None
        self._chips: dict[str, tuple[ctk.CTkFrame, ctk.CTkLabel, ctk.CTkLabel]] = {}
        self._chip_order: list[str] = []
        self._tools_key: tuple | None = None
        self._filter_ids: dict[str, str | None] = {ALL_ENGINES: None}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self._build_engines()
        self._build_tiles()
        self._build_toolbar()
        self._build_tables()
        self._build_actions()
        self._switch(VIEWS[0], render=False)

    # -- construção -------------------------------------------------------------

    def _build_engines(self) -> None:
        card = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)
        left = ctk.CTkFrame(card, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=(14, 12), pady=8)
        ctk.CTkLabel(left, text="MOTORES", anchor="w", text_color=GRAY,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w")
        self.mode_label = ctk.CTkLabel(left, text="", anchor="w", justify="left", wraplength=230,
                                       text_color=theme.ACCENT_TEXT, font=ctk.CTkFont(size=13, weight="bold"))
        self.mode_label.pack(anchor="w")
        self.detected_label = ctk.CTkLabel(left, text="", anchor="w", text_color=GRAY, font=ctk.CTkFont(size=12))
        self.detected_label.pack(anchor="w")
        self.chips = ctk.CTkFrame(card, fg_color="transparent")
        self.chips.grid(row=0, column=1, sticky="ew", pady=8)
        self.no_engines = ctk.CTkLabel(self.chips, text="", anchor="w", text_color=GRAY)
        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.grid(row=0, column=2, sticky="e", padx=(10, 14))
        self.btn_detect = _button(buttons, "Detectar agora", self._detect, "neutral", 124)
        self.btn_detect.pack(side="left", padx=(0, 8))
        _button(buttons, "Motores…", self._open_engines, width=104).pack(side="left")
        self.tools = ctk.CTkFrame(card, fg_color="transparent")
        self.tools.grid(row=1, column=0, columnspan=3, sticky="ew", padx=14, pady=(0, 8))
        self.tools.grid_remove()

    def _build_tiles(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.tiles: dict[str, _Tile] = {}
        for column, view in enumerate(VIEWS):
            row.grid_columnconfigure(column, weight=1, uniform="tile")
            tile = _Tile(row, view, lambda v=view: self._switch(v))
            last = column == len(VIEWS) - 1
            tile.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 4, 0 if last else 4))
            self.tiles[view] = tile

    def _build_toolbar(self) -> None:
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(3, weight=1)
        self.view_title = ctk.CTkLabel(toolbar, text="", anchor="w", text_color=theme.ACCENT_TEXT,
                                       font=ctk.CTkFont(size=14, weight="bold"), width=110)
        self.view_title.grid(row=0, column=0, sticky="w", padx=(2, 10))
        self.engine_filter = ctk.CTkOptionMenu(toolbar, values=[ALL_ENGINES], width=200, dynamic_resizing=False,
                                               command=lambda _v: self.app.render_current_tab())
        self.engine_filter.set(ALL_ENGINES)
        self.engine_filter.grid(row=0, column=1, padx=(0, 10))
        self.search = _search_entry(toolbar, "Buscar nome, imagem, stack…  (Ctrl+F)", self.app.render_current_tab)
        self.search.grid(row=0, column=2, padx=(0, 10))
        self.info = ctk.CTkLabel(toolbar, text="", anchor="e", text_color=GRAY)
        self.info.grid(row=0, column=3, sticky="e", padx=(0, 10))
        self.btn_updates = _button(toolbar, "Verificar atualizações (skopeo)", self._check_all_updates, "neutral",
                                   230)
        self.btn_updates.grid(row=0, column=4)
        self.btn_new = _button(toolbar, "+ Novo contêiner", self._new_container, width=150)
        self.btn_new.grid(row=0, column=5, padx=(8, 0))

    def _build_tables(self) -> None:
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=3, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self.tables: dict[str, DataTable] = {
            "Contêineres": DataTable(
                content,
                [Column("name", "Nome", 200, True), Column("engine", "Motor", 130),
                 Column("image", "Imagem", 230, True),
                 Column("state", "Estado", 165), Column("ports", "Portas", 150), Column("stack", "Stack/Pod", 120),
                 Column("cpu", "CPU", 62, anchor="e"), Column("mem", "Memória", 82, anchor="e")],
                tree_column=Column("status", "Status", 118), on_select=self._update_actions,
                on_activate=self._logs, menu_items=self._container_menu, export_name="conteineres"),
            "Imagens": DataTable(
                content,
                [Column("repo", "Repositório", 280, True), Column("tag", "Tag", 120), Column("engine", "Motor", 150),
                 Column("id", "ID", 122), Column("size", "Tamanho", 90, anchor="e"), Column("created", "Criada", 130),
                 Column("use", "Uso", 80), Column("update", "Atualização (registro)", 230, True)],
                on_select=self._update_actions, on_activate=self._inspect, menu_items=self._image_menu,
                export_name="imagens"),
            "Volumes": DataTable(
                content,
                [Column("name", "Volume", 280, True), Column("engine", "Motor", 150), Column("driver", "Driver", 90),
                 Column("stack", "Stack", 140), Column("use", "Em uso", 80), Column("mount", "Ponto de montagem", 380,
                                                                                    True)],
                on_select=self._update_actions, on_activate=self._inspect, menu_items=self._volume_menu,
                export_name="volumes"),
            "Redes": DataTable(
                content,
                [Column("name", "Rede", 220, True), Column("engine", "Motor", 150), Column("driver", "Driver", 90),
                 Column("scope", "Escopo", 80), Column("subnets", "Sub-redes", 260, True),
                 Column("count", "Contêineres", 100, anchor="e"), Column("internal", "Interna", 80)],
                on_select=self._update_actions, menu_items=self._copy_menu, export_name="redes"),
            "Builds": DataTable(
                content,
                [Column("name", "Contêiner de trabalho", 300, True), Column("id", "ID", 130),
                 Column("image", "Imagem base", 340, True), Column("engine", "Ferramenta", 120)],
                on_select=self._update_actions, menu_items=self._copy_menu, export_name="builds"),
            "Disco": DataTable(
                content,
                [Column("engine", "Motor", 180), Column("kind", "Tipo", 160), Column("total", "Total", 80, anchor="e"),
                 Column("active", "Ativos", 80, anchor="e"), Column("size", "Tamanho", 120, anchor="e"),
                 Column("reclaimable", "Recuperável", 150, anchor="e"), Column("pad", "", 10, True)],
                export_name="uso-de-disco"),
            "Mudanças": DataTable(
                content,
                [Column("time", "Quando", 130), Column("target", "Contêiner", 170), Column("action", "Ação", 90),
                 Column("risk", "Risco", 70), Column("saved", "O que foi salvo", 300, True),
                 Column("detail", "Resultado", 320, True)],
                tree_column=Column("outcome", "Situação", 130), sort_column="time", sort_desc=True,
                on_select=self._update_actions, on_activate=self._show_definition, export_name="mudancas"),
        }
        for table in self.tables.values():
            table.grid(row=0, column=0, sticky="nsew")

    def _build_actions(self) -> None:
        bar = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        bar.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        bar.grid_columnconfigure(0, weight=1)
        self.bar = bar
        self.selection = ctk.CTkLabel(bar, text="", anchor="w")
        self.selection.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        self.buttons = {
            "start": _button(bar, "Iniciar", lambda: self._service_action(ServiceAction.START), "start", 86),
            "stop": _button(bar, "Parar", lambda: self._service_action(ServiceAction.STOP), "stop", 80),
            "restart": _button(bar, "Reiniciar", lambda: self._service_action(ServiceAction.RESTART), width=92),
            "pause": _button(bar, "Pausar", self._toggle_pause, "neutral", 88),
            "logs": _button(bar, "Logs", self._logs, "neutral", 70),
            "console": _button(bar, "Console", self._console, "neutral", 86),
            "check": _button(bar, "Verificar atualização", self._check_selected_update, "neutral", 160),
            "inspect": _button(bar, "Inspecionar", self._inspect, "neutral", 104),
            "remove": _button(bar, "Remover", self._remove, "stop", 90),
            "prune": _button(bar, "Limpar órfãs", self._prune, "stop", 112),
            "copy": _button(bar, "Copiar nome", self._copy_name, "neutral", 110),
            "restore": _button(bar, "Restaurar", lambda: self._restore(False), width=100),
            "restore_snapshot": _button(bar, "Restaurar do snapshot", lambda: self._restore(True), width=170),
            "start_again": _button(bar, "Iniciar de novo", self._start_again, "start", 130),
            "definition": _button(bar, "Ver definição", self._show_definition, "neutral", 120),
            "folder": _button(bar, "Abrir pasta", self._open_folder, "neutral", 110),
        }
        self._view_buttons = {
            "Contêineres": ("start", "stop", "restart", "pause", "logs", "console", "inspect", "remove"),
            "Imagens": ("check", "inspect", "remove", "prune"),
            "Volumes": ("inspect", "remove", "copy"),
            "Redes": ("copy",),
            "Builds": ("copy",),
            "Disco": (),
            "Mudanças": ("start_again", "restore", "restore_snapshot", "definition", "folder"),
        }

    # -- troca de visão ------------------------------------------------------------

    def _switch(self, view: str, render: bool = True) -> None:
        self._view = view
        for name, table in self.tables.items():
            if name == view:
                table.grid()
            else:
                table.grid_remove()
        for name, tile in self.tiles.items():
            tile.set_selected(name == view)
        self.view_title.configure(text=view)
        for button in self.buttons.values():
            button.grid_forget()
        shown = self._view_buttons[view]
        for column, key in enumerate(shown, 1):
            self.buttons[key].grid(row=0, column=column, padx=(0, 14 if column == len(shown) else 6), pady=10)
        if view == "Imagens":
            self.btn_updates.grid()
        else:
            self.btn_updates.grid_remove()
        if view == "Contêineres":
            self.btn_new.grid()
        else:
            self.btn_new.grid_remove()
        if render:
            self.app.render_current_tab()

    # -- renderização ----------------------------------------------------------------

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        self._server = server
        inventory = snapshot.containers if snapshot else None
        self._inventory = inventory
        config = self.app.server_config(server)
        containers = [s for s in snapshot.services if s.kind.is_container] if snapshot else []
        self._render_engines(inventory, config)
        self._render_tools(inventory)
        self._render_filter(containers, inventory)
        engine = self._filter_ids.get(self.engine_filter.get())
        if engine is not None:
            containers = [s for s in containers if engine_of(s) == engine]
        images = [i for i in inventory.images if engine in (None, i.engine)] if inventory else []
        volumes = [v for v in inventory.volumes if engine in (None, v.engine)] if inventory else []
        networks = [n for n in inventory.networks if engine in (None, n.engine)] if inventory else []
        builds = list(inventory.builds) if inventory and engine in (None, "buildah") else []
        disk = [d for d in inventory.disk if engine in (None, d.engine)] if inventory else []
        self._render_tiles(containers, images, volumes, networks, builds, inventory)
        waiting = self._waiting_message(snapshot, inventory)
        self._render_containers(containers, snapshot, config, waiting)
        self._render_images(images, waiting)
        self._render_volumes(volumes, waiting)
        self._render_networks(networks, waiting)
        self._render_builds(builds, inventory, waiting)
        self._render_disk(disk, waiting)
        self._render_changes(containers)
        self._update_actions()

    def _waiting_message(self, snapshot: HostSnapshot | None, inventory: ContainerInventory | None) -> str | None:
        if snapshot is None:
            return "Aguardando a primeira coleta…"
        if inventory is None or inventory.detected_at is None:
            return "Detectando os motores de contêiner instalados…"
        if not visible_engines(inventory):
            return ("Nenhum motor de contêiner encontrado neste servidor (Docker, Podman, containerd, CRI-O, "
                    "Buildah, Skopeo). Instale um deles ou escolha em \"Motores…\".")
        return None

    def _render_engines(self, inventory: ContainerInventory | None, config) -> None:
        self.mode_label.configure(text=selection_summary(engines.modes_to_selection(config)))
        if inventory is None or inventory.detected_at is None:
            self.detected_label.configure(text="detectando…")
        else:
            self.detected_label.configure(text=f"detectado {fmt_ago(inventory.detected_at)}")
        shown = visible_engines(inventory)
        order = [e.id for e in shown]
        if order != self._chip_order:
            for frame, _dot, _detail in self._chips.values():
                frame.grid_forget()
            self.no_engines.grid_forget()
            for index, engine_id in enumerate(order):
                if engine_id not in self._chips:
                    self._chips[engine_id] = self._make_chip(engine_id)
                row, column = divmod(index, _CHIPS_PER_ROW)
                self._chips[engine_id][0].grid(row=row, column=column, sticky="w", padx=(0, 8),
                                               pady=(0 if row == 0 else 5, 0))
            if not order:
                self.no_engines.grid(row=0, column=0, sticky="w")
            self._chip_order = order
        if not order:
            self.no_engines.configure(text="aguardando a auto-detecção…" if inventory is None
                                      or inventory.detected_at is None else "nenhum motor encontrado")
        for status in shown:
            _frame, dot, detail = self._chips[status.id]
            text, color = engine_badge(status)
            dot.configure(text_color=color)
            detail.configure(text=text)

    def _make_chip(self, engine_id: str) -> tuple[ctk.CTkFrame, ctk.CTkLabel, ctk.CTkLabel]:
        """Uma linha por motor: ● Nome  versão · estado (compacto para caber 6+ motores)."""
        frame = ctk.CTkFrame(self.chips, corner_radius=10, fg_color=theme.PANEL_BG)
        dot = ctk.CTkLabel(frame, text="●", width=12, height=26, font=ctk.CTkFont(size=12))
        dot.pack(side="left", padx=(10, 5))
        ctk.CTkLabel(frame, text=engine_short(engine_id), height=26,
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=(0, 8))
        detail = ctk.CTkLabel(frame, text="", height=26, text_color=GRAY, font=ctk.CTkFont(size=12), anchor="w")
        detail.pack(side="left", padx=(0, 12))
        return frame, dot, detail

    def _render_tools(self, inventory: ContainerInventory | None) -> None:
        tools = inventory.tools if inventory else ()
        if tools == self._tools_key:
            return
        self._tools_key = tools
        for child in self.tools.winfo_children():
            child.destroy()
        if not tools:
            self.tools.grid_remove()
            return
        ctk.CTkLabel(self.tools, text="Painéis web detectados:", text_color=GRAY, anchor="w").pack(side="left",
                                                                                              padx=(0, 8))
        for tool in tools:
            if tool.url:
                widget = _button(self.tools, f"{tool.name} ↗", lambda url=tool.url: self.app.open_url(url),
                                 "neutral", max(90, 26 + 8 * len(tool.name)))
            else:
                widget = ctk.CTkLabel(self.tools, text=tool.name, corner_radius=8, fg_color=theme.PANEL_BG, padx=10)
            widget.pack(side="left", padx=(0, 4))
            note = ctk.CTkLabel(self.tools, text=_truncate(tool.detail, 58), text_color=GRAY,
                                font=ctk.CTkFont(size=12))
            note.pack(side="left", padx=(0, 14))
            full = f"{tool.name}: {tool.detail}" + (f" — {tool.url}" if tool.url else "")
            for target in (widget, note):
                target.bind("<Enter>", lambda _e, text=full: self.app.set_status(text))
        ctk.CTkLabel(self.tools, text="abrem no navegador · este painel não muda", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=12)).pack(side="right")
        self.tools.grid()

    def _render_filter(self, containers: list[ServiceInfo], inventory: ContainerInventory | None) -> None:
        present = {engine_of(s) for s in containers}
        if inventory is not None:
            present |= {i.engine for i in inventory.images} | {v.engine for v in inventory.volumes}
            present |= {n.engine for n in inventory.networks}
            if inventory.builds:
                present.add("buildah")
        ordered = [e for e in engines.ENGINE_ORDER if e in present]
        options = {ALL_ENGINES: None, **{engine_short(e): e for e in ordered}}
        if options != self._filter_ids:
            self._filter_ids = options
            self.engine_filter.configure(values=list(options))
            if self.engine_filter.get() not in options:
                self.engine_filter.set(ALL_ENGINES)

    def _render_tiles(self, containers, images, volumes, networks, builds, inventory) -> None:
        counts = container_counts(containers)
        parts = [f"{counts['running']} rodando"]
        for key, singular, plural_form in (("paused", "pausado", "pausados"), ("stopped", "parado", "parados"),
                                           ("failed", "falha", "falhas")):
            if counts[key]:
                parts.append(plural(counts[key], singular, plural_form))
        self.tiles["Contêineres"].set(str(counts["total"]) if inventory or containers else "—", " · ".join(parts),
                                      RED if counts["failed"] else None)
        unique = {(i.engine, i.id): i for i in images}
        size = sum(i.size_bytes or 0 for i in unique.values())
        dangling = sum(1 for i in images if i.dangling)
        newer = sum(1 for i in images if (u := self._update_for(i)) is not None and u.status == "nova versão")
        detail = [fmt_bytes(size) if size else "tamanho —"]
        if dangling:
            detail.append(plural(dangling, "órfã", "órfãs"))
        if newer:
            detail.append(plural(newer, "atualização", "atualizações"))
        self.tiles["Imagens"].set(str(len(images)) if inventory else "—", " · ".join(detail),
                                  YELLOW if newer else None)
        unused = sum(1 for v in volumes if v.in_use is False)
        self.tiles["Volumes"].set(str(len(volumes)) if inventory else "—",
                                  f"{unused} sem uso" if unused else "todos em uso" if volumes else "")
        custom = sum(1 for n in networks if n.name not in _DEFAULT_NETWORKS)
        self.tiles["Redes"].set(str(len(networks)) if inventory else "—",
                                plural(custom, "criada por projetos", "criadas por projetos") if networks else "")
        buildah = inventory.engine("buildah") if inventory else None
        self.tiles["Builds"].set(str(len(builds)) if buildah and buildah.active else "—",
                                 "Buildah" if buildah and buildah.active else "Buildah não detectado")
        reclaim = reclaimable_bytes(inventory)
        self.tiles["Disco"].set(fmt_bytes(size) if size else "—",
                                f"{fmt_bytes(reclaim)} recuperáveis" if reclaim else "em imagens")

    def _render_containers(self, containers, snapshot, config, waiting: str | None) -> None:
        mark = tuple(config.critical_services) != ("*",)
        self._services = {s.key: s for s in containers}
        rows = []
        for s in containers:
            if not _matches(self.search, s.name, s.description, s.state_text, s.group, engine_short(engine_of(s)),
                            s.meta_value("ports")):
                continue
            busy = self.app.busy_label(self._server, s.key) if self._server else None
            paused = is_paused(s)
            name = f"{s.name}  ★" if mark and s.critical else s.name
            state = f"{busy}…" if busy else s.state_text
            cpu = fmt_pct(s.cpu_percent, 1) if s.cpu_percent is not None else ""
            mem = fmt_bytes(s.mem_bytes) if s.mem_bytes is not None else ""
            group = s.group or s.meta_value("pod")
            rows.append(Row(
                key=s.key, text="Pausado" if paused else s.status.label,
                status=ServiceStatus.ACTIVATING if paused else s.status,
                values=(name, engine_short(engine_of(s)), s.description, state, ports_text(s), group, cpu, mem),
                sort=((s.status.severity, s.name.casefold()), s.name, engine_of(s), s.description, s.state_text,
                      ports_text(s) or None, group or None, s.cpu_percent, s.mem_bytes),
            ))
        empty = waiting or ("Nenhum contêiner neste servidor." if not containers else "Nada corresponde à busca.")
        self.tables["Contêineres"].set_rows(rows, empty)
        if self._view == "Contêineres":
            self.info.configure(text=f"Exibindo {len(rows)} de {len(containers)}")

    def _update_for(self, image: ContainerImage) -> ImageUpdate | None:
        if self._server is None:
            return None
        return self._updates.get(self._server, {}).get(engines.normalize_ref(image.reference))

    def _render_images(self, images: list[ContainerImage], waiting: str | None) -> None:
        self._images = {i.key: i for i in images}
        rows = []
        for i in images:
            if not _matches(self.search, i.repository, i.tag, i.id, engine_label(i.engine)):
                continue
            update_label, tag = update_text(self._update_for(i))
            use = "órfã" if i.dangling else {True: "em uso", False: "sem uso", None: ""}[i.in_use]
            busy = self.app.busy_label(self._server, f"image:{i.key}") if self._server else None
            if busy:
                update_label = f"{busy}…"
            rows.append(Row(
                key=i.key, values=(i.repository, i.tag, engine_short(i.engine), i.id,
                                   fmt_bytes(i.size_bytes) if i.size_bytes is not None else "",
                                   fmt_created(i.created), use, update_label),
                sort=(i.repository, i.tag, i.engine, i.id, i.size_bytes, i.created or None, use, update_label or None),
                tag=tag or ("muted" if i.dangling or i.in_use is False else None),
            ))
        empty = waiting or ("Aguardando o inventário de imagens…" if self._inventory is None
                            or self._inventory.collected_at is None else
                            "Nenhuma imagem." if not images else "Nada corresponde à busca.")
        self.tables["Imagens"].set_rows(rows, empty)
        if self._view == "Imagens":
            checked = self._updates_at.get(self._server or "")
            text = f"{len(rows)} imagem(ns)"
            if checked:
                text += f" · registro consultado {fmt_ago(checked)}"
            if self._update_future is not None:
                text += " · consultando o registro…"
            self.info.configure(text=text)

    def _render_volumes(self, volumes, waiting: str | None) -> None:
        self._volumes = {v.key: (v.engine, v.name, v.in_use) for v in volumes}
        rows = [Row(key=v.key, values=(v.name, engine_short(v.engine), v.driver, v.stack,
                                       {True: "sim", False: "não", None: ""}[v.in_use], v.mountpoint),
                    sort=(v.name, v.engine, v.driver, v.stack or None, v.in_use, v.mountpoint or None),
                    tag="muted" if v.in_use is False else None)
                for v in volumes if _matches(self.search, v.name, v.stack, v.driver, engine_label(v.engine))]
        empty = waiting or ("Nenhum volume." if not volumes else "Nada corresponde à busca.")
        self.tables["Volumes"].set_rows(rows, empty)
        if self._view == "Volumes":
            self.info.configure(text=f"{len(rows)} volume(s) · volumes sem uso aparecem esmaecidos")

    def _render_networks(self, networks, waiting: str | None) -> None:
        self._names = {n.key: n.name for n in networks}
        rows = [Row(key=n.key, values=(n.name, engine_short(n.engine), n.driver, n.scope, ", ".join(n.subnets),
                                       "" if n.containers is None else str(n.containers),
                                       "sim" if n.internal else "não"),
                    sort=(n.name, n.engine, n.driver, n.scope, ", ".join(n.subnets) or None, n.containers,
                          n.internal),
                    tag="muted" if n.name in _DEFAULT_NETWORKS else None)
                for n in networks if _matches(self.search, n.name, n.driver, " ".join(n.subnets),
                                              engine_label(n.engine))]
        self.tables["Redes"].set_rows(rows, waiting or ("Nenhuma rede." if not networks else
                                                        "Nada corresponde à busca."))
        if self._view == "Redes":
            self.info.configure(text=f"{len(rows)} rede(s)")

    def _render_builds(self, builds, inventory, waiting: str | None) -> None:
        for b in builds:
            self._names[f"build:{b.id}"] = b.name
        rows = [Row(key=f"build:{b.id}", values=(b.name, b.id, b.image, "Buildah"), sort=(b.name, b.id, b.image, ""))
                for b in builds if _matches(self.search, b.name, b.id, b.image)]
        buildah = inventory.engine("buildah") if inventory else None
        if waiting:
            empty = waiting
        elif buildah is None or not buildah.active:
            empty = "Buildah não detectado (ou desativado em \"Motores…\")."
        else:
            empty = "Nenhum build em andamento (contêineres de trabalho do buildah from)."
        self.tables["Builds"].set_rows(rows, empty)
        if self._view == "Builds":
            self.info.configure(text=f"{len(rows)} contêiner(es) de trabalho")

    def _render_disk(self, disk, waiting: str | None) -> None:
        rows = [Row(key=f"{d.engine}:{d.kind}", values=(engine_short(d.engine), _DISK_KINDS.get(d.kind, d.kind),
                                                         "" if d.total is None else str(d.total),
                                                         "" if d.active is None else str(d.active), d.size,
                                                         d.reclaimable, ""),
                    sort=(d.engine, d.kind, d.total, d.active, d.size, d.reclaimable, ""))
                for d in disk]
        self.tables["Disco"].set_rows(rows, waiting or "Sem dados de uso de disco (system df) para estes motores.")
        if self._view == "Disco":
            self.info.configure(text="Espaço usado por imagens, contêineres, volumes e cache de build")

    def _render_changes(self, containers: list[ServiceInfo]) -> None:
        records = self.app.manager.change_records(self._server) if self._server else []
        self._records = {r.id: r for r in records}
        present = {s.name: s for s in containers}
        self._present = present
        rows = []
        for record in records:
            if not _matches(self.search, record.target, record.action, record.message):
                continue
            saved = []
            if record.definition_dir:
                saved.append("definição")
            if record.snapshot_image:
                saved.append(f"snapshot {record.snapshot_image.rsplit(':', 1)[-1]}")
            if record.volume_backups:
                saved.append(plural(len(record.volume_backups), "volume", "volumes"))
            when = dt.datetime.fromtimestamp(record.time).strftime("%d/%m %H:%M:%S")
            rows.append(Row(
                key=record.id, text=_OUTCOME_TEXT.get(record.outcome, record.outcome),
                status=_OUTCOME_STATUS.get(record.outcome, ServiceStatus.UNKNOWN),
                values=(when, record.target, _ACTION_TEXT.get(record.action, record.action), record.risk,
                        ", ".join(saved) or "—", record.message),
                sort=((_OUTCOME_STATUS.get(record.outcome, ServiceStatus.UNKNOWN).severity, record.time),
                      record.time, record.target, record.action, record.risk, ", ".join(saved), record.message)))
        local = "neste PC" if self.app.manager.backups.root is not None else "nesta sessão (demonstração)"
        self.tables["Mudanças"].set_rows(rows, f"Nenhuma mudança registrada {local} para este servidor.")
        last = records[0] if records else None
        self.tiles["Mudanças"].set(str(len(records)),
                                   f"última: {_ACTION_TEXT.get(last.action, last.action).lower()} {last.target}"
                                   if last else "histórico e restauração",
                                   RED if last and last.outcome == "error" else None)
        if self._view == "Mudanças":
            self.info.configure(text=f"{len(rows)} mudança(s) · backups das definições {local}")

    def _selected_record(self):
        key = self.tables["Mudanças"].selected_key()
        return getattr(self, "_records", {}).get(key) if key else None

    def _restore(self, snapshot: bool) -> None:
        record = self._selected_record()
        if record is not None and self._server:
            self.app.open_change(self._server, ChangeAction.RESTORE, record=record, use_snapshot=snapshot)

    def _start_again(self) -> None:
        record = self._selected_record()
        service = getattr(self, "_present", {}).get(record.target) if record else None
        if service is not None and self._server:
            self.app.open_change(self._server, ChangeAction.START, service=service)

    def _show_definition(self) -> None:
        record = self._selected_record()
        if record is not None:
            self.app.show_text(f"Definição salva — {record.target}",
                               text=self.app.manager.backups.readable_definition(record))

    def _open_folder(self) -> None:
        record = self._selected_record()
        if record is not None and record.definition_dir and not record.definition_dir.startswith("memória://"):
            open_folder(record.definition_dir)

    def _new_container(self) -> None:
        if self._server:
            self.app.open_new_container(self._server)

    # -- seleção e ações ---------------------------------------------------------------

    def _selected_service(self) -> ServiceInfo | None:
        key = self.tables["Contêineres"].selected_key()
        return self._services.get(key) if key else None

    def _selected_image(self) -> ContainerImage | None:
        key = self.tables["Imagens"].selected_key()
        return self._images.get(key) if key else None

    def _selected_volume(self) -> tuple[str, str, bool | None] | None:
        key = self.tables["Volumes"].selected_key()
        return self._volumes.get(key) if key else None

    def _config(self):
        return self.app.server_config(self._server) if self._server else None

    def _connected(self) -> bool:
        return bool(self._server) and self.app.manager.is_connected(self._server)

    def _skopeo_ready(self) -> bool:
        skopeo = self._inventory.engine("skopeo") if self._inventory else None
        return bool(skopeo and skopeo.installed and skopeo.mode != "off")

    def _container_flags(self, service: ServiceInfo) -> dict[str, bool]:
        config = self._config()
        idle = self._connected() and self.app.busy_label(self._server, service.key) is None
        manageable = idle and service.kind.manageable
        paused = is_paused(service)
        running = service.status is ServiceStatus.ACTIVE or service.status is ServiceStatus.ACTIVATING
        return {
            "start": manageable and not running and not paused,
            "stop": manageable and (running or paused),
            "restart": manageable,
            "pause": manageable and (running or paused),
            "logs": self._connected(),
            "console": manageable and running and not paused,
            "inspect": self._connected(),
            # Em execução também: a mudança segura para (com backup) antes de remover.
            "remove": manageable and bool(config and config.container_admin),
        }

    def _update_actions(self) -> None:
        for button in self.buttons.values():
            _set_state(button, False)
        text, color = "", GRAY
        config = self._config()
        admin = bool(config and config.container_admin)
        if self._view == "Contêineres":
            service = self._selected_service()
            if service is None:
                text = "Selecione um contêiner (duplo clique abre os logs; botão direito mostra mais ações)."
            else:
                flags = self._container_flags(service)
                for key, enabled in flags.items():
                    _set_state(self.buttons[key], enabled)
                self.buttons["pause"].configure(text="Retomar" if is_paused(service) else "Pausar")
                busy = self.app.busy_label(self._server, service.key) if self._server else None
                text = f"{service.name}  ·  {engine_label(engine_of(service))}  ·  {service.state_text}"
                if busy:
                    text += f"  —  {busy}…"
                elif not service.kind.manageable:
                    text += "  ·  somente leitura (gerenciado pelo kubelet)"
                elif not admin and service.status is not ServiceStatus.ACTIVE:
                    text += "  ·  remover exige \"container_admin\""
                color = STATUS_COLORS[service.status]
        elif self._view == "Imagens":
            image = self._selected_image()
            cli = image is not None and image.engine in engines.CLI_ENGINES
            prune_engine = self._prune_engine()
            _set_state(self.buttons["prune"], admin and self._connected() and prune_engine is not None)
            if image is None:
                text = "Selecione uma imagem." + ("" if admin else "  Remover/limpar exige \"container_admin\".")
            else:
                idle = self._connected() and not self.app.busy_label(self._server, f"image:{image.key}")
                _set_state(self.buttons["check"], idle and self._skopeo_ready() and engines.updatable(image)
                           and self._update_future is None)
                _set_state(self.buttons["inspect"], self._connected() and image.engine != "buildah")
                _set_state(self.buttons["remove"], idle and cli and admin and image.in_use is not True)
                text = f"{image.reference}  ·  {engine_label(image.engine)}"
                update = self._update_for(image)
                if update is not None and update.status == "nova versão":
                    text += "  ·  nova versão no registro: atualize com pull + recriar (compose up -d)"
                    color = YELLOW
                elif image.in_use:
                    text += "  ·  em uso por contêiner(es)"
                elif not engines.updatable(image):
                    text += "  ·  sem digest de registro (imagem local ou órfã)"
            self.btn_updates.configure(state="normal" if self._skopeo_ready() and self._connected()
                                       and self._update_future is None else "disabled")
            if not self._skopeo_ready():
                text += "  ·  instale o skopeo no servidor para comparar com o registro sem baixar"
        elif self._view == "Volumes":
            volume = self._selected_volume()
            if volume is None:
                text = "Selecione um volume."
            else:
                engine_id, name, in_use = volume
                cli = engine_id in engines.CLI_ENGINES
                idle = self._connected() and not self.app.busy_label(self._server, f"volume:{engine_id}:{name}")
                _set_state(self.buttons["inspect"], self._connected() and cli)
                _set_state(self.buttons["remove"], idle and cli and admin and in_use is False)
                _set_state(self.buttons["copy"], True)
                text = f"{name}  ·  {engine_label(engine_id)}"
                if in_use:
                    text += "  ·  em uso (não pode ser removido)"
                elif not admin:
                    text += "  ·  remover exige \"container_admin\""
        elif self._view in ("Redes", "Builds"):
            key = self.tables[self._view].selected_key()
            _set_state(self.buttons["copy"], key is not None)
            text = self._names.get(key, "") if key else f"Selecione um item em {self._view}."
        elif self._view == "Mudanças":
            record = self._selected_record()
            if record is None:
                text = "Selecione uma mudança: dá para iniciar de novo, restaurar e ver o que foi salvo."
            else:
                present = getattr(self, "_present", {})
                service = present.get(record.target)
                connected = self._connected()
                can_restore = (connected and admin and record.definition_dir and record.target not in present
                               and record.action in ("remove", "stop", "restart", "pause"))
                _set_state(self.buttons["restore"], bool(can_restore))
                _set_state(self.buttons["restore_snapshot"], bool(can_restore and record.snapshot_image))
                _set_state(self.buttons["start_again"], bool(connected and service is not None
                                                             and service.status is not ServiceStatus.ACTIVE
                                                             and service.kind.manageable))
                _set_state(self.buttons["definition"], bool(record.definition_dir))
                _set_state(self.buttons["folder"], bool(record.definition_dir)
                           and not record.definition_dir.startswith("memória://"))
                text = f"{_ACTION_TEXT.get(record.action, record.action)} {record.target} · risco {record.risk}"
                if record.target not in present and record.definition_dir:
                    text += "  ·  não existe mais: pode ser restaurado"
                if record.compose_hint:
                    text += "  ·  Compose: " + record.compose_hint
        else:
            text = "Para liberar espaço: \"Limpar órfãs\" na visão Imagens (somente imagens sem tag)."
        self.selection.configure(text=_truncate(text), text_color=color)

    def _service_action(self, action: ServiceAction) -> None:
        service = self._selected_service()
        if service is not None and self._server is not None:
            self.app.run_service_action(self._server, service, action)

    def _toggle_pause(self) -> None:
        service = self._selected_service()
        if service is not None and self._server is not None:
            self.app.container_op(self._server, service, "unpause" if is_paused(service) else "pause")

    def _logs(self) -> None:
        service = self._selected_service()
        if service is not None and self._server is not None:
            self.app.open_logs(self._server, service)

    def _console(self) -> None:
        service = self._selected_service()
        if service is not None and self._server is not None:
            self.app.open_console(self._server, service)

    def _inspect(self) -> None:
        if self._server is None:
            return
        if self._view == "Contêineres":
            service = self._selected_service()
            if service is not None:
                self.app.inspect_item(self._server, "container", engine_of(service), service, service.name)
        elif self._view == "Imagens":
            image = self._selected_image()
            if image is not None and image.engine != "buildah":
                self.app.inspect_item(self._server, "image", image.engine, image, image.reference)
        elif self._view == "Volumes":
            volume = self._selected_volume()
            if volume is not None and volume[0] in engines.CLI_ENGINES:
                self.app.inspect_item(self._server, "volume", volume[0], volume[1], volume[1])

    def _remove(self) -> None:
        if self._server is None:
            return
        if self._view == "Contêineres":
            service = self._selected_service()
            if service is not None and self._container_flags(service)["remove"]:
                self.app.container_op(self._server, service, "rm")
        elif self._view == "Imagens":
            image = self._selected_image()
            if image is not None:
                self.app.image_op(self._server, image.engine, image, "rmi")
        elif self._view == "Volumes":
            volume = self._selected_volume()
            if volume is not None:
                self.app.volume_op(self._server, volume[0], volume[1], "rm")

    def _prune_engine(self) -> str | None:
        """Motor alvo de "Limpar órfãs": o da imagem selecionada ou o do filtro."""
        image = self._selected_image()
        engine = image.engine if image is not None else self._filter_ids.get(self.engine_filter.get())
        if engine is None and self._inventory is not None:
            with_images = {i.engine for i in self._inventory.images if i.engine in engines.CLI_ENGINES}
            engine = next(iter(with_images)) if len(with_images) == 1 else None
        return engine if engine in engines.CLI_ENGINES else None

    def _prune(self) -> None:
        engine = self._prune_engine()
        if engine is not None and self._server is not None:
            self.app.image_op(self._server, engine, None, "prune")

    def _copy_name(self) -> None:
        if self._view == "Volumes":
            volume = self._selected_volume()
            if volume is not None:
                self.app.copy_text(volume[1])
            return
        key = self.tables[self._view].selected_key() if self._view in self.tables else None
        if key in self._names:
            self.app.copy_text(self._names[key])

    # -- atualizações de imagens (skopeo) ------------------------------------------------

    def _check_all_updates(self) -> None:
        images = list(self._images.values())
        self._start_update_check(update_targets(images))

    def _check_selected_update(self) -> None:
        image = self._selected_image()
        if image is not None:
            self._start_update_check(update_targets([image]))

    def _start_update_check(self, targets: list[ContainerImage]) -> None:
        if self._server is None or self._update_future is not None:
            return
        if not targets:
            self.app.set_status("Nenhuma imagem verificável: é preciso tag e digest de registro (imagens baixadas "
                                "com pull).", warning=True)
            return
        self._update_server = self._server
        self._update_future = self.app.manager.check_image_updates(self._server, targets)
        self.app.set_status(f"Consultando o registro para {len(targets)} imagem(ns) via skopeo em {self._server} "
                            "(sem baixar nada)…")
        self._update_actions()
        self.after(300, self._poll_updates)

    def _poll_updates(self) -> None:
        future = self._update_future
        if future is None:
            return
        if not future.done():
            self.after(300, self._poll_updates)
            return
        self._update_future = None
        server = self._update_server or ""
        try:
            results = future.result()
        except Exception as exc:  # noqa: BLE001
            self.app.set_status(f"Falha ao verificar atualizações em {server}: {exc}", error=True)
            self.app.render_current_tab()
            return
        store = self._updates.setdefault(server, {})
        for result in results:
            store[engines.normalize_ref(result.reference)] = result
        self._updates_at[server] = time.time()
        newer = [r.reference for r in results if r.status == "nova versão"]
        errors = sum(1 for r in results if r.status == "erro")
        if newer:
            shown = ", ".join(newer[:3]) + ("…" if len(newer) > 3 else "")
            self.app.set_status(f"[{server}] {len(newer)} imagem(ns) com nova versão no registro: {shown}",
                                warning=True)
        else:
            self.app.set_status(f"[{server}] {len(results) - errors} imagem(ns) em dia com o registro"
                                + (f"; {errors} com erro" if errors else "") + ".", warning=bool(errors))
        self.app.render_current_tab()

    # -- menus de contexto -----------------------------------------------------------------

    def _container_menu(self):
        service = self._selected_service()
        if service is None:
            return []
        flags = self._container_flags(service)
        paused = is_paused(service)
        items = [
            ("Iniciar", (lambda: self._service_action(ServiceAction.START)) if flags["start"] else None),
            ("Parar", (lambda: self._service_action(ServiceAction.STOP)) if flags["stop"] else None),
            ("Reiniciar", (lambda: self._service_action(ServiceAction.RESTART)) if flags["restart"] else None),
            ("Retomar" if paused else "Pausar", self._toggle_pause if flags["pause"] else None),
            ("-", None),
            ("Logs", self._logs if flags["logs"] else None),
            ("Console (shell no contêiner)", self._console if flags["console"] else None),
            ("Inspecionar", self._inspect if flags["inspect"] else None),
            ("-", None),
            ("Remover contêiner", self._remove if flags["remove"] else None),
            ("-", None),
            ("Copiar nome", lambda: self.app.copy_text(service.name)),
        ]
        if service.description:
            items.append(("Copiar imagem", lambda: self.app.copy_text(service.description)))
        return items

    def _image_menu(self):
        image = self._selected_image()
        if image is None:
            return []
        self._update_actions()
        state = {key: self.buttons[key].cget("state") == "normal" for key in ("check", "inspect", "remove")}
        return [
            ("Verificar atualização no registro", self._check_selected_update if state["check"] else None),
            ("Inspecionar", self._inspect if state["inspect"] else None),
            ("Remover imagem", self._remove if state["remove"] else None),
            ("-", None),
            ("Copiar referência", lambda: self.app.copy_text(image.reference)),
            ("Copiar ID", lambda: self.app.copy_text(image.id)),
        ]

    def _volume_menu(self):
        volume = self._selected_volume()
        if volume is None:
            return []
        self._update_actions()
        state = {key: self.buttons[key].cget("state") == "normal" for key in ("inspect", "remove")}
        return [("Inspecionar", self._inspect if state["inspect"] else None),
                ("Remover volume", self._remove if state["remove"] else None),
                ("-", None), ("Copiar nome", self._copy_name)]

    def _copy_menu(self):
        return [("Copiar nome", self._copy_name)] if self.tables[self._view].selected_key() else []

    # -- motores ---------------------------------------------------------------------------

    def _detect(self) -> None:
        if self._server:
            self.app.manager.refresh(self._server, full=True)
            self.app.set_status(f"Detectando motores de contêiner em {self._server}…")

    def _open_engines(self) -> None:
        self.app.open_engines_dialog(self._server)

    def reset(self) -> None:
        for table in self.tables.values():
            table.clear()
        self._tools_key = None

    def focus_search(self) -> None:
        self.search.focus_set()
