"""Abas do painel de um servidor e o painel "Visão geral" (todos os servidores).

Cada aba recebe o snapshot mais recente em :meth:`Tab.render` e só é
redesenhada quando está visível (o Dashboard marca as demais como pendentes).
"""

from __future__ import annotations

import csv
import datetime as dt
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import customtkinter as ctk
from tkinter import filedialog

from core.models import (
    CheckLevel,
    ConnectionEvent,
    ConnectionState,
    HealthLevel,
    HostSnapshot,
    RuntimeState,
    ServiceAction,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    Stack,
)
from core.parsers import classify_systemd, format_timestamp
from ui import theme
from ui.widgets import (
    CARD_BG,
    GRAY,
    RED,
    STATUS_COLORS,
    TEXT,
    YELLOW,
    Column,
    DataTable,
    InfoGrid,
    LineChart,
    Row,
    Series,
    fmt_ago,
    fmt_bytes,
    fmt_duration,
    fmt_kb,
    fmt_num,
    fmt_pct,
    fmt_rate,
)

if TYPE_CHECKING:
    from ui.dashboard import Dashboard


class Tab(ctk.CTkFrame):
    title = ""

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, fg_color="transparent")
        self.app = app

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        """Chamado ao trocar de servidor."""

    def focus_search(self) -> None:
        """Ctrl+F."""


def _search_entry(master, placeholder: str, callback: Callable[[], None]) -> ctk.CTkEntry:
    entry = ctk.CTkEntry(master, placeholder_text=placeholder, width=280)
    job: list[str | None] = [None]

    def changed(_event=None) -> None:
        if job[0] is not None:
            entry.after_cancel(job[0])
        job[0] = entry.after(120, callback)

    def clear(_event=None) -> None:
        entry.delete(0, "end")
        callback()

    entry.bind("<KeyRelease>", changed)
    entry.bind("<Escape>", clear)
    return entry


def _matches(entry: ctk.CTkEntry, *fields: str) -> bool:
    terms = entry.get().casefold().split()
    haystack = " ".join(fields).casefold()
    return all(term in haystack for term in terms)


def _button(master, text: str, command: Callable[[], None], kind: str = "default", width: int = 104):
    colors = {
        "start": {"fg_color": ("#2da44e", "#238636"), "hover_color": ("#2c974b", "#2ea043")},
        "stop": {"fg_color": ("#cf222e", "#b62324"), "hover_color": ("#a40e26", "#d9363e")},
        "neutral": {"fg_color": theme.NEUTRAL, "hover_color": theme.NEUTRAL_HOVER, "text_color": theme.TEXT},
        "default": {},
    }[kind]
    return ctk.CTkButton(master, text=text, width=width, command=command, **colors)


def _set_state(button: ctk.CTkButton, enabled: bool) -> None:
    button.configure(state="normal" if enabled else "disabled")


def _section_label(master, text: str) -> ctk.CTkLabel:
    return ctk.CTkLabel(master, text=text, anchor="w", text_color=theme.ACCENT_TEXT,
                        font=ctk.CTkFont(size=13, weight="bold"))


# ---------------------------------------------------------------------------
# Serviços (todas as cargas)
# ---------------------------------------------------------------------------

STATUS_FILTERS: dict[str, set[ServiceStatus] | None] = {
    "Todos": None,
    "Ativos": {ServiceStatus.ACTIVE},
    "Com falha": {ServiceStatus.FAILED, ServiceStatus.DEGRADED},
    "Parados": {ServiceStatus.STOPPED},
    "Iniciando": {ServiceStatus.ACTIVATING},
}


def _is_unit(kind_type: str) -> Callable[[ServiceInfo], bool]:
    return lambda s: s.kind is ServiceKind.SYSTEMD and s.unit_type == kind_type


TYPE_FILTERS: dict[str, Callable[[ServiceInfo], bool]] = {
    "Serviços e cargas": lambda s: s.kind is not ServiceKind.SYSTEMD or s.unit_type == "service",
    "Tudo": lambda s: True,
    "systemd: serviços": _is_unit("service"),
    "systemd: timers": _is_unit("timer"),
    "systemd: sockets": _is_unit("socket"),
    "systemd: mounts": _is_unit("mount"),
    "systemd: paths": _is_unit("path"),
    "Contêineres Docker": lambda s: s.kind is ServiceKind.DOCKER,
    "Contêineres Podman": lambda s: s.kind is ServiceKind.PODMAN,
    "Pods Kubernetes": lambda s: s.kind is ServiceKind.KUBERNETES,
    "Máquinas virtuais": lambda s: s.kind is ServiceKind.LIBVIRT,
    "Instâncias LXD/Incus": lambda s: s.kind is ServiceKind.LXD,
}


def workload_row(service: ServiceInfo, mark_critical: bool) -> Row:
    name = f"{service.name}  ★" if mark_critical and service.critical else service.name
    cpu = fmt_pct(service.cpu_percent, 1) if service.cpu_percent is not None else ""
    mem = fmt_bytes(service.mem_bytes) if service.mem_bytes is not None else ""
    return Row(
        key=service.key,
        text=service.status.label,
        status=service.status,
        values=(name, service.type_label, service.group, service.state_text, cpu, mem, service.description),
        sort=((service.status.severity, service.name.casefold()), service.name, service.type_label,
              service.group or None, service.state_text, service.cpu_percent, service.mem_bytes,
              service.description or None),
    )


def _member_row(service: ServiceInfo) -> Row:
    """Linha da tabela de membros de uma stack (5 colunas)."""
    cpu = fmt_pct(service.cpu_percent, 1) if service.cpu_percent is not None else ""
    mem = fmt_bytes(service.mem_bytes) if service.mem_bytes is not None else ""
    return Row(key=service.key, text=service.status.label, status=service.status,
               values=(service.name, service.state_text, cpu, mem, service.description),
               sort=((service.status.severity, service.name), service.name, service.state_text,
                     service.cpu_percent, service.mem_bytes, service.description))


class ServicesTab(Tab):
    title = "Serviços"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._services: dict[str, ServiceInfo] = {}
        self._server: str | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(3, weight=1)
        self.status_filter = ctk.CTkSegmentedButton(toolbar, values=list(STATUS_FILTERS),
                                                    command=lambda _v: self.refresh())
        self.status_filter.set("Todos")
        self.status_filter.grid(row=0, column=0, padx=(0, 10))
        self.type_filter = ctk.CTkOptionMenu(toolbar, values=list(TYPE_FILTERS), width=190,
                                             dynamic_resizing=False, command=lambda _v: self.refresh())
        self.type_filter.set("Serviços e cargas")
        self.type_filter.grid(row=0, column=1, padx=(0, 10))
        self.search = _search_entry(toolbar, "Buscar nome, grupo, estado…  (Ctrl+F)", self.refresh)
        self.search.grid(row=0, column=2, padx=(0, 10))
        self.count = ctk.CTkLabel(toolbar, text="", text_color=GRAY, anchor="e")
        self.count.grid(row=0, column=3, sticky="e")

        self.table = DataTable(
            self,
            [Column("name", "Nome", 250, True), Column("type", "Tipo", 90), Column("group", "Grupo/Stack", 120),
             Column("state", "Estado", 210), Column("cpu", "CPU", 70, anchor="e"),
             Column("mem", "Memória", 90, anchor="e"), Column("desc", "Descrição", 260, True)],
            tree_column=Column("status", "Status", 125),
            on_select=self.update_actions, on_activate=self.open_logs, menu_items=self._menu,
            export_name="servicos",
        )
        self.table.grid(row=1, column=0, sticky="nsew")

        bar = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        bar.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        bar.grid_columnconfigure(0, weight=1)
        self.selection = ctk.CTkLabel(bar, text="", anchor="w")
        self.selection.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        self.btn_start = _button(bar, "Iniciar", lambda: self.act(ServiceAction.START), "start")
        self.btn_stop = _button(bar, "Parar", lambda: self.act(ServiceAction.STOP), "stop")
        self.btn_restart = _button(bar, "Reiniciar", lambda: self.act(ServiceAction.RESTART))
        self.btn_logs = _button(bar, "Ver logs", self.open_logs, "neutral")
        for column, button in enumerate((self.btn_start, self.btn_stop, self.btn_restart, self.btn_logs), 1):
            button.grid(row=0, column=column, padx=(0, 14 if column == 4 else 8), pady=10)

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        self._server = server
        services = list(snapshot.services) if snapshot else []
        self._services = {s.key: s for s in services}
        statuses = STATUS_FILTERS[self.status_filter.get()]
        type_filter = TYPE_FILTERS[self.type_filter.get()]
        mark = tuple(self.app.server_config(server).critical_services) != ("*",)
        rows = [workload_row(s, mark) for s in services
                if (statuses is None or s.status in statuses) and type_filter(s)
                and _matches(self.search, s.name, s.description, s.state_text, s.group, s.type_label)]
        if snapshot is None:
            empty = "Aguardando a primeira coleta…"
        elif not services:
            empty = "Nenhuma carga encontrada neste servidor."
        else:
            empty = "Nada corresponde aos filtros."
        self.table.set_rows(rows, empty)
        self.count.configure(text=f"Exibindo {len(rows)} de {len(services)}")
        self.update_actions()

    def refresh(self) -> None:
        self.app.render_current_tab()

    def reset(self) -> None:
        self.table.clear()

    def focus_search(self) -> None:
        self.search.focus_set()

    def show_all_and_select(self, key: str) -> None:
        self.status_filter.set("Todos")
        self.type_filter.set("Tudo")
        self.search.delete(0, "end")
        self.refresh()
        self.table.select_key(key)
        self.update_actions()

    def selected(self) -> ServiceInfo | None:
        key = self.table.selected_key()
        return self._services.get(key) if key else None

    def update_actions(self) -> None:
        service = self.selected()
        buttons = (self.btn_start, self.btn_stop, self.btn_restart, self.btn_logs)
        if service is None or self._server is None:
            self.selection.configure(text="Selecione uma carga na tabela (duplo clique abre os logs).",
                                     text_color=GRAY)
            for button in buttons:
                _set_state(button, False)
            return
        connected = self.app.manager.is_connected(self._server)
        busy = self.app.busy_label(self._server, service.key)
        text = f"{service.name}  ·  {service.type_label}  ·  {service.status.label}  ·  {service.state_text}"
        if busy:
            text += f"  —  {busy}…"
        self.selection.configure(text=text, text_color=STATUS_COLORS[service.status])
        can_act = connected and busy is None
        _set_state(self.btn_start, can_act and service.supports(ServiceAction.START)
                   and service.status is not ServiceStatus.ACTIVE)
        _set_state(self.btn_stop, can_act and service.supports(ServiceAction.STOP)
                   and service.status is not ServiceStatus.STOPPED)
        _set_state(self.btn_restart, can_act and service.supports(ServiceAction.RESTART))
        self.btn_logs.configure(text="Detalhes" if service.kind is ServiceKind.LIBVIRT else "Ver logs")
        _set_state(self.btn_logs, connected)

    def act(self, action: ServiceAction) -> None:
        service = self.selected()
        if service is not None and self._server is not None:
            self.app.run_service_action(self._server, service, action)

    def open_logs(self) -> None:
        service = self.selected()
        if service is not None and self._server is not None:
            self.app.open_logs(self._server, service)

    def _menu(self):
        service = self.selected()
        if service is None or self._server is None:
            return []
        connected = self.app.manager.is_connected(self._server)
        idle = connected and self.app.busy_label(self._server, service.key) is None
        items = []
        for action in ServiceAction:
            enabled = idle and service.supports(action)
            items.append((action.label, (lambda a=action: self.act(a)) if enabled else None))
        items.append(("-", None))
        items.append(("Ver logs" if service.kind is not ServiceKind.LIBVIRT else "Detalhes",
                      self.open_logs if connected else None))
        items.append(("Copiar nome", lambda: self.app.copy_text(service.name)))
        return items


# ---------------------------------------------------------------------------
# Stacks (Compose / pods do Podman / namespaces do Kubernetes)
# ---------------------------------------------------------------------------

class StacksTab(Tab):
    title = "Stacks"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._server: str | None = None
        self._stacks: dict[str, Stack] = {}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=3)
        self.grid_rowconfigure(4, weight=2)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Projetos Docker/Podman Compose, pods do Podman e namespaces do Kubernetes",
                     text_color=GRAY, anchor="w").grid(row=0, column=0, sticky="w")
        self.count = ctk.CTkLabel(header, text="", text_color=GRAY)
        self.count.grid(row=0, column=1, sticky="e")

        self.table = DataTable(
            self,
            [Column("name", "Stack", 200, True), Column("runtime", "Runtime", 100),
             Column("members", "Em execução", 125, anchor="e"), Column("cpu", "CPU", 80, anchor="e"),
             Column("mem", "Memória", 100, anchor="e"), Column("origin", "Origem (diretório / arquivos)", 380, True)],
            tree_column=Column("status", "Status", 125),
            on_select=self._selected_changed, on_activate=self.open_logs, menu_items=self._menu,
            export_name="stacks",
        )
        self.table.grid(row=1, column=0, sticky="nsew")

        bar = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        bar.grid(row=2, column=0, sticky="ew", pady=8)
        bar.grid_columnconfigure(0, weight=1)
        self.selection = ctk.CTkLabel(bar, text="", anchor="w")
        self.selection.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        self.btn_start = _button(bar, "Iniciar stack", lambda: self.act(ServiceAction.START), "start", 120)
        self.btn_stop = _button(bar, "Parar stack", lambda: self.act(ServiceAction.STOP), "stop", 120)
        self.btn_restart = _button(bar, "Reiniciar stack", lambda: self.act(ServiceAction.RESTART), width=130)
        self.btn_logs = _button(bar, "Logs da stack", self.open_logs, "neutral", 120)
        for column, button in enumerate((self.btn_start, self.btn_stop, self.btn_restart, self.btn_logs), 1):
            button.grid(row=0, column=column, padx=(0, 14 if column == 4 else 8), pady=10)

        _section_label(self, "Membros da stack selecionada").grid(row=3, column=0, sticky="w", pady=(0, 4))
        self.members = DataTable(
            self,
            [Column("name", "Nome", 260, True), Column("state", "Estado", 240), Column("cpu", "CPU", 80, anchor="e"),
             Column("mem", "Memória", 100, anchor="e"), Column("desc", "Imagem / detalhes", 300, True)],
            tree_column=Column("status", "Status", 125),
            on_activate=self._open_member_logs, export_name="membros-stack",
        )
        self.members.grid(row=4, column=0, sticky="nsew")
        self._member_map: dict[str, ServiceInfo] = {}

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        self._server = server
        stacks = snapshot.stacks() if snapshot else []
        self._stacks = {s.key: s for s in stacks}
        rows = []
        for stack in stacks:
            origin = stack.working_dir or stack.config_files
            if stack.kind is ServiceKind.KUBERNETES:
                origin = f"namespace {stack.name}"
            elif stack.members[0].meta_value("pod"):
                origin = f"pod do Podman {stack.name}"
            rows.append(Row(
                key=stack.key, text=stack.status.label, status=stack.status,
                values=(stack.name, stack.kind.label, f"{stack.running}/{len(stack.members)}",
                        fmt_pct(stack.cpu_percent, 1) if stack.cpu_percent is not None else "",
                        fmt_bytes(stack.mem_bytes) if stack.mem_bytes is not None else "", origin),
                sort=((stack.status.severity, stack.name), stack.name, stack.kind.label,
                      stack.running / len(stack.members), stack.cpu_percent, stack.mem_bytes, origin),
            ))
        empty = ("Aguardando a primeira coleta…" if snapshot is None else
                 "Nenhuma stack: contêineres sem projeto do Compose e nenhum namespace do Kubernetes.")
        self.table.set_rows(rows, empty)
        self.count.configure(text=f"{len(stacks)} stack{'s' if len(stacks) != 1 else ''}")
        self._selected_changed()

    def reset(self) -> None:
        self.table.clear()
        self.members.clear()

    def selected(self) -> Stack | None:
        key = self.table.selected_key()
        return self._stacks.get(key) if key else None

    def _selected_changed(self) -> None:
        stack = self.selected()
        self._member_map = {m.key: m for m in stack.members} if stack else {}
        self.members.set_rows([_member_row(m) for m in (stack.members if stack else ())],
                              "Selecione uma stack acima." if stack is None else "")
        buttons = (self.btn_start, self.btn_stop, self.btn_restart, self.btn_logs)
        if stack is None or self._server is None:
            self.selection.configure(text="Selecione uma stack.", text_color=GRAY)
            for button in buttons:
                _set_state(button, False)
            return
        connected = self.app.manager.is_connected(self._server)
        busy = self.app.busy_label(self._server, stack.key)
        text = f"{stack.name}  ·  {stack.kind.label}  ·  {stack.running}/{len(stack.members)} em execução"
        if busy:
            text += f"  —  {busy}…"
        self.selection.configure(text=text, text_color=STATUS_COLORS[stack.status])
        can_act = connected and busy is None and stack.kind.is_container
        _set_state(self.btn_start, can_act and stack.running < len(stack.members))
        _set_state(self.btn_stop, can_act and stack.running > 0)
        _set_state(self.btn_restart, can_act)
        _set_state(self.btn_logs, connected)

    def act(self, action: ServiceAction) -> None:
        stack = self.selected()
        if stack is not None and self._server is not None:
            self.app.run_stack_action(self._server, stack, action)

    def open_logs(self) -> None:
        stack = self.selected()
        if stack is not None and self._server is not None:
            self.app.open_stack_logs(self._server, stack)

    def _open_member_logs(self) -> None:
        key = self.members.selected_key()
        if key in self._member_map and self._server is not None:
            self.app.open_logs(self._server, self._member_map[key])

    def _menu(self):
        stack = self.selected()
        if stack is None or self._server is None:
            return []
        can_act = (self.app.manager.is_connected(self._server) and stack.kind.is_container
                   and self.app.busy_label(self._server, stack.key) is None)
        items = [(f"{action.label} stack", (lambda a=action: self.act(a)) if can_act else None)
                 for action in ServiceAction]
        items += [("-", None), ("Logs da stack", self.open_logs)]
        if stack.working_dir:
            items.append(("Copiar diretório", lambda: self.app.copy_text(stack.working_dir)))
        return items


# ---------------------------------------------------------------------------
# Processos
# ---------------------------------------------------------------------------

class ProcessesTab(Tab):
    title = "Processos"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._server: str | None = None
        self._pids: set[int] = set()
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(2, weight=1)
        self.search = _search_entry(toolbar, "Buscar processo, usuário, PID…  (Ctrl+F)", self.app_render)
        self.search.grid(row=0, column=0, padx=(0, 10))
        self.count = ctk.CTkLabel(toolbar, text="", text_color=GRAY)
        self.count.grid(row=0, column=1, padx=(0, 10))
        self.updated = ctk.CTkLabel(toolbar, text="", text_color=GRAY, anchor="e")
        self.updated.grid(row=0, column=2, sticky="e", padx=(0, 10))
        _button(toolbar, "Atualizar agora", self._refresh, "neutral", 130).grid(row=0, column=3)

        self.table = DataTable(
            self,
            [Column("pid", "PID", 75, anchor="e"), Column("user", "Usuário", 110),
             Column("cpu", "CPU", 75, anchor="e"), Column("mem", "Mem %", 70, anchor="e"),
             Column("rss", "RSS", 95, anchor="e"), Column("time", "Tempo", 90, anchor="e"),
             Column("state", "Estado", 65), Column("command", "Processo", 150),
             Column("args", "Linha de comando", 420, True)],
            sort_column="cpu", sort_desc=True, on_select=self._update_actions, menu_items=self._menu,
            export_name="processos",
        )
        self.table.grid(row=1, column=0, sticky="nsew")

        bar = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        bar.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        bar.grid_columnconfigure(0, weight=1)
        self.hint = ctk.CTkLabel(bar, text="", anchor="w", text_color=GRAY)
        self.hint.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        self.btn_term = _button(bar, "Encerrar (TERM)", lambda: self._kill(False), width=140)
        self.btn_kill = _button(bar, "Forçar (KILL)", lambda: self._kill(True), "stop", 130)
        self.btn_term.grid(row=0, column=1, padx=(0, 8), pady=10)
        self.btn_kill.grid(row=0, column=2, padx=(0, 14), pady=10)

    def app_render(self) -> None:
        self.app.render_current_tab()

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        self._server = server
        processes = list(snapshot.processes) if snapshot else []
        self._pids = {p.pid for p in processes}
        rows = []
        for p in processes:
            if not _matches(self.search, str(p.pid), p.user, p.command, p.args):
                continue
            cpu = p.cpu_percent
            rows.append(Row(
                key=str(p.pid),
                values=(str(p.pid), p.user, fmt_pct(cpu, 1) if cpu is not None else "…", fmt_pct(p.mem_percent, 1),
                        fmt_kb(p.rss_kb), fmt_duration(p.elapsed_seconds), p.state, p.command, p.args),
                sort=(p.pid, p.user, cpu, p.mem_percent, p.rss_kb, p.elapsed_seconds, p.state, p.command, p.args),
                tag="error" if (cpu or 0) >= 90 else "warn" if (cpu or 0) >= 50 else None,
            ))
        empty = "Aguardando a coleta de processos…" if snapshot is None or snapshot.detail_at is None else \
            "Nenhum processo corresponde à busca."
        self.table.set_rows(rows, empty)
        limit = self.app.settings.process_limit
        self.count.configure(text=f"Exibindo {len(rows)} (top {limit} por CPU)")
        interval = self.app.settings.detail_interval_seconds
        self.updated.configure(text=f"Atualizado {fmt_ago(snapshot.detail_at if snapshot else None)} · "
                                    f"a cada {fmt_num(interval, 0)} s")
        self._update_actions()

    def reset(self) -> None:
        self.table.clear()

    def focus_search(self) -> None:
        self.search.focus_set()

    def _selected_pid(self) -> int | None:
        key = self.table.selected_key()
        return int(key) if key and key.isdigit() and int(key) in self._pids else None

    def _update_actions(self) -> None:
        pid = self._selected_pid()
        allowed = self._server is not None and self.app.server_config(self._server).process_actions
        if not allowed:
            self.hint.configure(text="Ações em processos desativadas — habilite \"process_actions\" no servers.json.")
        elif pid is None:
            self.hint.configure(text="Selecione um processo para encerrá-lo.")
        else:
            self.hint.configure(text=f"PID {pid} selecionado.")
        enabled = (allowed and pid is not None and self.app.manager.is_connected(self._server)
                   and self.app.busy_label(self._server, f"pid:{pid}") is None)
        _set_state(self.btn_term, enabled)
        _set_state(self.btn_kill, enabled)

    def _kill(self, force: bool) -> None:
        pid = self._selected_pid()
        if pid is not None and self._server is not None:
            self.app.kill_process(self._server, pid, force)

    def _refresh(self) -> None:
        if self._server:
            self.app.manager.refresh(self._server, full=True)
            self.app.set_status(f"Atualizando processos de {self._server}…")

    def _menu(self):
        pid = self._selected_pid()
        allowed = self._server is not None and self.app.server_config(self._server).process_actions
        if pid is None:
            return []
        return [("Encerrar (TERM)", (lambda: self._kill(False)) if allowed else None),
                ("Forçar (KILL)", (lambda: self._kill(True)) if allowed else None),
                ("Copiar PID", lambda: self.app.copy_text(str(pid)))]


# ---------------------------------------------------------------------------
# Rede
# ---------------------------------------------------------------------------

def _exposure(address: str) -> str:
    if address in {"*", "0.0.0.0", "::"}:
        return "Todas as interfaces"
    if address.startswith("127.") or address == "::1":
        return "Somente local"
    return "Interface específica"


class NetworkTab(Tab):
    title = "Rede"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self.summary = ctk.CTkLabel(self, text="", anchor="w", justify="left")
        self.summary.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        _section_label(self, "Interfaces").grid(row=1, column=0, sticky="w", pady=(0, 4))
        self.interfaces = DataTable(
            self,
            [Column("name", "Interface", 140), Column("kind", "Tipo", 110),
             Column("rx", "Recebendo", 120, anchor="e"), Column("tx", "Enviando", 120, anchor="e"),
             Column("rx_total", "Total recebido", 130, anchor="e"),
             Column("tx_total", "Total enviado", 130, anchor="e"),
             Column("pad", "", 10, True)],
            sort_column="rx", sort_desc=True, export_name="interfaces", height=5,
        )
        self.interfaces.grid(row=2, column=0, sticky="ew")

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=3, column=0, sticky="ew", pady=(10, 4))
        header.grid_columnconfigure(0, weight=1)
        _section_label(header, "Portas em escuta").grid(row=0, column=0, sticky="w")
        self.search = _search_entry(header, "Filtrar porta, processo, endereço…", self.app.render_current_tab)
        self.search.grid(row=0, column=1, sticky="e")
        self.ports = DataTable(
            self,
            [Column("proto", "Proto", 70), Column("address", "Endereço", 170), Column("port", "Porta", 80, anchor="e"),
             Column("exposure", "Exposição", 150), Column("process", "Processo", 180),
             Column("pid", "PID", 80, anchor="e"), Column("pad", "", 10, True)],
            sort_column="port", export_name="portas",
        )
        self.ports.grid(row=4, column=0, sticky="nsew")

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        metrics = snapshot.metrics if snapshot else None
        network = snapshot.network if snapshot else None
        interfaces = metrics.interfaces if metrics else ()
        self.interfaces.set_rows([
            Row(key=i.name, values=(i.name, "virtual" if i.virtual else "física", fmt_rate(i.rx_bps),
                                    fmt_rate(i.tx_bps), fmt_bytes(i.rx_bytes), fmt_bytes(i.tx_bytes), ""),
                sort=(i.name, i.virtual, i.rx_bps, i.tx_bps, i.rx_bytes, i.tx_bytes, ""),
                tag="muted" if i.virtual else None)
            for i in interfaces], "Sem dados de interfaces.")
        listening = network.listening if network else ()
        rows = [Row(key=f"{s.proto}:{s.address}:{s.port}",
                    values=(s.proto, s.address, str(s.port), _exposure(s.address), s.process,
                            "" if s.pid is None else str(s.pid), ""),
                    sort=(s.proto, s.address, s.port, _exposure(s.address), s.process or None, s.pid, ""))
                for s in listening if _matches(self.search, s.proto, s.address, str(s.port), s.process)]
        self.ports.set_rows(rows, "Aguardando a coleta…" if network is None else "Nenhuma porta corresponde.")
        if network is None:
            self.summary.configure(text="Aguardando a coleta de rede…", text_color=GRAY)
            return
        parts = [f"{len(listening)} portas em escuta"]
        if network.tcp_inuse is not None:
            parts.append(f"TCP em uso: {network.tcp_inuse}")
        if network.tcp_timewait is not None:
            parts.append(f"TIME-WAIT: {network.tcp_timewait}")
        if network.udp_inuse is not None:
            parts.append(f"UDP: {network.udp_inuse}")
        if metrics and metrics.net_rx_bps is not None:
            parts.append(f"tráfego ↓ {fmt_rate(metrics.net_rx_bps)} ↑ {fmt_rate(metrics.net_tx_bps)}")
        text = " · ".join(parts)
        if not network.process_info:
            text += ("\nProcessos de outros usuários não aparecem sem privilégio: habilite \"network_sudo\" "
                     "(sudo -n ss) ou rode como root.")
        self.summary.configure(text=text, text_color=TEXT if network.process_info else YELLOW)

    def reset(self) -> None:
        self.interfaces.clear()
        self.ports.clear()

    def focus_search(self) -> None:
        self.search.focus_set()


# ---------------------------------------------------------------------------
# Agendamentos (timers + cron)
# ---------------------------------------------------------------------------

class SchedulesTab(Tab):
    title = "Agendamentos"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(3, weight=1)
        _section_label(self, "Timers do systemd").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.timers = DataTable(
            self,
            [Column("name", "Timer", 220), Column("activates", "Aciona", 220), Column("next", "Próxima execução", 190),
             Column("last", "Última execução", 190), Column("desc", "Descrição", 260, True)],
            tree_column=Column("status", "Status", 120), sort_column="next", export_name="timers",
        )
        self.timers.grid(row=1, column=0, sticky="nsew")
        _section_label(self, "Cron").grid(row=2, column=0, sticky="w", pady=(10, 4))
        self.cron = DataTable(
            self,
            [Column("source", "Origem", 220), Column("schedule", "Agenda", 140), Column("user", "Usuário", 110),
             Column("command", "Comando", 520, True)],
            export_name="cron",
        )
        self.cron.grid(row=3, column=0, sticky="nsew")

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        timers = snapshot.timers if snapshot else ()
        rows = []
        for timer in timers:
            status = classify_systemd(timer.active_state)
            rows.append(Row(key=timer.name, text=status.label, status=status,
                            values=(timer.name, timer.activates, timer.next_run or "—", timer.last_run or "nunca",
                                    timer.description),
                            sort=(status.severity, timer.name, timer.activates, timer.next_run or None,
                                  timer.last_run or None, timer.description)))
        waiting = snapshot is None or snapshot.inventory_at is None
        self.timers.set_rows(rows, "Aguardando o inventário…" if waiting else "Nenhum timer encontrado.")
        cron = snapshot.cron if snapshot else ()
        self.cron.set_rows([Row(key=f"{i}", values=(e.source, e.schedule, e.user, e.command),
                                sort=(e.source, e.schedule, e.user, e.command)) for i, e in enumerate(cron)],
                           "Aguardando o inventário…" if waiting else "Nenhuma entrada de cron legível.")

    def reset(self) -> None:
        self.timers.clear()
        self.cron.clear()


# ---------------------------------------------------------------------------
# Eventos (erros do journal)
# ---------------------------------------------------------------------------

class EventsTab(Tab):
    title = "Eventos"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._entries: dict[str, str] = {}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(2, weight=1)
        self.search = _search_entry(toolbar, "Buscar mensagem, unidade…  (Ctrl+F)", self.app.render_current_tab)
        self.search.grid(row=0, column=0, padx=(0, 10))
        self.count = ctk.CTkLabel(toolbar, text="", text_color=GRAY)
        self.count.grid(row=0, column=1, padx=(0, 10))
        self.info = ctk.CTkLabel(toolbar, text="", text_color=GRAY, anchor="e")
        self.info.grid(row=0, column=2, sticky="e")
        self.table = DataTable(
            self,
            [Column("time", "Data/hora", 140), Column("priority", "Prioridade", 95), Column("unit", "Unidade", 220),
             Column("ident", "Processo", 130), Column("message", "Mensagem", 520, True)],
            sort_column="time", sort_desc=True, on_activate=self._show, export_name="eventos",
        )
        self.table.grid(row=1, column=0, sticky="nsew")

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        events = snapshot.events if snapshot else ()
        rows = []
        self._entries = {}
        for index, event in enumerate(events):
            if not _matches(self.search, event.message, event.unit, event.identifier, event.priority_label):
                continue
            key = f"{event.timestamp}:{index}"
            self._entries[key] = (f"{format_timestamp(event.timestamp)}  [{event.priority_label}]  "
                                  f"{event.unit or event.identifier}\n\n{event.message}")
            rows.append(Row(key=key, values=(format_timestamp(event.timestamp), event.priority_label, event.unit,
                                             event.identifier, event.message.replace("\n", " ")),
                            sort=(event.timestamp, event.priority, event.unit or None, event.identifier,
                                  event.message),
                            tag="error" if event.priority <= 3 else "warn" if event.priority == 4 else None))
        waiting = snapshot is None or snapshot.inventory_at is None
        self.table.set_rows(rows, "Aguardando o inventário…" if waiting else "Nenhum erro registrado no período.")
        self.count.configure(text=f"{len(rows)} eventos")
        events_cfg = self.app.settings.events
        text = (f"Prioridade até \"{events_cfg.priority}\" nas últimas {events_cfg.since_hours} h · "
                f"atualizado {fmt_ago(snapshot.inventory_at if snapshot else None)}")
        limited = snapshot is not None and snapshot.system is not None and snapshot.system.journal_access is False
        if limited:
            text = "Journal parcial: adicione o usuário ao grupo systemd-journal · " + text
        self.info.configure(text=text, text_color=YELLOW if limited else GRAY)

    def reset(self) -> None:
        self.table.clear()

    def focus_search(self) -> None:
        self.search.focus_set()

    def _show(self) -> None:
        key = self.table.selected_key()
        if key in self._entries:
            self.app.show_text("Evento do journal", text=self._entries[key])


# ---------------------------------------------------------------------------
# Sistema
# ---------------------------------------------------------------------------

_RUNTIME_STATE_TEXT = {
    RuntimeState.OK: "OK",
    RuntimeState.DISABLED: "desativado na configuração",
    RuntimeState.NOT_INSTALLED: "não instalado",
    RuntimeState.DAEMON_DOWN: "serviço parado",
    RuntimeState.PERMISSION: "sem permissão",
    RuntimeState.ERROR: "erro",
}


class SystemTab(Tab):
    title = "Sistema"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=3, minsize=120)
        self.grid_rowconfigure(4, weight=2, minsize=110)
        self.info = InfoGrid(self, columns=3, wraplength=270)
        self.info.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8), ipady=6)
        _section_label(self, "Discos").grid(row=1, column=0, sticky="w", pady=(0, 4))
        _section_label(self, "E/S de disco").grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(0, 4))
        self.disks = DataTable(
            self,
            [Column("mount", "Montagem", 200, True), Column("fs", "Sistema de arquivos", 190, True),
             Column("size", "Tamanho", 90, anchor="e"), Column("used", "Usado", 90, anchor="e"),
             Column("free", "Livre", 90, anchor="e"), Column("pct", "Uso", 65, anchor="e"),
             Column("inodes", "Inodes", 70, anchor="e")],
            sort_column="pct", sort_desc=True, export_name="discos",
        )
        self.disks.grid(row=2, column=0, sticky="nsew")
        self.io = DataTable(
            self,
            [Column("dev", "Disco", 90), Column("read", "Leitura", 95, anchor="e"),
             Column("write", "Escrita", 95, anchor="e")],
            export_name="disco-es",
        )
        self.io.grid(row=2, column=1, sticky="nsew", padx=(10, 0))
        smart_header = ctk.CTkFrame(self, fg_color="transparent")
        smart_header.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 4))
        smart_header.grid_columnconfigure(1, weight=1)
        _section_label(smart_header, "Saúde dos discos (SMART)").grid(row=0, column=0, sticky="w")
        self.smart_info = ctk.CTkLabel(smart_header, text="", text_color=GRAY, anchor="e")
        self.smart_info.grid(row=0, column=1, sticky="e")
        self.smart = DataTable(
            self,
            [Column("dev", "Disco", 110), Column("model", "Modelo", 220), Column("size", "Capacidade", 115, anchor="e"),
             Column("temp", "Temperatura", 120, anchor="e"), Column("hours", "Horas ligado", 125, anchor="e"),
             Column("wear", "Desgaste", 95, anchor="e"), Column("problems", "Problemas / mensagem", 300, True)],
            tree_column=Column("status", "Saúde", 115), sort_column="status", export_name="smart",
        )
        self.smart.grid(row=4, column=0, columnspan=2, sticky="nsew")

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        system = snapshot.system if snapshot else None
        metrics = snapshot.metrics if snapshot else None
        updates = snapshot.updates if snapshot else None
        items: list[tuple[str, str, tuple[str, str] | None]] = []
        if system is None:
            items.append(("Inventário", "aguardando a primeira coleta…", GRAY))
        else:
            temps = ", ".join(f"{name} {fmt_num(value, 0)} °C" for name, value in system.temperatures) or "—"
            items += [
                ("Hostname", system.hostname or "—", None),
                ("Sistema", system.os_name or "—", None),
                ("Kernel", f"{system.kernel} ({system.arch})", None),
                ("CPU", f"{system.cpu_model or '—'}"
                        + (f" · {metrics.cpu_count} vCPU" if metrics and metrics.cpu_count else ""), None),
                ("Virtualização", system.virtualization, None),
                ("Boot", f"{system.boot_time or '—'} "
                         f"(uptime {fmt_duration(metrics.uptime_seconds if metrics else None)})", None),
                ("Fuso horário", system.timezone or "—", None),
                ("Endereços IP", ", ".join(system.ip_addresses) or "—", None),
                ("Usuários logados", "—" if system.logged_users is None else str(system.logged_users), None),
                ("Unidades com falha", "—" if system.failed_units is None else str(system.failed_units),
                 RED if system.failed_units else None),
                ("Reinício pendente", "sim" if system.reboot_required else "não",
                 YELLOW if system.reboot_required else None),
                ("Temperaturas", temps, None),
                ("Atualizações", self._updates_text(updates), YELLOW if updates and updates.security else None),
                ("Falhas de login SSH (24 h)", self._ssh_text(system),
                 RED if (system.ssh_failed_logins_24h or 0) >= 100 else None),
                ("Acesso ao journal", {True: "completo", False: "parcial (sem grupo systemd-journal/adm)",
                                       None: "—"}[system.journal_access],
                 YELLOW if system.journal_access is False else None),
                ("Swap", self._swap_text(metrics), None),
            ]
        for runtime in snapshot.runtimes if snapshot else ():
            text = _RUNTIME_STATE_TEXT[runtime.state]
            if runtime.state is RuntimeState.OK:
                text += f" · {len(runtime.items)} {'itens' if len(runtime.items) != 1 else 'item'}"
            elif runtime.message and runtime.state not in (RuntimeState.NOT_INSTALLED, RuntimeState.DISABLED):
                text += f" · {runtime.message}"
            color = RED if runtime.state in (RuntimeState.ERROR, RuntimeState.PERMISSION,
                                             RuntimeState.DAEMON_DOWN) else None
            items.append((runtime.kind.label if runtime.kind is not ServiceKind.LIBVIRT else "libvirt", text, color))
        self.info.set_items(items)

        disks = metrics.disks if metrics else ()
        self.disks.set_rows([
            Row(key=d.mount, values=(d.mount, d.filesystem, fmt_kb(d.size_kb), fmt_kb(d.used_kb), fmt_kb(d.avail_kb),
                                     fmt_pct(d.use_percent), fmt_pct(d.inode_percent)),
                sort=(d.mount, d.filesystem, d.size_kb, d.used_kb, d.avail_kb, d.use_percent, d.inode_percent),
                tag="error" if d.use_percent >= 90 else "warn" if d.use_percent >= 75 else None)
            for d in disks], "Sem dados de disco.")
        io = metrics.disk_io if metrics else ()
        self.io.set_rows([Row(key=d.device, values=(d.device, fmt_rate(d.read_bps), fmt_rate(d.write_bps)),
                              sort=(d.device, d.read_bps, d.write_bps)) for d in io], "Sem dados.")
        self._render_smart(server, snapshot)

    def _render_smart(self, server: str, snapshot: HostSnapshot | None) -> None:
        report = snapshot.smart if snapshot else None
        labels = {ServiceStatus.ACTIVE: "Saudável", ServiceStatus.DEGRADED: "Atenção", ServiceStatus.FAILED: "Falhando",
                  ServiceStatus.UNKNOWN: "Sem dados"}
        rows = []
        for disk in report.disks if report else ():
            status = disk.status
            rows.append(Row(
                key=disk.device, text=labels.get(status, status.label), status=status,
                values=(disk.device, disk.model or "—", fmt_bytes(disk.capacity_bytes),
                        "—" if disk.temperature is None else f"{fmt_num(disk.temperature, 0)} °C",
                        "—" if disk.power_on_hours is None else fmt_num(disk.power_on_hours, 0),
                        "—" if disk.percentage_used is None else f"{disk.percentage_used}%",
                        ", ".join(disk.problems) or disk.message or "nenhum"),
                sort=((status.severity, disk.device), disk.device, disk.model, disk.capacity_bytes, disk.temperature,
                      disk.power_on_hours, disk.percentage_used, disk.message),
            ))
        if self.app.server_config(server).smart == "off":
            empty, info = "SMART desativado (\"smart\": \"off\").", ""
        elif report is None:
            empty, info = "Aguardando a coleta de segurança/SMART…", ""
        else:
            empty = report.message or "Nenhum disco."
            info = "" if report.state is RuntimeState.OK else report.message
        self.smart.set_rows(rows, empty)
        self.smart_info.configure(text=info, text_color=YELLOW if info else GRAY)

    @staticmethod
    def _updates_text(updates) -> str:
        if updates is None:
            return "—"
        if updates.pending is None:
            return f"{updates.manager}: desconhecido"
        text = f"{updates.pending} pendente{'s' if updates.pending != 1 else ''} ({updates.manager})"
        if updates.security:
            text += f", {updates.security} de segurança"
        return text

    @staticmethod
    def _ssh_text(system) -> str:
        if system.ssh_failed_logins_24h is None:
            return "sem acesso ao journal" if system.journal_access is False else "—"
        return str(system.ssh_failed_logins_24h)

    @staticmethod
    def _swap_text(metrics) -> str:
        if metrics is None or not metrics.swap_total_mb:
            return "—"
        return f"{fmt_bytes((metrics.swap_used_mb or 0) * 1024 ** 2)} de {fmt_bytes(metrics.swap_total_mb * 1024 ** 2)}"

    def reset(self) -> None:
        self.disks.clear()
        self.io.clear()
        self.smart.clear()


# ---------------------------------------------------------------------------
# Histórico (gráficos)
# ---------------------------------------------------------------------------

WINDOWS = {"15 min": 900, "1 h": 3600, "6 h": 6 * 3600, "24 h": 86400, "7 dias": 7 * 86400}


class HistoryTab(Tab):
    title = "Histórico"
    REFRESH_SECONDS = 5.0

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._last_query = 0.0
        self._last_key: tuple | None = None
        self._series = None
        self.grid_columnconfigure((0, 1), weight=1, uniform="chart")
        self.grid_rowconfigure((1, 2, 3), weight=1, uniform="chart_row")
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(1, weight=1)
        self.window = ctk.CTkSegmentedButton(toolbar, values=list(WINDOWS), command=lambda _v: self._force())
        self.window.set("1 h")
        self.window.grid(row=0, column=0, padx=(0, 10))
        self.info = ctk.CTkLabel(toolbar, text="", text_color=GRAY, anchor="e")
        self.info.grid(row=0, column=1, sticky="e", padx=(0, 10))
        _button(toolbar, "Exportar CSV…", self._export, "neutral", 130).grid(row=0, column=2)

        percent = lambda v: f"{fmt_num(v, 0)}%"  # noqa: E731
        self.usage = LineChart(self, "Uso de recursos (%)", percent, fixed_max=100, height=150)
        self.load = LineChart(self, "Load average (1 min)", lambda v: fmt_num(v, 2), height=150)
        self.net = LineChart(self, "Rede (por segundo)", fmt_rate, height=150, binary=True)
        self.disk = LineChart(self, "E/S de disco (por segundo)", fmt_rate, height=150, binary=True)
        self.steal = LineChart(self, "CPU steal e iowait (%)", lambda v: f"{fmt_num(v, 1)}%", height=150)
        self.latency = LineChart(self, "Latência Windows → servidor (ms)", lambda v: f"{fmt_num(v, 0)} ms",
                                 height=150)
        for index, chart in enumerate((self.usage, self.load, self.net, self.disk, self.steal, self.latency)):
            row, column = divmod(index, 2)
            chart.grid(row=row + 1, column=column, sticky="nsew", padx=(0, 5) if column == 0 else (5, 0),
                       pady=(0 if row == 0 else 5, 0 if row == 2 else 5))

    def _force(self) -> None:
        self._last_query = 0.0
        self.app.render_current_tab()

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        history = self.app.history
        if history is None:
            self.info.configure(text="Histórico desativado (settings.history.enabled = false).")
            return
        window = WINDOWS[self.window.get()]
        key = (server, window)
        now = time.monotonic()
        if key == self._last_key and now - self._last_query < self.REFRESH_SECONDS:
            return
        self._last_key, self._last_query = key, now
        series = history.query(server, window)
        self._series = series
        v = series.values
        ts, bucket = series.timestamps, series.bucket_seconds
        self.usage.set_data(ts, [Series("CPU", v["cpu"], 0), Series("Memória", v["mem"], 1),
                                 Series("Disco /", v["disk"], 2)], window, bucket)
        self.load.set_data(ts, [Series("Load 1 min", v["load1"], 0)], window, bucket)
        self.net.set_data(ts, [Series("Recebido", v["net_rx"], 0), Series("Enviado", v["net_tx"], 1)],
                          window, bucket)
        self.disk.set_data(ts, [Series("Leitura", v["disk_read"], 0), Series("Escrita", v["disk_write"], 1)],
                           window, bucket)
        self.steal.set_data(ts, [Series("Steal", v["steal"], 0), Series("iowait", v["iowait"], 1)], window, bucket)
        self.latency.set_data(ts, [Series("Latência", v["latency"], 0)], window, bucket)
        retention = self.app.settings.history.retention_days
        self.info.configure(text=f"{len(series)} pontos · 1 ponto a cada {fmt_duration(bucket)} · "
                                 f"retenção {fmt_num(retention, 0)} dias")

    def reset(self) -> None:
        self._last_key = None

    def _export(self) -> None:
        series = self._series
        if series is None or not len(series):
            self.app.set_status("Nada para exportar neste período.", warning=True)
            return
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
        server = self._last_key[0] if self._last_key else "servidor"
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            initialfile=f"historico-{server}-{stamp}.csv",
                                            filetypes=[("CSV (Excel)", "*.csv")])
        if not path:
            return
        names = list(series.values)
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle, delimiter=";")
            writer.writerow(["data_hora", *names])
            for i, ts in enumerate(series.timestamps):
                row = [dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")]
                row += ["" if series.values[n][i] is None else f"{series.values[n][i]:.3f}".replace(".", ",")
                        for n in names]
                writer.writerow(row)
        self.app.set_status(f"Histórico exportado para {path}")


# ---------------------------------------------------------------------------
# Visão geral (todos os servidores)
# ---------------------------------------------------------------------------

_HEALTH_STATUS = {
    HealthLevel.OK: ServiceStatus.ACTIVE,
    HealthLevel.UNKNOWN: ServiceStatus.UNKNOWN,
    HealthLevel.WARNING: ServiceStatus.DEGRADED,
    HealthLevel.CRITICAL: ServiceStatus.FAILED,
}
_HEALTH_LABEL = {HealthLevel.OK: "OK", HealthLevel.UNKNOWN: "Aguardando", HealthLevel.WARNING: "Atenção",
                 HealthLevel.CRITICAL: "Crítico"}


class OverviewPanel(ctk.CTkFrame):
    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, fg_color="transparent")
        self.app = app
        #: chave do problema → (servidor, chave da carga, aba de destino)
        self._problem_targets: dict[str, tuple[str, str | None, str | None]] = {}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(3, weight=1)
        _section_label(self, "Servidores").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.servers = DataTable(
            self,
            [Column("name", "Servidor", 115), Column("conn", "Conexão", 110),
             Column("cpu", "CPU", 50, anchor="e"), Column("mem", "Mem", 55, anchor="e"),
             Column("disk", "Disco", 60, anchor="e"), Column("load", "Load", 52, anchor="e"),
             Column("net", "Rede ↓ / ↑", 145, anchor="e"), Column("latency", "Latência", 82, anchor="e"),
             Column("uptime", "Uptime", 72, anchor="e"), Column("ok", "Ativas", 66, anchor="e"),
             Column("bad", "Falhas", 66, anchor="e"), Column("mix", "Cont/Pod/VM", 114, anchor="e"),
             Column("security", "Segurança", 102, anchor="e"), Column("alerts", "Alertas", 110, True)],
            tree_column=Column("health", "Saúde", 92),
            on_activate=self._open_server, export_name="servidores",
            menu_items=lambda: [("Abrir servidor", self._open_server)],
        )
        self.servers.grid(row=1, column=0, sticky="nsew")
        _section_label(self, "Problemas em todos os servidores").grid(row=2, column=0, sticky="w", pady=(10, 4))
        self.problems = DataTable(
            self,
            [Column("server", "Servidor", 150), Column("name", "Item", 280, True), Column("type", "Tipo", 100),
             Column("state", "Estado", 240), Column("detail", "Detalhe", 300, True)],
            tree_column=Column("status", "Status", 120),
            on_activate=self._open_problem, export_name="problemas",
            menu_items=lambda: [("Ir para o item", self._open_problem)],
        )
        self.problems.grid(row=3, column=0, sticky="nsew")

    def render(self, snapshots: dict[str, HostSnapshot], connections: dict[str, ConnectionEvent],
               health: Callable[[str], HealthLevel]) -> None:
        server_rows, problem_rows = [], []
        self._problem_targets = {}
        for name in self.app.manager.server_names:
            snapshot, event = snapshots.get(name), connections.get(name)
            level = health(name)
            state = event.state.label if event else "Aguardando…"
            metrics = snapshot.metrics if snapshot else None
            fullest = metrics.fullest_disk if metrics else None
            counts = snapshot.counts() if snapshot else None
            mix = "—"
            if snapshot:
                containers = sum(snapshot.count_kind(k) for k in (ServiceKind.DOCKER, ServiceKind.PODMAN,
                                                                   ServiceKind.LXD))
                mix = (f"{containers} / {snapshot.count_kind(ServiceKind.KUBERNETES)} / "
                       f"{snapshot.count_kind(ServiceKind.LIBVIRT)}")
            alerts = ", ".join(snapshot.resource_alerts) if snapshot else ""
            if snapshot and snapshot.system and snapshot.system.reboot_required:
                alerts = ", ".join(a for a in (alerts, "reinício pendente") if a)
            net = "—"
            if metrics and metrics.net_rx_bps is not None:
                net = f"{fmt_rate(metrics.net_rx_bps)} / {fmt_rate(metrics.net_tx_bps)}"
            failed = (counts[ServiceStatus.FAILED] + counts[ServiceStatus.DEGRADED]) if counts else None
            latency = snapshot.latency_ms if snapshot else None
            score = snapshot.security.score if snapshot and snapshot.security else None
            server_rows.append(Row(
                key=name, text=_HEALTH_LABEL[level], status=_HEALTH_STATUS[level],
                values=(name, state, fmt_pct(metrics.cpu_percent) if metrics else "—",
                        fmt_pct(metrics.mem_percent) if metrics else "—",
                        fmt_pct(fullest.use_percent) if fullest else "—",
                        fmt_num(metrics.load_avg[0], 2) if metrics and metrics.load_avg else "—", net,
                        "—" if latency is None else f"{fmt_num(latency, 0)} ms",
                        fmt_duration(metrics.uptime_seconds) if metrics else "—",
                        str(counts[ServiceStatus.ACTIVE]) if counts else "—",
                        "—" if failed is None else str(failed), mix, "—" if score is None else f"{score}/100", alerts),
                sort=(-level, name, state, metrics.cpu_percent if metrics else None,
                      metrics.mem_percent if metrics else None, fullest.use_percent if fullest else None,
                      metrics.load_avg[0] if metrics and metrics.load_avg else None,
                      metrics.net_rx_bps if metrics else None, latency, metrics.uptime_seconds if metrics else None,
                      counts[ServiceStatus.ACTIVE] if counts else None, failed, mix, score, alerts or None),
            ))
            if event is not None and event.state is ConnectionState.RECONNECTING:
                key = f"{name}|offline"
                self._problem_targets[key] = (name, None, None)
                problem_rows.append(Row(key=key, text="Offline", status=ServiceStatus.FAILED,
                                        values=(name, name, "Servidor", "Sem conexão SSH", event.message),
                                        sort=((ServiceStatus.FAILED.severity, -1), name, name, "Servidor", "",
                                              event.message)))
            if snapshot is None:
                continue
            for alert in snapshot.resource_alerts:
                key = f"{name}|res|{alert}"
                self._problem_targets[key] = (name, None, None)
                problem_rows.append(Row(key=key, text="Limite", status=ServiceStatus.DEGRADED,
                                        values=(name, alert, "Recurso", "acima do limite configurado", ""),
                                        sort=((ServiceStatus.DEGRADED.severity, 2), name, alert, "Recurso", "",
                                              "")))
            for service in snapshot.services:
                if service.status not in (ServiceStatus.FAILED, ServiceStatus.DEGRADED):
                    continue
                key = f"{name}|{service.key}"
                self._problem_targets[key] = (name, service.key, None)
                problem_rows.append(Row(
                    key=key, text=service.status.label, status=service.status,
                    values=(name, service.name + ("  ★" if service.critical else ""), service.type_label,
                            service.state_text, service.description),
                    sort=((service.status.severity, 0 if service.critical else 1), name, service.name,
                          service.type_label,
                          service.state_text, service.description)))
            problem_rows += self._host_problems(name, snapshot)
        self.servers.set_rows(server_rows)
        self.problems.set_rows(problem_rows, "Nenhum problema detectado. Tudo em ordem.")

    def _open_server(self) -> None:
        name = self.servers.selected_key()
        if name:
            self.app.select_server(name)

    def _host_problems(self, name: str, snapshot: HostSnapshot) -> list[Row]:
        """Endpoints fora do ar, discos com SMART ruim e falhas críticas de segurança."""
        rows = []

        def add(key: str, status: ServiceStatus, text: str, item: str, kind: str, state: str, detail: str,
                tab: str) -> None:
            self._problem_targets[key] = (name, None, tab)
            rows.append(Row(key=key, text=text, status=status, values=(name, item, kind, state, detail),
                            sort=((status.severity, 3), name, item, kind, state, detail)))

        for endpoint in snapshot.failing_endpoints():
            add(f"{name}|endpoint|{endpoint.target}", endpoint.status, endpoint.status.label, endpoint.target,
                "Endpoint", "fora do ar" if endpoint.status is ServiceStatus.FAILED else "atenção", endpoint.detail,
                "VPS")
        for disk in snapshot.smart.disks if snapshot.smart else ():
            if disk.status in (ServiceStatus.FAILED, ServiceStatus.DEGRADED):
                add(f"{name}|smart|{disk.device}", disk.status, disk.status.label, disk.device, "SMART",
                    disk.model, ", ".join(disk.problems), "Sistema")
        if snapshot.security is not None:
            for check in snapshot.security.checks:
                if check.level is CheckLevel.FAIL:
                    add(f"{name}|security|{check.id}", ServiceStatus.DEGRADED, "Segurança", check.title,
                        "Segurança", check.category, check.detail, "Segurança")
        return rows

    def _open_problem(self) -> None:
        key = self.problems.selected_key()
        if key in self._problem_targets:
            server, service_key, tab = self._problem_targets[key]
            self.app.select_server(server, focus_key=service_key, tab=tab)

    def clear(self) -> None:
        self.servers.clear()
        self.problems.clear()

