"""Janela principal: métricas, tabela de serviços, filtros, ações e modais de logs.

Regra de ouro de threading: somente a thread da UI toca em widgets. Eventos do
monitor chegam por ``MonitorManager.events`` e chamadas de outras threads (ex.:
menu da bandeja) por :meth:`Dashboard.call_in_ui`; ambos são drenados por
``_pump`` a cada 100 ms via ``after``.
"""

from __future__ import annotations

import logging
import queue
import sys
import time
import tkinter as tk
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import Future
from pathlib import Path
from tkinter import ttk

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk

from config.settings import Config
from core.models import (
    ActionOutcome,
    ActionResultEvent,
    AlertKind,
    ConnectionEvent,
    ConnectionState,
    HealthLevel,
    HostSnapshot,
    MonitorEvent,
    ServiceAction,
    ServiceAlertEvent,
    ServiceInfo,
    ServiceKind,
    ServiceStatus,
    SnapshotEvent,
)
from core.monitor import MonitorManager
from core.notifier import Notifier
from core.ssh_client import build_docker_logs_command, build_journal_command

log = logging.getLogger(__name__)

APP_TITLE = "Firawynix Monitor"
UI_FONT = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO_FONT = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

# Cores no formato (modo claro, modo escuro) aceito pelo CustomTkinter.
GREEN = ("#1a7f37", "#3fb950")
RED = ("#cf222e", "#ff6b6b")
YELLOW = ("#9a6700", "#f2cc60")
GRAY = ("#57606a", "#8b949e")
PURPLE = ("#8250df", "#a371f7")
BLUE = ("#1f6aa5", "#1f6aa5")
CARD_BG = ("#f6f8fa", "#1c2128")
BANNER_WARN = ("#fff8c5", "#3d3000")
BANNER_ERROR = ("#ffebe9", "#4a1319")
BANNER_INFO = ("#ddf4ff", "#0c2d48")

STATUS_COLORS = {
    ServiceStatus.ACTIVE: GREEN,
    ServiceStatus.ACTIVATING: YELLOW,
    ServiceStatus.STOPPED: GRAY,
    ServiceStatus.FAILED: RED,
    ServiceStatus.UNKNOWN: PURPLE,
}
CONNECTION_COLORS = {
    ConnectionState.CONNECTING: YELLOW,
    ConnectionState.CONNECTED: GREEN,
    ConnectionState.RECONNECTING: RED,
    ConnectionState.STOPPED: GRAY,
}

STATUS_FILTERS: dict[str, set[ServiceStatus] | None] = {
    "Todos": None,
    "Ativos": {ServiceStatus.ACTIVE},
    "Com Falha": {ServiceStatus.FAILED},
    "Parados": {ServiceStatus.STOPPED},
    "Iniciando": {ServiceStatus.ACTIVATING},
}
KIND_FILTERS: dict[str, ServiceKind | None] = {
    "Tudo": None,
    "systemd": ServiceKind.SYSTEMD,
    "Docker": ServiceKind.DOCKER,
}
INTERVAL_OPTIONS = (2, 5, 10, 30, 60)


# ---------------------------------------------------------------------------
# Formatação (pt-BR)
# ---------------------------------------------------------------------------

def fmt_num(value: float, digits: int = 1) -> str:
    return f"{value:.{digits}f}".replace(".", ",")


def fmt_mb(mb: int | float | None) -> str:
    if mb is None:
        return "—"
    return f"{fmt_num(mb / 1024)} GB" if mb >= 1024 else f"{int(mb)} MB"


def fmt_kb(kb: int | float | None) -> str:
    if kb is None:
        return "—"
    gb = kb / 1024 / 1024
    if gb >= 1024:
        return f"{fmt_num(gb / 1024)} TB"
    return f"{fmt_num(gb)} GB" if gb >= 1 else f"{int(kb / 1024)} MB"


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs}s"


def usage_color(percent: float | None) -> tuple[str, str]:
    if percent is None:
        return GRAY
    if percent >= 90:
        return RED
    if percent >= 75:
        return YELLOW
    return BLUE


# ---------------------------------------------------------------------------
# Componentes
# ---------------------------------------------------------------------------

class MetricCard(ctk.CTkFrame):
    def __init__(self, master, title: str, *, with_bar: bool = True) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text=title.upper(), text_color=GRAY, anchor="w",
                     font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 0))
        self._value_label = ctk.CTkLabel(self, text="—", anchor="w", font=ctk.CTkFont(size=26, weight="bold"))
        self._value_label.grid(row=1, column=0, sticky="ew", padx=14)
        self._detail = ctk.CTkLabel(self, text="", anchor="w", justify="left", text_color=GRAY,
                                    font=ctk.CTkFont(size=12))
        self._detail.grid(row=2, column=0, sticky="ew", padx=14)
        self._note = ctk.CTkLabel(self, text="", anchor="w", font=ctk.CTkFont(size=12), height=18)
        self._note.grid(row=3, column=0, sticky="ew", padx=14)
        self._note.grid_remove()
        self._bar = None
        if with_bar:
            self._bar = ctk.CTkProgressBar(self, height=6, corner_radius=3)
            self._bar.set(0)
            self._bar.grid(row=4, column=0, sticky="ew", padx=14, pady=(6, 12))
        else:
            ctk.CTkFrame(self, height=6, fg_color="transparent").grid(row=4, column=0, pady=(6, 12))

    def set_values(self, value: str, detail: str = "", fraction: float | None = None,
                   color: tuple[str, str] | None = None, *, note: str = "",
                   note_color: tuple[str, str] | None = None) -> None:
        self._value_label.configure(text=value)
        self._detail.configure(text=detail)
        if note:
            self._note.configure(text=note, text_color=note_color or GRAY)
            self._note.grid()
        else:
            self._note.grid_remove()
        if self._bar is not None:
            self._bar.set(max(0.0, min(1.0, fraction or 0.0)))
            self._bar.configure(progress_color=color or BLUE)


class ServicesCard(ctk.CTkFrame):
    """Total de serviços ativos vs. com falha."""

    def __init__(self, master) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(self, text="SERVIÇOS", text_color=GRAY, anchor="w",
                     font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, columnspan=2,
                                                                    sticky="ew", padx=14, pady=(10, 0))
        big = ctk.CTkFont(size=26, weight="bold")
        self._active = ctk.CTkLabel(self, text="—", text_color=GREEN, font=big, anchor="w")
        self._failed = ctk.CTkLabel(self, text="—", text_color=RED, font=big, anchor="w")
        self._active.grid(row=1, column=0, sticky="w", padx=(14, 4))
        self._failed.grid(row=1, column=1, sticky="w", padx=(4, 14))
        small = ctk.CTkFont(size=12)
        ctk.CTkLabel(self, text="ativos", text_color=GRAY, font=small, anchor="w").grid(
            row=2, column=0, sticky="w", padx=(14, 4))
        ctk.CTkLabel(self, text="com falha", text_color=GRAY, font=small, anchor="w").grid(
            row=2, column=1, sticky="w", padx=(4, 14))
        self._detail = ctk.CTkLabel(self, text="", text_color=GRAY, font=small, anchor="w")
        self._detail.grid(row=3, column=0, columnspan=2, sticky="ew", padx=14, pady=(2, 12))

    def set_counts(self, snapshot: HostSnapshot | None) -> None:
        if snapshot is None:
            self._active.configure(text="—")
            self._failed.configure(text="—")
            self._detail.configure(text="")
            return
        counts = snapshot.counts()
        containers = len(snapshot.docker.containers)
        self._active.configure(text=str(counts[ServiceStatus.ACTIVE]))
        self._failed.configure(text=str(counts[ServiceStatus.FAILED]))
        parts = [f"{counts[ServiceStatus.STOPPED]} parados"]
        if counts[ServiceStatus.ACTIVATING]:
            parts.append(f"{counts[ServiceStatus.ACTIVATING]} iniciando")
        parts.append(f"{len(snapshot.services)} total")
        if containers:
            parts.append(f"{containers} contêineres")
        self._detail.configure(text=" · ".join(parts))


class ServiceTable(ctk.CTkFrame):
    """ttk.Treeview com tema escuro, ordenação por coluna e atualização incremental
    (preserva seleção e rolagem entre coletas)."""

    COLUMNS = (
        # id, título, largura, expande — "#0" é a coluna-árvore (ícone colorido + texto)
        ("#0", "Status", 130, False),
        ("name", "Serviço", 280, True),
        ("kind", "Tipo", 90, False),
        ("state", "Estado", 190, False),
        ("description", "Descrição", 380, True),
    )

    def __init__(self, master, *, on_select: Callable[[], None], on_activate: Callable[[], None],
                 on_context: Callable[[tk.Event], None]) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.sort_column = "#0"
        self.sort_desc = False
        self._services: dict[str, ServiceInfo] = {}
        self._rows: dict[str, tuple] = {}
        self._iid_by_key: dict[str, str] = {}
        self._key_by_iid: dict[str, str] = {}
        self._next_iid = 0

        self._setup_style()
        self._dots = self._create_status_dots()
        self.tree = ttk.Treeview(self, columns=[c[0] for c in self.COLUMNS[1:]], show="tree headings",
                                 selectmode="browse", style="Services.Treeview")
        for column, title, width, stretch in self.COLUMNS:
            self.tree.heading(column, text=title, anchor="w", command=lambda c=column: self.sort_by(c))
            self.tree.column(column, width=width, minwidth=70, stretch=stretch, anchor="w")
        scrollbar = ctk.CTkScrollbar(self, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(2, 6), pady=8)

        self._empty_label = ctk.CTkLabel(self, text="", text_color=GRAY, fg_color="transparent")
        self._apply_tag_colors()
        self._update_headings()

        self.tree.bind("<<TreeviewSelect>>", lambda _e: on_select())
        self.tree.bind("<Double-1>", lambda e: on_activate() if self.tree.identify_row(e.y) else None)
        self.tree.bind("<Return>", lambda _e: on_activate())
        self.tree.bind("<Button-3>", on_context)
        if sys.platform == "darwin":
            self.tree.bind("<Button-2>", on_context)

    def _palette(self) -> dict[str, str]:
        dark = ctk.get_appearance_mode() == "Dark"
        return {
            "bg": "#1c2128" if dark else "#ffffff",
            "fg": "#e6edf3" if dark else "#1f2328",
            "heading_bg": "#262c36" if dark else "#eaeef2",
            "heading_hover": "#30363d" if dark else "#d0d7de",
            "selected": "#1f6aa5",
            "index": 1 if dark else 0,
        }

    def _setup_style(self) -> None:
        p = self._palette()
        scaling = ctk.ScalingTracker.get_widget_scaling(self)
        style = ttk.Style(self)
        if style.theme_use() != "clam":
            style.theme_use("clam")  # "clam" permite customizar cores no Windows
        style.configure("Services.Treeview", background=p["bg"], fieldbackground=p["bg"], foreground=p["fg"],
                        rowheight=int(28 * scaling), borderwidth=0, relief="flat", font=(UI_FONT, 10))
        style.configure("Services.Treeview.Heading", background=p["heading_bg"], foreground=p["fg"],
                        relief="flat", borderwidth=0, font=(UI_FONT, 10, "bold"), padding=(8, 6))
        style.map("Services.Treeview", background=[("selected", p["selected"])],
                  foreground=[("selected", "#ffffff")])
        style.map("Services.Treeview.Heading", background=[("active", p["heading_hover"])])
        style.layout("Services.Treeview", [("Services.Treeview.treearea", {"sticky": "nswe"})])
        # Remove o indicador de expandir/recolher (as linhas não têm filhos).
        style.layout("Treeview.Item", [
            ("Treeitem.padding", {"sticky": "nswe", "children": [
                ("Treeitem.image", {"side": "left", "sticky": ""}),
                ("Treeitem.focus", {"side": "left", "sticky": "", "children": [
                    ("Treeitem.text", {"side": "left", "sticky": ""}),
                ]}),
            ]}),
        ])

    def _create_status_dots(self) -> dict[ServiceStatus, ImageTk.PhotoImage]:
        """Bolinhas coloridas por status (Treeview não colore células individuais)."""
        index = self._palette()["index"]
        size = max(10, round(12 * ctk.ScalingTracker.get_widget_scaling(self)))
        dots = {}
        for status, colors in STATUS_COLORS.items():
            big = Image.new("RGBA", (size * 4 + 8, size * 4), (0, 0, 0, 0))
            ImageDraw.Draw(big).ellipse((4, 4, size * 4 - 4, size * 4 - 4), fill=colors[index])
            image = big.resize((size + 2, size), Image.Resampling.LANCZOS)
            dots[status] = ImageTk.PhotoImage(image, master=self)
        return dots

    def _apply_tag_colors(self) -> None:
        index = self._palette()["index"]
        for status, colors in STATUS_COLORS.items():
            if status in (ServiceStatus.FAILED, ServiceStatus.ACTIVATING):
                self.tree.tag_configure(status.value, foreground=colors[index])
            elif status is ServiceStatus.STOPPED:
                self.tree.tag_configure(status.value, foreground="#9da7b3" if index else "#57606a")

    # -- dados --------------------------------------------------------------

    def set_services(self, services: list[ServiceInfo], empty_message: str = "") -> None:
        ordered = sorted(services, key=self._sort_key, reverse=self.sort_desc)
        new_keys = [s.key for s in ordered]
        for key in set(self._rows) - set(new_keys):
            iid = self._iid_by_key.pop(key)
            self._key_by_iid.pop(iid, None)
            self._rows.pop(key, None)
            self.tree.delete(iid)
        for service in ordered:
            values = (service.name, service.kind.label, service.state_text, service.description)
            row = (service.status, *values)
            item = {"text": f" {service.status.label}", "image": self._dots[service.status],
                    "values": values, "tags": (service.status.value,)}
            iid = self._iid_by_key.get(service.key)
            if iid is None:
                iid = f"r{self._next_iid}"
                self._next_iid += 1
                self._iid_by_key[service.key] = iid
                self._key_by_iid[iid] = service.key
                self.tree.insert("", "end", iid=iid, **item)
            elif self._rows.get(service.key) != row:
                self.tree.item(iid, **item)
            self._rows[service.key] = row
        wanted = [self._iid_by_key[k] for k in new_keys]
        if list(self.tree.get_children()) != wanted:
            for index, iid in enumerate(wanted):
                self.tree.move(iid, "", index)
        self._services = {s.key: s for s in ordered}
        if not ordered and empty_message:
            self._empty_label.configure(text=empty_message)
            self._empty_label.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self._empty_label.place_forget()

    def selected_service(self) -> ServiceInfo | None:
        selection = self.tree.selection()
        if not selection:
            return None
        key = self._key_by_iid.get(selection[0])
        return self._services.get(key) if key else None

    def select_row_at(self, y: int) -> bool:
        iid = self.tree.identify_row(y)
        if not iid:
            return False
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        return True

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        self._services.clear()
        self._iid_by_key.clear()
        self._key_by_iid.clear()

    # -- ordenação ----------------------------------------------------------

    def sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_column, self.sort_desc = column, False
        self._update_headings()
        self.set_services(list(self._services.values()))

    def _sort_key(self, service: ServiceInfo) -> tuple:
        name = service.name.casefold()
        column = self.sort_column
        if column == "#0":
            return service.status.severity, name
        if column == "kind":
            return service.kind.value, name
        if column == "state":
            return service.state_text.casefold(), name
        if column == "description":
            return service.description.casefold(), name
        return (name,)

    def _update_headings(self) -> None:
        for column, title, _width, _stretch in self.COLUMNS:
            arrow = (" ▼" if self.sort_desc else " ▲") if column == self.sort_column else ""
            self.tree.heading(column, text=title + arrow)


class ConfirmDialog(ctk.CTkToplevel):
    """Diálogo modal de confirmação (ou aviso, se ``cancel_text`` for None)."""

    def __init__(self, master, *, title: str, message: str, confirm_text: str = "Confirmar",
                 cancel_text: str | None = "Cancelar", danger: bool = False) -> None:
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.transient(master)
        self._result = False

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=18)
        ctk.CTkLabel(body, text=title, anchor="w", font=ctk.CTkFont(size=16, weight="bold")).pack(fill="x")
        ctk.CTkLabel(body, text=message, anchor="w", justify="left", wraplength=440).pack(fill="x", pady=(8, 18))
        buttons = ctk.CTkFrame(body, fg_color="transparent")
        buttons.pack(fill="x")
        if cancel_text:
            ctk.CTkButton(buttons, text=cancel_text, width=110, fg_color="transparent", border_width=1,
                          text_color=("gray10", "gray90"), command=self._cancel).pack(side="right", padx=(8, 0))
        confirm = ctk.CTkButton(buttons, text=confirm_text, width=120, command=self._confirm,
                                fg_color=RED if danger else BLUE,
                                hover_color=("#a40e26", "#d9363e") if danger else None)
        confirm.pack(side="right")

        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        _center_on(self, master)

    def show(self) -> bool:
        self.after(60, lambda: _make_modal(self))
        self.wait_window(self)
        return self._result

    def _confirm(self) -> None:
        self._result = True
        self.destroy()

    def _cancel(self) -> None:
        self._result = False
        self.destroy()


class LogViewer(ctk.CTkToplevel):
    """Modal com as últimas N linhas do journal (systemd) ou ``docker logs``."""

    LINE_OPTIONS = ("50", "100", "200", "500", "1000")
    _PERMISSION_HINTS = ("not seeing messages from other users", "insufficient permissions",
                         "no journal files were opened")

    def __init__(self, master, *, server: str, service: ServiceInfo, lines: int,
                 fetch: Callable[[int], Future[str]], command_preview: Callable[[int], str]) -> None:
        super().__init__(master)
        self.title(f"Logs — {service.name} @ {server}")
        self.geometry("1000x620")
        self.minsize(640, 360)
        self.transient(master)
        self._fetch = fetch
        self._preview = command_preview
        self._future: Future[str] | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=f"{service.name}  ·  {server}", anchor="w",
                     font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, sticky="w")
        self._command_label = ctk.CTkLabel(header, text="", anchor="w", text_color=GRAY,
                                           font=ctk.CTkFont(family=MONO_FONT, size=12))
        self._command_label.grid(row=1, column=0, sticky="w")

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, rowspan=2, sticky="e")
        ctk.CTkLabel(controls, text="Linhas").pack(side="left", padx=(0, 6))
        initial = str(lines) if str(lines) in self.LINE_OPTIONS else self.LINE_OPTIONS[0]
        options = self.LINE_OPTIONS if initial in self.LINE_OPTIONS else (str(lines), *self.LINE_OPTIONS)
        self._lines = ctk.CTkOptionMenu(controls, values=list(options), width=80, command=lambda _v: self.reload())
        self._lines.set(str(lines) if str(lines) in options else initial)
        self._lines.pack(side="left", padx=(0, 8))
        self._reload_btn = ctk.CTkButton(controls, text="Atualizar", width=96, command=self.reload)
        self._reload_btn.pack(side="left", padx=(0, 8))
        ctk.CTkButton(controls, text="Copiar", width=80, fg_color=("gray75", "gray30"),
                      text_color=("gray10", "gray90"), command=self._copy).pack(side="left", padx=(0, 8))
        ctk.CTkButton(controls, text="Fechar", width=80, fg_color="transparent", border_width=1,
                      text_color=("gray10", "gray90"), command=self.destroy).pack(side="left")

        self._textbox = ctk.CTkTextbox(self, wrap="none", font=ctk.CTkFont(family=MONO_FONT, size=12),
                                    corner_radius=10)
        self._textbox.grid(row=1, column=0, sticky="nsew", padx=16)
        self._status = ctk.CTkLabel(self, text="", anchor="w", text_color=GRAY)
        self._status.grid(row=2, column=0, sticky="ew", padx=18, pady=(6, 12))

        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<F5>", lambda _e: self.reload())
        _center_on(self, master)
        self.after(60, lambda: _make_modal(self))
        self.reload()

    def reload(self) -> None:
        if self._future is not None and not self._future.done():
            return
        lines = int(self._lines.get())
        self._command_label.configure(text=f"$ {self._preview(lines)}")
        self._set_text("Carregando…")
        self._status.configure(text="Consultando o servidor…", text_color=GRAY)
        self._reload_btn.configure(state="disabled")
        self._future = self._fetch(lines)
        self.after(100, self._poll)

    def _poll(self) -> None:
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        future = self._future
        if future is None:
            return
        if not future.done():
            self.after(100, self._poll)
            return
        self._reload_btn.configure(state="normal")
        try:
            text = future.result()
        except Exception as exc:  # noqa: BLE001
            self._set_text(f"Erro ao obter logs: {exc}")
            self._status.configure(text="Falha na consulta", text_color=RED)
            return
        self._set_text(text)
        self._textbox.see("end")
        lower = text.lower()
        if any(hint in lower for hint in self._PERMISSION_HINTS):
            self._status.configure(
                text="Dica: adicione o usuário SSH ao grupo 'systemd-journal' (ou 'adm') para ver todos os logs.",
                text_color=YELLOW)
        else:
            self._status.configure(text=f"{text.count(chr(10)) + 1} linhas · {time.strftime('%H:%M:%S')}",
                                   text_color=GRAY)

    def _set_text(self, text: str) -> None:
        self._textbox.configure(state="normal")
        self._textbox.delete("1.0", "end")
        self._textbox.insert("1.0", text)
        self._textbox.configure(state="disabled")

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._textbox.get("1.0", "end-1c"))
        self._status.configure(text="Logs copiados para a área de transferência.", text_color=GREEN)


def _center_on(window: tk.Misc, master: tk.Misc) -> None:
    window.update_idletasks()
    try:
        if not master.winfo_viewable():
            return
        width, height = window.winfo_width(), window.winfo_height()
        x = master.winfo_rootx() + (master.winfo_width() - width) // 2
        y = master.winfo_rooty() + (master.winfo_height() - height) // 3
        window.geometry(f"+{max(0, x)}+{max(0, y)}")
    except tk.TclError:
        pass


def _make_modal(window: tk.Toplevel, attempts: int = 10) -> None:
    try:
        if not window.winfo_exists():
            return
        window.lift()
        window.focus_force()
        window.grab_set()
    except tk.TclError:
        # A janela ainda não está visível ("grab failed: window not viewable").
        if attempts > 0:
            window.after(80, lambda: _make_modal(window, attempts - 1))


# ---------------------------------------------------------------------------
# Janela principal
# ---------------------------------------------------------------------------

class Dashboard(ctk.CTk):
    UI_POLL_MS = 100
    MAX_EVENTS_PER_TICK = 500
    STATUS_MAX_CHARS = 110

    def __init__(self, app_config: Config, manager: MonitorManager, notifier: Notifier, *,
                 icon_path: Path | None = None, on_quit: Callable[[], None] | None = None) -> None:
        super().__init__()
        self._config = app_config
        self._manager = manager
        self._notifier = notifier
        self._on_quit = on_quit
        self._ui_calls: queue.Queue[Callable[[], None]] = queue.Queue()
        self._snapshots: dict[str, HostSnapshot] = {}
        self._connections: dict[str, ConnectionEvent] = {}
        self._offline_notified: set[str] = set()
        self._busy: dict[str, ServiceAction] = {}
        self._current_server = app_config.servers[0].name
        self._tray = None
        self._hidden_hint_shown = False
        self._quitting = False
        self._search_job: str | None = None

        self.title(APP_TITLE)
        self.geometry("1320x840")
        self.minsize(1040, 660)
        if icon_path is not None and sys.platform == "win32":
            try:
                self.iconbitmap(default=str(icon_path))
            except tk.TclError:
                log.debug("Não foi possível definir o ícone da janela", exc_info=True)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self._build_header()
        self._build_metrics()
        self._build_banner()
        self._build_toolbar()
        self._build_table()
        self._build_actions()
        self._build_statusbar()
        self._build_context_menu()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<F5>", lambda _e: self.refresh_current())
        self.bind("<Control-f>", lambda _e: self._focus_search())
        self.report_callback_exception = self._report_callback_exception
        self._render_current()
        self.after(self.UI_POLL_MS, self._pump)
        self.after(1000, self._tick)

    # -- construção ---------------------------------------------------------

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(14, 8))
        header.grid_columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(brand, text=APP_TITLE, anchor="w", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        self._overview_label = ctk.CTkLabel(brand, text="", anchor="w", text_color=GRAY)
        self._overview_label.pack(anchor="w")

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(controls, text="Servidor").pack(side="left", padx=(0, 6))
        self._server_menu = ctk.CTkOptionMenu(controls, values=self._manager.server_names, width=220,
                                              dynamic_resizing=False, command=self._on_server_selected)
        self._server_menu.set(self._current_server)
        self._server_menu.pack(side="left", padx=(0, 12))
        self._conn_badge = ctk.CTkLabel(controls, text="", width=250, anchor="w")
        self._conn_badge.pack(side="left", padx=(0, 12))

        ctk.CTkLabel(controls, text="Intervalo").pack(side="left", padx=(0, 6))
        interval = self._config.settings.poll_interval_seconds
        options = sorted({*INTERVAL_OPTIONS, int(interval) if float(interval).is_integer() else interval})
        self._interval_menu = ctk.CTkOptionMenu(controls, values=[self._fmt_interval(v) for v in options],
                                                width=84, command=self._on_interval_selected)
        self._interval_menu.set(self._fmt_interval(interval))
        self._interval_menu.pack(side="left", padx=(0, 12))
        self._refresh_btn = ctk.CTkButton(controls, text="Atualizar", width=100, command=self.refresh_current)
        self._refresh_btn.pack(side="left")

    def _build_metrics(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 8))
        for column in range(5):
            row.grid_columnconfigure(column, weight=1, uniform="metric")
        self._cpu_card = MetricCard(row, "CPU")
        self._mem_card = MetricCard(row, "Memória")
        self._disk_card = MetricCard(row, "Disco")
        self._uptime_card = MetricCard(row, "Uptime", with_bar=False)
        self._services_card = ServicesCard(row)
        for column, card in enumerate((self._cpu_card, self._mem_card, self._disk_card,
                                       self._uptime_card, self._services_card)):
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 6, 0 if column == 4 else 6))

    def _build_banner(self) -> None:
        self._banner = ctk.CTkLabel(self, text="", anchor="w", justify="left", corner_radius=8,
                                    fg_color=BANNER_WARN, wraplength=1200)
        self._banner.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 8), ipady=6)
        self._banner.grid_remove()

    def _build_toolbar(self) -> None:
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 8))
        toolbar.grid_columnconfigure(3, weight=1)
        self._status_filter = ctk.CTkSegmentedButton(toolbar, values=list(STATUS_FILTERS),
                                                     command=lambda _v: self._render_table())
        self._status_filter.set("Todos")
        self._status_filter.grid(row=0, column=0, padx=(0, 10))
        self._kind_filter = ctk.CTkSegmentedButton(toolbar, values=list(KIND_FILTERS),
                                                   command=lambda _v: self._render_table())
        self._kind_filter.set("Tudo")
        self._kind_filter.grid(row=0, column=1, padx=(0, 10))
        self._search = ctk.CTkEntry(toolbar, placeholder_text="Buscar serviço…  (Ctrl+F)", width=300)
        self._search.grid(row=0, column=2, padx=(0, 10))
        self._search.bind("<KeyRelease>", self._on_search_changed)
        self._search.bind("<Escape>", lambda _e: self._clear_search())
        self._count_label = ctk.CTkLabel(toolbar, text="", text_color=GRAY, anchor="e")
        self._count_label.grid(row=0, column=3, sticky="e")

    def _build_table(self) -> None:
        self._table = ServiceTable(self, on_select=self._update_action_buttons, on_activate=self.open_logs,
                                   on_context=self._show_context_menu)
        self._table.grid(row=4, column=0, sticky="nsew", padx=18)

    def _build_actions(self) -> None:
        bar = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        bar.grid(row=5, column=0, sticky="ew", padx=18, pady=8)
        bar.grid_columnconfigure(0, weight=1)
        self._selection_label = ctk.CTkLabel(bar, text="", anchor="w")
        self._selection_label.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        self._btn_start = ctk.CTkButton(bar, text="Iniciar", width=104, fg_color=("#2da44e", "#238636"),
                                        hover_color=("#2c974b", "#2ea043"),
                                        command=lambda: self.confirm_action(ServiceAction.START))
        self._btn_stop = ctk.CTkButton(bar, text="Parar", width=104, fg_color=("#cf222e", "#b62324"),
                                       hover_color=("#a40e26", "#d9363e"),
                                       command=lambda: self.confirm_action(ServiceAction.STOP))
        self._btn_restart = ctk.CTkButton(bar, text="Reiniciar", width=104,
                                          command=lambda: self.confirm_action(ServiceAction.RESTART))
        self._btn_logs = ctk.CTkButton(bar, text="Ver Logs", width=104, fg_color=("gray70", "gray30"),
                                       hover_color=("gray60", "gray35"), text_color=("gray10", "gray95"),
                                       command=self.open_logs)
        for column, button in enumerate((self._btn_start, self._btn_stop, self._btn_restart, self._btn_logs), 1):
            button.grid(row=0, column=column, padx=(0, 14 if column == 4 else 8), pady=10)

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=6, column=0, sticky="ew", padx=18, pady=(0, 10))
        bar.grid_columnconfigure(0, weight=1)
        self._status_msg = ctk.CTkLabel(bar, text="Pronto.", anchor="w")
        self._status_msg.grid(row=0, column=0, sticky="ew")
        self._status_info = ctk.CTkLabel(bar, text="", anchor="e", text_color=GRAY)
        self._status_info.grid(row=0, column=1, sticky="e", padx=(12, 12))
        self._alerts_switch = ctk.CTkSwitch(bar, text="Alertas", command=self._on_alerts_switch)
        if self._config.settings.notifications.enabled:
            self._alerts_switch.select()
        else:
            self._alerts_switch.configure(state="disabled")
        self._alerts_switch.grid(row=0, column=2, sticky="e")

    def _build_context_menu(self) -> None:
        dark = ctk.get_appearance_mode() == "Dark"
        self._menu = tk.Menu(self, tearoff=0, bg="#262c36" if dark else "#ffffff",
                             fg="#e6edf3" if dark else "#1f2328", activebackground="#1f6aa5",
                             activeforeground="#ffffff", bd=0)
        self._menu.add_command(label="Iniciar", command=lambda: self.confirm_action(ServiceAction.START))
        self._menu.add_command(label="Parar", command=lambda: self.confirm_action(ServiceAction.STOP))
        self._menu.add_command(label="Reiniciar", command=lambda: self.confirm_action(ServiceAction.RESTART))
        self._menu.add_separator()
        self._menu.add_command(label="Ver Logs", command=self.open_logs)
        self._menu.add_command(label="Copiar nome", command=self._copy_selected_name)

    # -- API pública (tray / main) -------------------------------------------

    def call_in_ui(self, fn: Callable[[], None]) -> None:
        """Thread-safe: agenda ``fn`` para a thread da UI."""
        self._ui_calls.put(fn)

    def attach_tray(self, tray) -> None:
        self._tray = tray
        tray.set_muted(self._notifier.muted)
        self._update_tray()

    @property
    def tray_available(self) -> bool:
        return self._tray is not None and self._tray.available

    @property
    def can_hide_to_tray(self) -> bool:
        # Só no Windows a área de notificação é garantida; em outros sistemas o
        # ícone pode não aparecer (sem system tray) e a janela ficaria inacessível.
        return self.tray_available and sys.platform == "win32"

    def show_window(self) -> None:
        self.deiconify()
        self.lift()
        self.focus_force()
        self.attributes("-topmost", True)
        self.after(250, lambda: self.attributes("-topmost", False))

    def hide_to_tray(self) -> None:
        self.withdraw()
        if not self._hidden_hint_shown:
            self._hidden_hint_shown = True
            self._notifier.notify(APP_TITLE, "Continua monitorando em segundo plano. "
                                             "Use o ícone na bandeja para reabrir.", force=True)

    def refresh_current(self) -> None:
        self._manager.refresh(self._current_server)
        self._set_status(f"Atualizando {self._current_server}…")

    def refresh_all(self) -> None:
        self._manager.refresh()
        self._set_status("Atualizando todos os servidores…")

    def set_muted(self, muted: bool) -> None:
        self._notifier.muted = muted
        if self._config.settings.notifications.enabled:
            if muted:
                self._alerts_switch.deselect()
            else:
                self._alerts_switch.select()
        if self._tray is not None:
            self._tray.set_muted(muted)
        self._set_status("Alertas silenciados." if muted else "Alertas reativados.")

    def quit_app(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        log.info("Encerrando aplicação")
        if self._on_quit is not None:
            try:
                self._on_quit()
            except Exception:  # noqa: BLE001
                log.exception("Erro no encerramento")
        self.destroy()

    # -- ações de serviço -----------------------------------------------------

    def confirm_action(self, action: ServiceAction) -> None:
        service = self._table.selected_service()
        if service is None:
            return
        server = self._current_server
        if not self._manager.is_connected(server):
            self._set_status(f"{server} está desconectado; ação indisponível.", error=True)
            return
        noun = "o contêiner" if service.kind is ServiceKind.DOCKER else "o serviço"
        message = f"Deseja {action.label.lower()} {noun} \"{service.name}\" em {server}?"
        server_cfg = self._config.server(server)
        if service.critical and tuple(server_cfg.critical_services) != ("*",):
            message += "\n\nAtenção: este serviço está marcado como CRÍTICO."
        if action is ServiceAction.STOP:
            message += "\n\nO serviço ficará indisponível até ser iniciado novamente."
        dialog = ConfirmDialog(self, title=f"{action.label} {service.name}", message=message,
                               confirm_text=action.label, danger=action is ServiceAction.STOP)
        if not dialog.show():
            return
        self._busy[self._busy_key(server, service)] = action
        self._set_status(f"{action.progress_label} {service.name} em {server}…")
        self._update_action_buttons()
        self._manager.run_action(server, service, action)

    def open_logs(self) -> None:
        service = self._table.selected_service()
        if service is None:
            return
        server = self._current_server
        server_cfg = self._config.server(server)
        is_root = server_cfg.username == "root"

        def preview(lines: int) -> str:
            if service.kind is ServiceKind.DOCKER:
                return build_docker_logs_command(service.name, lines, server_cfg.docker_sudo and not is_root)
            return build_journal_command(service.name, lines, server_cfg.logs_sudo and not is_root)

        LogViewer(self, server=server, service=service, lines=self._config.settings.log_lines,
                  fetch=lambda lines: self._manager.fetch_logs(server, service, lines), command_preview=preview)

    def _busy_key(self, server: str, service: ServiceInfo) -> str:
        return f"{server}|{service.key}"

    # -- loop de eventos ------------------------------------------------------

    def _pump(self) -> None:
        try:
            while True:
                try:
                    fn = self._ui_calls.get_nowait()
                except queue.Empty:
                    break
                fn()
                if self._quitting:
                    return

            dirty: set[str] = set()
            alerts: list[ServiceAlertEvent] = []
            for _ in range(self.MAX_EVENTS_PER_TICK):
                try:
                    event = self._manager.events.get_nowait()
                except queue.Empty:
                    break
                self._handle_event(event, dirty, alerts)
            if alerts:
                self._dispatch_alerts(alerts)
            if dirty:
                self._render_overview()
                self._update_tray()
                if self._current_server in dirty:
                    self._render_current()
        except Exception:  # noqa: BLE001 - a bomba de eventos não pode parar
            log.exception("Erro processando eventos da UI")
        finally:
            if not self._quitting:
                self.after(self.UI_POLL_MS, self._pump)

    def _handle_event(self, event: MonitorEvent, dirty: set[str], alerts: list[ServiceAlertEvent]) -> None:
        server = event.server
        if isinstance(event, SnapshotEvent):
            self._snapshots[server] = event.snapshot
            dirty.add(server)
        elif isinstance(event, ConnectionEvent):
            previous = self._connections.get(server)
            self._connections[server] = event
            self._notify_connection_change(server, previous, event)
            dirty.add(server)
        elif isinstance(event, ServiceAlertEvent):
            alerts.append(event)
        elif isinstance(event, ActionResultEvent):
            self._busy.pop(self._busy_key(server, event.service), None)
            self._on_action_result(event)
            dirty.add(server)

    def _on_action_result(self, event: ActionResultEvent) -> None:
        result = event.result
        where = f"[{event.server}] "
        if result.outcome is ActionOutcome.ERROR:
            self._set_status(where + result.message, error=True)
            if self.winfo_viewable():
                # Agendado: o diálogo é modal e não pode bloquear a bomba de eventos.
                self.after(0, lambda: ConfirmDialog(
                    self, title=f"Falha: {event.action.label} {event.service.name}",
                    message=result.message, confirm_text="OK", cancel_text=None).show())
            else:
                self._notifier.notify(f"Falha ao {event.action.label.lower()} {event.service.name}",
                                      result.message)
        else:
            self._set_status(where + result.message, warning=result.outcome is ActionOutcome.PENDING)

    def _notify_connection_change(self, server: str, previous: ConnectionEvent | None,
                                  event: ConnectionEvent) -> None:
        settings = self._config.settings.notifications
        if event.state is ConnectionState.RECONNECTING:
            if server not in self._offline_notified:
                self._offline_notified.add(server)
                if settings.notify_on_disconnect:
                    title = ("Conexão perdida" if previous and previous.state is ConnectionState.CONNECTED
                             else "Servidor inacessível")
                    self._notifier.notify(f"{title}: {server}", event.message or "Sem resposta via SSH.",
                                          key=f"{server}:connection")
        elif event.state is ConnectionState.CONNECTED and server in self._offline_notified:
            self._offline_notified.discard(server)
            if settings.notify_on_disconnect and settings.notify_on_recovery:
                self._notifier.notify(f"Conexão restabelecida: {server}", event.message,
                                      key=f"{server}:connection-restored")

    def _dispatch_alerts(self, alerts: list[ServiceAlertEvent]) -> None:
        groups: dict[tuple[str, AlertKind], list[ServiceAlertEvent]] = defaultdict(list)
        for alert in alerts:
            groups[(alert.server, alert.alert)].append(alert)
        verbs = {AlertKind.FAILED: "falhou", AlertKind.STOPPED: "parou", AlertKind.RECOVERED: "recuperado"}
        for (server, kind), items in groups.items():
            names = [a.service.name for a in items]
            log.warning("[%s] alerta %s: %s", server, kind.value, ", ".join(names))
            if len(items) > 3:
                plural = {AlertKind.FAILED: "falharam", AlertKind.STOPPED: "pararam",
                          AlertKind.RECOVERED: "se recuperaram"}[kind]
                shown = ", ".join(names[:5]) + ("…" if len(names) > 5 else "")
                self._notifier.notify(f"{len(items)} serviços {plural} em {server}", shown,
                                      key=f"{server}:{kind.value}:batch")
            else:
                for alert in items:
                    service = alert.service
                    title = f"{service.name} {verbs[kind]}"
                    body = f"{server} · {service.kind.label} · {service.state_text}"
                    self._notifier.notify(title, body, key=f"{server}:{service.key}:{kind.value}")
            if kind is not AlertKind.RECOVERED:
                self._set_status(f"[{server}] {', '.join(names)} {verbs[kind] if len(names) == 1 else 'com problema'}",
                                 error=kind is AlertKind.FAILED)

    def _tick(self) -> None:
        """Atualizações por segundo: contagem regressiva de reconexão."""
        try:
            self._render_connection()
        finally:
            if not self._quitting:
                self.after(1000, self._tick)

    # -- renderização ----------------------------------------------------------

    def _render_current(self) -> None:
        snapshot = self._snapshots.get(self._current_server)
        self._render_connection()
        self._render_metrics(snapshot)
        self._render_banner(snapshot)
        self._render_table()
        self._update_action_buttons()
        self._render_status_info(snapshot)

    def _render_connection(self) -> None:
        event = self._connections.get(self._current_server)
        if event is None:
            self._conn_badge.configure(text="● Aguardando…", text_color=GRAY)
            return
        text = f"● {event.state.label}"
        if event.state is ConnectionState.RECONNECTING and event.retry_in is not None:
            remaining = event.timestamp + event.retry_in - time.time()
            text += f" · nova tentativa em {int(remaining) + 1} s" if remaining > 0.5 else " · reconectando…"
        self._conn_badge.configure(text=text, text_color=CONNECTION_COLORS[event.state])

    def _render_metrics(self, snapshot: HostSnapshot | None) -> None:
        metrics = snapshot.metrics if snapshot else None
        self._services_card.set_counts(snapshot)
        if metrics is None:
            for card in (self._cpu_card, self._mem_card, self._disk_card, self._uptime_card):
                card.set_values("—", "Sem dados")
            return

        cpu = metrics.cpu_percent
        load = metrics.load_avg
        load_text = f"Load {' · '.join(fmt_num(v, 2) for v in load)}" if load else "Load —"
        if metrics.cpu_count:
            load_text += f"  ({metrics.cpu_count} vCPU)"
        self._cpu_card.set_values(f"{cpu:.0f}%" if cpu is not None else "…", load_text,
                                  (cpu or 0) / 100, usage_color(cpu))

        mem_pct = metrics.mem_percent
        mem_detail = f"{fmt_mb(metrics.mem_used_mb)} de {fmt_mb(metrics.mem_total_mb)}"
        if metrics.swap_total_mb:
            mem_detail += f" · swap {fmt_mb(metrics.swap_used_mb)}"
        self._mem_card.set_values(f"{mem_pct:.0f}%" if mem_pct is not None else "—", mem_detail,
                                  (mem_pct or 0) / 100, usage_color(mem_pct))

        root, fullest = metrics.root_disk, metrics.fullest_disk
        if root is None:
            self._disk_card.set_values("—", "Sem dados de disco")
        else:
            detail = f"{root.mount} · {fmt_kb(root.avail_kb)} livres de {fmt_kb(root.size_kb)}"
            note, note_color = "", None
            if fullest is not None and fullest.mount != root.mount and fullest.use_percent > root.use_percent:
                note = f"Mais cheio: {fullest.mount} ({fullest.use_percent:.0f}%)"
                note_color = usage_color(fullest.use_percent) if fullest.use_percent >= 75 else GRAY
            self._disk_card.set_values(f"{root.use_percent:.0f}%", detail, root.use_percent / 100,
                                       usage_color(root.use_percent), note=note, note_color=note_color)

        self._uptime_card.set_values(fmt_duration(metrics.uptime_seconds),
                                     f"Coleta em {fmt_num(snapshot.duration, 2)} s")

    def _render_banner(self, snapshot: HostSnapshot | None) -> None:
        event = self._connections.get(self._current_server)
        server_cfg = self._config.server(self._current_server)
        text, color = "", BANNER_WARN
        if event is not None and event.state is ConnectionState.RECONNECTING:
            stale = " Exibindo os últimos dados coletados." if snapshot else ""
            text, color = f"Sem conexão com {server_cfg.address}: {event.message}{stale}", BANNER_ERROR
        elif snapshot is None:
            text, color = f"Conectando a {server_cfg.address}…", BANNER_INFO
        elif snapshot.warnings:
            text = "  |  ".join(snapshot.warnings)
        if text:
            self._banner.configure(text=text, fg_color=color)
            self._banner.grid()
        else:
            self._banner.grid_remove()

    def _render_table(self) -> None:
        snapshot = self._snapshots.get(self._current_server)
        services = list(snapshot.services) if snapshot else []
        statuses = STATUS_FILTERS[self._status_filter.get()]
        kind = KIND_FILTERS[self._kind_filter.get()]
        terms = self._search.get().casefold().split()
        filtered = [
            s for s in services
            if (statuses is None or s.status in statuses)
            and (kind is None or s.kind is kind)
            and all(t in f"{s.name} {s.description} {s.state_text}".casefold() for t in terms)
        ]
        event = self._connections.get(self._current_server)
        if snapshot is None and event is not None and event.state is ConnectionState.RECONNECTING:
            empty = "Servidor inacessível — nenhum dado coletado ainda."
        elif snapshot is None:
            empty = "Aguardando a primeira coleta…"
        elif not services:
            empty = "Nenhum serviço encontrado neste servidor."
        else:
            empty = "Nenhum serviço corresponde aos filtros."
        self._table.set_services(filtered, empty)
        self._count_label.configure(text=f"Exibindo {len(filtered)} de {len(services)}")

    def _render_status_info(self, snapshot: HostSnapshot | None) -> None:
        interval = self._manager.monitors[self._current_server].interval
        if snapshot is None:
            self._status_info.configure(text=f"Intervalo {self._fmt_interval(interval)}")
            return
        stamp = time.strftime("%H:%M:%S", time.localtime(snapshot.collected_at))
        self._status_info.configure(
            text=f"Atualizado às {stamp} · coleta {fmt_num(snapshot.duration, 2)} s · "
                 f"intervalo {self._fmt_interval(interval)}")

    def _render_overview(self) -> None:
        names = self._manager.server_names
        online = sum(1 for n in names if self._connections.get(n) and
                     self._connections[n].state is ConnectionState.CONNECTED)
        failing = sum(1 for n in names if self._server_health(n) is HealthLevel.CRITICAL)
        text = f"{len(names)} servidor{'es' if len(names) != 1 else ''} · {online} online"
        if failing:
            text += f" · {failing} com problemas"
        self._overview_label.configure(text=text, text_color=RED if failing else GRAY)
        values = [self._menu_label(n) for n in names]
        self._server_menu.configure(values=values)
        self._server_menu.set(self._menu_label(self._current_server))

    def _menu_label(self, server: str) -> str:
        health = self._server_health(server)
        return f"{server}  ●" if health is HealthLevel.CRITICAL else server

    def _update_action_buttons(self) -> None:
        service = self._table.selected_service()
        server = self._current_server
        buttons = (self._btn_start, self._btn_stop, self._btn_restart, self._btn_logs)
        if service is None:
            self._selection_label.configure(text="Selecione um serviço na tabela (duplo clique abre os logs).",
                                            text_color=GRAY)
            for button in buttons:
                button.configure(state="disabled")
            return
        connected = self._manager.is_connected(server)
        busy = self._busy.get(self._busy_key(server, service))
        label = f"{service.name}  ·  {service.status.label}  ·  {service.state_text}"
        if busy is not None:
            label += f"  —  {busy.progress_label}…"
        self._selection_label.configure(text=label, text_color=STATUS_COLORS[service.status])
        can_act = connected and busy is None

        def state(enabled: bool) -> str:
            return "normal" if enabled else "disabled"

        self._btn_start.configure(state=state(can_act and service.status is not ServiceStatus.ACTIVE))
        self._btn_stop.configure(state=state(can_act and service.status is not ServiceStatus.STOPPED))
        self._btn_restart.configure(state=state(can_act))
        self._btn_logs.configure(state=state(connected))

    def _update_tray(self) -> None:
        if self._tray is None:
            return
        names = self._manager.server_names
        levels = {n: self._server_health(n) for n in names}
        overall = max(levels.values(), default=HealthLevel.UNKNOWN)
        problems = []
        for name, level in levels.items():
            if level < HealthLevel.WARNING:
                continue
            event = self._connections.get(name)
            if event is not None and event.state is ConnectionState.RECONNECTING:
                problems.append(f"{name}: offline")
            else:
                snapshot = self._snapshots.get(name)
                failed = snapshot.counts()[ServiceStatus.FAILED] if snapshot else 0
                problems.append(f"{name}: {failed} falha{'s' if failed != 1 else ''}" if failed else f"{name}: aviso")
        tooltip = APP_TITLE + ("\n" + "\n".join(problems) if problems else " — tudo OK")
        self._tray.set_health(overall, tooltip)

    def _server_health(self, server: str) -> HealthLevel:
        event = self._connections.get(server)
        snapshot = self._snapshots.get(server)
        if event is not None and event.state is ConnectionState.RECONNECTING:
            return HealthLevel.CRITICAL
        if snapshot is None:
            return HealthLevel.UNKNOWN
        if snapshot.failed_critical():
            return HealthLevel.CRITICAL
        if snapshot.counts()[ServiceStatus.FAILED] or snapshot.warnings:
            return HealthLevel.WARNING
        return HealthLevel.OK

    # -- handlers ---------------------------------------------------------------

    def _on_server_selected(self, label: str) -> None:
        server = label.replace("●", "").strip()
        if server == self._current_server:
            return
        self._current_server = server
        self._table.clear()
        self._interval_menu.set(self._fmt_interval(self._manager.monitors[server].interval))
        self._render_overview()
        self._render_current()

    def _on_interval_selected(self, label: str) -> None:
        seconds = float(label.split()[0].replace(",", "."))
        self._manager.set_poll_interval(seconds)
        self._set_status(f"Intervalo de coleta alterado para {label}.")
        self._render_status_info(self._snapshots.get(self._current_server))

    def _on_search_changed(self, _event=None) -> None:
        if self._search_job is not None:
            self.after_cancel(self._search_job)
        self._search_job = self.after(120, self._apply_search)

    def _apply_search(self) -> None:
        self._search_job = None
        self._render_table()
        self._update_action_buttons()

    def _clear_search(self) -> None:
        self._search.delete(0, "end")
        self._render_table()
        self.focus_set()

    def _focus_search(self) -> None:
        self._search.focus_set()
        self._search.select_range(0, "end")

    def _on_alerts_switch(self) -> None:
        self.set_muted(not bool(self._alerts_switch.get()))

    def _show_context_menu(self, event: tk.Event) -> None:
        if not self._table.select_row_at(event.y):
            return
        self._update_action_buttons()
        service = self._table.selected_service()
        connected = self._manager.is_connected(self._current_server)
        busy = service is not None and self._busy_key(self._current_server, service) in self._busy
        for label in ("Iniciar", "Parar", "Reiniciar"):
            self._menu.entryconfigure(label, state="normal" if connected and not busy else "disabled")
        self._menu.entryconfigure("Ver Logs", state="normal" if connected else "disabled")
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    def _copy_selected_name(self) -> None:
        service = self._table.selected_service()
        if service is not None:
            self.clipboard_clear()
            self.clipboard_append(service.name)
            self._set_status(f"'{service.name}' copiado.")

    def _on_close(self) -> None:
        if self.can_hide_to_tray and self._config.settings.minimize_to_tray:
            self.hide_to_tray()
        else:
            self.quit_app()

    def _set_status(self, text: str, *, error: bool = False, warning: bool = False) -> None:
        color = RED if error else YELLOW if warning else ("gray10", "gray90")
        text = " ".join(text.split())
        if len(text) > self.STATUS_MAX_CHARS:
            text = text[: self.STATUS_MAX_CHARS - 1] + "…"
        self._status_msg.configure(text=f"{time.strftime('%H:%M:%S')}  {text}", text_color=color)

    def _report_callback_exception(self, exc_type, exc, tb) -> None:
        log.error("Erro não tratado na UI", exc_info=(exc_type, exc, tb))
        self._set_status(f"Erro interno: {exc}", error=True)

    @staticmethod
    def _fmt_interval(seconds: float) -> str:
        return f"{int(seconds)} s" if float(seconds).is_integer() else f"{fmt_num(seconds)} s"
