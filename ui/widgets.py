"""Componentes reutilizáveis da interface: tabela, cartões, diálogos, visualizador
de texto e gráfico de linhas (Canvas puro, sem dependências extras)."""

from __future__ import annotations

import csv
import datetime as dt
import logging
import math
import sys
import time
import tkinter as tk
from collections.abc import Callable, Sequence
from concurrent.futures import Future
from dataclasses import dataclass, field
from tkinter import filedialog, ttk

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk

from core.models import ServiceStatus
from ui import theme
from ui.theme import BANNER_ERROR, BANNER_INFO, BANNER_WARN, CARD_BG, PANEL_BG, TEXT  # noqa: F401 - reexportados

log = logging.getLogger(__name__)

UI_FONT = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO_FONT = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

# Cores no formato (modo claro, modo escuro) aceito pelo CustomTkinter. As de
# status são semânticas (verde/amarelo/vermelho) e não mudam com o tema.
GREEN = ("#1a7f37", "#3fb950")
RED = ("#cf222e", "#ff6b6b")
YELLOW = ("#9a6700", "#f2cc60")
ORANGE = ("#bc4c00", "#f0883e")
PURPLE = ("#8250df", "#a371f7")
GRAY = theme.TEXT_SECONDARY
CYAN = theme.ACCENT_BRIGHT

STATUS_COLORS = {
    ServiceStatus.ACTIVE: GREEN,
    ServiceStatus.ACTIVATING: YELLOW,
    ServiceStatus.DEGRADED: ORANGE,
    ServiceStatus.STOPPED: GRAY,
    ServiceStatus.FAILED: RED,
    ServiceStatus.UNKNOWN: PURPLE,
}


def mode_index() -> int:
    return 1 if ctk.get_appearance_mode() == "Dark" else 0


def pick(color: tuple[str, str]) -> str:
    return color[mode_index()]


# ---------------------------------------------------------------------------
# Formatação (pt-BR)
# ---------------------------------------------------------------------------

def fmt_num(value: float, digits: int = 1) -> str:
    return f"{value:,.{digits}f}".replace(",", "_").replace(".", ",").replace("_", ".")


def fmt_pct(value: float | None, digits: int = 0) -> str:
    return "—" if value is None else f"{fmt_num(value, digits)}%"


def fmt_bytes(value: float | None, suffix: str = "") -> str:
    if value is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        # Troca de unidade em 1000 (base 1024): evita "1.014,5 MB".
        if abs(value) < 1000 or unit == "TB":
            digits = 0 if unit == "B" else 1
            return f"{fmt_num(value, digits)} {unit}{suffix}"
        value /= 1024
    return "—"


def fmt_rate(value: float | None) -> str:
    return fmt_bytes(value, "/s")


def fmt_mb(mb: float | None) -> str:
    return "—" if mb is None else fmt_bytes(mb * 1024 * 1024)


def fmt_kb(kb: float | None) -> str:
    return "—" if kb is None else fmt_bytes(kb * 1024)


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


def short_path(path: str, limit: int = 22) -> str:
    """Encurta pelo início: "/var/lib/libvirt/images" → "…/libvirt/images"."""
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


def fmt_ago(timestamp: float | None) -> str:
    if timestamp is None:
        return "nunca"
    elapsed = max(0, time.time() - timestamp)
    return "agora" if elapsed < 2 else f"há {fmt_duration(elapsed)}"


def usage_color(percent: float | None) -> tuple[str, str]:
    if percent is None:
        return GRAY
    if percent >= 90:
        return RED
    if percent >= 75:
        return YELLOW
    return CYAN


# ---------------------------------------------------------------------------
# Tabela genérica
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Column:
    id: str
    title: str
    width: int
    stretch: bool = False
    anchor: str = "w"


@dataclass(frozen=True)
class Row:
    key: str
    #: Textos exibidos nas colunas de dados (sem a coluna-árvore).
    values: tuple[str, ...]
    #: Chaves de ordenação, uma por coluna (incluindo a coluna-árvore, se houver).
    sort: tuple = ()
    status: ServiceStatus | None = None
    #: Texto da coluna-árvore (ao lado da bolinha de status).
    text: str = ""
    #: Tag de cor da linha: status, "muted", "warn" ou "error". Padrão: o status.
    tag: str | None = None


_TAG_COLORS = {
    "failed": RED, "activating": YELLOW, "degraded": ORANGE, "unknown": PURPLE,
    "muted": theme.TEXT_MUTED, "stopped": theme.TEXT_MUTED,
    "warn": YELLOW, "error": RED,
}
_DOT_CACHE: dict[tuple, ImageTk.PhotoImage] = {}
_STYLE_READY: set[int] = set()


def status_dot(widget: tk.Misc, status: ServiceStatus) -> ImageTk.PhotoImage:
    """Bolinha colorida (Treeview não colore células individuais)."""
    index = mode_index()
    size = max(10, round(12 * ctk.ScalingTracker.get_widget_scaling(widget)))
    key = (status, index, size, str(widget.winfo_toplevel()))
    if key not in _DOT_CACHE:
        big = Image.new("RGBA", (size * 4 + 8, size * 4), (0, 0, 0, 0))
        ImageDraw.Draw(big).ellipse((4, 4, size * 4 - 4, size * 4 - 4), fill=STATUS_COLORS[status][index])
        _DOT_CACHE[key] = ImageTk.PhotoImage(big.resize((size + 2, size), Image.Resampling.LANCZOS), master=widget)
    return _DOT_CACHE[key]


def setup_table_style(widget: tk.Misc) -> None:
    root = widget.winfo_toplevel()
    if id(root) in _STYLE_READY:
        return
    _STYLE_READY.add(id(root))
    index = mode_index()
    bg, fg = CARD_BG[index], TEXT[index]
    heading_bg, hover = PANEL_BG[index], theme.PANEL_HOVER[index]
    scaling = ctk.ScalingTracker.get_widget_scaling(widget)
    style = ttk.Style(root)
    if style.theme_use() != "clam":
        style.theme_use("clam")  # "clam" permite customizar cores no Windows
    style.configure("Data.Treeview", background=bg, fieldbackground=bg, foreground=fg,
                    rowheight=int(26 * scaling), borderwidth=0, relief="flat", font=(UI_FONT, 10))
    style.configure("Data.Treeview.Heading", background=heading_bg, foreground=fg, relief="flat", borderwidth=0,
                    font=(UI_FONT, 10, "bold"), padding=(8, 5))
    style.map("Data.Treeview", background=[("selected", theme.ACCENT[index])], foreground=[("selected", "#ffffff")])
    style.map("Data.Treeview.Heading", background=[("active", hover)])
    style.layout("Data.Treeview", [("Data.Treeview.treearea", {"sticky": "nswe"})])
    # Sem o indicador de expandir/recolher (as linhas não têm filhos).
    style.layout("Treeview.Item", [
        ("Treeitem.padding", {"sticky": "nswe", "children": [
            ("Treeitem.image", {"side": "left", "sticky": ""}),
            ("Treeitem.focus", {"side": "left", "sticky": "", "children": [
                ("Treeitem.text", {"side": "left", "sticky": ""}),
            ]}),
        ]}),
    ])


MenuItems = list[tuple[str, Callable[[], None] | None]]


class DataTable(ctk.CTkFrame):
    """Treeview com tema escuro, ordenação por coluna, atualização incremental
    (preserva seleção e rolagem), menu de contexto e exportação CSV."""

    def __init__(self, master, columns: Sequence[Column], *, tree_column: Column | None = None,
                 sort_column: str | None = None, sort_desc: bool = False,
                 on_select: Callable[[], None] | None = None, on_activate: Callable[[], None] | None = None,
                 menu_items: Callable[[], MenuItems] | None = None, export_name: str = "tabela",
                 height: int | None = None) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        setup_table_style(self)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._columns = ([tree_column] if tree_column else []) + list(columns)
        self._has_tree = tree_column is not None
        self._on_select = on_select
        self._on_activate = on_activate
        self._menu_items = menu_items
        self._export_name = export_name
        self.sort_column = sort_column or self._columns[0].id
        self.sort_desc = sort_desc
        self._rows: dict[str, Row] = {}
        self._order: list[str] = []
        self._iid_by_key: dict[str, str] = {}
        self._key_by_iid: dict[str, str] = {}
        self._next_iid = 0

        kwargs = {"height": height} if height else {}
        self.tree = ttk.Treeview(self, columns=[c.id for c in columns], selectmode="browse", style="Data.Treeview",
                                 show="tree headings" if self._has_tree else "headings", **kwargs)
        for column in self._columns:
            column_id = "#0" if column is tree_column else column.id
            self.tree.heading(column_id, text=column.title, anchor=column.anchor,
                              command=lambda c=column.id: self.sort_by(c))
            self.tree.column(column_id, width=column.width, minwidth=50, stretch=column.stretch,
                             anchor=column.anchor)
        # Altura mínima pequena: a barra estica com a tabela (o padrão, 200 px, forçaria tabelas baixas a crescer).
        scrollbar = ctk.CTkScrollbar(self, command=self.tree.yview, height=40)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(2, 6), pady=8)
        self._empty = ctk.CTkLabel(self, text="", text_color=GRAY, fg_color="transparent")
        index = mode_index()
        for tag, color in _TAG_COLORS.items():
            self.tree.tag_configure(tag, foreground=color[index])
        self._update_headings()

        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._on_select() if self._on_select else None)
        self.tree.bind("<Double-1>", self._double_click)
        self.tree.bind("<Return>", lambda _e: self._on_activate() if self._on_activate else None)
        self.tree.bind("<Button-3>", self._context_menu)
        if sys.platform == "darwin":
            self.tree.bind("<Button-2>", self._context_menu)

    # -- dados --------------------------------------------------------------

    def set_rows(self, rows: Sequence[Row], empty_message: str = "") -> None:
        index = self._column_index(self.sort_column)
        try:
            ordered = sorted(rows, key=lambda r: _sort_value(r, index), reverse=self.sort_desc)
        except TypeError:  # chaves heterogêneas: ordena pelo texto em vez de derrubar a tela
            log.debug("Ordenação por texto na coluna %s", self.sort_column, exc_info=True)
            ordered = sorted(rows, key=lambda r: str(_sort_value(r, index)), reverse=self.sort_desc)
        new_keys = [row.key for row in ordered]
        for key in set(self._rows) - set(new_keys):
            iid = self._iid_by_key.pop(key)
            self._key_by_iid.pop(iid, None)
            self._rows.pop(key)
            self.tree.delete(iid)
        for row in ordered:
            iid = self._iid_by_key.get(row.key)
            item: dict = {"values": row.values, "tags": (row.tag or (row.status.value if row.status else ""),)}
            if self._has_tree:
                item["text"] = f" {row.text}"
                item["image"] = status_dot(self, row.status) if row.status else ""
            if iid is None:
                iid = f"r{self._next_iid}"
                self._next_iid += 1
                self._iid_by_key[row.key] = iid
                self._key_by_iid[iid] = row.key
                self.tree.insert("", "end", iid=iid, **item)
            elif self._rows.get(row.key) != row:
                self.tree.item(iid, **item)
            self._rows[row.key] = row
        wanted = [self._iid_by_key[key] for key in new_keys]
        if list(self.tree.get_children()) != wanted:
            for position, iid in enumerate(wanted):
                self.tree.move(iid, "", position)
        self._order = new_keys
        if not ordered and empty_message:
            self._empty.configure(text=empty_message)
            self._empty.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self._empty.place_forget()

    def selected_key(self) -> str | None:
        selection = self.tree.selection()
        return self._key_by_iid.get(selection[0]) if selection else None

    def select_key(self, key: str) -> bool:
        iid = self._iid_by_key.get(key)
        if iid is None:
            return False
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        self.tree.see(iid)
        return True

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        self._order.clear()
        self._iid_by_key.clear()
        self._key_by_iid.clear()

    # -- ordenação -----------------------------------------------------------

    def sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_column, self.sort_desc = column, False
        self._update_headings()
        self.set_rows([self._rows[key] for key in self._order])

    def _column_index(self, column_id: str) -> int:
        for index, column in enumerate(self._columns):
            if column.id == column_id:
                return index
        return 0

    def _update_headings(self) -> None:
        for index, column in enumerate(self._columns):
            arrow = (" ▼" if self.sort_desc else " ▲") if column.id == self.sort_column else ""
            self.tree.heading("#0" if self._has_tree and index == 0 else column.id, text=column.title + arrow)

    # -- interação -----------------------------------------------------------

    def _double_click(self, event: tk.Event) -> None:
        if self.tree.identify_row(event.y) and self._on_activate:
            self._on_activate()

    def _context_menu(self, event: tk.Event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.tree.focus(iid)
        index = mode_index()
        menu = tk.Menu(self, tearoff=0, bg=PANEL_BG[index], fg=TEXT[index], activebackground=theme.ACCENT[index],
                       activeforeground="#ffffff", bd=0)
        items = self._menu_items() if (self._menu_items and iid) else []
        for label, command in items:
            if label == "-":
                menu.add_separator()
            else:
                menu.add_command(label=label, command=command or (lambda: None),
                                 state="normal" if command else "disabled")
        if items:
            menu.add_separator()
        menu.add_command(label="Copiar linha", command=self._copy_row, state="normal" if iid else "disabled")
        menu.add_command(label="Exportar tabela (CSV)…", command=self.export_csv)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _row_texts(self, key: str) -> list[str]:
        row = self._rows[key]
        return ([row.text] if self._has_tree else []) + [str(v) for v in row.values]

    def _copy_row(self) -> None:
        key = self.selected_key()
        if key:
            self.clipboard_clear()
            self.clipboard_append("\t".join(self._row_texts(key)))

    def export_csv(self) -> None:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            initialfile=f"{self._export_name}-{stamp}.csv",
                                            filetypes=[("CSV (Excel)", "*.csv"), ("Todos os arquivos", "*.*")])
        if not path:
            return
        try:
            # ";" + BOM: abre direto no Excel em português.
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle, delimiter=";")
                writer.writerow([c.title for c in self._columns])
                for key in self._order:
                    writer.writerow(self._row_texts(key))
        except OSError as exc:
            log.warning("Falha ao exportar CSV", exc_info=True)
            ConfirmDialog(self.winfo_toplevel(), title="Falha ao exportar", message=str(exc), confirm_text="OK",
                          cancel_text=None).show()


def _sort_value(row: Row, index: int) -> tuple:
    value = row.sort[index] if index < len(row.sort) else (row.values[index - 1] if index else row.text)
    # None sempre no fim, qualquer que seja a direção.
    if value is None:
        return (1, 0)
    if isinstance(value, str):
        return (0, value.casefold())
    return (0, value)


# ---------------------------------------------------------------------------
# Cartões e rótulos
# ---------------------------------------------------------------------------

class MetricCard(ctk.CTkFrame):
    def __init__(self, master, title: str, *, with_bar: bool = True) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text=title.upper(), text_color=GRAY, anchor="w",
                     font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 0))
        self._value_label = ctk.CTkLabel(self, text="—", anchor="w", font=ctk.CTkFont(size=24, weight="bold"))
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
            self._bar.configure(progress_color=color or CYAN)


class CountsCard(ctk.CTkFrame):
    """Cargas ativas vs. com falha."""

    def __init__(self, master, title: str = "Cargas") -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(self, text=title.upper(), text_color=GRAY, anchor="w",
                     font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, columnspan=2,
                                                                    sticky="ew", padx=14, pady=(10, 0))
        big = ctk.CTkFont(size=24, weight="bold")
        self._good = ctk.CTkLabel(self, text="—", text_color=GREEN, font=big, anchor="w")
        self._bad = ctk.CTkLabel(self, text="—", text_color=RED, font=big, anchor="w")
        self._good.grid(row=1, column=0, sticky="w", padx=(14, 4))
        self._bad.grid(row=1, column=1, sticky="w", padx=(4, 14))
        small = ctk.CTkFont(size=12)
        ctk.CTkLabel(self, text="ativas", text_color=GRAY, font=small, anchor="w").grid(
            row=2, column=0, sticky="w", padx=(14, 4))
        ctk.CTkLabel(self, text="com falha", text_color=GRAY, font=small, anchor="w").grid(
            row=2, column=1, sticky="w", padx=(4, 14))
        self._detail = ctk.CTkLabel(self, text="", text_color=GRAY, font=small, anchor="w")
        self._detail.grid(row=3, column=0, columnspan=2, sticky="ew", padx=14, pady=(2, 12))

    def set_counts(self, good: int | None, bad: int | None, detail: str = "") -> None:
        self._good.configure(text="—" if good is None else str(good))
        self._bad.configure(text="—" if bad is None else str(bad))
        self._detail.configure(text=detail)


class InfoGrid(ctk.CTkFrame):
    """Pares rótulo/valor em colunas (aba Sistema)."""

    def __init__(self, master, columns: int = 2, wraplength: int = 420) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self._columns = columns
        self._wraplength = wraplength
        self._labels: dict[str, ctk.CTkLabel] = {}
        for column in range(columns):
            self.grid_columnconfigure(column * 2 + 1, weight=1)

    def set_items(self, items: Sequence[tuple[str, str, tuple[str, str] | None]]) -> None:
        for index, (label, value, color) in enumerate(items):
            row, column = divmod(index, self._columns)
            if label not in self._labels:
                ctk.CTkLabel(self, text=label, text_color=GRAY, anchor="w").grid(
                    row=row, column=column * 2, sticky="w", padx=(14, 10), pady=3)
                value_label = ctk.CTkLabel(self, text="", anchor="w", justify="left", wraplength=self._wraplength)
                value_label.grid(row=row, column=column * 2 + 1, sticky="w", padx=(0, 14), pady=3)
                self._labels[label] = value_label
            self._labels[label].configure(text=value, text_color=color or TEXT)


# ---------------------------------------------------------------------------
# Diálogos
# ---------------------------------------------------------------------------

def center_on(window: tk.Misc, master: tk.Misc) -> None:
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


def make_modal(window: tk.Toplevel, attempts: int = 10) -> None:
    try:
        if not window.winfo_exists():
            return
        window.lift()
        window.focus_force()
        window.grab_set()
    except tk.TclError:
        # A janela ainda não está visível ("grab failed: window not viewable").
        if attempts > 0:
            window.after(80, lambda: make_modal(window, attempts - 1))


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
        ctk.CTkLabel(body, text=message, anchor="w", justify="left", wraplength=460).pack(fill="x", pady=(8, 18))
        buttons = ctk.CTkFrame(body, fg_color="transparent")
        buttons.pack(fill="x")
        if cancel_text:
            ctk.CTkButton(buttons, text=cancel_text, width=110, fg_color="transparent", border_width=1,
                          text_color=TEXT, command=self._cancel).pack(side="right", padx=(8, 0))
        ctk.CTkButton(buttons, text=confirm_text, width=120, command=self._confirm,
                      fg_color=RED if danger else theme.ACCENT,
                      hover_color=("#a40e26", "#d9363e") if danger else theme.ACCENT_HOVER).pack(side="right")

        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        center_on(self, master)
        self.after(250, lambda: theme.style_window(self))

    def show(self) -> bool:
        self.after(60, lambda: make_modal(self))
        self.wait_window(self)
        return self._result

    def _confirm(self) -> None:
        self._result = True
        self.destroy()

    def _cancel(self) -> None:
        self._result = False
        self.destroy()


class TextViewer(ctk.CTkToplevel):
    """Modal de texto: logs (com seletor de linhas e atualização) ou conteúdo fixo."""

    LINE_OPTIONS = ("50", "100", "200", "500", "1000")
    _PERMISSION_HINTS = ("not seeing messages from other users", "insufficient permissions",
                         "no journal files were opened")

    def __init__(self, master, *, title: str, subtitle: str = "", lines: int | None = None,
                 fetch: Callable[[int], Future[str]] | None = None,
                 command_preview: Callable[[int], str] | None = None, text: str | None = None,
                 line_selector: bool = True) -> None:
        super().__init__(master)
        self.title(title)
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
        ctk.CTkLabel(header, text=subtitle or title, anchor="w",
                     font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, sticky="w")
        self._command_label = ctk.CTkLabel(header, text="", anchor="w", text_color=GRAY,
                                           font=ctk.CTkFont(family=MONO_FONT, size=12))
        self._command_label.grid(row=1, column=0, sticky="w")

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, rowspan=2, sticky="e")
        self._lines = None
        self._reload_btn = None
        if fetch is not None:
            if line_selector:
                initial = str(lines or 50)
                options = list(self.LINE_OPTIONS) if initial in self.LINE_OPTIONS else [initial, *self.LINE_OPTIONS]
                ctk.CTkLabel(controls, text="Linhas").pack(side="left", padx=(0, 6))
                self._lines = ctk.CTkOptionMenu(controls, values=options, width=80,
                                                command=lambda _v: self.reload())
                self._lines.set(initial)
                self._lines.pack(side="left", padx=(0, 8))
            self._reload_btn = ctk.CTkButton(controls, text="Atualizar", width=96, command=self.reload)
            self._reload_btn.pack(side="left", padx=(0, 8))
            self.bind("<F5>", lambda _e: self.reload())
        ctk.CTkButton(controls, text="Copiar", width=80, fg_color=theme.NEUTRAL, hover_color=theme.NEUTRAL_HOVER,
                      text_color=TEXT,
                      command=self._copy).pack(side="left", padx=(0, 8))
        ctk.CTkButton(controls, text="Fechar", width=80, fg_color="transparent", border_width=1, text_color=TEXT,
                      command=self.destroy).pack(side="left")

        self._textbox = ctk.CTkTextbox(self, wrap="none", font=ctk.CTkFont(family=MONO_FONT, size=12),
                                       corner_radius=10)
        self._textbox.grid(row=1, column=0, sticky="nsew", padx=16)
        self._status = ctk.CTkLabel(self, text="", anchor="w", text_color=GRAY)
        self._status.grid(row=2, column=0, sticky="ew", padx=18, pady=(6, 12))

        self.bind("<Escape>", lambda _e: self.destroy())
        center_on(self, master)
        self.after(250, lambda: theme.style_window(self))
        self.after(60, lambda: make_modal(self))
        if fetch is not None:
            self.reload()
        else:
            self._set_text(text or "")

    def reload(self) -> None:
        if self._fetch is None or (self._future is not None and not self._future.done()):
            return
        lines = int(self._lines.get()) if self._lines else 50
        if self._preview is not None:
            self._command_label.configure(text=f"$ {self._preview(lines)}")
        self._set_text("Carregando…")
        self._status.configure(text="Consultando o servidor…", text_color=GRAY)
        if self._reload_btn:
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
        if self._reload_btn:
            self._reload_btn.configure(state="normal")
        try:
            text = future.result()
        except Exception as exc:  # noqa: BLE001
            self._set_text(f"Erro ao obter dados: {exc}")
            self._status.configure(text="Falha na consulta", text_color=RED)
            return
        self._set_text(text)
        if self._lines is not None:  # logs: mostra o fim; JSON do inspect: o começo
            self._textbox.see("end")
        if any(hint in text.lower() for hint in self._PERMISSION_HINTS):
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
        self._status.configure(text="Copiado para a área de transferência.", text_color=GREEN)


# ---------------------------------------------------------------------------
# Gráfico de linhas
# ---------------------------------------------------------------------------

#: Paleta categórica do tema ciano, validada com o validador de paletas (todos os
#: pares, contra as superfícies dos cartões): claro #f9fcfd — pior ΔE daltonismo
#: 17,1, visão normal 23,2; escuro #102229 — 8,2 e 15,3; contraste >= 3:1 em ambos.
#: Ciano (slot 1) é a cor da marca; laranja e violeta vêm da paleta de referência.
SERIES_COLORS = (("#0891b2", "#0891b2"), ("#eb6834", "#d95926"), ("#4a3aa7", "#9085e9"))
_CHART_INK = {
    # superfície, grade, linha de base, texto secundário, texto discreto, texto principal, fundo do tooltip
    0: (CARD_BG[0], "#dfeaee", "#b8cdd3", theme.TEXT_SECONDARY[0], theme.TEXT_MUTED[0], TEXT[0], "#ffffff"),
    1: (CARD_BG[1], "#1b343d", "#2c4c57", "#a9c1c8", theme.TEXT_MUTED[1], TEXT[1], PANEL_BG[1]),
}


@dataclass
class Series:
    name: str
    values: Sequence[float | None]
    #: Posição fixa na paleta categórica (a cor segue a série, nunca a ordem).
    slot: int = 0


@dataclass
class _Plot:
    x0: float = 0
    x1: float = 0
    y0: float = 0
    y1: float = 0
    t0: float = 0
    t1: float = 1
    y_max: float = 1
    timestamps: Sequence[float] = field(default_factory=tuple)


class LineChart(ctk.CTkFrame):
    """Série temporal com um único eixo Y, grade discreta, legenda com chave de
    linha, marcador no último ponto e crosshair com tooltip de todas as séries."""

    MARGIN_LEFT, MARGIN_RIGHT, MARGIN_TOP, MARGIN_BOTTOM = 62, 16, 34, 26

    def __init__(self, master, title: str, formatter: Callable[[float], str], *,
                 fixed_max: float | None = None, height: int = 200, binary: bool = False) -> None:
        super().__init__(master, corner_radius=12, fg_color=CARD_BG)
        self._title = title
        #: Valores em bytes: marcas do eixo em múltiplos de 1024 (2,5 MB/s, 5 MB/s...).
        self._binary = binary
        self._fmt = formatter
        self._fixed_max = fixed_max
        self._series: list[Series] = []
        self._timestamps: Sequence[float] = ()
        self._window = 3600.0
        self._bucket = 60.0
        self._plot = _Plot()
        self.canvas = tk.Canvas(self, height=height, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True, padx=8, pady=8)
        self.canvas.bind("<Configure>", lambda _e: self.redraw())
        self.canvas.bind("<Motion>", self._hover)
        self.canvas.bind("<Leave>", lambda _e: self.canvas.delete("hover"))

    def set_data(self, timestamps: Sequence[float], series: list[Series], window: float, bucket: float) -> None:
        self._timestamps, self._series, self._window, self._bucket = timestamps, series, window, bucket
        self.redraw()

    def redraw(self) -> None:
        c = self.canvas
        c.delete("all")
        surface, grid, baseline, secondary, muted, primary, _tip = _CHART_INK[mode_index()]
        c.configure(bg=surface)
        width, height = c.winfo_width(), c.winfo_height()
        if width < 50 or height < 50:
            return
        font = (UI_FONT, 9)
        c.create_text(4, 10, text=self._title, anchor="w", fill=primary, font=(UI_FONT, 10, "bold"))
        if len(self._series) >= 2:
            x = width - self.MARGIN_RIGHT
            for series in reversed(self._series):
                label = c.create_text(x, 10, text=series.name, anchor="e", fill=secondary, font=font)
                bbox = c.bbox(label)
                c.create_line(bbox[0] - 22, 10, bbox[0] - 6, 10, fill=SERIES_COLORS[series.slot][mode_index()],
                              width=2, capstyle="round")
                x = bbox[0] - 34

        x0, x1 = self.MARGIN_LEFT, width - self.MARGIN_RIGHT
        y0, y1 = self.MARGIN_TOP, height - self.MARGIN_BOTTOM
        values = [v for s in self._series for v in s.values if v is not None]
        t1 = time.time()
        t0 = t1 - self._window
        if self._fixed_max:
            y_max, step = self._fixed_max, self._fixed_max / 4
        else:
            y_max, step = _nice_scale(max(values) if values else 1.0, 1024 if self._binary else 10)
        self._plot = _Plot(x0, x1, y0, y1, t0, t1, y_max, self._timestamps)

        for tick in _ticks(y_max, step):
            y = y1 - (y1 - y0) * tick / y_max
            c.create_line(x0, y, x1, y, fill=baseline if tick == 0 else grid, width=1)
            c.create_text(x0 - 8, y, text=self._fmt(tick), anchor="e", fill=muted, font=font)
        for t in _time_ticks(t0, t1):
            x = x0 + (x1 - x0) * (t - t0) / (t1 - t0)
            label = time.strftime("%d/%m %H:%M" if self._window > 86400 else "%H:%M", time.localtime(t))
            c.create_text(x, y1 + 12, text=label, anchor="center", fill=muted, font=font)

        if not values:
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2, text="Sem dados no período", fill=muted, font=(UI_FONT, 10))
            return
        gap = _gap_threshold(self._timestamps, self._bucket)
        index = mode_index()
        for series in self._series:
            color = SERIES_COLORS[series.slot][index]
            segment: list[float] = []
            last_t = None
            last_point = None
            for t, v in zip(self._timestamps, series.values, strict=False):
                if v is None or (last_t is not None and t - last_t > gap):
                    self._draw_segment(segment, color)
                    segment = []
                if v is not None:
                    point = self._point(t, v)
                    segment += point
                    last_point = point
                last_t = t
            self._draw_segment(segment, color)
            if last_point is not None:  # marcador final com anel da cor da superfície
                px, py = last_point
                c.create_oval(px - 6, py - 6, px + 6, py + 6, fill=surface, outline="")
                c.create_oval(px - 4, py - 4, px + 4, py + 4, fill=color, outline="")

    def _point(self, t: float, v: float) -> list[float]:
        p = self._plot
        x = p.x0 + (p.x1 - p.x0) * (t - p.t0) / max(1e-9, p.t1 - p.t0)
        y = p.y1 - (p.y1 - p.y0) * min(v, p.y_max) / p.y_max
        return [x, y]

    def _draw_segment(self, coords: list[float], color: str) -> None:
        if len(coords) >= 4:
            self.canvas.create_line(*coords, fill=color, width=2, capstyle="round", joinstyle="round")
        elif len(coords) == 2:
            x, y = coords
            self.canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill=color, outline="")

    def _hover(self, event: tk.Event) -> None:
        c, p = self.canvas, self._plot
        c.delete("hover")
        if not p.timestamps or not (p.x0 <= event.x <= p.x1):
            return
        t = p.t0 + (event.x - p.x0) / max(1, p.x1 - p.x0) * (p.t1 - p.t0)
        index = min(range(len(p.timestamps)), key=lambda i: abs(p.timestamps[i] - t))
        ts = p.timestamps[index]
        x = self._point(ts, 0)[0]
        surface, grid, baseline, secondary, muted, primary, tip = _CHART_INK[mode_index()]
        c.create_line(x, p.y0, x, p.y1, fill=baseline, width=1, tags="hover")
        lines = []
        for series in self._series:
            value = series.values[index] if index < len(series.values) else None
            color = SERIES_COLORS[series.slot][mode_index()]
            if value is not None:
                px, py = self._point(ts, value)
                c.create_oval(px - 6, py - 6, px + 6, py + 6, fill=surface, outline="", tags="hover")
                c.create_oval(px - 4, py - 4, px + 4, py + 4, fill=color, outline="", tags="hover")
            lines.append((color, "—" if value is None else self._fmt(value), series.name))
        # Tooltip: valor em destaque, nome da série discreto, chave de linha.
        stamp = time.strftime("%d/%m %H:%M:%S", time.localtime(ts))
        box_w, row_h = 190, 18
        box_h = 24 + row_h * len(lines)
        bx = x + 12 if x + 12 + box_w < p.x1 else x - 12 - box_w
        by = p.y0 + 4
        c.create_rectangle(bx, by, bx + box_w, by + box_h, fill=tip, outline=grid, tags="hover")
        c.create_text(bx + 10, by + 12, text=stamp, anchor="w", fill=muted, font=(UI_FONT, 9), tags="hover")
        for i, (color, value, name) in enumerate(lines):
            y = by + 30 + i * row_h
            c.create_line(bx + 10, y, bx + 24, y, fill=color, width=2, capstyle="round", tags="hover")
            value_id = c.create_text(bx + 32, y, text=value, anchor="w", fill=primary,
                                     font=(UI_FONT, 10, "bold"), tags="hover")
            c.create_text(c.bbox(value_id)[2] + 8, y, text=name, anchor="w", fill=secondary,
                          font=(UI_FONT, 9), tags="hover")


def _gap_threshold(timestamps: Sequence[float], bucket: float) -> float:
    """Distância a partir da qual a linha é interrompida (servidor offline, app fechado).

    Usa o espaçamento típico real das amostras — não o tamanho do balde — para que
    coletas espaçadas (ex.: intervalo de 60 s numa janela de 15 min) continuem ligadas.
    """
    deltas = sorted(b - a for a, b in zip(timestamps, timestamps[1:], strict=False) if b > a)
    typical = deltas[len(deltas) // 2] if deltas else bucket
    return max(typical * 3, bucket * 2.5, 15.0)


def _nice_ceiling(value: float) -> float:
    if value <= 0:
        return 1.0
    exponent = math.floor(math.log10(value))
    fraction = value / 10 ** exponent
    nice = next(n for n in (1, 2, 2.5, 5, 10) if fraction <= n)
    return nice * 10 ** exponent


def _nice_scale(value: float, base: int = 10) -> tuple[float, float]:
    """(máximo, passo) com 3 a 5 intervalos "redondos" que cobrem ``value``.

    ``base=1024`` escolhe o passo na unidade binária do valor (KB, MB...) para que
    as marcas formatadas em bytes fiquem redondas (2,5 MB/s em vez de 2,4 MB/s).
    """
    if value <= 0:
        return 1.0, 0.25
    unit = 1.0
    if base == 1024:
        while value / unit >= 1024:
            unit *= 1024
    scaled = value / unit
    best = None
    for count in (4, 5, 3):
        step = _nice_ceiling(scaled / count)
        if best is None or step * count < best[0] * best[1] - 1e-9:
            best = (step, count)
    step, count = best
    return step * count * unit, step * unit


def _ticks(y_max: float, step: float | None = None) -> list[float]:
    step = step or y_max / 4
    count = max(1, round(y_max / step))
    return [step * i for i in range(count + 1)]


def _time_ticks(t0: float, t1: float, count: int = 5) -> list[float]:
    span = t1 - t0
    steps = (60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
    step = next((s for s in steps if span / s <= count), 86400)
    offset = -time.localtime(t0).tm_gmtoff
    first = math.ceil((t0 - offset) / step) * step + offset
    return [t for t in (first + i * step for i in range(count + 2)) if t0 <= t <= t1]
