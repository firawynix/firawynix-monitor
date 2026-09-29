"""Janela principal: seletor de servidor (ou visão geral), métricas, abas, ações,
alertas e integração com a bandeja.

Regra de ouro de threading: somente a thread da UI toca em widgets. Eventos do
monitor chegam por ``MonitorManager.events`` e chamadas de outras threads (ex.:
menu da bandeja) por :meth:`Dashboard.call_in_ui`; ambos são drenados por
``_pump`` a cada 100 ms via ``after``.
"""

from __future__ import annotations

import logging
import queue
import shutil
import subprocess
import sys
import time
import tkinter as tk
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import Future
from pathlib import Path

import customtkinter as ctk

from config.settings import Config, ServerConfig
from core.history import HistoryStore
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
    Stack,
    ThresholdAlertEvent,
)
from core.monitor import MonitorManager
from core.notifier import Notifier
from ui.tabs import ALL_TABS, OverviewPanel, ServicesTab, Tab
from ui.widgets import (
    BANNER_ERROR,
    BANNER_INFO,
    BANNER_WARN,
    GRAY,
    GREEN,
    RED,
    TEXT,
    YELLOW,
    ConfirmDialog,
    CountsCard,
    MetricCard,
    TextViewer,
    fmt_duration,
    fmt_kb,
    fmt_mb,
    fmt_num,
    fmt_rate,
    short_path,
    usage_color,
)

log = logging.getLogger(__name__)

APP_TITLE = "Firawynix Monitor"
OVERVIEW = "Visão geral"
INTERVAL_OPTIONS = (2, 5, 10, 30, 60)
CONNECTION_COLORS = {
    ConnectionState.CONNECTING: YELLOW,
    ConnectionState.CONNECTED: GREEN,
    ConnectionState.RECONNECTING: RED,
    ConnectionState.STOPPED: GRAY,
}


class Dashboard(ctk.CTk):
    UI_POLL_MS = 100
    MAX_EVENTS_PER_TICK = 500
    STATUS_MAX_CHARS = 120

    def __init__(self, app_config: Config, manager: MonitorManager, notifier: Notifier, *,
                 history: HistoryStore | None = None, icon_path: Path | None = None,
                 on_quit: Callable[[], None] | None = None) -> None:
        super().__init__()
        self._config = app_config
        self.manager = manager
        self.settings = app_config.settings
        self.history = history
        self._notifier = notifier
        self._on_quit = on_quit
        self._ui_calls: queue.Queue[Callable[[], None]] = queue.Queue()
        self._snapshots: dict[str, HostSnapshot] = {}
        self._connections: dict[str, ConnectionEvent] = {}
        self._offline_notified: set[str] = set()
        self._busy: dict[str, str] = {}
        self._current: str | None = None if len(app_config.servers) > 1 else app_config.servers[0].name
        self._tray = None
        self._hidden_hint_shown = False
        self._quitting = False

        self.title(APP_TITLE)
        self.geometry("1400x900")
        self.minsize(1120, 700)
        if icon_path is not None and sys.platform == "win32":
            try:
                self.iconbitmap(default=str(icon_path))
            except tk.TclError:
                log.debug("Não foi possível definir o ícone da janela", exc_info=True)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self._build_header()
        self._build_cards()
        self._build_banner()
        self._build_content()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<F5>", lambda _e: self.refresh_current())
        self.bind("<Control-f>", lambda _e: self._focus_search())
        self.report_callback_exception = self._report_callback_exception
        self._apply_selection()
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
        self._server_menu = ctk.CTkOptionMenu(controls, values=[OVERVIEW, *self.manager.server_names], width=220,
                                              dynamic_resizing=False, command=self._on_server_menu)
        self._server_menu.pack(side="left", padx=(0, 12))
        self._conn_badge = ctk.CTkLabel(controls, text="", width=240, anchor="w")
        self._conn_badge.pack(side="left", padx=(0, 8))
        self._terminal_btn = ctk.CTkButton(controls, text="Terminal SSH", width=110, command=self.open_terminal,
                                           fg_color=("gray70", "gray30"), hover_color=("gray60", "gray35"),
                                           text_color=("gray10", "gray95"))
        self._terminal_btn.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(controls, text="Intervalo").pack(side="left", padx=(0, 6))
        interval = self.settings.poll_interval_seconds
        options = sorted({*INTERVAL_OPTIONS, int(interval) if float(interval).is_integer() else interval})
        self._interval_menu = ctk.CTkOptionMenu(controls, values=[self._fmt_interval(v) for v in options],
                                                width=84, command=self._on_interval_selected)
        self._interval_menu.set(self._fmt_interval(interval))
        self._interval_menu.pack(side="left", padx=(0, 12))
        ctk.CTkButton(controls, text="Atualizar", width=96, command=self.refresh_current).pack(side="left")

    def _build_cards(self) -> None:
        self._cards_row = ctk.CTkFrame(self, fg_color="transparent")
        self._cards_row.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 8))
        for column in range(6):
            self._cards_row.grid_columnconfigure(column, weight=1, uniform="metric")
        self._cpu_card = MetricCard(self._cards_row, "CPU")
        self._mem_card = MetricCard(self._cards_row, "Memória")
        self._disk_card = MetricCard(self._cards_row, "Disco")
        self._net_card = MetricCard(self._cards_row, "Rede", with_bar=False)
        self._uptime_card = MetricCard(self._cards_row, "Uptime", with_bar=False)
        self._counts_card = CountsCard(self._cards_row, "Cargas")
        cards = (self._cpu_card, self._mem_card, self._disk_card, self._net_card, self._uptime_card,
                 self._counts_card)
        for column, card in enumerate(cards):
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 5, 0 if column == 5 else 5))

    def _build_banner(self) -> None:
        self._banner = ctk.CTkLabel(self, text="", anchor="w", justify="left", corner_radius=8,
                                    fg_color=BANNER_WARN, wraplength=1300)
        self._banner.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 8), ipady=6)
        self._banner.grid_remove()

    def _build_content(self) -> None:
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=3, column=0, sticky="nsew", padx=18)
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self._overview = OverviewPanel(content, self)
        self._overview.grid(row=0, column=0, sticky="nsew")
        self._tabview = ctk.CTkTabview(content, anchor="w", command=self.render_current_tab)
        self._tabview.grid(row=0, column=0, sticky="nsew")
        self._tabs: dict[str, Tab] = {}
        for tab_cls in ALL_TABS:
            frame = self._tabview.add(tab_cls.title)
            tab = tab_cls(frame, self)
            tab.pack(fill="both", expand=True)
            self._tabs[tab_cls.title] = tab

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=4, column=0, sticky="ew", padx=18, pady=(6, 10))
        bar.grid_columnconfigure(0, weight=1)
        self._status_msg = ctk.CTkLabel(bar, text="Pronto.", anchor="w")
        self._status_msg.grid(row=0, column=0, sticky="ew")
        self._status_info = ctk.CTkLabel(bar, text="", anchor="e", text_color=GRAY)
        self._status_info.grid(row=0, column=1, sticky="e", padx=(12, 12))
        self._alerts_switch = ctk.CTkSwitch(bar, text="Alertas", command=self._on_alerts_switch)
        if self.settings.notifications.enabled:
            self._alerts_switch.select()
        else:
            self._alerts_switch.configure(state="disabled")
        self._alerts_switch.grid(row=0, column=2, sticky="e")

    # -- API usada pelas abas -------------------------------------------------

    def server_config(self, name: str) -> ServerConfig:
        return self._config.server(name)

    def busy_label(self, server: str, key: str) -> str | None:
        return self._busy.get(f"{server}|{key}")

    def set_status(self, text: str, *, error: bool = False, warning: bool = False) -> None:
        color = RED if error else YELLOW if warning else TEXT
        text = " ".join(text.split())
        if len(text) > self.STATUS_MAX_CHARS:
            text = text[: self.STATUS_MAX_CHARS - 1] + "…"
        self._status_msg.configure(text=f"{time.strftime('%H:%M:%S')}  {text}", text_color=color)

    def copy_text(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status(f"Copiado: {text}")

    def show_text(self, title: str, *, subtitle: str = "", text: str | None = None,
                  fetch: Callable[[int], Future[str]] | None = None,
                  preview: Callable[[int], str] | None = None) -> None:
        TextViewer(self, title=title, subtitle=subtitle, text=text, fetch=fetch, command_preview=preview,
                   lines=self.settings.log_lines)

    def confirm(self, title: str, message: str, confirm_text: str, danger: bool = False) -> bool:
        return ConfirmDialog(self, title=title, message=message, confirm_text=confirm_text, danger=danger).show()

    def run_service_action(self, server: str, service: ServiceInfo, action: ServiceAction) -> None:
        if not self._ensure_connected(server):
            return
        noun = {ServiceKind.SYSTEMD: "a unidade", ServiceKind.KUBERNETES: "o pod",
                ServiceKind.LIBVIRT: "a VM"}.get(service.kind, "o contêiner")
        message = f"Deseja {action.label.lower()} {noun} \"{service.name}\" em {server}?"
        if service.kind is ServiceKind.KUBERNETES:
            message = (f"Reiniciar o pod \"{service.name}\" em {server}?\n\nO pod será excluído e recriado pelo "
                       "controlador (Deployment/StatefulSet). Pods avulsos não voltam sozinhos.")
        elif service.kind is ServiceKind.LIBVIRT and action is ServiceAction.STOP:
            message += "\n\nSerá enviado um desligamento ACPI (shutdown), não um desligamento forçado."
        if service.critical and tuple(self.server_config(server).critical_services) != ("*",):
            message += "\n\nAtenção: este item está marcado como CRÍTICO."
        if action is ServiceAction.STOP:
            message += "\n\nEle ficará indisponível até ser iniciado novamente."
        if not self.confirm(f"{action.label} {service.name}", message, action.label, action is ServiceAction.STOP):
            return
        self._mark_busy(server, service.key, action.progress_label, service.name)
        self.manager.run_action(server, service, action)

    def run_stack_action(self, server: str, stack: Stack, action: ServiceAction) -> None:
        if not self._ensure_connected(server):
            return
        names = ", ".join(m.name for m in stack.members[:6]) + ("…" if len(stack.members) > 6 else "")
        message = (f"Deseja {action.label.lower()} os {len(stack.members)} contêineres da stack \"{stack.name}\" "
                   f"em {server}?\n\n{names}")
        if not self.confirm(f"{action.label} stack {stack.name}", message, action.label,
                            action is ServiceAction.STOP):
            return
        self._mark_busy(server, stack.key, action.progress_label, f"stack {stack.name}")
        self.manager.run_stack_action(server, stack, action)

    def kill_process(self, server: str, pid: int, force: bool) -> None:
        if not self._ensure_connected(server):
            return
        signal = "SIGKILL (imediato, sem limpeza)" if force else "SIGTERM (encerramento gracioso)"
        if not self.confirm("Encerrar processo", f"Enviar {signal} ao PID {pid} em {server}?",
                            "Forçar" if force else "Encerrar", danger=True):
            return
        self._mark_busy(server, f"pid:{pid}", "Encerrando", f"PID {pid}")
        self.manager.kill_process(server, pid, force)

    def open_logs(self, server: str, service: ServiceInfo) -> None:
        title = "Detalhes" if service.kind is ServiceKind.LIBVIRT else "Logs"
        self.show_text(f"{title} — {service.name} @ {server}", subtitle=f"{service.name}  ·  {server}",
                       fetch=lambda lines: self.manager.fetch_logs(server, service, lines),
                       preview=lambda lines: self.manager.logs_command(server, service, lines))

    def open_stack_logs(self, server: str, stack: Stack) -> None:
        self.show_text(f"Logs — stack {stack.name} @ {server}",
                       subtitle=f"stack {stack.name} ({len(stack.members)} membros)  ·  {server}",
                       fetch=lambda lines: self.manager.fetch_stack_logs(server, stack, lines))

    def _ensure_connected(self, server: str) -> bool:
        if self.manager.is_connected(server):
            return True
        self.set_status(f"{server} está desconectado; ação indisponível.", error=True)
        return False

    def _mark_busy(self, server: str, key: str, label: str, target: str) -> None:
        self._busy[f"{server}|{key}"] = label
        self.set_status(f"{label} {target} em {server}…")
        self.render_current_tab()

    # -- API pública (tray / main) --------------------------------------------

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
        if self._current is None:
            self.refresh_all()
            return
        self.manager.refresh(self._current, full=True)
        self.set_status(f"Atualizando {self._current}…")

    def refresh_all(self) -> None:
        self.manager.refresh(full=True)
        self.set_status("Atualizando todos os servidores…")

    def set_muted(self, muted: bool) -> None:
        self._notifier.muted = muted
        if self.settings.notifications.enabled:
            (self._alerts_switch.deselect if muted else self._alerts_switch.select)()
        if self._tray is not None:
            self._tray.set_muted(muted)
        self.set_status("Alertas silenciados." if muted else "Alertas reativados.")

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

    def open_terminal(self) -> None:
        """Abre um terminal com ``ssh`` para o servidor atual (cliente OpenSSH do Windows)."""
        if self._current is None:
            return
        server = self.server_config(self._current)
        args = ["ssh", "-p", str(server.port)]
        if server.key_file:
            args += ["-i", str(server.key_file)]
        args.append(f"{server.username}@{server.host}")
        command_line = subprocess.list2cmdline(args)
        try:
            if sys.platform == "win32":
                wt = shutil.which("wt")
                if wt:
                    subprocess.Popen([wt, "new-tab", "--title", f"SSH {server.name}", *args])
                else:
                    subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                terminal = shutil.which("x-terminal-emulator") or shutil.which("gnome-terminal")
                if terminal is None:
                    raise FileNotFoundError("nenhum emulador de terminal encontrado")
                subprocess.Popen([terminal, "-e", command_line] if "x-terminal" in terminal
                                 else [terminal, "--", *args])
        except OSError as exc:
            self.copy_text(command_line)
            self.set_status(f"Não foi possível abrir o terminal ({exc}). Comando copiado: {command_line}",
                            warning=True)
            return
        self.set_status(f"Terminal aberto: {command_line}")

    def select_server(self, name: str | None, focus_key: str | None = None) -> None:
        if name != self._current:
            for tab in self._tabs.values():
                tab.reset()
        self._current = name
        self._apply_selection()
        if name is not None and focus_key is not None:
            self._tabview.set(ServicesTab.title)
            services = self._tabs[ServicesTab.title]
            if isinstance(services, ServicesTab):
                services.show_all_and_select(focus_key)

    # -- renderização -----------------------------------------------------------

    def _apply_selection(self) -> None:
        if self._current is None:
            self._tabview.grid_remove()
            self._cards_row.grid_remove()
            self._overview.grid()
            _set_enabled(self._terminal_btn, False)
        else:
            self._overview.grid_remove()
            self._cards_row.grid()
            self._tabview.grid()
            _set_enabled(self._terminal_btn, True)
            self._interval_menu.set(self._fmt_interval(self.manager.monitors[self._current].interval))
        self._render_all()

    def _render_all(self) -> None:
        self._render_overview_header()
        self._render_connection()
        if self._current is None:
            self._banner.grid_remove()
            self._overview.render(self._snapshots, self._connections, self._server_health)
            self._status_info.configure(text=f"{len(self.manager.server_names)} servidores · "
                                             f"intervalo {self._fmt_interval(self.settings.poll_interval_seconds)}")
            return
        snapshot = self._snapshots.get(self._current)
        self._render_cards(snapshot)
        self._render_banner(snapshot)
        self._render_status_info(snapshot)
        self.render_current_tab()

    def render_current_tab(self, *_args) -> None:
        if self._current is None:
            self._overview.render(self._snapshots, self._connections, self._server_health)
            return
        tab = self._tabs.get(self._tabview.get())
        if tab is None:
            return
        try:
            tab.render(self._current, self._snapshots.get(self._current), self.manager.is_connected(self._current))
        except Exception:  # noqa: BLE001 - uma aba com defeito não pode travar as outras
            log.exception("Erro ao renderizar a aba %s", tab.title)

    def _render_connection(self) -> None:
        if self._current is None:
            online = sum(1 for e in self._connections.values() if e.state is ConnectionState.CONNECTED)
            total = len(self.manager.server_names)
            self._conn_badge.configure(text=f"● {online}/{total} online",
                                       text_color=GREEN if online == total else YELLOW if online else RED)
            return
        event = self._connections.get(self._current)
        if event is None:
            self._conn_badge.configure(text="● Aguardando…", text_color=GRAY)
            return
        text = f"● {event.state.label}"
        if event.state is ConnectionState.RECONNECTING and event.retry_in is not None:
            remaining = event.timestamp + event.retry_in - time.time()
            text += f" · nova tentativa em {int(remaining) + 1} s" if remaining > 0.5 else " · reconectando…"
        self._conn_badge.configure(text=text, text_color=CONNECTION_COLORS[event.state])

    def _render_cards(self, snapshot: HostSnapshot | None) -> None:
        metrics = snapshot.metrics if snapshot else None
        if snapshot is None:
            self._counts_card.set_counts(None, None)
        else:
            counts = snapshot.counts()
            parts = [f"{counts[ServiceStatus.STOPPED]} paradas", f"{len(snapshot.services)} total"]
            containers = snapshot.count_kind(ServiceKind.DOCKER) + snapshot.count_kind(ServiceKind.PODMAN)
            for count, label in ((containers, "contêineres"), (snapshot.count_kind(ServiceKind.KUBERNETES), "pods"),
                                 (snapshot.count_kind(ServiceKind.LIBVIRT), "VMs")):
                if count:
                    parts.append(f"{count} {label}")
            self._counts_card.set_counts(counts[ServiceStatus.ACTIVE],
                                         counts[ServiceStatus.FAILED] + counts[ServiceStatus.DEGRADED],
                                         " · ".join(parts))
        if metrics is None:
            for card in (self._cpu_card, self._mem_card, self._disk_card, self._net_card, self._uptime_card):
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
        swap = metrics.swap_percent
        self._mem_card.set_values(f"{mem_pct:.0f}%" if mem_pct is not None else "—",
                                  f"{fmt_mb(metrics.mem_used_mb)} de {fmt_mb(metrics.mem_total_mb)}",
                                  (mem_pct or 0) / 100, usage_color(mem_pct),
                                  note=f"swap {fmt_num(swap, 0)}%" if swap is not None else "",
                                  note_color=usage_color(swap) if swap and swap >= 75 else GRAY)

        root, fullest = metrics.root_disk, metrics.fullest_disk
        if root is None:
            self._disk_card.set_values("—", "Sem dados de disco")
        else:
            note, note_color = "", None
            if fullest is not None and fullest.mount != root.mount and fullest.use_percent > root.use_percent:
                note = f"Mais cheio: {short_path(fullest.mount)} ({fullest.use_percent:.0f}%)"
                note_color = usage_color(fullest.use_percent) if fullest.use_percent >= 75 else GRAY
            self._disk_card.set_values(f"{root.use_percent:.0f}%",
                                       f"{root.mount} · {fmt_kb(root.avail_kb)} livres de {fmt_kb(root.size_kb)}",
                                       root.use_percent / 100, usage_color(root.use_percent),
                                       note=note, note_color=note_color)

        rx, tx = metrics.net_rx_bps, metrics.net_tx_bps
        io_read, io_write = metrics.disk_read_bps, metrics.disk_write_bps
        self._net_card.set_values(f"↓ {fmt_rate(rx)}" if rx is not None else "…",
                                  f"↑ {fmt_rate(tx)} enviados" if tx is not None else "aguardando 2ª amostra",
                                  note=(f"disco ↓ {fmt_rate(io_read)} ↑ {fmt_rate(io_write)}"
                                        if io_read is not None else ""))

        system, updates = snapshot.system, snapshot.updates
        note, note_color = "", GRAY
        if system is not None and system.reboot_required:
            note, note_color = "Reinício pendente", YELLOW
        elif updates is not None and updates.pending:
            note = f"{updates.pending} atualizações" + (f" ({updates.security} seg.)" if updates.security else "")
            note_color = YELLOW if updates.security else GRAY
        self._uptime_card.set_values(fmt_duration(metrics.uptime_seconds),
                                     f"Coleta em {fmt_num(snapshot.duration, 2)} s", note=note, note_color=note_color)

    def _render_banner(self, snapshot: HostSnapshot | None) -> None:
        event = self._connections.get(self._current)
        server_cfg = self.server_config(self._current)
        text, color = "", BANNER_WARN
        if event is not None and event.state is ConnectionState.RECONNECTING:
            stale = " Exibindo os últimos dados coletados." if snapshot else ""
            text, color = f"Sem conexão com {server_cfg.address}: {event.message}{stale}", BANNER_ERROR
        elif snapshot is None:
            text, color = f"Conectando a {server_cfg.address}…", BANNER_INFO
        elif snapshot.resource_alerts or snapshot.warnings:
            alerts = [f"Limite excedido: {a}" for a in snapshot.resource_alerts]
            text = "  |  ".join([*alerts, *snapshot.warnings])
            color = BANNER_ERROR if snapshot.resource_alerts else BANNER_WARN
        if text:
            self._banner.configure(text=text, fg_color=color)
            self._banner.grid()
        else:
            self._banner.grid_remove()

    def _render_status_info(self, snapshot: HostSnapshot | None) -> None:
        interval = self.manager.monitors[self._current].interval
        if snapshot is None:
            self._status_info.configure(text=f"Intervalo {self._fmt_interval(interval)}")
            return
        stamp = time.strftime("%H:%M:%S", time.localtime(snapshot.collected_at))
        self._status_info.configure(text=f"Atualizado às {stamp} · coleta {fmt_num(snapshot.duration, 2)} s · "
                                         f"intervalo {self._fmt_interval(interval)}")

    def _render_overview_header(self) -> None:
        names = self.manager.server_names
        online = sum(1 for n in names if self._connections.get(n)
                     and self._connections[n].state is ConnectionState.CONNECTED)
        failing = sum(1 for n in names if self._server_health(n) is HealthLevel.CRITICAL)
        text = f"{len(names)} servidor{'es' if len(names) != 1 else ''} · {online} online"
        if failing:
            text += f" · {failing} com problemas"
        self._overview_label.configure(text=text, text_color=RED if failing else GRAY)
        self._server_menu.configure(values=[OVERVIEW, *(self._menu_label(n) for n in names)])
        self._server_menu.set(OVERVIEW if self._current is None else self._menu_label(self._current))

    def _menu_label(self, server: str) -> str:
        return f"{server}  ●" if self._server_health(server) is HealthLevel.CRITICAL else server

    def _server_health(self, server: str) -> HealthLevel:
        event = self._connections.get(server)
        snapshot = self._snapshots.get(server)
        if event is not None and event.state is ConnectionState.RECONNECTING:
            return HealthLevel.CRITICAL
        if snapshot is None:
            return HealthLevel.UNKNOWN
        if snapshot.failed_critical():
            return HealthLevel.CRITICAL
        counts = snapshot.counts()
        if (counts[ServiceStatus.FAILED] or counts[ServiceStatus.DEGRADED] or snapshot.warnings
                or snapshot.resource_alerts):
            return HealthLevel.WARNING
        return HealthLevel.OK

    def _update_tray(self) -> None:
        if self._tray is None:
            return
        levels = {n: self._server_health(n) for n in self.manager.server_names}
        overall = max(levels.values(), default=HealthLevel.UNKNOWN)
        problems = []
        for name, level in levels.items():
            if level < HealthLevel.WARNING:
                continue
            event, snapshot = self._connections.get(name), self._snapshots.get(name)
            if event is not None and event.state is ConnectionState.RECONNECTING:
                problems.append(f"{name}: offline")
            elif snapshot is not None:
                failed = snapshot.counts()[ServiceStatus.FAILED]
                problems.append(f"{name}: {failed} falha{'s' if failed != 1 else ''}" if failed else f"{name}: aviso")
        self._tray.set_health(overall, APP_TITLE + ("\n" + "\n".join(problems) if problems else " — tudo OK"))

    # -- loop de eventos ----------------------------------------------------------

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
                    event = self.manager.events.get_nowait()
                except queue.Empty:
                    break
                self._handle_event(event, dirty, alerts)
            if alerts:
                self._dispatch_alerts(alerts)
            if dirty:
                self._update_tray()
                if self._current is None or self._current in dirty:
                    self._render_all()
                else:
                    self._render_overview_header()
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
        elif isinstance(event, ThresholdAlertEvent):
            self._notify_threshold(event)
        elif isinstance(event, ActionResultEvent):
            self._busy.pop(f"{server}|{event.busy_key}", None)
            self._on_action_result(event)
            dirty.add(server)

    def _on_action_result(self, event: ActionResultEvent) -> None:
        result = event.result
        if result.outcome is ActionOutcome.ERROR:
            self.set_status(f"[{event.server}] {result.message}", error=True)
            if self.winfo_viewable():
                # Agendado: o diálogo é modal e não pode bloquear a bomba de eventos.
                self.after(0, lambda: ConfirmDialog(
                    self, title=f"Falha: {event.action_label} {event.target}", message=result.message,
                    confirm_text="OK", cancel_text=None).show())
            else:
                self._notifier.notify(f"Falha: {event.action_label} {event.target}", result.message)
        else:
            self.set_status(f"[{event.server}] {result.message}", warning=result.outcome is ActionOutcome.PENDING)

    def _notify_connection_change(self, server: str, previous: ConnectionEvent | None,
                                  event: ConnectionEvent) -> None:
        settings = self.settings.notifications
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

    def _notify_threshold(self, event: ThresholdAlertEvent) -> None:
        value = fmt_num(event.value, 0)
        if event.recovered:
            if self.settings.notifications.notify_on_recovery:
                self._notifier.notify(f"{event.label} normalizado — {event.server}", f"Agora em {value}%.",
                                      key=f"{event.server}:{event.metric}:ok")
            return
        log.warning("[%s] limite excedido: %s %s%%", event.server, event.label, value)
        self._notifier.notify(f"{event.label} em {value}% — {event.server}",
                              f"Acima do limite configurado de {fmt_num(event.threshold, 0)}%.",
                              key=f"{event.server}:{event.metric}")
        self.set_status(f"[{event.server}] {event.label} em {value}% (limite {fmt_num(event.threshold, 0)}%)",
                        warning=True)

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
                self._notifier.notify(f"{len(items)} itens {plural} em {server}", shown,
                                      key=f"{server}:{kind.value}:batch")
            else:
                for alert in items:
                    service = alert.service
                    self._notifier.notify(f"{service.name} {verbs[kind]}",
                                          f"{server} · {service.type_label} · {service.state_text}",
                                          key=f"{server}:{service.key}:{kind.value}")
            if kind is not AlertKind.RECOVERED:
                self.set_status(f"[{server}] {', '.join(names)} "
                                f"{verbs[kind] if len(names) == 1 else 'com problema'}",
                                error=kind is AlertKind.FAILED)

    def _tick(self) -> None:
        """Atualizações por segundo: contagem regressiva de reconexão."""
        try:
            self._render_connection()
        finally:
            if not self._quitting:
                self.after(1000, self._tick)

    # -- handlers -------------------------------------------------------------------

    def _on_server_menu(self, label: str) -> None:
        self.select_server(None if label == OVERVIEW else label.replace("●", "").strip())

    def _on_interval_selected(self, label: str) -> None:
        seconds = float(label.split()[0].replace(",", "."))
        self.manager.set_poll_interval(seconds)
        self.set_status(f"Intervalo de coleta alterado para {label}.")
        if self._current is not None:
            self._render_status_info(self._snapshots.get(self._current))

    def _focus_search(self) -> None:
        if self._current is not None:
            tab = self._tabs.get(self._tabview.get())
            if tab is not None:
                tab.focus_search()

    def _on_alerts_switch(self) -> None:
        self.set_muted(not bool(self._alerts_switch.get()))

    def _on_close(self) -> None:
        if self.can_hide_to_tray and self.settings.minimize_to_tray:
            self.hide_to_tray()
        else:
            self.quit_app()

    def _report_callback_exception(self, exc_type, exc, tb) -> None:
        log.error("Erro não tratado na UI", exc_info=(exc_type, exc, tb))
        self.set_status(f"Erro interno: {exc}", error=True)

    @staticmethod
    def _fmt_interval(seconds: float) -> str:
        return f"{int(seconds)} s" if float(seconds).is_integer() else f"{fmt_num(seconds)} s"


def _set_enabled(widget: ctk.CTkButton, enabled: bool) -> None:
    widget.configure(state="normal" if enabled else "disabled")
