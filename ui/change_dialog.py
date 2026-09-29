"""Diálogo "Mudança segura": antes de parar, iniciar, reiniciar, pausar, remover,
criar ou restaurar um contêiner, mostra o risco e o que pode ser afetado, as
proteções (backup) e o roteiro; depois acompanha cada passo ao vivo e oferece o
caminho de volta (iniciar de novo / restaurar)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from concurrent.futures import Future
from typing import TYPE_CHECKING

import customtkinter as ctk

from core.backups import ChangeRecord
from core.changes import ChangeAction, ContainerSpec, Risk, plan_steps
from core.models import ChangeProgressEvent, ServiceInfo
from ui import theme
from ui.widgets import CARD_BG, GRAY, GREEN, ORANGE, RED, TEXT, YELLOW, center_on, make_modal

if TYPE_CHECKING:
    from core.monitor import PreparedChange
    from ui.dashboard import Dashboard

log = logging.getLogger(__name__)

RISK_COLORS = {Risk.NONE: GRAY, Risk.LOW: GREEN, Risk.MEDIUM: YELLOW, Risk.HIGH: ORANGE, Risk.CRITICAL: RED}
STEP_ICONS = {"pending": ("○", GRAY), "running": ("◐", theme.ACCENT_TEXT), "ok": ("✓", GREEN),
              "warning": ("⚠", YELLOW), "error": ("✗", RED), "skipped": ("–", GRAY)}


def confirmation_needed(risk: Risk) -> bool:
    """Risco crítico: o usuário digita o nome do contêiner para confirmar."""
    return risk >= Risk.CRITICAL


class ChangeDialog(ctk.CTkToplevel):
    POLL_MS = 150

    def __init__(self, app: Dashboard, server: str, action: ChangeAction, *, service: ServiceInfo | None = None,
                 spec: ContainerSpec | None = None, record: ChangeRecord | None = None,
                 use_snapshot: bool = False) -> None:
        super().__init__(app)
        self.app = app
        self.server = server
        self.action = action
        self.service = service
        self.target = service.name if service else spec.name if spec else record.target if record else "?"
        self.prepared: PreparedChange | None = None
        self.change_id: str | None = None
        self.record: ChangeRecord | None = None
        self._future: Future | None = None
        self._checks: dict[str, ctk.CTkCheckBox] = {}
        self._step_rows: list[tuple[ctk.CTkLabel, ctk.CTkLabel, ctk.CTkLabel]] = []
        self.title(f"{action.label} {self.target} — mudança segura")
        self.geometry("820x720")
        self.minsize(700, 560)
        self.transient(app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 6))
        header.grid_columnconfigure(1, weight=1)
        engine = service.kind.label if service else (spec.engine if spec else record.engine if record else "")
        ctk.CTkLabel(header, text=f"{action.label} \"{self.target}\"", anchor="w",
                     font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ctk.CTkLabel(header, text=f"{server} · {engine} · o painel analisa o risco, salva o necessário, executa e "
                                  "confere o resultado", anchor="w", text_color=GRAY).grid(row=1, column=0,
                                                                                            columnspan=2, sticky="w")
        self.risk_badge = ctk.CTkLabel(header, text="ANALISANDO…", corner_radius=8, fg_color=theme.PANEL_BG,
                                       font=ctk.CTkFont(size=13, weight="bold"), padx=12, pady=4)
        self.risk_badge.grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.summary = ctk.CTkLabel(header, text="Lendo o estado real do contêiner no servidor…", anchor="w",
                                    justify="left", wraplength=640)
        self.summary.grid(row=2, column=1, sticky="ew", padx=(12, 0), pady=(10, 0))

        self.body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.body.grid(row=1, column=0, sticky="nsew", padx=14)
        self.body.grid_columnconfigure(0, weight=1)

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=20, pady=(8, 16))
        footer.grid_columnconfigure(0, weight=1)
        self.confirm_entry = ctk.CTkEntry(footer, width=260, placeholder_text=f"digite {self.target} para confirmar")
        self.status = ctk.CTkLabel(footer, text="", anchor="w", text_color=GRAY, justify="left", wraplength=420)
        self.status.grid(row=1, column=0, sticky="ew")
        self.buttons = ctk.CTkFrame(footer, fg_color="transparent")
        self.buttons.grid(row=1, column=1, sticky="e")
        self.cancel_btn = ctk.CTkButton(self.buttons, text="Cancelar", width=100, fg_color="transparent",
                                        border_width=1, text_color=TEXT, command=self._close)
        self.cancel_btn.pack(side="left", padx=(0, 8))
        self.run_btn = ctk.CTkButton(self.buttons, text="Executar com segurança", width=190, state="disabled",
                                     command=self._execute)
        self.run_btn.pack(side="left")
        self.after_buttons: list[ctk.CTkButton] = []

        self.protocol("WM_DELETE_WINDOW", self._close)
        self.bind("<Escape>", lambda _e: self._close())
        center_on(self, app)
        self.after(60, lambda: make_modal(self))
        self.after(250, lambda: theme.style_window(self))
        self._future = app.manager.prepare_change(server, action, service, spec=spec, record=record,
                                                  use_snapshot=use_snapshot)
        self.after(self.POLL_MS, self._poll_prepare)

    # -- análise ---------------------------------------------------------------

    def _poll_prepare(self) -> None:
        future = self._future
        if future is None or not self.winfo_exists():
            return
        if not future.done():
            self.after(self.POLL_MS, self._poll_prepare)
            return
        try:
            self.prepared = future.result()
        except Exception as exc:  # noqa: BLE001
            self.risk_badge.configure(text="SEM ANÁLISE", text_color=RED)
            self.summary.configure(text=f"Não foi possível analisar: {exc}. Nada foi alterado.", text_color=RED)
            return
        self._render_assessment()

    def _render_assessment(self) -> None:
        assessment = self.prepared.assessment
        color = RISK_COLORS[assessment.risk]
        self.risk_badge.configure(text=f"RISCO {assessment.risk.label.upper()}", text_color=color)
        self.summary.configure(text=assessment.summary, text_color=RED if assessment.blockers else TEXT)
        row = 0
        row = self._section("O QUE PODE SER AFETADO", row)
        if not assessment.impacts:
            ctk.CTkLabel(self.body, text="Nenhum impacto relevante encontrado.", text_color=GRAY,
                         anchor="w").grid(row=row, column=0, sticky="ew", padx=6)
            row += 1
        for impact in assessment.impacts:
            card = ctk.CTkFrame(self.body, corner_radius=10, fg_color=CARD_BG)
            card.grid(row=row, column=0, sticky="ew", padx=6, pady=3)
            card.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(card, text=f"● {impact.level.label}", width=78, anchor="w",
                         text_color=RISK_COLORS[impact.level],
                         font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, rowspan=2, sticky="nw",
                                                                        padx=(10, 6), pady=6)
            ctk.CTkLabel(card, text=f"{impact.area}: {impact.title}", anchor="w", justify="left",
                         wraplength=640).grid(row=0, column=1, sticky="ew", pady=(6, 0), padx=(0, 10))
            if impact.detail:
                ctk.CTkLabel(card, text=impact.detail, anchor="w", justify="left", wraplength=640, text_color=GRAY,
                             font=ctk.CTkFont(size=12)).grid(row=1, column=1, sticky="ew", pady=(0, 6),
                                                             padx=(0, 10))
            row += 1
        if assessment.protections:
            row = self._section("PROTEÇÃO ANTES DA MUDANÇA (SALVAR)", row)
            for protection in assessment.protections:
                text = protection.label + (" — obrigatória com este risco" if protection.required else "")
                if not protection.available:
                    text += f" — indisponível ({protection.reason or 'motor sem suporte'})"
                check = ctk.CTkCheckBox(self.body, text=text, command=self._refresh_steps)
                if protection.default or protection.required:
                    check.select()
                if protection.required or not protection.available:
                    if not protection.available:
                        check.deselect()
                    check.configure(state="disabled")
                check.grid(row=row, column=0, sticky="w", padx=10, pady=(4, 0))
                ctk.CTkLabel(self.body, text=protection.detail, anchor="w", justify="left", wraplength=680,
                             text_color=GRAY, font=ctk.CTkFont(size=12)).grid(row=row + 1, column=0, sticky="ew",
                                                                              padx=(38, 10))
                self._checks[protection.id] = check
                row += 2
        row = self._section("ROTEIRO (O PAINEL SEGUE EXATAMENTE ESTES PASSOS)", row)
        self._steps_frame = ctk.CTkFrame(self.body, fg_color="transparent")
        self._steps_frame.grid(row=row, column=0, sticky="ew", padx=6)
        self._steps_frame.grid_columnconfigure(2, weight=1)
        self._refresh_steps()
        if assessment.blockers:
            self.status.configure(text="Resolva os bloqueios acima para continuar.", text_color=RED)
            return
        if confirmation_needed(assessment.risk):
            self.confirm_entry.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
            self.confirm_entry.bind("<KeyRelease>", lambda _e: self._update_run_state())
            self.status.configure(text=f"Risco crítico: digite \"{self.target}\" para liberar a execução.",
                                  text_color=RED)
        self._update_run_state()

    def _section(self, title: str, row: int) -> int:
        ctk.CTkLabel(self.body, text=title, anchor="w", text_color=theme.ACCENT_TEXT,
                     font=ctk.CTkFont(size=12, weight="bold")).grid(row=row, column=0, sticky="ew", padx=6,
                                                                     pady=(12, 4))
        return row + 1

    def chosen(self) -> list[str]:
        return [pid for pid, check in self._checks.items() if check.get()]

    def _refresh_steps(self) -> None:
        if self.prepared is None or self.change_id is not None:
            return
        steps = plan_steps(self.action, self.prepared.assessment.protections, self.service, self.chosen())
        self._render_steps(steps)

    def _render_steps(self, steps) -> None:
        for widget in self._steps_frame.winfo_children():
            widget.destroy()
        self._step_rows = []
        for index, label in enumerate(steps):
            icon, color = STEP_ICONS["pending"]
            icon_label = ctk.CTkLabel(self._steps_frame, text=icon, width=22, text_color=color,
                                      font=ctk.CTkFont(size=14, weight="bold"))
            icon_label.grid(row=index, column=0, sticky="nw", pady=2)
            ctk.CTkLabel(self._steps_frame, text=f"{index + 1}. {label}", anchor="w").grid(
                row=index, column=1, sticky="nw", padx=(2, 10), pady=2)
            message = ctk.CTkLabel(self._steps_frame, text="", anchor="w", justify="left", wraplength=380,
                                   text_color=GRAY, font=ctk.CTkFont(size=12))
            message.grid(row=index, column=2, sticky="ew", pady=2)
            self._step_rows.append((icon_label, message, None))

    def _update_run_state(self) -> None:
        if self.prepared is None or self.change_id is not None:
            return
        assessment = self.prepared.assessment
        allowed = not assessment.blockers and self.app.manager.is_connected(self.server)
        if confirmation_needed(assessment.risk):
            allowed = allowed and self.confirm_entry.get().strip() == self.target
        self.run_btn.configure(state="normal" if allowed else "disabled")

    # -- execução -------------------------------------------------------------------

    def _execute(self) -> None:
        if self.prepared is None or self.change_id is not None:
            return
        try:
            change_id, future = self.app.manager.run_change(self.server, self.prepared, self.chosen(),
                                                            service=self.service)
        except ValueError as exc:
            self.status.configure(text=str(exc), text_color=RED)
            return
        self.change_id = change_id
        self._future = future
        self.app.register_change(change_id, self)
        for check in self._checks.values():
            check.configure(state="disabled")
        self.confirm_entry.configure(state="disabled")
        self.run_btn.configure(state="disabled", text="Executando…")
        self.cancel_btn.configure(text="Fechar (continua em segundo plano)")
        self.status.configure(text="Executando os passos no servidor…", text_color=GRAY)
        # Mostra o roteiro (andamento ao vivo) no fim da área rolável.
        self.after(80, lambda: self.body._parent_canvas.yview_moveto(1.0))
        self.app.set_status(f"[{self.server}] {self.action.label} {self.target}: mudança segura em andamento…")

    def on_progress(self, event: ChangeProgressEvent) -> None:
        """Chamado pelo Dashboard (thread da UI) a cada passo."""
        if not self.winfo_exists():
            return
        if event.steps:
            self._render_steps(event.steps)
        if 0 <= event.index < len(self._step_rows):
            icon_label, message, _ = self._step_rows[event.index]
            icon, color = STEP_ICONS.get(event.status, STEP_ICONS["pending"])
            icon_label.configure(text=icon, text_color=color)
            if event.message:
                message.configure(text=event.message, text_color=RED if event.status == "error" else GRAY)
        if event.finished:
            self._finished(event)

    def _finished(self, event: ChangeProgressEvent) -> None:
        records = {r.id: r for r in self.app.manager.change_records(self.server)}
        self.record = records.get(event.record_id)
        text = {"ok": ("Concluído com sucesso.", GREEN), "warning": ("Concluído com avisos.", YELLOW),
                "error": ("A mudança não foi concluída.", RED)}[event.outcome or "error"]
        self.status.configure(text=f"{text[0]} {event.message}", text_color=text[1])
        self.run_btn.pack_forget()
        self.cancel_btn.configure(text="Fechar")
        record = self.record
        if record is None:
            return
        if record.action == "stop" and record.outcome != "error":
            self._after_button("Iniciar novamente", self._start_again)
        if record.action == "remove" and record.definition_dir and record.outcome == "ok":
            self._after_button("Restaurar", lambda: self._restore(False))
            if record.snapshot_image:
                self._after_button("Restaurar do snapshot", lambda: self._restore(True))
        if record.definition_dir and not record.definition_dir.startswith("memória://"):
            self._after_button("Abrir pasta do backup", lambda: open_folder(record.definition_dir))

    def _after_button(self, text: str, command) -> None:
        button = ctk.CTkButton(self.buttons, text=text, width=150, command=command)
        button.pack(side="left", padx=(8, 0))
        self.after_buttons.append(button)

    def _start_again(self) -> None:
        service = self.service
        self.destroy()
        if service is not None:
            self.app.open_change(self.server, ChangeAction.START, service=service)

    def _restore(self, snapshot: bool) -> None:
        record = self.record
        self.destroy()
        if record is not None:
            self.app.open_change(self.server, ChangeAction.RESTORE, record=record, use_snapshot=snapshot)

    def _close(self) -> None:
        self.destroy()


def open_folder(path: str) -> None:
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606 - pasta local criada pelo próprio app
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except OSError:
        log.warning("Não foi possível abrir %s", path, exc_info=True)
