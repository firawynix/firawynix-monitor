"""Diálogo "Motores de contêiner": auto-detecção (padrão) ou escolha manual de
quais motores o painel usa em cada servidor — Docker, Podman, containerd,
CRI-O, LXD/Incus, Buildah e Skopeo.

A escolha fica em ``preferences.json`` (``engines.<servidor>``) e vale na hora,
sem reiniciar. Qualquer que seja o motor, a aba "Contêineres" mantém o mesmo
layout; painéis de terceiros (Portainer, Cockpit...) são só detectados.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core import containers as engines
from core.models import EngineStatus, RuntimeState
from ui import theme
from ui.widgets import CARD_BG, GRAY, GREEN, RED, YELLOW, center_on, make_modal

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

AUTO = "Auto-detectar (recomendado)"
MANUAL = "Escolher manualmente"
_REFRESH_MS = 1000


def detection_text(status: EngineStatus | None) -> tuple[str, tuple[str, str]]:
    """O que a auto-detecção encontrou para um motor (coluna "Neste servidor")."""
    if status is None or status.installed is None:
        return "aguardando detecção", GRAY
    if not status.installed:
        return "não encontrado", GRAY
    parts = ["detectado"]
    if status.version:
        parts.append(f"v{status.version}")
    if status.rootless:
        parts.append("rootless")
    color = GREEN
    problems = {RuntimeState.DAEMON_DOWN: ("daemon parado", RED), RuntimeState.PERMISSION: ("sem permissão", YELLOW),
                RuntimeState.ERROR: ("erro ao consultar", RED)}
    if status.state in problems:
        text, color = problems[status.state]
        parts.append(text)
    if status.mode == "off":
        parts.append("desativado")
        color = GRAY
    return " · ".join(parts), color


def build_selection(auto: bool, checked: list[str]) -> dict:
    """Auto: marcado = pode ser usado se detectado (desmarcado = ignorar).
    Manual: marcado = usar sempre (avisa se faltar), desmarcado = não usar."""
    if auto:
        disabled = [e for e in engines.ENGINE_ORDER if e not in checked]
        return {"mode": "auto", "disabled": disabled} if disabled else {"mode": "auto"}
    return {"mode": "manual", "enabled": [e for e in engines.ENGINE_ORDER if e in checked]}


class EnginesDialog(ctk.CTkToplevel):
    def __init__(self, app: Dashboard, server: str | None = None) -> None:
        super().__init__(app)
        self.app = app
        self.title("Motores de contêiner")
        self.resizable(False, False)
        self.transient(app)
        names = app.manager.server_names
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=18)
        ctk.CTkLabel(body, text="Motores de contêiner", anchor="w", text_color=theme.ACCENT_TEXT,
                     font=ctk.CTkFont(size=16, weight="bold")).pack(fill="x")
        ctk.CTkLabel(body, text="O painel é o mesmo para qualquer motor. Deixe a auto-detecção descobrir o que existe "
                                "no servidor ou marque os motores que você usa (ex.: trocar Docker por Podman).",
                     anchor="w", justify="left", wraplength=640, text_color=GRAY).pack(fill="x", pady=(2, 10))

        top = ctk.CTkFrame(body, fg_color="transparent")
        top.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(top, text="Servidor").pack(side="left", padx=(0, 8))
        self._server = ctk.CTkOptionMenu(top, values=names, width=220, command=lambda _v: self._load())
        self._server.set(server if server in names else (app.current_server or names[0]))
        self._server.pack(side="left", padx=(0, 16))
        self._mode = ctk.CTkSegmentedButton(top, values=[AUTO, MANUAL], command=lambda _v: self._mode_changed())
        self._mode.pack(side="left")

        table = ctk.CTkFrame(body, corner_radius=12, fg_color=CARD_BG)
        table.pack(fill="x")
        table.grid_columnconfigure(1, weight=1)
        for column, title in enumerate(("Motor / ferramenta", "Função", "Neste servidor")):
            ctk.CTkLabel(table, text=title.upper(), text_color=GRAY, anchor="w",
                         font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=column, sticky="w",
                                                                       padx=(16, 10), pady=(10, 4))
        self._checks: dict[str, ctk.CTkCheckBox] = {}
        self._status: dict[str, ctk.CTkLabel] = {}
        for row, engine_id in enumerate(engines.ENGINE_ORDER, 1):
            spec = engines.ENGINES[engine_id]
            check = ctk.CTkCheckBox(table, text=spec.label, width=230)
            check.grid(row=row, column=0, sticky="w", padx=(16, 10), pady=4)
            ctk.CTkLabel(table, text=spec.description, anchor="w", text_color=GRAY, wraplength=300,
                         justify="left").grid(row=row, column=1, sticky="w", padx=(0, 10), pady=4)
            status = ctk.CTkLabel(table, text="", anchor="w", width=210)
            status.grid(row=row, column=2, sticky="w", padx=(0, 16), pady=4)
            self._checks[engine_id] = check
            self._status[engine_id] = status
        ctk.CTkFrame(table, height=6, fg_color="transparent").grid(row=len(engines.ENGINE_ORDER) + 1, column=0)

        self._hint = ctk.CTkLabel(body, text="", anchor="w", justify="left", wraplength=640,
                                  text_color=theme.ACCENT_TEXT)
        self._hint.pack(fill="x", pady=(8, 0))
        self._note = ctk.CTkLabel(body, text="", anchor="w", justify="left", wraplength=640, text_color=GRAY)
        self._note.pack(fill="x", pady=(10, 6))
        ctk.CTkLabel(body, text="Portainer, Cockpit, Dockge e similares não mudam este painel: quando encontrados, "
                                "aparecem na aba Contêineres com um botão para abrir no navegador.",
                     anchor="w", justify="left", wraplength=640, text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=12)).pack(fill="x")

        footer = ctk.CTkFrame(body, fg_color="transparent")
        footer.pack(fill="x", pady=(14, 0))
        self._message = ctk.CTkLabel(footer, text="", anchor="w", text_color=GRAY)
        self._message.pack(side="left")
        ctk.CTkButton(footer, text="Aplicar", width=110, command=self._apply).pack(side="right")
        ctk.CTkButton(footer, text="Cancelar", width=100, fg_color="transparent", border_width=1,
                      text_color=theme.TEXT, command=self.destroy).pack(side="right", padx=(0, 8))
        ctk.CTkButton(footer, text="Detectar agora", width=130, fg_color=theme.NEUTRAL,
                      hover_color=theme.NEUTRAL_HOVER, text_color=theme.TEXT,
                      command=self._detect).pack(side="right", padx=(0, 8))

        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Return>", lambda _e: self._apply())
        self._load()
        center_on(self, app)
        self.after(60, lambda: make_modal(self))
        self.after(250, lambda: theme.style_window(self))
        self.after(_REFRESH_MS, self._tick)

    # -- estado ------------------------------------------------------------------

    @property
    def server(self) -> str:
        return self._server.get()

    def _statuses(self) -> dict[str, EngineStatus]:
        snapshot = self.app.snapshot(self.server)
        inventory = snapshot.containers if snapshot else None
        return {e.id: e for e in inventory.engines} if inventory else {}

    def _load(self) -> None:
        config = self.app.server_config(self.server)
        selection = engines.modes_to_selection(config)
        auto = selection["mode"] == "auto"
        self._mode.set(AUTO if auto else MANUAL)
        self._loaded_auto = auto
        checked = (set(engines.ENGINE_ORDER) - set(selection.get("disabled", ())) if auto
                   else set(selection.get("enabled", ())))
        for engine_id, check in self._checks.items():
            (check.select if engine_id in checked else check.deselect)()
        admin = "ativadas" if config.container_admin else "desativadas"
        self._note.configure(text=f"Remover contêineres, imagens e volumes pelo painel: {admin} "
                                  f"(\"container_admin\" no servers.json). Comandos com sudo usam sempre sudo -n "
                                  "(NOPASSWD restrito, veja docs/sudoers.example).")
        self._message.configure(text="")
        self._mode_changed()

    def _mode_changed(self) -> None:
        auto = self._mode.get() == AUTO
        if auto != self._loaded_auto:
            # Troca de modo: parte do que faz sentido — tudo (auto) ou o que foi detectado (manual).
            statuses = self._statuses()
            for engine_id, check in self._checks.items():
                status = statuses.get(engine_id)
                keep = auto or (status is not None and bool(status.installed))
                (check.select if keep else check.deselect)()
            self._loaded_auto = auto
        self._hint.configure(text=(
            "Auto-detecção: os motores marcados são usados quando encontrados no servidor; desmarque para "
            "ignorar um motor mesmo que esteja instalado." if auto else
            "Manual: os motores marcados são sempre consultados (com aviso se faltarem); os demais são "
            "ignorados."))
        self._refresh_status()

    def _refresh_status(self) -> None:
        statuses = self._statuses()
        for engine_id, label in self._status.items():
            text, color = detection_text(statuses.get(engine_id))
            label.configure(text=text, text_color=color)

    def _tick(self) -> None:
        try:
            if not self.winfo_exists():
                return
        except Exception:  # noqa: BLE001
            return
        self._refresh_status()
        self.after(_REFRESH_MS, self._tick)

    # -- ações ---------------------------------------------------------------------

    def _detect(self) -> None:
        self.app.manager.refresh(self.server, full=True)
        self._message.configure(text="Detectando… o resultado aparece em alguns segundos.", text_color=GRAY)

    def _apply(self) -> None:
        auto = self._mode.get() == AUTO
        checked = [engine_id for engine_id, check in self._checks.items() if check.get()]
        if not checked:
            self._message.configure(text="Marque ao menos um motor.", text_color=YELLOW)
            return
        self.app.apply_engine_selection(self.server, build_selection(auto, checked))
        self.destroy()
