"""Diálogo "Opções do Windows": integrações com a API do Windows e senhas SSH no
Gerenciador de Credenciais (criptografadas pelo Windows, nunca em arquivo)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import customtkinter as ctk

from core import winapi
from ui import theme
from ui.widgets import CARD_BG, GRAY, GREEN, RED, YELLOW, center_on, make_modal

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

log = logging.getLogger(__name__)

SECRET_KINDS = {"Senha SSH": "password", "Passphrase da chave": "passphrase"}


class WindowsOptionsDialog(ctk.CTkToplevel):
    def __init__(self, app: Dashboard) -> None:
        super().__init__(app)
        self.app = app
        self.title("Opções do Windows")
        self.resizable(False, False)
        self.transient(app)
        windows = winapi.IS_WINDOWS
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=18)
        ctk.CTkLabel(body, text="Integrações com o Windows", anchor="w", text_color=theme.ACCENT_TEXT,
                     font=ctk.CTkFont(size=16, weight="bold")).pack(fill="x")
        if not windows:
            ctk.CTkLabel(body, text="Disponíveis apenas no Windows (API Win32).", anchor="w",
                         text_color=YELLOW).pack(fill="x", pady=(4, 0))

        toggles = ctk.CTkFrame(body, corner_radius=12, fg_color=CARD_BG)
        toggles.pack(fill="x", pady=(10, 14))
        self._switches: dict[str, ctk.CTkSwitch] = {}
        options = [
            ("autostart", "Iniciar com o Windows (minimizado na bandeja)", app.autostart_enabled()),
            ("event_log", "Registrar alertas e ações no Visualizador de Eventos", app.windows_pref("event_log")),
            ("flash_taskbar", "Piscar a barra de tarefas em alertas críticos", app.windows_pref("flash_taskbar")),
            ("prevent_sleep", "Impedir a suspensão do PC enquanto monitora", app.windows_pref("prevent_sleep")),
        ]
        for key, label, value in options:
            switch = ctk.CTkSwitch(toggles, text=label, command=lambda k=key: self._toggle(k))
            if value:
                switch.select()
            if not windows:
                switch.configure(state="disabled")
            switch.pack(anchor="w", padx=16, pady=6)
            self._switches[key] = switch
        ctk.CTkLabel(toggles, text="Dica: para mensagens completas no Visualizador de Eventos, registre a origem uma "
                                   "vez (PowerShell como administrador):\nNew-EventLog -LogName Application -Source "
                                   "FirawynixMonitor", anchor="w", justify="left", text_color=GRAY,
                     font=ctk.CTkFont(size=12)).pack(fill="x", padx=16, pady=(2, 10))

        ctk.CTkLabel(body, text="Credenciais SSH (Gerenciador de Credenciais do Windows)", anchor="w",
                     text_color=theme.ACCENT_TEXT, font=ctk.CTkFont(size=14, weight="bold")).pack(fill="x")
        creds = ctk.CTkFrame(body, corner_radius=12, fg_color=CARD_BG)
        creds.pack(fill="x", pady=(8, 10))
        creds.grid_columnconfigure(1, weight=1)
        names = app.manager.server_names
        ctk.CTkLabel(creds, text="Servidor").grid(row=0, column=0, sticky="w", padx=(16, 10), pady=(12, 4))
        self._server = ctk.CTkOptionMenu(creds, values=names, width=220, command=lambda _v: self._refresh_status())
        self._server.set(app.current_server or names[0])
        self._server.grid(row=0, column=1, sticky="w", pady=(12, 4))
        ctk.CTkLabel(creds, text="Tipo").grid(row=1, column=0, sticky="w", padx=(16, 10), pady=4)
        self._kind = ctk.CTkSegmentedButton(creds, values=list(SECRET_KINDS), command=lambda _v: self._refresh_status())
        self._kind.set("Senha SSH")
        self._kind.grid(row=1, column=1, sticky="w", pady=4)
        ctk.CTkLabel(creds, text="Segredo").grid(row=2, column=0, sticky="w", padx=(16, 10), pady=4)
        self._secret = ctk.CTkEntry(creds, show="•", width=300)
        self._secret.grid(row=2, column=1, sticky="w", pady=4)
        ctk.CTkLabel(creds, text="Confirmação").grid(row=3, column=0, sticky="w", padx=(16, 10), pady=4)
        self._confirm = ctk.CTkEntry(creds, show="•", width=300)
        self._confirm.grid(row=3, column=1, sticky="w", pady=4)
        buttons = ctk.CTkFrame(creds, fg_color="transparent")
        buttons.grid(row=4, column=1, sticky="w", pady=(6, 4))
        self._save_btn = ctk.CTkButton(buttons, text="Salvar no Windows", width=150, command=self._save)
        self._save_btn.pack(side="left", padx=(0, 8))
        self._delete_btn = ctk.CTkButton(buttons, text="Remover", width=100, fg_color=theme.NEUTRAL,
                                         hover_color=theme.NEUTRAL_HOVER, text_color=theme.TEXT, command=self._delete)
        self._delete_btn.pack(side="left")
        self._status = ctk.CTkLabel(creds, text="", anchor="w", justify="left", wraplength=460)
        self._status.grid(row=5, column=0, columnspan=2, sticky="ew", padx=16, pady=(4, 12))
        if not windows:
            for widget in (self._secret, self._confirm, self._save_btn, self._delete_btn):
                widget.configure(state="disabled")

        ctk.CTkButton(body, text="Fechar", width=100, fg_color="transparent", border_width=1, text_color=theme.TEXT,
                      command=self.destroy).pack(anchor="e", pady=(6, 0))
        self.bind("<Escape>", lambda _e: self.destroy())
        self._refresh_status()
        center_on(self, app)
        self.after(60, lambda: make_modal(self))
        self.after(250, lambda: theme.style_window(self))

    # -- integrações -----------------------------------------------------------

    def _toggle(self, key: str) -> None:
        enabled = bool(self._switches[key].get())
        if key == "autostart":
            ok = self.app.set_autostart(enabled)
            if not ok:
                (self._switches[key].deselect if enabled else self._switches[key].select)()
            return
        self.app.set_windows_pref(key, enabled)

    # -- credenciais -------------------------------------------------------------

    def _target(self) -> tuple[str, str, bool]:
        """(alvo, tipo, referenciado no servers.json?)"""
        server = self.app.server_config(self._server.get())
        kind = SECRET_KINDS[self._kind.get()]
        configured = server.password_credential if kind == "password" else server.key_passphrase_credential
        return configured or winapi.credential_target(server.name, kind), kind, bool(configured)

    def _refresh_status(self) -> None:
        if not winapi.IS_WINDOWS:
            self._status.configure(text="O Gerenciador de Credenciais só existe no Windows.", text_color=GRAY)
            return
        target, kind, referenced = self._target()
        stored = any(t.lower() == target.lower() for t, _u in winapi.cred_list(""))  # só nomes, nunca segredos
        key = "password_credential" if kind == "password" else "key_passphrase_credential"
        text = f"Credencial \"{target}\": {'salva' if stored else 'não encontrada'}."
        if not referenced:
            text += f"\nPara usar, adicione  \"{key}\": true  a este servidor no servers.json."
        self._status.configure(text=text, text_color=GREEN if stored and referenced else GRAY)

    def _save(self) -> None:
        secret, confirm = self._secret.get(), self._confirm.get()
        if not secret:
            self._status.configure(text="Digite o segredo.", text_color=YELLOW)
            return
        if secret != confirm:
            self._status.configure(text="A confirmação não confere.", text_color=RED)
            return
        target, _kind, _referenced = self._target()
        server = self.app.server_config(self._server.get())
        try:
            winapi.cred_write(target, secret, server.username)
        except winapi.CredentialError as exc:
            self._status.configure(text=str(exc), text_color=RED)
            return
        finally:
            self._secret.delete(0, "end")
            self._confirm.delete(0, "end")
        log.info("Credencial %s gravada no Gerenciador de Credenciais", target)
        self.app.log_windows_event(f"Credencial {target} atualizada no Gerenciador de Credenciais.", "info", "app")
        self._refresh_status()
        self.app.set_status(f"Credencial salva no Windows. Reconectando {server.name}…")
        self.app.manager.reconnect(server.name)

    def _delete(self) -> None:
        target, _kind, _referenced = self._target()
        removed = winapi.cred_delete(target)
        self._refresh_status()
        self.app.set_status(f"Credencial {target} {'removida' if removed else 'não encontrada'}.")
