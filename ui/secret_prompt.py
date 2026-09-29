"""Pede a senha (ou a passphrase da chave) quando o servidor está configurado com
"pedir ao conectar". O valor fica só na memória desta sessão — nunca em disco —
a menos que o usuário peça para gravá-lo no Gerenciador de Credenciais do Windows."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from config.settings import set_session_secret
from core import winapi
from ui import theme
from ui.widgets import GRAY, RED, TEXT, center_on, make_modal

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

KIND_LABELS = {"password": "Senha", "passphrase": "Passphrase da chave SSH"}


class SecretPromptDialog(ctk.CTkToplevel):
    def __init__(self, app: Dashboard, server: str, target: str, kind: str, message: str = "", *,
                 master=None, reconnect: bool = True) -> None:
        super().__init__(master or app)
        self.app = app
        self.server = server
        self.target = target or server
        self.kind = kind
        self.reconnect = reconnect
        self.submitted = False
        label = KIND_LABELS.get(kind, "Senha")
        self.title(f"{label} — {self.target}")
        self.resizable(False, False)
        self.transient(master or app)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=18)
        ctk.CTkLabel(body, text=f"{label} para {self.target}", anchor="w", text_color=theme.ACCENT_TEXT,
                     font=ctk.CTkFont(size=16, weight="bold")).pack(fill="x")
        ctk.CTkLabel(body, text=message or "Este servidor está configurado para pedir o segredo ao conectar.",
                     anchor="w", justify="left", wraplength=420, text_color=GRAY).pack(fill="x", pady=(4, 10))
        self.entry = ctk.CTkEntry(body, show="•", width=420)
        self.entry.pack(fill="x")
        self.remember = ctk.CTkCheckBox(body, text="Gravar no Gerenciador de Credenciais do Windows "
                                                   "(senão, só vale até fechar o painel)")
        self.remember.pack(anchor="w", pady=(10, 0))
        if not winapi.IS_WINDOWS:
            self.remember.configure(state="disabled")
        self.error = ctk.CTkLabel(body, text="", text_color=RED, anchor="w")
        self.error.pack(fill="x", pady=(6, 0))
        buttons = ctk.CTkFrame(body, fg_color="transparent")
        buttons.pack(fill="x", pady=(8, 0))
        ctk.CTkButton(buttons, text="Conectar", width=120, command=self._submit).pack(side="right")
        ctk.CTkButton(buttons, text="Agora não", width=100, fg_color="transparent", border_width=1,
                      text_color=TEXT, command=self.destroy).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda _e: self._submit())
        self.bind("<Escape>", lambda _e: self.destroy())
        center_on(self, master or app)
        self.after(60, lambda: (make_modal(self), self.entry.focus_set()))
        self.after(250, lambda: theme.style_window(self))

    def _submit(self) -> None:
        value = self.entry.get()
        if not value:
            self.error.configure(text="Digite o segredo.")
            return
        set_session_secret(self.target, self.kind, value)
        if self.remember.get() and winapi.IS_WINDOWS:
            try:
                winapi.cred_write(winapi.credential_target(self.target, self.kind), value)
                self.app.set_status("Segredo gravado no Gerenciador de Credenciais. Para usá-lo sempre, escolha "
                                    "\"Gerenciador de Credenciais\" em Servidores e conexões.")
            except winapi.CredentialError as exc:
                self.error.configure(text=str(exc))
                return
        self.entry.delete(0, "end")
        self.submitted = True
        self.destroy()
        if self.reconnect:
            self.app.manager.reconnect(self.server)
            self.app.set_status(f"Conectando a {self.server}…")
