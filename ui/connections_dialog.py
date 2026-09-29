"""Diálogo "Servidores e conexões": adicionar, editar e remover servidores com
todas as formas de acesso — chave SSH, chave + passphrase, usuário e senha,
chave + senha (2 fatores) ou agente — e o caminho até o servidor: direto, VPN,
Cloudflare Tunnel, host de salto, proxy SOCKS5/HTTP ou comando.

"Testar conexão" conecta de verdade (sem gravar nada); "Salvar" valida o
servers.json inteiro, guarda a versão anterior (.bak) e aplica na hora.
Segredos vão para o Gerenciador de Credenciais do Windows (ou são pedidos ao
conectar) — nunca para o arquivo."""

from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from tkinter import filedialog
from typing import TYPE_CHECKING

import customtkinter as ctk

from config import editor
from config.settings import (
    AUTH_LABELS,
    AUTH_MODES,
    CONNECTOR_LABELS,
    CONNECTOR_TYPES,
    ConfigError,
    get_session_secret,
    parse_config,
    user_data_dir,
)
from core import winapi
from ui import theme
from ui.widgets import CARD_BG, GRAY, GREEN, RED, TEXT, YELLOW, ConfirmDialog, center_on, make_modal

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

log = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="conn-test")
NEW = "+ Novo servidor"
_AUTH_BY_LABEL = {AUTH_LABELS[m]: m for m in AUTH_MODES}
_CONNECTOR_BY_LABEL = {CONNECTOR_LABELS[c]: c for c in CONNECTOR_TYPES}
_SOURCE_BY_LABEL = {v: k for k, v in editor.SECRET_SOURCE_LABELS.items()}
_TOKEN_SOURCES = {"Login no navegador (cloudflared access login)": "none",
                  "Token de serviço no Gerenciador de Credenciais": "credential",
                  "Token de serviço em variáveis de ambiente": "env"}


def test_connection(server, settings) -> str:
    """Conecta, roda um comando curto e desconecta (usado pelo botão "Testar conexão")."""
    from core.ssh_client import SSHClient

    client = SSHClient(server, command_timeout=settings.command_timeout_seconds,
                       connect_timeout=settings.connect_timeout_seconds,
                       known_hosts_file=settings.known_hosts_file or user_data_dir() / "known_hosts")
    started = time.monotonic()
    try:
        client.connect()
        output = client.run("echo \"$(whoami)@$(hostname) · $(uname -srm)\"").stdout.strip()
    finally:
        client.close()
    via = server.connector.label(server.host)
    return f"{output} · {server.auth_label} · caminho: {via} · {time.monotonic() - started:.1f} s"


class ConnectionsDialog(ctk.CTkToplevel):
    POLL_MS = 150

    def __init__(self, app: Dashboard, server: str | None = None) -> None:
        super().__init__(app)
        self.app = app
        self.source: Path | None = app.config_source
        self.raw = editor.load_raw(self.source) if self.source and self.source.is_file() else {
            "servers": [editor.build_entry(_form_from_config(s)) for s in app.config_servers()]}
        self._editing: str | None = None
        self._future: Future | None = None
        self.title("Servidores e conexões")
        self.geometry("1080x760")
        self.minsize(960, 640)
        self.transient(app)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        side = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG, width=230)
        side.grid(row=0, column=0, sticky="nsw", padx=(16, 8), pady=16)
        side.grid_propagate(False)
        ctk.CTkLabel(side, text="SERVIDORES", text_color=GRAY, anchor="w",
                     font=ctk.CTkFont(size=11, weight="bold")).pack(fill="x", padx=14, pady=(12, 6))
        self.server_list = ctk.CTkScrollableFrame(side, fg_color="transparent")
        self.server_list.pack(fill="both", expand=True, padx=6)
        self.remove_btn = ctk.CTkButton(side, text="Remover servidor", fg_color="transparent", border_width=1,
                                        text_color=RED, command=self._remove)
        self.remove_btn.pack(fill="x", padx=14, pady=(6, 14))

        self.form = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.form.grid(row=0, column=1, sticky="nsew", padx=(8, 16), pady=(16, 0))
        self.form.grid_columnconfigure(1, weight=1)
        self._build_form()

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=12)
        footer.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(footer, text="", anchor="w", justify="left", wraplength=620)
        self.status.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(footer, text="Fechar", width=90, fg_color="transparent", border_width=1, text_color=TEXT,
                      command=self.destroy).grid(row=0, column=1, padx=(8, 0))
        self.test_btn = ctk.CTkButton(footer, text="Testar conexão", width=140, fg_color=theme.NEUTRAL,
                                      hover_color=theme.NEUTRAL_HOVER, text_color=theme.TEXT, command=self._test)
        self.test_btn.grid(row=0, column=2, padx=(8, 0))
        self.save_btn = ctk.CTkButton(footer, text="Salvar e aplicar", width=150, command=self._save)
        self.save_btn.grid(row=0, column=3, padx=(8, 0))
        if self.source is None:
            self.save_btn.configure(state="disabled")
            self.status.configure(text="Modo demonstração: dá para ver e testar, mas nada é gravado.", text_color=GRAY)

        self._refresh_list()
        names = [s.get("name") for s in self.raw.get("servers", []) if isinstance(s, dict)]
        self._load(server if server in names else (names[0] if names else None))
        self.bind("<Escape>", lambda _e: self.destroy())
        center_on(self, app)
        self.after(60, lambda: make_modal(self))
        self.after(250, lambda: theme.style_window(self))

    # -- construção do formulário ------------------------------------------------

    def _section(self, row: int, title: str, hint: str = "") -> int:
        ctk.CTkLabel(self.form, text=title, anchor="w", text_color=theme.ACCENT_TEXT,
                     font=ctk.CTkFont(size=14, weight="bold")).grid(row=row, column=0, columnspan=2, sticky="w",
                                                                     pady=(14, 2))
        if hint:
            ctk.CTkLabel(self.form, text=hint, anchor="w", justify="left", wraplength=720, text_color=GRAY,
                         font=ctk.CTkFont(size=12)).grid(row=row + 1, column=0, columnspan=2, sticky="w")
            return row + 2
        return row + 1

    def _row(self, row: int, label: str, widget) -> tuple[int, ctk.CTkLabel]:
        caption = ctk.CTkLabel(self.form, text=label, anchor="w")
        caption.grid(row=row, column=0, sticky="w", padx=(4, 12), pady=3)
        widget.grid(row=row, column=1, sticky="w", pady=3)
        return row + 1, caption

    def _build_form(self) -> None:
        f = self.form
        self.w: dict[str, object] = {}
        row = self._section(0, "Servidor")
        for key, label, width, placeholder in (("name", "Nome", 260, "prod-web-01"),
                                               ("host", "Host", 360, "IP, nome ou hostname do Cloudflare Access"),
                                               ("port", "Porta SSH", 90, "22"), ("username", "Usuário", 200,
                                                                                 "monitor")):
            self.w[key] = ctk.CTkEntry(f, width=width, placeholder_text=placeholder)
            row, _ = self._row(row, label, self.w[key])
        host_key = ctk.CTkFrame(f, fg_color="transparent")
        self.w["host_key_policy"] = ctk.CTkOptionMenu(host_key, values=["accept-new", "strict"], width=160)
        self.w["host_key_policy"].pack(side="left")
        ctk.CTkLabel(host_key, text="accept-new: confia na 1ª conexão; chave diferente depois é sempre recusada",
                     text_color=GRAY, font=ctk.CTkFont(size=12)).pack(side="left", padx=(10, 0))
        row, _ = self._row(row, "Chave do host", host_key)

        row = self._section(row, "Autenticação", "Todas as opções: chave SSH, chave com passphrase, usuário e "
                                                  "senha, chave + senha (servidor com 2 fatores) ou agente SSH. "
                                                  "Segredos ficam no Gerenciador de Credenciais do Windows ou são "
                                                  "pedidos ao conectar — nunca no servers.json.")
        self.w["auth"] = ctk.CTkOptionMenu(f, values=list(_AUTH_BY_LABEL), width=300,
                                           command=lambda _v: self._update_visibility())
        row, _ = self._row(row, "Modo", self.w["auth"])
        key_box = ctk.CTkFrame(f, fg_color="transparent")
        self.w["key_file"] = ctk.CTkEntry(key_box, width=360, placeholder_text="~/.ssh/id_ed25519 (vazio = chaves "
                                                                                "padrão)")
        self.w["key_file"].pack(side="left")
        ctk.CTkButton(key_box, text="Procurar…", width=90, fg_color=theme.NEUTRAL, hover_color=theme.NEUTRAL_HOVER,
                      text_color=theme.TEXT, command=self._browse_key).pack(side="left", padx=(6, 0))
        row, self._key_caption = self._row(row, "Chave privada", key_box)
        self._key_row = key_box
        row = self._secret_rows(row, "passphrase", "Passphrase da chave")
        row = self._secret_rows(row, "password", "Senha do usuário")

        row = self._section(row, "Conector (caminho até o servidor)",
                            "O painel roda neste PC e chega ao servidor direto, por VPN, pelo Cloudflare Tunnel "
                            "(cloudflared access ssh), por um host de salto, por proxy ou por um comando.")
        self.w["connector"] = ctk.CTkOptionMenu(f, values=list(_CONNECTOR_BY_LABEL), width=320,
                                                command=lambda _v: self._update_visibility())
        row, _ = self._row(row, "Tipo", self.w["connector"])
        self.connector_frame = ctk.CTkFrame(f, corner_radius=10, fg_color=CARD_BG)
        self.connector_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.connector_frame.grid_columnconfigure(1, weight=1)
        self._build_connector_fields()
        self.result = ctk.CTkLabel(f, text="", anchor="w", justify="left", wraplength=720)
        self.result.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.cf_login_btn = ctk.CTkButton(f, text="Entrar no Cloudflare Access (abre o navegador)", width=320,
                                          command=self._cloudflare_login)

    def _secret_rows(self, row: int, kind: str, label: str) -> int:
        f = self.form
        box = ctk.CTkFrame(f, fg_color="transparent")
        source = ctk.CTkOptionMenu(box, values=list(_SOURCE_BY_LABEL), width=300,
                                   command=lambda _v, k=kind: self._update_visibility())
        source.pack(side="left")
        env = ctk.CTkEntry(box, width=170, placeholder_text="NOME_DA_VARIAVEL")
        store = ctk.CTkFrame(box, fg_color="transparent")
        secret = ctk.CTkEntry(store, width=150, show="•", placeholder_text="digite para gravar")
        secret.pack(side="left", padx=(6, 0))
        save = ctk.CTkButton(store, text="Gravar no Windows", width=140, command=lambda k=kind: self._store(k))
        save.pack(side="left", padx=(6, 0))
        if not winapi.IS_WINDOWS:
            secret.configure(state="disabled")
            save.configure(state="disabled")
        self.w[f"{kind}_source"], self.w[f"{kind}_env"], self.w[f"{kind}_secret"] = source, env, secret
        self.w[f"{kind}_store"] = store
        row, caption = self._row(row, label, box)
        self.w[f"{kind}_box"], self.w[f"{kind}_caption"] = box, caption
        return row

    def _build_connector_fields(self) -> None:
        c = self.connector_frame
        self.cw: dict[str, object] = {}
        specs = {
            "vpn": [("name", "Nome da VPN", 260, "WireGuard escritório / Tailscale"),
                    ("check", "Testar antes", 200, "10.8.0.1:22 (vazio = o próprio host)"),
                    ("up_command", "Comando que liga", 0, "um argumento por linha (opcional)")],
            "cloudflared": [("hostname", "Hostname do Access", 300, "ssh.exemplo.com (vazio = o host)"),
                            ("cloudflared_path", "cloudflared.exe", 360, "vazio = procurar no PATH / Arquivos de "
                                                                          "Programas"),
                            ("token_source", "Autenticação", 0, ""),
                            ("token_id_env", "Variável do ID", 220, "CF_ACCESS_CLIENT_ID"),
                            ("token_secret_env", "Variável do segredo", 220, "CF_ACCESS_CLIENT_SECRET"),
                            ("token_store", "Gravar token", 0, "")],
            "jump": [("host", "Host de salto", 300, "bastion.exemplo.com"), ("port", "Porta", 90, "22"),
                     ("username", "Usuário", 200, "vazio = o mesmo do servidor"), ("auth", "Autenticação", 0, ""),
                     ("key_file", "Chave privada", 360, "~/.ssh/id_ed25519"),
                     ("password_source", "Senha do salto", 0, ""), ("password_env", "Variável da senha", 220, "")],
            "socks5": [("host", "Proxy", 260, "127.0.0.1"), ("port", "Porta", 90, "1080"),
                       ("username", "Usuário (opcional)", 200, ""), ("password_source", "Senha do proxy", 0, ""),
                       ("password_env", "Variável da senha", 220, "")],
            "command": [("command", "Comando", 0, "um argumento por linha; %h host, %p porta, %r usuário")],
        }
        specs["http"] = [(k, label, w, p.replace("1080", "3128")) for k, label, w, p in specs["socks5"]]
        self._connector_specs = specs
        self._cw_captions: dict[tuple[str, str], ctk.CTkLabel] = {}
        for kind, fields in specs.items():
            frame = ctk.CTkFrame(c, fg_color="transparent")
            frame.grid_columnconfigure(1, weight=1)
            widgets = {}
            for index, (key, label, width, placeholder) in enumerate(fields):
                caption = ctk.CTkLabel(frame, text=label, anchor="w")
                caption.grid(row=index, column=0, sticky="nw", padx=(12, 12), pady=3)
                self._cw_captions[(kind, key)] = caption
                if key in ("up_command", "command"):
                    widget = ctk.CTkTextbox(frame, width=460, height=70)
                elif key == "token_source":
                    widget = ctk.CTkOptionMenu(frame, values=list(_TOKEN_SOURCES), width=380,
                                               command=lambda _v: self._update_visibility())
                elif key == "auth":
                    widget = ctk.CTkOptionMenu(frame, values=list(_AUTH_BY_LABEL), width=300)
                elif key == "password_source":
                    widget = ctk.CTkOptionMenu(frame, values=[v for k, v in editor.SECRET_SOURCE_LABELS.items()
                                                              if kind == "jump" or k != "prompt"], width=300,
                                               command=lambda _v: self._update_visibility())
                elif key == "token_store":
                    widget = ctk.CTkFrame(frame, fg_color="transparent")
                    token_id = ctk.CTkEntry(widget, width=200, placeholder_text="Client ID")
                    token_id.pack(side="left")
                    token_secret = ctk.CTkEntry(widget, width=200, show="•", placeholder_text="Client Secret")
                    token_secret.pack(side="left", padx=(6, 0))
                    ctk.CTkButton(widget, text="Gravar no Windows", width=140,
                                  command=self._store_token).pack(side="left", padx=(6, 0))
                    widgets["token_id"], widgets["token_secret"] = token_id, token_secret
                else:
                    widget = ctk.CTkEntry(frame, width=width, placeholder_text=placeholder)
                widget.grid(row=index, column=1, sticky="w", pady=3)
                widgets[key] = widget
            self.cw[kind] = (frame, widgets)

    # -- lista de servidores --------------------------------------------------------

    def _refresh_list(self) -> None:
        for child in self.server_list.winfo_children():
            child.destroy()
        names = [s.get("name", "?") for s in self.raw.get("servers", []) if isinstance(s, dict)]
        for name in [*names, NEW]:
            selected = name == (self._editing or NEW)
            ctk.CTkButton(self.server_list, text=name, anchor="w", height=30,
                          fg_color=theme.ACCENT if selected else "transparent",
                          text_color="#ffffff" if selected else theme.TEXT, hover_color=theme.PANEL_HOVER,
                          command=lambda n=name: self._load(None if n == NEW else n)).pack(fill="x", pady=1)

    def _load(self, name: str | None) -> None:
        self._editing = name
        entry = editor.find_entry(self.raw, name) if name else None
        form = entry or {}
        for key in ("name", "host", "username"):
            _set_entry(self.w[key], str(form.get(key, "")))
        _set_entry(self.w["port"], str(form.get("port", 22)) if entry else "")
        _set_entry(self.w["key_file"], str(form.get("key_file", "")))
        self.w["host_key_policy"].set(form.get("host_key_policy", "accept-new"))
        self.w["auth"].set(AUTH_LABELS.get(form.get("auth", "auto"), AUTH_LABELS["auto"]))
        for kind, prefix in (("password", "password"), ("passphrase", "key_passphrase")):
            source, env = editor.secret_source(form, prefix)
            self.w[f"{kind}_source"].set(editor.SECRET_SOURCE_LABELS[source])
            _set_entry(self.w[f"{kind}_env"], env)
            _set_entry(self.w[f"{kind}_secret"], "")
        connector = form.get("connector") or {}
        if isinstance(connector, str):
            connector = {"type": connector}
        kind = connector.get("type", "direct")
        self.w["connector"].set(CONNECTOR_LABELS.get(kind, CONNECTOR_LABELS["direct"]))
        for ckind, (_frame, widgets) in self.cw.items():
            data = connector if ckind == kind else {}
            for key, widget in widgets.items():
                if isinstance(widget, ctk.CTkTextbox):
                    widget.delete("1.0", "end")
                    values = data.get(key) or []
                    widget.insert("1.0", "\n".join(values) if isinstance(values, list) else str(values))
                elif isinstance(widget, ctk.CTkEntry):
                    _set_entry(widget, "" if key in ("token_id", "token_secret") else str(data.get(key, "")))
                elif isinstance(widget, ctk.CTkOptionMenu):
                    if key == "auth":
                        widget.set(AUTH_LABELS.get(data.get("auth", "auto"), AUTH_LABELS["auto"]))
                    elif key == "token_source":
                        source = "credential" if data.get("service_token_credential") else \
                            "env" if data.get("service_token_id_env") else "none"
                        widget.set(next(k for k, v in _TOKEN_SOURCES.items() if v == source))
                    elif key == "password_source":
                        source, _env = editor.secret_source(data, "password")
                        widget.set(editor.SECRET_SOURCE_LABELS[source])
        if kind == "cloudflared":
            widgets = self.cw["cloudflared"][1]
            _set_entry(widgets["token_id_env"], connector.get("service_token_id_env", ""))
            _set_entry(widgets["token_secret_env"], connector.get("service_token_secret_env", ""))
        if kind in ("jump", "socks5", "http"):
            _set_entry(self.cw[kind][1]["password_env"], connector.get("password_env", ""))
        self.remove_btn.configure(state="normal" if name and self.source else "disabled")
        self.result.configure(text="")
        self.cf_login_btn.grid_forget()
        self._refresh_list()
        self._update_visibility()

    def _update_visibility(self) -> None:
        auth = _AUTH_BY_LABEL[self.w["auth"].get()]
        uses_key = auth in ("auto", "key", "key+password")
        uses_password = auth in ("auto", "password", "key+password")
        for widget, show in ((self._key_row, uses_key), (self._key_caption, uses_key),
                             (self.w["passphrase_box"], uses_key), (self.w["passphrase_caption"], uses_key),
                             (self.w["password_box"], uses_password), (self.w["password_caption"], uses_password)):
            (widget.grid if show else widget.grid_remove)()
        for kind in ("password", "passphrase"):
            source = _SOURCE_BY_LABEL[self.w[f"{kind}_source"].get()]
            env, store = self.w[f"{kind}_env"], self.w[f"{kind}_store"]
            env.pack_forget()
            store.pack_forget()
            if source == "env":
                env.pack(side="left", padx=(6, 0))
            elif source == "credential":
                store.pack(side="left")
        kind = _CONNECTOR_BY_LABEL[self.w["connector"].get()]
        for ckind, (frame, _widgets) in self.cw.items():
            if ckind == kind:
                frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=8)
            else:
                frame.grid_forget()
        if kind == "direct":
            self.connector_frame.grid_remove()
        else:
            self.connector_frame.grid()
        if kind == "cloudflared":
            widgets = self.cw["cloudflared"][1]
            token = _TOKEN_SOURCES[widgets["token_source"].get()]
            for key, show in (("token_id_env", token == "env"), ("token_secret_env", token == "env"),
                              ("token_store", token == "credential")):
                for widget in (widgets[key], self._cw_captions[("cloudflared", key)]):
                    (widget.grid if show else widget.grid_remove)()
        if kind in ("jump", "socks5", "http"):
            widgets = self.cw[kind][1]
            show = _SOURCE_BY_LABEL.get(widgets["password_source"].get()) == "env"
            for widget in (widgets["password_env"], self._cw_captions[(kind, "password_env")]):
                (widget.grid if show else widget.grid_remove)()

    # -- leitura do formulário ------------------------------------------------------

    def _form(self) -> dict:
        form = {key: self.w[key].get() for key in ("name", "host", "port", "username", "key_file",
                                                   "host_key_policy")}
        form["auth"] = _AUTH_BY_LABEL[self.w["auth"].get()]
        for kind in ("password", "passphrase"):
            form[f"{kind}_source"] = _SOURCE_BY_LABEL[self.w[f"{kind}_source"].get()]
            form[f"{kind}_env"] = self.w[f"{kind}_env"].get()
        if form["auth"] in ("key", "agent"):
            form["password_source"] = "none"
        if form["auth"] in ("password", "agent"):
            form["passphrase_source"], form["key_file"] = "none", ""
        kind = _CONNECTOR_BY_LABEL[self.w["connector"].get()]
        connector: dict = {"type": kind}
        if kind in self.cw:
            for key, widget in self.cw[kind][1].items():
                if isinstance(widget, ctk.CTkTextbox):
                    connector[key] = [line.strip() for line in widget.get("1.0", "end").splitlines()]
                elif isinstance(widget, ctk.CTkEntry) and key not in ("token_id", "token_secret"):
                    connector[key] = widget.get()
                elif isinstance(widget, ctk.CTkOptionMenu):
                    value = widget.get()
                    connector[key] = (_AUTH_BY_LABEL.get(value) if key == "auth" else _TOKEN_SOURCES.get(value)
                                      if key == "token_source" else _SOURCE_BY_LABEL.get(value))
        form["connector"] = connector
        return form

    def _entry(self) -> dict:
        existing = editor.find_entry(self.raw, self._editing) if self._editing else None
        return editor.build_entry(self._form(), existing)

    def _server_config(self, entry: dict):
        """ServerConfig só deste servidor (valida os campos de conexão)."""
        base = self.source.parent if self.source else None
        return parse_config({"servers": [entry]}, base_dir=base).servers[0]

    # -- ações -------------------------------------------------------------------------

    def _browse_key(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Chave privada SSH",
                                          initialdir=str(Path.home() / ".ssh"))
        if path:
            _set_entry(self.w["key_file"], path)

    def _store(self, kind: str) -> None:
        name = self.w["name"].get().strip()
        secret = self.w[f"{kind}_secret"].get()
        if not name or not secret:
            self._say("Preencha o nome do servidor e o segredo antes de gravar.", YELLOW)
            return
        try:
            winapi.cred_write(winapi.credential_target(name, kind), secret, self.w["username"].get().strip())
        except winapi.CredentialError as exc:
            self._say(str(exc), RED)
            return
        _set_entry(self.w[f"{kind}_secret"], "")
        self._say(f"Gravado no Gerenciador de Credenciais: {winapi.credential_target(name, kind)}", GREEN)

    def _store_token(self) -> None:
        name = self.w["name"].get().strip()
        widgets = self.cw["cloudflared"][1]
        token_id, token_secret = widgets["token_id"].get().strip(), widgets["token_secret"].get()
        if not name or not token_id or not token_secret:
            self._say("Informe o nome do servidor, o Client ID e o Client Secret do token de serviço.", YELLOW)
            return
        target = winapi.credential_target(name, "cloudflared")
        try:
            winapi.cred_write(target, token_secret, token_id)
        except winapi.CredentialError as exc:
            self._say(str(exc), RED)
            return
        _set_entry(widgets["token_secret"], "")
        self._say(f"Token de serviço gravado em {target} (usuário = Client ID).", GREEN)

    def _test(self) -> None:
        if self._future is not None and not self._future.done():
            return
        try:
            server = self._server_config(self._entry())
        except (ConfigError, ValueError) as exc:
            self._say(str(exc).replace("Configuração inválida:\n", ""), RED)
            return
        for kind, needed in (("password", server.password_prompt), ("passphrase", server.key_passphrase_prompt)):
            if needed and not get_session_secret(server.name, kind):
                self._ask_secret(server.name, kind)
                return
        self._say(f"Conectando a {server.address} ({server.connector.label(server.host)})…", GRAY)
        self.test_btn.configure(state="disabled")
        self.cf_login_btn.grid_forget()
        self._future = _EXECUTOR.submit(test_connection, server, self.app.settings)
        self._tested = server
        self.after(self.POLL_MS, self._poll_test)

    def _ask_secret(self, target: str, kind: str) -> None:
        from ui.secret_prompt import SecretPromptDialog

        dialog = SecretPromptDialog(self.app, target, target, kind, "Este servidor pede o segredo ao conectar. Ele "
                                    "fica só na memória desta sessão.", master=self, reconnect=False)
        self.wait_window(dialog)
        make_modal(self)
        if dialog.submitted:
            self._test()

    def _poll_test(self) -> None:
        future = self._future
        if future is None or not self.winfo_exists():
            return
        if not future.done():
            self.after(self.POLL_MS, self._poll_test)
            return
        self.test_btn.configure(state="normal")
        try:
            self._say(f"✓ Conectado: {future.result()}", GREEN)
        except Exception as exc:  # noqa: BLE001
            needs, target = getattr(exc, "needs", ""), getattr(exc, "target", "")
            if needs in ("password", "passphrase") and target and not get_session_secret(target, needs):
                self._ask_secret(target, needs)
                return
            self._say(f"✗ {exc}", RED)
            if needs == "cloudflare-login":
                self.cf_login_btn.grid(row=self.result.grid_info()["row"] + 1, column=0, columnspan=2,
                                       sticky="w", pady=(6, 0))

    def _cloudflare_login(self) -> None:
        from core.connectors import ConnectorError, cloudflared_login

        try:
            cloudflared_login(self._tested)
        except (ConnectorError, OSError) as exc:
            self._say(str(exc), RED)
            return
        self._say("Login aberto no navegador. Conclua lá e clique em \"Testar conexão\" de novo.", GRAY)

    def _save(self) -> None:
        if self.source is None:
            return
        try:
            entry = self._entry()
            raw = editor.upsert_server(self.raw, entry, self._editing)
            config = editor.validate(raw, self.source.parent)
        except (ConfigError, ValueError) as exc:
            self._say(str(exc).replace("Configuração inválida:\n", ""), RED)
            return
        try:
            backup = editor.save_raw(self.source, raw)
        except OSError as exc:
            self._say(f"Não foi possível gravar {self.source}: {exc}", RED)
            return
        self.raw = raw
        self._editing = entry["name"]
        result = self.app.apply_config(config)
        self._refresh_list()
        self._say(f"Salvo em {self.source.name}" + (f" (anterior em {backup.name})" if backup else "")
                  + f". Aplicado: {_describe(result)}.", GREEN)

    def _remove(self) -> None:
        name = self._editing
        if not name or self.source is None:
            return
        confirmed = ConfirmDialog(self, title="Remover servidor", confirm_text="Remover", danger=True,
                                  message=f"Remover \"{name}\" do servers.json? O monitoramento dele para agora "
                                          "(o arquivo anterior fica em servers.json.bak).").show()
        make_modal(self)
        if not confirmed:
            return
        raw = editor.remove_server(self.raw, name)
        try:
            config = editor.validate(raw, self.source.parent)
            editor.save_raw(self.source, raw)
        except (ConfigError, OSError) as exc:
            self._say(str(exc), RED)
            return
        self.raw = raw
        self.app.apply_config(config)
        self._load(None)
        self._say(f"{name} removido.", GREEN)

    def _say(self, text: str, color) -> None:
        self.result.configure(text=text, text_color=color)
        self.status.configure(text=text if len(text) < 160 else text[:157] + "…", text_color=color)


def _describe(result: dict[str, list[str]]) -> str:
    parts = [f"{label} {', '.join(result[key])}" for key, label in (("added", "novo"), ("updated", "atualizado"),
                                                                     ("removed", "removido")) if result.get(key)]
    return "; ".join(parts) or "sem mudanças de conexão"


def _set_entry(entry, value: str) -> None:
    entry.delete(0, "end")
    if value:
        entry.insert(0, value)


def _form_from_config(server) -> dict:
    """Formulário a partir de um ServerConfig (modo demonstração, sem servers.json)."""
    connector = server.connector
    form_connector: dict = {"type": connector.type, "name": connector.name}
    if connector.type == "vpn":
        form_connector["check"] = f"{connector.check_host}:{connector.check_port}" if connector.check_host else ""
        form_connector["up_command"] = list(connector.up_command)
    elif connector.type == "cloudflared":
        form_connector.update(hostname=connector.hostname, token_source="credential" if connector.token_credential
                              else "none")
    elif connector.type == "jump" and connector.jump is not None:
        form_connector.update(host=connector.jump.host, port=str(connector.jump.port), auth=connector.jump.auth,
                              username=connector.jump.username)
    source = "credential" if server.password_credential else "prompt" if server.password_prompt else \
        "env" if server.password_env else "none"
    return {"name": server.name, "host": server.host, "port": str(server.port), "username": server.username,
            "auth": server.auth, "key_file": str(server.key_file or ""), "password_source": source,
            "password_env": server.password_env or "", "passphrase_source": "none",
            "host_key_policy": server.host_key_policy, "connector": form_connector}
