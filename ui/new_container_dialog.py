"""Diálogo "Novo contêiner": o mesmo formulário para Docker, Podman e containerd.
Ao confirmar, abre a mudança segura (análise de risco → baixar imagem → criar →
confirmar que está rodando → histórico)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core import containers as engines
from core.changes import (
    RESTART_POLICIES,
    ChangeAction,
    ContainerSpec,
    parse_command,
    parse_env,
    parse_mounts,
    parse_ports,
    validate_spec,
)
from ui import theme
from ui.widgets import GRAY, RED, TEXT, center_on, make_modal

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

DEFAULT_NETWORK = "(padrão do motor)"


def available_engines(snapshot) -> list[str]:
    """Motores com CLI de criação que estão ativos no servidor."""
    inventory = snapshot.containers if snapshot else None
    if inventory is None:
        return []
    return [e.id for e in inventory.engines if e.id in engines.CLI_ENGINES and e.installed and e.mode != "off"]


def build_spec(engine: str, *, image: str, name: str, ports: str = "", env: str = "", volumes: str = "",
               network: str = "", restart: str = "unless-stopped", command: str = "", memory: str = "",
               cpus: str = "") -> ContainerSpec:
    """Monta e valida a especificação a partir dos campos do formulário (mensagens em português)."""
    if not image.strip():
        raise ValueError("Informe a imagem (ex.: nginx:1.27-alpine).")
    if not name.strip():
        raise ValueError("Informe o nome do contêiner.")
    spec = ContainerSpec(
        engine=engine, name=name.strip(), image=image.strip(), ports=parse_ports(ports), env=parse_env(env),
        mounts=parse_mounts(volumes), network="" if network in ("", DEFAULT_NETWORK) else network,
        restart=restart, command=parse_command(command), memory=memory.strip(), cpus=cpus.strip(),
        labels=(("io.firawynix.created-by", "firawynix-monitor"),))
    return validate_spec(spec)


class NewContainerDialog(ctk.CTkToplevel):
    def __init__(self, app: Dashboard, server: str) -> None:
        super().__init__(app)
        self.app = app
        self.server = server
        self.title(f"Novo contêiner — {server}")
        self.resizable(False, False)
        self.transient(app)
        snapshot = app.snapshot(server)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=18)
        body.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(body, text="Novo contêiner", anchor="w", text_color=theme.ACCENT_TEXT,
                     font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ctk.CTkLabel(body, text="Antes de criar, o painel confere nome e portas em uso, os riscos da configuração e "
                                "baixa a imagem se preciso; depois confirma que ele ficou rodando.",
                     anchor="w", justify="left", wraplength=560, text_color=GRAY).grid(row=1, column=0, columnspan=2,
                                                                                         sticky="w", pady=(2, 10))
        found = available_engines(snapshot)
        self.fields: dict[str, ctk.CTkEntry | ctk.CTkOptionMenu | ctk.CTkTextbox] = {}
        row = 2
        self.engine = ctk.CTkOptionMenu(body, values=[engines.ENGINES[e].label for e in found] or ["—"], width=260)
        self._engine_ids = {engines.ENGINES[e].label: e for e in found}
        row = self._row(body, row, "Motor", self.engine)
        for key, label, placeholder in (
                ("image", "Imagem *", "nginx:1.27-alpine"), ("name", "Nome *", "web-novo"),
                ("ports", "Portas", "8080:80, 127.0.0.1:5432:5432"),
                ("volumes", "Volumes", "dados:/var/lib/app, /srv/site:/usr/share/nginx/html:ro"),
                ("command", "Comando", "(opcional) ex.: sh -c \"echo oi && sleep 3600\"")):
            entry = ctk.CTkEntry(body, width=420, placeholder_text=placeholder)
            self.fields[key] = entry
            row = self._row(body, row, label, entry)
        self.env = ctk.CTkTextbox(body, width=420, height=90)
        self.env.insert("1.0", "TZ=America/Sao_Paulo\n")
        row = self._row(body, row, "Variáveis\n(CHAVE=valor)", self.env)
        networks = sorted({n.name for n in (snapshot.containers.networks if snapshot and snapshot.containers else ())
                           if n.name not in ("host", "none")})
        self.network = ctk.CTkOptionMenu(body, values=[DEFAULT_NETWORK, *networks], width=260)
        row = self._row(body, row, "Rede", self.network)
        self.restart = ctk.CTkOptionMenu(body, values=list(RESTART_POLICIES), width=160)
        self.restart.set("unless-stopped")
        row = self._row(body, row, "Reinício", self.restart)
        limits = ctk.CTkFrame(body, fg_color="transparent")
        self.memory = ctk.CTkEntry(limits, width=110, placeholder_text="ex.: 512m")
        self.memory.pack(side="left", padx=(0, 10))
        self.cpus = ctk.CTkEntry(limits, width=90, placeholder_text="CPUs: 1.5")
        self.cpus.pack(side="left")
        row = self._row(body, row, "Limites", limits)
        self.error = ctk.CTkLabel(body, text="", anchor="w", justify="left", wraplength=560, text_color=RED)
        self.error.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        buttons = ctk.CTkFrame(body, fg_color="transparent")
        buttons.grid(row=row + 1, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ctk.CTkButton(buttons, text="Cancelar", width=100, fg_color="transparent", border_width=1, text_color=TEXT,
                      command=self.destroy).pack(side="left", padx=(0, 8))
        self.create_btn = ctk.CTkButton(buttons, text="Analisar e criar…", width=160, command=self._submit)
        self.create_btn.pack(side="left")
        config = app.server_config(server)
        if not found:
            self.error.configure(text="Nenhum motor com suporte a criação (Docker, Podman, containerd) foi "
                                      "detectado neste servidor.")
            self.create_btn.configure(state="disabled")
        elif not config.container_admin:
            self.error.configure(text="Criar contêineres exige \"container_admin\": true no servers.json "
                                      "(ou em Servidores e conexões).")
            self.create_btn.configure(state="disabled")
        self.bind("<Escape>", lambda _e: self.destroy())
        center_on(self, app)
        self.after(60, lambda: make_modal(self))
        self.after(250, lambda: theme.style_window(self))

    def _row(self, body, row: int, label: str, widget) -> int:
        ctk.CTkLabel(body, text=label, anchor="nw", justify="left").grid(row=row, column=0, sticky="nw",
                                                                         padx=(0, 12), pady=4)
        widget.grid(row=row, column=1, sticky="w", pady=4)
        return row + 1

    def _submit(self) -> None:
        try:
            spec = build_spec(
                self._engine_ids.get(self.engine.get(), ""), image=self.fields["image"].get(),
                name=self.fields["name"].get(), ports=self.fields["ports"].get(), env=self.env.get("1.0", "end"),
                volumes=self.fields["volumes"].get(), network=self.network.get(), restart=self.restart.get(),
                command=self.fields["command"].get(), memory=self.memory.get(), cpus=self.cpus.get())
        except ValueError as exc:
            self.error.configure(text=str(exc))
            return
        self.destroy()
        self.app.open_change(self.server, ChangeAction.CREATE, spec=spec)
