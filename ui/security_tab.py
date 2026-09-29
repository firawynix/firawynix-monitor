"""Aba "Segurança": nota de 0 a 100, verificações com recomendação, fail2ban
(desbanir), tentativas de login SSH por origem (banir), logins aceitos, uso de
sudo, sessões abertas e chaves autorizadas."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

import customtkinter as ctk

from core.models import CheckLevel, HostSnapshot, SecurityReport
from core.parsers import format_timestamp
from core.security import firewall_summary
from ui.tabs import Tab, _button, _matches, _search_entry, _set_state
from ui.widgets import (
    CARD_BG,
    GRAY,
    GREEN,
    RED,
    TEXT,
    YELLOW,
    Column,
    DataTable,
    Row,
    fmt_ago,
    fmt_duration,
)

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

VIEWS = ("Verificações", "Tentativas SSH", "Fail2ban", "Logins aceitos", "sudo", "Sessões e chaves")


def score_color(score: int | None) -> tuple[str, str]:
    if score is None:
        return GRAY
    if score >= 80:
        return GREEN
    if score >= 60:
        return YELLOW
    return RED


def pick_jail(report: SecurityReport | None) -> str | None:
    """Jail usada para banir a partir da lista de tentativas SSH."""
    jails = [j.name for j in report.raw.fail2ban] if report else []
    for preferred in ("sshd", "ssh"):
        if preferred in jails:
            return preferred
    return next((j for j in jails if "ssh" in j), jails[0] if jails else None)


def ban_block_reason(ip: str, report: SecurityReport | None) -> str | None:
    """Motivo para NÃO banir (nunca bloquear o próprio monitor ou o loopback)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "endereço inválido"
    if report is not None and ip == report.raw.ssh_client:
        return "é o IP deste monitor — banir derrubaria a conexão"
    if address.is_loopback or address.is_unspecified:
        return "endereço local"
    if report is not None and any(ip in jail.banned_ips for jail in report.raw.fail2ban):
        return "já está banido"
    return None


class SecurityTab(Tab):
    title = "Segurança"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._server: str | None = None
        self._report: SecurityReport | None = None
        self._details: dict[str, str] = {}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        summary = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        summary.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        summary.grid_columnconfigure(1, weight=1)
        score_box = ctk.CTkFrame(summary, fg_color="transparent")
        score_box.grid(row=0, column=0, rowspan=2, padx=(16, 22), pady=10)
        ctk.CTkLabel(score_box, text="NOTA DE SEGURANÇA", text_color=GRAY,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w")
        self.score = ctk.CTkLabel(score_box, text="—", font=ctk.CTkFont(size=34, weight="bold"), anchor="w")
        self.score.pack(anchor="w")
        self.counts = ctk.CTkLabel(score_box, text="", text_color=GRAY, anchor="w")
        self.counts.pack(anchor="w")
        self.headline = ctk.CTkLabel(summary, text="", anchor="w", justify="left", wraplength=900)
        self.headline.grid(row=0, column=1, sticky="ew", pady=(12, 2))
        self.updated = ctk.CTkLabel(summary, text="", anchor="w", text_color=GRAY)
        self.updated.grid(row=1, column=1, sticky="ew", pady=(0, 12))
        _button(summary, "Auditar agora", self._audit_now, "neutral", 130).grid(row=0, column=2, rowspan=2,
                                                                              padx=16)

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(2, weight=1)
        self.view = ctk.CTkSegmentedButton(toolbar, values=list(VIEWS), command=lambda _v: self._switch())
        self.view.set(VIEWS[0])
        self.view.grid(row=0, column=0, padx=(0, 10))
        self.search = _search_entry(toolbar, "Filtrar…  (Ctrl+F)", self.app.render_current_tab)
        self.search.grid(row=0, column=1, padx=(0, 10))
        self.info = ctk.CTkLabel(toolbar, text="", text_color=GRAY, anchor="e")
        self.info.grid(row=0, column=2, sticky="e")

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=2, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self.tables: dict[str, DataTable] = {
            "Verificações": DataTable(
                content, [Column("category", "Categoria", 110), Column("title", "Verificação", 220),
                          Column("detail", "Resultado", 420, True), Column("fix", "Recomendação", 340, True)],
                tree_column=Column("level", "Nível", 125), export_name="seguranca-verificacoes",
                on_activate=self._show_check),
            "Tentativas SSH": DataTable(
                content, [Column("ip", "Origem", 200), Column("count", "Conexões com falha", 150, anchor="e"),
                          Column("user", "Último usuário tentado", 180), Column("last", "Última tentativa", 150),
                          Column("banned", "Banido agora", 150), Column("pad", "", 10, True)],
                sort_column="count", sort_desc=True, export_name="tentativas-ssh", on_select=self._update_actions,
                menu_items=self._attempt_menu),
            "Fail2ban": DataTable(
                content, [Column("ip", "IP banido", 220), Column("jail", "Jail", 160),
                          Column("attempts", "Tentativas (24 h)", 150, anchor="e"), Column("pad", "", 10, True)],
                export_name="fail2ban", on_select=self._update_actions, menu_items=self._banned_menu),
            "Logins aceitos": DataTable(
                content, [Column("time", "Data/hora", 150), Column("user", "Usuário", 140),
                          Column("source", "Origem", 220), Column("method", "Método", 180),
                          Column("note", "Observação", 260, True)],
                sort_column="time", sort_desc=True, export_name="logins-ssh"),
            "sudo": DataTable(
                content, [Column("time", "Data/hora", 150), Column("user", "Usuário", 120),
                          Column("outcome", "Resultado", 130), Column("as", "Como", 90), Column("tty", "Terminal", 90),
                          Column("command", "Comando", 460, True)],
                sort_column="time", sort_desc=True, export_name="sudo"),
        }
        sessions_frame = ctk.CTkFrame(content, fg_color="transparent")
        sessions_frame.grid_columnconfigure(0, weight=1)
        sessions_frame.grid_rowconfigure((0, 1), weight=1)
        self.sessions = DataTable(
            sessions_frame, [Column("user", "Sessão: usuário", 160), Column("tty", "Terminal", 100),
                             Column("source", "Origem", 220), Column("since", "Desde", 180),
                             Column("pad", "", 10, True)],
            export_name="sessoes")
        self.sessions.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        self.keys = DataTable(
            sessions_frame, [Column("type", "Chave autorizada: tipo", 190), Column("bits", "Bits", 70, anchor="e"),
                             Column("fp", "Impressão digital", 360), Column("comment", "Comentário", 200, True),
                             Column("restricted", "Restrições", 110)],
            export_name="chaves-autorizadas")
        self.keys.grid(row=1, column=0, sticky="nsew")
        self._views = {**self.tables, "Sessões e chaves": sessions_frame}
        for widget in self._views.values():
            widget.grid(row=0, column=0, sticky="nsew")

        bar = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        bar.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        bar.grid_columnconfigure(0, weight=1)
        self.hint = ctk.CTkLabel(bar, text="", anchor="w", text_color=GRAY)
        self.hint.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        self.btn_ban = _button(bar, "Banir IP", lambda: self._ban(True), "stop", 120)
        self.btn_unban = _button(bar, "Desbanir IP", lambda: self._ban(False), width=120)
        self.btn_copy = _button(bar, "Copiar IP", self._copy_ip, "neutral", 110)
        self.btn_ban.grid(row=0, column=1, padx=(0, 8), pady=10)
        self.btn_unban.grid(row=0, column=2, padx=(0, 8), pady=10)
        self.btn_copy.grid(row=0, column=3, padx=(0, 14), pady=10)
        self._switch(render=False)

    # -- renderização --------------------------------------------------------------

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        self._server = server
        config = self.app.server_config(server)
        report = snapshot.security if snapshot else None
        self._report = report
        self._render_summary(snapshot, report, config)
        self._render_checks(report, snapshot, config)
        self._render_attempts(report)
        self._render_fail2ban(report, config)
        self._render_logins(report, config)
        self._render_sudo(report)
        raw = report.raw if report else None
        self.sessions.set_rows([Row(key=f"{i}", values=(s.user, s.tty, s.source or "local", s.since, ""),
                                    sort=(s.user, s.tty, s.source, s.since, ""))
                                for i, s in enumerate(raw.sessions if raw else ())], "Nenhuma sessão aberta.")
        self.keys.set_rows([Row(key=k.fingerprint + str(i),
                                values=(k.key_type, "" if k.bits is None else str(k.bits), k.fingerprint, k.comment,
                                        "sim" if k.restricted else "não"),
                                sort=(k.key_type, k.bits, k.fingerprint, k.comment, k.restricted),
                                tag="error" if k.key_type == "ssh-dss"
                                or (k.key_type == "ssh-rsa" and (k.bits or 0) < 2048) else None)
                            for i, k in enumerate(raw.authorized_keys if raw else ())],
                           f"Nenhuma chave em ~{config.username}/.ssh/authorized_keys legível.")
        self._update_actions()

    def _render_summary(self, snapshot, report: SecurityReport | None, config) -> None:
        if not config.security:
            self.score.configure(text="—", text_color=GRAY)
            self.counts.configure(text="auditoria desativada")
            self.headline.configure(text="A auditoria está desativada para este servidor (\"security\": false).",
                                    text_color=GRAY)
            self.updated.configure(text="")
            return
        if report is None:
            self.score.configure(text="…", text_color=GRAY)
            self.counts.configure(text="")
            self.headline.configure(text="Aguardando a primeira auditoria…", text_color=GRAY)
            self.updated.configure(text="")
            return
        self.score.configure(text="—" if report.score is None else f"{report.score}/100",
                             text_color=score_color(report.score))
        self.counts.configure(text=f"{report.count(CheckLevel.FAIL)} crítico(s) · {report.count(CheckLevel.WARN)} "
                                   f"atenção · {report.count(CheckLevel.OK)} OK")
        active, firewall = firewall_summary(report.raw)
        parts = [f"Firewall: {firewall if active else 'não detectado' if active is None else 'INATIVO'}"]
        bruteforce = report.check("bruteforce")
        if bruteforce is not None:
            parts.append(bruteforce.detail.rstrip("."))
        password = report.check("ssh_password")
        if password is not None:
            parts.append("SSH só com chave" if password.level is CheckLevel.OK else "SSH aceita senha")
        if report.logins is not None:
            parts.append(f"{report.logins.failed_total} conexões SSH com falha em 24 h")
        worst = next((c for c in report.checks if c.level is CheckLevel.FAIL), None)
        text = " · ".join(parts)
        if worst is not None:
            text = f"Crítico: {worst.title} — {worst.detail}\n" + text
        self.headline.configure(text=text, text_color=RED if worst else TEXT)
        sudo_note = "" if config.security_sudo else "  ·  sem \"security_sudo\": fail2ban e iptables não são lidos"
        self.updated.configure(text=f"Auditado {fmt_ago(snapshot.security_at)} · a cada "
                                    f"{fmt_duration(self.app.settings.security_interval_seconds)}{sudo_note}")

    def _render_checks(self, report, snapshot, config) -> None:
        rows = []
        self._details = {}
        for check in report.checks if report else ():
            if not _matches(self.search, check.category, check.title, check.detail, check.recommendation):
                continue
            self._details[check.id] = (f"[{check.level.label}] {check.category} — {check.title}\n\n{check.detail}"
                                       + (f"\n\nRecomendação: {check.recommendation}" if check.recommendation else ""))
            rows.append(Row(key=check.id, text=check.level.label, status=check.level.status,
                            values=(check.category, check.title, check.detail, check.recommendation),
                            sort=((check.level.status.severity, check.category), check.category, check.title,
                                  check.detail, check.recommendation or None),
                            tag="muted" if check.level is CheckLevel.INFO else None))
        empty = ("Auditoria desativada." if not config.security else
                 "Aguardando a primeira auditoria…" if report is None else "Nada corresponde ao filtro.")
        self.tables["Verificações"].set_rows(rows, empty)

    def _banned(self, report) -> dict[str, list[str]]:
        banned: dict[str, list[str]] = {}
        for jail in report.raw.fail2ban if report else ():
            for ip in jail.banned_ips:
                banned.setdefault(ip, []).append(jail.name)
        return banned

    def _render_attempts(self, report) -> None:
        banned = self._banned(report)
        sources = report.logins.failed_sources if report and report.logins else ()
        rows = [Row(key=s.source, values=(s.source, str(s.count), s.last_user, format_timestamp(s.last_seen),
                                          ", ".join(banned.get(s.source, [])), ""),
                    sort=(s.source, s.count, s.last_user or None, s.last_seen, bool(banned.get(s.source)), ""),
                    tag="muted" if s.source in banned else "error" if s.count >= 20 else None)
                for s in sources if _matches(self.search, s.source, s.last_user)]
        empty = "Aguardando a auditoria…" if report is None else "Nenhuma tentativa com falha nas últimas 24 h."
        if report is not None and report.logins is not None and not report.logins.complete:
            empty = "Sem acesso ao journal: adicione o usuário SSH ao grupo systemd-journal (ou adm)."
        self.tables["Tentativas SSH"].set_rows(rows, empty)

    def _render_fail2ban(self, report, config) -> None:
        counts = {s.source: s.count for s in (report.logins.failed_sources if report and report.logins else ())}
        rows = []
        for jail in report.raw.fail2ban if report else ():
            for ip in jail.banned_ips:
                if _matches(self.search, ip, jail.name):
                    rows.append(Row(key=f"{jail.name}|{ip}", values=(ip, jail.name, str(counts.get(ip, "")), ""),
                                    sort=(ip, jail.name, counts.get(ip), "")))
        if report is None:
            empty = "Aguardando a auditoria…"
        elif not (config.security_sudo or config.username == "root"):
            empty = "O fail2ban-client exige root: habilite \"security_sudo\" (NOPASSWD, veja docs/sudoers.example)."
        elif report.raw.fail2ban_error:
            empty = f"fail2ban indisponível: {report.raw.fail2ban_error}"
        else:
            empty = "Nenhum IP banido no momento."
        self.tables["Fail2ban"].set_rows(rows, empty)
        jails = report.raw.fail2ban if report else ()
        self._jail_summary = " · ".join(
            f"{j.name}: {j.currently_banned or 0} banido(s), {j.total_failed or 0} falhas" for j in jails)

    def _render_logins(self, report, config) -> None:
        client_ip = report.raw.ssh_client if report else ""
        rows = []
        for i, e in enumerate(report.logins.accepted if report and report.logins else ()):
            if not _matches(self.search, e.user, e.source, e.method):
                continue
            note = "este monitor" if e.user == config.username and e.source == client_ip else ""
            if e.user == "root":
                note = "login do root" + (" POR SENHA" if e.method.startswith(("password", "keyboard")) else "")
            rows.append(Row(key=f"{e.timestamp}:{i}", values=(format_timestamp(e.timestamp), e.user, e.source,
                                                              e.method, note),
                            sort=(e.timestamp, e.user, e.source, e.method, note or None),
                            tag="error" if "SENHA" in note else "warn" if e.user == "root" else
                            "muted" if note == "este monitor" else None))
        self.tables["Logins aceitos"].set_rows(rows, "Nenhum login aceito nas últimas 24 h." if report else
                                               "Aguardando a auditoria…")

    def _render_sudo(self, report) -> None:
        rows = [Row(key=f"{e.timestamp}:{i}", values=(format_timestamp(e.timestamp), e.user, e.outcome, e.run_as,
                                                      e.tty, e.command),
                    sort=(e.timestamp, e.user, e.outcome, e.run_as, e.tty, e.command),
                    tag="error" if e.outcome != "ok" else None)
                for i, e in enumerate(report.sudo if report else ())
                if _matches(self.search, e.user, e.command, e.outcome)]
        self.tables["sudo"].set_rows(rows, "Nenhum uso interativo de sudo nas últimas 24 h (as chamadas do "
                                           "próprio monitor são omitidas)." if report else "Aguardando a auditoria…")

    # -- ações -----------------------------------------------------------------

    def _switch(self, render: bool = True) -> None:
        current = self.view.get()
        for name, widget in self._views.items():
            if name == current:
                widget.grid()
            else:
                widget.grid_remove()
        if render:
            self.app.render_current_tab()

    def _selected_ip(self) -> tuple[str | None, str | None]:
        view = self.view.get()
        if view == "Tentativas SSH":
            return self.tables[view].selected_key(), None
        if view == "Fail2ban":
            key = self.tables[view].selected_key()
            if key:
                jail, _, ip = key.partition("|")
                return ip, jail
        return None, None

    def _update_actions(self) -> None:
        view = self.view.get()
        ip, jail = self._selected_ip()
        config = self.app.server_config(self._server) if self._server else None
        connected = bool(self._server) and self.app.manager.is_connected(self._server)
        allowed = bool(config and config.security_actions and (config.security_sudo or config.username == "root"))
        busy = bool(ip and self._server and self.app.busy_label(self._server, f"ip:{ip}"))
        ban_jail = pick_jail(self._report)
        reason = ban_block_reason(ip, self._report) if ip else None
        for button in (self.btn_ban, self.btn_unban):
            button.grid_remove()
        if view == "Tentativas SSH":
            self.btn_ban.grid()
        elif view == "Fail2ban":
            self.btn_unban.grid()
        _set_state(self.btn_ban, bool(ip and allowed and connected and ban_jail and not reason and not busy))
        _set_state(self.btn_unban, bool(ip and jail and allowed and connected and not busy))
        _set_state(self.btn_copy, bool(ip))
        if view not in ("Tentativas SSH", "Fail2ban"):
            self.hint.configure(text="Duplo clique em uma verificação mostra a explicação completa."
                                if view == "Verificações" else "", text_color=GRAY)
            self.info.configure(text="")
            return
        if not allowed:
            text = "Banir/desbanir exige \"security_actions\" e \"security_sudo\" no servers.json."
        elif ban_jail is None and view == "Tentativas SSH":
            text = "Nenhuma jail do fail2ban disponível para banir."
        elif reason:
            text = f"{ip}: não pode ser banido ({reason})."
        elif ip:
            text = f"{ip} selecionado" + (f" · jail {jail or ban_jail}" if (jail or ban_jail) else "")
        else:
            text = "Selecione um IP."
        self.hint.configure(text=text, text_color=YELLOW if reason else GRAY)
        self.info.configure(text=getattr(self, "_jail_summary", "") if view == "Fail2ban" else "")

    def _ban(self, ban: bool) -> None:
        ip, jail = self._selected_ip()
        jail = jail or pick_jail(self._report)
        if not ip or not jail or self._server is None or (ban and ban_block_reason(ip, self._report)):
            return
        self.app.fail2ban_action(self._server, jail, ip, ban)

    def _copy_ip(self) -> None:
        ip, _ = self._selected_ip()
        if ip:
            self.app.copy_text(ip)

    def _attempt_menu(self):
        ip, _ = self._selected_ip()
        if not ip:
            return []
        return [("Banir IP", lambda: self._ban(True)), ("Copiar IP", self._copy_ip)]

    def _banned_menu(self):
        ip, _ = self._selected_ip()
        if not ip:
            return []
        return [("Desbanir IP", lambda: self._ban(False)), ("Copiar IP", self._copy_ip)]

    def _show_check(self) -> None:
        key = self.tables["Verificações"].selected_key()
        if key in self._details:
            self.app.show_text("Verificação de segurança", text=self._details[key])

    def _audit_now(self) -> None:
        if self._server:
            self.app.manager.refresh(self._server, full=True)
            self.app.set_status(f"Auditando {self._server}…")

    def reset(self) -> None:
        for table in (*self.tables.values(), self.sessions, self.keys):
            table.clear()

    def focus_search(self) -> None:
        self.search.focus_set()

