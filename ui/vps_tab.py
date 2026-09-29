"""Aba "VPS": plataforma/provedor, CPU steal, latência a partir do Windows, horário
(NTP), DNS, OOM killer, franquia de tráfego do mês (vnStat) e endpoints
(sites, APIs e certificados TLS verificados a partir do Windows)."""

from __future__ import annotations

import datetime as dt
import ipaddress
from typing import TYPE_CHECKING

import customtkinter as ctk

from core.models import HostSnapshot, ServiceStatus
from ui.tabs import Tab, _button, _section_label
from ui.widgets import (
    GRAY,
    RED,
    YELLOW,
    Column,
    DataTable,
    InfoGrid,
    Row,
    fmt_ago,
    fmt_bytes,
    fmt_duration,
    fmt_num,
    fmt_pct,
)

if TYPE_CHECKING:
    from ui.dashboard import Dashboard

_ENDPOINT_LABELS = {ServiceStatus.ACTIVE: "OK", ServiceStatus.DEGRADED: "Atenção", ServiceStatus.FAILED: "Falha",
                    ServiceStatus.UNKNOWN: "Aguardando"}


def classify_ip(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return address
    if ip.is_loopback:
        return f"{address} (loopback)"
    return f"{address} ({'público' if ip.is_global else 'privado'})"


def fmt_latency(value: float | None, method: str = "") -> str:
    if value is None:
        return method or "—"
    text = f"{fmt_num(value, 1 if value < 10 else 0)} ms"
    return f"{text} ({method})" if method else text


class VpsTab(Tab):
    title = "VPS"

    def __init__(self, master, app: Dashboard) -> None:
        super().__init__(master, app)
        self._server: str | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1, minsize=140)
        self.info = InfoGrid(self, columns=3, wraplength=270)
        self.info.grid(row=0, column=0, sticky="ew", pady=(0, 8), ipady=6)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        header.grid_columnconfigure(1, weight=1)
        _section_label(header, "Tráfego do mês (vnStat)").grid(row=0, column=0, sticky="w")
        self.quota = ctk.CTkLabel(header, text="", anchor="e", text_color=GRAY)
        self.quota.grid(row=0, column=1, sticky="e")
        self.bandwidth = DataTable(
            self,
            [Column("iface", "Interface", 130), Column("period", "Mês", 90), Column("rx", "Recebido", 120, anchor="e"),
             Column("tx", "Enviado", 120, anchor="e"), Column("total", "Total", 120, anchor="e"),
             Column("today", "Hoje ↓ / ↑", 200, anchor="e"), Column("pad", "", 10, True)],
            export_name="trafego-mensal", height=2,
        )
        self.bandwidth.grid(row=2, column=0, sticky="ew")

        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=3, column=0, sticky="ew", pady=(10, 4))
        bar.grid_columnconfigure(1, weight=1)
        _section_label(bar, "Endpoints — sites, APIs e certificados (verificados a partir do Windows)").grid(
            row=0, column=0, sticky="w")
        self.endpoint_info = ctk.CTkLabel(bar, text="", anchor="e", text_color=GRAY)
        self.endpoint_info.grid(row=0, column=1, sticky="e", padx=(0, 10))
        self.check_btn = _button(bar, "Verificar agora", self._check_now, "neutral", 130)
        self.check_btn.grid(row=0, column=2)
        self.endpoints = DataTable(
            self,
            [Column("target", "Endpoint", 260, True), Column("scheme", "Tipo", 60),
             Column("http", "HTTP", 60, anchor="e"), Column("latency", "Latência", 85, anchor="e"),
             Column("days", "Certificado", 105, anchor="e"), Column("expires", "Expira em", 100),
             Column("issuer", "Emissor", 170), Column("detail", "Detalhe", 260, True)],
            tree_column=Column("status", "Status", 110), sort_column="status", export_name="endpoints",
            on_activate=self._show_endpoint,
        )
        self.endpoints.grid(row=5, column=0, sticky="nsew")
        self._endpoint_details: dict[str, str] = {}

    def render(self, server: str, snapshot: HostSnapshot | None, connected: bool) -> None:
        self._server = server
        config = self.app.server_config(server)
        vps = snapshot.vps if snapshot else None
        system = snapshot.system if snapshot else None
        metrics = snapshot.metrics if snapshot else None
        items: list[tuple[str, str, tuple[str, str] | None]] = []
        if snapshot is None:
            items.append(("VPS", "aguardando a primeira coleta…", GRAY))
        else:
            platform = (vps.provider if vps and vps.provider else "—")
            if vps and vps.product and vps.product != vps.provider:
                platform += f"  ({vps.product})"
            steal = metrics.cpu_steal if metrics else None
            threshold = self.app.settings.thresholds.steal_percent
            steal_color = RED if steal is not None and threshold and steal >= threshold else \
                YELLOW if steal is not None and steal >= 2 else None
            items += [
                ("Plataforma", platform, None),
                ("Virtualização", system.virtualization if system else "—", None),
                ("vCPU / RAM", f"{metrics.cpu_count or '—'} vCPU · {fmt_bytes((metrics.mem_total_mb or 0) * 1024 ** 2)}"
                 if metrics else "—", None),
                ("CPU steal / iowait", f"{fmt_pct(steal, 1)} / {fmt_pct(metrics.cpu_iowait if metrics else None, 1)}",
                 steal_color),
                ("Latência (Windows → servidor)", fmt_latency(snapshot.latency_ms, snapshot.latency_method),
                 YELLOW if (snapshot.latency_ms or 0) >= 200 else None),
                ("Uptime", fmt_duration(metrics.uptime_seconds if metrics else None), None),
            ]
            if vps is not None:
                ntp = {True: "sincronizado", False: "NÃO sincronizado", None: "—"}[vps.ntp_synchronized]
                if vps.ntp_service:
                    ntp += f" · serviço NTP {vps.ntp_service}"
                if vps.clock_offset is not None:
                    ntp += f" · desvio {fmt_num(vps.clock_offset * 1000, 2)} ms"
                oom = "sem acesso ao journal" if vps.oom_kills_24h is None else str(vps.oom_kills_24h)
                if vps.oom_kills:
                    oom += " · " + ", ".join(dict.fromkeys(k.process for k in vps.oom_kills[:5]))
                swap = "—"
                if metrics and metrics.swap_total_mb is not None:
                    swap = ("sem swap" if not metrics.swap_total_mb else
                            f"{fmt_bytes((metrics.swap_used_mb or 0) * 1024 ** 2)} de "
                            f"{fmt_bytes(metrics.swap_total_mb * 1024 ** 2)}")
                if vps.swappiness is not None:
                    swap += f" · swappiness {vps.swappiness}"
                items += [
                    ("Horário (NTP)", ntp, YELLOW if vps.ntp_synchronized is False else None),
                    ("Fuso horário", system.timezone if system and system.timezone else "—", None),
                    ("DNS", ", ".join(vps.dns_servers) or "—", None),
                    ("Gateway padrão", vps.default_gateway or "—", None),
                    ("Endereços IP", ", ".join(classify_ip(ip) for ip in system.ip_addresses)
                     if system and system.ip_addresses else "—", None),
                    ("Swap", swap, None),
                    ("OOM killer (24 h)", oom, RED if vps.oom_kills_24h else None),
                ]
        self.info.set_items(items)
        self._render_bandwidth(vps, config)
        self._render_endpoints(snapshot, config)

    def _render_bandwidth(self, vps, config) -> None:
        rows = []
        for b in vps.bandwidth if vps else ():
            today = "—" if b.today_rx is None else f"{fmt_bytes(b.today_rx)} / {fmt_bytes(b.today_tx)}"
            rows.append(Row(key=b.interface, values=(b.interface, b.period, fmt_bytes(b.rx_bytes),
                                                      fmt_bytes(b.tx_bytes), fmt_bytes(b.total_bytes), today, ""),
                            sort=(b.interface, b.period, b.rx_bytes, b.tx_bytes, b.total_bytes, b.today_rx, "")))
        if vps is None:
            empty = "Aguardando o inventário…"
        elif not vps.bandwidth_source:
            empty = "vnStat não instalado — instale com 'apt install vnstat' para acompanhar a franquia mensal."
        else:
            empty = "vnStat ainda sem dados deste mês."
        self.bandwidth.set_rows(rows, empty)
        used = vps.bandwidth_total(config.bandwidth_count) if vps else None
        if config.bandwidth_quota_gb and used is not None:
            fraction = used / (config.bandwidth_quota_gb * 1024 ** 3)
            what = "enviados" if config.bandwidth_count == "tx" else "no total"
            quota = fmt_num(config.bandwidth_quota_gb, 0)
            self.quota.configure(text=f"Franquia: {fmt_bytes(used)} {what} de {quota} GB ({fmt_pct(fraction * 100)})",
                                 text_color=RED if fraction >= 1 else YELLOW if fraction >= 0.8 else GRAY)
        elif config.bandwidth_quota_gb:
            self.quota.configure(text=f"Franquia de {fmt_num(config.bandwidth_quota_gb, 0)} GB (sem dados do vnStat)",
                                 text_color=GRAY)
        else:
            self.quota.configure(text="Defina \"bandwidth_quota_gb\" para alertas de franquia.", text_color=GRAY)

    def _render_endpoints(self, snapshot: HostSnapshot | None, config) -> None:
        results = {r.target: r for r in snapshot.endpoints} if snapshot else {}
        rows = []
        self._endpoint_details = {}
        for target in config.endpoints:
            result = results.get(target)
            if result is None:
                rows.append(Row(key=target, text="Aguardando", status=ServiceStatus.UNKNOWN,
                                values=(target, "", "", "", "", "", "", "primeira verificação pendente"),
                                sort=((ServiceStatus.UNKNOWN.severity, target), target)))
                continue
            expires = dt.datetime.fromtimestamp(result.cert_expires).strftime("%d/%m/%Y") if result.cert_expires else ""
            days = "" if result.cert_days_left is None else f"{int(result.cert_days_left)} dias"
            if result.cert_valid is False:
                days = f"inválido · {days}" if days else "inválido"
            latency = "" if result.latency_ms is None else f"{fmt_num(result.latency_ms, 0)} ms"
            rows.append(Row(
                key=target, text=_ENDPOINT_LABELS.get(result.status, result.status.label), status=result.status,
                values=(target, result.scheme, "" if result.http_status is None else str(result.http_status), latency,
                        days, expires, result.cert_issuer, result.detail),
                sort=((result.status.severity, target), target, result.scheme, result.http_status, result.latency_ms,
                      result.cert_days_left, result.cert_expires, result.cert_issuer or None, result.detail),
            ))
            self._endpoint_details[target] = (
                f"{target}\n\nStatus: {result.status.label}\nDetalhe: {result.detail}\n"
                f"Latência: {latency or '—'}\nHTTP: {result.http_status or '—'}\n"
                f"Certificado: {result.cert_subject or '—'} · emissor {result.cert_issuer or '—'} · "
                f"expira {expires or '—'} ({days or '—'})")
        empty = ("Nenhum endpoint configurado. Adicione \"endpoints\": [\"https://seu-site.com\"] ao servidor no "
                 "servers.json para monitorar sites, APIs e certificados.")
        self.endpoints.set_rows(rows, empty)
        _set_enabled(self.check_btn, bool(config.endpoints))
        if config.endpoints:
            interval = self.app.settings.endpoint_interval_seconds
            self.endpoint_info.configure(
                text=f"Verificado {fmt_ago(snapshot.endpoints_at if snapshot else None)} · "
                     f"a cada {fmt_duration(interval)} · alerta de certificado com "
                     f"{fmt_num(self.app.settings.cert_warning_days, 0)} dias")
        else:
            self.endpoint_info.configure(text="")

    def _check_now(self) -> None:
        if self._server:
            self.app.manager.refresh(self._server, full=True)
            self.app.set_status(f"Verificando endpoints e inventário de {self._server}…")

    def _show_endpoint(self) -> None:
        key = self.endpoints.selected_key()
        if key in self._endpoint_details:
            self.app.show_text("Endpoint", text=self._endpoint_details[key])

    def reset(self) -> None:
        self.bandwidth.clear()
        self.endpoints.clear()


def _set_enabled(widget, enabled: bool) -> None:
    widget.configure(state="normal" if enabled else "disabled")
