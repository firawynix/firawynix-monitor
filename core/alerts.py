"""Alertas "de host" além de serviços e limites de recurso: endpoints (sites e
certificados), saúde SMART, auditoria de segurança, logins SSH, OOM killer e
franquia mensal de tráfego.

Cada regra só dispara na TRANSIÇÃO (nunca repete o mesmo alerta a cada coleta)
e a primeira leitura estabelece a linha de base: abrir o monitor não despeja o
histórico das últimas 24 h em notificações.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from config.settings import NotificationSettings, ServerConfig
from core.models import (
    CheckLevel,
    EndpointResult,
    HostAlertEvent,
    SecurityReport,
    ServiceStatus,
    SmartReport,
    VpsInfo,
)

#: Frações da franquia mensal que geram alerta.
BANDWIDTH_STEPS = (0.8, 1.0)


class HostAlertPolicy:
    def __init__(self, server: ServerConfig, notifications: NotificationSettings) -> None:
        self.server = server
        self.notifications = notifications
        self._endpoint_state: dict[str, ServiceStatus] = {}
        self._cert_warned: dict[str, str] = {}
        self._smart_state: dict[str, ServiceStatus] = {}
        self._security_fail: set[str] | None = None
        self._login_watermark: float | None = None
        self._oom_watermark: float | None = None
        self._bandwidth_steps: dict[str, float] = {}

    def _event(self, category: str, key: str, title: str, message: str, level: str = "warning",
               recovered: bool = False) -> HostAlertEvent:
        return HostAlertEvent(server=self.server.name, category=category, key=f"{self.server.name}:{key}",
                              title=title, message=message, level=level, recovered=recovered)

    # -- endpoints -----------------------------------------------------------

    def endpoints(self, results: Sequence[EndpointResult], now: float | None = None) -> list[HostAlertEvent]:
        events = []
        today = time.strftime("%Y-%m-%d", time.localtime(now or time.time()))
        for result in results:
            previous = self._endpoint_state.get(result.target)
            self._endpoint_state[result.target] = result.status
            if result.status is ServiceStatus.FAILED and previous is not ServiceStatus.FAILED:
                events.append(self._event("endpoint", f"endpoint:{result.target}", f"Fora do ar: {result.target}",
                                          f"{self.server.name} · {result.detail}", "critical"))
            elif result.status is not ServiceStatus.FAILED and previous is ServiceStatus.FAILED \
                    and self.notifications.notify_on_recovery:
                events.append(self._event("endpoint", f"endpoint:{result.target}:ok",
                                          f"De volta: {result.target}", result.detail or "respondendo",
                                          "info", recovered=True))
            days = result.cert_days_left
            if days is not None and days >= 0 and result.status is ServiceStatus.DEGRADED \
                    and self._cert_warned.get(result.target) != today and "certificado" in result.detail:
                self._cert_warned[result.target] = today
                events.append(self._event("endpoint", f"cert:{result.target}:{today}",
                                          f"Certificado expira em {int(days)} dia(s)",
                                          f"{result.target} · emissor {result.cert_issuer or '?'}"))
        return events

    # -- SMART ---------------------------------------------------------------

    def smart(self, report: SmartReport | None) -> list[HostAlertEvent]:
        events = []
        for disk in report.disks if report else ():
            status = disk.status
            previous = self._smart_state.get(disk.device)
            self._smart_state[disk.device] = status
            if status in (ServiceStatus.FAILED, ServiceStatus.DEGRADED) and previous is not status:
                level = "critical" if status is ServiceStatus.FAILED else "warning"
                events.append(self._event("smart", f"smart:{disk.device}:{status.value}",
                                          f"Disco {disk.device} com problema — {self.server.name}",
                                          f"{disk.model or 'disco'}: {', '.join(disk.problems) or disk.message}",
                                          level))
        return events

    # -- segurança -------------------------------------------------------------

    def security(self, report: SecurityReport | None) -> list[HostAlertEvent]:
        if report is None:
            return []
        failing = {c.id: c for c in report.checks if c.level is CheckLevel.FAIL}
        events = []
        first = self._security_fail is None
        new = set(failing) - (self._security_fail or set())
        self._security_fail = set(failing)
        if new and self.notifications.security_alerts:
            if first and len(new) > 1:
                titles = ", ".join(failing[c].title for c in sorted(new))
                events.append(self._event("security", "security:summary",
                                          f"{len(new)} problemas críticos de segurança — {self.server.name}",
                                          titles, "critical"))
            else:
                for check_id in sorted(new):
                    check = failing[check_id]
                    events.append(self._event("security", f"security:{check_id}",
                                              f"Segurança: {check.title} — {self.server.name}", check.detail,
                                              "critical"))
        if report.logins is not None:
            events += self._logins(report)
        return events

    def _logins(self, report: SecurityReport) -> list[HostAlertEvent]:
        accepted = report.logins.accepted if report.logins else ()
        newest = max((e.timestamp for e in accepted), default=None)
        if self._login_watermark is None:
            self._login_watermark = newest or time.time()
            return []
        mode = self.notifications.notify_on_ssh_login
        client_ip = report.raw.ssh_client
        events = []
        for login in sorted(accepted, key=lambda e: e.timestamp):
            if login.timestamp <= self._login_watermark:
                continue
            if login.user == self.server.username and login.source == client_ip:
                continue  # reconexão do próprio monitor
            if mode == "all" or (mode == "root" and login.user == "root"):
                events.append(self._event("login", f"login:{login.user}:{login.source}:{int(login.timestamp)}",
                                          f"Login SSH de {login.user} em {self.server.name}",
                                          f"origem {login.source} · método {login.method}",
                                          "critical" if login.user == "root" else "warning"))
        if newest is not None:
            self._login_watermark = max(self._login_watermark, newest)
        return events

    # -- VPS: OOM killer e franquia --------------------------------------------

    def vps(self, vps: VpsInfo | None, now: float | None = None) -> list[HostAlertEvent]:
        if vps is None:
            return []
        events = []
        newest = max((k.timestamp for k in vps.oom_kills), default=None)
        if self._oom_watermark is None:
            self._oom_watermark = newest or (now or time.time())
        else:
            fresh = [k for k in vps.oom_kills if k.timestamp > self._oom_watermark]
            if fresh:
                names = ", ".join(dict.fromkeys(k.process for k in fresh))
                events.append(self._event("oom", f"oom:{int(max(k.timestamp for k in fresh))}",
                                          f"Memória esgotada em {self.server.name}",
                                          f"O OOM killer encerrou: {names}.", "critical"))
                self._oom_watermark = max(k.timestamp for k in fresh)

        quota = self.server.bandwidth_quota_gb
        used = vps.bandwidth_total(self.server.bandwidth_count)
        if quota and used is not None and vps.bandwidth:
            period = vps.bandwidth[0].period
            fraction = used / (quota * 1024 ** 3)
            reached = max((step for step in BANDWIDTH_STEPS if fraction >= step), default=0.0)
            if reached > self._bandwidth_steps.get(period, 0.0):
                self._bandwidth_steps[period] = reached
                what = "enviado" if self.server.bandwidth_count == "tx" else "total"
                events.append(self._event("bandwidth", f"bandwidth:{period}:{reached}",
                                          f"Franquia de tráfego em {fraction * 100:.0f}% — {self.server.name}",
                                          f"{used / 1024 ** 3:.1f} GB ({what}) de {quota:g} GB em {period}.",
                                          "critical" if reached >= 1.0 else "warning"))
        return events
