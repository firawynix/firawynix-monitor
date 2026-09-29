"""Notificações nativas do Windows (toast) com fallback.

Ordem de tentativa: ``win11toast`` (WinRT, Windows 10/11) → ``plyer`` (balão
clássico) → ícone da bandeja (``pystray``) → apenas log. Todas as chamadas são
não bloqueantes: o envio acontece em uma thread daemon.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from config.settings import APP_NAME, NotificationSettings

log = logging.getLogger(__name__)

TrayFallback = Callable[[str, str], None]


class Notifier:
    def __init__(self, settings: NotificationSettings, *, icon_path: Path | None = None) -> None:
        self.settings = settings
        self.icon_path = icon_path
        self.muted = False
        self._tray_fallback: TrayFallback | None = None
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._backend: str | None = None

    def set_tray_fallback(self, callback: TrayFallback | None) -> None:
        self._tray_fallback = callback

    def notify(self, title: str, message: str, *, key: str | None = None, force: bool = False) -> bool:
        """Envia um toast. ``key`` aplica o cooldown (evita spam do mesmo alerta)."""
        if not force and (not self.settings.enabled or self.muted):
            log.info("Notificação suprimida: %s — %s", title, message)
            return False
        if key is not None and not force:
            with self._lock:
                now = time.monotonic()
                last = self._last_sent.get(key)
                if last is not None and now - last < self.settings.cooldown_seconds:
                    log.info("Notificação em cooldown (%s): %s", key, title)
                    return False
                self._last_sent[key] = now
        threading.Thread(target=self._send, args=(title, message), name="toast", daemon=True).start()
        return True

    # -- backends -------------------------------------------------------------

    def _send(self, title: str, message: str) -> None:
        log.info("Notificação: %s — %s", title, message)
        for name, sender in self._senders():
            try:
                sender(title, message)
            except Exception:  # noqa: BLE001 - tenta o próximo backend
                log.debug("Backend de notificação %s falhou", name, exc_info=True)
                continue
            if self._backend != name:
                self._backend = name
                log.info("Backend de notificação ativo: %s", name)
            return
        log.warning("Nenhum backend de notificação disponível")

    def _senders(self) -> list[tuple[str, Callable[[str, str], None]]]:
        senders: list[tuple[str, Callable[[str, str], None]]] = []
        if sys.platform == "win32":
            senders.append(("win11toast", self._send_win11toast))
        senders.append(("plyer", self._send_plyer))
        if self._tray_fallback is not None:
            senders.append(("tray", self._tray_fallback))
        return senders

    def _send_win11toast(self, title: str, message: str) -> None:
        from win11toast import notify

        # on_click="" substitui o launch padrão do win11toast ("http:"), que abriria o navegador.
        kwargs: dict = {"title": title, "body": message, "on_click": ""}
        if self.settings.app_id:
            kwargs["app_id"] = self.settings.app_id
        if self.icon_path is not None and self.icon_path.is_file():
            kwargs["icon"] = {"placement": "appLogoOverride", "src": str(self.icon_path.resolve())}
        notify(**kwargs)

    def _send_plyer(self, title: str, message: str) -> None:
        from plyer import notification

        kwargs: dict = {"title": title[:63], "message": message[:255], "app_name": APP_NAME, "timeout": 10}
        if sys.platform == "win32" and self.icon_path is not None:
            ico = self.icon_path.with_suffix(".ico")
            if ico.is_file():
                kwargs["app_icon"] = str(ico)
        notification.notify(**kwargs)
