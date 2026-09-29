"""Ícone na bandeja do sistema (pystray) e geração dos ícones da aplicação.

O pystray roda o próprio loop de mensagens em outra thread. Os callbacks do
menu NUNCA tocam no Tkinter diretamente: eles recebem funções que o Dashboard
enfileira para a thread da UI (``Dashboard.call_in_ui``).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from PIL import Image, ImageDraw

from core.models import HealthLevel

log = logging.getLogger(__name__)

HEALTH_COLORS = {
    HealthLevel.OK: "#2ecc71",
    HealthLevel.UNKNOWN: "#8b949e",
    HealthLevel.WARNING: "#f1c40f",
    HealthLevel.CRITICAL: "#ff4d4f",
}
_BACKGROUND = "#161b22"
_PULSE = "#58a6ff"
ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def create_icon_image(level: HealthLevel | None = None, size: int = 64) -> Image.Image:
    """Quadrado arredondado com linha de "batimento" e LED de status.

    Desenhado em 256 px e reduzido com LANCZOS para bordas suaves.
    """
    scale = 256
    image = Image.new("RGBA", (scale, scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((8, 8, scale - 8, scale - 8), radius=56, fill=_BACKGROUND)
    pulse = [(36, 140), (84, 140), (108, 84), (140, 196), (166, 116), (182, 140), (220, 140)]
    draw.line(pulse, fill=_PULSE, width=18, joint="curve")
    if level is not None:
        color = HEALTH_COLORS[level]
        draw.ellipse((158, 158, 244, 244), fill=_BACKGROUND)
        draw.ellipse((170, 170, 232, 232), fill=color)
    return image.resize((size, size), Image.Resampling.LANCZOS)


def export_app_icons(target_dir: Path) -> tuple[Path, Path]:
    """Grava ``app.png`` (toasts) e ``app.ico`` (janela/balões) em ``target_dir``."""
    target_dir.mkdir(parents=True, exist_ok=True)
    png_path = target_dir / "app.png"
    ico_path = target_dir / "app.ico"
    base = create_icon_image(None, 256)
    base.save(png_path, format="PNG")
    base.save(ico_path, format="ICO", sizes=ICO_SIZES)
    return png_path, ico_path


class TrayIcon:
    def __init__(
        self,
        app_name: str,
        *,
        on_open: Callable[[], None],
        on_refresh: Callable[[], None],
        on_toggle_mute: Callable[[bool], None],
        on_quit: Callable[[], None],
    ) -> None:
        self.app_name = app_name
        self._on_open = on_open
        self._on_refresh = on_refresh
        self._on_toggle_mute = on_toggle_mute
        self._on_quit = on_quit
        self._icon = None
        self._muted = False
        self._level: HealthLevel | None = None
        self._images: dict[HealthLevel, Image.Image] = {}

    @property
    def available(self) -> bool:
        return self._icon is not None

    def start(self) -> bool:
        """Cria o ícone. Retorna False se a plataforma não suportar bandeja."""
        try:
            # Import tardio: em Linux sem display o pystray levanta erros ao importar.
            import pystray
        except Exception:  # noqa: BLE001
            log.warning("Bandeja do sistema indisponível; minimizar para a bandeja desativado", exc_info=True)
            return False

        menu = pystray.Menu(
            pystray.MenuItem("Abrir painel", self._handle_open, default=True),
            pystray.MenuItem("Atualizar agora", self._handle_refresh),
            pystray.MenuItem("Silenciar alertas", self._handle_mute, checked=lambda _item: self._muted),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Sair", self._handle_quit),
        )
        try:
            self._icon = pystray.Icon(
                "firawynix-monitor",
                icon=self._image_for(HealthLevel.UNKNOWN),
                title=self.app_name,
                menu=menu,
            )
            self._icon.run_detached()
        except Exception:  # noqa: BLE001
            log.warning("Falha ao iniciar o ícone da bandeja", exc_info=True)
            self._icon = None
            return False
        return True

    def stop(self) -> None:
        icon, self._icon = self._icon, None
        if icon is not None:
            try:
                icon.stop()
            except Exception:  # noqa: BLE001
                log.debug("Erro ao parar ícone da bandeja", exc_info=True)

    def set_health(self, level: HealthLevel, tooltip: str) -> None:
        icon = self._icon
        if icon is None:
            return
        try:
            if level is not self._level:
                icon.icon = self._image_for(level)
                self._level = level
            # Limite do Windows para o tooltip da bandeja: 127 caracteres.
            icon.title = tooltip if len(tooltip) <= 127 else tooltip[:126] + "…"
        except Exception:  # noqa: BLE001
            log.debug("Falha ao atualizar ícone da bandeja", exc_info=True)

    def set_muted(self, muted: bool) -> None:
        self._muted = muted
        if self._icon is not None:
            try:
                self._icon.update_menu()
            except Exception:  # noqa: BLE001
                pass

    def notify(self, title: str, message: str) -> None:
        """Fallback de notificação (balão da bandeja)."""
        if self._icon is None:
            raise RuntimeError("ícone da bandeja indisponível")
        self._icon.notify(message, title)

    # -- callbacks (thread do pystray) ---------------------------------------

    def _image_for(self, level: HealthLevel) -> Image.Image:
        if level not in self._images:
            self._images[level] = create_icon_image(level, 64)
        return self._images[level]

    def _handle_open(self, _icon=None, _item=None) -> None:
        self._on_open()

    def _handle_refresh(self, _icon=None, _item=None) -> None:
        self._on_refresh()

    def _handle_mute(self, _icon=None, _item=None) -> None:
        self._muted = not self._muted
        self._on_toggle_mute(self._muted)

    def _handle_quit(self, _icon=None, _item=None) -> None:
        self._on_quit()
