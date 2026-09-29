"""Tema ciano: tokens de cor (modo claro, modo escuro) e aplicação no CustomTkinter
e na barra de título do Windows.

Contrastes verificados (WCAG): texto branco sobre o ciano dos botões (#0e7490)
5,4:1; texto secundário sobre os cartões 5,8:1 (claro) e 6,8:1 (escuro). A
paleta dos gráficos (ui/widgets.py) foi validada separadamente contra as
superfícies dos cartões (daltonismo, contraste e separação entre séries).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import customtkinter as ctk

from core import winapi

log = logging.getLogger(__name__)

Color = tuple[str, str]

# Superfícies
WINDOW_BG: Color = ("#e6f1f4", "#081317")
CARD_BG: Color = ("#f9fcfd", "#102229")
PANEL_BG: Color = ("#dbeaee", "#173139")
PANEL_HOVER: Color = ("#c6dee4", "#1f3f4a")
BORDER: Color = ("#b3cfd7", "#24444f")

# Acento ciano
ACCENT: Color = ("#0e7490", "#0e7490")
ACCENT_HOVER: Color = ("#155e75", "#0891b2")
#: Barras de progresso e destaques gráficos (não textuais: >= 3:1 sobre o cartão).
ACCENT_BRIGHT: Color = ("#0891b2", "#06b6d4")
#: Texto em ciano (marca, títulos de seção).
ACCENT_TEXT: Color = ("#0e7490", "#22d3ee")

# Texto
TEXT: Color = ("#102a33", "#e3f2f5")
TEXT_SECONDARY: Color = ("#4f6a73", "#8fabb3")
TEXT_MUTED: Color = ("#5a747d", "#7d9aa3")

# Botões neutros (logs, copiar, terminal)
NEUTRAL: Color = ("#c9dde2", "#1f3a44")
NEUTRAL_HOVER: Color = ("#b5d0d7", "#284a56")

# Faixas de aviso
BANNER_WARN: Color = ("#fff4d6", "#3a2f06")
BANNER_ERROR: Color = ("#fde8e8", "#43161b")
BANNER_INFO: Color = ("#d9f2f7", "#0b3340")

THEME_FILE = "cyan.json"


def resource_path(*parts: str) -> Path:
    """Arquivo empacotado: pasta do projeto ou ``sys._MEIPASS`` no executável."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base.joinpath(*parts)


def apply_theme(appearance_mode: str) -> None:
    ctk.set_appearance_mode(appearance_mode)
    path = resource_path("ui", "themes", THEME_FILE)
    try:
        ctk.set_default_color_theme(str(path))
    except (OSError, ValueError):
        log.warning("Tema %s indisponível; usando o tema padrão", path, exc_info=True)
        ctk.set_default_color_theme("dark-blue")


def is_dark() -> bool:
    return ctk.get_appearance_mode() == "Dark"


def style_window(window, *, accent: bool = True) -> None:
    """Barra de título escura/clara com borda e legenda na cor do tema (Windows 11)."""
    if not winapi.IS_WINDOWS:
        return
    dark = is_dark()
    index = 1 if dark else 0
    try:
        if accent:
            winapi.style_title_bar(window, dark=dark, caption=WINDOW_BG[index], border=ACCENT_BRIGHT[index],
                                   text=TEXT[index])
        else:
            winapi.style_title_bar(window, dark=dark)
    except Exception:  # noqa: BLE001 - puramente cosmético
        log.debug("Falha ao estilizar a barra de título", exc_info=True)
