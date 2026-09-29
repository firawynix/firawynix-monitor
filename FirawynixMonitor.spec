# -*- mode: python ; coding: utf-8 -*-
# PyInstaller: gera dist/FirawynixMonitor.exe (arquivo único, sem janela de console).
#
#   pyinstaller --noconfirm --clean FirawynixMonitor.spec
#
# Ou use scripts/build.ps1, que também cria o ambiente virtual e roda os testes.
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH)
ICON = ROOT / "assets" / "app.ico"
VERSION_FILE = ROOT / "packaging" / "version_info.txt"

# Temas JSON e fontes do CustomTkinter não são detectados pela análise estática;
# o tema ciano do app vai em ui/themes (lido via sys._MEIPASS em ui/theme.py).
datas = collect_data_files("customtkinter")
datas.append((str(ROOT / "ui" / "themes" / "cyan.json"), "ui/themes"))

# Backends carregados dinamicamente (pystray/plyer escolhem a implementação em
# tempo de execução; win11toast importa módulos WinRT nativos).
if sys.platform == "win32":
    hiddenimports = [
        "pystray._win32",
        "plyer.platforms.win.notification",
        "plyer.platforms.win.libs.balloontip",
        "win11toast",
        *collect_submodules("winrt"),
    ]
else:
    hiddenimports = ["pystray._xorg", "plyer.platforms.linux.notification"]
# ImageTk (ícones de status da tabela) depende deste módulo, que o hook do PIL omite.
hiddenimports.append("PIL._tkinter_finder")

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["pytest", "_pytest", "pydoc", "unittest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="FirawynixMonitor",
    console=False,
    icon=str(ICON) if ICON.exists() else None,
    version=str(VERSION_FILE) if sys.platform == "win32" else None,
    upx=False,  # UPX costuma gerar falso positivo em antivírus
    strip=False,
    debug=False,
)
