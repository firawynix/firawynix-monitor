"""Firawynix Monitor — ponto de entrada e ciclo de vida da aplicação.

Uso::

    python main.py                   # usa servers.json (veja README)
    python main.py --config C:\\caminho\\servers.json
    python main.py --minimized       # inicia oculto na bandeja
    python main.py --demo            # servidores simulados, sem SSH
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config.settings import APP_NAME, ConfigError, find_config, load_config, user_data_dir
from core import __version__

log = logging.getLogger("firawynix")

APP_TITLE = "Firawynix Monitor"
_MUTEX_NAME = "Local\\FirawynixMonitorSingleInstance"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=APP_NAME, description="Monitor de serviços systemd/Docker via SSH.")
    parser.add_argument("--config", metavar="ARQUIVO", help="caminho do servers.json")
    parser.add_argument("--minimized", action="store_true", help="inicia oculto na bandeja do sistema")
    parser.add_argument("--demo", action="store_true", help="usa servidores simulados (sem SSH)")
    parser.add_argument("--debug", action="store_true", help="log detalhado")
    parser.add_argument("--set-credential", metavar="SERVIDOR",
                        help="grava a senha SSH do servidor no Gerenciador de Credenciais do Windows e sai")
    parser.add_argument("--passphrase", action="store_true",
                        help="com --set-credential/--delete-credential: passphrase da chave em vez da senha")
    parser.add_argument("--delete-credential", metavar="SERVIDOR",
                        help="remove a credencial do servidor do Gerenciador de Credenciais e sai")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def configure_logging(debug: bool) -> Path:
    log_dir = user_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "monitor.log"
    handlers: list[logging.Handler] = [
        RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"),
    ]
    if sys.stderr is not None:  # executável --noconsole não tem stderr
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    for noisy in ("paramiko", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    def thread_excepthook(args: threading.ExceptHookArgs) -> None:
        log.error("Exceção não tratada na thread %s", args.thread.name if args.thread else "?",
                  exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    threading.excepthook = thread_excepthook
    sys.excepthook = lambda *exc: log.critical("Exceção não tratada", exc_info=exc)
    return log_file


def acquire_single_instance():
    """Mutex nomeado do Windows: impede duas instâncias (e dois ícones na bandeja)."""
    if sys.platform != "win32":
        return True
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    error_already_exists = 183
    if not handle or ctypes.get_last_error() == error_already_exists:
        return None
    return handle


def open_history(settings, *, demo: bool):
    """Histórico em SQLite (em memória no modo demo, para não misturar dados)."""
    if not settings.history.enabled:
        return None
    from core.history import HistoryStore

    path = None if demo else (settings.history.file or user_data_dir() / "history.sqlite3")
    store = HistoryStore(path, retention_days=settings.history.retention_days)
    log.info("Histórico: %s (retenção de %g dias)", path or "memória", settings.history.retention_days)
    return store


def manage_credential(config_path, server_name: str, *, passphrase: bool, delete: bool) -> int:
    """CLI do Gerenciador de Credenciais. A senha é lida com getpass (sem eco) e
    nunca aparece em argumentos de linha de comando, no histórico ou em log."""
    import getpass

    from config.settings import load_config
    from core import winapi

    if not winapi.IS_WINDOWS:
        print("O Gerenciador de Credenciais só existe no Windows.", file=sys.stderr)
        return 2
    if sys.stdin is None or not sys.stdin.isatty():
        # O .exe é um aplicativo de janela (sem console): não há onde digitar a senha.
        show_fatal(APP_TITLE, "Sem console para digitar a senha. Use o botão \"Windows ⚙\" > Credenciais no "
                              f"monitor, ou no PowerShell:\n\ncmdkey /generic:{winapi.credential_target(server_name)} "
                              "/user:<usuario> /pass")
        return 2
    kind = "passphrase" if passphrase else "password"
    target, username = winapi.credential_target(server_name, kind), ""
    try:
        server = load_config(find_config(config_path), load_env=False).server(server_name)
        configured = server.key_passphrase_credential if passphrase else server.password_credential
        target, username = configured or target, server.username
    except (ConfigError, KeyError):
        print(f"Aviso: servidor '{server_name}' não encontrado no servers.json; usando o nome padrão {target}.")
    if delete:
        removed = winapi.cred_delete(target)
        print(f"Credencial {target} {'removida' if removed else 'não encontrada'}.")
        return 0 if removed else 1
    label = "Passphrase da chave" if passphrase else "Senha SSH"
    secret = getpass.getpass(f"{label} para {server_name} ({target}): ")
    if not secret or secret != getpass.getpass("Confirme: "):
        print("Vazio ou não confere; nada foi gravado.", file=sys.stderr)
        return 1
    winapi.cred_write(target, secret, username)
    key = "key_passphrase_credential" if passphrase else "password_credential"
    print(f"Credencial gravada em {target}. No servers.json use \"{key}\": true (ou \"{target}\").")
    return 0


def show_fatal(title: str, message: str) -> None:
    log.error("%s: %s", title, message)
    try:
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror(title, message, parent=root)
        root.destroy()
    except Exception:  # noqa: BLE001 - sem Tk disponível, resta o stderr
        if sys.stderr is not None:
            print(f"{title}: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.set_credential or args.delete_credential:
        return manage_credential(args.config, args.set_credential or args.delete_credential,
                                 passphrase=args.passphrase, delete=bool(args.delete_credential))
    log_file = configure_logging(args.debug)
    log.info("%s %s iniciando (Python %s, log em %s)", APP_TITLE, __version__, sys.version.split()[0], log_file)

    from core.monitor import MonitorManager, default_client_factory

    if args.demo:
        from core.demo import demo_client_factory, demo_config

        app_config, client_factory = demo_config(), demo_client_factory
    else:
        try:
            config_path = find_config(args.config)
            app_config = load_config(config_path)
        except ConfigError as exc:
            show_fatal(f"{APP_TITLE} — configuração", str(exc))
            return 2
        client_factory = default_client_factory
        log.info("Configuração carregada de %s (%d servidores)", config_path, len(app_config.servers))

    instance_lock = acquire_single_instance()
    if instance_lock is None:
        show_fatal(APP_TITLE, "O Firawynix Monitor já está em execução (verifique a bandeja do sistema).")
        return 1

    # Imports de UI só depois da configuração validada (inicialização mais rápida em erro).
    from config.preferences import Preferences, apply_engine_preferences
    from config.settings import user_config_dir
    from core.notifier import Notifier
    from ui.dashboard import Dashboard
    from ui.theme import apply_theme
    from ui.tray import TrayIcon, export_app_icons

    settings = app_config.settings
    icon_png = icon_ico = None
    try:
        icon_png, icon_ico = export_app_icons(user_data_dir() / "icons")
    except OSError:
        log.warning("Não foi possível gerar os ícones da aplicação", exc_info=True)

    apply_theme(settings.appearance_mode)
    preferences = Preferences(None if args.demo else user_config_dir() / "preferences.json")
    app_config = apply_engine_preferences(app_config, preferences)

    history = open_history(settings, demo=args.demo)
    if args.demo and history is not None:
        from core.demo import seed_demo_history

        seed_demo_history(history, app_config)

    notifier = Notifier(settings.notifications, icon_path=icon_png)
    from core.backups import BackupStore

    # Backups das mudanças e histórico: neste PC (%LOCALAPPDATA%); no modo demonstração, só em memória.
    backups = BackupStore(None if args.demo else user_data_dir() / "backups")
    manager = MonitorManager(app_config, client_factory=client_factory, history=history, backups=backups)
    tray: TrayIcon | None = None

    def shutdown() -> None:
        manager.stop()
        if tray is not None:
            tray.stop()
        if history is not None:
            history.close()

    app = Dashboard(app_config, manager, notifier, history=history, icon_path=icon_ico, on_quit=shutdown,
                    preferences=preferences)
    if args.demo:
        app.title(f"{APP_TITLE} — DEMONSTRAÇÃO")

    if settings.minimize_to_tray:
        tray = TrayIcon(
            APP_TITLE,
            on_open=lambda: app.call_in_ui(app.show_window),
            on_refresh=lambda: app.call_in_ui(app.refresh_all),
            on_toggle_mute=lambda muted: app.call_in_ui(lambda: app.set_muted(muted)),
            on_quit=lambda: app.call_in_ui(app.quit_app),
            on_toggle_autostart=(lambda enabled: app.call_in_ui(lambda: app.set_autostart(enabled)))
            if sys.platform == "win32" else None,
            autostart_state=app.autostart_enabled,
        )
        if tray.start():
            app.attach_tray(tray)
            notifier.set_tray_fallback(tray.notify)
        else:
            tray = None

    manager.start()
    if (args.minimized or settings.start_minimized) and app.can_hide_to_tray:
        app.withdraw()

    try:
        app.mainloop()
    except KeyboardInterrupt:
        log.info("Interrompido pelo usuário")
    finally:
        shutdown()
        log.info("Encerrado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
