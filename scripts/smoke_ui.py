"""Teste de fumaça da interface: abre o painel em modo demonstração, passa pelos
diálogos principais (Conexões, mudança segura, novo contêiner, pedido de senha)
e salva capturas de tela. Sai com código 1 se algo falhar.

    python scripts/smoke_ui.py --out capturas

Usado no CI (runner Windows) e útil localmente para conferir a interface.
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CONNECTOR_LABELS, get_session_secret  # noqa: E402
from core.backups import BackupStore  # noqa: E402
from core.demo import demo_client_factory, demo_config  # noqa: E402
from core.models import ConnectionEvent, ConnectionState, ServiceAction  # noqa: E402
from core.monitor import MonitorManager  # noqa: E402
from core.notifier import Notifier  # noqa: E402
from ui.change_dialog import ChangeDialog  # noqa: E402
from ui.connections_dialog import ConnectionsDialog  # noqa: E402
from ui.dashboard import Dashboard  # noqa: E402
from ui.new_container_dialog import NewContainerDialog  # noqa: E402
from ui.secret_prompt import SecretPromptDialog  # noqa: E402
from ui.theme import apply_theme  # noqa: E402
from ui.widgets import ConfirmDialog  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("capturas"))
    parser.add_argument("--timeout", type=float, default=30.0, help="espera máxima de cada etapa (s)")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    apply_theme("dark")
    config = demo_config()
    manager = MonitorManager(config, client_factory=demo_client_factory, backups=BackupStore(None))
    notifier = Notifier(config.settings.notifications)
    notifier.muted = True
    app = Dashboard(config, manager, notifier, on_quit=manager.stop)
    app.geometry("1280x800+0+0")
    failures: list[str] = []
    app.report_callback_exception = lambda *exc: failures.append("".join(traceback.format_exception(*exc)))
    manager.start()

    def find(cls, root=None):
        for widget in (root or app).winfo_children():
            if isinstance(widget, cls):
                return widget
            found = find(cls, widget)
            if found is not None:
                return found
        return None

    def shown(cls):
        """O diálogo já está na tela? No Windows o CustomTkinter esconde a janela ao criá-la e só a
        mostra ~200 ms depois (para pintar a barra de título); fechar antes disso gera erro do Tk."""
        widget = find(cls)
        try:
            return widget if widget is not None and widget.winfo_viewable() else None
        except Exception:  # noqa: BLE001 - destruída no meio do caminho
            return None

    def shot(name: str) -> None:
        app.update()
        try:
            from PIL import ImageGrab

            grab = ImageGrab.grab(all_screens=True) if sys.platform == "win32" else ImageGrab.grab()
            grab.save(args.out / f"{name}.png")
            print(f"  captura: {name}.png")
        except Exception as exc:  # noqa: BLE001 - captura é informativa
            print(f"  (sem captura {name}: {exc})")

    def until(predicate, what: str):
        return predicate, what

    def pause(seconds: float):
        end = time.monotonic() + seconds
        return (lambda: time.monotonic() >= end), f"pausa de {seconds} s"

    def scenario():
        print("1. painel em modo demonstração")
        yield until(lambda: app.snapshot("prod-web-01") is not None, "primeira coleta de prod-web-01")
        shot("01-visao-geral")

        print("2. aba Contêineres")
        app.select_server("prod-web-01", tab="Contêineres")
        yield pause(1.5)
        shot("02-conteineres")

        print("3. Servidores e conexões: todos os servidores e conectores")
        app.open_connections("prod-web-01")
        yield until(lambda: shown(ConnectionsDialog), "diálogo Conexões")
        dialog = find(ConnectionsDialog)
        dialog.geometry("1080x740+40+20")
        for server in config.servers:
            dialog._load(server.name)
            dialog.update()
            form = dialog._form()
            assert form["name"] == server.name, form
            assert form["connector"]["type"] == server.connector.type, (server.name, form["connector"])
        dialog._load("prod-web-01")
        shot("03-conexoes-cloudflared")
        for label in CONNECTOR_LABELS.values():
            dialog.w["connector"].set(label)
            dialog._update_visibility()
            dialog.update()
        dialog.destroy()

        print("4. mudança segura: parar o Redis (análise, proteções, execução, verificação)")
        tab = app._tabs["Contêineres"]
        tab.tables["Contêineres"].select_key("docker:shop-redis-1")
        tab._update_actions()
        tab._service_action(ServiceAction.STOP)
        yield until(lambda: (d := shown(ChangeDialog)) is not None and d.prepared is not None, "análise de risco")
        change = find(ChangeDialog)
        assert change.risk_badge.cget("text") not in ("ANALISANDO…", "SEM ANÁLISE"), change.risk_badge.cget("text")
        print(f"  risco: {change.risk_badge.cget('text')}")
        shot("04-mudanca-analise")
        change._execute()
        yield until(lambda: getattr(change, "record", None) is not None, "fim da mudança")
        assert change.record.outcome in ("ok", "warning"), change.record.steps
        print(f"  resultado: {change.record.outcome} · {[b.cget('text') for b in change.after_buttons]}")
        shot("05-mudanca-concluida")
        change._close()

        print("5. parar o túnel de acesso é crítico e exige digitar o nome")
        tab.tables["Contêineres"].select_key("docker:cloudflared")
        tab._update_actions()
        tab._service_action(ServiceAction.STOP)
        yield until(lambda: (d := shown(ChangeDialog)) is not None and d.prepared is not None, "análise do túnel")
        change = find(ChangeDialog)
        assert "CRÍTICO" in change.risk_badge.cget("text").upper(), change.risk_badge.cget("text")
        assert change.run_btn.cget("state") == "disabled"
        change.confirm_entry.insert(0, "cloudflared")
        change._update_run_state()
        assert change.run_btn.cget("state") == "normal"
        shot("06-tunel-critico")
        change._close()

        print("6. novo contêiner")
        app.open_new_container("prod-web-01")
        yield until(lambda: shown(NewContainerDialog), "formulário de novo contêiner")
        form = find(NewContainerDialog)
        form.fields["image"].insert(0, "nginx:1.27-alpine")
        form.fields["name"].insert(0, "web-smoke")
        form.fields["ports"].insert(0, "127.0.0.1:8089:80")
        shot("07-novo-conteiner")
        form._submit()
        yield until(lambda: (d := shown(ChangeDialog)) is not None and d.prepared is not None, "análise do novo")
        change = find(ChangeDialog)
        assert not change.prepared.assessment.blockers, change.prepared.assessment.blockers
        change._execute()
        yield until(lambda: getattr(change, "record", None) is not None, "criação")
        assert change.record.outcome in ("ok", "warning"), change.record.steps
        change._close()

        print("7. senha pedida ao conectar")
        manager.events.put(ConnectionEvent(server="prod-db-01", timestamp=time.time(),
                                           state=ConnectionState.RECONNECTING, retry_in=30,
                                           message="Senha de monitor@10.0.10.31:22 necessária.",
                                           needs="password", needs_target="prod-db-01"))
        yield until(lambda: shown(SecretPromptDialog), "pedido de senha")
        prompt = find(SecretPromptDialog)
        shot("08-pedido-de-senha")
        prompt.entry.insert(0, "senha-de-teste")
        prompt._submit()
        assert get_session_secret("prod-db-01", "password") == "senha-de-teste"

        print("8. login do Cloudflare Access (recusado: não pergunta de novo)")
        manager.events.put(ConnectionEvent(server="prod-web-01", timestamp=time.time(),
                                           state=ConnectionState.RECONNECTING, retry_in=30,
                                           message="Sem login no Cloudflare Access.",
                                           needs="cloudflare-login", needs_target="prod-web-01"))
        yield until(lambda: shown(ConfirmDialog), "pergunta do login")
        find(ConfirmDialog)._cancel()
        yield pause(0.5)

        print("9. histórico de mudanças")
        tab._switch("Mudanças")
        yield pause(1.0)
        records = manager.change_records("prod-web-01")
        assert len(records) >= 2, records
        shot("09-historico-de-mudancas")

    steps = scenario()
    state: dict = {"current": None, "deadline": 0.0}

    def finish(code: int) -> None:
        state["code"] = code
        app.after(200, app.quit_app)

    def advance() -> None:
        try:
            predicate, what = state["current"] or next(steps)
        except StopIteration:
            finish(1 if failures else 0)
            return
        except Exception:  # noqa: BLE001
            failures.append(traceback.format_exc())
            finish(1)
            return
        if state["current"] is None:
            state["current"] = (predicate, what)
            state["deadline"] = time.monotonic() + args.timeout
        try:
            ready = predicate()
        except Exception:  # noqa: BLE001
            ready = False
        if ready:
            state["current"] = None
            app.after(50, advance)
        elif failures:
            finish(1)
        elif time.monotonic() > state["deadline"]:
            failures.append(f"tempo esgotado esperando: {what}")
            finish(1)
        else:
            app.after(100, advance)

    app.after(500, advance)
    app.mainloop()
    for failure in failures:
        print("FALHA:", failure, file=sys.stderr)
    print("OK: interface verificada" if not failures else f"{len(failures)} falha(s)")
    return state.get("code", 1)


if __name__ == "__main__":
    sys.exit(main())
