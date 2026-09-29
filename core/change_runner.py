"""Executor das mudanças seguras.

Segue exatamente o roteiro mostrado ao usuário antes da confirmação
(:func:`core.changes.plan_steps`): conferir → salvar → parar → backup → agir →
confirmar → registrar. Passos longos (parada graciosa de 30 s, commit, backup
de volumes, pull) rodam em segundo plano no servidor e são acompanhados por
comandos curtos, respeitando o limite de 5 s por comando SSH.

Regra de segurança: se uma proteção falha ANTES da ação destrutiva, a mudança
para ali (nada é removido sem backup); se falha depois de o contêiner já ter
sido parado, o painel avisa e mantém o caminho de volta (iniciar/restaurar).
"""

from __future__ import annotations

import json
import logging
import secrets
import shlex
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol

from core import containers as engines
from core.backups import BackupStore, ChangeRecord
from core.changes import (
    BACKUP_SCRIPT,
    ChangeAction,
    ContainerSpec,
    JobState,
    Risk,
    backup_file_name,
    build_job_cleanup,
    build_job_poll,
    build_job_start,
    compose_hint,
    parse_job_poll,
    plan_steps,
    run_args,
    shell_join,
    snapshot_image,
    spec_from_inspect,
    state_from_inspect,
    validate_spec,
    volume_backup_args,
)
from core.commands import validate_container_name
from core.models import ChangeProgressEvent, ServiceInfo

log = logging.getLogger(__name__)


class StepError(Exception):
    pass


@dataclass(frozen=True)
class BackupTarget:
    directory: str = ""
    owner: str = ""
    #: Script do administrador para backups com sudo (docs/firawynix-volume-backup).
    script: str = ""
    error: str = ""


@dataclass(frozen=True)
class ShellResult:
    ok: bool
    output: str


class ChangeBackend(Protocol):
    def executable(self, engine: str) -> str: ...
    def inspect(self, engine: str, name: str) -> dict | None: ...
    def image_config(self, engine: str, image: str) -> dict | None: ...
    def exec(self, engine: str, args: Sequence[str]) -> ShellResult: ...
    def start_job(self, job_id: str, command: str) -> ShellResult: ...
    def poll_job(self, job_id: str) -> JobState: ...
    def cleanup_job(self, job_id: str) -> None: ...
    def file_size(self, path: str) -> int | None: ...
    def logs_tail(self, engine: str, name: str, lines: int = 20) -> str: ...
    def backup_target(self, engine: str) -> BackupTarget: ...


def new_change_id(action: ChangeAction) -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{action.value}-{secrets.token_hex(2)}"


@dataclass
class ChangeRequest:
    id: str
    server: str
    action: ChangeAction
    engine: str
    name: str
    risk: Risk = Risk.LOW
    service: ServiceInfo | None = None
    spec: ContainerSpec | None = None
    protections: frozenset[str] = frozenset()
    stop_timeout: int = 10
    source_record: ChangeRecord | None = None
    use_snapshot: bool = False
    steps: tuple[str, ...] = field(default=())


class ChangeRunner:
    POLL = 1.0

    def __init__(self, backend: ChangeBackend, store: BackupStore, emit: Callable[[ChangeProgressEvent], None],
                 request: ChangeRequest, *, expect_stop: Callable[[str], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        self.backend = backend
        self.store = store
        self.emit = emit
        self.request = request
        self.expect_stop = expect_stop or (lambda _key: None)
        self.sleep = sleep
        self.clock = clock
        self.inspect: dict | None = None
        self.record = ChangeRecord(id=request.id, time=time.time(), server=request.server, target=request.name,
                                   engine=request.engine, action=request.action.value, risk=request.risk.label)
        self._done_early = False
        self._current = -1
        self._handlers: dict[str, Callable[[], str]] = {
            "Conferir o estado atual e as pré-condições": self._check,
            "Salvar a definição do contêiner neste PC": self._save_definition,
            "Parar com desligamento gracioso": self._stop,
            "Confirmar que parou": self._verify_stopped,
            "Snapshot do contêiner (commit)": self._snapshot,
            "Backup dos volumes com o contêiner parado": self._backup_volumes,
            "Iniciar": self._start,
            "Reiniciar": self._restart,
            "Confirmar que está rodando e estável": self._verify_running,
            "Pausar": lambda: self._simple("pause", "pausado"),
            "Retomar": lambda: self._simple("unpause", "retomado"),
            "Confirmar o estado": self._verify_pause_state,
            "Remover o contêiner (volumes são mantidos)": self._remove,
            "Confirmar a remoção": self._verify_removed,
            "Baixar a imagem, se necessário": self._pull_if_needed,
            "Criar e iniciar": self._create,
            "Conferir a imagem (original ou snapshot)": self._restore_image,
            "Recriar com a definição salva": self._create,
            "Registrar no histórico de mudanças (com opção de iniciar/restaurar)": self._record,
        }

    # -- execução --------------------------------------------------------------

    def steps(self) -> tuple[str, ...]:
        request = self.request
        return request.steps or plan_steps(request.action, (), request.service, request.protections)

    def run(self) -> ChangeRecord:
        steps = self.steps()
        self._emit(steps=steps, status="pending")
        self.store.append(self.record)
        outcome = "ok"
        for index, label in enumerate(steps):
            is_record = label.startswith("Registrar")
            if outcome == "error" and not is_record or self._done_early and not is_record:
                self.record.steps.append((label, "skipped", "não executado"))
                self._step(index, "skipped", "não executado")
                continue
            if is_record:
                self.record.outcome = outcome
            self._current = index
            self._step(index, "running", "")
            try:
                message = self._handlers[label]()
                status = "ok"
                if message.startswith("!"):
                    status, message = "warning", message[1:]
                    outcome = "warning" if outcome == "ok" else outcome
            except StepError as exc:
                status, message = "error", str(exc)
                outcome = "error"
            except Exception as exc:  # noqa: BLE001 - nunca deixa o diálogo sem resposta
                log.exception("[%s] erro no passo %s da mudança %s", self.request.server, label, self.request.id)
                status, message = "error", f"erro inesperado: {exc}"
                outcome = "error"
            self.record.steps.append((label, status, message))
            self._step(index, status, message)
        self.record.outcome = outcome
        failed = next((m for _l, s, m in self.record.steps if s == "error"), "")
        self.record.message = failed or next((m for _l, s, m in reversed(self.record.steps)
                                              if s in ("ok", "warning") and not _l.startswith("Registrar")), "")
        self.store.append(self.record)
        self._emit(finished=True, outcome=outcome, message=self.record.message, record_id=self.record.id)
        return self.record

    def _emit(self, **kwargs) -> None:
        self.emit(ChangeProgressEvent(server=self.request.server, change_id=self.request.id, **kwargs))

    def _step(self, index: int, status: str, message: str) -> None:
        self._emit(index=index, status=status, message=message)

    # -- auxiliares ---------------------------------------------------------------

    def _state(self):
        self.inspect = self.backend.inspect(self.request.engine, self.request.name)
        return state_from_inspect(self.inspect)

    def _exec(self, args: Sequence[str], what: str) -> str:
        result = self.backend.exec(self.request.engine, args)
        if not result.ok:
            raise StepError(f"{what} falhou: {_first_lines(result.output)}")
        return result.output

    def _job(self, command: str, what: str, deadline: float, index_hint: str = "") -> JobState:
        job_id = f"fwx-{self.request.id}-{secrets.token_hex(2)}"
        started = self.backend.start_job(job_id, command)
        if not started.ok:
            raise StepError(f"não foi possível iniciar '{what}' no servidor: {_first_lines(started.output)}")
        began = self.clock()
        last_note = began
        while True:
            state = self.backend.poll_job(job_id)
            if state.done:
                self.backend.cleanup_job(job_id)
                if state.missing:
                    raise StepError(f"'{what}': a tarefa sumiu do servidor (reinício?)")
                return state
            elapsed = self.clock() - began
            if elapsed > deadline:
                raise StepError(f"'{what}' continua em execução no servidor após {int(elapsed)} s "
                                f"(tarefa {job_id}); acompanhe antes de tentar de novo")
            if self.clock() - last_note >= 5:
                last_note = self.clock()
                self._step(self._current, "running", f"{what}… {int(elapsed)} s{index_hint}")
            self.sleep(self.POLL)

    def _engine_job(self, args: Sequence[str], what: str, deadline: float) -> JobState:
        state = self._job(shell_join(self.backend.executable(self.request.engine), args), what, deadline)
        if state.exit_code != 0:
            raise StepError(f"{what} falhou (código {state.exit_code}): {_first_lines(state.log)}")
        return state

    # -- passos -------------------------------------------------------------------

    def _check(self) -> str:
        request = self.request
        action = request.action
        if action in (ChangeAction.CREATE, ChangeAction.RESTORE):
            spec = request.spec
            if spec is None:
                raise StepError("definição do contêiner ausente")
            validate_spec(spec)
            if self._state() is not None:
                raise StepError(f"já existe um contêiner chamado {spec.name}: remova-o ou use outro nome")
            return f"{spec.name} livre · imagem {spec.image}"
        validate_container_name(request.name)
        state = self._state()
        if state is None:
            raise StepError(f"{request.name} não existe mais no servidor")
        running = state.running or state.status == "restarting"
        if action is ChangeAction.STOP and not running and state.status != "paused":
            self._done_early = True
            return f"já estava parado ({state.status}); nada a fazer"
        if action is ChangeAction.START and running:
            self._done_early = True
            return "já está em execução; nada a fazer"
        if action is ChangeAction.PAUSE and not running:
            raise StepError(f"só é possível pausar um contêiner em execução (estado: {state.status})")
        if action is ChangeAction.UNPAUSE and state.status != "paused":
            raise StepError(f"o contêiner não está pausado (estado: {state.status})")
        return f"estado atual: {state.status}" + (f" · saúde {state.health}" if state.health else "")

    def _save_definition(self) -> str:
        request = self.request
        data = self.inspect or self.backend.inspect(request.engine, request.name)
        if data is None:
            raise StepError("não foi possível ler a definição (inspect)")
        image = str((data.get("Config") or {}).get("Image") or "")
        spec = None
        try:
            spec = spec_from_inspect(data, request.engine, self.backend.image_config(request.engine, image)
                                     if image else None)
        except (ValueError, TypeError) as exc:
            log.info("Definição sem comando de recriação: %s", exc)
        try:
            path = self.store.save_definition(request.server, request.name, request.id, data, spec,
                                              self.backend.executable(request.engine))
        except OSError as exc:
            raise StepError(f"não foi possível gravar neste PC: {exc}") from exc
        self.record.definition_dir = path
        self.record.compose_hint = compose_hint(((k, str(v)) for k, v in
                                                 ((data.get("Config") or {}).get("Labels") or {}).items()))
        return f"salvo em {path}"

    def _stop(self) -> str:
        request = self.request
        state = self._state()
        if state is not None and not state.running and state.status not in ("paused", "restarting"):
            return f"já estava parado ({state.status})"
        if request.service is not None:
            self.expect_stop(request.service.key)
        started = self.clock()
        self._engine_job(["stop", "-t", str(request.stop_timeout), request.name], "Parar",
                         request.stop_timeout + 25)
        return f"parado em {self.clock() - started:.0f} s (limite gracioso de {request.stop_timeout} s)"

    def _verify_stopped(self) -> str:
        state = self._state()
        if state is None:
            raise StepError("o contêiner sumiu durante a parada")
        if state.running:
            raise StepError("continua em execução")
        if state.exit_code == 137:
            return (f"!parado, mas encerrado à força (SIGKILL, código 137): o processo não respondeu ao pedido de "
                    f"desligamento em {self.request.stop_timeout} s. Em bancos de dados isso exige recuperação "
                    "na próxima partida — confira os logs ao iniciar")
        code = f" · código de saída {state.exit_code}" if state.exit_code is not None else ""
        return f"parado ({state.status}{code})"

    def _snapshot(self) -> str:
        image = snapshot_image(self.request.name, self.request.id.split("-", 2)[0] + "-"
                               + self.request.id.split("-", 2)[1])
        self._engine_job(["commit", self.request.name, image], "Snapshot (commit)", 1800)
        self.record.snapshot_image = image
        return f"imagem {image} criada no servidor"

    def _backup_volumes(self) -> str:
        request = self.request
        data = self.inspect or {}
        volumes = [m.get("Name") for m in data.get("Mounts") or [] if m.get("Type") == "volume" and m.get("Name")]
        if not volumes:
            return "!nenhum volume para copiar"
        target = self.backend.backup_target(request.engine)
        if target.error:
            return self._protection_failed(f"backup indisponível: {target.error}")
        stamp = request.id.split("-", 2)
        paths = []
        for position, volume in enumerate(volumes, 1):
            file_name = backup_file_name(request.name, volume[:40], f"{stamp[0]}-{stamp[1]}")
            if target.script:
                command = (f"sudo -n {shlex.quote(target.script)} {shlex.quote(request.engine)} "
                           f"{shlex.quote(volume)} {shlex.quote(file_name)}")
            else:
                command = shell_join(self.backend.executable(request.engine),
                                     volume_backup_args(volume, target.directory, file_name, target.owner))
            try:
                state = self._job(command, f"Backup do volume {volume}", 3600, f" ({position}/{len(volumes)})")
            except StepError as exc:
                return self._protection_failed(str(exc))
            if state.exit_code != 0:
                return self._protection_failed(f"backup de {volume} falhou: {_first_lines(state.log)}")
            path = f"{target.directory}/{file_name}"
            size = self.backend.file_size(path)
            if size == 0:
                return self._protection_failed(f"o backup de {volume} ficou vazio ({path})")
            paths.append(f"{path} ({_fmt_bytes(str(size) if size is not None else '?')})")
        self.record.volume_backups = paths
        return f"{len(paths)} volume(s) copiado(s) no servidor: " + "; ".join(paths)

    def _protection_failed(self, message: str) -> str:
        """Backup falhou: antes de remover, aborta; em parar/reiniciar, só avisa (o caminho de volta existe)."""
        if self.request.action is ChangeAction.REMOVE:
            raise StepError(message + " — remoção cancelada; o contêiner ficou parado (use Iniciar para voltar)")
        return "!" + message

    def _start(self) -> str:
        self._exec(["start", self.request.name], "Iniciar")
        return "comando aceito pelo motor"

    def _restart(self) -> str:
        request = self.request
        if request.service is not None:
            self.expect_stop(request.service.key)
        self._engine_job(["restart", "-t", str(request.stop_timeout), request.name], "Reiniciar",
                         request.stop_timeout + 30)
        return "reiniciado"

    def _simple(self, op: str, done: str) -> str:
        self._exec([op, self.request.name], op)
        return done

    def _verify_pause_state(self) -> str:
        state = self._state()
        expected = "paused" if self.request.action is ChangeAction.PAUSE else "running"
        if state is None or state.status != expected:
            raise StepError(f"estado inesperado: {state.status if state else 'ausente'}")
        return f"estado: {state.status}"

    def _remove(self) -> str:
        state = self._state()
        if state is not None and state.running:
            raise StepError("o contêiner voltou a rodar (política de reinício?) — remoção cancelada")
        self._exec(["rm", self.request.name], "Remover")
        return "removido (volumes mantidos)"

    def _verify_removed(self) -> str:
        if self._state() is not None:
            raise StepError("o contêiner ainda existe")
        extra = " · restauração disponível no histórico" if self.record.definition_dir else ""
        return "não existe mais no servidor" + extra

    def _pull_if_needed(self) -> str:
        spec = self.request.spec
        if self.backend.image_config(self.request.engine, spec.image) is not None:
            return f"imagem {spec.image} já está no servidor"
        started = self.clock()
        self._engine_job(["pull", spec.image], f"Baixar {spec.image}", 1800)
        return f"imagem baixada em {self.clock() - started:.0f} s"

    def _restore_image(self) -> str:
        request = self.request
        spec = request.spec
        record = request.source_record
        if request.use_snapshot and record is not None and record.snapshot_image:
            if self.backend.image_config(request.engine, record.snapshot_image) is None:
                raise StepError(f"o snapshot {record.snapshot_image} não existe mais no servidor")
            request.spec = spec = replace(spec, image=record.snapshot_image)
            return f"usando o snapshot {record.snapshot_image}"
        if self.backend.image_config(request.engine, spec.image) is not None:
            return f"imagem original {spec.image} disponível"
        self._engine_job(["pull", spec.image], f"Baixar {spec.image}", 1800)
        return f"imagem {spec.image} baixada"

    def _create(self) -> str:
        spec = self.request.spec
        output = self._exec(run_args(spec), "Criar")
        for network in spec.extra_networks:
            result = self.backend.exec(self.request.engine, ["network", "connect", network, spec.name])
            if not result.ok:
                return f"!criado, mas sem a rede {network}: {_first_lines(result.output)}"
        container_id = output.strip().splitlines()[-1][:12] if output.strip() else ""
        return f"criado ({container_id})" if container_id else "criado"

    def _verify_running(self) -> str:
        name = self.request.name if self.request.spec is None else self.request.spec.name
        deadline = self.clock() + 30
        state = None
        while self.clock() < deadline:
            state = self._state_of(name)
            if state is not None and state.running:
                break
            if state is not None and state.status in ("exited", "dead", "stopped"):
                logs = _last_lines(self.backend.logs_tail(self.request.engine, name))
                raise StepError(f"parou logo após iniciar (código {state.exit_code}). Últimas linhas do log: {logs}")
            self.sleep(self.POLL)
        if state is None or not state.running:
            raise StepError(f"não entrou em execução em 30 s (estado: {state.status if state else 'ausente'})")
        restarts = state.restarts
        self.sleep(3)
        state = self._state_of(name)
        if state is None or not state.running or (restarts is not None and state.restarts is not None
                                                  and state.restarts > restarts):
            raise StepError("caiu logo depois de iniciar (reiniciando em loop?). Últimas linhas do log: "
                            + _last_lines(self.backend.logs_tail(self.request.engine, name)))
        health_deadline = self.clock() + 45
        while state.health == "starting" and self.clock() < health_deadline:
            self.sleep(2)
            state = self._state_of(name) or state
        if state.health == "unhealthy":
            return "!rodando, mas o healthcheck está falhando (unhealthy)"
        health = f" · saúde {state.health}" if state.health else ""
        return f"rodando e estável{health}"

    def _state_of(self, name: str):
        self.inspect = self.backend.inspect(self.request.engine, name)
        return state_from_inspect(self.inspect)

    def _record(self) -> str:
        where = "neste PC" if self.store.root is not None else "nesta sessão (demonstração)"
        return f"registrado no histórico de mudanças {where}"


def _first_lines(text: str, limit: int = 300) -> str:
    text = " ".join((text or "").strip().split())
    return (text[:limit] + "…") if len(text) > limit else text or "sem detalhes"


def _last_lines(text: str, count: int = 5) -> str:
    lines = [ln.strip() for ln in (text or "").strip().splitlines() if ln.strip()]
    return " | ".join(lines[-count:])[-600:] or "(log vazio)"


def _fmt_bytes(value: str) -> str:
    if not value.isdigit():
        return "tamanho ?"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}".replace(".", ",")
        size /= 1024
    return value


# ---------------------------------------------------------------------------
# Backend SSH
# ---------------------------------------------------------------------------

class SSHChangeBackend:
    """Operações das mudanças seguras sobre o :class:`core.ssh_client.SSHClient`."""

    def __init__(self, client) -> None:
        self.client = client

    def _sudo(self, engine: str) -> bool:
        return engines.engine_sudo(self.client.server, engine)

    def executable(self, engine: str) -> str:
        namespace = self.client.server.nerdctl_namespace if engine == "nerdctl" else ""
        return engines.cli(engine, self._sudo(engine), namespace)

    def _run(self, command: str) -> ShellResult:
        result = self.client.run(command)
        return ShellResult(result.ok, result.output if not result.ok else result.stdout)

    def inspect(self, engine: str, name: str) -> dict | None:
        quoted = shlex.quote(validate_container_name(name))
        result = self.client.run(f"{self.executable(engine)} inspect --size {quoted}")
        if not result.ok and "size" in result.output.lower():
            result = self.client.run(f"{self.executable(engine)} inspect {quoted}")
        if not result.ok:
            return None
        try:
            data = json.loads(result.stdout)
        except ValueError:
            return None
        return data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else None

    def image_config(self, engine: str, image: str) -> dict | None:
        ref = shlex.quote(engines.validate_image_ref(image))
        result = self.client.run(f"{self.executable(engine)} image inspect {ref}")
        if not result.ok:
            return None
        try:
            data = json.loads(result.stdout)
        except ValueError:
            return None
        return (data[0].get("Config") or {}) if isinstance(data, list) and data else None

    def exec(self, engine: str, args: Sequence[str]) -> ShellResult:
        return self._run(shell_join(self.executable(engine), args))

    def start_job(self, job_id: str, command: str) -> ShellResult:
        result = self._run(build_job_start(job_id, command))
        return result if "started" in result.output else ShellResult(False, result.output)

    def poll_job(self, job_id: str) -> JobState:
        return parse_job_poll(self.client.run(build_job_poll(job_id)).stdout)

    def cleanup_job(self, job_id: str) -> None:
        self.client.run(build_job_cleanup(job_id))

    def file_size(self, path: str) -> int | None:
        output = self.client.run(f"stat -c %s {shlex.quote(path)} 2>/dev/null").stdout.strip()
        return int(output) if output.isdigit() else None

    def logs_tail(self, engine: str, name: str, lines: int = 20) -> str:
        quoted = shlex.quote(validate_container_name(name))
        return self.client.run(f"{self.executable(engine)} logs --tail {int(lines)} --timestamps {quoted} 2>&1").stdout

    def backup_target(self, engine: str) -> BackupTarget:
        if self._sudo(engine):
            result = self.client.run(f"test -x {BACKUP_SCRIPT} && echo yes")
            if "yes" not in result.stdout:
                return BackupTarget(error=f"com {engine}_sudo o backup usa o script {BACKUP_SCRIPT} "
                                          "(veja docs/firawynix-volume-backup), que não está instalado")
            return BackupTarget(directory="/var/backups/firawynix", script=BACKUP_SCRIPT)
        result = self.client.run('d="$HOME/firawynix-backups"; mkdir -p "$d" && chmod 700 "$d" && '
                                 'echo "$d|$(id -u):$(id -g)"')
        line = result.stdout.strip().splitlines()[-1] if result.ok and result.stdout.strip() else ""
        directory, _, owner = line.partition("|")
        if not directory.startswith("/"):
            return BackupTarget(error=f"não foi possível preparar a pasta de backup: {_first_lines(result.output)}")
        # Podman rootless mapeia usuários: o arquivo já nasce do usuário SSH.
        return BackupTarget(directory=directory, owner=owner if engine == "docker" else "")
