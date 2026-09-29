"""Backups locais das mudanças e o histórico de mudanças (neste PC, nunca no servidor).

Para cada mudança com risco o painel guarda, em
``%LOCALAPPDATA%\\FirawynixMonitor\\backups\\<servidor>\\<contêiner>\\<mudança>``:

* ``inspect.json.dpapi`` — o ``inspect`` completo, criptografado com a chave do
  usuário do Windows (DPAPI), porque variáveis de ambiente costumam ter senhas.
  Fora do Windows: ``inspect.json`` com permissão 0600;
* ``recriar.txt`` — o comando para recriar o contêiner, com os valores de
  variáveis sensíveis ocultos, e o comando do Compose quando houver;
* o histórico (``mudancas.jsonl``) com o resultado de cada passo, o snapshot
  (imagem) e os arquivos de backup dos volumes no servidor.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core import winapi
from core.changes import ContainerSpec, compose_hint, masked_args, run_args, shell_join

log = logging.getLogger(__name__)

_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe(name: str) -> str:
    return _SAFE_RE.sub("_", name).strip("._") or "_"


@dataclass
class ChangeRecord:
    id: str
    time: float
    server: str
    target: str
    engine: str
    action: str
    risk: str
    outcome: str = "running"  # running | ok | warning | error
    message: str = ""
    definition_dir: str = ""
    snapshot_image: str = ""
    volume_backups: list[str] = field(default_factory=list)
    compose_hint: str = ""
    steps: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def restorable(self) -> bool:
        return bool(self.definition_dir) and self.action in ("remove", "stop", "restart", "pause")

    @classmethod
    def from_dict(cls, data: dict) -> ChangeRecord:
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        known["steps"] = [tuple(step) for step in known.get("steps", [])]
        return cls(**known)


class BackupStore:
    JOURNAL = "mudancas.jsonl"

    def __init__(self, root: Path | None) -> None:
        #: None = sem gravação em disco (testes e modo demonstração em memória).
        self.root = root
        self._lock = threading.Lock()
        self._memory: list[ChangeRecord] = []
        self._memory_definitions: dict[tuple[str, str], dict] = {}

    # -- definição ---------------------------------------------------------

    def change_dir(self, server: str, container: str, change_id: str) -> Path | None:
        if self.root is None:
            return None
        return self.root / _safe(server) / _safe(container) / _safe(change_id)

    def save_definition(self, server: str, container: str, change_id: str, inspect: dict,
                        spec: ContainerSpec | None, executable: str) -> str:
        """Grava a definição e devolve a pasta (ou "memória" sem disco)."""
        directory = self.change_dir(server, container, change_id)
        if directory is None:
            self._memory_definitions[(server, change_id)] = inspect
            return f"memória://{server}/{container}/{change_id}"
        directory.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(inspect, indent=2, ensure_ascii=False).encode("utf-8")
        if winapi.IS_WINDOWS:
            (directory / "inspect.json.dpapi").write_bytes(winapi.protect_data(raw, f"Firawynix {container}"))
        else:
            path = directory / "inspect.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
        lines = [f"# Contêiner {container} em {server} — salvo em {time.strftime('%d/%m/%Y %H:%M:%S')}",
                 "# Valores de variáveis sensíveis aparecem como <oculto>; a definição completa está em",
                 "# inspect.json(.dpapi) e é usada pelo botão Restaurar do painel.", ""]
        if spec is not None:
            try:
                lines.append(shell_join(executable, masked_args(run_args(spec))))
            except ValueError as exc:
                lines.append(f"# não foi possível gerar o comando: {exc}")
            for network in spec.extra_networks:
                lines.append(f"{executable} network connect {network} {spec.name}")
            for note in spec.notes:
                lines.append(f"# atenção: {note}")
        hint = compose_hint(((k, str(v)) for k, v in ((inspect.get("Config") or {}).get("Labels") or {}).items()))
        if hint:
            lines += ["", "# Gerenciado pelo Compose — o caminho recomendado para recriar é:", hint]
        (directory / "recriar.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(directory)

    def load_definition(self, record: ChangeRecord) -> dict | None:
        if record.definition_dir.startswith("memória://"):
            return self._memory_definitions.get((record.server, record.id))
        directory = Path(record.definition_dir)
        protected, plain = directory / "inspect.json.dpapi", directory / "inspect.json"
        try:
            if protected.is_file():
                return json.loads(winapi.unprotect_data(protected.read_bytes()).decode("utf-8"))
            if plain.is_file():
                return json.loads(plain.read_text(encoding="utf-8"))
        except (OSError, ValueError, winapi.CredentialError):
            log.warning("Definição ilegível em %s", directory, exc_info=True)
        return None

    def readable_definition(self, record: ChangeRecord) -> str:
        if record.definition_dir.startswith("memória://"):
            data = self.load_definition(record) or {}
            return json.dumps(data, indent=2, ensure_ascii=False)[:20000]
        path = Path(record.definition_dir) / "recriar.txt"
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return "Definição não encontrada."

    # -- histórico -----------------------------------------------------------

    def append(self, record: ChangeRecord) -> None:
        with self._lock:
            if self.root is None:
                self._memory.append(record)
                return
            self.root.mkdir(parents=True, exist_ok=True)
            with (self.root / self.JOURNAL).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

    def records(self, server: str | None = None, limit: int = 300) -> list[ChangeRecord]:
        with self._lock:
            if self.root is None:
                items = list(self._memory)
            else:
                items = []
                path = self.root / self.JOURNAL
                try:
                    for line in path.read_text(encoding="utf-8").splitlines():
                        try:
                            items.append(ChangeRecord.from_dict(json.loads(line)))
                        except (ValueError, TypeError):
                            continue
                except FileNotFoundError:
                    pass
        latest: dict[str, ChangeRecord] = {}
        for item in items:  # a última gravação de cada mudança vale (o registro é refeito ao terminar)
            latest[item.id] = item
        result = [r for r in latest.values() if server is None or r.server == server]
        return sorted(result, key=lambda r: r.time, reverse=True)[:limit]
