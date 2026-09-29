"""Preferências alteradas pela interface (ex.: integrações do Windows ligadas ou
desligadas no diálogo de opções). Ficam em ``preferences.json`` na pasta de
configuração do usuário e têm prioridade sobre os padrões do ``servers.json``.
Nunca contêm segredos."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class Preferences:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        if path is not None and path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._data = data if isinstance(data, dict) else {}
            except (OSError, ValueError):
                log.warning("Preferências ilegíveis em %s; usando padrões", path, exc_info=True)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value
            data = dict(self._data)
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(temporary, self.path)
        except OSError:
            log.warning("Falha ao salvar preferências em %s", self.path, exc_info=True)
