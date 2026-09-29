"""Histórico de métricas em SQLite (biblioteca padrão; um arquivo local).

Uma linha por servidor a cada coleta rápida (~17 mil linhas/dia por servidor
com intervalo de 5 s). As consultas agregam em "baldes" de tempo para que os
gráficos tenham no máximo algumas centenas de pontos, qualquer que seja a janela.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from core.models import HostMetrics

log = logging.getLogger(__name__)

FIELDS = ("cpu", "mem", "swap", "load1", "disk", "net_rx", "net_tx", "disk_read", "disk_write",
          "failed", "active")
_PRUNE_EVERY = 600.0


@dataclass(frozen=True)
class HistorySeries:
    timestamps: tuple[float, ...]
    values: dict[str, tuple[float | None, ...]]
    bucket_seconds: float

    def __len__(self) -> int:
        return len(self.timestamps)


class HistoryStore:
    def __init__(self, path: Path | None, retention_days: float = 7.0) -> None:
        self.retention_seconds = retention_days * 86400
        self._lock = threading.Lock()
        self._last_prune = 0.0
        self.path = path
        self._conn = self._open(path)

    def _open(self, path: Path | None) -> sqlite3.Connection:
        target = ":memory:"
        if path is not None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                target = str(path)
            except OSError:
                log.warning("Não foi possível criar %s; histórico só em memória", path, exc_info=True)
        try:
            conn = self._connect(target)
        except sqlite3.DatabaseError:
            log.warning("Banco de histórico inválido em %s; usando memória", target, exc_info=True)
            conn = self._connect(":memory:")
        return conn

    @staticmethod
    def _connect(target: str) -> sqlite3.Connection:
        # Uma conexão compartilhada entre threads, serializada por self._lock.
        conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None, timeout=5)
        if target != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        columns = ", ".join(f"{name} REAL" for name in FIELDS)
        conn.execute(f"CREATE TABLE IF NOT EXISTS samples (server TEXT NOT NULL, ts REAL NOT NULL, {columns}, "
                     "PRIMARY KEY (server, ts)) WITHOUT ROWID")
        return conn

    def record(self, server: str, timestamp: float, metrics: HostMetrics | None,
               failed: int | None = None, active: int | None = None) -> None:
        if metrics is None:
            return
        root = metrics.root_disk
        load = metrics.load_avg[0] if metrics.load_avg else None
        row = (server, timestamp, metrics.cpu_percent, metrics.mem_percent, metrics.swap_percent, load,
               root.use_percent if root else None, metrics.net_rx_bps, metrics.net_tx_bps,
               metrics.disk_read_bps, metrics.disk_write_bps, failed, active)
        placeholders = ", ".join("?" * len(row))
        try:
            with self._lock:
                self._conn.execute(f"INSERT OR REPLACE INTO samples VALUES ({placeholders})", row)
                if timestamp - self._last_prune > _PRUNE_EVERY:
                    self._last_prune = timestamp
                    self._conn.execute("DELETE FROM samples WHERE ts < ?", (timestamp - self.retention_seconds,))
        except sqlite3.Error:
            log.warning("Falha ao gravar histórico", exc_info=True)

    def query(self, server: str, window_seconds: float, max_points: int = 360,
              now: float | None = None) -> HistorySeries:
        now = time.time() if now is None else now
        since = now - window_seconds
        bucket = max(1.0, window_seconds / max_points)
        averages = ", ".join(f"AVG({name})" for name in FIELDS)
        sql = (f"SELECT AVG(ts), {averages} FROM samples WHERE server = ? AND ts >= ? "
               "GROUP BY CAST(ts / ? AS INTEGER) ORDER BY 1")
        try:
            with self._lock:
                rows = self._conn.execute(sql, (server, since, bucket)).fetchall()
        except sqlite3.Error:
            log.warning("Falha ao consultar histórico", exc_info=True)
            rows = []
        timestamps = tuple(row[0] for row in rows)
        values = {name: tuple(row[i + 1] for row in rows) for i, name in enumerate(FIELDS)}
        return HistorySeries(timestamps, values, bucket)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
