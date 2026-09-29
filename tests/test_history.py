"""Testes do histórico em SQLite."""

import pytest

from core.history import HistoryStore
from core.models import DiskUsage, HostMetrics, InterfaceStats


def _metrics(cpu: float) -> HostMetrics:
    return HostMetrics(cpu_percent=cpu, mem_total_mb=1000, mem_used_mb=500, load_avg=(1.0, 1.0, 1.0),
                       disks=(DiskUsage("/dev/sda1", "/", 100, 60, 40, 60.0),),
                       interfaces=(InterfaceStats("eth0", 0, 0, 100.0, 50.0),))


def test_record_and_query_aggregates_into_buckets(tmp_path):
    store = HistoryStore(tmp_path / "h.sqlite3", retention_days=7)
    now = 1_000_000.0
    for i in range(120):  # 2 horas, uma amostra por minuto
        store.record("web", now - 7200 + i * 60, _metrics(cpu=float(i % 2) * 100))
    store.record("other", now - 60, _metrics(cpu=5))
    series = store.query("web", 7200, max_points=60, now=now)
    assert series.bucket_seconds == 120
    assert 55 <= len(series) <= 61
    assert all(v == pytest.approx(50.0) for v in series.values["cpu"][1:-1])  # média de 0 e 100
    assert series.values["mem"][0] == pytest.approx(50.0)
    assert series.values["disk"][0] == pytest.approx(60.0)
    assert series.values["net_rx"][0] == pytest.approx(100.0)
    assert list(series.timestamps) == sorted(series.timestamps)
    store.close()
    # Persistência: reabrir o arquivo mantém os dados.
    reopened = HistoryStore(tmp_path / "h.sqlite3")
    assert len(reopened.query("other", 3600, now=now)) == 1


def test_retention_prunes_old_samples():
    store = HistoryStore(None, retention_days=1)
    store.record("web", 1_000.0, _metrics(1))
    store.record("web", 1_000.0 + 2 * 86400, _metrics(2))  # dispara a limpeza
    series = store.query("web", 10 * 86400, now=1_000.0 + 2 * 86400)
    assert list(series.values["cpu"]) == [2]


def test_invalid_database_falls_back_to_memory(tmp_path):
    bad = tmp_path / "bad.sqlite3"
    bad.write_bytes(b"this is not a sqlite database" * 100)
    store = HistoryStore(bad)
    store.record("web", 10.0, _metrics(3))
    assert list(store.query("web", 100, now=20.0).values["cpu"]) == [3]


def test_record_ignores_missing_metrics():
    store = HistoryStore(None)
    store.record("web", 10.0, None)
    assert len(store.query("web", 100, now=20.0)) == 0
