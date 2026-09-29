"""Funções auxiliares da interface (sem abrir janelas)."""

import pytest

pytest.importorskip("tkinter")

from core.models import ServiceStatus  # noqa: E402
from ui.widgets import (  # noqa: E402
    Row,
    _gap_threshold,
    _nice_ceiling,
    _sort_value,
    fmt_bytes,
    fmt_duration,
    fmt_num,
    fmt_pct,
    short_path,
)


def test_number_formatting_is_pt_br():
    assert fmt_num(1234567.891, 2) == "1.234.567,89"
    assert fmt_pct(12.345, 1) == "12,3%"
    assert fmt_pct(None) == "—"
    assert fmt_bytes(512) == "512 B"
    assert fmt_bytes(1014.5 * 1024 * 1024) == "1,0 GB"
    assert fmt_bytes(1536, "/s") == "1,5 KB/s"
    assert fmt_duration(3 * 86400 + 5 * 3600) == "3d 5h"
    assert fmt_duration(125) == "2m 5s"


def test_short_path():
    assert short_path("/") == "/"
    assert short_path("/var/lib/libvirt/images", 16) == "…/libvirt/images"


def test_gap_threshold_uses_real_sample_spacing():
    minute_samples = [i * 60.0 for i in range(20)]
    assert _gap_threshold(minute_samples, bucket=2.5) == pytest.approx(180.0)
    assert _gap_threshold([], bucket=10.0) == pytest.approx(30.0)
    assert _gap_threshold([0.0, 5.0, 10.0], bucket=1.0) == pytest.approx(15.0)


def test_nice_ceiling():
    assert _nice_ceiling(0.83) == 1.0
    assert _nice_ceiling(3.7e6) == 5e6
    assert _nice_ceiling(0) == 1.0


def test_sort_value_puts_none_last_and_ignores_case():
    rows = [Row("a", ("b",), sort=("B",)), Row("b", ("-",), sort=(None,)), Row("c", ("a",), sort=("a",))]
    ordered = sorted(rows, key=lambda r: _sort_value(r, 0))
    assert [r.key for r in ordered] == ["c", "a", "b"]
    assert _sort_value(Row("x", ("v",), status=ServiceStatus.ACTIVE), 1) == (0, "v")
