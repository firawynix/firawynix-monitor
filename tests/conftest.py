"""Configuração comum dos testes."""

import sys

import pytest


def pytest_collection_modifyitems(config, items):
    """``@pytest.mark.posix_shell``: o teste roda comandos do servidor Linux num ``sh`` real
    (sintaxe e comportamento). No Windows — onde só o painel roda — ele é pulado."""
    if sys.platform != "win32":
        return
    skip = pytest.mark.skip(reason="executa comandos do servidor Linux num shell POSIX")
    for item in items:
        if "posix_shell" in item.keywords:
            item.add_marker(skip)
