"""Shared pytest configuration.

Applies the test-layer markers required by the infrastructure strategy
(unit / integration / infra / e2e) based on where a test lives, so the layers
can be selected without annotating hundreds of existing tests:

    pytest -q -W error -m unit
    pytest -q -W error -m integration
    pytest -q -W error -m infra
    pytest -q -W error -m e2e
"""

from __future__ import annotations

import pathlib

import pytest

_LAYERS = ("unit", "integration", "infra", "e2e")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        path = pathlib.Path(str(item.fspath)).as_posix()
        for layer in _LAYERS:
            if f"/{layer}/" in path:
                item.add_marker(getattr(pytest.mark, layer))
                break
