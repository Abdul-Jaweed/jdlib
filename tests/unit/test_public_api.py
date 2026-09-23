from __future__ import annotations

import json
import subprocess
import sys

import jdlib

EXPECTED_PUBLIC_API = frozenset(
    {
        "AccessControl",
        "ContextFactory",
        "JdlibError",
        "TenancyConfig",
        "TenantContext",
        "TenantRegistry",
        "TenantRepository",
        "UnitOfWork",
        "authorize",
        "current_principal",
        "current_tenant",
        "errors",
        "requires",
    }
)

OPTIONAL_DISTRIBUTIONS = ("fastapi", "pytest", "typer")


def test_all_is_exactly_the_public_surface() -> None:
    assert frozenset(jdlib.__all__) == EXPECTED_PUBLIC_API
    assert len(jdlib.__all__) == len(EXPECTED_PUBLIC_API)


def test_every_exported_name_resolves() -> None:
    for name in jdlib.__all__:
        assert getattr(jdlib, name) is not None
    assert jdlib.errors.__name__ == "jdlib.errors"


def test_version_is_a_string() -> None:
    assert isinstance(jdlib.__version__, str)
    assert jdlib.__version__ == "0.1.0"


def test_import_does_not_pull_optional_dependencies() -> None:
    script = (
        "import json, sys, jdlib; "
        f"loaded = sorted({{name.split('.')[0] for name in sys.modules}} "
        f"& set({OPTIONAL_DISTRIBUTIONS!r})); "
        "print(json.dumps(loaded))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == []
