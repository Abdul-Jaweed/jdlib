"""Every first-party import must be declared, or the package only installs by accident.

Defect this test exists for: ``src/jdlib/integrations/fastapi.py`` imported ``starlette``
while nothing declared it. It resolved because ``fastapi`` happens to depend on ``starlette``
transitively — so the package worked and the declaration was wrong. A consumer installing a
different extra, or a future fastapi release dropping the dependency, would find out at
runtime rather than at install time.

The test reads the source (not the installed environment) and compares against what
``pyproject.toml`` declares, so it fails at the moment the import is written, in the same
suite run as the code, rather than in a downstream install.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import tomllib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src" / "jdlib"

# Modules whose distribution name shares no substring with the import name. Kept short and
# explicit: an alias list is a maintenance cost, so a wrong entry should look wrong.
DISTRIBUTION_ALIASES = {
    "jwt": "pyjwt",
    "pglast": "pglast",
    "dotenv": "python-dotenv",
    "multipart": "python-multipart",
    "yaml": "pyyaml",
    "dateutil": "python-dateutil",
}


def _normalise(name: str) -> str:
    """PEP 503 style: compare names without case, separators or dots."""
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def _declared_distributions() -> set[str]:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    raw = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        raw.extend(extra)
    names: set[str] = set()
    for requirement in raw:
        # Strip version specifiers, markers and extras: "foo[bar]>=1 ; python_version<'3.13'"
        head = requirement.split(";")[0].split("[")[0]
        for separator in (">=", "<=", "==", "~=", "!=", ">", "<"):
            head = head.split(separator)[0]
        names.add(_normalise(head.strip()))
    return {name for name in names if name}


def _imported_top_level_modules() -> set[str]:
    modules: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0])
            # level > 0 is a relative import inside the package itself, which needs no
            # declaration.
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
    return modules


def _is_declared(module: str, declared: set[str]) -> bool:
    if module in sys.stdlib_module_names:
        return True
    if module == "jdlib":
        return True
    candidate = _normalise(DISTRIBUTION_ALIASES.get(module, module))
    if candidate in declared:
        return True
    # Distributions that extend a module namespace: "opentelemetry-api" declares the
    # "opentelemetry" import, "prometheus-client" declares "prometheus_client".
    return any(candidate in name or name in candidate for name in declared)


def test_every_first_party_import_is_declared_by_pyproject() -> None:
    declared = _declared_distributions()
    imported = _imported_top_level_modules()

    undeclared = sorted(
        module for module in imported if not _is_declared(module, declared)
    )

    assert not undeclared, (
        "these modules are imported by src/jdlib but no dependency or extra declares them, "
        f"so the package installs only by luck: {undeclared}"
    )


@pytest.mark.parametrize(
    ("module", "expected"),
    [("starlette", True), ("fastapi", True), ("jdlib", True), ("os", True), ("httpx", True)],
)
def test_the_check_recognises_declared_and_stdlib_modules(module: str, expected: bool) -> None:
    """Guard against a vacuous pass: the detector must say yes to things that are declared.

    A test that returned False for everything would satisfy the assertion above for a
    codebase that imports nothing, which is not the property being protected.
    """
    assert _is_declared(module, _declared_distributions()) is expected


def test_an_undeclared_module_is_detected() -> None:
    """The negative direction, so the suite fails if the detector ever stops working."""
    assert _is_declared("definitely_not_a_dependency", _declared_distributions()) is False


def test_the_import_scan_actually_finds_imports() -> None:
    """A scan that found nothing would make the main test pass vacuously."""
    imported = _imported_top_level_modules()
    assert {"contextlib", "typing"} <= imported
    assert "jdlib" in imported
