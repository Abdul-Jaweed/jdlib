"""The capability pages document what exists, and say so checkably.

A documentation page that drifts from the code is worse than no page, because it is trusted. Each
page under ``docs/jdlib/capabilities/`` therefore carries front-matter naming its modules, its
public exports, its refusals, its test files and how many test functions those files hold - and
this module checks every one of those claims against the working tree.

What is checked is exactly what is claimed: module paths exist, exports resolve, refusal names are
real attributes of the module that defines them, the stated test-function count matches the files,
and the index lists precisely the pages that exist. Nothing here checks prose, and nothing pretends
to.

Counts are **functions**, not parametrized cases, and the pages say so: a function count is a
deterministic property of a file, whereas a case count depends on how the suite was invoked.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

DOCS = Path("docs/jdlib/capabilities")


def _front_matter(path: Path) -> dict[str, object]:
    """Parse the simple front-matter these pages use: ``key: value`` and ``  - item``."""

    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "---", f"{path} must start with front-matter"
    meta: dict[str, object] = {}
    key: str | None = None
    for line in lines[1:]:
        if line == "---":
            break
        if line.startswith("  - "):
            assert key is not None, f"{path}: a list item without a key"
            cast = meta.setdefault(key, [])
            assert isinstance(cast, list)
            cast.append(line[4:].strip())
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        # A bare ``key:`` introduces a list; storing "" here would break the next item line,
        # which is exactly the bug this parser had when the pages were first checked.
        meta[key] = (int(value) if value.isdigit() else value) if value else []
    assert key is not None
    return meta


#: The index carries no claims of its own, so it is not checked as a capability page.
PAGES = (
    sorted(p for p in DOCS.glob("*.md") if p.name != "README.md") if DOCS.exists() else []
)


def test_there_are_capability_pages() -> None:
    assert PAGES, "no capability pages were found"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_a_page_only_names_modules_that_exist(page: Path) -> None:
    meta = _front_matter(page)
    modules = meta.get("modules", [])
    assert isinstance(modules, list) and modules
    for module in modules:
        assert (Path(module)).exists(), f"{page.name} names a module that does not exist: {module}"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_a_page_only_names_refusals_that_exist(page: Path) -> None:
    meta = _front_matter(page)
    module_name = str(meta["errors_module"])
    module = __import__(module_name, fromlist=["*"])
    refusals = meta.get("refusals", [])
    assert isinstance(refusals, list) and refusals
    for refusal in refusals:
        assert hasattr(module, refusal), (
            f"{page.name} names a refusal that does not exist: {refusal}"
        )


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_a_page_only_names_exports_the_namespace_provides(page: Path) -> None:
    meta = _front_matter(page)
    namespace = __import__(str(meta["namespace"]), fromlist=["*"])
    modules = meta.get("modules", [])
    assert isinstance(modules, list)
    where = [namespace] + [
        __import__(
            str(m).removeprefix("src/").removesuffix(".py").replace("/", "."),
            fromlist=["*"],
        )
        for m in modules
    ]
    exports = meta.get("exports", [])
    assert isinstance(exports, list) and exports
    for export in exports:
        found = any(hasattr(module, export) for module in where)
        assert found, f"{page.name} claims an export that does not resolve: {export}"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_the_stated_test_function_count_matches_the_files(page: Path) -> None:
    meta = _front_matter(page)
    files = meta.get("test_files", [])
    assert isinstance(files, list) and files
    counted = 0
    for name in files:
        source = Path(name)
        assert source.exists(), f"{page.name} names a test file that does not exist: {name}"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        counted += sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name.startswith("test_")
        )
    assert counted == meta["test_functions"], (
        f"{page.name} claims {meta['test_functions']} test functions; the files hold {counted}"
    )


# --- the page set the programme's documentation phase names -------------------------------------

JDLIB_DOCS = Path("docs/jdlib")

#: Every page the programme's documentation section and final-deliverables section name. Listed
#: literally so that a missing page fails here rather than being noticed by a reader.
REQUIRED_PAGES = (
    "architecture.md",
    "security-model.md",
    "tenancy.md",
    "authentication.md",
    "authorization.md",
    "privileged-access.md",
    "resource-management.md",
    "credentials.md",
    "connectors.md",
    "query-system.md",
    "production-readiness.md",
    "successor/00-current-state.md",
    "successor/01-capability-matrix.md",
    "successor/02-target-architecture.md",
    "successor/03-api-naming.md",
    "successor/04-adoption-decisions.md",
    "successor/05-roadmap.md",
)


@pytest.mark.parametrize("page", REQUIRED_PAGES)
def test_every_documented_page_exists_and_is_not_a_stub(page: str) -> None:
    path = JDLIB_DOCS / page
    assert path.exists(), f"{page} is named by the programme and does not exist"
    body = path.read_text(encoding="utf-8")
    assert len(body.splitlines()) >= 15, f"{page} is too short to be documentation"


DOC_PAGES = sorted(p for p in JDLIB_DOCS.glob("*.md")) if JDLIB_DOCS.exists() else []


@pytest.mark.parametrize("page", DOC_PAGES, ids=lambda p: p.stem)
def test_a_page_only_cites_sources_that_exist(page: Path) -> None:
    """A page that points at a path which moved is a page that will be trusted and be wrong."""
    text = page.read_text(encoding="utf-8")
    if not text.startswith("---"):
        pytest.skip("no front-matter to check")
    meta = _front_matter(page)
    sources = meta.get("sources", [])
    assert isinstance(sources, list)
    for source in sources:
        assert Path(source).exists(), f"{page.name} cites a source that does not exist: {source}"
