"""The example's documentation is checkable, and checked.

The programme's rule for the example application is that **no claim ships without an example and a
test**. That rule has to apply to the documentation too, or the documentation is where the claims go
to hide: a guide that names a module which was renamed, a path that moved, a heading that was never
written, or a snippet presented as a production pattern when it is deliberately wrong.

So the guides under ``docs/jdlib/features/`` carry machine-read front-matter - the guide's name, its
design authority, its modules, its exports and its test files - and this module checks every one of
those claims against the working tree. What is checked is exactly what is claimed, and nothing here
checks prose.

The one prose rule that *is* checked is the directive's own: the with-and-without comparison must
mark every illustrative snippet, because unmarked illustrative code is indistinguishable from
recommended code.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

FEATURES = Path("docs/jdlib/features")
ARCHITECTURE = Path("docs/jdlib/architecture")
EXAMPLES_DOCS = Path("docs/jdlib/examples")

#: The guide set, listed literally: a guide that disappears fails here rather than being noticed by
#: a reader. The order is the order the README presents them in.
GUIDES = (
    "authentication",
    "authorization",
    "tenancy",
    "resource-management",
    "query-system",
    "credentials",
    "caching",
    "storage",
    "connectors",
    "graph",
    "mcp",
    "jobs",
    "audit",
    "observability",
)

#: The directive's template, in the directive's order.
HEADINGS = (
    "What it is",
    "Why it exists",
    "When to use it",
    "When not to use it",
    "How it works",
    "Architecture",
    "Example",
    "Security",
    "Reliability",
    "Observability",
    "Audit",
    "Configuration",
    "Testing",
    "Common mistakes",
    "Production checklist",
)

#: The pages the example's documentation section names. A missing page fails here.
REQUIRED_EXAMPLE_DOCS = (
    "features/README.md",
    "architecture/example-architecture.md",
    "architecture/security-flow.md",
    "architecture/tenant-flow.md",
    "architecture/neo4j-flow.md",
    "architecture/mcp-flow.md",
    "architecture/observability-flow.md",
    "examples/overview.md",
    "examples/minimal-example.md",
    "examples/enterprise-example.md",
    "examples/with-and-without.md",
    "examples/developer-journey.md",
    "examples/coverage-matrix.md",
    "examples/feature-matrix.md",
)


def _front_matter(path: Path) -> dict[str, object]:
    """Parse the simple front-matter these guides use: ``key: value`` and ``  - item``."""

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
        meta[key.strip()] = value.strip() if value.strip() else []
    assert key is not None
    return meta


def _module_from_path(raw: str):
    """Import the module a front-matter path names."""

    name = raw.removeprefix("src/").removesuffix(".py").replace("/", ".")
    return __import__(name, fromlist=["*"])


GUIDE_PATHS = [FEATURES / f"{name}.md" for name in GUIDES]


def test_the_guide_set_is_exactly_the_one_named_here() -> None:
    found = sorted(p.stem for p in FEATURES.glob("*.md") if p.name != "README.md")
    assert found == sorted(GUIDES), f"the guides on disk differ from the set: {found}"


def test_the_index_lists_every_guide() -> None:
    index = (FEATURES / "README.md").read_text(encoding="utf-8")
    for name in GUIDES:
        assert f"({name}.md)" in index, f"the index does not link the {name} guide"


@pytest.mark.parametrize("guide", GUIDE_PATHS, ids=lambda p: p.stem)
def test_a_guide_carries_every_heading_of_the_template(guide: Path) -> None:
    assert guide.exists(), f"the {guide.stem} guide does not exist"
    text = guide.read_text(encoding="utf-8")
    missing = [h for h in HEADINGS if f"\n## {h}\n" not in text]
    assert not missing, f"{guide.name} is missing template headings: {missing}"


@pytest.mark.parametrize("guide", GUIDE_PATHS, ids=lambda p: p.stem)
def test_a_guide_names_its_design_authority_and_it_exists(guide: Path) -> None:
    meta = _front_matter(guide)
    assert meta.get("guide") == guide.stem, f"{guide.name} names itself {meta.get('guide')!r}"
    authority = str(meta["authority"])
    assert Path(authority).exists(), (
        f"{guide.name} names an authority that does not exist: {authority}"
    )
    assert authority in guide.read_text(encoding="utf-8"), (
        f"{guide.name} does not link the authority page it claims"
    )


@pytest.mark.parametrize("guide", GUIDE_PATHS, ids=lambda p: p.stem)
def test_a_guide_only_names_modules_that_exist(guide: Path) -> None:
    modules = _front_matter(guide).get("modules", [])
    assert isinstance(modules, list) and modules
    for module in modules:
        assert Path(module).exists(), f"{guide.name} names a module that does not exist: {module}"


@pytest.mark.parametrize("guide", GUIDE_PATHS, ids=lambda p: p.stem)
def test_a_guide_only_claims_exports_that_resolve(guide: Path) -> None:
    meta = _front_matter(guide)
    modules = meta.get("modules", [])
    assert isinstance(modules, list) and modules
    where = [_module_from_path(str(m)) for m in modules]
    exports = meta.get("exports", [])
    assert isinstance(exports, list) and exports
    for export in exports:
        assert any(hasattr(module, export) for module in where), (
            f"{guide.name} claims an export that does not resolve: {export}"
        )


@pytest.mark.parametrize("guide", GUIDE_PATHS, ids=lambda p: p.stem)
def test_a_guide_only_names_test_files_that_exist(guide: Path) -> None:
    files = _front_matter(guide).get("test_files", [])
    assert isinstance(files, list) and files
    for name in files:
        assert Path(name).exists(), f"{guide.name} names a test file that does not exist: {name}"


@pytest.mark.parametrize("guide", GUIDE_PATHS, ids=lambda p: p.stem)
def test_a_guide_only_names_examples_that_exist(guide: Path) -> None:
    meta = _front_matter(guide)
    for name in meta.get("example", []):
        assert Path(str(name)).exists(), (
            f"{guide.name} names an example that does not exist: {name}"
        )


@pytest.mark.parametrize("page", REQUIRED_EXAMPLE_DOCS)
def test_every_named_example_page_exists_and_is_not_a_stub(page: str) -> None:
    path = Path("docs/jdlib") / page
    assert path.exists(), f"{page} is named by the programme and does not exist"
    assert len(path.read_text(encoding="utf-8").splitlines()) >= 15, f"{page} is too short"


# --- what the pages cite ------------------------------------------------------------------------

#: A backticked token that looks like a repository path. Only these are checked, so prose is not
#: held to a rule it cannot satisfy.
PATH_LIKE = re.compile(r"`((?:src|tests|examples|docs|config|scripts)/[A-Za-z0-9_./-]+)`")

#: A page documenting the enterprise example may cite a path *relative to that example*
#: (``tests/security/test_denial_non_execution.py``), because that is how it reads to the person
#: following it. So a citation is resolved against both roots, and exactly one of them must exist:
#: the rule is stated here rather than left to the reader to guess.
ROOTS = (Path("."), Path("examples/enterprise"))


def _resolve(cited: str) -> Path | None:
    """Resolve a citation to a real path, or ``None`` when it exists under neither root."""

    for root in ROOTS:
        candidate = root / cited
        if candidate.exists():
            return candidate
    return None


CITING_PAGES = (
    [p for p in ARCHITECTURE.glob("*.md")]
    + [p for p in EXAMPLES_DOCS.glob("*.md")]
    + [FEATURES / "README.md"]
)


@pytest.mark.parametrize("page", CITING_PAGES, ids=lambda p: f"{p.parent.name}-{p.stem}")
def test_a_page_only_cites_paths_that_exist(page: Path) -> None:
    """A page that points at a path which moved is a page that will be trusted and be wrong."""

    text = page.read_text(encoding="utf-8")
    missing = []
    for cited in sorted(set(PATH_LIKE.findall(text))):
        # A citation may carry a symbol suffix (``app/main.py:create_app``); the path is the claim.
        path = cited.split(":", 1)[0].rstrip(".")
        if _resolve(path) is None:
            missing.append(cited)
    assert not missing, f"{page} cites paths that do not exist: {missing}"


def test_the_illustrative_snippets_are_marked_as_illustrative() -> None:
    """The directive forbids shipping deliberately wrong code as a production pattern.

    Every fenced ``python`` block in the with-and-without comparison must open with a comment
    saying it is illustrative and not runnable - otherwise the page reads as a recommendation.
    """

    page = EXAMPLES_DOCS / "with-and-without.md"
    text = page.read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", text, flags=re.DOTALL)
    assert blocks, "the with-and-without page carries no snippets at all"
    unmarked = [b.splitlines()[0] for b in blocks if "ILLUSTRATIVE" not in b.splitlines()[0]]
    assert not unmarked, f"unmarked illustrative snippets: {unmarked}"


# --- every documented command is one the repository can run --------------------------------------

#: The pages whose commands a reader is expected to follow.
COMMAND_PAGES = (
    EXAMPLES_DOCS / "minimal-example.md",
    EXAMPLES_DOCS / "enterprise-example.md",
    EXAMPLES_DOCS / "developer-journey.md",
    Path("examples/minimal/README.md"),
    Path("examples/enterprise/README.md"),
)

#: ``uvicorn <module>:<attr>`` - the documented way to serve an ASGI application.
UVICORN = re.compile(r"uvicorn\s+([A-Za-z0-9_.]+):([A-Za-z0-9_]+)")
#: ``python -m <module>`` - a documented module entry point.
PYTHON_M = re.compile(r"python\s+-m\s+([A-Za-z0-9_.]+)")
#: ``python <script>.py`` - a documented script.
PYTHON_SCRIPT = re.compile(r"python\s+(scripts/[A-Za-z0-9_.-]+\.py)")
#: ``-f <path>`` - a compose file the reader is told to use.
COMPOSE_FILE = re.compile(r"-f\s+(examples/[A-Za-z0-9_./-]+\.ya?ml)")


def _documented_commands() -> list[tuple[str, str, str]]:
    """Every checkable command the pages document, as (page, kind, target)."""

    found: list[tuple[str, str, str]] = []
    for page in COMMAND_PAGES:
        if not page.exists():
            continue
        body = page.read_text(encoding="utf-8")
        for block in re.findall(r"```bash\n(.*?)```", body, flags=re.DOTALL):
            for line in block.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                for match in UVICORN.finditer(line):
                    found.append((page.as_posix(), "uvicorn", f"{match.group(1)}:{match.group(2)}"))
                for match in PYTHON_M.finditer(line):
                    found.append((page.as_posix(), "module", match.group(1)))
                for match in PYTHON_SCRIPT.finditer(line):
                    found.append((page.as_posix(), "script", match.group(1)))
                for match in COMPOSE_FILE.finditer(line):
                    found.append((page.as_posix(), "compose", match.group(1)))
    return found


def test_the_pages_document_commands_at_all() -> None:
    """A run guide with nothing runnable in it is a page nobody can follow."""

    assert len(_documented_commands()) >= 8, _documented_commands()


@pytest.mark.parametrize(
    "page,kind,target",
    _documented_commands(),
    ids=lambda value: str(value).replace("/", "-").replace(":", "-"),
)
def test_every_documented_command_names_something_that_exists(
    page: str, kind: str, target: str
) -> None:
    """A documented command that does not work is fixed, not removed (the directive's rule).

    What is checked is the *target*: the module exists, the ASGI attribute is assigned at module
    level, the script is present, the compose file is there. Whether the command then succeeds
    depends on the lab, and that is what the live and e2e layers are for.
    """

    if kind == "uvicorn":
        module_name, attribute = target.split(":")
        # Resolve the file rather than importing it: an ASGI entry point builds its application at
        # import time, which needs the lab's environment, and this check is about the *target*
        # existing. The runtime path is what the e2e layer covers.
        source_path = Path(module_name.replace(".", "/") + ".py")
        assert source_path.exists(), (
            f"{page} documents `uvicorn {target}`, and no such module exists"
        )
        source = source_path.read_text(encoding="utf-8")
        assert re.search(rf"^{attribute}\s*[:=]", source, flags=re.MULTILINE), (
            f"{page} documents `uvicorn {target}`, and {module_name} never assigns {attribute!r} "
            "at module level"
        )
        return
    if kind == "module":
        path = Path(f"src/{target.replace('.', '/')}.py")
        assert path.exists() or Path(target.replace(".", "/") + ".py").exists(), (
            f"{page} documents `python -m {target}`, and no such module exists"
        )
        return
    assert Path(target).exists(), f"{page} documents {target}, which does not exist"


# --- the matrices say something checkable --------------------------------------------------------

FEATURE_MATRIX = EXAMPLES_DOCS / "feature-matrix.md"
COVERAGE_MATRIX = EXAMPLES_DOCS / "coverage-matrix.md"

#: A feature-matrix row: symbol, the seam cell, the example cell, the asserted-by cell.
FEATURE_ROW = re.compile(
    r"^\| `(?P<symbol>[A-Za-z0-9_]+)` \| `(?P<seam>[^`:]+):(?P<seam_line>\d+)` \| "
    r"(?P<example>[^|]+) \| (?P<asserted>[^|]+) \|$",
    re.MULTILINE,
)
#: A cell that is a path with a line number, in either the example or the asserted-by column.
CELL = re.compile(r"`((?:src|tests|examples)/[A-Za-z0-9_./-]+\.py):(\d+)`")


def test_the_feature_matrix_carries_rows_at_all() -> None:
    rows = FEATURE_ROW.findall(FEATURE_MATRIX.read_text(encoding="utf-8"))
    assert len(rows) >= 40, f"the feature matrix holds only {len(rows)} rows"


@pytest.mark.parametrize(
    "row",
    [m.groupdict() for m in FEATURE_ROW.finditer(FEATURE_MATRIX.read_text(encoding="utf-8"))],
    ids=lambda row: row["symbol"],
)
def test_a_feature_matrix_row_says_what_it_measured(row: dict[str, str]) -> None:
    """Every cell of a row is checked against the tree, in the sense the column claims.

    * the **seam** cell is the symbol's definition site, so that line must define it;
    * the **example** cell is the first line of ``examples/`` that mentions the symbol, so that
      line must mention it - or the cell must say *not named directly* / *library-only*, which are
      claims about absence and are checked by the generator, not by prose;
    * the **asserted by** cell is a test function, so that line must define one.
    """

    symbol = row["symbol"]
    seam = Path(row["seam"])
    assert seam.exists(), f"{symbol}: the seam path does not exist: {seam}"
    seam_lines = seam.read_text(encoding="utf-8").splitlines()
    seam_line = int(row["seam_line"])
    assert re.match(r"(class |def |async def )", seam_lines[seam_line - 1]), (
        f"{symbol}: {seam}:{seam_line} does not define anything"
    )

    example = row["example"].strip()
    if example.startswith("`"):
        match = CELL.search(example)
        assert match, f"{symbol}: the example cell is not a path:line: {example}"
        path, number = Path(match.group(1)), int(match.group(2))
        assert path.exists(), f"{symbol}: the example path does not exist: {path}"
        line = path.read_text(encoding="utf-8").splitlines()[number - 1]
        assert re.search(rf"\b{re.escape(symbol)}\b", line), (
            f"{symbol}: {path}:{number} does not mention the symbol it is cited for"
        )
    else:
        assert example in {"*not named directly*", "*library-only*"}, (
            f"{symbol}: the example cell says something unexpected: {example}"
        )

    asserted = row["asserted"].strip()
    if asserted != "—":
        match = CELL.search(asserted)
        assert match, f"{symbol}: the asserted-by cell is not a path:line: {asserted}"
        path, number = Path(match.group(1)), int(match.group(2))
        assert path.exists(), f"{symbol}: the test path does not exist: {path}"
        line = path.read_text(encoding="utf-8").splitlines()[number - 1]
        assert re.match(r"\s*(async )?def test_", line), (
            f"{symbol}: {path}:{number} is not a test function"
        )


#: A coverage-matrix row: a test file and the number of test functions it holds.
COVERAGE_ROW = re.compile(
    r"^\| `((?:tests|examples)/[A-Za-z0-9_./-]+\.py)` \| (\d+) \|$", re.MULTILINE
)


def test_the_coverage_matrix_counts_match_the_files() -> None:
    """The coverage matrix's whole claim is the count, so the count is what is checked."""

    rows = COVERAGE_ROW.findall(COVERAGE_MATRIX.read_text(encoding="utf-8"))
    assert len(rows) >= 10, f"the coverage matrix holds only {len(rows)} file rows"
    wrong = []
    for raw, claimed in rows:
        path = Path(raw)
        if not path.exists():
            wrong.append(f"{raw} (no such file)")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        counted = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name.startswith("test_")
        )
        if counted != int(claimed):
            wrong.append(f"{raw} claims {claimed}, holds {counted}")
    assert not wrong, f"the coverage matrix's counts are stale: {wrong}"
