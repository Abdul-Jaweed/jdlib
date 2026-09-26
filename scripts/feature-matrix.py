"""Generate the example application's coverage matrix and feature matrix.

Both pages claim a lot of `file:line` facts, and a hand-written table of line numbers is wrong the
first time someone edits the file above it. So the pages are generated: every cell is read from the
working tree, and the pages say which script produces them.

The feature matrix's cells are:

* **seam** — the definition site of the symbol in ``src/jdlib`` (the first top-level ``class`` or
  ``def`` of that name);
* **example** — the first line of ``examples/`` that mentions the symbol, or *library-only* when the
  example deliberately does not use the feature (the guide says so as well);
* **asserted by** — the first ``test_`` function in the guide's own ``test_files`` whose body names
  the symbol.

Run it from the repository root:

    .venv/Scripts/python scripts/feature-matrix.py      # Windows
    python scripts/feature-matrix.py                    # POSIX

``tests/unit/test_example_docs.py`` checks that every path these pages cite exists; this script is
what keeps the line numbers honest.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "jdlib"
FEATURES_DOCS = ROOT / "docs" / "jdlib" / "features"
EXAMPLES_DOCS = ROOT / "docs" / "jdlib" / "examples"

#: The guide set, in the order the README presents it.
FEATURES = (
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

LAYERS = {
    "unit": (
        "nothing — no service, no lab",
        "what is declared, and how it is wired: the tool inventory, the capabilities, the "
        "collaborator identity, the settings",
    ),
    "integration": (
        "PostgreSQL + Cerbos (+ Neo4j for the graph, MCP for the surface)",
        "does the real infrastructure answer: the tenant plane, RLS, the policy decisions, the "
        "graph projection, the MCP chain",
    ),
    "security": (
        "PostgreSQL + Cerbos (+ Neo4j + MCP)",
        "isolation across tenants over both surfaces, denial as non-execution, and what a failure "
        "is allowed to say",
    ),
    "e2e": (
        "a POSIX host (the stop probe), PostgreSQL + Cerbos",
        "does the documented command work as a process: readiness, the whole chain over a socket, "
        "and a refusal to start unconfigured",
    ),
}


def front_matter(path: Path) -> dict[str, object]:
    """Parse the simple front-matter the guides use: ``key: value`` and ``  - item``."""

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        return {}
    meta: dict[str, object] = {}
    key: str | None = None
    for line in lines[1:]:
        if line == "---":
            break
        if line.startswith("  - "):
            if key is not None:
                cast = meta.setdefault(key, [])
                if isinstance(cast, list):
                    cast.append(line[4:].strip())
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        meta[key] = value.strip() if value.strip() else []
    return meta


def definitions() -> dict[str, tuple[str, int]]:
    """Every top-level class/function in the library: symbol -> (repo path, line)."""

    index: dict[str, tuple[str, int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                index.setdefault(node.name, (path.relative_to(ROOT).as_posix(), node.lineno))
    return index


def first_example_use(symbol: str) -> tuple[str, int] | None:
    """The first line under ``examples/`` that mentions the symbol."""

    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    best: tuple[str, int] | None = None
    for path in sorted((ROOT / "examples").rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                candidate = (path.relative_to(ROOT).as_posix(), number)
                if best is None or candidate < best:
                    best = candidate
                break
    return best


def first_test_use(symbol: str, files: list[str]) -> tuple[str, int] | None:
    """The first test function in the cited files whose body names the symbol."""

    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    for name in files:
        path = ROOT / name
        if not path.exists():
            continue
        source = path.read_text(encoding="utf-8").splitlines()
        tree = ast.parse("\n".join(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not node.name.startswith("test_"):
                continue
            body = "\n".join(source[node.lineno - 1 : node.end_lineno or node.lineno])
            if pattern.search(body):
                return (name, node.lineno)
    return None


def test_functions(path: Path) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    )


def layer_files(layer: str) -> list[Path]:
    root = ROOT / "examples" / "enterprise" / "tests" / layer
    return sorted(
        p for p in root.rglob("*.py") if not p.name.startswith("_") and p.name != "conftest.py"
    )


def feature_matrix() -> str:
    """The feature matrix as text: every cell read from the working tree."""

    definitions_index = definitions()
    out = [
        "# The feature matrix",
        "",
        "Every feature the library offers, with the seam that implements it, where the "
        "example uses",
        "it, and the test that asserts the claim — each cell a real `file:line`, **generated "
        "from the",
        "working tree** rather than written by hand.",
        "",
        "Two cells need reading carefully, and both say exactly what was measured:",
        "",
        "* ***library-only*** — the guide declares no example path, so the example application "
        "does not",
        "  use this feature at all (background jobs, for instance); the evidence is the library's "
        "own",
        "  suite, which the guide names;",
        "* ***not named directly*** — the example uses the feature but reaches it through "
        "another seam",
        "  (the builder, the middleware, the `install`), so this particular symbol never appears "
        "in",
        "  `examples/`. Calling that library-only would be false.",
        "",
        "Line numbers are the definition (library), the first use (example) and the test "
        "function that",
        "names the symbol. Regenerate with `python scripts/feature-matrix.py`;",
        "`tests/unit/test_example_docs.py` checks that every path these pages cite exists.",
        "",
    ]
    rows = 0
    for name in FEATURES:
        meta = front_matter(FEATURES_DOCS / f"{name}.md")
        out += [
            f"## {meta.get('guide', name)} — [`features/{name}.md`](../features/{name}.md)",
            "",
            "| Seam | Implements | The example uses it at | Asserted by |",
            "|---|---|---|---|",
        ]
        test_files = meta.get("test_files", [])
        assert isinstance(test_files, list)
        exports = meta.get("exports", [])
        assert isinstance(exports, list)
        example_paths = meta.get("example", [])
        assert isinstance(example_paths, list)
        for symbol in exports[:5]:
            symbol = str(symbol)
            seam = definitions_index.get(symbol)
            if seam is None:
                continue
            used = first_example_use(symbol)
            asserted = first_test_use(symbol, [str(f) for f in test_files])
            if used:
                example_cell = f"`{used[0]}:{used[1]}`"
            elif example_paths:
                # The example uses this feature, but reaches it through another seam (the builder,
                # the middleware, the install) rather than naming this symbol. Saying "library-only"
                # here would be false; saying "not named directly" is exactly what was measured.
                example_cell = "*not named directly*"
            else:
                example_cell = "*library-only*"
            out.append(
                "| `{symbol}` | `{seam}:{line}` | {example} | {asserted} |".format(
                    symbol=symbol,
                    seam=seam[0],
                    line=seam[1],
                    example=example_cell,
                    asserted=f"`{asserted[0]}:{asserted[1]}`" if asserted else "—",
                )
            )
            rows += 1
        out.append("")
    return "\n".join(out)


def coverage_matrix() -> str:
    """The coverage matrix as text: every count read from the working tree."""

    out = [
        "# The coverage matrix",
        "",
        "What each test layer covers, what it needs to run, and what it is for. Counts are **test",
        "functions** (a deterministic property of a file); the number of *cases* depends on how "
        "the",
        "suite was invoked, so it is not claimed here.",
        "",
        "## The enterprise example",
        "",
        "| Layer | Files | Tests | Needs | Answers |",
        "|---|---|---|---|---|",
    ]
    files_total = 0
    tests_total = 0
    for layer, (needs, answers) in LAYERS.items():
        files = layer_files(layer)
        counted = sum(test_functions(p) for p in files)
        files_total += len(files)
        tests_total += counted
        out.append(f"| `tests/{layer}/` | {len(files)} | {counted} | {needs} | {answers} |")
    out.append(f"| **total** | **{files_total}** | **{tests_total}** | the lab up | |")
    out += ["", "### The files", "", "| File | Tests |", "|---|---|"]
    for layer in LAYERS:
        for path in layer_files(layer):
            counted = test_functions(path)
            if counted:
                out.append(f"| `{path.relative_to(ROOT).as_posix()}` | {counted} |")

    minimal = sorted(
        p
        for p in (ROOT / "examples" / "minimal" / "tests").rglob("*.py")
        if not p.name.startswith("_") and p.name != "conftest.py"
    )
    minimal_tests = sum(test_functions(p) for p in minimal)
    out += [
        "",
        "## The minimal example",
        "",
        "| Files | Tests | Needs | Answers |",
        "|---|---|---|---|",
        f"| {len(minimal)} | {minimal_tests} | PostgreSQL | the shape (the mount, the guard's "
        "declaration), the denial over a real chain, and the operator step |",
        "",
        "| File | Tests |",
        "|---|---|",
    ]
    for path in minimal:
        counted = test_functions(path)
        if counted:
            out.append(f"| `{path.relative_to(ROOT).as_posix()}` | {counted} |")

    out += [
        "",
        "## What is *not* covered, stated rather than implied",
        "",
        "* **`tests/e2e/test_http_chain.py::test_the_process_stops_on_sigterm` skips on "
        "Windows** — it",
        "  uses POSIX signals, and it says so in its skip reason rather than pretending to pass.",
        "* **Every live layer skips when its lab is absent**, naming the missing variable and the",
        "  operator step that provides it. A suite that failed without a container would teach "
        "nothing.",
        "* **No layer covers a second database vendor.** The dialect seam exists (`QueryDialect`,",
        "  `MysqlDialect`); the example runs PostgreSQL, and no test claims otherwise.",
        "* **Coverage of the *example* is not a gate.** The library's own coverage floor is "
        "enforced in",
        "  CI; the example's layers exist to be run, and their value is the defects they found "
        "(see the",
        "  README's \"what writing it found\").",
        "",
        "Regenerate with `python scripts/feature-matrix.py`.",
    ]
    return "\n".join(out)


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def check(path: Path, text: str) -> bool:
    """Is the page on disk exactly what would be generated now?

    Line endings are normalised before comparing: the repository is checked out on Windows with
    CRLF in places, and a gate that fails because of that would be a gate nobody trusts.
    """

    if not path.exists():
        return False
    on_disk = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return on_disk == text.replace("\r\n", "\n")


if __name__ == "__main__":
    import sys

    check_only = "--check" in sys.argv[1:]
    feature_text = feature_matrix()
    coverage_text = coverage_matrix()
    pages = (
        (EXAMPLES_DOCS / "feature-matrix.md", feature_text, "feature-matrix"),
        (EXAMPLES_DOCS / "coverage-matrix.md", coverage_text, "coverage-matrix"),
    )
    if check_only:
        stale = [name for path, text, name in pages if not check(path, text)]
        if stale:
            print(f"FAIL: {', '.join(stale)} do not match the working tree")
            print("regenerate with: python scripts/feature-matrix.py")
            raise SystemExit(1)
        print("the generated pages match the working tree")
    else:
        for path, text, _ in pages:
            write(path, text)
        print(f"feature-matrix: {feature_text.count('| `')} cited cells")
        print(f"coverage-matrix: {coverage_text.count('| `')} cited rows")
