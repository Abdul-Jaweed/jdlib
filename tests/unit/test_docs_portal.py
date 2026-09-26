"""The documentation portal builds, and says only what the tree supports.

`mkdocs build --strict` is the first half of this: it fails on a broken link, a missing page, an
unlisted page or a missing anchor. This module is the second half - the checks MkDocs cannot make:

* every navigation entry resolves, and **every published page is in the navigation** (a page nobody
  can reach is a page nobody reads);
* every relative link in every page resolves to a file that exists;
* every Mermaid fence names a diagram type the renderer can draw - a fence the site cannot render is
  an error the reader sees and the build does not;
* every page has an H1 and a body;
* the generated inventory is regenerated rather than edited, and the judgement rows it carries cite
  paths that exist.

Nothing here checks prose. What it checks is that the site's structure is true.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
CONFIG = ROOT / "mkdocs.yml"

#: The diagram types MkDocs Material's bundled Mermaid renderer draws. A fence naming anything else
#: renders as an error box in the browser, which is the failure this list exists to prevent.
MERMAID_TYPES = (
    "flowchart",
    "graph",
    "sequenceDiagram",
    "classDiagram",
    "stateDiagram-v2",
    "erDiagram",
    "journey",
    "gantt",
    "pie",
    "quadrantChart",
    "requirementDiagram",
    "gitGraph",
    "mindmap",
    "timeline",
    "block-beta",
    "packet-beta",
    "architecture-beta",
    "xychart-beta",
    "sankey-beta",
    "C4Context",
    "C4Container",
)

#: The target of a markdown link, up to the first whitespace or closing parenthesis. A link's
#: optional title is ignored: this module checks where a link points, not how it is labelled.
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)")
MERMAID = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)


class _Loader(yaml.SafeLoader):
    """A safe loader that understands MkDocs' one non-standard tag.

    `mkdocs.yml` uses PyYAML's `!!python/name:` tag for the Mermaid fence renderer. A plain
    `safe_load` refuses it, and `unsafe_load` would execute whatever a config asked it to; this
    loader records the name as text, which is all these checks need to know.
    """


_Loader.add_multi_constructor(
    "tag:yaml.org,2002:python/name:",
    lambda loader, suffix, node: f"<python/name:{suffix}>",
)


def _config() -> dict:
    return yaml.load(CONFIG.read_text(encoding="utf-8"), Loader=_Loader)


def _excluded() -> list[str]:
    raw = str(_config().get("exclude_docs", "") or "")
    return [line.strip().rstrip("/") for line in raw.splitlines() if line.strip()]


def _nav_paths() -> list[str]:
    """Every file path the navigation names, in order."""

    found: list[str] = []

    def walk(entry: object) -> None:
        if isinstance(entry, str):
            found.append(entry)
        elif isinstance(entry, list):
            for item in entry:
                walk(item)
        elif isinstance(entry, dict):
            for value in entry.values():
                walk(value)

    walk(_config().get("nav", []))
    return found


def _published_pages() -> list[Path]:
    excluded = _excluded()
    pages = []
    for path in sorted(DOCS.rglob("*.md")):
        rel = path.relative_to(DOCS).as_posix()
        if any(rel == item or rel.startswith(f"{item}/") for item in excluded):
            continue
        pages.append(path)
    return pages


def test_the_portal_is_configured() -> None:
    config = _config()
    for key in ("site_name", "site_description", "theme", "plugins", "markdown_extensions", "nav"):
        assert key in config, f"mkdocs.yml has no {key!r}"
    assert config["theme"]["name"] == "material"
    assert "search" in str(config["plugins"])


def test_every_navigation_entry_exists() -> None:
    missing = [p for p in _nav_paths() if not (DOCS / p).exists()]
    assert not missing, f"the navigation names pages that do not exist: {missing}"


def test_every_published_page_is_in_the_navigation() -> None:
    """A page that exists but is unreachable is a page that will be trusted and never read."""

    listed = set(_nav_paths())
    published = [p.relative_to(DOCS).as_posix() for p in _published_pages()]
    orphans = [name for name in published if name not in listed]
    assert not orphans, f"these pages are published but not in the navigation: {orphans}"


@pytest.mark.parametrize("page", _published_pages(), ids=lambda p: p.relative_to(DOCS).as_posix())
def test_a_page_has_a_title_and_a_body(page: Path) -> None:
    text = page.read_text(encoding="utf-8")
    assert re.search(r"^# \S", text, re.MULTILINE), f"{page.name} has no H1"
    assert len(text.splitlines()) >= 8, f"{page.name} is too short to be a page"


@pytest.mark.parametrize("page", _published_pages(), ids=lambda p: p.relative_to(DOCS).as_posix())
def test_a_pages_relative_links_resolve(page: Path) -> None:
    text = page.read_text(encoding="utf-8")
    broken = []
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path = target.split("#", 1)[0]
        if not path:
            continue
        if not (page.parent / path).exists():
            broken.append(target)
    where = page.relative_to(DOCS).as_posix()
    assert not broken, f"{where} links to files that do not exist: {broken}"


@pytest.mark.parametrize("page", _published_pages(), ids=lambda p: p.relative_to(DOCS).as_posix())
def test_every_mermaid_fence_is_a_type_the_renderer_draws(page: Path) -> None:
    text = page.read_text(encoding="utf-8")
    where = page.relative_to(DOCS).as_posix()
    wrong = []
    for block in MERMAID.findall(text):
        first = block.strip().splitlines()[0].strip() if block.strip() else ""
        if not any(first.startswith(name) for name in MERMAID_TYPES):
            wrong.append(first[:40])
    assert not wrong, f"{where} has unrenderable diagrams: {wrong}"

    # the regex above needs a closing fence to match at all, so an unclosed fence is caught here;
    # a fence with nothing between the markers would render as an empty box, not a diagram
    openings = text.count("```mermaid")
    closings = len(re.findall(r"^```\s*$", text, re.MULTILINE))
    assert openings == len(MERMAID.findall(text)), f"{where} has an unclosed Mermaid fence"
    assert openings * 2 <= closings + openings, f"{where} has an unbalanced code fence"
    empty = [block for block in MERMAID.findall(text) if not block.strip()]
    assert not empty, f"{where} has an empty Mermaid fence"


def _inventory_module():
    generator = ROOT / "scripts" / "docs-inventory.py"
    spec = importlib.util.spec_from_file_location("docs_inventory", generator)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_documentation_inventory_is_generated_not_edited() -> None:
    module = _inventory_module()
    on_disk = (DOCS / "development" / "documentation-inventory.md").read_text(encoding="utf-8")
    assert on_disk.replace("\r\n", "\n") == module.page_text().replace("\r\n", "\n"), (
        "docs/development/documentation-inventory.md is stale: regenerate it with "
        "`python scripts/docs-inventory.py`"
    )


def _api_reference_module():
    generator = ROOT / "scripts" / "api-reference.py"
    spec = importlib.util.spec_from_file_location("api_reference", generator)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_api_reference_is_generated_not_edited() -> None:
    """The reference is read from the source, so a page that drifts from it is a false claim."""

    module = _api_reference_module()
    on_disk = (DOCS / "reference" / "public-api.md").read_text(encoding="utf-8")
    assert on_disk.replace("\r\n", "\n") == module.page_text().replace("\r\n", "\n"), (
        "docs/reference/public-api.md is stale: regenerate it with "
        "`python scripts/api-reference.py`"
    )


def test_the_api_reference_covers_every_public_namespace() -> None:
    module = _api_reference_module()
    text = (DOCS / "reference" / "public-api.md").read_text(encoding="utf-8")
    missing = [ns for ns in module.namespaces() if module.exported(ns) and f"## `{ns}`" not in text]
    assert not missing, f"the API reference omits these namespaces: {missing}"


def test_the_inventorys_judgement_rows_cite_paths_that_exist() -> None:
    module = _inventory_module()
    missing = [citation for _, _, _, citation in module.JUDGEMENT if not (ROOT / citation).exists()]
    assert not missing, f"the inventory cites files that do not exist: {missing}"
