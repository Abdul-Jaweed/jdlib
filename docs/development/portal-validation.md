# How the portal is validated

Every claim in this portal is checked by something that fails when the claim stops being true. This
page records what runs, what it has caught, and what it deliberately does not check.

## The build

`mkdocs build --strict` runs in `scripts/ci-local.sh` and in `.github/workflows/ci.yml`, so a
broken link, a page that exists but is not in the navigation, or an unresolved reference fails the
gate rather than shipping. The build is clean - **0 warnings** over every published page - and the
[documentation inventory](documentation-inventory.md) carries the live page and line counts rather
than this page guessing them.

The strict build is not a formality. It caught nineteen real problems the first time it ran:

| What it caught | Why it mattered | How it was fixed |
|---|---|---|
| Relative links that left `docs/` and climbed to files the site never serves (`../../tests/infra/README.md`, `../../SECURITY.md`, `../../CONTRIBUTING.md`) | a reader clicking a link in a built site lands on a 404 | rewritten to the repository URLs the site can actually reach |
| An anchor that did not exist (`24-future-architecture-...--...`) | a link that silently goes nowhere | corrected to the slug `markdown.extensions.toc.slugify` really produces: a double hyphen collapses to one |

## Consistency between the documentation and the source

"Documented API exists" is checked mechanically rather than promised:

| Check | What it compares | Where it runs |
|---|---|---|
| `scripts/api-reference.py --check` | the generated reference against the live public surface: 24 namespaces, 257 exported names, their signatures and their own docstrings | both gates, plus two unit tests |
| `scripts/docs-inventory.py --check` | the audit page against the tree: 34 namespaces, their surface, their pages, their tests | both gates, plus the documentation test |
| `scripts/docs-matrix.py --check` | the documentation test matrix against the tree: 14 areas, 56 of 56 cells earned | both gates, plus the documentation test |
| `scripts/feature-matrix.py --check` | the feature and coverage matrices against the example's source | both gates |
| `tests/unit/test_example_docs.py` | every `file:line` and every symbol a page cites exists at that line | the unit layer |
| `tests/unit/test_docs_portal.py` | navigation, links, page inventory, Mermaid fences, and the generated pages | the unit layer |

## What the checks caught in the portal itself

Writing the checks was worth more than the pages they guard. Each of these was found by running a
check, not by reading the output:

* **`inspect.getdoc` walks the MRO.** A class with no docstring of its own was credited with its
  base class's, so the generated reference described `Exception` under a jdlib class's name. The
  generator reads `__doc__` directly now.
* **The namespace walk was rooted at the wrong directory.** Rooted at `src` with the `jdlib.` prefix
  it produced one namespace called `jdlib.jdlib`; rooted at `src/jdlib` it produces the surface.
* **A line-splitting helper dropped the space at every chunk boundary**, so a published page read
  "holdit." and "thispage". Seventeen boundaries were repaired, and both generators now report the
  first differing line when a page is stale instead of only that it is stale.
* **A page that listed files in filesystem order.** `rglob` yields in NTFS order on one machine and
  ext4 order on another, so the inventory passed locally and failed in CI. The list is sorted, and
  the failure now names the line and both sides.

## What is deliberately not checked

* **Mermaid syntax, line by line.** The fences are checked for balance, for a known diagram type,
  for content, and for the two structural mistakes that survive review -- a sequence keyword in a
  flowchart (or a `subgraph` in a sequence diagram) and an unclosed `subgraph`. That is not a
  parser: a diagram can still be wrong in a way only the renderer sees, so a diagram that renders
  wrongly remains a documentation bug a reviewer catches.
* **The rendered appearance.** The gate proves the site builds and the links resolve; it does not
  take a screenshot. Typography and theme regressions are visible in review, not in CI.
* **Prose accuracy.** A sentence can be wrong and still pass every check above. The citation checks
  narrow the gap: pages that cite code must cite code that exists.
