# Contributing

JDLib is a multi-tenant data-access library for PostgreSQL + SQLAlchemy
applications, with a completed security-hardening programme on top of it. This
document is how to work in the repository: the gate that must pass before a
commit, the test layers and how to run them against real infrastructure, and the
contribution rules the hardening programme established — including the ones that
only matter for this kind of work (skips, suppressions, evidence claims,
credentials, history).

Python 3.12+ (`requires-python` in `pyproject.toml`) and PostgreSQL 15+ (see
[`README.md`](README.md)). On Windows/git-bash the
interpreter lives at `.venv/Scripts/python.exe`; on POSIX at `.venv/bin/python`.
The examples below use the Windows path because that is what the other documents
in this repository use.

## 1. Set up a working copy

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"
```

`.[dev]` brings the test, lint and type tooling (pytest, mypy, ruff,
testcontainers, typer). `[cli]` and `[fastapi]` are the optional runtime extras —
neither is needed to run the suite, and a new optional dependency must never
leak into the core import (see §5).

## 2. The gate

Three commands. All of them pass before a commit; none is optional, and no
commit is made with one of them red "to be fixed in the next one".

```bash
.venv/Scripts/python.exe -m pytest -q -W error
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy src/jdlib
```

* `-W error` is deliberate: this project's gate treats warnings as errors. If a
  dependency warning is raised by fixture data, fix the fixture — never add a
  warning filter.
* Run them as separate commands, or read the output of a chain: a `&&` chain
  that stops at a failing linter never runs the tests, and a trailing
  `echo "exit=$?"` reports the echo's status. Read what the tools printed.
* CI runs the same three as the `test` job in
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`python -m ruff check .`,
  `python -m mypy src/jdlib`, `python -m pytest -q`, Python 3.12). A second
  `security` job adds dependency scanning, full-history secret scanning, SAST, an
  SBOM and a packaging smoke test — see
  [`docs/security/ci-security.md`](docs/security/ci-security.md).
* The suite reports skips. On a machine with the local infrastructure stack up
  (§4), the only skips are the six documented Tyk ones. On a machine without it,
  the other infrastructure layers skip as well — that is the designed behaviour,
  not a failure, and the reason string on each skip says which service was
  missing.

## 3. Test layers

The four layers are declared as markers in `pyproject.toml`
(`[tool.pytest.ini_options] markers`) and applied by directory in
[`tests/conftest.py`](tests/conftest.py): a test under `tests/unit/`,
`tests/integration/`, `tests/infra/` or `tests/e2e/` gets the matching marker
automatically, so the layers can be selected without annotating every test.

| Marker | What it means | How to run |
|---|---|---|
| `unit` | Fast, isolated, no external infrastructure. | `pytest -q -W error -m unit` |
| `integration` | Real infrastructure, hermetic: PostgreSQL 16 through Testcontainers, plus real HTTP servers and real RSA keys. Set `JDLIB_TEST_DATABASE_URL` to reuse an existing database instead of starting a container. | `pytest -q -W error -m integration` |
| `infra` | Depends on the local docker-compose stack (Cerbos, Redis, Kong, ZITADEL, the OpenTelemetry collector) or a service harness; each test skips with a reason when its service is not configured. | `pytest -q -W error -m infra` |
| `e2e` | Declared for end-to-end authentication and authorisation flows. There is no `tests/e2e/` directory in this checkout, so `-m e2e` collects nothing today; those flows currently live in the `integration` and `infra` layers. | `pytest -q -W error -m e2e` |

A test that proves a control belongs at the layer where the control actually
runs: unit tests prove wiring, the integration layer proves the code path against
a real server, and only the `infra` layer proves the protocol against a real
engine. Do not move a claim up a layer to make it cheaper to run, and do not
mark a claim verified at a layer you have not executed.

## 4. Infrastructure for the integration and infra layers

`pytest -q -W error -m unit` needs nothing. The integration layer starts its own
PostgreSQL container. The `infra` layer needs the local stack or a per-service
harness ([`tests/infra/README.md`](tests/infra/README.md)):

```bash
# the whole stack (postgres, redis, cerbos, otel-collector, zitadel + its db)
docker compose -f tests/infra/docker-compose.yml up -d

# just the persistence layer
docker compose -f tests/infra/docker-compose.yml up -d postgres

docker compose -f tests/infra/docker-compose.yml down -v

# required on Docker Desktop: both Testcontainers and the compose services
# publish to 127.0.0.1, and the container IP is not routable from the host
export TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1
```

Each service that has its own harness:

| Service | Bring up | Environment |
|---|---|---|
| Cerbos | `docker compose -f tests/infra/docker-compose.yml up -d cerbos` | `export JDLIB_INFRA_CERBOS_URL=http://localhost:3592` |
| OpenTelemetry collector | `bash tests/infra/otel/start.sh` (tear down with `stop.sh`) | writes `tests/infra/out/otel.env`, which the tests read; a listed but **unreachable** collector is a failure, not a skip |
| Kong + echo upstream | `bash tests/infra/kong/start.sh`, then `set -a; . tests/infra/out/kong-credentials.env; set +a` | `export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:8000` |
| ZITADEL | `docker compose -f tests/infra/docker-compose.yml up -d zitadel` | `export JDLIB_INFRA_ZITADEL_ISSUER=http://127.0.0.1:8080`; local-only (heavy image, its own schema, ~1 minute to be ready), so the tests skip without it and CI stays hermetic |
| Tyk | `bash tests/infra/tyk/start.sh`, then `set -a; . tests/infra/out/tyk-credentials.env; set +a` | `export JDLIB_INFRA_TYK_URL=http://127.0.0.1:8081` |

Rules for this layer:

* `tests/infra/out/` holds per-run generated credentials and is gitignored. It
  is never committed, never echoed, and never copied into a document — not even
  a value that looks like a placeholder.
* **Six tests in `tests/infra/test_tyk_infra.py` do not run here, and their skip
  is correct.** They skip when the Tyk harness variables are unset, and the live
  path they exercise cannot be verified against the stock image: Tyk 5.3.1 OSS
  ships no JavaScript/coprocess runtime, so the middleware that stamps the
  validity window (`tests/infra/tyk/middleware/stamp_window.js`) cannot execute.
  The blocker is recorded, with the second observation from the attempt, in
  [`docs/security/gateway-hardening.md`](docs/security/gateway-hardening.md) §6.
  It is also recorded as `JDL-GW-02` (`partial`, verification method `runtime`)
  in the control register. Do not delete these tests, loosen their assertions or
  drop the skip to get a greener run: the skip *is* the honest result, and Kong
  is the gateway verified end to end.
* A service harness that cannot run must skip cleanly (an `env`-gated
  `pytest.mark.skipif` with a reason naming the variable), never error out and
  never silently pass.

## 5. Security-specific contribution rules

These come out of the hardening programme and apply to every change, not only to
`src/jdlib/security/`.

**No new skipped test unless the reason is a documented infrastructure
limitation.** A skip is a visible, attributable claim that something was not
tested; that is only acceptable when the engine or environment genuinely cannot
run it, the reason string says so, and the limitation is written down where a
reader will find it (the phase document and, if it is a control, the register).
A skip introduced to make a red test green is a regression.

**No new suppression without a documented reason.** That covers `# nosec`,
`# noqa`, ruff config ignores, warning filters and scanner allowlists. Two
worked examples to follow:

* The gitleaks allowlist (`.gitleaks.toml`) entries are pinned to an **exact
  path and an exact value** with `condition = "AND"` — never a rule, a
  directory or a file allowlist — and every entry has a row in
  [`docs/security/ci-security.md`](docs/security/ci-security.md) §6.1 saying what
  the matched text actually is. A finding that is not a synthetic fixture is
  rotated, never allowlisted.
* The repository's single `# nosec B608`
  (`src/jdlib/migrations/runner.py:121`) carries its reasoning inline in the
  source and a reviewer's note in §4 of the same document, and stays visible in
  bandit's own metrics (`#nosec` skipped: 1).

**Evidence and posture claims must be reproducible.** The register's
`evidence_sources` are checked against the filesystem by a test, so a claim
whose artefact was renamed or deleted fails the suite — keep them pointing at
real files. A posture finding needs a substantive reason, and a claim that was
not executed is never reported as verified: a control that cannot be verified
live is `partial` with the exact blocker, never "passed", and never "broken
because the environment is hard". Prefer naming the command or test that
regenerates an observation, and do not quote a count you have not just measured
— test counts, file counts and line anchors drift the moment a slice lands.

**Never commit credentials.** Use placeholder fixtures; runtime secrets come from
the environment and are never written into repository config. The secret scanner
reads the **full history**, so a credential that was committed and then deleted
is still exposed and still fails the gate. If a real credential ever lands,
rotate it and deal with the history — do not add an allowlist entry.

**Never rewrite published history.** No force-pushes. If a commit turned out too
broad, `git reset --soft HEAD~1` and re-split it into logical commits rather
than rebasing over it, then check CI on the pushed SHA. One logical commit per
phase or slice, each taken with the full gate green.

**Additive public surface.** `jdlib.security`'s public surface is pinned by an
exact-equality test, so new API goes in a new submodule (which is why
`jdlib.security.compliance` is a submodule and not more names in the core).
Additive enum members and new optional parameters with secure defaults are
non-breaking; reordering, renaming and changing a default are not. A new
optional dependency must not reach the core import — prove it with an import
test.

**Declare behaviour changes.** Every change in observable behaviour (an error
code, a status, an audit reason, a configuration default) gets an explicit note —
before → after and why — in the phase document. Hardening must not silently
redefine an existing behaviour.

## 6. Commits

* One logical commit per slice, with the full gate green.
* Subject lines read like the existing history — a conventional prefix, the
  change, and the phase when the change belongs to one, e.g.
  `feat(compliance): evidence records and the first two collectors (phase 9.3)`.
* Tests and the document that explains them travel with the change. A phase
  document that claims a control is implemented without its test, or a test
  without the doc update, is an incomplete slice.
* Never commit `tests/infra/out/` (generated local credentials) or
  `security-artifacts/` (CI scan output); both are gitignored.

## 7. Documentation

| Where | What goes there |
|---|---|
| [`docs/security/`](docs/security/README.md) | The security programme, one document per phase, plus the adversarial review and the CI gates. The index is [`docs/security/README.md`](docs/security/README.md). |
| [`docs/jdlib/`](docs/jdlib/) | The design contracts: relational schema (`02`), isolation invariants (`03`), authorization model (`04`), tenant lifecycle (`05`), strategy matrix (`06`), implementation design (`07`). |
| [`docs/operations/README.md`](docs/operations/README.md) | Running the posture and evidence commands, CI artifacts, and what stays the operator's job. |
| [`docs/compliance/README.md`](docs/compliance/README.md) | The assessor-facing view: register, frameworks, evidence, posture outcomes. |
| [`SECURITY.md`](SECURITY.md) | What the library is responsible for, what it deliberately leaves to a deployment, known limitations, how to report a vulnerability. |

Two habits worth keeping: put a claim where its evidence is, and machine-check
what you write about the code (paths, counts, `file.py:NNN` anchors) before
shipping the document. The register's own tests enforce the evidence-path half of
that; the rest is on the author.
