# CI Security Gates

Status: **ACTIVE** — the `security` job in `.github/workflows/ci.yml` runs five
gate categories on every `push` and every `pull_request`. Every gate fails the
build on a finding: none of them is advisory, none is `continue-on-error`, and
there is no `|| true` anywhere in the job. The only suppressions are the
reviewed, value-pinned allowlists in §6; §7 lists exactly what is **not**
covered, including the checks that cannot fail the build.

The pre-existing `test` job (`pytest -q`, `ruff check .`, `mypy src/jdlib`) is
unchanged by design — the security gates are additive and run in parallel.

## 1. Overview

| # | Gate | Tool and pinned version | Fails the build? | Verified locally |
|---|---|---|---|---|
| 1 | Dependency vulnerabilities | `pip-audit` 2.10.1 | **Yes**, on any advisory for any installed dependency | Yes (incl. negative test) |
| 2 | Secrets (full git history) | `gitleaks` v8.30.1, official container `zricethezav/gitleaks` | **Yes**, on any leak not covered by a reviewed allowlist entry | Yes (incl. negative test) |
| 3 | SAST | `bandit` 1.9.4, medium+ severity | **Yes**, on any MEDIUM or HIGH finding | Yes (incl. negative test) |
| 4 | SBOM | `cyclonedx-bom` 7.4.0 (CycloneDX JSON 1.6) | Only if generation fails; the BOM content is not evaluated (see §7) | Yes |
| 5 | Build + install smoke test | `build` 1.6.1 | **Yes**, on build failure, install failure or import failure | Yes |

Job-level hardening (`.github/workflows/ci.yml`):

* `permissions: contents: read` at workflow level — the job never needs a
  write-scoped `GITHUB_TOKEN`.
* `timeout-minutes: 30` on the `security` job.
* Scanner tooling is installed into a **throwaway venv** under `$RUNNER_TEMP`
  (Python tools) or run as a **pinned container** (gitleaks). No scanner is
  added to `pyproject.toml`: the project's runtime and dev dependencies are
  untouched by this workstream.
* No paid or hosted service is used: Docker Hub (public image), PyPI (public
  packages), and the GitHub Actions runner image only.
* Evidence (redacted gitleaks report, CycloneDX SBOM, sdist + wheel) is
  uploaded as the `security-artifacts` build artifact with `if: always()`, so a
  failing job still leaves the scan output behind. Retention: 14 days.

### 1.1 Run recorded on the phase 10 branch (re-verified end to end)

Every gate was executed locally before this was committed, with the tools at the
pinned versions above:

```text
pip-audit 2.10.1     No known vulnerabilities found        (57 packages, --no-deps, frozen set)
gitleaks v8.30.1     no leaks found                        (full history; 157 commits at that run)
bandit 1.9.4         exit 0, 0 MEDIUM / 0 HIGH             (19 LOW, 1 reviewed #nosec B608)
cyclonedx-bom 7.4.0  CycloneDX 1.6, root jdlib 0.1.0       (58 components, no credential-shaped keys)
build 1.6.1          jdlib-0.1.0.tar.gz + jdlib-0.1.0-py3-none-any.whl
smoke                fresh venv + wheel only: import jdlib, jdlib.security,
                     jdlib.security.compliance; 19 controls registered
```

Two findings of the scanner against this repository were **synthetic test
fixtures written in phase 9** (a fake GitHub token and a `secret = "…"`
assignment) and are recorded as historical allowlist entries in §6. One bandit
finding is a reviewed exception: the interpolated schema identifier in
`MigrationRunner.tenant_version` is validated by an allowlist regex before the
query is built, which is why the file carries the repository's only `# nosec`
annotation — with the reasoning inline and the reviewer's note here.

## 2. Gate 1 — Dependency vulnerabilities (`pip-audit`)

**Covers.** Every package installed for the project — runtime dependencies and
the `dev` extra (pytest, testcontainers, ruff, mypy, typer, …) including
transitive dependencies — matched against the GitHub Advisory / PyPI / OSV
advisory data for the exact pinned versions.

**Tool and version.** `pip-audit==2.10.1` (installed into the scanner venv).
The audited set is produced by the job itself:

```bash
# in the job, after: python -m pip install -e ".[dev]"
python -m pip freeze --exclude-editable > "$RUNNER_TEMP/requirements-lock.txt"   # 57 pins today
```

**Command (gate, verbatim from the workflow).**

```bash
"$RUNNER_TEMP/scanners/bin/python" -m pip_audit \
  --requirement "$RUNNER_TEMP/requirements-lock.txt" \
  --no-deps \
  --desc on \
  --progress-spinner off
```

`--no-deps` audits exactly the frozen set instead of re-resolving it, so the
gate cannot drift from what the tests actually run against. `pip-audit` exits
`1` when any advisory is found; the step therefore fails the job.

**Local verification.**

```text
$ .venv/Scripts/python.exe -m pip freeze --exclude-editable > requirements-lock.txt   # 57 entries
$ python -m pip_audit -r requirements-lock.txt --no-deps --desc on --progress-spinner off
No known vulnerabilities found            # exit 0
```

Negative test (proves the gate is not a no-op) — a deliberately vulnerable pin
set in the scratch dir:

```text
$ printf 'requests==2.19.0\npyyaml==5.3.1\n' > vuln-probe.txt
$ python -m pip_audit -r vuln-probe.txt --no-deps --desc on --progress-spinner off
... PYSEC-2026-1994 ... PYSEC-2026-141 ... (advisories listed)            # exit 1
```

**Documented limitation.** The repository has no lock file (no `uv.lock`,
`requirements*.txt`, `poetry.lock`), and the lock built in CI is a version
freeze **without hashes** — `pip-audit` itself warns about this. Version pins
still make the audit deterministic, but a hash-pinned lock (e.g. `pip-compile`
with `--generate-hashes`) is the stronger follow-up. This limitation does not
weaken the gate; it is recorded so it is a known, measured gap rather than an
assumption.

## 3. Gate 2 — Secret scanning (`gitleaks`)

**Covers.** Every commit in the repository's history (not just the working
tree): all 244 commits / ~4.14 MB at the phase-17 MCP work (155 commits / ~2.97 MB when this section was first written). History scanning is deliberate — a
secret that was committed and later deleted is still exposed and still fails
the gate. The checkout uses `fetch-depth: 0` so the full history is present.

**Tool and version.** `zricethezav/gitleaks:v8.30.1` (official image, pinned
tag; `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`
at the time of writing). Running the container sidesteps binary installs and
version skew on the runner.

**Command (gate, verbatim from the workflow).**

```bash
docker run --rm \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
  -v "${{ github.workspace }}:/repo" \
  zricethezav/gitleaks:v8.30.1 detect \
    --source=/repo --config=/repo/.gitleaks.toml --no-banner --redact --exit-code 1 \
    --report-format json --report-path=/repo/security-artifacts/gitleaks-report.json
```

`--exit-code 1` fails the job on any leak. `--redact` means a finding never
prints secret material into the job log **or** the uploaded artifact — the
report records rule, file, line and commit only.

**Local verification.**

```text
$ docker run ... zricethezav/gitleaks:v8.30.1 detect --source=/repo --config=/repo/.gitleaks.toml --no-banner --redact --exit-code 1
INF 155 commits scanned.
INF scanned ~2965511 bytes (2.97 MB)
INF no leaks found                       # exit 0
```

Re-measured at the phase-17 MCP work, after the entry below was added:

```text
INF 244 commits scanned.
INF scanned ~4143443 bytes (4.14 MB)
INF no leaks found                       # exit 0
```

Negative test in both directions, using a scratch probe repository that
contains (a) the reviewed fixture from `tests/unit/security/test_telemetry.py`
and (b) a new, unreviewed GitHub-PAT-shaped value:

```text
Finding: token = "REDACTED          # (a) suppressed by the allowlist
Secret:  REDACTED                   # (b) reported, redacted
RuleID:  github-pat
File:    tests/unit/security/test_probe_unreviewed.py
INF leaks found: 1                  # exit 1
```

This proves the allowlist entries are *value-* and *path*-pinned: they do not
disable a rule, a directory or a file, and a new secret anywhere — including
inside an allowlisted file — still fails the gate.

**Documented exceptions:** 13 allowlist entries, counted from `.gitleaks.toml`
at the phase-17 MCP work (the section previously said 10, which was already
stale — two phase-9 historical fixtures had been added without updating it), each
pinned by exact path **and** exact value with `condition = "AND"`. The newest
(phase 17) is a *false positive* rather than a credential-shaped fixture — a two-argument fixture call
(`authorization="Bearer …", x_correlation_id="…"`) whose captured secret was the
tail of the call, `x_correlation_id=`, which `generic-api-key` read as a value.
The fixture itself was rewritten in the working tree to remove the
credential-adjacent word; the entry pins the historical value, so the finding is
allowlisted rather than the rule relaxed — a new value in that file, or that
value anywhere else, is still reported.

**Rejected alternative:** scanning the working tree (`gitleaks dir`). Measured
locally: 35 findings, of which 25 come from `.venv/`, `__pycache__/` and
`tests/infra/out/` (local, gitignored artefacts, including real local infra
credentials that must never be printed). History scanning of the checkout is
both quieter and stricter, since CI only ever contains committed content.

## 4. Gate 3 — Static analysis (`bandit`)

**Covers.** Security anti-patterns in the shipped source tree, `src/jdlib`
(12,249 lines of code): hardcoded SQL, `subprocess` misuse, weak crypto,
`eval`/`exec`, unsafe deserialisation, hardcoded credential strings, `assert`
usage, and the rest of bandit's plugin set.

**Tool and version.** `bandit==1.9.4`, medium-or-higher threshold:

```bash
"$RUNNER_TEMP/scanners/bin/python" -m bandit -r src/jdlib -ll -f txt
```

Bandit exits `1` when any reported issue is at or above the threshold, so the
step fails the job.

**Local verification.**

```text
$ python -m bandit -r src/jdlib -ll -f txt
Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 1
Total issues (by severity): Low: 19, Medium: 0, High: 0     # exit 0
```

Negative test — a scratch file with string-formatted SQL:

```text
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   Location: probe.py:2:11                                  # exit 1
```

**Documented exception.** One inline `# nosec B608` in
`src/jdlib/migrations/runner.py:121`, with a comment naming this document. The
interpolated value is a schema identifier that is allowlist-validated by
`_validate_tenant_schema` (`t_[a-z0-9][a-z0-9_]{0,50}`, `fullmatch`) or
`_validate_deployment_schema` (`[a-z_][a-z0-9_]{0,62}`, `fullmatch`) on both
call paths that reach `_read_version`, so no attacker-controlled text can reach
the f-string; the adjacent `to_regclass` probe on the same values is already
parameter-bound. The exception is narrow (that one line, that one check, still
counted as "skipped" in the bandit metrics above) and re-reviewed whenever
`runner.py` changes; B608 stays enabled everywhere else.

**Explicitly not gated: 19 LOW findings.** `-ll` reports only MEDIUM and
HIGH, so the existing LOW backlog neither fails the build nor appears in the
default output. It is:

* 10 × B105 `hardcoded_password_string` — matched constant/enum *values* that
  contain the word "secret"/"password" but are not credentials:
  `ClientAuthMethod.CLIENT_SECRET_POST` / `CLIENT_SECRET_BASIC`
  (`security/authn/provider.py:56-57`), audit/authn error-code constants
  (`security/audit/events.py:44-46`, `security/errors.py:30-31`,
  `security/gateway/config.py:29`, `security/gateway/adapters.py:196`,
  `security/compliance/posture.py:84`).
* 9 × B101 `assert_used` — assertions used as internal invariants, including in
  the deliberately-importable testing helpers (`src/jdlib/testing/assertions.py`).
  Addressable by policy (asserts are stripped under `python -O`) but not by a
  scanner; it needs a code-owner decision, so it is recorded here rather than
  silenced.

To see the backlog locally: `bandit -r src/jdlib -l -f txt`. If a LOW-severity
finding is ever judged worth gating, either widen the threshold to `-l` or add
targeted skips — both would be recorded here first.

## 5. Gate 4 — SBOM (`CycloneDX`) and Gate 5 — build + install smoke test

### 5.1 SBOM (CycloneDX JSON, `cyclonedx-bom` 7.4.0)

**Covers.** The full installed dependency set of the project interpreter —
runtime and dev, including transitive packages — as a CycloneDX 1.6 JSON BOM,
with the project itself as the root component.

**Command (gate, verbatim from the workflow).**

```bash
"$RUNNER_TEMP/scanners/bin/python" -m cyclonedx_py environment \
  "$(python -c 'import sys; print(sys.executable)')" \
  --pyproject pyproject.toml --mc-type library \
  --output-format JSON --output-file security-artifacts/sbom.cdx.json
```

The interpreter argument is what makes this correct: the BOM describes the
*project's* environment, not the scanner venv. The file is uploaded as a build
artifact.

**Fails the build?** Only for generation failures (non-zero exit). The BOM is
evidence; nothing in this job evaluates its contents. Stated plainly rather
than implied: **an SBOM does not itself fail the build for anything.** Policy
evaluation against the BOM (banned licences, components without versions) is
not implemented — see §7.

**No secrets.** Verified: the BOM contains package metadata only (names,
versions, PURLs, licences) and a scan of the file for credential-like patterns
matched nothing but PyJWT's description text ("JSON Web Token implementation").

**Local verification.**

```text
$ python -m cyclonedx_py environment /path/to/project/python --pyproject pyproject.toml --mc-type library --output-format JSON --output-file sbom.cdx.json
# -> CycloneDX 1.6 | root component: jdlib 0.1.0 (library) | 58 components | 77 KB
```

### 5.2 Build + install smoke test (`build` 1.6.1)

**Covers.** That the project still builds both distributions from source and
that the wheel is installable and importable in a clean environment with only
the declared runtime dependencies — the fastest way to catch packaging
regressions (missing package data, a module that imports a dev-only dependency
at import time, broken `pyproject.toml` metadata).

**Commands (gate, verbatim from the workflow).**

```bash
"$RUNNER_TEMP/scanners/bin/python" -m build --outdir security-artifacts/dist

python -m venv "$RUNNER_TEMP/smoke"
"$RUNNER_TEMP/smoke/bin/python" -m pip install security-artifacts/dist/*.whl
"$RUNNER_TEMP/smoke/bin/python" -c "import jdlib, jdlib.security; print('smoke test ok:', jdlib.__file__)"
```

Any failure in build, install or import fails the job.

**Local verification.**

```text
$ python -m build --outdir dist
Successfully built jdlib-0.1.0.tar.gz and jdlib-0.1.0-py3-none-any.whl      # exit 0
# sdist: 294 entries (includes pyproject.toml) | wheel: 108 files
#   (includes jdlib/__init__.py and jdlib/security/__init__.py)

$ python -m venv smoke && smoke/bin/python -m pip install dist/jdlib-0.1.0-py3-none-any.whl
$ smoke/bin/python -c "import jdlib, jdlib.security; ..."
SMOKE_IMPORT_OK: jdlib / jdlib.security                                     # exit 0
# import resolved from ...\smoke\Lib\site-packages\jdlib\..., i.e. the installed copy
```

**Not covered, stated explicitly:** only the *wheel* is installed; the sdist is
built and uploaded but not installed in the smoke venv. Adding an sdist install
is a one-line change if it is ever wanted.

## 6. Reviewed exceptions (complete list)

**6.1 Secret-scanning allowlist — `.gitleaks.toml` (10 entries).** Every entry
carries `condition = "AND"` with an anchored `paths` regex and an anchored
`regexTarget = "secret"` regex, so it can only suppress one exact value in one
exact file. All ten were reviewed and are synthetic, not credentials:

| File (finding location) | Rule | What the matched text actually is |
|---|---|---|
| `tests/unit/security/test_telemetry.py:33` | `jwt` | Elided dummy JWT placeholder (the fixture value is literally abbreviated with an ellipsis) used to test log/telemetry redaction |
| `tests/unit/security/test_telemetry.py:93` | `generic-api-key` | A fake API-key assignment built from obviously repeating digits — redaction fixture |
| `tests/unit/security/test_error_responses.py:194` | `generic-api-key` | One of a dict of fake credentials (a sandbox-style API-key placeholder) asserting error responses are redacted |
| `tests/unit/security/test_error_responses.py:202` | `jwt` | Multi-line synthetic JWT built from placeholder parts and the public jwt.io demo signature |
| `tests/unit/security/test_gateway_adapters.py:131` | `generic-api-key` | **False positive**: the matched text is the keyword `subject_header=` in `subject_header="X-JDLIB-Subject"` — no credential at all |
| `tests/unit/security/test_jwt_validator.py:3` | `generic-api-key` | **False positive**: the matched text is docstring text listing JWT claims (`iss/aud/sub/exp/...`) |
| `tests/unit/security/test_security_context.py:163` | `generic-api-key` | Dummy JWT in a test asserting `TokenMetadata` rejects raw credentials |
| `tests/unit/security/test_security_interfaces.py:84` | `generic-api-key` | Dummy outbound-token placeholder |
| `tests/unit/security/test_audit_events.py:239` | `generic-api-key` | A placeholder value of repeating hex digits — metadata-safety fixture |
| `tests/integration/test_security_audit_persistence.py:220` | `generic-api-key` | The same placeholder value in a DB-backed test |
| `tests/unit/security/test_compliance_posture.py` (phase 9 commit) | `github-pat` | **Historical**: a synthetic token in a test asserting a posture report carries no secret-shaped text. The value was replaced in the working tree by a DSN-shaped fixture (which the redaction path also covers and which the scanner does not flag); the entry remains because the commit is in history and history is scanned. Pinned by path **and** exact value |
| `tests/unit/test_cli_security.py` (phase 9 commit) | `generic-api-key` | **Historical**: `secret = "…"` in a CLI test proving a policy *body* never reaches the output. Now a `marker` variable, same reason as above |

The exact matched values are, by construction, recorded only in `.gitleaks.toml`
(that is what a value-pinned allowlist is); this table describes them so a
reviewer can check the pin without re-deriving it from the scanner.

Procedure for a new entry: confirm the value is synthetic, add an entry pinned
to the exact path and exact value (never a rule skip, never a directory
allowlist), re-run `gitleaks detect` locally, and extend the table above with
the justification. A finding that is **not** a synthetic fixture must never be
allowlisted: it is rotated and, if it is in history, the history is dealt with
by the code owners.

**6.2 SAST exception — one inline `# nosec B608`.** See §4. It is visible in
bandit's own metrics (`#nosec` skipped: 1) rather than hidden in a config skip
list.

**6.3 Gates that cannot fail the build.** Only one, and it is a *category*
statement rather than a suppressed failure: the SBOM step fails only if
generation fails — the BOM's contents are not evaluated. The 19 LOW-severity
bandit findings are reported but not gated (§4). Everything else in the job
fails on findings.

## 7. What is deliberately not covered

* **LOW-severity bandit findings** — reported, not gated (§4).
* **SBOM policy evaluation** — the BOM is produced and uploaded, but nothing
  fails on its contents; there is no licence-policy or component-completeness
  check, and no BOM signing/attestation.
* **Non-Python static analysis** — no linter/SAST for YAML, Dockerfiles, SQL or
  shell scripts; bandit covers `src/jdlib` only (not `tests/`, which is
  exercised by the test job and scanned for secrets).
* **Container/IaC scanning** — no image or compose-stack scan; the project
  ships no images.
* **Untracked/gitignored local files** — e.g. `tests/infra/out/kong-credentials.env`
  is never scanned, because CI never has it (it is gitignored and must stay
  that way). Local secret hygiene for those files is out of scope for this job.
* **Hosted services** — no SARIF upload to GitHub code scanning and no
  third-party dashboard: code scanning requires GitHub Advanced Security for
  private repositories (paid) and the task forbids paid/hosted dependencies.
  The gitleaks report and SBOM are run artifacts instead.

## 8. Tools evaluated and rejected

| Tool | Evidence | Why it was rejected |
|---|---|---|
| `semgrep` (registry ruleset `p/python`) | Ran locally: `Ran 151 rules on 101 files: 12 findings` — **all 12** from the single rule `avoid-sqlalchemy-text` (impact LOW, confidence MEDIUM), 11 of them in `src/jdlib/persistence/**` where parameter-bound `sqlalchemy.text()` is the documented design | Noisy for this codebase: it flags every use of `text()`, including correctly bound parameters, so the gate would either fail on false positives or need a broad exclusion. It also fetches rules from the semgrep registry at run time (unpinned ruleset, extra network dependency) and exits `0` unless `--error` is passed, which makes a naive wiring a silent no-op. Bandit covers the Python scope with a pinned version and no registry. |
| `gitleaks/gitleaks-action` | Upstream README: `GITLEAKS_LICENSE: ... # Only required for Organizations, not personal accounts`; the action's licence changed from MIT at v2 | Requires a paid licence for organisations, which the constraints rule out. The pinned official container gives the identical engine with no licence and no extra moving parts. |
| GitHub code scanning / CodeQL (SARIF upload) | Requires GitHub Advanced Security for private repositories (paid) | Paid hosted dependency; also unnecessary — the same findings live in the uploaded artifacts. |
| `detect-secrets` (alternative secret scanner) | Not run | gitleaks already covers full-history scanning with an official pinned container and a config format that supports value-pinned allowlists. Adding a second secret scanner would duplicate the gate without adding coverage. Recorded as considered, not as tested. |
| `gitleaks dir` (working-tree mode) | Ran locally: 35 findings, 25 of them from `.venv/`, `__pycache__/` and `tests/infra/out/` | Noisy and unsafe locally (it matches local infra credential files); the committed checkout contains none of that, and history scanning is the stricter gate anyway. |

## 9. Verification status (what is proven where)

Verified locally on the development host (Windows, Docker 29.8.0, Python
3.12.10) by running each gate's command against this working tree:

| Check | Result |
|---|---|
| `yaml.safe_load` of `.github/workflows/ci.yml` | OK |
| Workflow audit (job names, test job unchanged, no soft-fail constructs, every invoked module present) | PASS |
| pip-audit (57 pinned requirements) | `No known vulnerabilities found`, exit 0 |
| pip-audit negative test (`requests==2.19.0`, `pyyaml==5.3.1`) | advisories listed, exit 1 |
| gitleaks v8.30.1 history scan with `.gitleaks.toml` | `no leaks found`, exit 0 (155 commits at that run; the count grows with every commit, and a later run of the same gate scanned 157) |
| gitleaks probe (reviewed fixture + unreviewed PAT) | 1 finding, exit 1; allowlisted fixture suppressed |
| Post-commit simulation (`.gitleaks.toml`, this document and the workflow committed in a scratch repo, plus one planted unreviewed secret) | exactly 1 finding — the planted secret, exit 1; none in the new/changed files |
| bandit 1.9.4 `-ll` | exit 0; Low 19 / Medium 0 / High 0; `#nosec` skipped 1 |
| bandit negative test (string-formatted SQL) | `B608` MEDIUM reported, exit 1 |
| CycloneDX SBOM (exact CI command) | CycloneDX 1.6, jdlib 0.1.0, 58 components, no secrets |
| `python -m build` | `Successfully built jdlib-0.1.0.tar.gz and jdlib-0.1.0-py3-none-any.whl` |
| Fresh venv wheel install + `import jdlib, jdlib.security` | OK, imported from the smoke venv's `site-packages` |
| Pinned gitleaks tag `v8.30.1` pull + scan | identical result to `latest` |

**Not verifiable locally (stated so it is not mistaken for tested):** GitHub
Actions runner behaviour — `actions/checkout@v4`/`actions/setup-python@v5`/
`actions/upload-artifact@v4` execution, `$RUNNER_TEMP` resolution, and the
Ubuntu equivalent of the `docker run` invocation above (the same flags were
executed through Docker Desktop on Windows, not on the runner image). The first
run of the `security` job on a real runner is the remaining verification step.

## 10. Maintenance

* Bump the pinned versions (four Python tools, one image tag) deliberately and
  re-run each command above locally before pushing; record the new versions in
  §1.
* Any change to `.gitleaks.toml` must come with a table row in §6.1.
* Keep the existing `test` job untouched; the security job adds gates, it does
  not replace or relax anything.
* Commands never print credentials: gitleaks runs with `--redact`, and the
  SBOM, the gitleaks report and the distributions are the only uploaded
  artifacts. `tests/infra/out/kong-credentials.env` and any `.env` file are
  gitignored and must never be committed, uploaded or echoed.
