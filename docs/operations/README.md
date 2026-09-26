# Operations

This is the operational entry point for a deployment that uses JDLib's security
surface: how to run the readiness commands and read them, what the test skips
mean when you see them, where the CI evidence lands, and what stays the
operator's job because the library deliberately does not do it.

Two lines to keep in mind throughout. The commands report **readiness** —
technical controls, the evidence behind them and the gaps — so a green report is
not a certification and a `warn` is not a failure. And the commands assess **the
profile you declare**, not the configuration your application actually loads:
the CLI cannot read a deployment's private settings and says so rather than
guessing.

## 1. The three commands

| Command | What it does |
|---|---|
| `jdlib security posture` | One finding per control in the register: outcome, severity, title and the reason. Exits non-zero when a control fails, so it can gate a pipeline. |
| `jdlib security evidence` | The evidence records behind the report, each with the command or procedure that reproduces it. |
| `jdlib security compliance` | The control register and its framework mappings, filtered with `--framework`. |

Common options (`src/jdlib/integrations/cli.py`, `security` sub-app):

| Option | Meaning |
|---|---|
| `--environment development\|test\|staging\|production` | The profile being assessed. Default when omitted: the library defaults, which report `profile=development`. An unknown value is refused. |
| `--database-url` + `--schema` | Adds the live observations: row-level security on the bound schema's catalog, and the revision that schema has applied. `--database-url` without `--schema` is refused. `--database-url` also defaults to `JDLIB_CONTROL_DSN`. |
| `--branch control\|tenant` | Which revision branch the schema carries (default `tenant`). The collector records what it finds rather than assuming. |
| `--policy-directory` | Adds policy-configuration evidence: file names and counts only — a policy body is never read. |
| `--pdp-kind` | Names the decision point for the policy evidence (default `cerbos`). |
| `--json` | Machine-readable output for every command. |

Installing the package declares a `jdlib` console script
(`[project.scripts] jdlib = "jdlib.integrations.cli:main"`; requires the `cli`
extra, which is typer). From a checkout without an install:

```bash
pip install -e ".[cli]"     # then: jdlib security posture
.venv/Scripts/python.exe -c "from jdlib.integrations.cli import app; app()" security posture
.venv/Scripts/python.exe -c "from jdlib.integrations.cli import app; app()" security posture --json --environment production
.venv/Scripts/python.exe -c "from jdlib.integrations.cli import app; app()" security evidence --database-url "$JDLIB_CONTROL_DSN" --schema public
.venv/Scripts/python.exe -c "from jdlib.integrations.cli import app; app()" security compliance --framework soc2
```

## 2. Exit codes

| Command | Code | Meaning |
|---|---|---|
| `security posture` | `0` | Nothing failed. `warn` and `not_applicable` findings keep the exit code at zero. |
| | `1` | At least one control `fail`ed — the report's `is_ready` is `false`. This is the code a pipeline gate should act on. |
| | `2` | Bad option value (Typer's own code), for example an unknown `--environment`. |
| `security evidence` | `0` | Records were collected. |
| | `1` | The command raised — for example the database could not be reached on the live path. A non-zero exit means **no report**, not "a report with failures". |
| | `2` | Bad option value — for example `--database-url` without `--schema`. |
| `security compliance` | `0` | The register (or the requested framework's slice) was printed. |
| | `2` | Bad option value — an unknown `--framework`. |

`posture` is the only one of the three that gates: it fails the process when a
control that should be in force is absent, disabled or contradicted by what was
observed. Treat `warn` and `not_applicable` deliberately rather than as noise —
the semantics are in [`docs/security/compliance-evidence.md`](../security/compliance-evidence.md) §4
and repeated in [`docs/compliance/README.md`](../compliance/README.md) §5.

## 3. Reading a posture report

```
profile=development outcome=warn ready=true
pass=13 warn=3 not_applicable=3
PASS           JDL-AUDIT-01   info     Security events are recorded with fail-closed attribution
    Security events are written to the audit trail with an actor and time is in force.
...
WARN           JDL-ISO-01     medium   Tenant isolation is enforced by the database, not only by the library
    Row-level security is implemented in the schema, but no evidence was supplied for this report: the policies were not observed on a live catalog.
```

* Line 1 is the profile that was assessed, the worst outcome and `is_ready`;
  line 2 is the count per outcome.
* Every finding carries a reason, and the reason names what is missing when the
  evidence is incomplete — `JDL-ISO-01` above turns `pass` once
  `--database-url` and `--schema` let the collector observe the catalog.
* The counts move as evidence is supplied and as the register changes; they are
  not a target. What matters is which controls are `warn` or `fail` and why.
* The run above is the no-argument default on this checkout: no live evidence,
  `development` profile. The three `warn`s are the register's unverified and
  deliberately-out-of-library controls (`JDL-ISO-01` without a catalog,
  `JDL-AUDIT-03`, `JDL-SUPPLY-01`), which is what "no evidence supplied" is
  supposed to look like.

To capture the report for a review, run `--json` and keep the payload: it
contains the profile, the counts, `is_ready`, and per finding the control id,
outcome, severity, reason and evidence summaries — never observation values.

## 4. Tyk: verified, and why it used to be recorded as unavailable

`tests/infra/test_tyk_infra.py` holds six tests that run against the live harness
(`bash tests/infra/tyk/start.sh`); **all six pass**. They skip only when the harness's
variables are not exported, which is the rule every infrastructure layer here follows.

The section that stood here recorded them as permanently skipping, on the finding that
stock Tyk 5.3.1 OSS ships no JavaScript runtime. That finding was wrong - the image ships
JSVM and loads the middleware file. What stood in the way were five defects in *this*
harness: the gateway was hostname-bound (`TYK_GW_HOSTNAME` is used as an API's default
domain, so only requests carrying that `Host` matched - even Tyk's own shipped sample API
answered 404), the rendered config never substituted its own secret placeholder, the
middleware named a driver Tyk does not know (`javascript`; the JS driver is `otto`), the
middleware's global did not match the name the definition looks up, and two schema
mistakes doubled the upstream path and put `global_headers` where Tyk ignores it.
[`docs/security/gateway-hardening.md`](../security/gateway-hardening.md) §6 carries the
full list.

What that means operationally:

* **Kong 3.6 and Tyk 5.3.1 are both verified end to end.** The Tyk adapter's contract is
  unit-verified as well, and it fails closed: a deployment that sends a *static* validity
  window is refused exactly as a replayed one is.
* A Tyk deployment should still run `tests/infra/test_tyk_infra.py` against **its own**
  build before trusting the integration, as with any gateway.
* Counts on this page come from a run, and the run is named. With the whole stack up and
  its environment variables exported - as on the development host - the complete local
  gate was **1570 passed, 7 skipped** at this revision, and those seven are the
  documentation parser's "no front-matter to check" cases. On a machine without the
  stack, the other infrastructure layers skip as well, each naming the missing variable;
  that is designed behaviour rather than a failure. A skip in a layer whose service *is*
  configured is a signal: the OTel harness makes the rule explicit - a listed but
  unreachable collector is a failure, not a skip.
* Kong, Cerbos, ZITADEL, Tyk and the OpenTelemetry collector skip when their environment
  variables are unset; that is how a machine without the local stack stays green without
  pretending to have tested them ([`tests/infra/README.md`](https://github.com/Abdul-Jaweed/jdlib/blob/main/tests/infra/README.md)).

## 5. CI security job and its artifacts

The `security` job in `.github/workflows/ci.yml` runs on every `push` and every
`pull_request`, beside the unchanged `test` job. Five gate categories, each of
which fails the build on a finding (none is advisory, none is `continue-on-error`):

| Gate | Tool, pinned | Fails on |
|---|---|---|
| Dependency vulnerabilities | `pip-audit` 2.10.1 over the job's own `pip freeze --exclude-editable` set | any advisory for an installed dependency |
| Secret scanning | `gitleaks` `v8.30.1` (official container), full git history, `--redact` | any leak not covered by a reviewed, path- and value-pinned allowlist entry |
| Static analysis | `bandit` 1.9.4, medium+ (`-ll`) over `src/jdlib` | any MEDIUM or HIGH finding |
| SBOM | `cyclonedx-bom` 7.4.0, CycloneDX JSON from the project interpreter | generation failure only — the BOM's contents are not evaluated |
| Packaging | `build` 1.6.1, then the wheel installed and imported in a fresh venv | build, install or import failure |

Artifacts, all written under `security-artifacts/` and uploaded by
`actions/upload-artifact@v4`:

| Artifact | Path | Produced by |
|---|---|---|
| CycloneDX SBOM | `security-artifacts/sbom.cdx.json` | the SBOM step (root component `jdlib`, package metadata only) |
| Redacted gitleaks report | `security-artifacts/gitleaks-report.json` | the secret-scanning step (`--redact`, so a finding records rule, file, line and commit — never the value) |
| Distributions | `security-artifacts/dist/` (sdist + wheel) | the build step |

Where to find them: on the workflow run for the commit (GitHub → **Actions** →
the run → **Artifacts** → `security-artifacts`). The upload runs with
`if: always()`, so a **failing** run still leaves the scan output behind;
retention is 14 days. Locally the same directory is gitignored
(`.gitignore`), which is why it never appears in a diff.

Notes for anyone acting on the output:

* The job needs no hosted service and no write-scoped token
  (`permissions: contents: read`, 30-minute timeout), and the scanners are
  installed into a throwaway venv or run as a pinned container — no scanner is a
  project dependency.
* What the gates **do not** do: the SBOM's contents are not evaluated (no
  licence or completeness policy), LOW-severity bandit findings are reported but
  not gated, non-Python files are not scanned, and untracked/gitignored local
  files (including `tests/infra/out/`) are never scanned. The complete list is
  [`docs/security/ci-security.md`](../security/ci-security.md) §7.
* Bumping a pinned tool version is a deliberate edit followed by re-running each
  command locally (`ci-security.md` §10).

## 6. What the operator must do that the library does not

These are not gaps that were forgotten; each is recorded as a deliberate
boundary. Installing JDLib does not discharge them.

1. **Tamper-evident audit storage.** The audit trail is written in the caller's
   transaction and refuses mis-attributed events, but nothing in-database stops
   an actor with write access. Per
   [`docs/security/audit-hardening.md`](../security/audit-hardening.md) §7 the
   deployment must: ship audit rows to append-only storage the application's
   role cannot rewrite (WAL/CDC streaming, retention-locked object storage, a
   SIEM); anchor a periodic digest of each tenant's audit range in that store;
   and keep the application role without `UPDATE`/`DELETE` on `audit_events`
   (the fail-closed design never needs either). Registered as `JDL-AUDIT-03`,
   `not_implemented`, owner `platform-operations`. Absent that, a
   database-level actor can alter history undetectably — the residual risk is
   stated in the same document rather than papered over.
2. **Backup, retention and deletion.** The library owns the schema, the
   lifecycle state machine and the `purge`/`destroy` paths; backup, restore,
   retention windows and the deletion policy are the deployment's. In
   particular, a **shared-schema placement cannot physically delete a tenant
   plane**: `strategy.deprovision` is a no-op there, so `purge`/`destroy` retain
   the tenant-plane rows and only the control-plane deletion is proven by the
   `tenant.deprovisioned` audit record
   ([`docs/jdlib/05-tenant-lifecycle.md`](../jdlib/05-tenant-lifecycle.md) §5) —
   a shared-schema deployment that owes data deletion has to perform it itself.
3. **Key management.** Signing keys, gateway secrets, OIDC client credentials,
   database credentials and their rotation are provisioned and rotated outside
   the library; JDLib reads them from configuration, holds secrets as
   secret-typed values and keeps them out of `repr`, logs, spans, error
   responses and audit metadata. Secret management itself is listed as out of
   scope in [`SECURITY.md`](https://github.com/Abdul-Jaweed/jdlib/blob/main/SECURITY.md), as are database roles and their
   privileges — including the requirement that the RLS runtime role is
   `NOBYPASSRLS`, not the table owner and not a superuser (`README.md`, *RLS
   enablement*).
4. **The network boundary.** Identity assertions are worthless without the
   gateway's secret, but *availability* is what an attacker gains by reaching
   the backend directly: the backend must not be reachable from anywhere except
   the gateway's network
   ([`docs/security/gateway-hardening.md`](../security/gateway-hardening.md) §4).
5. **Declaring the truth.** `posture` describes the profile you name. Nothing
   verifies that the name matches the running deployment's configuration, so the
   declaration is an operational claim, not a control. Live observations
   (catalog, schema revision) reduce the gap but cover the database, not the
   application's settings.
6. **Out-of-band audit for aborted work.** Audit participates in the caller's
   transaction, so a rolled-back operation leaves no audit row — a deliberate
   choice, since a row describing work that never happened is worse for an
   investigator. A deployment that needs a record of aborted operations must add
   its own compensating path (`audit-hardening.md` §4).
7. **Operating the dependencies.** Cerbos, ZITADEL, Kong/Tyk and the telemetry
   collector are yours to run; JDLib's obligation is to fail safely when they
   are unavailable, which is what the tests assert (a degraded policy decision
   is a `503 AuthorizationUnavailable`, still a denial).
8. **Acting on the reports.** The SBOM is evidence, not policy: licence and
   component decisions, and what to do about a gitleaks finding that is a real
   credential (rotate it — never allowlist it), are operational decisions.

## 7. Where to go next

| For | Read |
|---|---|
| What the library guarantees and what it explicitly does not | [`SECURITY.md`](https://github.com/Abdul-Jaweed/jdlib/blob/main/SECURITY.md) |
| The compliance register, evidence and posture, framed for a reviewer | [`docs/compliance/README.md`](../compliance/README.md) |
| The engineering record of the audit trail and its residual risk | [`docs/security/audit-hardening.md`](../security/audit-hardening.md) |
| The CI gates, their exceptions and their blind spots | [`docs/security/ci-security.md`](../security/ci-security.md) |
| Gateway trust, including the Tyk limitation | [`docs/security/gateway-hardening.md`](../security/gateway-hardening.md) |
| The index of security documents | [`docs/security/README.md`](../security/README.md) |
| Local infrastructure for the test layers | [`tests/infra/README.md`](https://github.com/Abdul-Jaweed/jdlib/blob/main/tests/infra/README.md) |
| Building and testing in this repository | [`CONTRIBUTING.md`](https://github.com/Abdul-Jaweed/jdlib/blob/main/CONTRIBUTING.md) |
