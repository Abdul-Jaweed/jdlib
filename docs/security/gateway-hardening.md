# Gateway Hardening (Phase 4)

Status: **COMPLETE** for the adapter layer and for Kong; **PARTIAL** for Tyk —
its adapter is implemented and unit-verified, its live harness is provided but
could not be executed in this environment (§19 requires documenting that rather
than marking it verified; see §6).

Source: `src/jdlib/security/gateway/` (new)
Tests: `tests/unit/security/test_gateway_adapters.py`,
`tests/infra/test_kong_infra.py` (real Kong),
`tests/infra/test_tyk_infra.py` (real Tyk, skipped unless the stack is up)
Harnesses: `tests/infra/kong/`, `tests/infra/tyk/`

| Evidence | Result |
|---|---|
| Unit (gateway adapters) | 27 passed |
| Infra against real Kong 3.6 | 9 passed (skipped without the Kong env vars) |
| `ruff check .` / `mypy src/jdlib` | clean |

---

## 1. The property this phase establishes

An identity asserted by the edge is trusted **only** when the channel it arrived
on is authenticated. `GatewayAdapter` is the port (spec #12); the adapters are:

| Adapter | Trust model |
|---|---|
| `NoGatewayAdapter` | no gateway: identity headers are ignored outright, so a direct caller cannot impersonate a user or tenant |
| `SharedSecretGatewayAdapter` (Kong) | identity headers are trusted only when the request carries the gateway's own secret, the assertion is complete, and its validity window is sane |
| `TykGatewayAdapter` | same verification, Tyk's header conventions (`x-tyk-jdlib-*`) by default |
| HMAC mode | the assertion is signed over subject, tenant, scopes and window; any tampering invalidates it |

## 2. Fail-closed rules (each has a test)

| Condition | Result |
|---|---|
| Secret missing, empty or wrong | no identity (identical outcome — nothing to distinguish for a caller) |
| Assertion incomplete (no subject, unparsable timestamps) | no identity |
| Window expired or not yet valid | no identity |
| Window wider than `2 × max_skew` (replay) | no identity |
| Signature mode receiving only a secret header | no identity (no downgrade) |
| Shared-secret mode receiving only a signature | no identity (no substitution) |
| Tampered subject/tenant/scopes/window under signature | no identity |
| `NONE` mode configured with a secret | rejected at construction (a gateway that is not verified must not look verified) |
| Secret shorter than 32 bytes | rejected at construction |

Secrets are held as `SecretStr`; `repr`, `model_dump()` and `model_dump_json()`
never contain them. Unknown configuration fields are rejected, so a deployment
cannot add a "trust headers" switch.

## 3. Real Kong (directive §18)

`tests/infra/kong/kong.yml` is a declarative, DB-less Kong 3.6 configuration and
`kong/start.sh` brings the stack up with per-run generated credentials. The
upstream reflects the request it received, so what the gateway forwarded is
directly observable. Verified end to end:

| Requirement | Evidence |
|---|---|
| Routing | a gateway request reaches the upstream with the path intact |
| Authentication | no key → 401 "No API key found in request"; wrong key → 401 "Unauthorized" (Kong's answer, not the backend's) |
| Identity propagation | the upstream receives `x-jdlib-subject/-tenant/-scopes` and the gateway secret, and the adapter verifies the resulting assertion |
| Request ids | `x-request-id` reaches the upstream, differs per request, and is echoed downstream |
| Spoofed headers | a caller's `x-jdlib-subject: admin`, foreign tenant, `tenants:admin` scope and forged secret are all replaced; the adapter then yields the gateway's identity, not the caller's |
| Forged validity window | a caller's `issued=0`/`expires=4102444800` is replaced by the gateway's fresh window; the adapter accepts the gateway's values only |
| Rate limiting | the rate-limited route returns 429 at the edge (8/minute per consumer), 200s before it |
| Failure behaviour | off-gateway identity claims never verify, and `NoGatewayAdapter` ignores headers entirely |

### A vendor trap worth recording

Kong's `request-transformer` `replace` only touches headers that **already
exist**: a caller who omits the identity headers gets them omitted upstream, and
a caller who sends them gets them replaced. The configuration therefore uses
`remove` **then** `add`, which yields exactly one canonical value in every case
(`add` alone would append, leaving a smuggled duplicate behind). The tests
assert both halves, and the incident is documented in `kong.yml` itself.

## 4. Gateway failure and the backend

The tests establish that identity claims are worthless without the gateway's
secret, which is what makes a bypass harmless *for identity*. The remaining
requirement is a deployment property, not a code property, and is stated here
so it is not mistaken for something the library can enforce: the backend must
not be reachable from anywhere except the gateway's network, because
availability (not identity) is what an attacker gains by reaching it directly.
`NoGatewayAdapter` is the safe configuration when no gateway fronting exists.

## 5. Tyk adapter (verification scope)

The adapter is implemented, unit-tested and satisfies the port; its default
header conventions are `x-tyk-jdlib-{subject,tenant,scopes,issued-at,expires-at,
gateway-secret,signature}`, and everything in §2 applies to it unchanged.

## 6. Tyk live harness: verified (directive §19)

**Corrected 2026-09-25 - the harness passes all six of its tests, and both
observations recorded below turned out to be fixture defects, not gateway limits.**

`tests/infra/tyk/` contains a complete, reproducible harness: an API definition
(`apps/documents.json`) with key auth, rate limiting, `global_headers` and a
custom middleware, the middleware itself (`middleware/stamp_window.js`) that
stamps a fresh validity window, a start script that provisions redis, the
gateway and an API key, and `tests/infra/test_tyk_infra.py`, which asserts the
same properties as the Kong suite and skips unless the stack is running.

The two observations recorded during the failed attempt were both re-diagnosed, and
each was a defect in *this harness* rather than in Tyk:

1. *"Your API specifies a CP custom middleware"* did **not** mean the image lacks a
   runtime. It is what Tyk logs when a middleware entry names a driver it does not
   know: this harness wrote `"driver": "javascript"`, and Tyk's JavaScript driver is
   **`otto`**. With the correct driver the JSVM loads the file
   (`Loading JS File: ... prefix=jsvm`) and stamps the window per request.
   `global_headers` alone would indeed be static - and therefore correctly refused -
   so the middleware is genuinely needed; a rich-plugin (gRPC/Python) build is not.
2. The `404 Not Found` was the real blocker and was also a harness defect: the start
   script passed `TYK_GW_HOSTNAME=jdlib-tyk`, which Tyk uses as the *default domain*
   for API definitions that declare none, so it routed only requests carrying
   `Host: jdlib-tyk` - including Tyk's own shipped sample API - and answered 404 to
   everything else. The test client sends no Host at all.

Three further defects were fixed on the way: the rendered gateway config never
substituted its own `__GATEWAY_SECRET__` placeholder, so every administrative call
from the start script failed silently; the middleware's global was named
`stampWindow` while the definition's entry is `stamp_window` (Tyk looks the entry's
name up in the file, so the request failed with `ReferenceError`); and
`strip_listen_path: false` with a path in `target_url` doubled the upstream path
while `global_headers` sat at the top level of the definition, where Tyk ignores it
instead of adding it to the version.

The honest status now: the *adapter* is verified by unit tests **and** the
*deployment* is verified against a live Tyk 5.3.1 - all six tests in
`tests/infra/test_tyk_infra.py` pass with the harness up. The fail-closed property
is unchanged and still unit-verified: a deployment that sends a *static* validity
window is refused exactly as a replayed one is.

## 7. Deferred (explicitly not implemented)

* **Still true, stated precisely.** The adapters are not wired into the
  library's FastAPI request path or its tenant resolution chain: a deployment
  wires them at its own edge, as the reference application does (its
  `security.py` builds `KongGatewayAdapter`), which is the shape this deferral
  anticipated. The library ships the adapters, their envelope verification and
  their tests; it does not choose a gateway for you.
* Kong's `X-Consumer-*` headers are supported via configuration overrides but
  the test configuration uses the `x-jdlib-*` convention.
* No mTLS channel authentication is implemented; both adapters authenticate the
  channel with a shared secret or an HMAC signature.
