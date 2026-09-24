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

## 6. Tyk live harness: provided, not verified (directive §19)

`tests/infra/tyk/` contains a complete, reproducible harness: an API definition
(`apps/documents.json`) with key auth, rate limiting, `global_headers` and a
custom middleware, the middleware itself (`middleware/stamp_window.js`) that
stamps a fresh validity window, a start script that provisions redis, the
gateway and an API key, and `tests/infra/test_tyk_infra.py`, which asserts the
same properties as the Kong suite and skips unless the stack is running.

It was **not** executed successfully in this environment, and no part of it is
claimed as verified. Two concrete observations from the attempt, so a follow-up
does not start from zero:

1. **The blocker:** Tyk 5.3.1 OSS rejects a `javascript` custom-middleware
   driver with *"Your API specifies a CP custom middleware, either Tyk wasn't
   build with CP support or CP is not enabled in your Tyk configuration file!"*
   — the stock image has no JSVM/coprocess plugin runtime. The validity window
   therefore cannot be stamped by `global_headers` alone (they are static, and a
   static window is correctly *rejected* by the adapter, which is the replay
   protection working). A working harness needs a Tyk build with a rich-plugin
   runtime (gRPC plugin server or the Python-enabled image) to stamp the window.
2. **Secondary:** with the JS middleware present, the gateway loaded the API but
   answered `404 Not Found` for `/documents/42`, i.e. the route did not match
   under this configuration; that needs to be resolved before the harness can
   pass even with a plugin runtime.

Until then the honest status is: the *adapter* is verified by unit tests, the
*deployment* is not verified against a live Tyk, and a Tyk deployment that sends
a static validity window will be refused by the adapter (fail closed).

## 7. Deferred (explicitly not implemented)

* The adapters are not yet wired into the FastAPI request path or the tenant
  resolution chain (same deferral as the PEP: the request-edge rework belongs to
  the integration phase, with its own tests).
* Kong's `X-Consumer-*` headers are supported via configuration overrides but
  the test configuration uses the `x-jdlib-*` convention.
* No mTLS channel authentication is implemented; both adapters authenticate the
  channel with a shared secret or an HMAC signature.
