# Local infrastructure stack

Real infrastructure for the layers above the unit tests — a policy engine, an
identity provider, two gateways, a collector and PostgreSQL — so the suites can
assert against protocols rather than against doubles.

The layers are selected by **directory**, not by marker (the markers exist, but
most tests carry none):

| Layer | Command | Needs |
| --- | --- | --- |
| Unit | `pytest tests/unit` | nothing |
| Integration | `pytest tests/integration` | Docker (testcontainers) or `JDLIB_TEST_DATABASE_URL` |
| Infra (this directory) | `pytest tests/infra` | the harness below |

Every infra suite **skips cleanly** when its service is absent: each guards on the
variable or file its bring-up writes, so a machine without the harness reports
skips rather than failures. A skip is not evidence — run this layer with the
harness up when this layer is what you are verifying.

## The services

| Service | Image as pinned here | Suite | Purpose |
| --- | --- | --- | --- |
| `postgres` | `postgres:16` | optional for `tests/integration` | an alternative to the testcontainers database, via `JDLIB_INFRA_POSTGRES_DSN` |
| `cerbos` | `ghcr.io/cerbos/cerbos:0.37.0` | `test_cerbos_infra.py` | external authorization decisions (PDP) |
| `redis` | `redis:7-alpine` | — | published for the cache and rate-limit URLs; the infra suites reach services by URL and need neither this nor Postgres |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.110.0` (`JDLIB_INFRA_OTEL_IMAGE`) | `test_otel_infra.py` | what actually left the process: spans, metrics, and a secret that must not appear |
| `zitadel` (+ `zitadel-db`) | `ghcr.io/zitadel/zitadel:latest` | `test_zitadel_infra.py` | a real identity provider; local-only, see below |
| `kong` + `jdlib-echo` | `kong:3.6`, `mendhak/http-https-echo:31` | `test_kong_infra.py` | gateway behaviour: routing, edge auth, identity propagation, rate limiting |
| `tyk` | `tykio/tyk-gateway:v5.3.1` | `test_tyk_infra.py` | the second gateway's plugin semantics (JSVM window, session metadata) |

Cerbos, Kong and Tyk are pinned to the versions above deliberately: this suite
verifies *protocol* behaviour (decision payloads, plugin execution, header
propagation), so the version is part of the fixture. The reference application's
lab pins newer ones (Cerbos 0.54.0, ZITADEL v4.16.2) and is a separate stack —
the two coexist on one machine, which is why every port here is overridable.
`zitadel` is the one floating tag (`latest`): pin it locally if you need a
reproducible identity provider.

## Bring-up

```bash
# the compose services the infra suites talk to
docker compose -f tests/infra/docker-compose.yml up -d cerbos otel-collector zitadel

# the three standalone harnesses; each writes its credentials/env file under tests/infra/out/
bash tests/infra/kong/start.sh && . tests/infra/out/kong-credentials.env
bash tests/infra/otel/start.sh && . tests/infra/out/otel.env
bash tests/infra/tyk/start.sh  && . tests/infra/out/tyk-credentials.env

export TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1
pytest tests/infra -q -W error
```

Two things that bite on a developer machine:

* **Do not start the whole compose file.** It publishes 6379 and 5432, which are
  popular ports and are often already taken — the bring-up then fails on the bind
  and takes the rest of the stack with it. The infra suites reach their services
  by URL and need neither, so name the services (`cerbos otel-collector zitadel`),
  which is also what `scripts/ci-local.sh` expects.
* **The gateway ports are overridable.** Kong's harness prints the proxy URL it
  bound and takes `JDLIB_INFRA_KONG_PROXY_PORT` / `JDLIB_INFRA_KONG_ADMIN_PORT`
  (defaults 8000/8001); export the URL it printed. Tyk listens on 8081.

`docker compose -f tests/infra/docker-compose.yml down -v` stops the compose
services and removes their volumes; the standalone harnesses have their own
teardown beside them (`tests/infra/otel/stop.sh`).

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `JDLIB_INFRA_POSTGRES_DSN` | `postgresql://jdlib:***@127.0.0.1:5432/jdlib` | the compose Postgres, when it is used instead of testcontainers |
| `JDLIB_INFRA_CERBOS_URL` | `http://127.0.0.1:3592` | Cerbos endpoint; **unset means the Cerbos suite skips** |
| `JDLIB_INFRA_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis endpoint |
| `JDLIB_INFRA_OTLP_ENDPOINT` | `http://127.0.0.1:4318` | OTLP/HTTP collector endpoint |
| `JDLIB_INFRA_OTEL_IMAGE` | `otel/opentelemetry-collector-contrib:0.110.0` | the collector image both routes use |
| `JDLIB_INFRA_OTEL_OTLP_HTTP` / `_OUTPUT` / `_PROMETHEUS` / `_INTERNAL_METRICS` | written to `tests/infra/out/otel.env` | the collector's endpoints and its file-exporter directory; the OTel suite skips when that file is absent |
| `JDLIB_INFRA_KONG_PROXY_URL` (+ `_SECRET`, `_CLIENT_KEY`) | printed by `tests/infra/kong/start.sh`, written to `tests/infra/out/kong-credentials.env` | Kong proxy URL and the credentials its plugins verify |
| `JDLIB_INFRA_KONG_PROXY_PORT` / `_ADMIN_PORT` | `8000` / `8001` | host ports for the Kong harness |
| `JDLIB_INFRA_TYK_URL` (+ `_SECRET`, `_API_KEY`) | `http://127.0.0.1:8081`, written to `tests/infra/out/tyk-credentials.env` | Tyk gateway URL and credentials |
| `JDLIB_INFRA_ZITADEL_ISSUER` | `http://127.0.0.1:8080` | ZITADEL issuer; **unset means the ZITADEL suite skips** |
| `TESTCONTAINERS_HOST_OVERRIDE` | — | `127.0.0.1` on Docker Desktop, where the container IP is not routable from the host |

## ZITADEL

`zitadel` is a heavyweight stack (its own database schema, first-run migrations,
~1 minute to become ready) and pulls an image of several hundred megabytes. It is
therefore **local-only**: the tests that use it skip unless
`JDLIB_INFRA_ZITADEL_ISSUER` is set, so CI stays hermetic.

The hermetic `integration` layer covers the same code paths against a real HTTP
server and real RSA keys (`tests/integration/test_authn_http_integration.py`), so
a ZITADEL outage cannot hide a regression: the vendor-specific part left to the
local stack is configuration fidelity (issuer paths, discovery document, real
client credentials).

The first-run masterkey must be exactly 32 characters, as ZITADEL requires; for
local use the compose file falls back to an obvious placeholder. Never reuse it
anywhere reachable from a network.

## The collector, and its two routes

The compose service `otel-collector` and `tests/infra/otel/start.sh` bring up the
*same* container (`jdlib-otel-collector`) from the *same* configuration
(`tests/infra/otel/collector.yaml`), with the file exporter writing to
`tests/infra/out/otel/`. Use one route or the other — `start.sh` replaces the
container (`docker rm -f`) rather than fighting it for the name, and it is also
what writes `tests/infra/out/otel.env`, which the suite reads, so run it at least
once. The suite stamps each run with its own start time and filters on it, so a
stale store from a previous run cannot make it pass.

## Gateway (Kong)

Kong is DB-less (declarative config) and its upstream is a service that reflects
the request it received, so what the gateway forwarded is directly observable:

```bash
bash tests/infra/kong/start.sh                  # generates credentials, starts Kong + upstream
. tests/infra/out/kong-credentials.env          # secret + client key (not tracked by git)
export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:8000
pytest tests/infra/test_kong_infra.py -q -W error
```

`tests/infra/kong/kong.yml` is the full declarative configuration: `key-auth` on
the route, `correlation-id`, `rate-limiting` (8/minute per consumer),
`request-transformer` that *replaces* the identity headers, and a `pre-function`
that stamps a fresh validity window. See the header comment in that file for why
each plugin is security-relevant.

## The Tyk harness

The suite is verified: with `bash tests/infra/tyk/start.sh` up, **all six tests
pass**. Getting there meant fixing five fixture defects, each found by measurement
rather than reading:

1. **`TYK_GW_HOSTNAME=jdlib-tyk` (the reason every route 404'd).** Tyk uses the
   configured hostname as the *default domain* for API definitions that declare
   none, so the gateway routed only requests carrying `Host: jdlib-tyk` and
   answered 404 — including for Tyk's own shipped sample API — to everything else.
   The suite's own client sends no Host at all. The gateway now runs with no
   hostname, so its APIs match any host.
2. **The rendered config never rendered its secret.** `sed` replaced the Redis host
   but left `__GATEWAY_SECRET__` in place; the gateway then used that
   18-character placeholder as its secret while `tyk-credentials.env` held the real
   one, so every administrative call from the start script (`/tyk/keys/...`,
   `/tyk/reload/group`) failed silently and no session existed for the key the
   tests use.
3. **`"driver": "javascript"` is not a driver Tyk knows.** The JavaScript
   middleware was therefore classified as coprocess, logged as `Your API specifies
   a CP custom middleware ... CP is not enabled` next to `Rich plugins are
   disabled`, and never ran — which is why the window it stamps was absent. The
   JSVM driver is **`otto`**.
4. **The middleware's global was named `stampWindow`, the definition's entry
   `stamp_window`.** Tyk's JSVM looks the entry's name up in the file, so every
   request failed with `ReferenceError: 'stamp_window' is not defined` once the
   middleware was live.
5. **Two schema mistakes:** `strip_listen_path: false` combined with a path in
   `target_url` produced `/documents/documents/42` upstream, and `global_headers`
   sat at the top level of the definition where Tyk ignores it — it belongs to the
   version, which is why the identity headers never reached the upstream.

The earlier note here — "stock Tyk 5.3.1 has no JavaScript runtime, so the plugin
never loads" — was wrong twice over: this image ships JSVM, and the plugin not
loading had five fixable causes.
