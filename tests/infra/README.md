# Local infrastructure stack (directive §5)

Real infrastructure for the layers above the unit tests. Nothing here is
required for `pytest -m unit`; the hermetic integration suite
(`pytest -m integration`) runs without Docker.

| Service | Image | Used by | Purpose |
| --- | --- | --- | --- |
| `postgres` | `postgres:16` | `-m integration`, `-m infra` | tenancy, RLS, audit and outbox persistence |
| `cerbos` | `ghcr.io/cerbos/cerbos:0.37.0` | `-m infra`, `-m e2e` | external authorisation decisions (PDP) |
| `redis` | `redis:7-alpine` | `-m infra` | rate limiting and distributed token caches |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.110.0` | `-m infra`, `-m e2e` | trace/metric export verification |
| `zitadel` | `ghcr.io/zitadel/zitadel:latest` | `-m infra` (local only) | identity provider for real token flows |
| `kong` + `jdlib-echo` | `kong:3.6`, `mendhak/http-https-echo:31` | `-m infra` (local only) | real gateway behaviour: routing, edge auth, identity propagation, rate limiting |

## Gateway (Kong)

Kong is DB-less (declarative config) and its upstream is a service that reflects
the request it received, so what the gateway forwarded is directly observable:

```bash
bash tests/infra/kong/start.sh                  # generates credentials, starts Kong + upstream
source tests/infra/out/kong-credentials.env     # secret + client key (not tracked by git)
export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:8000
pytest -q -W error -m infra tests/infra/test_kong_infra.py
```

`tests/infra/kong/kong.yml` is the full declarative configuration: `key-auth` on
the route, `correlation-id`, `rate-limiting` (8/minute per consumer),
`request-transformer` that *replaces* the identity headers, and a
`pre-function` that stamps a fresh validity window. See the header comment in
that file for why each plugin is security-relevant.


## Usage

```bash
# the whole stack
docker compose -f tests/infra/docker-compose.yml up -d

# just the persistence layer used by the integration tests
docker compose -f tests/infra/docker-compose.yml up -d postgres

docker compose -f tests/infra/docker-compose.yml down -v
```

Export the host override when running tests against these containers
(Testcontainers and the compose services both publish to `127.0.0.1`):

```bash
export TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1
pytest -q -W error -m "integration or infra"
```

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `JDLIB_INFRA_POSTGRES_DSN` | `postgresql://jdlib:jdlib@127.0.0.1:5432/jdlib` | DSN for the `postgres` service |
| `JDLIB_INFRA_CERBOS_URL` | `http://127.0.0.1:3592` | Cerbos gRPC/HTTP endpoint |
| `JDLIB_INFRA_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis endpoint |
| `JDLIB_INFRA_OTLP_ENDPOINT` | `http://127.0.0.1:4318` | OTLP/HTTP collector endpoint |
| `JDLIB_INFRA_ZITADEL_ISSUER` | `http://127.0.0.1:8080` | ZITADEL issuer; **unset means the ZITADEL infra tests skip** |

## ZITADEL

`zitadel` is a heavyweight stack (its own database schema, `start-from-init`
migrations, ~1 minute to become ready) and pulls an image of several hundred
megabytes. It is therefore **local-only**: the `infra`-marked tests that use it
skip unless `JDLIB_INFRA_ZITADEL_ISSUER` is set, so CI stays hermetic.

The hermetic `integration` layer covers the same code paths against a real
HTTP server and real RSA keys (`tests/integration/test_authn_http_integration.py`),
so a ZITADEL outage cannot hide a regression: the vendor-specific part left to
the local stack is configuration fidelity (issuer paths, discovery document,
real client credentials).

The first-run masterkey must be exactly 32 characters, as required by ZITADEL;
for local use the compose file falls back to an obvious placeholder. Never
reuse it anywhere reachable from a network.
