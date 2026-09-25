#!/usr/bin/env bash
# Start the Kong gateway + echo upstream for the gateway infrastructure tests.
#
#   bash tests/infra/kong/start.sh          # generate config, start containers
#   export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:8000
#   export JDLIB_INFRA_KONG_SECRET=<printed secret>
#   export JDLIB_INFRA_KONG_CLIENT_KEY=<printed key>
#   pytest -q -W error -m infra tests/infra/test_kong_infra.py
#
# The gateway secret and the client key are generated per run and written to a
# local file that is not tracked by git.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(cd "$HERE/.." && pwd)/out"
mkdir -p "$OUT"

SECRET="${JDLIB_INFRA_KONG_SECRET:-$(python -c 'import secrets; print(secrets.token_hex(24))')}"
CLIENT_KEY="${JDLIB_INFRA_KONG_CLIENT_KEY:-$(python -c 'import secrets; print("key-" + secrets.token_hex(8))')}"

sed -e "s/__GATEWAY_SECRET__/$SECRET/" -e "s/__CLIENT_KEY__/$CLIENT_KEY/" \
    "$HERE/kong.yml" > "$OUT/kong.yml"
printf 'export JDLIB_INFRA_KONG_SECRET=%s\nexport JDLIB_INFRA_KONG_CLIENT_KEY=%s\n' "$SECRET" "$CLIENT_KEY" \
    > "$OUT/kong-credentials.env"

docker network inspect jdlib-infra >/dev/null 2>&1 || docker network create jdlib-infra

# Ports are overridable because this harness has to coexist with the reference application's
# own lab on a developer machine: its Kong holds 8000/8001. Same shape as the Tyk harness,
# which takes its URL from the environment.
PROXY_PORT="${JDLIB_INFRA_KONG_PROXY_PORT:-8000}"
ADMIN_PORT="${JDLIB_INFRA_KONG_ADMIN_PORT:-8001}"

# upstream that reflects what the gateway forwarded
docker rm -f jdlib-echo >/dev/null 2>&1 || true
docker run -d --name jdlib-echo --network jdlib-infra mendhak/http-https-echo:31 >/dev/null

# Kong: DB-less, declarative configuration mounted read-only
docker rm -f jdlib-kong >/dev/null 2>&1 || true
docker run -d --name jdlib-kong --network jdlib-infra \
    -e KONG_DATABASE=off \
    -e KONG_DECLARATIVE_CONFIG=/kong/declarative/kong.yml \
    -e KONG_PROXY_LISTEN=0.0.0.0:8000 \
    -e KONG_ADMIN_LISTEN=0.0.0.0:8001 \
    -e KONG_PROXY_ACCESS_LOG=/dev/stdout \
    -e KONG_ADMIN_ACCESS_LOG=/dev/stdout \
    -e KONG_PROXY_ERROR_LOG=/dev/stderr \
    -e KONG_LOG_LEVEL=notice \
    -p "127.0.0.1:${PROXY_PORT}:8000" \
    -p "127.0.0.1:${ADMIN_PORT}:8001" \
    -v "$OUT/kong.yml:/kong/declarative/kong.yml:ro" \
    kong:3.6 >/dev/null

echo "waiting for Kong (admin API + declarative config)..."
for _ in $(seq 1 60); do
    if curl -fsS -m 2 "http://127.0.0.1:${ADMIN_PORT}/status" >/dev/null 2>&1 \
        && curl -fsS -m 2 "http://127.0.0.1:${ADMIN_PORT}/routes" >/dev/null 2>&1; then
        echo "Kong is up."
        break
    fi
    sleep 2
done

curl -fsS -m 5 "http://127.0.0.1:${ADMIN_PORT}/routes" >/dev/null || {
    echo "Kong did not become ready; see: docker logs jdlib-kong" >&2
    exit 1
}

echo "gateway secret and client key written to $OUT/kong-credentials.env"
echo "export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:${PROXY_PORT}"
