#!/usr/bin/env bash
# Start the Tyk gateway + redis + echo upstream for the gateway infrastructure
# tests.
#
#   bash tests/infra/tyk/start.sh
#   set -a; . tests/infra/out/tyk-credentials.env; set +a
#   export JDLIB_INFRA_TYK_URL=http://127.0.0.1:8081
#   pytest -q -W error -m infra tests/infra/test_tyk_infra.py
#
# Tyk is heavier to drive than Kong: it needs redis for session storage, node
# configuration to allow the key the tests use, and custom middleware to stamp
# the validity window (see middleware/stamp_window.js).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(cd "$HERE/.." && pwd)/out"
mkdir -p "$OUT"

SECRET="${JDLIB_INFRA_TYK_SECRET:-$(python -c 'import secrets; print(secrets.token_hex(16))')}"
API_KEY="${JDLIB_INFRA_TYK_API_KEY:-$(python -c 'import secrets; print("tyk-" + secrets.token_hex(8))')}"

sed -e "s/__GATEWAY_SECRET__/$SECRET/" "$HERE/apps/documents.json" > "$OUT/tyk-documents.json"

docker network inspect jdlib-infra >/dev/null 2>&1 || docker network create jdlib-infra

docker rm -f jdlib-echo >/dev/null 2>&1 || true
docker run -d --name jdlib-echo --network jdlib-infra mendhak/http-https-echo:31 >/dev/null

docker rm -f jdlib-tyk-redis >/dev/null 2>&1 || true
docker run -d --name jdlib-tyk-redis --network jdlib-infra redis:7-alpine >/dev/null

docker rm -f jdlib-tyk >/dev/null 2>&1 || true
docker run -d --name jdlib-tyk --network jdlib-infra \
    -e TYK_GW_SECRET="$SECRET" \
    -e TYK_GW_STORAGE_TYPE=redis \
    -e TYK_GW_STORAGE_HOST=jdlib-tyk-redis \
    -e TYK_GW_STORAGE_PORT=6379 \
    -e TYK_GW_STORAGE_USESSL=false \
    -e TYK_GW_HASHKEYS=false \
    -e TYK_GW_ALLOWMASTERKEYS=true \
    -e TYK_GW_HOSTNAME=jdlib-tyk \
    -e TYK_GW_LISTENPORT=8080 \
    -e TYK_GW_ENABLEANALYTICS=false \
    -e TYK_GW_ENABLEJSVM=true \
    -e TYK_GW_MIDDLEWARE_JSVMPATH=/opt/tyk-gateway/middleware \
    -p 127.0.0.1:8081:8080 \
    -v "$OUT/tyk-documents.json:/opt/tyk-gateway/apps/documents.json:ro" \
    -v "$HERE/middleware:/opt/tyk-gateway/middleware:ro" \
    tykio/tyk-gateway:v5.3.1 >/dev/null

echo "waiting for Tyk..."
for _ in $(seq 1 60); do
    if curl -fsS -m 2 -H "x-tyk-authorization: $SECRET" http://127.0.0.1:8081/tyk/apis >/dev/null 2>&1; then
        echo "Tyk is up."
        break
    fi
    sleep 2
done

# The key the tests authenticate with. access_rights keeps it scoped to this API
# (a key without them would be a master key, which is disabled by default).
curl -sS -m 5 -X POST "http://127.0.0.1:8081/tyk/keys/$API_KEY" \
    -H "x-tyk-authorization: $SECRET" \
    -H "Content-Type: application/json" \
    -d '{"alias":"jdlib-infra","org_id":"jdlib","rate":8,"per":60,"access_rights":{"documents":{"api_id":"documents","api_name":"Documents","versions":["Default"],"allowed_urls":[]}}}' \
    || echo "warning: key creation returned an error; see docker logs jdlib-tyk" >&2

curl -sS -m 5 -o /dev/null "http://127.0.0.1:8081/tyk/reload/group" \
    -H "x-tyk-authorization: $SECRET" || true

printf 'export JDLIB_INFRA_TYK_SECRET=%s\nexport JDLIB_INFRA_TYK_API_KEY=%s\n' "$SECRET" "$API_KEY" \
    > "$OUT/tyk-credentials.env"

echo "credentials written to $OUT/tyk-credentials.env"
echo "export JDLIB_INFRA_TYK_URL=http://127.0.0.1:8081"
