#!/usr/bin/env bash
# Bring up an OpenTelemetry Collector for the observability tests (Phase 7.5).
#
#   bash tests/infra/otel/start.sh          # start (idempotent)
#   bash tests/infra/otel/stop.sh           # tear down
#
# Writes tests/infra/out/otel.env with the endpoint and the file exporter's
# output path; the infra test skips cleanly when that file is absent, so a
# machine without Docker is not a failing machine.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="$root/tests/infra/out"
mkdir -p "$out/otel"
chmod 777 "$out/otel" 2>/dev/null || true

collector_image="${JDLIB_INFRA_OTEL_IMAGE:-otel/opentelemetry-collector-contrib:0.110.0}"
name="jdlib-otel-collector"

echo "--- pulling $collector_image ---"
timeout 900 docker pull "$collector_image" >/dev/null

docker rm -f "$name" >/dev/null 2>&1 || true

echo "--- starting collector ---"
docker run -d --name "$name" \
  -p 127.0.0.1:4317:4317 \
  -p 127.0.0.1:4318:4318 \
  -p 127.0.0.1:8889:8889 \
  -p 127.0.0.1:8888:8888 \
  -p 127.0.0.1:13133:13133 \
  -v "$here/collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  -v "$out/otel:/out" \
  "$collector_image" --config=/etc/otelcol-contrib/config.yaml >/dev/null

echo "--- waiting for readiness ---"
ready=0
for _ in $(seq 1 40); do
  if curl -fsS -m 2 http://127.0.0.1:13133/ >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "collector did not become ready; last logs:" >&2
  docker logs --tail 30 "$name" >&2 || true
  exit 1
fi

printf 'export JDLIB_INFRA_OTEL_OTLP_HTTP=%s\n' "http://127.0.0.1:4318" > "$out/otel.env"
printf 'export JDLIB_INFRA_OTEL_OUTPUT=%s\n' "$out/otel/telemetry.jsonl" >> "$out/otel.env"
printf 'export JDLIB_INFRA_OTEL_PROMETHEUS=%s\n' "http://127.0.0.1:8889/metrics" >> "$out/otel.env"
printf 'export JDLIB_INFRA_OTEL_INTERNAL_METRICS=%s\n' "http://127.0.0.1:8888/metrics" >> "$out/otel.env"

echo "collector ready:"
cat "$out/otel.env"
