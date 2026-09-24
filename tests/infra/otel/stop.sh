#!/usr/bin/env bash
# Tear the observability collector down. Safe to run when it was never started.
set -euo pipefail
docker rm -f jdlib-otel-collector >/dev/null 2>&1 || true
echo "collector removed"
