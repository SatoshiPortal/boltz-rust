#!/usr/bin/env bash
set -xe

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR/boltz"
./stop.sh

cd "$SCRIPT_DIR/proxy"
docker compose down --volumes
