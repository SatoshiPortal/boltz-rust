#!/usr/bin/env bash
set -xe

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting regtest environment..."

cd "$SCRIPT_DIR/proxy"
docker compose down
docker compose up --remove-orphans -d

cd "$SCRIPT_DIR/boltz"
echo "Starting boltz regtest services..."
./start.sh
