#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export AGENT_CONTENT_FIREWALL_ROOT="$ROOT_DIR"

exec npx @deepseek-ai/dsh --patch "$ROOT_DIR/adapters/deepseek-harness/cordis.patch.yml" "$@"
