#!/usr/bin/env bash
# Everything a change must pass. Run inside `nix develop` (rust/flake.nix).
#   scripts/check.sh          # fmt, clippy, tests (e2e too), deny, cooldown, unsafe audit
#   scripts/check.sh quick    # fmt, clippy, unit tests only
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/audit.sh

echo "== fmt"
cargo fmt --all --check

echo "== clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

export DATABASE_URL="$(scripts/pg.sh start)"
echo "== tests"
if [ "${1:-}" = quick ]; then
  cargo nextest run --workspace --locked --lib
  exit 0
fi
# The e2e suite (crates/e2e, ~15 s) runs the workspace's binaries against
# this Postgres: build them first so it never runs stale ones.
cargo build --workspace --bins --locked
cargo nextest run --workspace --locked

echo "== deny"
cargo deny check

echo "== cooldown"
python3 -I scripts/cooldown.py check
COOLDOWN_ROOT=fuzz python3 -I scripts/cooldown.py check
