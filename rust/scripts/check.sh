#!/usr/bin/env bash
# Everything a change must pass. Run inside `nix develop` (rust/flake.nix).
#   scripts/check.sh          # fmt, clippy, tests, deny, cooldown, unsafe audit
#   scripts/check.sh quick    # fmt, clippy, unit tests only
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== unsafe audit"
# No `unsafe` anywhere in our code, and every crate root forbids it.
if grep -rnE '\bunsafe\b' --include='*.rs' crates fuzz 2>/dev/null | grep -vE '^\S+:\s*(//|\*)' | grep -v 'forbid(unsafe_code)' | grep -v 'unsafe_code'; then
  echo "!!!!!!!! UNSAFE CODE FOUND — not allowed in this workspace !!!!!!!!" >&2
  exit 1
fi
for root in $(find crates -path '*/src/lib.rs' -o -path '*/src/main.rs' -o -path '*/src/bin/*.rs'); do
  grep -q '^#!\[forbid(unsafe_code)\]' "$root" || { echo "$root lacks #![forbid(unsafe_code)]" >&2; exit 1; }
done

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
cargo nextest run --workspace --locked

echo "== deny"
cargo deny check

echo "== cooldown"
python3 -I scripts/cooldown.py check
