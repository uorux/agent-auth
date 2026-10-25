#!/usr/bin/env bash
# Run every Kani proof harness in the workspace, inside the `kani` dev shell
# (rust/flake.nix; Kani itself is rust/nix/kani.nix).
#   scripts/kani.sh                          # all crates that have harnesses
#   scripts/kani.sh --harness status_machine # extra args go to `cargo kani`
set -euo pipefail
cd "$(dirname "$0")/.."

# A crate has harnesses when one of its sources has `#[kani::proof]`.
packages=()
for manifest in crates/*/Cargo.toml; do
  dir=$(dirname "$manifest")
  if grep -rqF '#[kani::proof' "$dir/src"; then
    name=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest" | head -n1)
    packages+=(-p "$name")
  fi
done
if [ ${#packages[@]} -eq 0 ]; then
  echo "no Kani harnesses found" >&2
  exit 1
fi

echo "== kani: ${packages[*]}"
exec nix develop "$PWD#kani" -c cargo kani "${packages[@]}" "$@"
