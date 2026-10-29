#!/usr/bin/env bash
# Run the pure crates' unit tests under Miri. Slow (core alone takes over an
# hour), so it is not part of check.sh. Run inside `nix develop .#nightly`.
#
# agent-auth-crypto is left out: its tests call ring, whose primitives are
# assembly and C that Miri cannot interpret ("can't call foreign function").
# Tests that spawn processes or use FIFOs are marked to be skipped under Miri.
set -euo pipefail
cd "$(dirname "$0")/.."

export SQLX_OFFLINE=true PROPTEST_CASES=4 MIRIFLAGS="-Zmiri-disable-isolation"
for c in agent-auth-core agent-auth-wire; do
  echo "== $c"
  cargo miri test -p "$c" --lib
done
