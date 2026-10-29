#!/usr/bin/env bash
# Regenerate rust/fuzz/Cargo.toml's [[bin]] list from fuzz/fuzz_targets/*.rs
# (one target per file), keeping everything above the first [[bin]].
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
head=$(sed '/^\[\[bin\]\]/,$d' Cargo.toml)
{
  printf '%s\n' "$head"
  for f in fuzz_targets/*.rs; do
    t=$(basename "$f" .rs)
    printf '\n[[bin]]\nname = "%s"\npath = "%s"\ntest = false\ndoc = false\nbench = false\n' "$t" "$f"
  done
} > Cargo.toml.new
mv Cargo.toml.new Cargo.toml
