#!/usr/bin/env bash
# The source audits of scripts/check.sh, on their own: no `unsafe`, and
# human approvals attested only by authenticated human surfaces. Needs only
# grep and find (the nix flake runs it as checks.<system>.audit).
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

echo "== human approval audit"
# A human's approval is attested only by authenticated human surfaces (core
# approval.rs). Allowed: the broker's auth, Discord and web-panel modules,
# the decision service, the definition, and test code (tests/ directories,
# tests.rs modules). Comments are ignored.
if grep -rnE '\battest\b' --include='*.rs' crates \
  | grep -vE '^[^:]+:[0-9]+:\s*//' \
  | grep -vE '^crates/broker/src/(auth|discord|webui)/' \
  | grep -vE '^crates/broker/src/service/decide[^/]*\.rs:' \
  | grep -vE '^crates/core/src/approval\.rs:' \
  | grep -vE '^crates/[^:]*/tests/' \
  | grep -vE '^crates/[^:]*/tests\.rs:'; then
  echo "!!!!!!!! HumanApproval::attest outside an authenticated human surface !!!!!!!!" >&2
  exit 1
fi
