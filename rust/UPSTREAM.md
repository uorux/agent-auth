# Tracking the Python

The port follows the Python on branch `agent-sandbox`
(github.com/uorux/agent-auth). Ported up to:

- `090879c` Merge pull request #1 from uorux/security-audit-fixes

Snapshot of upstream's uncommitted work, being ported (taken after it sat
unchanged for 2 h): `refs/upstream-snapshots/2026-10-25` (87c1db9), checked
out read-only at `.claude/worktrees/upstream-snapshot`. Its review log is
`docs/review-2026-10.md` there. It contains:

- platforms `mail` (an address: read / send / read+send / create, narrowed
  by topic, correspondents, since, prefix) and `pool` (lease an item of a
  pool by name, the previous one, or by matching properties); a real
  `google` provisioner with an OAuth consent flow (`google_consent.py`);
  `grant_access.py`, `mail_routes.py`, `discord_bot/mail.py`, `mail/`.

Ported from that snapshot (branch `rust-catchup`): `pool`, the real
`google` and `admin google-consent`, `release_grant`, and every
"Fixed → Existing code" item of the review log outside hostd/hostexec,
sandboxd and mail (checked one by one; most were already fixed in the
port, see DEVIATIONS.md), plus the flagged items: timestamped webhook
signatures without a broker-wide key, the `GoogleTokens` lock, the
stub-era Google rules warning, lowercase GitHub rule resources and project
repos, one `AgentKind`/`Placement`. Not here: `mail` (and
`grant_access.require_web_tool` for mail routes), hostd/hostexec, sandboxd.
