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
