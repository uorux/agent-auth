# Tracking the Python

The port follows the Python on branch `agent-sandbox`
(github.com/uorux/agent-auth). Ported up to:

- `090879c` Merge pull request #1 from uorux/security-audit-fixes

Seen in progress upstream (uncommitted in the main checkout, 2026-10-25),
to port once committed:

- platforms `mail` (an address: read / send / read+send / create, narrowed
  by topic, correspondents, since, prefix) and `pool` (lease an item of a
  pool by name, the previous one, or by matching properties); a real
  `google` provisioner with an OAuth consent flow (`google_consent.py`);
  `grant_access.py`, `mail_routes.py`, `discord_bot/mail.py`, `mail/`.
