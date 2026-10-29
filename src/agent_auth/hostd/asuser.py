"""The last step before a user-tier job runs on macOS (docs/hostd-macos.md).

hostd (root) starts `launchctl asuser <uid> <python> -I -m agent_auth.hostd.asuser
<spec>`: launchctl moves the process into the user's own launchd domain (their
login session's services: the simulators, the pasteboard, the keychain's
session), still as root, and this module then becomes the user for good and
runs the job. It can't be done in the other order: only root may `asuser`.

The spec is one JSON argument: {"user", "cwd", "env", "argv"}. Nothing here
reads hostd's environment; the job gets exactly `env`.
"""

from __future__ import annotations

import json
import os
import pwd
import sys


def drop_to(user: str) -> pwd.struct_passwd:
    """setgid/initgroups/setuid to `user`, and check it can't be undone."""
    pw = pwd.getpwnam(user)
    if pw.pw_uid == 0:
        raise SystemExit("asuser: refusing to run a user-tier job as root")
    os.initgroups(pw.pw_name, pw.pw_gid)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    if os.getuid() != pw.pw_uid or os.geteuid() != pw.pw_uid or os.getegid() != pw.pw_gid:
        raise SystemExit("asuser: could not become the user")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise SystemExit("asuser: root could be regained; not running the job")
    return pw


def main(args: list[str]) -> None:
    if len(args) != 1:
        raise SystemExit("usage: python -I -m agent_auth.hostd.asuser <json spec>")
    spec = json.loads(args[0])
    argv = [str(a) for a in spec["argv"]]
    env = {str(k): str(v) for k, v in spec["env"].items()}
    if not argv:
        raise SystemExit("asuser: empty argv")
    drop_to(str(spec["user"]))
    os.chdir(spec["cwd"])
    try:
        # PATH lookup in the job's own PATH, not this process's.
        os.execvpe(argv[0], argv, env)
    except OSError as exc:
        print(f"asuser: {argv[0]}: {exc.strerror}", file=sys.stderr)
        raise SystemExit(127) from None


if __name__ == "__main__":
    main(sys.argv[1:])
