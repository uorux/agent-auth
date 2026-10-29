"""hostd on macOS (docs/hostd-macos.md), tested on Linux: the darwin branches
with sys.platform patched, and the executor's process-group handling for real
(it is plain POSIX)."""

from __future__ import annotations

import asyncio
import json
import os
import plistlib
import struct
import sys
import time
from pathlib import Path

import pytest

from agent_auth.daemon_common import localsock
from agent_auth.hostd import asuser, executor, user
from agent_auth.hostd.config import HostConfig, TierConfig, DesktopConfig

KEY = "ed25519:" + "A" * 43


def config(**kw) -> HostConfig:
    return HostConfig(broker_url="http://127.0.0.1:1", broker_public_key=KEY, name="mac", **kw)


@pytest.fixture
def mac(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")


# --- config ---------------------------------------------------------------------------


def test_linux_defaults_are_unchanged():
    c = config()
    assert c.state_dir == Path("/var/lib/agent-auth-hostd")
    assert c.runtime_dir == Path("/run/agent-auth-hostd")
    assert c.job_path == "/run/wrappers/bin:/run/current-system/sw/bin"


def test_macos_defaults(mac):
    c = config()
    assert c.state_dir == Path("/var/db/agent-auth-hostd")
    assert c.ctl_socket == Path("/var/run/agent-auth-hostd/ctl.sock")
    assert c.job_path.split(":")[0] == "/run/current-system/sw/bin" and "/usr/bin" in c.job_path.split(":")


def test_macos_refuses_what_needs_systemd_or_polkit(mac):
    with pytest.raises(ValueError, match="systemd units"):
        config(vm_unit="agent-vm.service").check()
    with pytest.raises(ValueError, match="polkit"):
        config(desktop=DesktopConfig(enable=True, approve_root=True), user="me").check()
    with pytest.raises(ValueError, match="logind"):
        config(desktop=DesktopConfig(enable=True, idle_source="logind"), user="me").check()
    config(desktop=DesktopConfig(enable=True, approve_user=True, idle_source="macos"), user="me").check()


def test_the_example_config_loads(mac):
    example = Path(__file__).parent.parent / "deploy" / "macos" / "hostd.example.json"
    c = HostConfig.load(example)
    assert c.tiers["user"].enable and not c.tiers["root"].enable and c.desktop.idle_source == "macos"


def test_idle_source_macos_loads(tmp_path):
    path = tmp_path / "hostd.json"
    path.write_text(json.dumps({
        "broker_url": "http://127.0.0.1:1", "broker_public_key": KEY, "name": "mac",
        "desktop": {"enable": True, "idle_source": "macos"}, "user": "me",
    }))
    assert HostConfig.load(path).desktop.idle_source == "macos"


# --- peer credentials -------------------------------------------------------------------


class FakeSock:
    def __init__(self, replies):
        self.replies = replies

    def getsockopt(self, level, name, size):
        return self.replies[(level, name)][:size]


class FakeWriter:
    def __init__(self, sock):
        self.sock = sock

    def get_extra_info(self, key):
        return self.sock


def test_peer_credentials_on_macos(mac):
    xucred = struct.pack("=IIh2x16I", 0, 501, 1, 20, *([0] * 15))
    assert len(xucred) == localsock.XUCRED_SIZE
    writer = FakeWriter(FakeSock({
        (localsock.SOL_LOCAL, localsock.LOCAL_PEERCRED): xucred,
        (localsock.SOL_LOCAL, localsock.LOCAL_PEERPID): struct.pack("=i", 4321),
    }))
    assert localsock.peer_uid(writer) == 501
    assert localsock.peer_pid(writer) == 4321


def test_peer_credentials_on_linux_over_a_real_socket(tmp_path):
    async def go():
        seen = {}

        async def handle(reader, writer):
            seen["uid"], seen["pid"] = localsock.peer_uid(writer), localsock.peer_pid(writer)
            writer.close()

        server = await asyncio.start_unix_server(handle, path=str(tmp_path / "s"))
        _, w = await asyncio.open_unix_connection(str(tmp_path / "s"))
        await asyncio.sleep(0.1)
        w.close()
        server.close()
        return seen

    seen = asyncio.run(go())
    assert seen == {"uid": os.getuid(), "pid": os.getpid()}


# --- the executor -----------------------------------------------------------------------


def local_executor() -> executor.DarwinExecutor:
    """Root-tier jobs with this test's PATH (whose nix store, in a sandbox,
    isn't root's: the root-PATH check has its own tests)."""
    ex = executor.DarwinExecutor(config(job_path=os.environ["PATH"]))
    ex.root_path_problem = lambda: None
    return ex


def run_job(ex, tier, argv, timeout=30, stdin=None, job_id="j1"):
    chunks: list[bytes] = []

    async def on_output(chunk):
        chunks.append(chunk)

    rc = asyncio.run(ex.run(job_id, tier, argv, None, {"TZ": "UTC"}, timeout, stdin, on_output))
    return rc, b"".join(chunks).decode()


def test_make_executor_by_platform(monkeypatch):
    assert isinstance(executor.make_executor(config()), executor.LinuxExecutor)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert isinstance(executor.make_executor(config()), executor.DarwinExecutor)


def test_user_tier_goes_through_launchctl_asuser(monkeypatch):
    me = executor.pwd.struct_passwd(("me", "x", 501, 20, "", "/Users/me", "/bin/zsh"))
    monkeypatch.setattr(executor.pwd, "getpwnam", lambda name: me)
    ex = executor.DarwinExecutor(config(user="me", tiers={"user": TierConfig(enable=True), "root": TierConfig()}))
    command, cwd, env = ex.command("user", ["xcodebuild", "-list"], None, {"TZ": "UTC"})
    assert command[:7] == ["/bin/launchctl", "asuser", "501", sys.executable, "-I", "-m", "agent_auth.hostd.asuser"]
    spec = json.loads(command[7])
    assert spec["user"] == "me" and spec["cwd"] == "/Users/me" and spec["argv"] == ["xcodebuild", "-list"]
    assert spec["env"]["HOME"] == "/Users/me" and spec["env"]["TZ"] == "UTC"
    assert spec["env"]["PATH"].endswith(":/etc/profiles/per-user/me/bin:/opt/homebrew/bin:/usr/local/bin")
    # launchctl itself gets nothing of the job's environment.
    assert cwd == "/" and "TZ" not in env


def test_root_tier_runs_with_its_own_environment(tmp_path):
    ex = local_executor()
    rc, out = run_job(ex, "root", ["sh", "-c", 'echo "$TZ $PATH"; pwd; echo err >&2; exit 3'])
    assert rc == 3
    assert out.splitlines() == [f"UTC {os.environ['PATH']}", "/", "err"]


def test_stdin_reaches_the_job():
    ex = local_executor()
    assert run_job(ex, "root", ["cat"], stdin=b"hello\n") == (0, "hello\n")


def test_timeout_kills_the_whole_group():
    ex = local_executor()
    started = time.monotonic()
    rc, out = run_job(ex, "root", ["sh", "-c", "sleep 30 & echo $!; wait"], timeout=1)
    assert time.monotonic() - started < 10
    assert rc == 128 + 15
    child = int(out.split()[0])
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_what_is_left_in_the_group_dies_with_the_job():
    """The main process exits, a background one still holds the output pipe:
    the job is over and so is the straggler (KillMode=control-group)."""
    ex = local_executor()
    started = time.monotonic()
    rc, out = run_job(ex, "root", ["sh", "-c", "sleep 30 & echo $!"])
    assert rc == 0 and time.monotonic() - started < executor.DRAIN_SECS
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(int(out.split()[0]), 0)


def test_kill_stops_a_running_job():
    ex = local_executor()

    async def go():
        async def on_output(chunk):
            pass

        task = asyncio.create_task(ex.run("j9", "root", ["sleep", "30"], None, {}, 60, None, on_output))
        await asyncio.sleep(0.3)
        await ex.kill("j9", "root")
        return await asyncio.wait_for(task, 10)

    assert asyncio.run(go()) == 128 + 15


def test_root_jobs_refuse_a_path_others_can_write(tmp_path, monkeypatch):
    mine = tmp_path / "bin"
    mine.mkdir()
    ex = executor.DarwinExecutor(config(job_path=f"/nonexistent:{mine}"))
    real_stat = os.stat

    def stat(path, *a, **kw):
        if path == "/rootdir":
            return os.stat_result((0o40755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        if path == "/groupwritable":
            return os.stat_result((0o40775, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_stat(path, *a, **kw)

    monkeypatch.setattr(executor.os, "stat", stat)
    if os.getuid() != 0:
        assert "writable by others than root" in ex.root_path_problem()
        with pytest.raises(RuntimeError, match="not running a root job"):
            run_job(ex, "root", ["true"])
    ex.config.job_path = "/rootdir:/nonexistent"
    assert ex.root_path_problem() is None
    ex.config.job_path = "/rootdir:/groupwritable"
    assert "/groupwritable" in ex.root_path_problem()


def test_homebrew_is_on_the_user_tiers_path_only(monkeypatch):
    ex = executor.DarwinExecutor(config(user="me"))
    assert "/opt/homebrew/bin" not in ex._path("root").split(":")
    assert ex._path("user").split(":")[-2:] == ["/opt/homebrew/bin", "/usr/local/bin"]
    monkeypatch.setattr(sys, "platform", "darwin")
    assert "/opt/homebrew/bin" not in config().job_path


def test_no_units_and_no_polkit_on_macos():
    ex = executor.DarwinExecutor(config())
    with pytest.raises(RuntimeError):
        asyncio.run(ex.unit_action("freeze", "x"))
    assert asyncio.run(ex.polkit_auth(1, 501, "m", 5)) is False


# --- asuser ------------------------------------------------------------------------------


class FakeIds:
    def __init__(self, regain=False):
        self.uid = self.euid = 0
        self.gid = self.egid = 0
        self.regain = regain
        self.groups = None

    def install(self, monkeypatch):
        monkeypatch.setattr(asuser.os, "initgroups", lambda name, gid: setattr(self, "groups", (name, gid)))
        monkeypatch.setattr(asuser.os, "setgid", self.setgid)
        monkeypatch.setattr(asuser.os, "setuid", self.setuid)
        monkeypatch.setattr(asuser.os, "getuid", lambda: self.uid)
        monkeypatch.setattr(asuser.os, "geteuid", lambda: self.euid)
        monkeypatch.setattr(asuser.os, "getegid", lambda: self.egid)

    def setgid(self, gid):
        self.gid = self.egid = gid

    def setuid(self, uid):
        if uid == 0 and self.uid != 0 and not self.regain:
            raise PermissionError
        self.uid = self.euid = uid


ME = asuser.pwd.struct_passwd(("me", "x", 501, 20, "", "/Users/me", "/bin/zsh"))


def test_asuser_becomes_the_user_and_runs_the_job(monkeypatch):
    ids = FakeIds()
    ids.install(monkeypatch)
    monkeypatch.setattr(asuser.pwd, "getpwnam", lambda name: ME)
    monkeypatch.setattr(asuser.os, "chdir", lambda d: setattr(ids, "cwd", d))
    ran = {}

    def execvpe(file, args, env):
        ran.update(file=file, args=args, env=env, uid=ids.uid)
        raise SystemExit(0)

    monkeypatch.setattr(asuser.os, "execvpe", execvpe)
    spec = {"user": "me", "cwd": "/Users/me/app", "env": {"PATH": "/usr/bin"}, "argv": ["swift", "build"]}
    with pytest.raises(SystemExit):
        asuser.main([json.dumps(spec)])
    assert ran == {"file": "swift", "args": ["swift", "build"], "env": {"PATH": "/usr/bin"}, "uid": 501}
    assert ids.groups == ("me", 20) and ids.gid == 20 and ids.cwd == "/Users/me/app"


def test_asuser_refuses_when_root_can_be_regained(monkeypatch):
    FakeIds(regain=True).install(monkeypatch)
    monkeypatch.setattr(asuser.pwd, "getpwnam", lambda name: ME)
    with pytest.raises(SystemExit, match="regained"):
        asuser.drop_to("me")


def test_asuser_never_runs_as_root(monkeypatch):
    FakeIds().install(monkeypatch)
    monkeypatch.setattr(asuser.pwd, "getpwnam", lambda name: asuser.pwd.struct_passwd(
        ("root", "x", 0, 0, "", "/var/root", "/bin/sh")))
    with pytest.raises(SystemExit, match="as root"):
        asuser.drop_to("root")


# --- the desktop helper -------------------------------------------------------------------


def test_macos_dialog_and_its_answers(mac):
    argv = user._fill(user.default_prompt(), {"title": "agent-auth: x", "text": 'a "quoted" end run', "timeout": "90"})
    assert argv[0] == "/usr/bin/osascript"
    # The agent's text is an argument of the run handler, never script.
    assert argv[-3:] == ["agent-auth: x", 'a "quoted" end run', "90"]
    assert all('quoted' not in a for a in argv[:-3])
    assert user.parse_answer(0, "allow\n") == "allow"
    assert user.parse_answer(0, "discord\n") == "discord"
    assert user.parse_answer(0, "timeout\n") == "timeout"
    assert user.parse_answer(1, "") == "deny"  # Deny is the cancel button: osascript fails


def test_linux_dialog_is_still_zenity():
    assert user.default_prompt() is user.DEFAULT_PROMPT


def test_macos_notification_is_not_escaped(mac):
    helper = user.UserHelper(config(desktop=DesktopConfig(enable=True), user="me"))
    spawned = []
    helper._spawn = spawned.append
    helper.notify({"title": "build", "text": "a < b & c"})
    assert spawned == [[*user.DARWIN_NOTIFY[:-2], "build", "a < b & c"]]


def test_linux_notification_is_escaped_and_off_by_default():
    helper = user.UserHelper(config(desktop=DesktopConfig(enable=True, notify_command=["n", "{text}"]), user="me"))
    spawned = []
    helper._spawn = spawned.append
    helper.notify({"text": "a < b"})
    helper.config.desktop.notify_command = []
    helper.notify({"text": "x"})
    assert spawned == [["n", "a &lt; b"]]


def test_hid_idle_and_console_lock():
    sample = '    |   "HIDIdleTime" = 2500000000\n    |   "HIDIdleTimeInSeconds" = 2\n'
    assert user.parse_hid_idle(sample) == 2.5
    assert user.parse_hid_idle("") is None
    tree = {"IOConsoleUsers": [
        {"kCGSSessionUserIDKey": 502, "kCGSSessionOnConsoleKey": False},
        {"kCGSSessionUserIDKey": 501, "kCGSSessionOnConsoleKey": True},
    ]}
    assert user.parse_console_locked(plistlib.dumps(tree), 501) is False
    tree["IOConsoleUsers"][1]["CGSSessionScreenIsLocked"] = True
    assert user.parse_console_locked(plistlib.dumps([tree]), 501) is True
    assert user.parse_console_locked(plistlib.dumps(tree), 502) is True  # switched away
    assert user.parse_console_locked(plistlib.dumps(tree), 503) is None
    assert user.parse_console_locked(b"not a plist", 501) is None


# --- main ---------------------------------------------------------------------------------


def test_prepare_dirs(tmp_path):
    from agent_auth.hostd.main import prepare_dirs

    c = config(state_dir=tmp_path / "state", runtime_dir=tmp_path / "run")
    old = os.umask(0o077)
    try:
        prepare_dirs(c)
    finally:
        os.umask(old)
    assert (tmp_path / "state").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "run").stat().st_mode & 0o777 == 0o755
