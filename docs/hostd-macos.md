# hostd on a Mac

hostd is the per-host daemon behind `host_run` and host shells (README
"Commands on hosts", docs/sandbox-design.md §8). This page is how to run it on
an Apple Silicon Mac (macOS 14 or later) so agents can build and test apps
there (`xcodebuild`, `swift`, `xcrun simctl`), approved the same way as on the
NixOS hosts: the broker relays an approval, and the Mac's own config decides
whether that is enough (arming, TOTP codes, templates, auto commands).

Two ways to install it: [nix-darwin](#with-nix-darwin) (`darwinModules.hostd`)
or [without nix](#without-nix) (`deploy/macos/install.sh`). Both give the same
daemon with the same layout:

| | |
|---|---|
| daemon | LaunchDaemon `dev.agent-auth.hostd`, as root |
| desktop helper | LaunchAgent `dev.agent-auth.hostd-user`, in your GUI session (only with `desktop.enable`) |
| config (the host's local policy) | `/etc/agent-auth/hostd.json` |
| state (host key, TOTP secrets, lockdown flag) | `/var/db/agent-auth-hostd`, 0700 root |
| sockets (`agent-auth-hostctl`, the helper) | `/var/run/agent-auth-hostd/` |
| log | `/var/log/agent-auth-hostd.log` |

## How it works on macOS, and what it doesn't protect against

**hostd runs as root, as a LaunchDaemon.** The alternative, a LaunchAgent
running as you with only the user tier, was rejected: the agents on this Mac
also run as you, so they could read hostd's identity key and TOTP secrets,
speak to the broker as this host, generate their own codes, and approve their
own commands. As root, those files are out of their reach. The config is
root-owned too (in the nix store, or `/etc/agent-auth/hostd.json` 0644 root)
because it *is* the local policy; an agent that could edit it could loosen it.
For the same reason, everything hostd runs from must be root's: the nix store,
or `/opt/agent-auth` (install.sh puts uv's own Python there and checks
ownership). Never point the daemon at a Homebrew Python or an editable
checkout in your home directory: those are yours, so they are the agents', and
hostd is root.

**Jobs.** There is no systemd, so no transient units and no cgroups. A job is
a child of hostd in a new session and process group, with its own working
directory and environment (only what the job's PATH, the user's identity and
`env_allow` give it) and no inherited file descriptors.

- **Root tier:** run as root directly. hostd refuses root jobs while any
  directory on `job_path` is writable by someone other than root, which is why
  Homebrew (`/opt/homebrew/bin`, `/usr/local/bin`, owned by you) is not on the
  default `job_path`; the user tier adds it.
- **User tier:** `launchctl asuser <uid> python -I -m agent_auth.hostd.asuser …`.
  `launchctl asuser` puts the job in your launchd domain (the per-user
  services: CoreSimulator, the pasteboard, the keychain's session); then
  `asuser` drops to you (initgroups, setgid, setuid), checks root can't be
  regained, and execs the command. The order matters: only root may `asuser`.
- **Timeout, kill, lockdown:** the job's process group gets SIGTERM, then
  SIGKILL after 5 s. When the job's main process exits, whatever is left in
  its group is killed (as `KillMode=control-group` does on Linux).

What this does not protect against, plainly:

- **Escaping the process group.** A job that calls `setsid`, double-forks into
  a new session, or asks launchd or LaunchServices to start something
  (`open -a Simulator`, `launchctl submit`, a login item, `xcrun simctl boot`
  starting simulator services) leaves processes hostd neither times out nor
  kills, and a lockdown doesn't stop them. On Linux a cgroup catches all of
  these. If you need "everything an agent started is gone", that is not
  available here.
- **No VM freeze.** There is no agent VM on the Mac and `vm_unit` is refused.
  Lockdown disarms, ends shells, kills jobs (with the limit above) and refuses
  new ones.
- **hostd itself is not sandboxed.** On NixOS its unit has `ProtectSystem`,
  no capabilities, and so on. launchd has no equivalent; a bug in hostd is a
  root bug.
- **The user tier is you.** A user-tier job can read and change everything
  you can, including your keychain items it can unlock and other apps' data
  that TCC lets it reach. Arming, TOTP and the per-command approvals decide
  *whether* it runs, not what it can touch once it does.
- **No desk approval for root.** On Linux, polkit asks for your password
  before a root command approved at the desk runs. macOS has no polkit, so
  `desktop.approve.root` is refused; root commands need an armed tier or a TOTP
  code. `desktop.approve.user` works as on Linux, with the same caveat:
  anything running as you can answer that dialog.

## With nix-darwin

In the flake that builds the Mac:

```nix
{
  inputs.agent-auth.url = "git+ssh://git@github.com/uorux/agent-auth?ref=agent-sandbox";
  # (agent-auth.inputs.nixpkgs.follows = "nixpkgs" if you want one nixpkgs)

  outputs = { nix-darwin, agent-auth, ... }: {
    darwinConfigurations.my-mac = nix-darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [
        agent-auth.darwinModules.hostd
        {
          services.agent-auth-hostd = {
            enable = true;
            brokerUrl = "https://agent-auth.recusant.rooty.dev";
            brokerPublicKey = "ed25519:…";          # agent-auth admin broker-key
            name = "my-mac";                        # default: lower-cased networking.hostName
            user = "jrt";
            tiers.user = { enable = true; shell.enable = true; };
            tiers.root.enable = false;              # turn on when you want darwin-rebuild through it
            autoCommands = [ [ "xcrun" "simctl" "list" "**" ] [ "xcodebuild" "-list" ] ];
            templates.xcode-test = {
              tier = "user";
              argv = [ "xcodebuild" "test" "-scheme" "{scheme}" "-destination" "platform=iOS Simulator,name={device}" ];
              params = { scheme = "[A-Za-z0-9_-]+"; device = "iPhone [0-9]+( Pro)?"; };
            };
            desktop = { enable = true; approve.user = false; };
          };
        }
      ];
    };
  };
}
```

`darwin-rebuild switch`, then [pair](#pairing). The options are those of
`nixosModules.hostd` without `vm.unit` and `desktop.approve.root`;
`desktop.idleSource` is `"macos"` (default) or `"hooks"`, and an empty
`promptCommand` / `notifyCommand` means the built-in osascript dialog and
notification. The package is `agent-auth.packages.aarch64-darwin.default`;
every native dependency resolves to a `macosx_11_0_arm64` wheel, so building it
should compile nothing.

Upgrading: bump the input and `darwin-rebuild switch`. The plists name the
package's and the config's store paths, so an upgrade or a config change
changes the plist, and nix-darwin's activation reloads a daemon whose plist
changed. A store path changes on every upgrade, which matters for
[TCC](#xcode-simulators-and-tcc).

## Without nix

You need [uv](https://docs.astral.sh/uv/) (`brew install uv` is fine: it is only
run by you, once, at install time) and a checkout of agent-auth.

```sh
git clone git@github.com:uorux/agent-auth.git ~/src/agent-auth
cd ~/src/agent-auth && git checkout agent-sandbox
sudo deploy/macos/install.sh ~/src/agent-auth     # first run writes /etc/agent-auth/hostd.json and stops
sudo vi /etc/agent-auth/hostd.json                # replace every REPLACE_…; see deploy/macos/hostd.example.json
sudo deploy/macos/install.sh ~/src/agent-auth     # installs and loads the daemon (and the helper)
```

The script puts uv's Python 3.13 and a non-editable venv in `/opt/agent-auth`,
checks nothing there belongs to anyone but root, checks the config loads, and
installs and bootstraps the plists from `deploy/macos/`. Run it again to
upgrade (after `git pull`); it reinstalls the package and restarts the daemon.

## Pairing

As on every host. On a machine with the broker's admin CLI:

```sh
agent-auth admin daemon-pair my-mac          # prints a one-time code
agent-auth admin broker-key                  # the key that goes in the config
```

On the Mac (the code is typed at the prompt, never on the command line):

```sh
sudo agent-auth-hostd pair                   # nix-darwin: the wrapper knows the config
# without nix:
sudo /opt/agent-auth/venv/bin/agent-auth-hostd pair --config /etc/agent-auth/hostd.json
```

Compare the fingerprints it prints with `agent-auth admin daemons`. Then, if any
tier is enabled, enroll the TOTP secrets (four QR codes, shown once; `qrencode`
comes with the nix-darwin module, otherwise `brew install qrencode` or type the
secret by hand):

```sh
sudo agent-auth-hostd totp-enroll            # or the /opt/agent-auth path with --config
sudo launchctl kickstart -k system/dev.agent-auth.hostd
```

Check: `agent-auth-hostctl status` (as you or root), the broker's
`agent-auth admin hosts`, and `tail -f /var/log/agent-auth-hostd.log`.

## Tiers, shells and templates on a Mac

They mean what they mean on NixOS (README "Commands on hosts"):

- **user tier:** commands as `user`, in your launchd domain. This is the one
  for app work: `xcodebuild`, `swift build|test`, `xcrun simctl`, `git`.
- **root tier:** commands as root. Useful for `darwin-rebuild switch` through
  a template; leave it off until you want that.
- **shells:** time-boxed, always opened with a TOTP code, every command shown
  on Discord, per tier.
- **templates:** named commands with checked parameters, requested as
  `tpl.<name>`. A template with a narrow regex is the way to pre-approve a
  build without approving `xcodebuild` in general. Mirror it in the broker's
  `platforms.hostexec.templates` so Discord shows the expanded command.
- **auto commands:** user-tier commands that run on any relayed approval,
  armed or not. Keep them read-only (`xcodebuild -list`, `xcrun simctl list`).

The broker's policy decides who may ask (the usual `hostexec` rules, matched
on `host: my-mac`); this Mac's config decides what an approval is worth here.

**The desktop helper** (`desktop.enable`) shows approval prompts as an
AppleScript dialog: Deny (the default, and what Enter or Escape do), Send to
Discord, Allow once. AppleScript dialogs have three buttons at most, so there
is no "Mute agent 1h" on the Mac. Presence comes from `ioreg`: keyboard/mouse
idle time and whether your console session is locked or switched away. The
first dialog or notification may make macOS ask whether `osascript` may
control your computer or send notifications; allow it in System Settings.

## Xcode, simulators and TCC

- Once, as you: `sudo xcode-select -s /Applications/Xcode.app` and
  `sudo xcodebuild -license accept`, then open Xcode once so it installs its
  components. Agents shouldn't be the ones doing this (it is root, and
  interactive).
- **Simulators** live in your launchd domain, which is why the user tier goes
  through `launchctl asuser`. `xcrun simctl boot` and `simctl` tests should
  work headless; the Simulator app's window needs you logged in at the GUI.
- **Code signing** needs your login keychain unlocked, which it normally is
  while you are logged in. Builds for the simulator need no signing (set
  `CODE_SIGNING_ALLOWED=NO` if a scheme insists); signing for devices and
  archives is better kept for you.
- **TCC** (privacy prompts) applies to jobs: a job touching `~/Documents`,
  `~/Desktop`, `~/Downloads`, iCloud Drive or removable volumes may be refused
  with "Operation not permitted", and no prompt appears for a daemon. Keep
  projects somewhere unprotected (`~/src/…`), or grant Full Disk Access to the
  Python that runs hostd (`/opt/agent-auth/python/…/bin/python3.13`, or the
  nix store path, which changes on every upgrade, so the grant has to be
  renewed).
- `DEVELOPER_DIR` can be let through with `envAllow` / `env_allow` to pick an
  Xcode per request.

## Uninstall

```sh
agent-auth admin daemon-unpair <id>          # broker side; the id from `agent-auth admin daemons`
sudo launchctl bootout system/dev.agent-auth.hostd
sudo launchctl bootout gui/$(id -u)/dev.agent-auth.hostd-user 2>/dev/null
# nix-darwin: set services.agent-auth-hostd.enable = false and darwin-rebuild switch. Without nix:
sudo rm -f /Library/LaunchDaemons/dev.agent-auth.hostd.plist /Library/LaunchAgents/dev.agent-auth.hostd-user.plist
sudo rm -rf /opt/agent-auth /etc/agent-auth
# both: the host's key and TOTP secrets (remove the TOTP entries from your authenticator too)
sudo rm -rf /var/db/agent-auth-hostd /var/run/agent-auth-hostd /var/log/agent-auth-hostd.log
```

## Not verified

Everything here was written and tested on Linux; none of it has run on a Mac.

Tested: the darwin branches with `sys.platform` patched (paths, the refusals,
peer credentials from `LOCAL_PEERCRED`/`LOCAL_PEERPID` against packed bytes,
the user-tier command line, the `asuser` drop against fake id calls, the
dialog's arguments and answers, the `ioreg` parsers on hand-written samples);
the macOS executor's process groups, timeouts, kills and stragglers for real
(they are plain POSIX); `nix-darwin` evaluation of a whole system using the
module, and the generated `hostd.json` loading under the darwin checks; the
`aarch64-darwin` package evaluating to wheels only.

Not tested, and the likeliest to need a fix on first contact:

- the socket options' values and `struct xucred` layout on a real kernel;
- `launchctl asuser` then dropping to the user, from a LaunchDaemon, and
  whether simulators and the keychain are reachable from there;
- the osascript dialog appearing from a LaunchAgent (and over full-screen apps);
- `ioreg`'s output format for `HIDIdleTime` and `IOConsoleUsers` on macOS 14/15;
- building `packages.aarch64-darwin.default` (only evaluated);
- `install.sh` end to end (only `bash -n` and shellcheck);
- TCC's behaviour for jobs started this way.
