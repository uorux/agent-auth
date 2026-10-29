# hostd (Rust), the per-host daemon: `services.agent-auth-hostd`, the same
# options as the Python flake's nixosModules.hostd (plus templates' cwd,
# env, stdin and description). Import on every host; it dials out to the
# broker (no inbound ports). Pair once per host:
#   broker admin:  agent-auth admin daemon-pair <hostname>
#   on the host:   sudo agent-auth-hostd pair      (prompts for the code)
#
# With no tier enabled and no VM it only connects and reports, as an
# unprivileged user. Enabling a tier (or vm.unit) makes it root: it then
# runs approved commands, in transient systemd units, under THIS config,
# which is the host's local policy; the broker can't change it. Then, once
# per host:
#   sudo agent-auth-hostd totp-enroll              (four QR codes, shown once)
# and, for what needs its own code (rust/DEVIATIONS.md, hostd finding 4):
#   sudo agent-auth-hostd totp-enroll --add root-shell    (root shells need it)
#   sudo agent-auth-hostd totp-enroll --add root-unlock   (unlocking from the broker)
#   sudo agent-auth-hostd totp-enroll --add user-shell    (optional)
# A secret locked by 20 wrong codes in 30 days stays locked until
#   sudo agent-auth-hostctl totp-unlock NAME
#
# State (the identity key, TOTP secrets and their lock state, the lockdown
# flag, the spool) lives in /var/lib/agent-auth-hostd: persist it on
# impermanence hosts. A Python hostd's state does not carry over: pair again.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.agent-auth-hostd;
  shared = import ./hostd-options.nix { inherit lib; };
  inherit (lib) mkOption types;
  inherit (shared) duration argvPattern;
  stateDir = "/var/lib/agent-auth-hostd";
  serviceUser = "agent-auth-hostd";
  privileged = cfg.tiers.user.enable || cfg.tiers.root.enable || cfg.vm.unit != null;
  owner = if privileged then "root" else serviceUser;
  settings = shared.common cfg // {
    state_dir = stateDir;
    runtime_dir = "/run/agent-auth-hostd";
    vm_unit = cfg.vm.unit;
    systemd_run = "${config.systemd.package}/bin/systemd-run";
    systemctl = "${config.systemd.package}/bin/systemctl";
    qrencode = "${pkgs.qrencode}/bin/qrencode";
    pkcheck = "${pkgs.polkit}/bin/pkcheck";
    desktop = {
      inherit (cfg.desktop) enable;
      max_idle = cfg.desktop.maxIdle;
      idle_source = cfg.desktop.idleSource;
      prompt_command = cfg.desktop.promptCommand;
      prompt_timeout = cfg.desktop.promptTimeout;
      busy_command = cfg.desktop.busyCommand;
      approve = { inherit (cfg.desktop.approve) user root; };
      attention_command = cfg.desktop.attentionCommand;
      notify_command = cfg.desktop.notifyCommand;
    };
  };
  configFile = pkgs.writeText "hostd.json" (builtins.toJSON settings);
  # What hostd asks polkit for before a root command approved at this host's
  # desk: the user's password, in their own session only.
  polkitAction = pkgs.writeTextDir "share/polkit-1/actions/dev.agent-auth.hostd.policy" ''
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
      "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
    <policyconfig>
      <action id="dev.agent-auth.hostd.run-as-root">
        <description>Approve a command an agent asked to run as root</description>
        <message>Authentication is required to let an agent run a command as root</message>
        <defaults>
          <allow_any>no</allow_any>
          <allow_inactive>no</allow_inactive>
          <allow_active>auth_admin</allow_active>
        </defaults>
      </action>
    </policyconfig>
  '';
  # `agent-auth-hostd pair|totp-enroll|key` on the host use the same config
  # as the service. While the service is unprivileged, root drops to its
  # user so the key it creates is one the service reads.
  cli = pkgs.writeShellScriptBin "agent-auth-hostd" ''
    export AGENT_AUTH_HOSTD_CONFIG=${configFile}
    ${lib.optionalString (!privileged) ''
      if [ "$EUID" = 0 ] && [ "''${1:-}" != totp-enroll ]; then
        exec ${pkgs.util-linux}/bin/runuser -u ${serviceUser} -- ${cfg.package}/bin/agent-auth-hostd "$@"
      fi
    ''}
    exec ${cfg.package}/bin/agent-auth-hostd "$@"
  '';
  hostctl = pkgs.writeShellScriptBin "agent-auth-hostctl" ''
    exec ${cfg.package}/bin/agent-auth-hostctl "$@"
  '';
in
{
  options.services.agent-auth-hostd = {
    enable = lib.mkEnableOption "agent-auth host daemon (Rust)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.hostd;
      defaultText = lib.literalExpression "agent-auth-rs.packages.<system>.hostd";
    };

    inherit (shared) brokerUrl brokerPublicKey templates;

    name = mkOption {
      type = types.strMatching "[a-z0-9][a-z0-9-]{0,62}";
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
    };

    user = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "jrt";
      description = ''
        The account the user tier runs commands as (system units with
        User=; their session's bus is in the environment while they are
        logged in), and whose desktop is asked.
      '';
    };

    tiers.user = shared.tierOptions { rootDefaults = false; };
    tiers.root = shared.tierOptions { rootDefaults = true; };

    autoCommands = mkOption {
      type = types.listOf argvPattern;
      default = [ ];
      example = [
        [
          "systemctl"
          "--user"
          "status"
          "*"
        ]
      ];
      description = ''
        User-tier commands that run on any approval the broker relays, armed
        or not. One glob per argument (`*` never crosses `/`, and an argv
        with a `..` path segment never matches); a final "**" stands for any
        further arguments. Whatever matches needs no human at this host, so
        keep these read-only.
      '';
    };

    denyCommands = mkOption {
      type = types.listOf argvPattern;
      default = [ ];
      example = [
        [
          "rm"
          "**"
        ]
      ];
      description = ''
        Never run, whatever the approval (also inside shells). The first
        element also matches the program's basename, and path arguments are
        also matched normalized. A guard against mistakes, not a boundary:
        `sh -c` walks around it.
      '';
    };

    envAllow = mkOption {
      type = types.listOf types.str;
      default = [
        "LANG"
        "LC_ALL"
        "TZ"
        "TERM"
      ];
      description = "Environment variables a request may set.";
    };

    jobPath = mkOption {
      type = types.str;
      default = "/run/wrappers/bin:/run/current-system/sw/bin";
      description = "PATH of commands (the user tier adds the user's profile).";
    };

    defaultTimeout = mkOption {
      type = duration;
      default = "10m";
    };
    maxTimeout = mkOption {
      type = duration;
      default = "1h";
    };

    vm.unit = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "agent-vm.service";
      description = "The agent VM's unit on this host: frozen on lockdown.";
    };

    desktop = {
      enable = lib.mkEnableOption ''
        approval prompts on this host's desktop: a helper in the user's
        graphical session (hostd-user) reports presence and shows them
      '';
      maxIdle = mkOption {
        type = duration;
        default = "5m";
        description = "Prompts are shown only if the session was used this recently.";
      };
      idleSource = mkOption {
        type = types.enum [
          "hooks"
          "logind"
        ];
        default = "hooks";
        description = ''
          Where idle and locked come from. "hooks": what
          `agent-auth-hostctl presence idle|active|locked|unlocked` reports
          (call it from hypridle and around the lock screen). "logind": the
          session's IdleHint/LockedHint.
        '';
      };
      approve = {
        user = lib.mkEnableOption ''
          Allow at this desk as this host's own approval of a user-tier
          command on this host: the dialog shows what the host would run,
          and no arming or TOTP code is needed. Anything running as the user
          can answer that dialog, and could run the command itself anyway
        '';
        root = lib.mkEnableOption ''
          the same for root commands, after polkit has also asked for the
          user's password (they must be allowed to authenticate as an
          administrator, and a polkit agent must run in their session)
        '';
      };
      attentionCommand = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = lib.literalExpression ''[ "''${pkgs.pipewire}/bin/pw-play" "/path/to/sound.oga" ]'';
        description = "Run when a prompt or a notification arrives at this desk (a sound).";
      };
      notifyCommand = mkOption {
        type = types.listOf types.str;
        default = [
          "${pkgs.libnotify}/bin/notify-send"
          "--app-name"
          "agent-auth"
          "--urgency"
          "{urgency}"
          "{title}"
          "{text}"
        ];
        defaultText = lib.literalExpression ''[ "''${pkgs.libnotify}/bin/notify-send" … ]'';
        description = ''
          Shows a notification an agent asked for. {title}, {text} (markup
          escaped) and {urgency} (low, normal or critical) are replaced,
          each as one argument.
        '';
      };
      promptCommand = mkOption {
        type = types.listOf types.str;
        default = [
          "${pkgs.zenity}/bin/zenity"
          "--question"
          "--no-markup"
          "--default-cancel"
          "--width"
          "560"
          "--title"
          "{title}"
          "--text"
          "{text}"
          "--timeout"
          "{timeout}"
          "--ok-label"
          "Allow once"
          "--cancel-label"
          "Deny"
          "--extra-button"
          "Mute agent 1h"
          "--extra-button"
          "Send to Discord"
        ];
        defaultText = lib.literalExpression ''[ "''${pkgs.zenity}/bin/zenity" "--question" … ]'';
        description = ''
          The dialog. Placeholders are replaced, each as one argument: {who}
          (the agent), {what} and {detail}, or the same laid out as {title}
          and {text}; and {timeout}. Exit 0 = allow, 5 = timed out, anything
          else = deny; it may print "mute", "discord", or sbx-prompt's
          once|session|deny on stdout. A command too long to show in full
          is not asked at the desk (it stays on Discord).
        '';
      };
      promptTimeout = mkOption {
        type = duration;
        default = "90s";
      };
      busyCommand = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          A command run every few seconds in the user's session: exit 0 =
          show no prompts now; failing to run counts as that too. Empty: the
          built-in check, Hyprland's focused window being fullscreen.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.tiers.user.enable || cfg.user != null;
        message = "services.agent-auth-hostd: the user tier needs `user`.";
      }
      {
        assertion = !(cfg.desktop.approve.user || cfg.desktop.approve.root) || cfg.desktop.enable;
        message = "services.agent-auth-hostd.desktop.approve needs desktop.enable.";
      }
      {
        assertion = !cfg.desktop.enable || cfg.user != null;
        message = "services.agent-auth-hostd: desktop prompts need `user`.";
      }
    ];

    # A root without capabilities is authorized by polkit when it asks
    # systemd for a unit.
    security.polkit.enable = lib.mkIf (privileged || cfg.desktop.approve.root) true;

    environment.systemPackages = [
      cli
      hostctl
    ]
    ++ lib.optional cfg.desktop.approve.root polkitAction;
    environment.etc."agent-auth/hostd.json".source = configFile;

    users.users.${serviceUser} = {
      isSystemUser = true;
      group = serviceUser;
      description = "agent-auth host daemon";
    };
    users.groups.${serviceUser} = { };

    # `pair` may run before the service ever started, so the state dir must
    # exist without it. Z keeps everything in it with the owner the service
    # runs as (hostd refuses a key that isn't its own), in both directions:
    # enabling a tier moves it to root.
    systemd.tmpfiles.rules = [
      "d ${stateDir} 0700 ${owner} ${owner} -"
      "Z ${stateDir} - ${owner} ${owner} -"
    ];

    systemd.services.agent-auth-hostd = {
      description = "agent-auth host daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment.AGENT_AUTH_HOSTD_CONFIG = "/etc/agent-auth/hostd.json";
      restartTriggers = [ configFile ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/agent-auth-hostd run";
        # ctl.sock and user.sock take any local uid's connection (each
        # capped per uid and overall, and checked before a byte is read):
        # room for those and the jobs' pipes.
        LimitNOFILE = 65536;
        StateDirectory = "agent-auth-hostd";
        StateDirectoryMode = "0700";
        # ctl.sock and user.sock: any local user connects (hostctl, the
        # desktop helper); hostd checks each peer itself.
        RuntimeDirectory = "agent-auth-hostd";
        RuntimeDirectoryMode = "0755";
        Restart = "always";
        RestartSec = 10;

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        ProtectHostname = true;
        LockPersonality = true;
        # hostd itself never maps W+X memory (the jobs run in units of their
        # own, outside this sandbox).
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        UMask = "0077";
      }
      // (
        if privileged then
          {
            # Root, to ask PID 1 for units over the system bus: the jobs (as
            # root, or with User= for the user tier) and the VM's freeze.
            # systemd starts them, outside this sandbox. That takes root's
            # uid and no capability (polkit vouches for uid 0), so none is
            # kept.
            User = "root";
            CapabilityBoundingSet = "";
          }
        else
          {
            # Connect-and-report only: unprivileged and locked down hard.
            # Not ProtectProc=invisible (the Python unit had it): hostd
            # reads a local peer's /proc/<pid>/cgroup to refuse callers
            # inside a job's unit, and refuses peers it can't place, so
            # other users' processes must be visible to it (hostctl, the
            # desktop helper).
            User = serviceUser;
            Group = serviceUser;
            ProtectHome = true;
            ProcSubset = "pid";
            CapabilityBoundingSet = "";
            SystemCallFilter = [
              "@system-service"
              "~@privileged"
            ];
          }
      );
    };

    # hostd-user: in the user's graphical session, so its dialogs have a
    # display. It holds no secrets and decides nothing.
    systemd.user.services.agent-auth-hostd-user = lib.mkIf cfg.desktop.enable {
      description = "agent-auth desktop prompts";
      wantedBy = [ "graphical-session.target" ];
      partOf = [ "graphical-session.target" ];
      after = [ "graphical-session.target" ];
      unitConfig.ConditionUser = cfg.user;
      environment.AGENT_AUTH_HOSTD_CONFIG = "/etc/agent-auth/hostd.json";
      # `kill` (util-linux) ends a dialog the broker withdrew.
      path = [ pkgs.util-linux ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/agent-auth-hostd user";
        Restart = "always";
        RestartSec = 5;
      };
    };
  };
}
