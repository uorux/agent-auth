# hostd (Rust) on a Mac, for nix-darwin (docs/hostd-macos.md): the same
# options as the Python flake's darwinModules.hostd. The same daemon and
# local policy as the NixOS module, without what needs systemd or polkit:
# no VM unit, and root commands are never approved at the desk. It is a
# LaunchDaemon, always root (it holds the host's key and TOTP secrets out of
# reach of the user the agents run as); user-tier jobs go through
# `launchctl asuser` into the user's session, then drop to them.
# Pair once:
#   broker admin:  agent-auth admin daemon-pair <name>
#   on the Mac:    sudo agent-auth-hostd pair       (prompts for the code)
#                  sudo agent-auth-hostd totp-enroll
#                  sudo agent-auth-hostd totp-enroll --add root-shell   (root shells)
#                  sudo agent-auth-hostd totp-enroll --add root-unlock  (unlock from the broker)
# State: /var/db/agent-auth-hostd. Log: /var/log/agent-auth-hostd.log.
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
  label = "dev.agent-auth.hostd";
  settings = shared.common cfg // {
    state_dir = "/var/db/agent-auth-hostd";
    runtime_dir = "/var/run/agent-auth-hostd";
    qrencode = "${pkgs.qrencode}/bin/qrencode";
    desktop = {
      inherit (cfg.desktop) enable;
      max_idle = cfg.desktop.maxIdle;
      idle_source = cfg.desktop.idleSource;
      prompt_command = cfg.desktop.promptCommand;
      prompt_timeout = cfg.desktop.promptTimeout;
      busy_command = cfg.desktop.busyCommand;
      approve = {
        user = cfg.desktop.approve.user;
        root = false;
      };
      attention_command = cfg.desktop.attentionCommand;
      notify_command = cfg.desktop.notifyCommand;
    };
  };
  configFile = pkgs.writeText "hostd.json" (builtins.toJSON settings);
  cli = pkgs.writeShellScriptBin "agent-auth-hostd" ''
    export AGENT_AUTH_HOSTD_CONFIG=${configFile}
    exec ${cfg.package}/bin/agent-auth-hostd "$@"
  '';
  hostctl = pkgs.writeShellScriptBin "agent-auth-hostctl" ''
    exec ${cfg.package}/bin/agent-auth-hostctl "$@"
  '';
in
{
  options.services.agent-auth-hostd = {
    enable = lib.mkEnableOption "agent-auth host daemon (Rust, macOS)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.hostd;
      defaultText = lib.literalExpression "agent-auth-rs.packages.<system>.hostd";
    };

    inherit (shared) brokerUrl brokerPublicKey templates;

    name = mkOption {
      type = types.nullOr (types.strMatching "[a-z0-9][a-z0-9-]{0,62}");
      default =
        if config.networking.hostName == null then null else lib.toLower config.networking.hostName;
      defaultText = lib.literalExpression "lib.toLower config.networking.hostName";
    };

    user = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "jrt";
      description = ''
        The account the user tier runs commands as (in that user's launchd
        domain, via `launchctl asuser`), and whose desktop is asked.
      '';
    };

    tiers.user = shared.tierOptions { rootDefaults = false; };
    tiers.root = shared.tierOptions { rootDefaults = true; };

    autoCommands = mkOption {
      type = types.listOf argvPattern;
      default = [ ];
      example = [
        [
          "xcodebuild"
          "-list"
        ]
      ];
      description = "User-tier commands that run on any approval the broker relays. Keep these read-only.";
    };

    denyCommands = mkOption {
      type = types.listOf argvPattern;
      default = [ ];
      example = [
        [
          "security"
          "**"
        ]
      ];
      description = "Never run, whatever the approval. A guard against mistakes, not a boundary.";
    };

    envAllow = mkOption {
      type = types.listOf types.str;
      default = [
        "LANG"
        "LC_ALL"
        "TZ"
        "TERM"
      ];
    };

    jobPath = mkOption {
      type = types.str;
      default = "/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin:/usr/sbin:/sbin";
      description = ''
        PATH of commands; the user tier adds /etc/profiles/per-user/<user>/bin
        and Homebrew's. Root-owned directories only: hostd refuses root jobs
        while any directory here is writable by someone else.
      '';
    };

    defaultTimeout = mkOption {
      type = duration;
      default = "10m";
    };
    maxTimeout = mkOption {
      type = duration;
      default = "1h";
    };

    desktop = {
      enable = lib.mkEnableOption ''
        approval prompts on this Mac: a LaunchAgent in the user's GUI
        session (hostd-user) reports presence and shows them
      '';
      maxIdle = mkOption {
        type = duration;
        default = "5m";
      };
      idleSource = mkOption {
        type = types.enum [
          "macos"
          "hooks"
        ];
        default = "macos";
        description = ''
          "macos": keyboard/mouse idle time and the screen lock, from ioreg.
          "hooks": only what `agent-auth-hostctl presence …` reports.
        '';
      };
      approve.user = lib.mkEnableOption ''
        Allow at this desk as this host's own approval of a user-tier
        command on this host (no arming or TOTP code). Anything running as
        the user can answer that dialog, and could run the command itself
        anyway. (Root has no desk approval on macOS: no polkit.)
      '';
      attentionCommand = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "/usr/bin/afplay"
          "/System/Library/Sounds/Glass.aiff"
        ];
      };
      notifyCommand = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Empty: a notification through osascript. {title} {text} {urgency} are replaced.";
      };
      promptCommand = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Empty: an osascript dialog (Deny / Send to Discord / Allow once).
          Otherwise as in nixosModules.hostd.
        '';
      };
      promptTimeout = mkOption {
        type = duration;
        default = "90s";
      };
      busyCommand = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Exit 0 = show no prompts now. Empty: never busy.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.name != null;
        message = "services.agent-auth-hostd.name: set it, or networking.hostName.";
      }
      {
        assertion = !cfg.tiers.user.enable || cfg.user != null;
        message = "services.agent-auth-hostd: the user tier needs `user`.";
      }
      {
        assertion = !cfg.desktop.approve.user || cfg.desktop.enable;
        message = "services.agent-auth-hostd.desktop.approve needs desktop.enable.";
      }
      {
        assertion = !cfg.desktop.enable || cfg.user != null;
        message = "services.agent-auth-hostd: desktop prompts need `user`.";
      }
    ];

    environment.systemPackages = [
      cli
      hostctl
    ];
    environment.etc."agent-auth/hostd.json".source = configFile;

    launchd.daemons.agent-auth-hostd.serviceConfig = {
      Label = label;
      ProgramArguments = [
        "${cfg.package}/bin/agent-auth-hostd"
        "run"
      ];
      # A config change changes the plist: launchd restarts it.
      EnvironmentVariables.AGENT_AUTH_HOSTD_CONFIG = "${configFile}";
      RunAtLoad = true;
      KeepAlive = true;
      ThrottleInterval = 10;
      Umask = 63; # 0077
      # Room for ctl.sock / user.sock peers and the jobs' pipes.
      SoftResourceLimits.NumberOfFiles = 65536;
      StandardOutPath = "/var/log/agent-auth-hostd.log";
      StandardErrorPath = "/var/log/agent-auth-hostd.log";
    };

    # hostd-user: in the GUI session, so its dialogs have a display.
    # Installed for every user who logs in; hostd listens only to `user`.
    launchd.user.agents.agent-auth-hostd-user = lib.mkIf cfg.desktop.enable {
      serviceConfig = {
        Label = "${label}-user";
        ProgramArguments = [
          "${cfg.package}/bin/agent-auth-hostd"
          "user"
        ];
        EnvironmentVariables.AGENT_AUTH_HOSTD_CONFIG = "${configFile}";
        RunAtLoad = true;
        KeepAlive = true;
        LimitLoadToSessionType = "Aqua";
        ProcessType = "Interactive";
      };
    };
  };
}
