# sandboxd (Rust), inside an agent VM's guest (docs/sandbox-design.md §6):
# `services.agent-auth-sandboxd`, the same options as the Python flake's
# nixosModules.sandboxd plus the new config keys. The host side (the VM
# itself) is nixos-dots' modules.agentVm; this module goes into its
# guestModules. Pair once:
#   broker admin:  agent-auth admin daemon-pair --role sandbox <host>
#   in the guest:  agent-auth-sandboxd pair        (prompts for the code)
# State (agent keys, conversations: JSON documents, no SQLite) is in
# /var/lib/sandboxd, projects in /var/lib/sandbox: both on the guest's
# persisted /var/lib. A Python sandboxd's state does not carry over: pair
# again, and the VM's agents are minted again.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.agent-auth-sandboxd;
  inherit (lib) mkOption types;
  pkg = cfg.package;
  agentEnv = pkgs.buildEnv {
    name = "agent-sandbox-path";
    paths = cfg.agentPackages;
  };
  settings = {
    broker_url = cfg.brokerUrl;
    broker_public_key = cfg.brokerPublicKey;
    name = cfg.hostName;
    agent_path = "${agentEnv}/bin:${pkg}/bin";
    agent_auth_mcp = "${pkg}/bin/agent-auth-mcp";
    sandbox_mcp = "${pkg}/bin/agent-auth-sandbox-mcp";
    mcp_bridge = "${pkg}/bin/agent-auth-mcp-bridge";
    tmux = "${pkgs.tmux}/bin/tmux";
    systemd_run = "${config.systemd.package}/bin/systemd-run";
    systemctl = "${config.systemd.package}/bin/systemctl";
    setfacl = "${pkgs.acl}/bin/setfacl";
    orchestrator_runtime = cfg.orchestratorRuntime;
    runtimes = lib.mapAttrs (name: r: {
      command = "${r.package}/bin/${r.binary}";
      inherit (r) model;
    }) cfg.runtimes;
    inherit (cfg)
      park_grace_secs
      max_processes
      max_processes_per_project
      interactive_idle_secs
      unit_memory_max
      codex_auth_owner
      refuse_vm_logins_when_unreachable
      ;
  }
  // cfg.extraConfig;
  configFile = pkgs.writeText "sandboxd.json" (builtins.toJSON settings);
in
{
  options.services.agent-auth-sandboxd = {
    enable = lib.mkEnableOption "agent-auth sandboxd (Rust, in an agent VM)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.sandboxd;
      defaultText = lib.literalExpression "agent-auth-rs.packages.<system>.sandboxd";
      description = "sandboxd, sandboxctl, the sandbox MCP server and the client programs agents use.";
    };

    brokerUrl = mkOption {
      type = types.strMatching "https://[^/].*|http://(localhost|127\\.0\\.0\\.1|\\[::1])(:[0-9]+)?(/.*)?";
    };

    brokerPublicKey = mkOption {
      type = types.strMatching "ed25519:[A-Za-z0-9_-]{43}";
      description = "The broker's public signing key, pinned (as for hostd).";
    };

    hostName = mkOption {
      # No `-`: the VM's agents are <runtime>-<project>-<host>-sandbox,
      # which must read one way only (sandboxd and pairing refuse it).
      type = types.strMatching "[a-z0-9]{1,63}";
      description = ''
        The PHYSICAL host this VM runs on: the sandbox daemon's name, and
        the <host> in its agents' names (<runtime>-<project>-<host>-sandbox).
      '';
    };

    runtimes = mkOption {
      type = types.attrsOf (
        types.submodule (
          { name, ... }:
          {
            options = {
              package = mkOption { type = types.package; };
              binary = mkOption {
                type = types.str;
                default = name;
                description = "The binary in the package (unwrapped, not a sandbox launcher).";
              };
              model = mkOption {
                type = types.nullOr types.str;
                default = null;
              };
            };
          }
        )
      );
      default = { };
      example = lib.literalExpression "{ claude.package = pkgs.claude-code; codex.package = pkgs.codex; }";
      description = "Agent runtimes: claude and/or codex (sandboxd refuses any other name).";
    };

    orchestratorRuntime = mkOption {
      type = types.enum [
        "claude"
        "codex"
      ];
      default = "claude";
      description = "Which runtime the VM's orchestrator runs as.";
    };

    agentPackages = mkOption {
      type = types.listOf types.package;
      default = with pkgs; [
        bashInteractive
        coreutils
        findutils
        gnugrep
        gnused
        gawk
        diffutils
        gnutar
        gzip
        xz
        unzip
        which
        file
        less
        procps
        git
        gh
        openssh
        curl
        wget
        jq
        ripgrep
        fd
        tree
        config.nix.package
        python3
      ];
      defaultText = lib.literalExpression "[ git gh coreutils nix python3 ripgrep … ]";
      description = "What agents find on PATH in their units.";
    };

    park_grace_secs = mkOption {
      type = types.number;
      default = 30;
      description = "Idle seconds after a turn before a conversation's process is parked.";
    };
    max_processes = mkOption {
      type = types.ints.positive;
      default = 16;
      description = "Agent processes (headless, TUI, triage) at once in the VM.";
    };
    max_processes_per_project = mkOption {
      type = types.ints.positive;
      default = 4;
      description = "... and per project (the orchestrator counts as its own).";
    };
    interactive_idle_secs = mkOption {
      type = types.number;
      default = 1800;
      description = "An attached TUI nobody used for this long is ended (its conversation goes back to headless).";
    };
    unit_memory_max = mkOption {
      type = types.str;
      default = "8G";
      description = "MemoryMax= of each agent process's unit.";
    };
    refuse_vm_logins_when_unreachable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        With the broker unreachable (so no word on its model gateway), start
        no agent process rather than fall back to the VM's own logins.
      '';
    };
    codex_auth_owner = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "infra";
      description = ''
        The one project whose codex login is written back to the shared
        login; every other project gets a copy and its changes never go
        back. null: nobody writes it back (rust/DEVIATIONS.md, Agent VMs).
      '';
    };
    extraConfig = mkOption {
      type = types.attrsOf types.anything;
      default = { };
      example = {
        triage_model = "claude-haiku-4-5";
        unit_tasks_max = 2048;
      };
      description = ''
        Other keys of sandboxd.json (crates/sandboxd/src/config.rs:
        triage, triage_runtime, triage_model, triage_timeout_secs,
        unit_tasks_max, uid_base, uid_max, ...). sandboxd refuses unknown
        keys, so a typo stops it instead of being ignored.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.runtimes ? ${cfg.orchestratorRuntime};
        message = "services.agent-auth-sandboxd: orchestratorRuntime ${cfg.orchestratorRuntime} is not in runtimes.";
      }
      {
        assertion = lib.all (
          n:
          lib.elem n [
            "claude"
            "codex"
          ]
        ) (lib.attrNames cfg.runtimes);
        message = "services.agent-auth-sandboxd.runtimes: only claude and codex.";
      }
    ];

    environment.etc."agent-auth/sandboxd.json".source = configFile;
    # sandboxd refuses to run without it (a project could otherwise
    # hard-link files it does not own into its tree). NixOS's default too.
    boot.kernel.sysctl."fs.protected_hardlinks" = lib.mkDefault 1;
    # Project users are userdb drop-ins sandboxd writes at run time.
    services.userdbd.enable = lib.mkDefault true;
    environment.etc.userdb.source = lib.mkDefault "/var/lib/userdb";
    environment.systemPackages = [
      pkg
      pkgs.tmux
      pkgs.acl
    ];

    systemd.tmpfiles.rules = [
      "d /var/lib/sandbox 0711 root root -"
      "d /var/lib/sandbox/projects 0711 root root -"
      "d /var/lib/sandbox/homes 0711 root root -"
      "d /var/lib/sandbox/tmp 0711 root root -"
    ];

    systemd.services.agent-auth-sandboxd = {
      description = "agent-auth sandbox daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "systemd-userdbd.service"
      ];
      environment.AGENT_AUTH_SANDBOXD_CONFIG = "/etc/agent-auth/sandboxd.json";
      path = [
        pkgs.util-linux
        pkgs.acl
        pkgs.coreutils
        config.systemd.package
        pkgs.tmux
      ];
      # Running agents live in their own transient units: restarting the
      # daemon parks them (they resume on their next message).
      restartIfChanged = true;
      restartTriggers = [ configFile ];
      serviceConfig = {
        ExecStart = "${pkg}/bin/agent-auth-sandboxd run";
        Restart = "always";
        RestartSec = 5;
        StateDirectory = "sandboxd";
        StateDirectoryMode = "0700";
        # Created root-only here (the Python module made both 0755; upstream
        # review 2026-10); sandboxd then sets each mode itself through a
        # handle before binding a socket: /run/sandboxd 0711 (the operator
        # socket; env/ 0700 holds the conversations' broker tokens),
        # /run/sandboxd-agent 0755 (the agents' socket).
        RuntimeDirectory = [
          "sandboxd"
          "sandboxd-agent"
        ];
        RuntimeDirectoryMode = "0700";
        LimitNOFILE = 65536;
        # The daemon manages users, ACLs and units: it is root, on purpose.
        # It holds every agent key in the VM; the agents themselves run
        # unprivileged, each in its own unit (with /run/sandboxd
        # inaccessible).
        UMask = "0077";
      };
    };
  };
}
