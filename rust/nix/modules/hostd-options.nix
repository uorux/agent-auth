# What nixosModules.hostd and darwinModules.hostd share: hostd's local
# policy (tiers, commands, templates, the desktop) and how it becomes
# hostd.json. hostd refuses unknown keys and wrong types in that file, so
# what is written here is exactly what it reads (crates/hostd/src/config.rs).
{ lib }:
let
  inherit (lib) mkOption types;
in
rec {
  duration = types.either types.ints.positive (types.strMatching "[0-9]+[smhdw]?");
  argvPattern = types.listOf types.str;

  brokerUrl = mkOption {
    # https only; plain http just to a loopback broker (development).
    type = types.strMatching "https://[^/].*|http://(localhost|127\\.0\\.0\\.1|\\[::1])(:[0-9]+)?(/.*)?";
    example = "https://agent-auth.example";
  };

  brokerPublicKey = mkOption {
    type = types.strMatching "ed25519:[A-Za-z0-9_-]{43}";
    description = ''
      The broker's public signing key (`agent-auth admin broker-key`).
      Pinned here, in the host's own config, so a compromised network path
      or broker URL can't substitute another broker.
    '';
  };

  tierOptions =
    { rootDefaults }:
    {
      enable = lib.mkEnableOption "this tier";
      maxArm = mkOption {
        type = duration;
        default = if rootDefaults then "1h" else "8h";
        description = "The longest one arming of this tier lasts.";
      };
      acceptApproveAll = mkOption {
        type = types.bool;
        default = !rootDefaults;
        description = "While armed, honour \"approve all\" windows for this tier.";
      };
      acceptMachineApprovals = mkOption {
        type = types.bool;
        default = false;
        description = ''
          While armed, honour approvals no human made for the request
          itself: a saved rule, the LLM reviewer, a policy rule. Off = an
          armed tier still needs a human's click per command.
        '';
      };
      shell = {
        enable = lib.mkEnableOption ''
          time-boxed shells on this tier, always opened with a TOTP code:
          the tier's shell secret (`user-shell`, `root-shell`) when enrolled
          with `agent-auth-hostd totp-enroll --add <name>`; a root shell
          needs `root-shell`
        '';
        maxDuration = mkOption {
          type = duration;
          default = if rootDefaults then "30m" else "1h";
        };
      };
    };

  templates = mkOption {
    type = types.attrsOf (
      types.submodule {
        options = {
          tier = mkOption {
            type = types.enum [
              "user"
              "root"
            ];
          };
          argv = mkOption {
            type = types.listOf types.str;
            description = "The command; {name} is replaced by a parameter, whole arguments only.";
          };
          params = mkOption {
            type = types.attrsOf types.str;
            default = { };
            description = ''
              Parameter name -> regex its value must match in full (Rust
              `regex` syntax: no backreferences or lookaround; a pattern
              that does not compile stops hostd).
            '';
          };
          description = mkOption {
            type = types.str;
            default = "";
            description = "Shown with the template in the broker's catalog.";
          };
          cwd = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "The working directory the template runs in (a request may not set one).";
          };
          env = mkOption {
            type = types.attrsOf types.str;
            default = { };
            description = "Environment the template runs with (a request may not add any).";
          };
          stdin = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Standard input the template gets (a request may not give any).";
          };
        };
      }
    );
    default = { };
    description = ''
      Named commands with checked parameters (capability tpl.<name>). A
      template pins its argv and, if set, its cwd, environment and stdin:
      a request for it carrying any of those is refused on the host.
    '';
  };

  tier = t: {
    inherit (t) enable;
    max_arm = t.maxArm;
    accept_approve_all = t.acceptApproveAll;
    accept_machine_approvals = t.acceptMachineApprovals;
    shell = {
      inherit (t.shell) enable;
      max_duration = t.shell.maxDuration;
    };
  };

  # The parts of hostd.json both modules write.
  common = cfg: {
    broker_url = cfg.brokerUrl;
    broker_public_key = cfg.brokerPublicKey;
    inherit (cfg) name user;
    tiers = {
      user = tier cfg.tiers.user;
      root = tier cfg.tiers.root;
    };
    auto_commands = cfg.autoCommands;
    deny_commands = cfg.denyCommands;
    templates = lib.mapAttrs (_: t: {
      inherit (t)
        tier
        argv
        params
        description
        cwd
        env
        stdin
        ;
    }) cfg.templates;
    env_allow = cfg.envAllow;
    job_path = cfg.jobPath;
    default_timeout = cfg.defaultTimeout;
    max_timeout = cfg.maxTimeout;
  };
}
