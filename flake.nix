{
  description = "agent-auth — Discord-surfaced credential broker for AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, pyproject-nix, uv2nix, pyproject-build-systems, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;
      python = pkgs.python313;

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };
      overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

      pythonSet =
        (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope
          (lib.composeManyExtensions [
            pyproject-build-systems.overlays.default
            overlay
          ]);

      venv = pythonSet.mkVirtualEnv "agent-auth-env" workspace.deps.default;
    in
    {
      packages.${system} = {
        default = venv;

        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "agent-auth";
          tag = "latest";
          contents = [ venv pkgs.cacert pkgs.tzdata ];
          config = {
            Cmd = [ "${venv}/bin/agent-auth-server" ];
            Env = [
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              "PYTHONUNBUFFERED=1"
            ];
            ExposedPorts = { "8400/tcp" = { }; };
          };
        };
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [ pkgs.uv python pkgs.postgresql ];
        # manylinux wheels (greenlet et al.) need libstdc++ at runtime on NixOS
        env.LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
      };

      # Native NixOS service — the recommended deployment. The policy file
      # comes from the nix store (immutable at runtime; changes require a
      # rebuild, i.e. an audited commit to the host's config repo). Keep that
      # repo out of reach of every brokered agent.
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.agent-auth;
        in
        {
          options.services.agent-auth = {
            enable = lib.mkEnableOption "agent-auth credential broker";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "agent-auth.packages.<system>.default";
              description = "The agent-auth virtualenv package to run.";
            };

            policyFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                Policy YAML (see policy.example.yaml). Referencing a repo file
                copies it into the nix store, making the runtime policy
                immutable.
              '';
            };

            listenHost = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1";
              description = "Bind address; front with your reverse proxy for TLS.";
            };

            port = lib.mkOption {
              type = lib.types.port;
              default = 8400;
            };

            environmentFiles = lib.mkOption {
              type = lib.types.listOf lib.types.path;
              default = [ ];
              example = lib.literalExpression
                ''[ config.sops.secrets."agent-auth/env".path ]'';
              description = ''
                EnvironmentFile(s) with secrets (ADMIN_TOKEN, ENCRYPTION_KEY,
                BROKER_SIGNING_KEY, DISCORD_*, OPENROUTER_API_KEY, GITHUB_*,
                LLDAP_*, ...). BROKER_SIGNING_KEY is the broker's private
                ed25519 seed (`agent-auth admin gen-signing-key --out FILE`):
                it belongs here, never in `settings`, which lands in the
                world-readable nix store. Point at sops-nix
                (`format = "dotenv"`) or agenix paths — never nix-store
                files. Root-owned 0400 secrets are fine: systemd reads
                EnvironmentFile before dropping to the DynamicUser.
              '';
            };

            loadCredentials = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = lib.literalExpression ''
                [ "github-pem:''${config.sops.secrets."agent-auth/github-app-pem".path}" ]
              '';
              description = ''
                systemd LoadCredential entries for file secrets (GitHub App PEM,
                out-of-cluster k8s token). Reference them from `settings` as
                /run/credentials/agent-auth.service/<name>. Like
                environmentFiles, sources may be root-owned 0400 — systemd
                loads credentials before dropping privileges.
              '';
            };

            settings = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              example = {
                KUBERNETES_API_URL = "https://k8s.example:6443";
                KUBERNETES_TOKEN_FILE = "/run/credentials/agent-auth.service/k8s-token";
              };
              description = "Extra non-secret environment for the service.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.agent-auth = {
              description = "agent-auth credential broker";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];

              environment = {
                DATABASE_URL = "sqlite+aiosqlite:////var/lib/agent-auth/agent-auth.db";
                POLICY_FILE = "${cfg.policyFile}";
                LISTEN_HOST = cfg.listenHost;
                LISTEN_PORT = toString cfg.port;
              } // cfg.settings;

              serviceConfig = {
                ExecStart = "${cfg.package}/bin/agent-auth-server";
                DynamicUser = true;
                StateDirectory = "agent-auth";
                WorkingDirectory = "/var/lib/agent-auth";
                EnvironmentFile = cfg.environmentFiles;
                LoadCredential = cfg.loadCredentials;
                Restart = "on-failure";
                RestartSec = 5;

                # Hardening. MemoryDenyWriteExecute is deliberately absent:
                # cryptography/cffi needs executable mappings.
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectKernelLogs = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectProc = "invisible";
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RemoveIPC = true;
                LockPersonality = true;
                CapabilityBoundingSet = "";
                SystemCallFilter = [ "@system-service" "~@privileged" ];
                SystemCallArchitectures = "native";
                UMask = "0077";
              };
            };
          };
        };

      # The per-host daemon (docs/sandbox-design.md §8). Import on every host;
      # it dials out to the broker (no inbound ports). Pair once per host:
      #   broker admin:  agent-auth admin daemon-pair <hostname>
      #   on the host:   sudo agent-auth-hostd pair      (prompts for the code)
      #
      # With no tier enabled and no VM it only connects and reports, as an
      # unprivileged user. Enabling a tier (or vm.unit) makes it root: it then
      # runs approved commands, in transient systemd units, under THIS config
      # — which is the host's local policy, and the broker can't change it.
      # Then, once per host:
      #   sudo agent-auth-hostd totp-enroll              (four QR codes, shown once)
      #
      # State (the identity key, TOTP secrets, the lockdown flag) lives in
      # /var/lib/agent-auth-hostd: persist it on impermanence hosts.
      nixosModules.hostd = { config, lib, pkgs, ... }:
        let
          cfg = config.services.agent-auth-hostd;
          stateDir = "/var/lib/agent-auth-hostd";
          serviceUser = "agent-auth-hostd";
          privileged = cfg.tiers.user.enable || cfg.tiers.root.enable || cfg.vm.unit != null;
          owner = if privileged then "root" else serviceUser;
          tier = t: {
            inherit (t) enable;
            max_arm = t.maxArm;
            accept_approve_all = t.acceptApproveAll;
            accept_machine_approvals = t.acceptMachineApprovals;
            shell = { inherit (t.shell) enable; max_duration = t.shell.maxDuration; };
          };
          settings = {
            broker_url = cfg.brokerUrl;
            broker_public_key = cfg.brokerPublicKey;
            name = cfg.name;
            state_dir = stateDir;
            runtime_dir = "/run/agent-auth-hostd";
            user = cfg.user;
            tiers = { user = tier cfg.tiers.user; root = tier cfg.tiers.root; };
            auto_commands = cfg.autoCommands;
            deny_commands = cfg.denyCommands;
            templates = cfg.templates;
            env_allow = cfg.envAllow;
            vm_unit = cfg.vm.unit;
            job_path = cfg.jobPath;
            default_timeout = cfg.defaultTimeout;
            max_timeout = cfg.maxTimeout;
            systemd_run = "${config.systemd.package}/bin/systemd-run";
            systemctl = "${config.systemd.package}/bin/systemctl";
            setpriv = "${pkgs.util-linux}/bin/setpriv";
            qrencode = "${pkgs.qrencode}/bin/qrencode";
            desktop = {
              inherit (cfg.desktop) enable;
              max_idle = cfg.desktop.maxIdle;
              idle_source = cfg.desktop.idleSource;
              prompt_command = cfg.desktop.promptCommand;
              prompt_timeout = cfg.desktop.promptTimeout;
            };
          };
          configFile = pkgs.writeText "hostd.json" (builtins.toJSON settings);
          # `agent-auth-hostd pair|totp-enroll|key` on the host use the same
          # config as the service. While the service is unprivileged, root
          # drops to its user so the key it creates is one the service reads.
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
          duration = lib.types.either lib.types.ints.positive (lib.types.strMatching "[0-9]+[smhdw]?");
          argvPattern = lib.types.listOf lib.types.str;
          tierOptions = { rootDefaults }: {
            enable = lib.mkEnableOption "this tier";
            maxArm = lib.mkOption {
              type = duration;
              default = if rootDefaults then "1h" else "8h";
              description = "The longest one arming of this tier lasts.";
            };
            acceptApproveAll = lib.mkOption {
              type = lib.types.bool;
              default = !rootDefaults;
              description = "While armed, honour \"approve all\" windows for this tier.";
            };
            acceptMachineApprovals = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                While armed, honour approvals no human made for the request
                itself: a saved rule, the LLM reviewer, a policy rule. Off =
                an armed tier still needs a human's click per command.
              '';
            };
            shell = {
              enable = lib.mkEnableOption "time-boxed shells on this tier (always opened with a TOTP code)";
              maxDuration = lib.mkOption {
                type = duration;
                default = if rootDefaults then "30m" else "1h";
              };
            };
          };
        in
        {
          options.services.agent-auth-hostd = {
            enable = lib.mkEnableOption "agent-auth host daemon";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "agent-auth.packages.<system>.default";
            };

            brokerUrl = lib.mkOption {
              # https only; plain http just to a loopback broker (development).
              type = lib.types.strMatching
                "https://[^/].*|http://(localhost|127\\.0\\.0\\.1|\\[::1])(:[0-9]+)?(/.*)?";
              example = "https://agent-auth.recusant.rooty.dev";
            };

            brokerPublicKey = lib.mkOption {
              type = lib.types.strMatching "ed25519:[A-Za-z0-9_-]{43}";
              description = ''
                The broker's public signing key (`agent-auth admin broker-key`).
                Pinned here, in the host's own config, so a compromised network
                path or broker URL can't substitute another broker.
              '';
            };

            name = lib.mkOption {
              type = lib.types.strMatching "[a-z0-9][a-z0-9-]{0,62}";
              default = config.networking.hostName;
              defaultText = lib.literalExpression "config.networking.hostName";
            };

            user = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "jrt";
              description = ''
                The account the user tier runs commands as, and whose desktop
                is asked. Its systemd manager must be running for user-tier
                commands (logged in, or `users.users.<name>.linger = true`).
              '';
            };

            tiers.user = tierOptions { rootDefaults = false; };
            tiers.root = tierOptions { rootDefaults = true; };

            autoCommands = lib.mkOption {
              type = lib.types.listOf argvPattern;
              default = [ ];
              example = [ [ "systemctl" "--user" "status" "*" ] ];
              description = ''
                User-tier commands that run on any approval the broker relays,
                armed or not. One glob per argument; a final "**" stands for
                any further arguments. Whatever matches needs no human at this
                host, so keep these read-only.
              '';
            };

            denyCommands = lib.mkOption {
              type = lib.types.listOf argvPattern;
              default = [ ];
              example = [ [ "rm" "**" ] ];
              description = ''
                Never run, whatever the approval (also inside shells). The
                first element also matches the program's basename. A guard
                against mistakes, not a boundary: `sh -c` walks around it.
              '';
            };

            templates = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options = {
                  tier = lib.mkOption { type = lib.types.enum [ "user" "root" ]; };
                  argv = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    description = "The command; {name} is replaced by a parameter, whole arguments only.";
                  };
                  params = lib.mkOption {
                    type = lib.types.attrsOf lib.types.str;
                    default = { };
                    description = "Parameter name -> regex its value must match in full.";
                  };
                };
              });
              default = { };
              example = lib.literalExpression ''
                {
                  nixos-rebuild = {
                    tier = "root";
                    argv = [ "nixos-rebuild" "switch" "--flake" "{flake}" ];
                    params.flake = "git\\+https://git\\.example/me/[a-z0-9-]+#[a-z0-9-]+";
                  };
                }
              '';
              description = "Named commands with checked parameters (capability tpl.<name>).";
            };

            envAllow = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "LANG" "LC_ALL" "TZ" "TERM" ];
              description = "Environment variables a request may set.";
            };

            jobPath = lib.mkOption {
              type = lib.types.str;
              default = "/run/wrappers/bin:/run/current-system/sw/bin";
              description = "PATH of commands (the user tier adds the user's profile).";
            };

            defaultTimeout = lib.mkOption { type = duration; default = "10m"; };
            maxTimeout = lib.mkOption { type = duration; default = "1h"; };

            vm.unit = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "agent-vm.service";
              description = "The agent VM's unit on this host: frozen on lockdown.";
            };

            desktop = {
              enable = lib.mkEnableOption ''
                approval prompts on this host's desktop: a helper in the user's
                graphical session (hostd-user) reports presence and shows them
              '';
              maxIdle = lib.mkOption {
                type = duration;
                default = "5m";
                description = "Prompts are shown only if the session was used this recently.";
              };
              idleSource = lib.mkOption {
                type = lib.types.enum [ "hooks" "logind" ];
                default = "hooks";
                description = ''
                  Where idle and locked come from. "hooks": what
                  `agent-auth-hostctl presence idle|active|locked|unlocked`
                  reports — call it from hypridle and around the lock screen
                  (Hyprland keeps no logind hints). "logind": the session's
                  IdleHint/LockedHint.
                '';
              };
              promptCommand = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [
                  "${pkgs.zenity}/bin/zenity" "--question" "--no-markup" "--width" "560"
                  "--title" "{title}" "--text" "{text}" "--timeout" "{timeout}"
                  "--ok-label" "Allow once" "--cancel-label" "Deny"
                  "--extra-button" "Mute agent 1h" "--extra-button" "Send to Discord"
                ];
                defaultText = lib.literalExpression ''[ "''${pkgs.zenity}/bin/zenity" "--question" … ]'';
                description = ''
                  The dialog. {title}, {text} and {timeout} are replaced, each
                  as one argument. Exit 0 = allow, 5 = timed out, anything
                  else = deny; it may print "mute", "discord", or sbx-prompt's
                  once|session|deny on stdout.
                '';
              };
              promptTimeout = lib.mkOption { type = duration; default = "90s"; };
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [
              {
                assertion = !cfg.tiers.user.enable || cfg.user != null;
                message = "services.agent-auth-hostd: the user tier needs `user`.";
              }
              {
                assertion = !cfg.desktop.enable || cfg.user != null;
                message = "services.agent-auth-hostd: desktop prompts need `user`.";
              }
            ];

            environment.systemPackages = [ cli hostctl ];
            environment.etc."agent-auth/hostd.json".source = configFile;

            users.users.${serviceUser} = {
              isSystemUser = true;
              group = serviceUser;
              description = "agent-auth host daemon";
            };
            users.groups.${serviceUser} = { };

            # `pair` may run before the service ever started, so the state dir
            # must exist without it. Z keeps everything in it with the owner
            # the service runs as (hostd refuses a key that isn't its own), in
            # both directions: enabling a tier moves it to root.
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
                StateDirectory = "agent-auth-hostd";
                StateDirectoryMode = "0700";
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
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RemoveIPC = true;
                ProtectHostname = true;
                LockPersonality = true;
                SystemCallArchitectures = "native";
                UMask = "0077";
              } // (if privileged then {
                # Root, to ask systemd for units (system ones directly; the
                # user's by dropping to that user). The jobs themselves are
                # started by systemd, outside this sandbox. /run/user stays
                # reachable (no ProtectHome); CAP_SETUID/SETGID are for the
                # drop, CAP_DAC_READ_SEARCH to look into /run/user/<uid>, and
                # nothing else of root's is kept.
                User = "root";
                CapabilityBoundingSet = [ "CAP_SETUID" "CAP_SETGID" "CAP_DAC_READ_SEARCH" ];
              } else {
                # Connect-and-report only: unprivileged and locked down hard.
                User = serviceUser;
                Group = serviceUser;
                ProtectHome = true;
                ProtectProc = "invisible";
                CapabilityBoundingSet = "";
                SystemCallFilter = [ "@system-service" "~@privileged" ];
              });
            };

            # hostd-user: in the user's graphical session, so its dialogs have
            # a display. It holds no secrets and decides nothing.
            systemd.user.services.agent-auth-hostd-user = lib.mkIf cfg.desktop.enable {
              description = "agent-auth desktop prompts";
              wantedBy = [ "graphical-session.target" ];
              partOf = [ "graphical-session.target" ];
              after = [ "graphical-session.target" ];
              unitConfig.ConditionUser = cfg.user;
              environment.AGENT_AUTH_HOSTD_CONFIG = "/etc/agent-auth/hostd.json";
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/agent-auth-hostd user";
                Restart = "always";
                RestartSec = 5;
              };
            };
          };
        };

      # sandboxd, inside an agent VM's guest (docs/sandbox-design.md §6). The
      # host side (the VM itself) is nixos-dots' modules.agentVm; this module
      # goes into its guestModules. Pair once:
      #   broker admin:  agent-auth admin daemon-pair --role sandbox <host>
      #   in the guest:  agent-auth-sandboxd pair        (prompts for the code)
      # State (agent keys, conversations) is in /var/lib/sandboxd, projects in
      # /var/lib/sandbox: both on the guest's persisted /var/lib.
      nixosModules.sandboxd = { config, lib, pkgs, ... }:
        let
          cfg = config.services.agent-auth-sandboxd;
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
            tmux = "${pkgs.tmux}/bin/tmux";
            systemd_run = "${config.systemd.package}/bin/systemd-run";
            systemctl = "${config.systemd.package}/bin/systemctl";
            setfacl = "${pkgs.acl}/bin/setfacl";
            orchestrator_runtime = cfg.orchestratorRuntime;
            runtimes = lib.mapAttrs (name: r: {
              command = "${r.package}/bin/${r.binary}";
              model = r.model;
            }) cfg.runtimes;
            inherit (cfg) park_grace_secs max_processes unit_memory_max;
          };
          configFile = pkgs.writeText "sandboxd.json" (builtins.toJSON settings);
        in
        {
          options.services.agent-auth-sandboxd = {
            enable = lib.mkEnableOption "agent-auth sandboxd (in an agent VM)";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "agent-auth.packages.<system>.default";
            };

            brokerUrl = lib.mkOption {
              type = lib.types.strMatching
                "https://[^/].*|http://(localhost|127\\.0\\.0\\.1|\\[::1])(:[0-9]+)?(/.*)?";
            };

            brokerPublicKey = lib.mkOption {
              type = lib.types.strMatching "ed25519:[A-Za-z0-9_-]{43}";
              description = "The broker's public signing key, pinned (as for hostd).";
            };

            hostName = lib.mkOption {
              type = lib.types.strMatching "[a-z0-9][a-z0-9-]{0,62}";
              description = ''
                The PHYSICAL host this VM runs on: the sandbox daemon's name,
                and the <host> in its agents' names
                (<runtime>-<project>-<host>-sandbox).
              '';
            };

            runtimes = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
                options = {
                  package = lib.mkOption { type = lib.types.package; };
                  binary = lib.mkOption {
                    type = lib.types.str;
                    default = name;
                    description = "The binary in the package (unwrapped, not a sandbox launcher).";
                  };
                  model = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                  };
                };
              }));
              default = { };
              example = lib.literalExpression
                ''{ claude.package = pkgs.claude-code; codex.package = pkgs.codex; }'';
              description = "Agent runtimes: claude and/or codex.";
            };

            orchestratorRuntime = lib.mkOption {
              type = lib.types.str;
              default = "claude";
              description = "Which runtime the VM's orchestrator runs as.";
            };

            agentPackages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = with pkgs; [
                bashInteractive coreutils findutils gnugrep gnused gawk diffutils
                gnutar gzip xz unzip which file less procps
                git gh openssh curl wget jq ripgrep fd tree
                config.nix.package python3
              ];
              defaultText = lib.literalExpression "[ git gh coreutils nix python3 ripgrep … ]";
              description = "What agents find on PATH in their units.";
            };

            park_grace_secs = lib.mkOption {
              type = lib.types.number;
              default = 30;
              description = "Idle seconds after a turn before a conversation's process is parked.";
            };
            max_processes = lib.mkOption {
              type = lib.types.ints.positive;
              default = 16;
            };
            unit_memory_max = lib.mkOption {
              type = lib.types.str;
              default = "8G";
              description = "MemoryMax= of each agent process's unit.";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.etc."agent-auth/sandboxd.json".source = configFile;
            # Project users are userdb drop-ins sandboxd writes at run time.
            services.userdbd.enable = lib.mkDefault true;
            environment.etc.userdb.source = lib.mkDefault "/var/lib/userdb";
            environment.systemPackages = [ pkg pkgs.tmux pkgs.acl ];

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
              after = [ "network-online.target" "systemd-userdbd.service" ];
              environment.AGENT_AUTH_SANDBOXD_CONFIG = "/etc/agent-auth/sandboxd.json";
              path = [ pkgs.util-linux pkgs.acl pkgs.coreutils config.systemd.package pkgs.tmux ];
              # Running agents live in their own transient units: restarting the
              # daemon parks them (they resume on their next message).
              restartIfChanged = true;
              serviceConfig = {
                ExecStart = "${pkg}/bin/agent-auth-sandboxd run";
                Restart = "always";
                RestartSec = 5;
                StateDirectory = "sandboxd";
                StateDirectoryMode = "0700";
                RuntimeDirectory = [ "sandboxd" "sandboxd-agent" ];
                RuntimeDirectoryMode = "0755";
                # The daemon manages users, ACLs and units: it is root, on purpose.
                # It holds every agent key in the VM; the agents themselves run
                # unprivileged, each in its own unit.
                UMask = "0077";
              };
            };
          };
        };
    };
}
