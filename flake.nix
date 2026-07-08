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
                DISCORD_*, OPENROUTER_API_KEY, GITHUB_*, LLDAP_*, ...).
                Point at sops-nix (`format = "dotenv"`) or agenix paths — never
                nix-store files. Root-owned 0400 secrets are fine: systemd reads
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
    };
}
