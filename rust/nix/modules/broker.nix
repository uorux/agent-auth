# The broker (Rust) as a NixOS service: `services.agent-auth`, the same
# options as the Python flake's nixosModules.default, plus `database`
# (the Rust broker runs on PostgreSQL only) and a stricter sandbox.
#
# The policy file comes from the nix store (immutable at runtime; a change
# is a rebuild, i.e. an audited commit to the host's config repo). Keep that
# repo out of reach of every brokered agent.
#
# Exactly one broker per database: it takes an advisory lock at start and a
# second one exits (ARCHITECTURE.md "Deployment").
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.agent-auth;
  inherit (lib) mkOption types;
  localDb = cfg.database.createLocally;
  # The broker reads its environment case-insensitively (every key
  # upper-cased), so every check here compares upper-cased names.
  upperKeys = map lib.toUpper (lib.attrNames cfg.settings);
  # Secrets that must never sit in `settings` (the world-readable store):
  # these by name, and anything named like a token, key, password or secret
  # (`*_FILE` paths to such files are fine).
  secretNames = [
    "ADMIN_TOKEN"
    "ENCRYPTION_KEY"
    "BROKER_SIGNING_KEY"
    "DISCORD_TOKEN"
    "OPENROUTER_API_KEY"
    "LLDAP_ADMIN_PASSWORD"
    "LITELLM_MASTER_KEY"
    "KUBERNETES_TOKEN"
    "WEBHOOK_SIGNING_SECRET"
  ];
  looksSecret =
    k:
    lib.elem k secretNames
    || lib.any (suffix: lib.hasSuffix suffix k) [
      "_TOKEN"
      "_KEY"
      "_PASSWORD"
      "_SECRET"
    ];
  secretsInSettings = lib.filter looksSecret upperKeys;
  # DATABASE_URL in `settings` only without a password (peer or certificate
  # authentication); one with a password goes in an environment file.
  settingsDbUrls = lib.mapAttrsToList (_: v: v) (
    lib.filterAttrs (k: _: lib.toUpper k == "DATABASE_URL") cfg.settings
  );
  hasPassword =
    url:
    let
      u = lib.toLower url;
    in
    builtins.match "[a-z0-9+.-]+://[^/?#@]*:[^/?#@]*@.*" u != null
    || builtins.match ".*[?&]password=.*" u != null;
  overlayPaths = lib.imap0 (
    i: _: "/run/credentials/agent-auth.service/policy-overlay-${toString i}"
  ) cfg.policyOverlays;
in
{
  options.services.agent-auth = {
    enable = lib.mkEnableOption "agent-auth credential broker (Rust)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.broker;
      defaultText = lib.literalExpression "agent-auth-rs.packages.<system>.broker";
      description = "The package with `bin/agent-auth-server`.";
    };

    policyFile = mkOption {
      type = types.path;
      description = ''
        Policy YAML (see policy.example.yaml; what changed for the Rust
        broker is in rust/DEVIATIONS.md, section Policy). Referencing a repo
        file copies it into the nix store, making the runtime policy
        immutable. The broker does not start without it.
      '';
    };

    policyOverlays = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = lib.literalExpression ''[ config.sops.secrets."agent-auth/policy-private".path ]'';
      description = ''
        More policy, merged over policyFile in order: policy that must not
        sit in the repo agents read (a restricted zone's project, rules and
        readers). Paths to secret files (sops-nix), as strings so they never
        reach the nix store; loaded with LoadCredential. A missing one stops
        the broker from starting.
      '';
    };

    listenHost = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Bind address; front with your reverse proxy for TLS.";
    };

    port = mkOption {
      type = types.port;
      default = 8400;
    };

    database.createLocally = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Run PostgreSQL on this host (services.postgresql) with a database
        and a role named `agent-auth`, reached over its unix socket with
        peer authentication: no password anywhere. Off: give DATABASE_URL
        yourself (`postgres://user:password@host/db?sslmode=verify-full&sslrootcert=/path/ca.crt`)
        in one of `environmentFiles`, since it holds a password.
      '';
    };

    environmentFiles = mkOption {
      type = types.listOf types.path;
      default = [ ];
      example = lib.literalExpression ''[ config.sops.secrets."agent-auth/env".path ]'';
      description = ''
        EnvironmentFile(s) with secrets: ADMIN_TOKEN, ENCRYPTION_KEY
        (`agent-auth admin gen-key`), BROKER_SIGNING_KEY
        (`agent-auth admin gen-signing-key --out FILE`), DISCORD_*,
        OPENROUTER_API_KEY, GITHUB_*, LLDAP_ADMIN_PASSWORD,
        LITELLM_MASTER_KEY, DATABASE_URL (when not createLocally), ...
        (rust/README.md lists them all). Give paths as strings
        (sops-nix's `config.sops.secrets.<x>.path`, agenix), never Nix path
        literals: those are copied into the world-readable store (an
        assertion refuses them). Root-owned 0400 files are fine: systemd
        reads them before dropping to the DynamicUser.
      '';
    };

    loadCredentials = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = lib.literalExpression ''
        [ "github-pem:''${config.sops.secrets."agent-auth/github-app-pem".path}" ]
      '';
      description = ''
        systemd LoadCredential entries for file secrets (GitHub App PEM,
        out-of-cluster Kubernetes token, Google login files). Reference them
        from `settings` as /run/credentials/agent-auth.service/<name>.
      '';
    };

    settings = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        KUBERNETES_API_URL = "https://k8s.example:6443";
        KUBERNETES_TOKEN_FILE = "/run/credentials/agent-auth.service/k8s-token";
        LLDAP_URL = "https://lldap.example";
        LLDAP_LDAP_URL = "ldaps://lldap.example:6360";
        LLDAP_BASE_DN = "dc=example,dc=com";
        TRUST_PROXY_HEADERS = "1";
      };
      description = ''
        Non-secret environment for the service (rust/README.md lists every
        variable). Lands in the world-readable store: no secrets here.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # A Nix path literal (./secrets.env) is copied into the
        # world-readable store.
        assertion = !(lib.any builtins.isPath cfg.environmentFiles);
        message = "services.agent-auth.environmentFiles: pass secret files as strings (e.g. config.sops.secrets.<x>.path), not Nix paths, which are copied into the world-readable store";
      }
      {
        # Two spellings of one variable would leave which one wins to the
        # broker's map order.
        assertion = lib.all (k: k == lib.toUpper k) (lib.attrNames cfg.settings);
        message = "services.agent-auth.settings: write variable names in upper case (the broker reads them case-insensitively): ${
          toString (lib.filter (k: k != lib.toUpper k) (lib.attrNames cfg.settings))
        }";
      }
      {
        assertion = !(lib.elem "DATABASE_URL" upperKeys && localDb);
        message = "services.agent-auth: settings.DATABASE_URL is set while database.createLocally is on; turn one off";
      }
      {
        assertion = !(lib.any hasPassword settingsDbUrls);
        message = "services.agent-auth.settings.DATABASE_URL holds a password (it lands in the world-readable store): put DATABASE_URL in environmentFiles";
      }
      {
        assertion = secretsInSettings == [ ];
        message = "services.agent-auth.settings holds a secret (it lands in the world-readable store): put ${toString secretsInSettings} in environmentFiles";
      }
    ];

    services.postgresql = lib.mkIf localDb {
      enable = true;
      ensureDatabases = [ "agent-auth" ];
      ensureUsers = [
        {
          name = "agent-auth";
          ensureDBOwnership = true;
        }
      ];
    };

    systemd.services.agent-auth = {
      description = "agent-auth credential broker";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ] ++ lib.optional localDb "postgresql.target";
      requires = lib.optional localDb "postgresql.target";

      environment = {
        POLICY_FILE = "${cfg.policyFile}";
        POLICY_OVERLAYS = lib.concatStringsSep "," overlayPaths;
        LISTEN_HOST = cfg.listenHost;
        LISTEN_PORT = toString cfg.port;
      }
      // lib.optionalAttrs localDb {
        # The unix socket, as the role of the same name as the service's
        # user (peer authentication).
        DATABASE_URL = "postgres://agent-auth@localhost/agent-auth?host=/run/postgresql";
      }
      // cfg.settings;

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/agent-auth-server";
        DynamicUser = true;
        User = "agent-auth";
        Group = "agent-auth";
        # No state on disk (it is all in Postgres). The broker reads ./.env:
        # start where nothing can put one.
        WorkingDirectory = "/var/empty";
        EnvironmentFile = cfg.environmentFiles;
        LoadCredential =
          cfg.loadCredentials
          ++ lib.imap0 (i: path: "policy-overlay-${toString i}:${path}") cfg.policyOverlays;
        Restart = "on-failure";
        RestartSec = 5;
        # Long-polls (decisions, a2a) and paired daemons' WebSockets each
        # hold a connection.
        LimitNOFILE = 65536;
        # Open requests get 10 s, LLM evaluations 10 s more, then it exits.
        TimeoutStopSec = 30;

        # Hardening: everything the Python unit had, plus W^X memory (no
        # cffi any more), a private user namespace, no host name changes,
        # only /proc/<pid>, no devices.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        DevicePolicy = "closed";
        PrivateUsers = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        SystemCallErrorNumber = "EPERM";
        SystemCallArchitectures = "native";
        UMask = "0077";
      };
    };
  };
}
