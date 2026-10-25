# Checks of the NixOS and nix-darwin modules.
#
# - module-eval: evaluates a NixOS system with all three modules (no VM),
#   checks the units' settings that matter (sandbox, directory modes, the
#   assertions), and feeds the hostd.json / sandboxd.json the modules write
#   to the Rust binaries' own strict config parsers.
# - module-darwin-eval: the nix-darwin module, evaluated against stub
#   options (nix-darwin is not an input here), its hostd.json parsed too.
# - broker-vm: a NixOS VM test (KVM, or QEMU TCG: a few minutes):
#   PostgreSQL on the VM, the broker from the module, an agent created with
#   the admin CLI and an access request taken through to a credential.
{
  lib,
  pkgs,
  self,
  nixpkgsPath,
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  packages = self.packages.${system};
  brokerPublicKey = "ed25519:CAGm4HjX5-lT9w2JNi7U1yomf5i7u8Sge5G7o0eNWpY";
  brokerUrl = "https://agent-auth.example";

  base = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "/dev/vda";
      fsType = "ext4";
    };
    system.stateVersion = "26.05";
    networking.hostName = "testhost";
  };

  evalSystem =
    modules:
    import "${nixpkgsPath}/nixos/lib/eval-config.nix" {
      inherit system;
      modules = [ base ] ++ modules;
    };

  # Everything on: broker (local Postgres), a privileged hostd with
  # templates and desktop prompts, sandboxd.
  full = evalSystem [
    self.nixosModules.broker
    self.nixosModules.hostd
    self.nixosModules.sandboxd
    {
      services.agent-auth = {
        enable = true;
        policyFile = pkgs.writeText "policy.yaml" "{}\n";
        policyOverlays = [ "/run/secrets/policy-private" ];
        environmentFiles = [ "/run/secrets/agent-auth.env" ];
        loadCredentials = [ "github-pem:/run/secrets/github.pem" ];
        settings.LLDAP_LDAP_URL = "ldaps://lldap.example:6360";
      };
      users.users.alice = {
        isNormalUser = true;
      };
      services.agent-auth-hostd = {
        enable = true;
        inherit brokerUrl brokerPublicKey;
        user = "alice";
        tiers.user.enable = true;
        tiers.user.shell.enable = true;
        tiers.root.enable = true;
        vm.unit = "agent-vm.service";
        autoCommands = [
          [
            "systemctl"
            "--user"
            "status"
            "*"
          ]
        ];
        denyCommands = [
          [
            "rm"
            "**"
          ]
        ];
        templates.rebuild = {
          tier = "root";
          argv = [
            "nixos-rebuild"
            "switch"
            "--flake"
            "{flake}"
          ];
          params.flake = "git\\+https://git\\.example/me/[a-z0-9-]+#[a-z0-9-]+";
          cwd = "/";
          env.LANG = "C.UTF-8";
        };
        desktop = {
          enable = true;
          approve.user = true;
          approve.root = true;
        };
      };
      services.agent-auth-sandboxd = {
        enable = true;
        inherit brokerUrl brokerPublicKey;
        hostName = "testhost";
        runtimes.claude.package = pkgs.hello;
        runtimes.claude.binary = "hello";
        codex_auth_owner = "infra";
        extraConfig.unit_tasks_max = 2048;
      };
    }
  ];

  # hostd unprivileged (connect and report only).
  plain = evalSystem [
    self.nixosModules.hostd
    {
      services.agent-auth-hostd = {
        enable = true;
        inherit brokerUrl brokerPublicKey;
      };
    }
  ];

  # A Nix path literal in environmentFiles must be refused.
  pathLiteral = evalSystem [
    self.nixosModules.broker
    {
      services.agent-auth = {
        enable = true;
        policyFile = pkgs.writeText "policy.yaml" "{}\n";
        environmentFiles = [ ./module-tests.nix ];
      };
    }
  ];

  # The broker with these settings (and no local database).
  brokerWith =
    settings:
    evalSystem [
      self.nixosModules.broker
      {
        services.agent-auth = {
          enable = true;
          policyFile = pkgs.writeText "policy.yaml" "{}\n";
          database.createLocally = false;
          inherit settings;
        };
      }
    ];
  refused = prefix: settings: lib.any (lib.hasPrefix prefix) (failed (brokerWith settings));
  accepted = settings: failed (brokerWith settings) == [ ];

  failed = c: map (a: a.message) (lib.filter (a: !a.assertion) c.config.assertions);

  unit = c: name: c.config.systemd.services.${name}.serviceConfig;
  broker = unit full "agent-auth";
  brokerEnv = full.config.systemd.services.agent-auth.environment;
  hostdRoot = unit full "agent-auth-hostd";
  hostdPlain = unit plain "agent-auth-hostd";
  sandboxd = unit full "agent-auth-sandboxd";

  expect = name: cond: if cond then null else throw "module-eval: ${name}";
  facts = [
    (expect "no failed assertions in the full system" (failed full == [ ]))
    (expect "no failed assertions in the plain hostd" (failed plain == [ ]))
    (expect "a path literal in environmentFiles is refused" (
      lib.any (lib.hasPrefix "services.agent-auth.environmentFiles") (failed pathLiteral)
    ))
    (expect "a secret in settings is refused" (
      refused "services.agent-auth.settings holds a secret" { ADMIN_TOKEN = "x"; }
    ))
    (expect "a secret in settings is refused whatever its case" (
      refused "services.agent-auth.settings holds a secret" { admin_token = "x"; }
    ))
    (expect "secret-looking names are refused" (
      refused "services.agent-auth.settings holds a secret" { GITHUB_WEBHOOK_SECRET = "x"; }
    ))
    (expect "lower-case names are refused" (
      refused "services.agent-auth.settings: write variable names in upper case" { log_level = "info"; }
    ))
    (expect "a DATABASE_URL with a password is refused" (
      refused "services.agent-auth.settings.DATABASE_URL holds a password" {
        DATABASE_URL = "postgres://u:hunter2@db.example/aa?sslmode=verify-full&sslrootcert=/ca.crt";
      }
    ))
    (expect "a password in DATABASE_URL's query is refused" (
      refused "services.agent-auth.settings.DATABASE_URL holds a password" {
        DATABASE_URL = "postgres://u@db.example/aa?sslmode=verify-full&PASSWORD=x";
      }
    ))
    (expect "a DATABASE_URL without a password is accepted" (accepted {
      DATABASE_URL = "postgres://agent-auth@db.example/aa?sslmode=verify-full&sslrootcert=/ca.crt";
      KUBERNETES_TOKEN_FILE = "/run/credentials/agent-auth.service/k8s-token";
      GITHUB_APP_PRIVATE_KEY_FILE = "/run/credentials/agent-auth.service/github-pem";
    }))
    (expect "broker: local Postgres" full.config.services.postgresql.enable)
    (expect "broker: DATABASE_URL over the socket" (
      brokerEnv.DATABASE_URL == "postgres://agent-auth@localhost/agent-auth?host=/run/postgresql"
    ))
    (expect "broker: overlays from credentials" (
      brokerEnv.POLICY_OVERLAYS == "/run/credentials/agent-auth.service/policy-overlay-0"
    ))
    (expect "broker: new settings pass through" (
      brokerEnv.LLDAP_LDAP_URL == "ldaps://lldap.example:6360"
    ))
    (expect "broker: DynamicUser" broker.DynamicUser)
    (expect "broker: W^X" broker.MemoryDenyWriteExecute)
    (expect "broker: no capabilities" (broker.CapabilityBoundingSet == ""))
    (expect "broker: LimitNOFILE" (broker.LimitNOFILE == 65536))
    (expect "broker: secrets file not in the store" (
      broker.EnvironmentFile == [ "/run/secrets/agent-auth.env" ]
    ))
    (expect "hostd privileged: root" (hostdRoot.User == "root"))
    (expect "hostd: LimitNOFILE" (hostdRoot.LimitNOFILE == 65536))
    (expect "hostd plain: its own user" (hostdPlain.User == "agent-auth-hostd"))
    (expect "hostd plain: peers' /proc visible" (!(hostdPlain ? ProtectProc)))
    (expect "sandboxd: runtime dirs made root-only (sandboxd sets their modes)" (
      sandboxd.RuntimeDirectory == [
        "sandboxd"
        "sandboxd-agent"
      ]
      && sandboxd.RuntimeDirectoryMode == "0700"
    ))
    (expect "sandboxd: protected hardlinks" (
      full.config.boot.kernel.sysctl."fs.protected_hardlinks" == 1
    ))
  ];

  hostdJson = full.config.environment.etc."agent-auth/hostd.json".source;
  hostdPlainJson = plain.config.environment.etc."agent-auth/hostd.json".source;
  sandboxdJson = full.config.environment.etc."agent-auth/sandboxd.json".source;

  # nix-darwin: stub the options the module sets.
  darwin = lib.evalModules {
    specialArgs = {
      pkgs = pkgs;
    };
    modules = [
      self.darwinModules.hostd
      (
        { lib, ... }:
        {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.unspecified;
              default = [ ];
            };
            environment = lib.mkOption {
              type = lib.types.attrsOf lib.types.unspecified;
              default = { };
            };
            launchd = lib.mkOption {
              type = lib.types.attrsOf lib.types.unspecified;
              default = { };
            };
            networking.hostName = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = "MacBook";
            };
          };
          config.services.agent-auth-hostd = {
            enable = true;
            inherit brokerUrl brokerPublicKey;
            # The aarch64-darwin package; only its path is used here.
            package = packages.hostd;
            user = "alice";
            tiers.user.enable = true;
            desktop.enable = true;
            desktop.approve.user = true;
          };
        }
      )
    ];
  };
  darwinJson = darwin.config.environment.etc."agent-auth/hostd.json".source;
  darwinFailed = map (a: a.message) (lib.filter (a: !a.assertion) darwin.config.assertions);

  # The binaries' own parsers, which refuse unknown keys and wrong types:
  # `totp-enroll` reads the config first (exit 2 if it does not parse),
  # then refuses to go on as non-root (exit 1); `pair -` reads the config,
  # then fails to reach the broker (no network in the build).
  parses = pkgs.runCommand "agent-auth-module-configs" { nativeBuildInputs = [ pkgs.jq ]; } ''
    hostd_parses() {
      set +e
      ${packages.hostd}/bin/agent-auth-hostd totp-enroll --config "$1" 2>err
      code=$?
      set -e
      if [ $code -ne 1 ] || ! grep -q "run as root" err; then
        echo "hostd refused $2:"; cat err; cat "$1"; exit 1
      fi
    }
    hostd_parses ${hostdJson} "the full hostd.json"
    hostd_parses ${hostdPlainJson} "the plain hostd.json"
    hostd_parses ${darwinJson} "the darwin module's hostd.json"

    mkdir state
    jq --arg s "$PWD/state" '.state_dir = $s' ${sandboxdJson} > sandboxd.json
    set +e
    echo 000000 | ${packages.sandboxd}/bin/agent-auth-sandboxd pair - --config sandboxd.json 2>err
    code=$?
    set -e
    if [ $code -eq 2 ] || grep -q "invalid config" err; then
      echo "sandboxd refused sandboxd.json:"; cat err; cat sandboxd.json; exit 1
    fi
    echo "sandboxd read its config, then (as expected without a network):"; cat err
    touch $out
  '';
in
{
  module-eval = builtins.deepSeq facts parses;

  module-darwin-eval =
    if darwinFailed != [ ] then
      throw "darwin module: ${toString darwinFailed}"
    else
      builtins.deepSeq darwin.config.launchd.daemons.agent-auth-hostd.serviceConfig parses;

  broker-vm = import ./vm-test.nix { inherit pkgs self; };
}
