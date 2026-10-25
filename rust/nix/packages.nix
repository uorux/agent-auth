# The Rust port's packages, built with crane from Cargo.lock (offline: every
# crate is fetched by its lock-file checksum; sqlx's queries are checked
# against the committed `.sqlx` data, SQLX_OFFLINE=true).
#
# One dependency build (`cargoArtifacts`) is shared by every package and
# check, so a change to our code rebuilds our crates only.
{
  lib,
  pkgs,
  craneLib,
  # Only the parts that build on this platform (Linux: everything; macOS:
  # hostd and the agent-side programs).
  linux ? pkgs.stdenv.hostPlatform.isLinux,
}:
let
  root = ../.;
  # What cargo needs and nothing else: no target/, no flake files (a change
  # to packaging does not rebuild the code), no specs or fuzz workspace.
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../clippy.toml
      ../.sqlx
      ../crates
    ];
  };

  # The tests also read the repository's policy.example.yaml (core's
  # policy tests load it), one level above the workspace.
  testSrc = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../policy.example.yaml
      ../Cargo.toml
      ../Cargo.lock
      ../clippy.toml
      ../.sqlx
      ../crates
    ];
  };
  # Build from the workspace in testSrc's rust/.
  inTestSrc = {
    src = testSrc;
    cargoLock = ../Cargo.lock;
    cargoToml = ../Cargo.toml;
    postUnpack = ''
      cd "$sourceRoot/rust"
      sourceRoot=.
    '';
  };

  common = {
    inherit src;
    pname = "agent-auth";
    version = (lib.importTOML ../Cargo.toml).workspace.package.version;
    strictDeps = true;
    # Queries are checked against .sqlx (no database at build time).
    SQLX_OFFLINE = "true";
    # ring's build script compiles its C and assembly with the stdenv cc.
    nativeBuildInputs = [ ];
    buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
    # The release profile of Cargo.toml (overflow checks on, thin LTO).
    CARGO_PROFILE = "release";
    cargoExtraArgs = "--locked";
  };

  # Every dependency of the workspace (normal, build and dev), compiled once.
  cargoArtifacts = craneLib.buildDepsOnly (
    common
    // {
      pname = "agent-auth-deps";
      # macOS builds only the crates that run there; the broker's
      # dependencies (sqlx, ...) are not needed for them.
      cargoExtraArgs =
        if linux then
          "--locked --workspace"
        else
          "--locked -p agent-auth-hostd -p agent-auth-cli -p agent-auth-mcp";
    }
  );

  # One package per part: `bins` are cargo `--bin` names, `crates` the
  # packages that hold them.
  part =
    {
      pname,
      crates,
      bins,
      description,
      mainProgram,
    }:
    craneLib.buildPackage (
      common
      // {
        inherit pname cargoArtifacts;
        cargoExtraArgs =
          "--locked "
          + lib.concatMapStringsSep " " (c: "-p ${c}") crates
          + " "
          + lib.concatMapStringsSep " " (b: "--bin ${b}") bins;
        # Tests run in checks.rust-tests (they need Postgres).
        doCheck = false;
        # Exactly the binaries asked for.
        postInstall = ''
          for f in $out/bin/*; do
            case " ${lib.concatStringsSep " " bins} " in
              *" $(basename "$f") "*) ;;
              *) rm "$f" ;;
            esac
          done
        '';
        meta = {
          inherit description mainProgram;
          license = lib.licenses.mit;
          platforms = if linux then lib.platforms.linux else lib.platforms.darwin;
        };
      }
    );

  clientBins = [
    "agent-auth"
    "agent-auth-mcp"
    "agent-auth-mcp-bridge"
  ];

  hostd = part {
    pname = "agent-auth-hostd";
    crates = [ "agent-auth-hostd" ];
    bins = [
      "agent-auth-hostd"
      "agent-auth-hostctl"
    ];
    description = "agent-auth's host daemon (hostexec, desktop prompts, lockdown) and hostctl";
    mainProgram = "agent-auth-hostd";
  };

  client = part {
    pname = "agent-auth-client";
    crates = [
      "agent-auth-cli"
      "agent-auth-mcp"
    ];
    bins = clientBins;
    description = "agent-auth's agent-side programs: the CLI, the stdio MCP server and the MCP bridge";
    mainProgram = "agent-auth";
  };

  linuxParts = rec {
    broker = part {
      pname = "agent-auth-server";
      crates = [ "agent-auth-broker" ];
      bins = [ "agent-auth-server" ];
      description = "agent-auth's broker (HTTP API, Discord bot, admin panel, daemon hub)";
      mainProgram = "agent-auth-server";
    };

    # Inside an agent VM: sandboxd puts the client programs on its agents'
    # PATH and in their MCP configs, so they come with it.
    sandboxd = part {
      pname = "agent-auth-sandboxd";
      crates = [
        "agent-auth-sandboxd"
        "agent-auth-cli"
        "agent-auth-mcp"
      ];
      bins = [
        "agent-auth-sandboxd"
        "agent-auth-sandboxctl"
        "agent-auth-sandbox-mcp"
      ]
      ++ clientBins;
      description = "agent-auth's agent-VM daemon, sandboxctl, the sandbox MCP server and the client programs";
      mainProgram = "agent-auth-sandboxd";
    };

    # Everything, for a workstation or the e2e suite.
    default = pkgs.symlinkJoin {
      name = "agent-auth-${common.version}";
      paths = [
        broker
        hostd
        sandboxd
        client
      ];
      meta.mainProgram = "agent-auth";
    };

    # The broker as an OCI image (docker load < result). No shell, no
    # package manager, no CA bundle: the broker trusts its own root store
    # (agent-auth-tls: webpki-roots minus the distrusted roots; Postgres
    # TLS takes `sslrootcert` from DATABASE_URL), never the system's. Runs
    # as an unprivileged uid; the filesystem can be read-only.
    image = pkgs.dockerTools.buildLayeredImage {
      name = "agent-auth";
      tag = common.version;
      contents = [ broker ];
      # A /tmp for the libraries that want one, writable by anyone (sticky);
      # mount an emptyDir there with a read-only root filesystem.
      extraCommands = ''
        mkdir -p tmp etc
        chmod 1777 tmp
        echo 'agent-auth:x:65532:65532:agent-auth:/var/empty:/nonexistent' > etc/passwd
        echo 'agent-auth:x:65532:' > etc/group
      '';
      config = {
        Entrypoint = [ "${broker}/bin/agent-auth-server" ];
        User = "65532:65532";
        # The broker reads ./.env: start somewhere nothing can put one.
        WorkingDir = "/";
        Env = [
          "LISTEN_HOST=0.0.0.0"
          "LISTEN_PORT=8400"
          "POLICY_FILE=/etc/agent-auth/policy.yaml"
        ];
        ExposedPorts."8400/tcp" = { };
        Labels = {
          "org.opencontainers.image.title" = "agent-auth";
          "org.opencontainers.image.description" = "agent-auth broker (Rust)";
          "org.opencontainers.image.source" = "https://github.com/uorux/agent-auth";
          "org.opencontainers.image.licenses" = "MIT";
        };
        # Liveness: GET /healthz (unauthenticated, {"ok": true}); there is
        # no HEALTHCHECK command because the image has nothing to run one
        # with. Kubernetes probes it over HTTP (deploy/k8s).
      };
    };
  };
in
{
  packages = {
    inherit hostd client;
  }
  // lib.optionalAttrs linux linuxParts;

  inherit
    cargoArtifacts
    common
    src
    inTestSrc
    ;
}
