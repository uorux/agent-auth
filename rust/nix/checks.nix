# `nix flake check` for the Rust workspace: what scripts/check.sh does,
# minus what needs the network (cargo deny's advisory database, the
# cooldown check against crates.io).
{
  lib,
  pkgs,
  craneLib,
  built,
}:
let
  inherit (built) common cargoArtifacts inTestSrc;
  auditSrc = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../scripts/audit.sh
      ../crates
      ../fuzz
    ];
  };
in
{
  # No `unsafe`; human approvals only from human surfaces.
  rust-audit = pkgs.runCommand "agent-auth-audit" { } ''
    cp -r ${auditSrc} src && chmod -R u+w src && cd src
    ${pkgs.bash}/bin/bash scripts/audit.sh
    touch $out
  '';

  rust-fmt = craneLib.cargoFmt { inherit (common) src pname version; };

  # The workspace's lints (Cargo.toml [workspace.lints], clippy.toml) as
  # errors, on every target.
  rust-clippy = craneLib.cargoClippy (
    common
    // inTestSrc
    // {
      inherit cargoArtifacts;
      pname = "agent-auth-clippy";
      cargoClippyExtraArgs = "--workspace --all-targets -- -D warnings";
    }
  );

  # Every test, the database ones and the e2e suite included, against a
  # throwaway Postgres in the build sandbox (as scripts/pg.sh makes one).
  # The e2e suite runs the workspace's binaries, so they are built first.
  rust-tests = craneLib.mkCargoDerivation (
    common
    // inTestSrc
    // {
      inherit cargoArtifacts;
      pname = "agent-auth-tests";
      nativeBuildInputs = [
        pkgs.cargo-nextest
        pkgs.postgresql_18
        # Tests that drive the daemons' helpers (setfacl, kill, ...).
        pkgs.acl
        pkgs.util-linux
        pkgs.procps
      ];
      doInstallCargoArtifacts = false;
      buildPhaseCargoCommand = ''
        export HOME="$TMPDIR/home"
        mkdir -p "$HOME"
        pg="$TMPDIR/pg"
        initdb -D "$pg/data" -U agent_auth --auth=trust --no-instructions >/dev/null
        pg_ctl -D "$pg/data" -l "$pg/log" -w start \
          -o "-k $pg -p 54321 -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=400" >/dev/null
        trap 'pg_ctl -D "$pg/data" -w -m immediate stop >/dev/null || true' EXIT
        createdb -h "$pg" -p 54321 -U agent_auth agent_auth
        export DATABASE_URL=postgres://agent_auth@127.0.0.1:54321/agent_auth

        pg_ctl -D "$pg/data" status
        cargo build --release --locked --workspace --bins
        # Two sandboxd tests run their fake systemctl/systemd-run with
        # sandboxd's fixed child PATH (/run/current-system/sw/bin), which
        # only a NixOS host has: they run in scripts/check.sh there.
        cargo nextest run --release --locked --workspace --no-fail-fast \
          --color never --hide-progress-bar \
          -E 'not (test(=host::tests::children_get_a_clean_environment_and_clients_a_unit) | test(=host::tests::a_freeze_is_verified_and_an_unfreezable_unit_is_stopped))' \
          2>&1 | tee nextest.log
        test "''${PIPESTATUS[0]}" = 0
      '';
      installPhaseCommand = ''
        mkdir -p $out
        cp nextest.log $out/
      '';
    }
  );
}
