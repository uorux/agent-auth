{
  description = "agent-auth (Rust port): packages, NixOS/nix-darwin modules, the broker's image, and toolchains for building, testing, fuzzing and verifying";

  # Consumers: `inputs.agent-auth-rs.url = "github:uorux/agent-auth?dir=rust"`
  # (or `git+file:///path/to/agent-auth?dir=rust`). The Python flake at the
  # repository's top level is unchanged; both export modules with the same
  # option names (services.agent-auth, -hostd, -sandboxd), so a host
  # switches by importing the other flake's module. Import one, not both.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      ...
    }:
    let
      lib = nixpkgs.lib;
      system = "x86_64-linux";
      # Packages: Linux (everything) and macOS (hostd and the client).
      # Only x86_64-linux is built and checked here; the others evaluate.
      packageSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      pkgsFor =
        s:
        import nixpkgs {
          system = s;
          overlays = [ rust-overlay.overlays.default ];
        };
      # Stable builds everything that ships. The nightly is only for tools
      # that need it (miri, cargo-fuzz's sanitizers) and is pinned by date.
      stableFor =
        p:
        p.rust-bin.stable."1.99.0".default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
            "llvm-tools"
          ];
        };
      builtFor =
        s:
        let
          p = pkgsFor s;
        in
        import ./nix/packages.nix {
          inherit lib;
          pkgs = p;
          craneLib = (crane.mkLib p).overrideToolchain stableFor;
        };
      built = lib.genAttrs packageSystems builtFor;

      pkgs = pkgsFor system;
      stable = stableFor pkgs;
      nightly = pkgs.rust-bin.nightly."2026-10-01".default.override {
        extensions = [
          "rust-src"
          "miri"
          "llvm-tools"
        ];
      };
      # Kani is built against one exact nightly (its bundle's
      # rust-toolchain-version); nix/kani.nix checks they match.
      kaniNightly = pkgs.rust-bin.nightly."2026-08-21".default.override {
        extensions = [
          "rust-src"
          "rustc-dev"
          "llvm-tools"
          "rustfmt"
        ];
      };
      kani = pkgs.callPackage ./nix/kani.nix { toolchain = kaniNightly; };
      tools = [
        pkgs.cargo-deny
        pkgs.cargo-audit
        pkgs.cargo-nextest
        pkgs.cargo-geiger
        pkgs.cargo-vet
        pkgs.sqlx-cli
        pkgs.postgresql_18
        pkgs.nss_wrapper
        pkgs.pkg-config
        pkgs.python3
        pkgs.jq
      ];
    in
    {
      packages = lib.mapAttrs (_: b: b.packages) built // {
        ${system} = built.${system}.packages // {
          inherit kani;
        };
      };

      # services.agent-auth (the broker), services.agent-auth-hostd,
      # services.agent-auth-sandboxd; `default` is the broker, as in the
      # Python flake.
      nixosModules = rec {
        broker = import ./nix/modules/broker.nix self;
        default = broker;
        hostd = import ./nix/modules/hostd.nix self;
        sandboxd = import ./nix/modules/sandboxd.nix self;
      };
      darwinModules.hostd = import ./nix/modules/hostd-darwin.nix self;

      checks.${system} =
        import ./nix/checks.nix {
          inherit lib pkgs;
          craneLib = (crane.mkLib pkgs).overrideToolchain stableFor;
          built = built.${system};
        }
        // import ./nix/module-tests.nix {
          inherit lib pkgs self;
          nixpkgsPath = nixpkgs.outPath;
        };

      devShells.${system} = {
        default = pkgs.mkShell {
          packages = [ stable ] ++ tools;
          SQLX_OFFLINE = "true";
          NSS_WRAPPER_LIB = "${pkgs.nss_wrapper}/lib/libnss_wrapper.so";
        };
        nightly = pkgs.mkShell {
          packages = [
            nightly
            pkgs.cargo-fuzz
          ]
          ++ tools;
          SQLX_OFFLINE = "true";
          NSS_WRAPPER_LIB = "${pkgs.nss_wrapper}/lib/libnss_wrapper.so";
        };
        # `cargo kani` (scripts/kani.sh). Kani drives its own nightly; it is
        # also the shell's cargo so `cargo` and `cargo kani` agree.
        kani = pkgs.mkShell {
          packages = [
            kani
            kaniNightly
          ];
          SQLX_OFFLINE = "true";
        };
        # Kubernetes manifests: kustomize, kubeconform (deploy/k8s).
        k8s = pkgs.mkShell {
          packages = [
            pkgs.kubectl
            pkgs.kubeconform
            pkgs.kustomize
          ];
        };
      };
    };
}
