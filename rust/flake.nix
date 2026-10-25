{
  description = "agent-auth (Rust port): toolchains for building, testing, fuzzing and verifying";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      # Stable builds everything that ships. The nightly is only for tools
      # that need it (miri, cargo-fuzz's sanitizers) and is pinned by date.
      stable = pkgs.rust-bin.stable."1.99.0".default.override {
        extensions = [ "rust-src" "clippy" "rustfmt" "llvm-tools" ];
      };
      nightly = pkgs.rust-bin.nightly."2026-10-01".default.override {
        extensions = [ "rust-src" "miri" "llvm-tools" ];
      };
      # Kani is built against one exact nightly (its bundle's
      # rust-toolchain-version); nix/kani.nix checks they match.
      kaniNightly = pkgs.rust-bin.nightly."2026-08-21".default.override {
        extensions = [ "rust-src" "rustc-dev" "llvm-tools" "rustfmt" ];
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
      packages.${system}.kani = kani;

      devShells.${system} = {
        default = pkgs.mkShell {
          packages = [ stable ] ++ tools;
          SQLX_OFFLINE = "true";
          NSS_WRAPPER_LIB = "${pkgs.nss_wrapper}/lib/libnss_wrapper.so";
        };
        nightly = pkgs.mkShell {
          packages = [ nightly pkgs.cargo-fuzz ] ++ tools;
          SQLX_OFFLINE = "true";
          NSS_WRAPPER_LIB = "${pkgs.nss_wrapper}/lib/libnss_wrapper.so";
        };
        # `cargo kani` (scripts/kani.sh). Kani drives its own nightly; it is
        # also the shell's cargo so `cargo` and `cargo kani` agree.
        kani = pkgs.mkShell {
          packages = [ kani kaniNightly ];
          SQLX_OFFLINE = "true";
        };
      };
    };
}
