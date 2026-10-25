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
      };
    };
}
