# Kani (https://github.com/model-checking/kani) from its x86_64-linux
# release bundle, made to run on NixOS.
#
# Upstream installs with `cargo install kani-verifier && cargo kani setup`:
# the `kani-verifier` crate is only a proxy that downloads this same bundle
# into `$KANI_HOME/kani-<version>` (default `~/.kani`), installs the pinned
# nightly with rustup, symlinks it as `<bundle>/toolchain`, and then execs
# `<bundle>/bin/kani-driver` with argv[0] set to `kani` or `cargo-kani`.
# Here the bundle is a store path, the nightly comes from rust-overlay (no
# rustup), the prebuilt ELF files are patched with autoPatchelfHook (no
# /lib64/ld-linux-x86-64.so.2 on NixOS), and `bin/kani` / `bin/cargo-kani`
# are the exec wrappers the proxy would have been.
#
# kani-driver finds everything else relative to its own executable: the
# compiler and CBMC in `bin/`, its sysroot in `lib/`, and the toolchain's
# cargo at `toolchain/bin/cargo`. Nothing is written into the bundle, so it
# can stay read-only in the store.
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
  makeWrapper,
  # The nightly the bundle was built against, with the rustc-dev component
  # (kani-compiler links librustc_driver from it). It must be exactly the
  # one named in the bundle's `rust-toolchain-version`; the build checks.
  toolchain,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "kani";
  version = "0.68.0";

  src = fetchurl {
    url = "https://github.com/model-checking/kani/releases/download/kani-${finalAttrs.version}/kani-${finalAttrs.version}-x86_64-unknown-linux-gnu.tar.gz";
    hash = "sha256-MuK0hNc+3gu/ZKLPCHnEJZQiSX2K7E7mfUSN6a54Q9M=";
  };

  nativeBuildInputs = [
    autoPatchelfHook
    makeWrapper
  ];
  # libstdc++ for CBMC; librustc_driver-*.so for kani-compiler.
  buildInputs = [
    stdenv.cc.cc.lib
    toolchain
  ];

  dontConfigure = true;
  dontBuild = true;
  # The rlibs in lib/ are the sysroot kani-compiler builds against; do not
  # let the fixup phase strip them.
  dontStrip = true;

  installPhase = ''
    runHook preInstall

    bundle=$out/kani-${finalAttrs.version}
    mkdir -p $bundle $out/bin
    cp -r . $bundle/
    ln -s ${toolchain} $bundle/toolchain

    # The bundle records the toolchain it was built with; refuse any other.
    want=$(cat $bundle/rustc-version)
    have=$(${toolchain}/bin/rustc --version)
    if [ "$want" != "$have" ]; then
      echo "kani ${finalAttrs.version} needs '$want' but the toolchain is '$have'" >&2
      exit 1
    fi

    for name in kani cargo-kani; do
      makeWrapper $bundle/bin/kani-driver $out/bin/$name \
        --argv0 $name \
        --prefix PATH : $bundle/bin \
        --set KANI_HOME $out \
        --set RUSTUP_TOOLCHAIN "$(cat $bundle/rust-toolchain-version)"
    done

    runHook postInstall
  '';

  # kani-compiler's RUNPATH names the CI runner's rustup directory; keep only
  # the bundle-relative entry (which resolves through the toolchain symlink)
  # and the dependencies autoPatchelfHook adds.
  preFixup = ''
    patchelf --set-rpath '$ORIGIN/../toolchain/lib' $out/kani-${finalAttrs.version}/bin/kani-compiler
  '';

  meta = {
    description = "Kani Rust model checker (prebuilt release bundle, patched for NixOS)";
    homepage = "https://github.com/model-checking/kani";
    license = with lib.licenses; [
      asl20
      mit
      bsdOriginal # CBMC (BSD-4-Clause)
    ];
    platforms = [ "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    mainProgram = "cargo-kani";
  };
})
