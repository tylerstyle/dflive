{ lib
, rustPlatform
}:

rustPlatform.buildRustPackage {
  pname = "dflive";
  version = "0.1.0";

  # Exclude `dfkit` from `dflive`'s source and workspace members: `dfkit` depends on
  # the Linux-only sibling `../../dfcore` crate, which is not in `dflive`'s sandbox
  # and must not be pulled into Windows/macOS cross-builds of `dflive`.
  src = lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target" && baseNameOf path != "dfkit";
    src = lib.cleanSource ./.;
  };

  postPatch = ''
    substituteInPlace Cargo.toml --replace-fail '"dfkit", ' ""
  '';

  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [ "-p" "dflive" ];
  cargoTestFlags = [ "-p" "dflive" "-p" "dfstream" ];

  meta = with lib; {
    description = "Companion for running systems: authenticated, encrypted streams to dfnix (dfstream/1)";
    homepage = "https://github.com/tylerstyle/dflive";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dflive";
    platforms = platforms.unix ++ platforms.windows;
  };
}
