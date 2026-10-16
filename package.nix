{ lib
, rustPlatform
}:

rustPlatform.buildRustPackage {
  pname = "dflive";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target";
    src = lib.cleanSource ./.;
  };

  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [ "-p" "dflive" ];
  cargoTestFlags = [ "--workspace" ];

  meta = with lib; {
    description = "Companion for running systems: authenticated, encrypted streams to dfnix (dfstream/1)";
    homepage = "https://github.com/tylerstyle/dflive";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dflive";
    platforms = platforms.unix ++ platforms.windows;
  };
}
