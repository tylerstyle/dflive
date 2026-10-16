{ lib
, rustPlatform
, runCommand
, makeWrapper
, gptfdisk
, util-linux
, ntfs3g
, hfsprogs
, e2fsprogs
, exfatprogs
, udev
, dfcoreSrc ? ../../dfcore
}:

let
  clean = src: lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target";
    src = lib.cleanSource src;
  };
  # Lay out workspace and sibling dfcore so `path = "../../dfcore"` in dfkit/Cargo.toml resolves
  src = runCommand "dfkit-src" { } ''
    mkdir -p $out
    cp -r ${clean ./..} $out/dflive
    cp -r ${clean dfcoreSrc} $out/dfcore
    chmod -R u+w $out
  '';
  runtimePath = lib.makeBinPath [
    gptfdisk
    util-linux
    ntfs3g
    hfsprogs
    e2fsprogs
    exfatprogs
    udev
  ];
in
rustPlatform.buildRustPackage {
  pname = "dfkit";
  version = "0.1.0";

  inherit src;
  sourceRoot = "dfkit-src/dflive";

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];

  cargoBuildFlags = [ "-p" "dfkit" ];
  cargoTestFlags = [ "-p" "dfkit" ];

  postInstall = ''
    wrapProgram $out/bin/dfkit \
      --prefix PATH : "${runtimePath}"
  '';

  meta = with lib; {
    description = "Write and verify multi-partition forensic field-kit USB sticks on dfnix";
    homepage = "https://github.com/tylerstyle/dflive";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfkit";
    platforms = platforms.linux;
  };
}
