{
  description = "dflive: companion for running systems; dfstream/1 authenticated streams to dfnix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Shared safety core (sibling Cargo path dependency `../../dfcore` for `dfkit`)
    dfcore = {
      url = "github:tylerstyle/dfcore";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, dfcore }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dflive = pkgs.callPackage ./package.nix { };
        dfkit = pkgs.callPackage ./dfkit/package.nix { dfcoreSrc = dfcore; };
      in
      {
        packages = {
          default = dflive;
          dflive = dflive;
          dfkit = dfkit;
        } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # The field kit's binaries
          dflive-static = pkgs.pkgsStatic.callPackage ./package.nix { };
          dflive-aarch64-static = pkgs.pkgsCross.aarch64-multiplatform-musl.pkgsStatic.callPackage ./package.nix { };
          dflive-windows = pkgs.pkgsCross.mingw-msvcrt-x86_64.callPackage ./package.nix { };
        };

        checks = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          live = import ./tests/live.nix { inherit pkgs dflive; };
          wine = import ./tests/wine.nix {
            inherit pkgs;
            dflive = self.packages.${system}.dflive-windows;
          };
          dfkit = import ./tests/dfkit.nix {
            inherit pkgs dfkit;
          };
        };

        apps = {
          default = flake-utils.lib.mkApp { drv = dflive; };
          dflive = flake-utils.lib.mkApp { drv = dflive; };
          dfkit = flake-utils.lib.mkApp { drv = dfkit; };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dflive ];
          buildInputs = with pkgs; [ rustc cargo rustfmt clippy ];
        };
      }
    );
}
