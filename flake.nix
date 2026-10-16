{
  description = "dflive: companion for running systems; dfstream/1 authenticated streams to dfnix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dflive = pkgs.callPackage ./package.nix { };
      in
      {
        packages = {
          default = dflive;
          dflive = dflive;
        } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # The field kit's binaries
          dflive-static = pkgs.pkgsStatic.callPackage ./package.nix { };
          dflive-aarch64-static = pkgs.pkgsCross.aarch64-multiplatform-musl.pkgsStatic.callPackage ./package.nix { };
          dflive-windows = pkgs.pkgsCross.mingwW64.callPackage ./package.nix { };
        };

        checks = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          live = import ./tests/live.nix { inherit pkgs dflive; };
          wine = import ./tests/wine.nix {
            inherit pkgs;
            dflive = self.packages.${system}.dflive-windows;
          };
        };

        apps = {
          default = flake-utils.lib.mkApp { drv = dflive; };
          dflive = flake-utils.lib.mkApp { drv = dflive; };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dflive ];
          buildInputs = with pkgs; [ rustc cargo rustfmt clippy ];
        };
      }
    );
}
