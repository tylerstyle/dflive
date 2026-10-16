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
