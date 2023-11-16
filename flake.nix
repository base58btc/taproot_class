{
  description = "Base58 Lightning Network Class";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            jq
            bitcoind
            clightning

            (python3.withPackages (ps: with ps; with python3Packages; [
              jupyter
              ipython
              coincurve
            ]))
          ];
          # Automatically run jupyter when entering the shell.
          #shellHook = "jupyter notebook";

          # env vars
          PATH_TO_BITCOIN = "${pkgs.bitcoind}/bin/bitcoind";
          PATH_TO_LIGHTNING = "${pkgs.clightning}/bin/lightningd";
        };
      });
}
