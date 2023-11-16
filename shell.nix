{
  tinypkgs ? import (fetchTarball {
    url = "https://gitlab.inria.fr/nix-tutorial/packages-repository/-/archive/master/packages-repository-8e43243635cd8f28c7213205b08c12f2ca2ac74d.tar.gz";
    sha256 = "sha256:09l2w3m1z0308zc476ci0bsz5amm536hj1n9xzpwcjm59jxkqpqa";
  }) {}
}:

with tinypkgs; # Put tinypkgs's attributes in the current scope.
with pkgs; # Same for pkgs.

mkShell {
  buildInputs = [
    chord
    bitcoind

    # Defines a python + set of packages.
    (python3.withPackages (ps: with ps; with python3Packages; [
      jupyter
      ipython
      coincurve

      # Uncomment the following lines to make them available in the shell.
      # pandas
      # numpy
      # matplotlib
    ]))
  ];

  # Automatically run jupyter when entering the shell.
  #shellHook = "jupyter notebook";
}
