{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.rustup
  ];

  shellHook = ''
    rustup default stable
  '';
}
