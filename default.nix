{ pkgs ? import <nixpkgs> {} }: 
let
  hsmConfiguration = pkgs.writeTextFile { name = "hsm.conf";
  text = ''
    directories.tokendir = ${builtins.toString ./.}/hsmstate/tokens/
    objectstore.backend = file
    log.level = INFO
    slots.mechanisms = ALL
    '';
  };
in
{
  shell = pkgs.mkShell {
    buildInputs = [
      pkgs.cargo
      pkgs.rustc
      pkgs.softhsm
    ];

    PKCS11_SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
    shellHook = ''
      export SOFTHSM2_CONF="${hsmConfiguration}"
    '';
  };
}
