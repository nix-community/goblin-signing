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
  shell = pkgs.mkShell rec {
    buildInputs = [
      pkgs.cargo
      pkgs.rustc
      pkgs.softhsm
    ];

    PKCS11_SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
    DEFAULT_TOKEN_URI = "pkcs11:token=GoblinSigningTest;slot-id=360816258?module-path=${PKCS11_SOFTHSM2_MODULE}&pin-value=fedcba";
    shellHook = ''
      export SOFTHSM2_CONF="${hsmConfiguration}"
    '';
  };
}
