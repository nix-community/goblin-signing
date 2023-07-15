{ pkgs ? import <nixpkgs> {} }: {
  shell = pkgs.mkShell {
    buildInputs = [
      pkgs.cargo
      pkgs.rustc
    ];

    PKCS11_SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
  };
}
