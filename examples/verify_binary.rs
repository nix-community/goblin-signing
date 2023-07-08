/// Demonstrates how to sign a PE binary.
use goblin::pe::PE;
use goblin_signing::{certificate::AttributeCertificateExt, check_against_attribute_certificate};

fn main() {
    let file = include_bytes!("../tests/bins/nixos-uki.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();

    for certificate in pe.certificates.iter() {
        println!("verifying against PE a certificate...");
        println!("{:#?}", check_against_attribute_certificate(&pe, certificate));
    }

    let file = include_bytes!("../tests/bins/nixos-uki-tampered.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();

    for certificate in pe.certificates.iter() {
        println!("verifying against PE a certificate...");
        println!("{:#?}", check_against_attribute_certificate(&pe, certificate));
    }

}
