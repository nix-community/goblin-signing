/// Demonstrates how to sign a PE binary.
use goblin::pe::PE;
use goblin_signing::certificate::AttributeCertificateExt;

fn main() {
    let file = include_bytes!("../tests/bins/nixos-uki.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();
    println!("{:#?}", pe.certificates.first().unwrap().as_signed_data().unwrap().unwrap());
}
