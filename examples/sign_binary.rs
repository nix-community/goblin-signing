use std::str::FromStr;

use cms::cert::IssuerAndSerialNumber;
use cryptoki::{context::{Pkcs11, CInitializeArgs}, mechanism::Mechanism, object::Attribute};
/// Demonstrates how to sign a PE binary.
use goblin::pe::{PE, writer::PEWriter};
use goblin_signing::{sign::create_certificate, pkcs11::{signature_request::SignatureRequest, keypair::DerivedKeypair}};
use sha2::Sha256;
use x509_cert::name::RdnSequence;

fn main() {
    let file = include_bytes!("../tests/bins/nixos-uki.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();

    println!("{:?}", pe.certificates.first().unwrap().1.certificate);

    let mut pkcs11 = Pkcs11::new(
        std::env::var("PKCS11_SOFTHSM2_MODULE").unwrap()
    ).unwrap();

    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    println!("PKCS#11 initialized");

    // Take first slot
    println!("Available tokens: {:#?}", pkcs11.get_slots_with_token().unwrap());
    let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

    println!("Obtained a security token, i.e. a slot: {:#?}", slot);

    let _ = pkcs11.init_token(slot, "fedcba", "my first token").unwrap();
    let session = pkcs11.open_rw_session(slot).unwrap();

    println!("Session opened in read-write");

    let _ = session.login(cryptoki::session::UserType::So, Some("fedcba")).unwrap();
    println!("Logged in as the security officer");

    let _ = session.init_pin("fedcba").unwrap();
    println!("Normal pin initialized");

    let _ = session.logout().unwrap();
    println!("Logged out from the security officer");

    let _ = session.login(cryptoki::session::UserType::User, Some("fedcba")).unwrap();
    println!("Logged in as a user");

    println!("Available mechanisms: {:#?}", pkcs11.get_mechanism_list(slot).unwrap().into_iter().map(|mech| mech.to_string()).collect::<Vec<_>>());

    let mechanism = Mechanism::Sha256RsaPkcs;
    let (_public_key, private_key) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &[
            Attribute::Verify(true),
            Attribute::ModulusBits(2048.into())
        ],
        &[
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Subject("test@example.org".into()),
            Attribute::Id("test".into()),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
        ]
    ).unwrap();

    println!("New key generated on the security token");

    let signer = SignatureRequest::<'_, ecdsa::der::Signature<p256::NistP256>>::new(
        mechanism,
        DerivedKeypair::from_session(private_key, &session).unwrap(),
        &session
    );

    // TODO: assert public_key is the one we expect.
    /*let certificate = create_certificate::<Sha256, _, _>(&pe,
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
            IssuerAndSerialNumber {
                issuer: RdnSequence::from_str("CN=test").unwrap(),
                serial_number: 1_u32.into()
            }
        ), &signer).unwrap();
    let pe_writer = PEWriter::new(pe).unwrap();
    println!("Signed!");*/
}
