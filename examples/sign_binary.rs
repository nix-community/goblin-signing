use cms::cert::IssuerAndSerialNumber;
use cryptoki::{context::{Pkcs11, CInitializeArgs}, mechanism::MechanismType, object::{AttributeType, Attribute}};
/// Demonstrates how to sign a PE binary.
use goblin::pe::PE;
use goblin_signing::{certificate::AttributeCertificateExt, sign::resign, for_cryptoki::{signature_request::SignatureRequest, keypair::DerivedKeypair}};

fn main() {
    let file = include_bytes!("../tests/bins/nixos-uki.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();

    let mut pkcs11 = Pkcs11::new(
        std::env::var("PKCS11_SOFTHSM2_MODULE").unwrap()
    ).unwrap();

    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    println!("PKCS#11 initialized");

    // Take first slot
    let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

    println!("Obtained a security token, i.e. a slot");

    let session = pkcs11.open_rw_session(slot).unwrap();

    println!("Session opened in read-write");

    session.login(cryptoki::session::UserType::User, Some("fedcba"));

    println!("Logged in as a user");

    let (public_key, private_key) = session.generate_key_pair(
        MechanismType::RSA_PKCS,
        &[
            Attribute::Verify(true),
            Attribute::ModulusBits(2048)
        ],
        &[
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Subject("test@example.org"),
            Attribute::Id(100),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
        ]
    ).unwrap();

    println!("New key generated on the security token");

    let signer = SignatureRequest::new(
        MechanismType::ECC_KEY_PAIR_GEN,
        DerivedKeypair::from_session(private_key, &session),
        &session
    );

    // TODO: assert public_key is the one we expect.

    resign(pe,
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
            IssuerAndSerialNumber {
                issuer: "test",
                serial_number: 1
            }
        ), &signer)
}
