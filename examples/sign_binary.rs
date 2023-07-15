use std::str::FromStr;

use cms::cert::IssuerAndSerialNumber;
use cryptoki::{context::{Pkcs11, CInitializeArgs}, mechanism::{MechanismType, Mechanism, rsa::{PkcsPssParams, PkcsMgfType}}, object::{AttributeType, Attribute}};
/// Demonstrates how to sign a PE binary.
use goblin::pe::PE;
use goblin_signing::{certificate::AttributeCertificateExt, sign::resign, for_cryptoki::{signature_request::SignatureRequest, keypair::DerivedKeypair}};
use sha2::{Sha256, OidSha256};
use x509_cert::name::RdnSequence;

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

    let mechanism = Mechanism::RsaPkcsPss(PkcsPssParams { hash_alg: MechanismType::SHA256, mgf: PkcsMgfType::MGF1_SHA256, s_len: 0x0.into() });
    let (public_key, private_key) = session.generate_key_pair(
        &mechanism,
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

    let signer = SignatureRequest::<'_, rsa::pss::Signature>::new(
        mechanism,
        DerivedKeypair::from_session(private_key, &session).unwrap(),
        &session
    );

    // TODO: assert public_key is the one we expect.

    resign::<Sha256, _, _>(pe,
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
            IssuerAndSerialNumber {
                issuer: RdnSequence::from_str("test").unwrap(),
                serial_number: 1_u32.into()
            }
        ), &signer);
}
