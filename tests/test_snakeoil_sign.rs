/// We test various ways to manipulate PE binaries w.r.t. to signatures
/// with a snakeoil certificate and signer.
use std::str::FromStr;
use std::time::Duration;

use cms::cert::IssuerAndSerialNumber;
use digest::Digest;
use goblin::pe::PE;
use goblin_signing::authenticode::Authenticode;
use goblin_signing::sign::create_certificate;
use goblin_signing::verify::{certificates_from_pe, verify_pe_signatures_no_trust};
use ifrit::writer::PEWriter;
use p256::ecdsa::SigningKey;
use sha2::Sha256;
use signature::rand_core::OsRng;
use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::name::{Name, RdnSequence};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Certificate;

fn build_issuer(rdn: &str, serial: u32) -> der::Result<cms::signed_data::SignerIdentifier> {
    Ok(cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
        IssuerAndSerialNumber {
            issuer: RdnSequence::from_str(rdn)?,
            serial_number: serial.into(),
        },
    ))
}

fn build_certificate(subject: &str, serial: u32, signer: &SigningKey) -> Certificate {
    let profile = x509_cert::builder::Profile::Root;
    let serial_number = SerialNumber::from(serial);
    let validity =
        Validity::from_now(Duration::new(5, 0)).expect("Failed to build a validity from now on");
    let subject = Name::from_str(subject).expect("Failed to build the subject");
    let pub_key = SubjectPublicKeyInfoOwned::try_from(
        signer
            .verifying_key()
            .to_public_key_der()
            .expect("Failed to transform the verifying key into a DER")
            .as_bytes(),
    )
    .unwrap();

    CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, signer)
        .expect("Failed to prepare a certificate")
        .build::<ecdsa::der::Signature<_>>()
        .expect("Failed to build a certificate")
}

#[test]
fn test_create_attribute_certificate() {
    let file = std::fs::read("tests/bins/nixos-uki.efi").unwrap();
    let pe = PE::parse(&file[..]).unwrap();
    let signing_key = SigningKey::random(&mut OsRng);
    let sid = build_issuer("CN=test", 1).expect("Failed to build a trivial issuer");
    let certificate = build_certificate("CN=test", 1, &signing_key);
    let _ = create_certificate::<Sha256, _, ecdsa::der::Signature<_>>(
        &pe,
        vec![certificate],
        sid,
        &signing_key,
    )
    .expect("Failed to build an attribute certificate");
}

#[test]
fn test_attaching_attribute_certificate_to_pe() {
    let file = std::fs::read("tests/bins/nixos-uki.efi").unwrap();
    let pe = PE::parse(&file[..]).unwrap();
    println!("PE original certificates: {:?}", certificates_from_pe(&pe));
    let original_cert = pe
        .certificates
        .first()
        .expect("Original PE does not have a certificate!")
        .clone();
    let signing_key = SigningKey::random(&mut OsRng);
    let sid = build_issuer("CN=test", 1).expect("Failed to build a trivial issuer");
    let certificate = build_certificate("CN=test", 1, &signing_key);
    let mut pe_writer = PEWriter::new(pe).expect("Failed to create a PE writer");
    let pending_pe = pe_writer
        .write_into()
        .expect("Failed to write an unsigned PE");
    std::fs::write("/tmp/pending.pe", &pending_pe[..])
        .expect("Failed to dump the unsigned PE temporarily");
    let pending_pe = PE::parse(&pending_pe[..]).expect("Failed to parse the unsigned PE");
    println!(
        "Pending PE digest: {:?}",
        pending_pe.authenticode_dyndigest(Box::new(sha2::Sha256::new()))
    );
    let attr_cert = create_certificate::<Sha256, _, ecdsa::der::Signature<_>>(
        &pending_pe,
        vec![certificate],
        sid,
        &signing_key,
    )
    .expect("Failed to build an attribute certificate");
    pe_writer
        .attach_certificates(vec![attr_cert.attribute()])
        .expect("Failed to attach a certificate to PE");
    let new_pe_bytes = pe_writer
        .write_into()
        .expect("Failed to write the new PE with new certificate");
    std::fs::write("/tmp/signed.pe", &new_pe_bytes[..])
        .expect("Failed to dump the signed PE temporarily");
    let new_pe = PE::parse(&new_pe_bytes[..]).expect("Failed to read the new PE");
    assert_eq!(new_pe.certificates.len(), 1);
    let cert = new_pe.certificates.first().unwrap();
    assert!(
        cert.certificate == attr_cert.attribute().certificate,
        "Attribute certificate is different from expected!"
    );
    assert!(
        original_cert.certificate != cert.certificate,
        "Attribute certificate is same as original!"
    );
    println!("PE new certificates: {:?}", certificates_from_pe(&new_pe));
    println!(
        "New PE digest: {:?}",
        new_pe.authenticode_dyndigest(Box::new(sha2::Sha256::new()))
    );
    assert!(
        verify_pe_signatures_no_trust(&new_pe).unwrap().0,
        "PE signatures are not verified, wrong authenticode or wrong algorithm for the digest?"
    );
}

#[test]
fn test_multisig_pe() {
    let file = std::fs::read("tests/bins/nixos-uki.efi").unwrap();
    let pe = PE::parse(&file[..]).unwrap();
    let original_cert = pe
        .certificates
        .first()
        .expect("Original PE does not have a certificate!")
        .clone();
    let signing_key = SigningKey::random(&mut OsRng);
    let sid = build_issuer("CN=test", 1).expect("Failed to build a trivial issuer");
    let certificate = build_certificate("CN=test", 1, &signing_key);
    let mut pe_writer = PEWriter::new(pe).expect("Failed to create a PE writer");
    let pending_pe = pe_writer
        .write_into()
        .expect("Failed to write an unsigned PE");
    let pending_pe = PE::parse(&pending_pe[..]).expect("Failed to parse the unsigned PE");
    let attr_cert = create_certificate::<Sha256, _, ecdsa::der::Signature<_>>(
        &pending_pe,
        vec![certificate],
        sid,
        &signing_key,
    )
    .expect("Failed to build an attribute certificate");
    pe_writer
        .attach_certificates(vec![original_cert, attr_cert.attribute()])
        .expect("Failed to attach a certificate to PE");
    let new_pe_bytes = pe_writer
        .write_into()
        .expect("Failed to write the new PE with new certificate");
    let new_pe = PE::parse(&new_pe_bytes[..]).expect("Failed to read the new PE");
    assert_eq!(new_pe.certificates.len(), 2);
    assert!(verify_pe_signatures_no_trust(&new_pe).unwrap().0, "Even if the PE contains an old invalid signature, it should contain a new valid signature.");
}
