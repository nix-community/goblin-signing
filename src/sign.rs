use std::result::Result;

use cms::{builder::{SignerInfoBuilder, SignedDataBuilder}, signed_data::SignerIdentifier, content_info::ContentInfo};
use der::Encode;
use digest::Digest;
use signature::{Keypair, Signer};
use x509_cert::{spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding}, builder::Builder, Certificate};
use goblin::pe::{PE, certificate_table::AttributeCertificate};

use crate::{authenticode::Authenticode, certificate::DigestInfo};
use crate::errors::SignatureError;

/// Produces a certificate for the given PE
/// with the given signer identifier and signer.
pub fn create_certificate<'pe, 's, D: Digest, S, Signature>(pe: &PE<'pe>,
    certificate: Certificate,
    sid: SignerIdentifier,
    signer: &'s S) -> Result<AttributeCertificate<'pe>, SignatureError>
where
    D: const_oid::AssociatedOid,
    S: Keypair + DynSignatureAlgorithmIdentifier,
    S::VerifyingKey: EncodePublicKey,
    S: Signer<Signature>,
    Signature: SignatureBitStringEncoding
{
    let authenticode = pe.authenticode_digest::<D>();
    let digest_info = DigestInfo::from_authenticode::<D>(authenticode)?;
    let digest_algorithm = digest_info.digest_algorithm.clone();
    let signature_content = digest_info
        .as_spc_indirect_data_content()
        .as_encapsulated_content_info()
        .map_err(SignatureError::AuthenticodeEncodeFailure)?;

    let mut signed_data_builder = SignedDataBuilder::new(&signature_content);
    let signer_info = SignerInfoBuilder::new(signer, sid,
        digest_algorithm.clone(),
        &signature_content, None)
    // The construction never fails…
        .unwrap();

    let signed_data_builder = signed_data_builder
        .add_signer_info(signer_info)
        .unwrap()
        .add_digest_algorithm(digest_algorithm)
        .unwrap()
        .add_certificate(cms::cert::CertificateChoices::Certificate(certificate))
        .unwrap();

    let signed_data = signed_data_builder.build().unwrap();
    let mut certificate_contents = Vec::new();
    signed_data.encode_to_vec(&mut certificate_contents)?;

    Ok(AttributeCertificate::from_bytes(certificate_contents.into(),
        goblin::pe::certificate_table::AttributeCertificateRevision::Revision2_0,
        goblin::pe::certificate_table::AttributeCertificateType::PkcsSignedData
    ))
}
