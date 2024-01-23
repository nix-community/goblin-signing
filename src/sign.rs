use std::result::Result;

use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    signed_data::SignerIdentifier,
};
use der::Encode;
use digest::Digest;
use goblin::pe::{
    certificate_table::{
        AttributeCertificate, AttributeCertificateRevision, AttributeCertificateType,
    },
    PE,
};
use signature::{Keypair, Signer};
use x509_cert::{
    spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding},
    Certificate,
};

use crate::errors::SignatureError;
use crate::{authenticode::Authenticode, certificate::DigestInfo};

/// Because [`AttributeCertificate`] is a purely borrowing a structure,
/// we cannot return it naked, we need to own the raw certificate data somewhere.
#[derive(Debug, Clone)]
pub struct CertificateBundle {
    certificate_raw: Vec<u8>,
    attribute_revision: AttributeCertificateRevision,
    attribute_type: AttributeCertificateType,
}

impl CertificateBundle {
    pub fn new(
        raw: Vec<u8>,
        attribute_revision: AttributeCertificateRevision,
        attribute_type: AttributeCertificateType,
    ) -> Self {
        Self {
            certificate_raw: raw,
            attribute_revision,
            attribute_type,
        }
    }

    pub fn attribute(&self) -> AttributeCertificate {
        AttributeCertificate::from_bytes(
            &self.certificate_raw,
            self.attribute_revision,
            self.attribute_type,
        )
    }
}

/// Produces a certificate for the given PE
/// with the given signer identifier and signer.
pub fn create_certificate<'pe, D: Digest, S, Signature>(
    pe: &PE<'pe>,
    certificates: Vec<Certificate>,
    sid: SignerIdentifier,
    signer: &S,
) -> Result<CertificateBundle, SignatureError>
where
    D: const_oid::AssociatedOid,
    S: Keypair + DynSignatureAlgorithmIdentifier,
    S::VerifyingKey: EncodePublicKey,
    S: Signer<Signature>,
    Signature: SignatureBitStringEncoding,
{
    let authenticode = pe.authenticode_digest::<D>();
    let digest_info = DigestInfo::from_authenticode::<D>(authenticode)?;
    let digest_algorithm = digest_info.digest_algorithm.clone();
    let signature_content = digest_info
        .as_spc_indirect_data_content()
        .as_encapsulated_content_info()
        .map_err(SignatureError::AuthenticodeEncodeFailure)?;

    let mut signed_data_builder = SignedDataBuilder::new(&signature_content);
    let signer_info = SignerInfoBuilder::new(
        signer,
        sid,
        digest_algorithm.clone(),
        &signature_content,
        None,
    )
    // The construction never fails…
    .unwrap();

    let mut signed_data_builder = signed_data_builder
        .add_signer_info(signer_info)
        .unwrap()
        .add_digest_algorithm(digest_algorithm)
        .unwrap();

    for certificate in certificates {
        signed_data_builder = signed_data_builder
            .add_certificate(cms::cert::CertificateChoices::Certificate(certificate))
            .unwrap();
    }

    let signed_data = signed_data_builder.build().unwrap();
    let mut certificate_contents = Vec::new();
    signed_data.encode_to_vec(&mut certificate_contents)?;

    Ok(CertificateBundle::new(
        certificate_contents,
        goblin::pe::certificate_table::AttributeCertificateRevision::Revision2_0,
        goblin::pe::certificate_table::AttributeCertificateType::PkcsSignedData,
    ))
}
