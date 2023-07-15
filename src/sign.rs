use std::borrow::Cow;

use cms::{builder::{SignerInfoBuilder, SignedDataBuilder}, signed_data::{SignedData, SignerInfo, SignerIdentifier}, content_info::ContentInfo};
use der::Encode;
use digest::Digest;
use signature::{Keypair, Signer};
use x509_cert::{Certificate, spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding, AlgorithmIdentifierOwned}};
use x509_cert::der::Result;
use goblin::pe::{PE, certificate_table::AttributeCertificate};

use crate::{authenticode::Authenticode, certificate::DigestInfo};

fn from_signed_data<'a>(sdata: ContentInfo) -> Result<AttributeCertificate<'a>> {
    let certificate_bytes = sdata.to_der()?;

    Ok(AttributeCertificate {
        length: u32::try_from(certificate_bytes.len()).unwrap() + 0x32,
        revision: goblin::pe::certificate_table::AttributeCertificateRevision::Revision2_0,
        certificate_type: goblin::pe::certificate_table::AttributeCertificateType::PkcsSignedData,
        certificate: Cow::Owned(certificate_bytes)
    })
}

/// Resign the given binary
/// with the provided signer identifier and signer entity
pub fn resign<'pe, 's, D: Digest, S, Signature>(mut pe: PE<'pe>,
    sid: SignerIdentifier,
    signer: &'s S) -> Result<PE<'pe>>
where
    D: const_oid::AssociatedOid,
    S: Keypair + DynSignatureAlgorithmIdentifier,
    S::VerifyingKey: EncodePublicKey,
    S: Signer<Signature>,
    Signature: SignatureBitStringEncoding
{
    let authenticode = pe.authenticode_digest::<D>();
    let signature_content = DigestInfo::from_authenticode::<D>(authenticode)?
        .as_spc_indirect_data_content()
        .as_encapsulated_content_info()?;

    let signer_info = SignerInfoBuilder::new(signer, sid, signer.signature_algorithm_identifier().unwrap(), &signature_content, None).unwrap();
    let mut signed_data_builder = SignedDataBuilder::new(&signature_content);

    let signed_data = signed_data_builder
        .add_signer_info(signer_info).unwrap()
        .build().unwrap();

    // Clear all signatures, add the new one.
    pe.certificates.clear();
    pe.certificates.push(from_signed_data(signed_data)?);

    Ok(pe)
}
