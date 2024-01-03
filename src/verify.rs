use std::collections::HashMap;

use crate::authenticode::Authenticode;
use crate::certificate::{AttributeCertificateExt, DigestInfo};
use crate::errors::VerificationError;
use cms::signed_data::SignedData;
use const_oid::db::DB;
use digest::{Digest, DynDigest};
use goblin::pe::PE;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_verify::VerifyingKey;

/// Policies to use when verifying the signatures of a PE.
/// e.g. which certificates are trusted.
pub struct VerificationOptions {
    /// Trusted certificates set, if None, there's no trust verification performed.
    pub trust_store: Option<Vec<Certificate>>,
}

/// Returns a couple of signed data and digest information
/// contained in the PE.
/// Anything that is malformed is skipped.
pub fn certificates_from_pe(pe: &PE) -> Vec<(SignedData, DigestInfo)> {
    pe.certificates
        .iter()
        .filter_map(|(_, cert)| {
            match (cert.as_signed_data(), cert.as_spc_indirect_data_content()) {
                (Some(Ok(sdata)), Some(Ok(spc))) => Some((sdata, spc.message_digest)),
                _ => None,
            }
        })
        .collect()
}

/// Get a hasher for a given digest algorithm
/// Stolen from RustCrypto/formats cms crate.
pub(crate) fn get_hasher(
    digest_algorithm_identifier: &AlgorithmIdentifierOwned,
) -> Option<Box<dyn DynDigest>> {
    let digest_name = DB.by_oid(&digest_algorithm_identifier.oid)?;
    match digest_name {
        "id-sha256" => Some(Box::new(sha2::Sha256::new())),
        "id-sha384" => Some(Box::new(sha2::Sha384::new())),
        "id-sha512" => Some(Box::new(sha2::Sha512::new())),
        "id-sha224" => Some(Box::new(sha2::Sha224::new())),
        _ => None,
    }
}

/// Perform verification of PE signatures with the provided `options`
/// e.g. with a specific trust store, ignoring timestamps, etc.
/// In case of fatal error, this will return an Err.
/// In case of non-fatal errors, this will return an boolean
///     if true, it means that validation passed under current policy.
///     if false, it means that validation failed under current policy.
/// *Almost* all potential source of errors are included in the second element of tuple, even if it
/// passed. There's no guarantee this function will find *all* source of errors, some code paths
/// could early return to show a more "important" error before getting to the next error.
pub fn verify_pe_signatures(
    pe: &PE,
    options: VerificationOptions,
) -> Result<(bool, Vec<VerificationError>), VerificationError> {
    let certificates = certificates_from_pe(pe);
    let mut hashes = HashMap::new();
    let mut verified = 0;
    let mut errors = Vec::new();

    if certificates.is_empty() {
        return Err(VerificationError::NoCertificate);
    }

    for (sdata, message_digest) in certificates {
        if let Some(hasher) = get_hasher(&message_digest.digest_algorithm) {
            let authenticode = hashes
                .entry(message_digest.digest_algorithm.oid)
                .or_insert(pe.authenticode_dyndigest(hasher));

            if sdata.certificates.is_none() {
                errors.push(VerificationError::MissingCertificate(sdata.signer_infos));
            }

            let valid_authenticode = message_digest.digest.as_bytes() == &authenticode[..];

            if !valid_authenticode {
                errors.push(VerificationError::InvalidAuthenticode(
                    sdata.certificates.clone(),
                    format!("{:x?}", authenticode),
                    format!("{:x?}", message_digest.digest.as_bytes()),
                ));
            }

            // Verify if any of the certificate is valid among a set of trusted certificates.
            // If there is no trusted certificates in the trust store, we skip this test.
            let trusted_certificates = match options.trust_store {
                Some(ref trusted_certs) => trusted_certs.iter().map(|trusted_cert|
                    VerifyingKey::try_from(trusted_cert)
                ).collect::<Result<Vec<_>, _>>().expect("Failed to transform a trusted certificate into a verifying key; unsupported certificate?"),
                None => Vec::new()
            };
            let mut any_valid_certificate = trusted_certificates.is_empty();
            for certificate in sdata.certificates.map(|certs| certs.0.into_vec()).unwrap() {
                match certificate {
                    cms::cert::CertificateChoices::Certificate(certificate) => {
                        let mut untrusted_certificate = true;
                        for trusted_certificate in &trusted_certificates {
                            if trusted_certificate.verify(&certificate).is_ok() {
                                untrusted_certificate = false;
                            }
                        }

                        any_valid_certificate = any_valid_certificate || !untrusted_certificate;
                        if !untrusted_certificate {
                            errors.push(VerificationError::UntrustedCertificate(certificate));
                        }
                    }
                    cms::cert::CertificateChoices::Other(_other) => {
                        todo!("Certificate choice of type 'Other' is unsupported")
                    }
                }
            }

            // TODO: verify timestamps.
            if any_valid_certificate && valid_authenticode {
                verified += 1;
            }
        }
    }

    if verified == 0 {
        Ok((false, errors))
    } else {
        Ok((true, errors))
    }
}

/// Perform verification of the PE signatures while trusting any certificate.
/// Useful when you do not care about verifying that a certificate which signed the PE
/// has been signed by a certificate you trust.
pub fn verify_pe_signatures_no_trust(
    pe: &PE,
) -> Result<(bool, Vec<VerificationError>), VerificationError> {
    verify_pe_signatures(pe, VerificationOptions { trust_store: None })
}
