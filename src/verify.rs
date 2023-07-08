use crate::authenticode::Authenticode;
use crate::certificate::AttributeCertificateExt;
use digest::{Digest, DynDigest};
use goblin::pe::{PE, certificate_table::AttributeCertificate};
use x509_cert::spki::AlgorithmIdentifierOwned;


fn dyndigest_from_algo_identifier(algo: AlgorithmIdentifierOwned) -> Option<Box<dyn DynDigest>> {
    if algo.oid == const_oid::db::rfc5912::ID_SHA_256 {
        Some(Box::new(sha2::Sha256::new()))
    } else {
        None
    }
}

pub fn check_against_attribute_certificate(pe: &PE, certificate: &AttributeCertificate) -> bool {
    match certificate.as_spc_indirect_data_content() {
        Some(Ok(spc_data)) => {
            // derive dyndigest from digest_algorithm…
            if let Some(hasher) = dyndigest_from_algo_identifier(spc_data.message_digest.digest_algorithm) {
                let output = pe.authenticode_dyndigest(hasher);

                &output[..] == spc_data.message_digest.digest.as_bytes()
            } else {
                false
            }
        },
        Some(_) | None => false
    }
}

pub fn verify_pe_signatures(pe: &PE) -> bool {
    pe.certificates.iter().all(|cert| check_against_attribute_certificate(&pe, cert))
}
