//! # Goblin signing
//!
//! Goblin signing is intended to be a support library for goblin to help with the signature of
//! executable.

use authenticode::Authenticode;
use certificate::AttributeCertificateExt;
use digest::Digest;
use goblin::pe::PE;
use x509_cert::Certificate;
pub mod authenticode;
pub mod certificate;

pub fn sign(pe: PE, certificate: Certificate) -> PE {
    pe
}

// Verify that PE's Authenticode
// match the one provided in the signatures.
// pub fn verify_authenticode_in_signatures<D: Digest>(pe: PE) -> bool {
//     let pe_authenticode_digest = pe.authenticode_digest::<D>();
//     // TODO: filter out correctly the digest by D
//     pe.certificates
//         .into_iter()
//         .all(|cert| {
//             match cert.as_digest_info() {
//                 Some(Ok(digest_info)) => digest_info.digest.as_bytes().into_iter().zip(pe_authenticode_digest).all(|(a, b): (&u8, u8)| *a == b),
//                 Some(_) => false,
//                 None => false
//             }
//         })
// }
