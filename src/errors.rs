use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Failed to encode authenticode signature as an encapsulated content info")]
    AuthenticodeEncodeFailure(#[from] x509_cert::der::Error),
    #[error("Failed to determine the signature's algorithm identifier")]
    UnknownSignatureAlgorithmIdentifier(#[from] spki::Error),
    #[error("Failed to run the signer information through the signer")]
    SigningError(#[from] x509_cert::builder::Error),
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("No certificate was found")]
    NoCertificate,
    #[error("Missing certificate from a signed data information")]
    MissingCertificate(cms::signed_data::SignerInfos),
    #[error("Authenticode is not matching, expected: {1}, got: {2}")]
    InvalidAuthenticode(Option<cms::signed_data::CertificateSet>, String, String),
    #[error("One of the certificate expired")]
    CertificateExpiration(Box<x509_cert::certificate::Certificate>),
    #[error("Untrusted certificate")]
    UntrustedCertificate(Box<x509_cert::certificate::Certificate>),
}
