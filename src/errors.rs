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
