use cryptoki::{session::Session, mechanism::Mechanism};
use signature::{Signer, Keypair};
use crate::for_cryptoki::keypair::DerivedKeypair;

#[derive(Debug)]
pub struct SignatureRequest<'sess> {
    pub(crate) mechanism: Mechanism,
    keypair: DerivedKeypair,
    session: &'sess Session
}

impl<'sess> SignatureRequest<'sess> {
    pub fn new(mechanism: Mechanism, keypair: DerivedKeypair, session: &'sess Session) -> Self {
        SignatureRequest {
            mechanism,
            keypair,
            session
        }
    }
}

impl<'sess> Keypair for SignatureRequest<'sess> {
    // TODO: keep it sync with DerivedKeypair::VerifyingKey
    type VerifyingKey = DerivedKeypair;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.keypair
    }
}

impl<'sess> Signer<Vec<u8>> for SignatureRequest<'sess> {
    fn try_sign(&self, msg: &[u8]) -> core::result::Result<Vec<u8>, signature::Error> {
        self.session.sign(&self.mechanism, self.keypair.private_key_handle, msg).map_err(signature::Error::from_source)
    }
}

