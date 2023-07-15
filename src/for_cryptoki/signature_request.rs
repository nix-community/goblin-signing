use std::marker::PhantomData;
use std::fmt::Debug;

use cryptoki::{session::Session, mechanism::Mechanism};
use signature::{Signer, Keypair};
use crate::for_cryptoki::keypair::DerivedKeypair;

#[derive(Debug)]
pub struct SignatureRequest<'sess, Signature> {
    pub(crate) mechanism: Mechanism,
    keypair: DerivedKeypair,
    session: &'sess Session,
    _signature: PhantomData<Signature>
}

impl<'sess, Signature> SignatureRequest<'sess, Signature> {
    pub fn new(mechanism: Mechanism, keypair: DerivedKeypair, session: &'sess Session) -> Self {
        SignatureRequest {
            mechanism,
            keypair,
            session,
            _signature: PhantomData
        }
    }
}

impl<'sess, Signature> Keypair for SignatureRequest<'sess, Signature> {
    // TODO: keep it sync with DerivedKeypair::VerifyingKey
    type VerifyingKey = DerivedKeypair;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.keypair.clone()
    }
}

impl<'sess, Signature> Signer<Signature> for SignatureRequest<'sess, Signature> 
where
    Signature: for<'a> TryFrom<&'a [u8]>,
    for<'a> <Signature as TryFrom<&'a [u8]>>::Error: Debug
{
    fn try_sign(&self, msg: &[u8]) -> core::result::Result<Signature, signature::Error> {
        let raw_data = self.session
            .sign(&self.mechanism, self.keypair.private_key_handle, msg)
            .map_err(signature::Error::from_source)?;

        Ok(raw_data.as_slice().try_into().unwrap())
    }
}

