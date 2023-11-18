use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
use cryptoki::mechanism::Mechanism;

use spki::DynSignatureAlgorithmIdentifier;

use super::signature_request::SignatureRequest;

impl<'sess, Signature> DynSignatureAlgorithmIdentifier for SignatureRequest<'sess, Signature> {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        match self.mechanism {
            Mechanism::Sha256RsaPkcs => {
                Ok(spki::AlgorithmIdentifier {
                    oid: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: None
                })
            },
            _ => todo!("please")
        }
    }
}
