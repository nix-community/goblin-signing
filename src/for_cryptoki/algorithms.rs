use const_oid::db::rfc5912::{ID_RSASSA_PSS, ID_MGF_1, ID_SHA_1, ID_SHA_256};
use cryptoki::mechanism::{Mechanism, rsa::PkcsMgfType, MechanismType};
use der::{asn1::Int, Sequence};
use spki::{DynSignatureAlgorithmIdentifier, AlgorithmIdentifier};

use super::signature_request::SignatureRequest;

fn default_salt_length() -> Int {
    Int::new(&0x20_usize.to_le_bytes()).unwrap()
}

fn default_trailer_field() -> Int {
    Int::new(&0x1_usize.to_le_bytes()).unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct RsaSsaPssParams {
    // omit it when it's sha-1
    hash_algorithm: Option<AlgorithmIdentifier<()>>,
    // mask gen is ( id-mgf1, $hashAlgorithm ).
    mask_gen_algorithm: Option<AlgorithmIdentifier<AlgorithmIdentifier<()>>>,
    #[asn1(default = "default_salt_length")]
    salt_length: Int,
    #[asn1(default = "default_trailer_field")]
    trailer_field: Int
}

fn mgf_to_asn1(mgf: PkcsMgfType) -> AlgorithmIdentifier<AlgorithmIdentifier<()>> {
    AlgorithmIdentifier {
        oid: ID_MGF_1,
        parameters: Some(match mgf {
            PkcsMgfType::MGF1_SHA1 => AlgorithmIdentifier { oid: ID_SHA_1, parameters: None },
            PkcsMgfType::MGF1_SHA256 => AlgorithmIdentifier { oid: ID_SHA_256, parameters: None },
            _ => todo!("please do it")
        })
    }
}

fn hash_alg_to_asn1(hash_alg: MechanismType) -> spki::Result<AlgorithmIdentifier<()>> {
    Ok(AlgorithmIdentifier {
        oid: match hash_alg {
            MechanismType::SHA1 | MechanismType::SHA1_RSA_PKCS_PSS => ID_SHA_1,
            MechanismType::SHA256 | MechanismType::SHA256_RSA_PKCS_PSS => ID_SHA_256,
            _ => return Err(spki::Error::AlgorithmParametersMissing),
        },
        parameters: None
    })
}

impl<'sess> DynSignatureAlgorithmIdentifier for SignatureRequest<'sess> {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        match self.mechanism {
            Mechanism::RsaPkcsPss(params) => {
                Ok(spki::AlgorithmIdentifier {
                    oid: ID_RSASSA_PSS,
                    parameters: Some(RsaSsaPssParams {
                        hash_algorithm: Some(hash_alg_to_asn1(params.hash_alg)?),
                        mask_gen_algorithm: Some(mgf_to_asn1(params.mgf)),
                        salt_length: Int::new(&usize::from(params.s_len).to_be_bytes())?,
                        trailer_field: Int::new(&0x1_usize.to_be_bytes())?
                    }.into())
                })
            },
            _ => todo!("please")
        }
    }
}
