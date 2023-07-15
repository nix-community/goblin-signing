use cryptoki::object::Attribute;
use cryptoki::object::AttributeType;
use cryptoki::object::KeyType;
use cryptoki::session::Session;
use rsa::BigUint;
use rsa::RsaPublicKey;
use spki::EncodePublicKey;

/// A keypair derived from
/// PKCS#11 attributes of the private key
#[derive(Clone, Debug)]
pub struct DerivedKeypair {
    /// Pre-encoded SPKI of the public key
    public_key: spki::Document,
    /// Private key handle in some session
    pub private_key_handle: cryptoki::object::ObjectHandle
}

impl DerivedKeypair {
    pub fn new(private_key_handle: cryptoki::object::ObjectHandle, kt: cryptoki::object::KeyType, private_key_attributes: Vec<cryptoki::object::Attribute>) -> Result<Self, String> {
        Ok(DerivedKeypair {
            private_key_handle,
            public_key: derive_public_key_from_private_key_data(kt, private_key_attributes)?.to_public_key_der().unwrap()
        })
    }

    pub fn from_session(private_key_handle: cryptoki::object::ObjectHandle, session: &Session) -> Result<Self, String> {
        let pkey_attrs = session.get_attributes(private_key_handle, &vec![
            AttributeType::KeyType,
            AttributeType::EcPoint,
            AttributeType::EcParams,
            AttributeType::PublicExponent,
            AttributeType::Modulus
        ]).unwrap();

        let mut key_type: Option<KeyType> = None;
        for attr in pkey_attrs {
            if let Attribute::KeyType(kt) = attr {
                key_type = Some(kt);
            }
        }

        Self::new(private_key_handle, key_type.unwrap(), pkey_attrs)
    }
}

fn derive_public_key_from_private_key_data(kt: cryptoki::object::KeyType, attributes: Vec<cryptoki::object::Attribute>) -> Result<impl EncodePublicKey, String> {
    use cryptoki::object::{Attribute, KeyType};

    match kt {
        KeyType::RSA => {
            let modulus: BigUint = BigUint::from_bytes_le(&attributes.iter().find_map(|attr| match attr {
                Attribute::Modulus(modulus) => Some(modulus),
                _ => None
            }).ok_or("No modulus in RSA key")?);
            let p_exponent: BigUint = BigUint::from_bytes_le(&attributes.iter().find_map(|attr| match attr {
                Attribute::PublicExponent(p_exponent) => Some(p_exponent),
                _ => None
            }).ok_or("No public exponent in RSA key")?);

            // Build an RsaPublicKey from modulus, p_exponent
            Ok(RsaPublicKey::new(modulus, p_exponent).unwrap())
        },
        KeyType::EC => {
            let ec_point: &Vec<u8> = attributes.iter().find_map(|attr| match attr {
                Attribute::EcPoint(point) => Some(point),
                _ => None
            }).ok_or("No EC point in EC key")?;
            let ec_params: &Vec<u8> = attributes.iter().find_map(|attr| match attr {
                Attribute::EcParams(params) => Some(params),
                _ => None
            }).ok_or("No EC params in EC key")?;

            // Find the associated curve to the `ec_params`
            // Verify if the point is on the curve.
            // TODO: figure out what needs to be checked mathematically.
            // Convert ec_point to an AffinePoint on the associated curve.
            // Instantiate a PublicKey from that affine point.
            todo!("lord")
        },
        _ => todo!("implement other schemes yourself please")
    }
}

