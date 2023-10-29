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

impl EncodePublicKey for DerivedKeypair {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        Ok(self.public_key.clone())
    }
}

// Ugly, but avoids E0038
enum SupportedPublicKey {
    ED25519,
    RSA(RsaPublicKey),
    NistP224(elliptic_curve::PublicKey<p224::NistP224>),
    NistP256(elliptic_curve::PublicKey<p256::NistP256>),
    NistP384(elliptic_curve::PublicKey<p384::NistP384>),
    // NistP521(elliptic_curve::PublicKey<p521::NistP521>),
}

impl DerivedKeypair {
    pub fn new(private_key_handle: cryptoki::object::ObjectHandle, kt: cryptoki::object::KeyType, private_key_attributes: Vec<cryptoki::object::Attribute>) -> Result<Self, String> {
        Ok(DerivedKeypair {
            private_key_handle,
            public_key: match derive_public_key_from_private_key_data(kt, private_key_attributes)? {
                // TODO Ryan's trick
                SupportedPublicKey::RSA(pk) => pk.to_public_key_der().unwrap(),
                SupportedPublicKey::NistP224(pk) => pk.to_public_key_der().unwrap(),
                SupportedPublicKey::NistP256(pk) => pk.to_public_key_der().unwrap(),
                SupportedPublicKey::NistP384(pk) => pk.to_public_key_der().unwrap(),
                // SupportedPublicKey::NistP521(pk) => pk.to_public_key_der().unwrap(),
                SupportedPublicKey::ED25519 => todo!(),
            }
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
        for attr in &pkey_attrs {
            if let Attribute::KeyType(kt) = attr {
                key_type = Some(*kt);
            }
        }

        Self::new(private_key_handle, key_type.unwrap(), pkey_attrs)
    }
}

// TODO rename as this doesn't use the private key
fn derive_public_key_from_private_key_data(kt: cryptoki::object::KeyType, attributes: Vec<cryptoki::object::Attribute>) -> Result<SupportedPublicKey, String> {
    use cryptoki::object::{Attribute, KeyType};

    match kt {
        KeyType::RSA => {
            let modulus: BigUint = BigUint::from_bytes_be(&attributes.iter().find_map(|attr| match attr {
                Attribute::Modulus(modulus) => Some(modulus),
                _ => None
            }).ok_or("No modulus in RSA key")?);
            let p_exponent: BigUint = BigUint::from_bytes_be(&attributes.iter().find_map(|attr| match attr {
                Attribute::PublicExponent(p_exponent) => Some(p_exponent),
                _ => None
            }).ok_or("No public exponent in RSA key")?);

            println!("modulus: {:#?}, public exponent: {:#?}", modulus, p_exponent);
            // Build an RsaPublicKey from modulus, p_exponent
            Ok(SupportedPublicKey::RSA(RsaPublicKey::new(modulus, p_exponent).unwrap()))
        },
        KeyType::EC => {
            let ec_point: &mut &Vec<u8> = &mut attributes.iter().find_map(|attr| match attr {
                Attribute::EcPoint(point) => Some(point),
                _ => None
            }).ok_or("No EC point in EC key")?;
            let ec_params: &Vec<u8> = attributes.iter().find_map(|attr| match attr {
                Attribute::EcParams(params) => Some(params),
                _ => None
            }).ok_or("No EC params in EC key")?;

            if ec_point.len() == 0 {
                Err("Public key has length 0".to_owned())
            } else {
                let mut parity = None;
                // X9.62 hybrid representation, not supported by SEC1, so convert to uncompressed
                if ec_point[0] == 4 || ec_point[0] == 5 {
                    parity = Some(ec_point[0] % 2);
                    ec_point[0] = 1;
                };

                // TODO get curve from the sequence ECParameters
                let curve = ec_params;

                // TODO branch on EC curve
                let pub_key = elliptic_curve::PublicKey::<p224::NistP224>::from_sec1_bytes(ec_point).map_err(|_| "Couldn't decode the NistP224 public key".to_owned()).map(|pk| SupportedPublicKey::NistP224(pk));
                let pub_key = elliptic_curve::PublicKey::<p256::NistP256>::from_sec1_bytes(ec_point).map_err(|_| "Couldn't decode the NistP256 public key".to_owned()).map(|pk| SupportedPublicKey::NistP256(pk));
                let pub_key = elliptic_curve::PublicKey::<p384::NistP384>::from_sec1_bytes(ec_point).map_err(|_| "Couldn't decode the NistP384 public key".to_owned()).map(|pk| SupportedPublicKey::NistP384(pk));
                // TODO NistP521: CurveArithmetic
                // let pub_key = elliptic_curve::PublicKey::<p521::NistP521>::from_sec1_bytes(ec_point).map_err(|_| "Couldn't decode the NistP521 public key".to_owned()).map(|pk| SupportedPublicKey::NistP521(pk));
                // TODO let pub_key = elliptic_curve::PublicKey::<ed25519::???>::from_sec1_bytes(ec_point).map_err(|_| "Could't decode the ED25519 public key".to_owned());
                // TODO ?? : as elliptic_curve::Curve

                // Validation
                // TODO
                // TODO parity validation

                pub_key
            }
        },
        _ => todo!("implement other schemes yourself please")
    }
}
