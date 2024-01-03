use clap::{Parser, Subcommand};
/// Demonstrates how to sign a PE binary
/// in a fairly realistic setup, i.e.
/// a CA as a root certificate
/// a sub CA as a certificate for a bunch of entities
/// a leaf certificate for a target file.
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use const_oid::AssociatedOid;
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, CertificateType, KeyType, ObjectHandle},
    session::Session,
    slot::Slot,
};
use cryptoki_rustcrypto::{x509::CertPkcs11, SessionLike};
use der::Encode;
use goblin::pe::{writer::PEWriter, PE};
use goblin_signing::sign::create_certificate;
use pkcs11_uri::Pkcs11Uri;
use rpassword::read_password;
use sha2::Sha256;
use signature::Keypair;
use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use x509_cert::{
    builder::{Builder, CertificateBuilder},
    serial_number::SerialNumber,
    time::Validity,
    Certificate,
};

type P256Signer<S> = cryptoki_rustcrypto::ecdsa::Signer<p256::NistP256, S>;

fn prompt_pin() -> String {
    loop {
        print!("Type a PIN: ");
        std::io::stdout().flush().unwrap();
        let password = read_password();

        if password.is_err() {
            continue;
        }

        return password.unwrap();
    }
}

fn prompt_label() -> String {
    let mut label = String::new();
    loop {
        print!("Type a token label: ");
        std::io::stdout().flush().unwrap();
        if std::io::stdin().read_line(&mut label).is_err() {
            continue;
        }

        return label;
    }
}

/// We will massage a bit the hardware token here.
/// Open it, initialize a token, initialize the various PINs.
fn initialize_token(pkcs11: &mut Pkcs11, token: &Pkcs11Uri) -> (Slot, Session) {
    println!(
        "Slots available with initialized token: {:?}",
        pkcs11.get_all_slots().unwrap()
    );
    let slot = token
        .path_attributes
        .slot_id
        .unwrap()
        .try_into()
        .expect("Failed to read the slot ID");
    println!("Obtained a security token, i.e. a slot: {:#?}", slot);

    let pin = if let Some(pin) = token.query_attributes.pin_value.clone() {
        pin
    } else {
        prompt_pin()
    }
    .try_into()
    .expect("Failed to read the PIN value");

    let token_label = if let Some(label) = token.path_attributes.token_label.clone() {
        label
    } else {
        prompt_label()
    };

    let _ = pkcs11
        .init_token(slot, &pin, &token_label)
        .expect("Failed to initialize the token");
    let session = pkcs11
        .open_rw_session(slot)
        .expect("Failed to open the slot in RW session");

    println!("Session opened in read-write");
    let _ = session
        .login(cryptoki::session::UserType::So, Some(&pin))
        .unwrap();
    println!("Logged in as the security officer");

    let _ = session.init_pin(&pin).unwrap();
    println!("Normal pin initialized");

    let _ = session.logout().unwrap();
    println!("Logged out from the security officer");

    let _ = session
        .login(cryptoki::session::UserType::User, Some(&pin))
        .unwrap();
    println!("Logged in as a user");

    println!("Token initialized.");

    (slot, session)
}

fn connect_to_token(pkcs11: &mut Pkcs11, token: &Pkcs11Uri) -> (Slot, Session) {
    println!(
        "Available tokens: {:#?}",
        pkcs11.get_slots_with_token().unwrap()
    );
    let slot = token
        .path_attributes
        .slot_id
        .unwrap()
        .try_into()
        .expect("Failed to read the slot ID");
    let session = pkcs11
        .open_rw_session(slot)
        .expect("Failed to open the token in RO");

    println!(
        "Available mechanisms: {:#?}",
        pkcs11
            .get_mechanism_list(slot)
            .unwrap()
            .into_iter()
            .map(|mech| mech.to_string())
            .collect::<Vec<_>>()
    );

    let pin = if let Some(pin) = token.query_attributes.pin_value.clone() {
        pin
    } else {
        prompt_pin()
    }
    .try_into()
    .expect("Failed to read the PIN value");
    let _ = session
        .login(cryptoki::session::UserType::User, Some(&pin))
        .unwrap();

    println!("Logged in as a user.");

    (slot, session)
}

struct CertificateParameters {
    label: String,
    subject: x509_cert::name::DistinguishedName,
    profile: x509_cert::builder::Profile,
}

fn find_or_create<PKey: EncodePublicKey, S: SessionLike>(
    session: &Session,
    signer: &P256Signer<S>,
    certificate: CertificateParameters,
    public_key: PKey,
) -> Result<Certificate, cryptoki_rustcrypto::x509::Error> {
    let cert_template = &[
        Attribute::Label(certificate.label.into()),
        Attribute::Subject(certificate.subject.to_der().unwrap()),
    ];

    match Certificate::pkcs11_load(session, cert_template) {
        Ok(cert) => Ok(cert),
        Err(err) => match err {
            cryptoki_rustcrypto::x509::Error::MissingCert => {
                let builder = CertificateBuilder::new(
                    certificate.profile,
                    SerialNumber::from(42u32),
                    Validity::from_now(Duration::new(5, 0)).unwrap(),
                    certificate.subject,
                    SubjectPublicKeyInfoOwned::from_key(public_key)
                        .expect("Failed to encode the public key as SPKI"),
                    signer,
                )
                .expect("Failed to create certificate");

                let cert = builder
                    .build::<ecdsa::der::Signature<p256::NistP256>>()
                    .expect("Failed to assemble the certificate");
                cert.pkcs11_store(session, cert_template)
                    .expect("Failed to store the certificate");
                Ok(cert)
            }
            _ => Err(err),
        },
    }
}

#[derive(Debug)]
struct SigningKeyInfo {
    /// Description
    pub label: String,
    /// DER-encoding of the certificate subject name
    pub subject: x509_cert::name::Name,
}

impl SigningKeyInfo {
    fn label_attribute(&self) -> Attribute {
        Attribute::Label(self.label.as_bytes().to_vec())
    }

    fn subject_to_der(&self) -> der::Result<Vec<u8>> {
        self.subject.to_der()
    }

    fn subject_attribute(&self) -> der::Result<Attribute> {
        Ok(Attribute::Subject(self.subject_to_der()?))
    }
}

fn generate_signing_key(
    session: &Session,
    key_info: &SigningKeyInfo,
    mechanism: Mechanism,
) -> (ObjectHandle, ObjectHandle) {
    let ec_params = match mechanism {
        // https://oid-rep.orange-labs.fr/get/1.2.840.10045.3.1.7
        Mechanism::EccKeyPairGen => p256::NistP256::OID.to_der().unwrap(),
        // http://www.oid-info.com/cgi-bin/display?oid=1.3.101.112&action=display
        // Mechanism::EccEdwardsKeyPairGen => const_oid::ObjectIdentifier::new_unwrap("1.3.101.112").to_der().unwrap(),
        _ => todo!("implement this EC parameters or introduce new parameters"),
    };

    let public_key_template = &[
        Attribute::Token(true),
        Attribute::EcParams(ec_params),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        key_info.label_attribute(),
    ];
    let private_key_template = &[
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        key_info.label_attribute(),
        key_info
            .subject_attribute()
            .expect("Failed to DER-encode the subject of the signing key information"),
        Attribute::Sensitive(true),
    ];

    session
        .generate_key_pair(&mechanism, public_key_template, private_key_template)
        .expect("Failed to generate signing keys")
}

/// We will mimic here a organizational-level setup
/// where there is an org-level CA on the hardware token.
/// Then, we will generate a sub-CA for each "entity", e.g. a machine or a group of machines.
/// Each sub-CA will be responsible to sign the files for those specific entities.
/// It is sufficient to trust the CA to trust the sub-CA signatures.
fn generate_secrets(
    mechanism: &str,
    ca_key_info: SigningKeyInfo,
    subca_key_info: SigningKeyInfo,
    ca_parameters: CertificateParameters,
    subca_parameters: CertificateParameters,
    session: &Session,
) -> (Certificate, Certificate) {
    let mechanism = match mechanism {
        "ecdsa" => Mechanism::EccKeyPairGen,
        _ => todo!("implement this mechanism as an exercise and extend this example!"),
    };

    // Generate a private key for the CA.
    // TODO: find or create the key.
    let (ca_public_key, ca_private_key) = generate_signing_key(&session, &ca_key_info, mechanism);
    let (subca_public_key, subca_private_key) =
        generate_signing_key(&session, &subca_key_info, mechanism);

    println!("CA label: {}", ca_key_info.label);
    let ca_signer = match mechanism {
        Mechanism::EccKeyPairGen => P256Signer::new(session, ca_key_info.label.as_bytes()),
        _ => todo!("implement this mechanism as an exercise and extend this example!"),
    }
    .expect("Failed to derive a CA signer from session and label");
    println!("SubCA label: {}", subca_key_info.label);
    let subca_signer = match mechanism {
        Mechanism::EccKeyPairGen => P256Signer::new(session, subca_key_info.label.as_bytes()),
        _ => todo!("implement this mechanism as an exercise and extend this example!"),
    }
    .expect("Failed to derive a SubCA signer from session and label");

    // As it is self-signed, the SPKI is the public key of the ca_signer.
    let ca_cert = find_or_create(
        &session,
        &ca_signer,
        ca_parameters,
        ca_signer.verifying_key(),
    )
    .expect("Failed to produce and self-sign the CA certificate");
    // As it is not self-signed, the SPKI is our own public key generated for the occasion.
    let subca_cert = find_or_create(
        &session,
        &ca_signer,
        subca_parameters,
        subca_signer.verifying_key(),
    )
    .expect("Failed to produce and sign the sub CA certificate");

    println!(
        "CA {} and SubCA {} generated or found on the security token: {:?}/{:?} - {:?}/{:?}",
        ca_key_info.subject,
        subca_key_info.subject,
        ca_public_key,
        ca_private_key,
        subca_public_key,
        subca_private_key
    );

    (ca_cert, subca_cert)
}

fn sign_file<S: SessionLike>(
    file: &Path,
    mut parents: Vec<Certificate>,
    parent_signer: &P256Signer<S>,
) {
    let contents = std::fs::read(file).expect("Failed to read the PE binary");
    let pe = PE::parse(&contents).expect("Failed to parse the PE binary");

    let certificate;
    let issuer;
    {
        let parent = parents.last().unwrap();
        // Create a unique certificate for this particular instance,
        // but do not store it in the HSM,
        // signed off some certificate.
        let builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Leaf {
                issuer: parent.tbs_certificate.subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(42u32),
            Validity::from_now(Duration::new(5, 0)).unwrap(),
            "CN=leaf@example.com".parse().unwrap(),
            parent.tbs_certificate.subject_public_key_info.clone(),
            parent_signer,
        )
        .expect("Failed to create certificate");

        certificate = builder
            .build::<ecdsa::der::Signature<p256::NistP256>>()
            .expect("Failed to assemble the certificate");
        issuer = cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
            cms::cert::IssuerAndSerialNumber {
                issuer: parent.tbs_certificate.issuer.clone(),
                serial_number: parent.tbs_certificate.serial_number.clone(),
            },
        );
    }
    parents.push(certificate);
    let pe_certificate = create_certificate::<Sha256, _, ecdsa::der::Signature<_>>(
        &pe,
        parents,
        issuer,
        parent_signer,
    )
    .expect("Failed to produce an PE attribute certificate");
    let mut pe_writer = PEWriter::new(pe).expect("Failed to construct the PE writer");
    pe_writer
        .attach_certificates(vec![pe_certificate])
        .expect("Failed to attach a new certificate to PE");
    println!("Signed!");
    std::fs::write(
        file.with_extension("efi.signed"),
        pe_writer
            .write_into()
            .expect("Failed to materialize the new PE"),
    )
    .expect("Failed to write the new PE");
}

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long)]
    token_uri: String,
    #[clap(subcommand)]
    commands: Commands,
}

/// Format: pkcs11:token=TokenLabel;slot-id=1;id=%4a%8d%2f%6e%d9%c4%15%2b%26%0d%6c%74%a1%ae%72%fc%fd%c6%4b%65?module-path=/usr/local/lib/libp11.so&pin-value=1234

#[derive(Subcommand, Debug)]
enum Commands {
    Initialize,
    TestConnection,
    GenerateSecretMaterial(GenerateSecretMaterialCommand),
    SignFile(SignFileCommand),
}

#[derive(Debug, Parser)]
struct SignFileCommand {
    file_to_sign: PathBuf,
    #[arg(long, default_value = "Example CA")]
    ca_label: String,
    #[arg(long, default_value = "Example SubCA")]
    subca_label: String,
    #[arg(long, default_value = "CN=subca@example.com")]
    subca_subject: String,
}

#[derive(Debug, Parser)]
struct GenerateSecretMaterialCommand {
    mechanism: String,
    #[arg(long, default_value = "Example CA")]
    ca_label: String,
    #[arg(long, default_value = "Example SubCA")]
    subca_label: String,
    #[arg(long, default_value = "CN=ca@example.com")]
    ca_subject: String,
    #[arg(long, default_value = "CN=subca@example.com")]
    subca_subject: String,
}

fn main() {
    let args = Cli::parse();
    let token_uri: Pkcs11Uri = args
        .token_uri
        .as_str()
        .try_into()
        .expect("Expected a PKCS#11 URL");
    let module_path = token_uri
        .query_attributes
        .module_path
        .clone()
        .unwrap_or_else(|| std::env::var("PKCS11_SOFTHSM2_MODULE").unwrap());
    let mut pkcs11 = Pkcs11::new(module_path).unwrap();

    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    println!("PKCS#11 initialized");

    match args.commands {
        Commands::Initialize => {
            let _ = initialize_token(&mut pkcs11, &token_uri);
        }
        Commands::TestConnection => {
            let _ = connect_to_token(&mut pkcs11, &token_uri);
        }
        Commands::GenerateSecretMaterial(GenerateSecretMaterialCommand {
            mechanism,
            ca_label,
            subca_label,
            ca_subject,
            subca_subject,
        }) => {
            let (_slot, session) = connect_to_token(&mut pkcs11, &token_uri);
            let ca_signing_key = SigningKeyInfo {
                label: ca_label.clone(),
                subject: ca_subject.parse().expect("Failed to parse CA subject"),
            };
            let subca_signing_key = SigningKeyInfo {
                label: subca_label.clone(),
                subject: subca_subject
                    .parse()
                    .expect("Failed to parse SubCA subject"),
            };
            let ca_parameters = CertificateParameters {
                label: ca_label,
                subject: ca_subject.parse().unwrap(),
                profile: x509_cert::builder::Profile::Root,
            };
            let subca_parameters = CertificateParameters {
                label: subca_label,
                subject: subca_subject.parse().unwrap(),
                profile: x509_cert::builder::Profile::SubCA {
                    issuer: ca_subject.parse().unwrap(),
                    path_len_constraint: None,
                },
            };
            let (_ca, _subca) = generate_secrets(
                &mechanism,
                ca_signing_key,
                subca_signing_key,
                ca_parameters,
                subca_parameters,
                &session,
            );
        }
        Commands::SignFile(SignFileCommand {
            file_to_sign,
            subca_label,
            subca_subject,
            ca_label,
        }) => {
            let (_slot, session) = connect_to_token(&mut pkcs11, &token_uri);

            let cert_template = &[Attribute::Label(ca_label.into())];

            let ca_cert = Certificate::pkcs11_load(&session, cert_template)
                .expect("Failed to locate CA certificate");

            let subca_signing_key = SigningKeyInfo {
                label: subca_label.clone(),
                subject: subca_subject
                    .parse()
                    .expect("Failed to parse SubCA subject"),
            };
            let subca_signer = P256Signer::new(&session, subca_signing_key.label.as_bytes())
                .expect("Failed to obtain Sub CA signer");

            let cert_template = &[Attribute::Label(subca_label.into())];

            let subca_cert = Certificate::pkcs11_load(&session, cert_template)
                .expect("Failed to locate sub CA certificate");
            sign_file(&file_to_sign, vec![ca_cert, subca_cert], &subca_signer);
        }
    }
}
