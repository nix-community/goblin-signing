/// Demonstrates how to verify a PE binary.
/// This will verify that a PE binary will be valid under Secure Boot policy
/// of the current system or a given a certificate on the command line.
use std::path::PathBuf;

use clap::Parser;
use der::Decode;
use goblin_signing::verify::VerificationOptions;

use bitflags::bitflags;
use goblin_signing::efi::signature_lists::SignatureDatabase;
use scroll::Pread;
use x509_cert::Certificate;

bitflags! {
    #[derive(Debug)]
    struct EfiAttribute: u32 {
        const EFI_VARIABLE_NON_VOLATILE = 0x00000001;
        const EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002;
        const EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004;
        const EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010;
        const EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020;
        const EFI_VARIABLE_APPEND_WRITE = 0x00000040;
        const EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS = 0x00000080;
    }
}

fn certificate_from_efi_database(contents: &[u8]) -> Vec<Certificate> {
    // Skip the 4 first bytes of attributes.
    let attributes = EfiAttribute::from_bits(u32::from_le_bytes(contents[..4].try_into().unwrap()));
    println!("Attributes: {:?}", attributes);
    let signature_database: SignatureDatabase = contents[4..].pread_with(0, scroll::LE).unwrap();
    println!("Signature database: {:?}", signature_database);

    signature_database
        .0
        .into_iter()
        .flat_map(|list| {
            list.signatures
                .into_iter()
                .filter_map(|signature| signature.certificate)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[derive(Parser, Debug)]
struct Cli {
    /// File to verify
    file_to_verify: PathBuf,

    #[arg(short, long)]
    database_certificate: Option<PathBuf>,

    #[arg(
        short,
        long,
        default_value = "/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
    )]
    efi_variable_path: PathBuf,
}

fn main() {
    let args = Cli::parse();

    let mut certificates = Vec::new();
    if let Some(db_cert_path) = args.database_certificate {
        certificates.push(
            Certificate::from_der(
                &std::fs::read(db_cert_path)
                    .expect("Failed to read the provided database certificate"),
            )
            .expect("Failed to read the DER representation of the provided database certificate"),
        );
    }

    if let Ok(contents) = std::fs::read(&args.efi_variable_path) {
        certificates.append(&mut certificate_from_efi_database(&contents));
    } else {
        println!(
            "Failed to read the EFI variable path: {}",
            args.efi_variable_path.display()
        );
    }

    let pe_data =
        std::fs::read(&args.file_to_verify).expect("Failed to read the PE binary to verify");
    let pe = goblin::pe::PE::parse(&pe_data).expect("Failed to parse the PE binary to verify");

    if certificates.is_empty() {
        println!(
            "Verification without a trust store as no certificate has been given: {:?}",
            goblin_signing::verify::verify_pe_signatures_no_trust(&pe)
        );
    } else {
        println!(
            "Verification with a trust store as certificates has been given: {:?}",
            goblin_signing::verify::verify_pe_signatures(
                &pe,
                VerificationOptions {
                    trust_store: Some(certificates)
                }
            )
        );
    }
}
