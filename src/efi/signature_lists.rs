use super::errors::{Error, Result};
use der::Decode;
use scroll::{ctx::TryFromCtx, Pread};
use uuid::Uuid;
use x509_cert::Certificate;

/// TODO: sort along the GUID types — EfiCertX509                  = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"

#[derive(Pread, Debug)]
pub struct SignatureListHeader {
    /// Signature type in form of GUID
    guid: [u8; 16],
    /// Total length of the signature list, including this header
    length: u32,
    /// Size of the signature header
    header_length: u32,
    /// Size of each signature, at least as big as EFI_SIGNATURE_DATA
    signature_length: u32,
}

impl SignatureListHeader {
    pub fn guid(&self) -> Uuid {
        Uuid::from_slice_le(&self.guid).unwrap()
    }
}

#[derive(Debug)]
pub struct Signature<'a> {
    pub owner: Uuid,
    pub data: &'a [u8],
    pub certificate: Option<Certificate>,
}

#[derive(Debug)]
pub struct SignatureList<'a> {
    pub header: SignatureListHeader,
    signature_header: &'a [u8],
    pub signatures: Vec<Signature<'a>>,
}

#[derive(Debug)]
pub struct SignatureDatabase<'a>(pub Vec<SignatureList<'a>>);

impl<'a> Signature<'a> {
    fn parse(bytes: &'a [u8], offset: usize, signature_size: u32) -> Result<Self> {
        let owner = Uuid::from_slice_le(bytes.get(offset..(offset + 16)).unwrap()).unwrap();

        let data = bytes
            .get((offset + 16)..(offset + signature_size as usize))
            .unwrap();

        Ok(Self {
            owner,
            data,
            certificate: Certificate::from_der(data).ok(),
        })
    }
}

impl<'a> TryFromCtx<'a, scroll::Endian> for SignatureList<'a> {
    type Error = super::errors::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let header: SignatureListHeader = from.gread_with(offset, ctx)?;
        let signature_header = from
            .get(*offset..(*offset + header.header_length as usize))
            .ok_or(Error::Malformed(format!(
                "No signature header on {}...{} in a {}-long bytes",
                *offset,
                *offset + header.header_length as usize,
                from.len()
            )))?;
        *offset += header.header_length as usize;
        let mut signatures = Vec::new();
        while *offset < (header.length as usize) {
            signatures.push(Signature::parse(from, *offset, header.signature_length)?);
            *offset += header.signature_length as usize;
        }

        Ok((
            Self {
                header,
                signature_header,
                signatures,
            },
            *offset,
        ))
    }
}

impl<'a> TryFromCtx<'a, scroll::Endian> for SignatureDatabase<'a> {
    type Error = super::errors::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut lists = Vec::new();

        while let Ok(signature_list) = from.gread_with(offset, ctx) {
            lists.push(signature_list);
        }

        Ok((SignatureDatabase(lists), *offset))
    }
}
