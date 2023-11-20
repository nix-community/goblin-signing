use goblin::pe::certificate_table::WindowsCertificateHeader;
use scroll::{Pread, ctx::TryFromCtx};
use super::errors::{Result, Error};

/// EFI_TIME
#[repr(C)]
#[derive(Debug, Clone, Copy, Pread)]
pub struct EfiTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    _pad1: u8,
    nanosecond: u32,
    timezone: i16,
    daylight: u8,
    _pad2: u8
}

/// WIN_CERTIFICATE_UEFI_GUID
/// header's wCertificateType should be set to WIN_CERT_TYPE_EFI_GUID here.
#[derive(Debug)]
pub struct CertificateUefiGuid<'var> {
    pub header: WindowsCertificateHeader,
    pub guid: [u8; 16],
    pub cert_data: &'var [u8]
}

impl<'a> TryFromCtx<'a, scroll::Endian> for CertificateUefiGuid<'a> {
    type Error = super::errors::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let header: WindowsCertificateHeader = from.gread_with(offset, ctx)?;
        let guid = from.get(*offset..(*offset + 16))
            .ok_or(Error::Malformed("A valid GUID".into()))?.try_into().unwrap();
        *offset += 16;
        let cert_data = from.get(*offset..(*offset + header.length as usize))
            .ok_or(Error::Malformed("A valid certificate data".into()))?;
        *offset += header.length as usize;

//    if guid != WIN_CERT_TYPE_EFI_GUID {
//        return Err(Invalid...);
//    }
//
        Ok((Self {
            header,
            guid,
            cert_data
        }, *offset))
    }

}

//pub const WIN_CERT_TYPE_EFI_GUID: [u8; 16] = {0xa7717414, 0xc616, 0x4977, 0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf };
