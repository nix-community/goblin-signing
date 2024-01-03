use super::errors::Result;
use scroll::ctx::TryFromCtx;
use scroll::Pread;

use super::common::{CertificateUefiGuid, EfiTime};

/// EFI_VARIABLE_AUTHENTICATION_2
#[derive(Debug)]
pub struct AuthenticatedVariable2<'var> {
    pub timestamp: EfiTime,
    pub auth_info: CertificateUefiGuid<'var>,
}

impl<'a> TryFromCtx<'a, scroll::Endian> for AuthenticatedVariable2<'a> {
    type Error = super::errors::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let timestamp: EfiTime = from.gread_with(offset, ctx)?;
        let auth_info: CertificateUefiGuid = from.gread_with(offset, ctx)?;

        //    if guid != WIN_CERT_TYPE_EFI_GUID {
        //        return Err(Invalid...);
        //    }
        //
        Ok((
            Self {
                timestamp,
                auth_info,
            },
            *offset,
        ))
    }
}
