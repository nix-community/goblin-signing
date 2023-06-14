use goblin::pe::certificate_table::{AttributeCertificate, AttributeCertificateType};
use cms::content_info::ContentInfo;
use x509_cert::der::{Decode, Result};

pub trait AttributeCertificateExt {
    fn as_signed_data(&self) -> Option<Result<ContentInfo>>;
}

impl<'a> AttributeCertificateExt for AttributeCertificate<'a> {
    /// Return the pkcs7 [`ContentInfo`] attached to the [`PE`]
    fn as_signed_data(&self) -> Option<Result<ContentInfo>> {
        if self.certificate_type == AttributeCertificateType::PkcsSignedData {
            Some(ContentInfo::from_der(self.certificate))
        } else {
            None
        }
    }
}
