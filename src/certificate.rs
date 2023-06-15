use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use goblin::pe::certificate_table::{AttributeCertificate, AttributeCertificateType};
use x509_cert::der::{Encode, Decode, Sequence, AnyRef, Reader};
use x509_cert::der::asn1::{ObjectIdentifier, OctetStringRef};
use x509_cert::spki::AlgorithmIdentifier;

/// SPC_INDIRECT_DATA_OBJID http://oid-info.com/get/1.3.6.1.4.1.311.2.1.4
pub const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo<'a> {
    // Technically: RFC3279 only?
    // Not updates, or is it?
    pub digest_algorithm: AlgorithmIdentifier<AnyRef<'a>>,
    pub digest: OctetStringRef<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SpcIndirectDataContent<'a> {
    pub data: ContentInfo,
    pub message_digest: DigestInfo<'a>
}

pub trait AttributeCertificateExt {
    fn as_signed_data(&self) -> Option<Result<SignedData>>;
    fn as_spc_indirect_data_content(&self) -> Option<Result<SpcIndirectDataContent>>;
}

impl<'a> AttributeCertificateExt for AttributeCertificate<'a> {
    /// Return the pkcs7 [`ContentInfo`] attached to the [`PE`]
    fn as_signed_data(&self) -> Option<Result<SignedData>> {
        if self.certificate_type == AttributeCertificateType::PkcsSignedData {
            Some(
                ContentInfo::from_der(self.certificate).and_then(|cinfo| cinfo.content.decode_as::<SignedData>())
            )
        } else {
            None
        }
    }

    fn as_spc_indirect_data_content(&self) -> Option<Result<SpcIndirectDataContent>> {
        self.as_signed_data()
            .map(|maybe_sdata| {
                if let Ok(sdata) = maybe_sdata {
                    if sdata.encap_content_info.econtent_type != SPC_INDIRECT_DATA_OBJID {
                        return None;
                    }

                    // This is bad
                    Some(sdata.encap_content_info.econtent.unwrap().decode_as::<SpcIndirectDataContent<'a>>())
                } else {
                    None
                }
            })
    }

}
