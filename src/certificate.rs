use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData};
use const_oid::AssociatedOid;
use der::asn1::{Null, OctetString};
use digest::{Digest, Output};
use goblin::pe::certificate_table::{AttributeCertificate, AttributeCertificateType};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Any, Decode, Result, Sequence};
use x509_cert::spki::AlgorithmIdentifierOwned;

/// SPC_INDIRECT_DATA_OBJID <http://oid-info.com/get/1.3.6.1.4.1.311.2.1.4>
pub const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/1537695a-28f0-4828-8b7b-d6dab62b8030>
pub const SPC_PE_IMAGE_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");
pub const DEFAULT_DATA: SpcAttributeTypeAndOptionalValue = SpcAttributeTypeAndOptionalValue {
    content_type: SPC_PE_IMAGE_DATA_OBJID,
    value: None,
};

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo {
    // Technically: RFC3279 only?
    // Not updates, or is it?
    pub digest_algorithm: AlgorithmIdentifierOwned,
    pub digest: OctetString,
}

impl DigestInfo {
    pub fn from_authenticode<D: Digest + AssociatedOid>(digest: Output<D>) -> Result<DigestInfo> {
        Ok(DigestInfo {
            digest_algorithm: AlgorithmIdentifierOwned {
                oid: D::OID,
                parameters: Some(Null.into()),
            },
            digest: OctetString::new(digest.to_vec())?,
        })
    }
    pub fn as_spc_indirect_data_content(self) -> SpcIndirectDataContent {
        let mut data = DEFAULT_DATA.clone();
        data.value = Some(Any::encode_from(&OctetString::new([]).unwrap()).unwrap());
        SpcIndirectDataContent {
            data,
            message_digest: self,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue {
    pub content_type: ObjectIdentifier,
    pub value: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent {
    pub data: SpcAttributeTypeAndOptionalValue,
    pub message_digest: DigestInfo,
}

impl SpcIndirectDataContent {
    pub fn as_encapsulated_content_info(&self) -> Result<EncapsulatedContentInfo> {
        Ok(EncapsulatedContentInfo {
            econtent_type: SPC_INDIRECT_DATA_OBJID,
            econtent: Some(Any::encode_from(self)?),
        })
    }
}

pub trait AttributeCertificateExt<'a> {
    fn as_signed_data(&self) -> Option<Result<SignedData>>;
    fn as_spc_indirect_data_content(&self) -> Option<Result<SpcIndirectDataContent>>;
}

pub trait SignedDataExt {
    fn as_spc_indirect_data_content(&self) -> Option<Result<SpcIndirectDataContent>>;
    fn as_message_digest(&self) -> Option<Result<DigestInfo>>;
}

impl SignedDataExt for SignedData {
    fn as_spc_indirect_data_content(&self) -> Option<Result<SpcIndirectDataContent>> {
        if self.encap_content_info.econtent_type != SPC_INDIRECT_DATA_OBJID {
            return None;
        }

        // FIXME: propagate properly the unwrap issue.
        Some(
            self.encap_content_info
                .econtent
                .as_ref()
                .unwrap()
                .decode_as::<SpcIndirectDataContent>(),
        )
    }

    fn as_message_digest(&self) -> Option<Result<DigestInfo>> {
        self.as_spc_indirect_data_content()
            .map(|maybe_spc| maybe_spc.map(|spc| spc.message_digest))
    }
}

impl<'a> AttributeCertificateExt<'a> for AttributeCertificate<'a> {
    /// Return the pkcs7 [`ContentInfo`] attached to the [`goblin::pe::PE`]
    fn as_signed_data(&self) -> Option<Result<SignedData>> {
        if self.certificate_type == AttributeCertificateType::PkcsSignedData {
            Some(
                ContentInfo::from_der(&self.certificate)
                    .and_then(|cinfo| cinfo.content.decode_as::<SignedData>()),
            )
        } else {
            None
        }
    }

    fn as_spc_indirect_data_content(&self) -> Option<Result<SpcIndirectDataContent>> {
        self.as_signed_data().and_then(|maybe_sdata| {
            if let Ok(sdata) = maybe_sdata {
                sdata.as_spc_indirect_data_content()
            } else {
                None
            }
        })
    }
}
