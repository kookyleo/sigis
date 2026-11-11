//! `SignaturePolicyIdentifier` (RFC 5126 §5.8.1, ETSI EN 319 122-1 §5.2.9).

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{Ia5String, Null};
use der::{Any, Choice, Sequence};
use x509_cert::ext::pkix::certpolicy::UserNotice;

use super::{oids, OtherHashAlgAndValue};

/// `SigPolicyQualifierInfo`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigPolicyQualifierInfo {
    /// Qualifier type, e.g. [`oids::SPQ_ETS_URI`].
    pub sig_policy_qualifier_id: ObjectIdentifier,
    /// Qualifier value, interpreted according to the type.
    pub sig_qualifier: Any,
}

/// A decoded signature policy qualifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigPolicyQualifier {
    /// `SPuri`: where the policy document can be found.
    Uri(String),
    /// `SPUserNotice`: text to show to the user.
    UserNotice(Box<UserNotice>),
    /// Any other qualifier.
    Other(ObjectIdentifier),
}

impl SigPolicyQualifierInfo {
    /// Decode the qualifier value.
    pub fn decode(&self) -> der::Result<SigPolicyQualifier> {
        if self.sig_policy_qualifier_id == oids::SPQ_ETS_URI {
            let uri: Ia5String = self.sig_qualifier.decode_as()?;
            Ok(SigPolicyQualifier::Uri(uri.to_string()))
        } else if self.sig_policy_qualifier_id == oids::SPQ_ETS_UNOTICE {
            Ok(SigPolicyQualifier::UserNotice(Box::new(
                self.sig_qualifier.decode_as()?,
            )))
        } else {
            Ok(SigPolicyQualifier::Other(self.sig_policy_qualifier_id))
        }
    }
}

/// `SignaturePolicyId`: an explicit signature policy.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignaturePolicyId {
    /// Policy OID.
    pub sig_policy_id: ObjectIdentifier,
    /// Digest of the policy document.
    pub sig_policy_hash: OtherHashAlgAndValue,
    /// Optional qualifiers.
    #[asn1(optional = "true")]
    pub sig_policy_qualifiers: Option<Vec<SigPolicyQualifierInfo>>,
}

/// `SignaturePolicyIdentifier` attribute value.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SignaturePolicyIdentifier {
    /// An explicit policy.
    SignaturePolicyId(SignaturePolicyId),
    /// `signaturePolicyImplied`: the policy is implied by context.
    SignaturePolicyImplied(Null),
}

impl AssociatedOid for SignaturePolicyIdentifier {
    const OID: ObjectIdentifier = oids::AA_ETS_SIG_POLICY_ID;
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};
    use spki::AlgorithmIdentifierOwned;

    #[test]
    fn explicit_policy_round_trip() {
        let uri = Ia5String::new("https://example.com/policy.pdf").expect("ia5");
        let policy = SignaturePolicyIdentifier::SignaturePolicyId(SignaturePolicyId {
            sig_policy_id: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
            sig_policy_hash: OtherHashAlgAndValue {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: oids::SHA256,
                    parameters: None,
                },
                hash_value: der::asn1::OctetString::new([0xab; 32]).expect("octets"),
            },
            sig_policy_qualifiers: Some(vec![SigPolicyQualifierInfo {
                sig_policy_qualifier_id: oids::SPQ_ETS_URI,
                sig_qualifier: Any::encode_from(&uri).expect("any"),
            }]),
        });
        let der = policy.to_der().expect("encode");
        let decoded = SignaturePolicyIdentifier::from_der(&der).expect("decode");
        assert_eq!(decoded, policy);
        let SignaturePolicyIdentifier::SignaturePolicyId(id) = decoded else {
            panic!("expected explicit policy");
        };
        let qualifiers = id.sig_policy_qualifiers.expect("qualifiers");
        assert_eq!(
            qualifiers[0].decode().expect("qualifier"),
            SigPolicyQualifier::Uri("https://example.com/policy.pdf".into())
        );
    }

    #[test]
    fn implied_policy_round_trip() {
        let implied = SignaturePolicyIdentifier::SignaturePolicyImplied(Null);
        let der = implied.to_der().expect("encode");
        assert_eq!(der, [0x05, 0x00]);
        assert_eq!(
            SignaturePolicyIdentifier::from_der(&der).expect("decode"),
            implied
        );
    }
}
