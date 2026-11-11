//! `CommitmentTypeIndication` (RFC 5126 §5.11.1, ETSI EN 319 122-1 §5.2.3).

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Any, Sequence};

use super::oids;

/// `CommitmentTypeQualifier`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CommitmentTypeQualifier {
    /// Qualifier type.
    pub commitment_type_identifier: ObjectIdentifier,
    /// Qualifier value.
    #[asn1(optional = "true")]
    pub qualifier: Option<Any>,
}

/// `CommitmentTypeIndication` attribute value.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CommitmentTypeIndication {
    /// Commitment type, e.g. [`CommitmentType::ProofOfOrigin`].
    pub commitment_type_id: ObjectIdentifier,
    /// Optional qualifiers.
    #[asn1(optional = "true")]
    pub commitment_type_qualifier: Option<Vec<CommitmentTypeQualifier>>,
}

impl AssociatedOid for CommitmentTypeIndication {
    const OID: ObjectIdentifier = oids::AA_ETS_COMMITMENT_TYPE;
}

/// The commitment types defined in RFC 5126 and ETSI EN 319 122-1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CommitmentType {
    /// The signer recognizes to have created, approved and sent the data.
    ProofOfOrigin,
    /// The signer recognizes to have received the content.
    ProofOfReceipt,
    /// A trusted service provider indicates that the data was delivered.
    ProofOfDelivery,
    /// The entity signing has sent the data (not necessarily created it).
    ProofOfSender,
    /// The signer has approved the content.
    ProofOfApproval,
    /// The signer has created the data (not necessarily approved or sent it).
    ProofOfCreation,
}

impl CommitmentType {
    const ALL: [(Self, ObjectIdentifier); 6] = [
        (Self::ProofOfOrigin, oids::CTI_PROOF_OF_ORIGIN),
        (Self::ProofOfReceipt, oids::CTI_PROOF_OF_RECEIPT),
        (Self::ProofOfDelivery, oids::CTI_PROOF_OF_DELIVERY),
        (Self::ProofOfSender, oids::CTI_PROOF_OF_SENDER),
        (Self::ProofOfApproval, oids::CTI_PROOF_OF_APPROVAL),
        (Self::ProofOfCreation, oids::CTI_PROOF_OF_CREATION),
    ];

    /// The OID of this commitment type.
    pub fn oid(self) -> ObjectIdentifier {
        Self::ALL
            .iter()
            .find(|(t, _)| *t == self)
            .map_or(oids::CTI_PROOF_OF_ORIGIN, |(_, oid)| *oid)
    }

    /// The commitment type for `oid`, if it is one of the standard ones.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Self::ALL.iter().find(|(_, o)| o == oid).map(|(t, _)| *t)
    }
}

impl From<CommitmentType> for CommitmentTypeIndication {
    fn from(t: CommitmentType) -> Self {
        Self {
            commitment_type_id: t.oid(),
            commitment_type_qualifier: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    #[test]
    fn round_trip_all_standard_types() {
        for (t, oid) in CommitmentType::ALL {
            let indication = CommitmentTypeIndication::from(t);
            let der = indication.to_der().expect("encode");
            let decoded = CommitmentTypeIndication::from_der(&der).expect("decode");
            assert_eq!(decoded.commitment_type_id, oid);
            assert_eq!(
                CommitmentType::from_oid(&decoded.commitment_type_id),
                Some(t)
            );
        }
        assert_eq!(CommitmentType::from_oid(&oids::SHA256), None);
    }
}
