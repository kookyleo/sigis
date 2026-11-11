// Derived from pyHanko `sign/validation/utils.py` (MIT, see LICENSE-pyHanko).

//! Algorithm usage policy for CMS signatures (`CMSAlgorithmUsagePolicy`).

use std::sync::Arc;

use const_oid::ObjectIdentifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use hanko_core::algorithms::{
    digest_algorithm_name, AlgorithmUsageConstraint, AlgorithmUsagePolicy,
    DisallowWeakAlgorithmsPolicy, SignatureMechanism,
};
use hanko_core::asn1::oids;
use hanko_core::time::Moment;

/// An algorithm usage policy that also decides whether the message digest
/// algorithm may differ from the one implied by the signature algorithm.
pub trait CmsAlgorithmUsagePolicy: AlgorithmUsagePolicy {
    /// `digest_combination_allowed`: by default the message digest must use
    /// the digest the signature mechanism implies, if any (RFC 8933).
    fn digest_combination_allowed(
        &self,
        signature_algorithm: &AlgorithmIdentifierOwned,
        message_digest_algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        ensure_digest_match(signature_algorithm, message_digest_algorithm)
    }
}

/// A base policy lifted to a CMS policy with the default digest
/// combination rule (`CMSAlgorithmUsagePolicy.lift_policy`).
#[derive(Debug, Clone)]
pub struct LiftedPolicy(pub Arc<dyn AlgorithmUsagePolicy>);

impl AlgorithmUsagePolicy for LiftedPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.0.digest_algorithm_allowed(algorithm, moment)
    }

    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        self.0
            .signature_algorithm_allowed(algorithm, moment, public_key)
    }

    fn min_rsa_key_size(&self) -> usize {
        self.0.min_rsa_key_size()
    }
}

impl CmsAlgorithmUsagePolicy for LiftedPolicy {}

/// Lift a base policy (`lift_policy`).
pub fn lift_policy(policy: Arc<dyn AlgorithmUsagePolicy>) -> Arc<dyn CmsAlgorithmUsagePolicy> {
    Arc::new(LiftedPolicy(policy))
}

/// `DEFAULT_ALGORITHM_USAGE_POLICY`: weak hashes `md2`, `md5`, `sha1`.
pub fn default_policy() -> Arc<dyn CmsAlgorithmUsagePolicy> {
    lift_policy(Arc::new(DisallowWeakAlgorithmsPolicy::default()))
}

/// The asn1crypto name of a signature algorithm OID.
pub fn signature_algorithm_name(oid: &ObjectIdentifier) -> String {
    match *oid {
        oids::RSA_ENCRYPTION => "rsassa_pkcs1v15",
        oids::MD2_WITH_RSA => "md2_rsa",
        oids::MD5_WITH_RSA => "md5_rsa",
        oids::SHA1_WITH_RSA => "sha1_rsa",
        oids::SHA224_WITH_RSA => "sha224_rsa",
        oids::SHA256_WITH_RSA => "sha256_rsa",
        oids::SHA384_WITH_RSA => "sha384_rsa",
        oids::SHA512_WITH_RSA => "sha512_rsa",
        oids::RSASSA_PSS => "rsassa_pss",
        oids::EC_PUBLIC_KEY | oids::ECDSA_GENERIC => "ecdsa",
        oids::ECDSA_WITH_SHA1 => "sha1_ecdsa",
        oids::ECDSA_WITH_SHA224 => "sha224_ecdsa",
        oids::ECDSA_WITH_SHA256 => "sha256_ecdsa",
        oids::ECDSA_WITH_SHA384 => "sha384_ecdsa",
        oids::ECDSA_WITH_SHA512 => "sha512_ecdsa",
        oids::DSA => "dsa",
        oids::DSA_WITH_SHA1 => "sha1_dsa",
        oids::DSA_WITH_SHA224 => "sha224_dsa",
        oids::DSA_WITH_SHA256 => "sha256_dsa",
        oids::ED25519 => "ed25519",
        oids::ED448 => "ed448",
        oids::ML_DSA_44 => "mldsa44",
        oids::ML_DSA_65 => "mldsa65",
        oids::ML_DSA_87 => "mldsa87",
        _ => return oid.to_string(),
    }
    .to_owned()
}

/// The asn1crypto name of a digest algorithm OID.
pub fn digest_name(oid: &ObjectIdentifier) -> String {
    digest_algorithm_name(oid).map_or_else(
        || match *oid {
            oids::SHA3_224 => "sha3_224".to_owned(),
            oids::SHA3_384 => "sha3_384".to_owned(),
            oids::SHA3_512 => "sha3_512".to_owned(),
            oids::SHAKE128 => "shake128".to_owned(),
            oids::SHAKE256 => "shake256".to_owned(),
            oids::SHAKE256_LEN => "shake256_len".to_owned(),
            _ => oid.to_string(),
        },
        str::to_owned,
    )
}

/// The digest implied by a signature algorithm (`SignedDigestAlgorithm.hash_algo`),
/// by name; `None` if the algorithm does not imply one.
fn implied_hash(sig: &AlgorithmIdentifierOwned) -> Option<String> {
    Some(
        match sig.oid {
            oids::MD2_WITH_RSA => "md2",
            oids::MD5_WITH_RSA => "md5",
            oids::SHA1_WITH_RSA | oids::ECDSA_WITH_SHA1 | oids::DSA_WITH_SHA1 => "sha1",
            oids::SHA224_WITH_RSA | oids::ECDSA_WITH_SHA224 | oids::DSA_WITH_SHA224 => "sha224",
            oids::SHA256_WITH_RSA | oids::ECDSA_WITH_SHA256 | oids::DSA_WITH_SHA256 => "sha256",
            oids::SHA384_WITH_RSA | oids::ECDSA_WITH_SHA384 => "sha384",
            oids::SHA512_WITH_RSA | oids::ECDSA_WITH_SHA512 => "sha512",
            oids::ED25519 => "sha512",
            oids::ED448 => "shake256",
            oids::RSASSA_PSS => {
                return SignatureMechanism::from_algorithm_identifier(sig, None)
                    .ok()
                    .and_then(|m| m.digest())
                    .map(|d| d.name().to_owned())
            }
            _ => return None,
        }
        .to_owned(),
    )
}

/// `_ensure_digest_match` (pyHanko `sign/validation/utils.py`).
pub fn ensure_digest_match(
    signature_algorithm: &AlgorithmIdentifierOwned,
    message_digest_algorithm: &AlgorithmIdentifierOwned,
) -> AlgorithmUsageConstraint {
    let sig_name = signature_algorithm_name(&signature_algorithm.oid);
    let md_name = digest_name(&message_digest_algorithm.oid);
    let table: Option<&[&str]> = match signature_algorithm.oid {
        oids::ED448 => Some(&["shake256", "shake256_len"]),
        oids::ML_DSA_44 => Some(&[
            "sha256", "sha3_256", "sha384", "sha3_384", "sha512", "sha3_512", "shake256",
            "shake256_len",
        ]),
        oids::ML_DSA_65 => Some(&[
            "sha384", "sha3_384", "sha512", "sha3_512", "shake256", "shake256_len",
        ]),
        oids::ML_DSA_87 => Some(&["sha512", "sha3_512", "shake256", "shake256_len"]),
        _ => None,
    };
    if let Some(allowed) = table {
        return if allowed.contains(&md_name.as_str()) {
            AlgorithmUsageConstraint::allowed()
        } else {
            AlgorithmUsageConstraint::denied(format!(
                "Digest algorithm {md_name} does not match value implied by signature algorithm {sig_name}"
            ))
        };
    }
    // asn1crypto compares the DER of `DigestAlgorithm({'algorithm': hash})`
    // with the message digest algorithm as encoded. For SHA-1 and SHA-2 that
    // constructor adds an explicit NULL parameter, for other digests it adds
    // none; any other encoding counts as a mismatch, and so it does here.
    if let Some(implied) = implied_hash(signature_algorithm) {
        let expect_null = matches!(
            implied.as_str(),
            "sha1" | "sha224" | "sha256" | "sha384" | "sha512"
        );
        let params_match = match &message_digest_algorithm.parameters {
            None => !expect_null,
            Some(p) => expect_null && der::Tagged::tag(p) == der::Tag::Null && p.value().is_empty(),
        };
        if implied != md_name || !params_match {
            return AlgorithmUsageConstraint::denied(format!(
                "Digest algorithm {md_name} does not match value implied by signature algorithm {sig_name}"
            ));
        }
    }
    AlgorithmUsageConstraint::allowed()
}
