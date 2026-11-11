// Derived from pyhanko-certvalidator `sig_validate.py`, `util.py` and
// `policy_decl.py` (MIT, see LICENSE-pyHanko).

//! Digest and signature algorithms.
//!
//! - [`DigestAlgorithm`]: SHA-1 and SHA-2 digests.
//! - [`SignatureMechanism`]: an `AlgorithmIdentifier` resolved to a concrete
//!   mechanism (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA, Ed25519), including the
//!   CMS convention where `rsaEncryption` or `id-ecPublicKey` appears as the
//!   signature algorithm and the digest comes from context.
//! - [`validate_signature`]: verify a raw signature, the equivalent of
//!   `DefaultSignatureValidator.validate_signature` in pyhanko-certvalidator.
//! - [`AlgorithmUsagePolicy`] and [`DisallowWeakAlgorithmsPolicy`]: policy hooks
//!   that decide whether an algorithm or key size is acceptable.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode, Sequence};
use sha2::Digest;
use signature::hazmat::PrehashVerifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::asn1::oids;
use crate::errors::SignatureError;
use crate::time::Moment;

/// A supported digest algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-1 (weak; only for legacy material).
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlgorithm {
    /// Resolve a digest algorithm OID.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Some(match *oid {
            oids::SHA1 => Self::Sha1,
            oids::SHA224 => Self::Sha224,
            oids::SHA256 => Self::Sha256,
            oids::SHA384 => Self::Sha384,
            oids::SHA512 => Self::Sha512,
            _ => return None,
        })
    }

    /// The algorithm OID.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha1 => oids::SHA1,
            Self::Sha224 => oids::SHA224,
            Self::Sha256 => oids::SHA256,
            Self::Sha384 => oids::SHA384,
            Self::Sha512 => oids::SHA512,
        }
    }

    /// The pyHanko / asn1crypto name (`sha256`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// `AlgorithmIdentifier` with absent parameters (RFC 5754).
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// Digest output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Compute the digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha224 => sha2::Sha224::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// Name of a digest algorithm OID, including ones we do not implement.
pub fn digest_algorithm_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    DigestAlgorithm::from_oid(oid)
        .map(DigestAlgorithm::name)
        .or(match *oid {
            oids::MD2 => Some("md2"),
            oids::MD5 => Some("md5"),
            oids::SHA3_256 => Some("sha3_256"),
            _ => None,
        })
}

/// `RSASSA-PSS-params` (RFC 4055). Absent fields take the ASN.1 defaults
/// (SHA-1, MGF1 with SHA-1, salt length 20, trailer field 1).
#[derive(Clone, Debug, Default, Eq, PartialEq, Sequence)]
pub struct RsaPssParams {
    /// Digest algorithm.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// Mask generation function.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub mask_gen_algorithm: Option<AlgorithmIdentifierOwned>,
    /// Salt length in bytes.
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub salt_length: Option<u32>,
    /// Trailer field; only 1 (0xBC) is defined.
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub trailer_field: Option<u32>,
}

/// Resolved PSS parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PssParameters {
    /// Message digest.
    pub digest: DigestAlgorithm,
    /// MGF1 digest.
    pub mgf1_digest: DigestAlgorithm,
    /// Salt length in bytes.
    pub salt_length: usize,
}

impl PssParameters {
    /// Resolve `RSASSA-PSS-params`, applying ASN.1 defaults.
    pub fn from_asn1(params: &RsaPssParams) -> Result<Self, SignatureError> {
        let unsupported = |what: String| SignatureError::AlgorithmNotSupported(what);
        let digest_oid = params.hash_algorithm.as_ref().map_or(oids::SHA1, |a| a.oid);
        let digest = DigestAlgorithm::from_oid(&digest_oid)
            .ok_or_else(|| unsupported(format!("PSS digest {digest_oid}")))?;
        let mgf1_digest = match &params.mask_gen_algorithm {
            None => DigestAlgorithm::Sha1,
            Some(mgf) if mgf.oid == oids::MGF1 => {
                let inner = mgf
                    .parameters
                    .as_ref()
                    .ok_or_else(|| SignatureError::Malformed("MGF1 without digest".into()))?
                    .decode_as::<AlgorithmIdentifierOwned>()
                    .map_err(|e| SignatureError::Malformed(format!("MGF1 parameters: {e}")))?;
                DigestAlgorithm::from_oid(&inner.oid)
                    .ok_or_else(|| unsupported(format!("MGF1 digest {}", inner.oid)))?
            }
            Some(mgf) => return Err(unsupported(format!("mask generation function {}", mgf.oid))),
        };
        if params.trailer_field.unwrap_or(1) != 1 {
            return Err(unsupported("PSS trailer field other than 1".into()));
        }
        let salt_length = usize::try_from(params.salt_length.unwrap_or(20))
            .map_err(|_| SignatureError::Malformed("PSS salt length".into()))?;
        Ok(Self {
            digest,
            mgf1_digest,
            salt_length,
        })
    }
}

/// A signature mechanism resolved from an `AlgorithmIdentifier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureMechanism {
    /// RSASSA-PKCS1-v1_5 with the given digest.
    RsaPkcs1v15(DigestAlgorithm),
    /// RSASSA-PSS.
    RsaPss(PssParameters),
    /// ECDSA with the given digest; the curve comes from the public key.
    Ecdsa(DigestAlgorithm),
    /// Ed25519 (pure).
    Ed25519,
}

impl SignatureMechanism {
    /// The pyHanko / asn1crypto name of the mechanism.
    pub fn name(&self) -> &'static str {
        match self {
            Self::RsaPkcs1v15(_) => "rsassa_pkcs1v15",
            Self::RsaPss(_) => "rsassa_pss",
            Self::Ecdsa(_) => "ecdsa",
            Self::Ed25519 => "ed25519",
        }
    }

    /// The digest the mechanism applies to the message, if any.
    pub fn digest(&self) -> Option<DigestAlgorithm> {
        match self {
            Self::RsaPkcs1v15(d) | Self::Ecdsa(d) => Some(*d),
            Self::RsaPss(p) => Some(p.digest),
            Self::Ed25519 => None,
        }
    }

    /// Resolve `algorithm`. `contextual_digest` supplies the digest when the
    /// identifier does not carry one, as with `rsaEncryption` in a CMS
    /// `SignerInfo` (the `contextual_md_algorithm` of pyhanko-certvalidator).
    pub fn from_algorithm_identifier(
        algorithm: &AlgorithmIdentifierOwned,
        contextual_digest: Option<DigestAlgorithm>,
    ) -> Result<Self, SignatureError> {
        use DigestAlgorithm::*;
        let contextual = || {
            contextual_digest.ok_or_else(|| {
                SignatureError::AlgorithmNotSupported(format!(
                    "{} requires a digest algorithm from context",
                    algorithm.oid
                ))
            })
        };
        Ok(match algorithm.oid {
            oids::SHA1_WITH_RSA => Self::RsaPkcs1v15(Sha1),
            oids::SHA224_WITH_RSA => Self::RsaPkcs1v15(Sha224),
            oids::SHA256_WITH_RSA => Self::RsaPkcs1v15(Sha256),
            oids::SHA384_WITH_RSA => Self::RsaPkcs1v15(Sha384),
            oids::SHA512_WITH_RSA => Self::RsaPkcs1v15(Sha512),
            oids::RSA_ENCRYPTION => Self::RsaPkcs1v15(contextual()?),
            oids::RSASSA_PSS => {
                let params = match &algorithm.parameters {
                    Some(any) => any
                        .decode_as::<RsaPssParams>()
                        .map_err(|e| SignatureError::Malformed(format!("PSS parameters: {e}")))?,
                    None => RsaPssParams::default(),
                };
                Self::RsaPss(PssParameters::from_asn1(&params)?)
            }
            oids::ECDSA_WITH_SHA1 => Self::Ecdsa(Sha1),
            oids::ECDSA_WITH_SHA224 => Self::Ecdsa(Sha224),
            oids::ECDSA_WITH_SHA256 => Self::Ecdsa(Sha256),
            oids::ECDSA_WITH_SHA384 => Self::Ecdsa(Sha384),
            oids::ECDSA_WITH_SHA512 => Self::Ecdsa(Sha512),
            oids::EC_PUBLIC_KEY => Self::Ecdsa(contextual()?),
            oids::ED25519 => Self::Ed25519,
            other => {
                let name = match other {
                    oids::ED448 => "ed448".to_owned(),
                    oids::DSA
                    | oids::DSA_WITH_SHA1
                    | oids::DSA_WITH_SHA224
                    | oids::DSA_WITH_SHA256 => "dsa".to_owned(),
                    oids::ML_DSA_44 | oids::ML_DSA_65 | oids::ML_DSA_87 => "ml-dsa".to_owned(),
                    oids::MD2_WITH_RSA | oids::MD5_WITH_RSA => {
                        "rsassa_pkcs1v15 with md2/md5".to_owned()
                    }
                    _ => other.to_string(),
                };
                return Err(SignatureError::AlgorithmNotSupported(format!(
                    "Signature mechanism {name} is not supported."
                )));
            }
        })
    }
}

/// Context for [`validate_signature`], mirroring pyhanko-certvalidator's
/// `SignatureValidationContext`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignatureValidationContext {
    /// Digest to use when the signature algorithm does not specify one.
    pub contextual_digest: Option<DigestAlgorithm>,
    /// `signed_data` is already the message digest.
    pub prehashed: bool,
}

/// Verify `signature` over `signed_data` with `public_key`.
///
/// Port of `DefaultSignatureValidator.validate_signature`. Any failure,
/// including malformed keys or signatures, returns an error; the function
/// does not panic on untrusted input.
pub fn validate_signature(
    signature: &[u8],
    signed_data: &[u8],
    public_key: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    context: &SignatureValidationContext,
) -> Result<(), SignatureError> {
    let key_oid = public_key.algorithm.oid;
    if key_oid == oids::DSA {
        if public_key.algorithm.parameters.is_none() {
            return Err(SignatureError::DsaParametersUnavailable);
        }
        return Err(SignatureError::AlgorithmNotSupported(
            "Signature mechanism dsa is not supported.".into(),
        ));
    }
    let mechanism =
        SignatureMechanism::from_algorithm_identifier(algorithm, context.contextual_digest)?;

    // An id-RSASSA-PSS key may restrict its parameters; they must then match
    // the parameters on the signature.
    if key_oid == oids::RSASSA_PSS {
        if let Some(key_params) = &public_key.algorithm.parameters {
            let sig_params = algorithm.parameters.as_ref();
            let same = sig_params.is_some_and(|p| p.to_der().ok() == key_params.to_der().ok());
            if !same || algorithm.oid != oids::RSASSA_PSS {
                return Err(SignatureError::PssParameterMismatch);
            }
        }
    }

    let prehash = |digest: DigestAlgorithm| -> Vec<u8> {
        if context.prehashed {
            signed_data.to_vec()
        } else {
            digest.digest(signed_data)
        }
    };
    let key_bits = public_key.subject_public_key.raw_bytes();
    let invalid = |_| SignatureError::InvalidSignature;

    match mechanism {
        SignatureMechanism::RsaPkcs1v15(digest) => {
            let key = rsa_key(key_oid, key_bits)?;
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(invalid)?;
            let hash = prehash(digest);
            match digest {
                DigestAlgorithm::Sha1 => {
                    rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key).verify_prehash(&hash, &sig)
                }
                DigestAlgorithm::Sha224 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha224>::new(key)
                    .verify_prehash(&hash, &sig),
                DigestAlgorithm::Sha256 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
                    .verify_prehash(&hash, &sig),
                DigestAlgorithm::Sha384 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key)
                    .verify_prehash(&hash, &sig),
                DigestAlgorithm::Sha512 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key)
                    .verify_prehash(&hash, &sig),
            }
            .map_err(invalid)
        }
        SignatureMechanism::RsaPss(params) => {
            if params.mgf1_digest != params.digest {
                return Err(SignatureError::AlgorithmNotSupported(
                    "PSS with an MGF1 digest different from the message digest".into(),
                ));
            }
            let key = rsa_key(key_oid, key_bits)?;
            let sig = rsa::pss::Signature::try_from(signature).map_err(invalid)?;
            let hash = prehash(params.digest);
            let salt = params.salt_length;
            match params.digest {
                DigestAlgorithm::Sha1 => {
                    rsa::pss::VerifyingKey::<sha1::Sha1>::new_with_salt_len(key, salt)
                        .verify_prehash(&hash, &sig)
                }
                DigestAlgorithm::Sha224 => {
                    rsa::pss::VerifyingKey::<sha2::Sha224>::new_with_salt_len(key, salt)
                        .verify_prehash(&hash, &sig)
                }
                DigestAlgorithm::Sha256 => {
                    rsa::pss::VerifyingKey::<sha2::Sha256>::new_with_salt_len(key, salt)
                        .verify_prehash(&hash, &sig)
                }
                DigestAlgorithm::Sha384 => {
                    rsa::pss::VerifyingKey::<sha2::Sha384>::new_with_salt_len(key, salt)
                        .verify_prehash(&hash, &sig)
                }
                DigestAlgorithm::Sha512 => {
                    rsa::pss::VerifyingKey::<sha2::Sha512>::new_with_salt_len(key, salt)
                        .verify_prehash(&hash, &sig)
                }
            }
            .map_err(invalid)
        }
        SignatureMechanism::Ecdsa(digest) => {
            if key_oid != oids::EC_PUBLIC_KEY {
                return Err(SignatureError::KeyMismatch(format!(
                    "ECDSA signature with {key_oid} key"
                )));
            }
            let curve = public_key
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or_else(|| SignatureError::Malformed("EC key without named curve".into()))?;
            let hash = prehash(digest);
            match curve {
                oids::SECP256R1 => {
                    ecdsa_verify::verify::<p256::NistP256>(key_bits, signature, &hash)
                }
                oids::SECP384R1 => {
                    ecdsa_verify::verify::<p384::NistP384>(key_bits, signature, &hash)
                }
                oids::SECP521R1 => {
                    ecdsa_verify::verify::<p521::NistP521>(key_bits, signature, &hash)
                }
                other => Err(SignatureError::AlgorithmNotSupported(format!(
                    "elliptic curve {other}"
                ))),
            }
        }
        SignatureMechanism::Ed25519 => {
            if key_oid != oids::ED25519 {
                return Err(SignatureError::KeyMismatch(format!(
                    "Ed25519 signature with {key_oid} key"
                )));
            }
            if context.prehashed {
                return Err(SignatureError::AlgorithmNotSupported(
                    "prehashed Ed25519".into(),
                ));
            }
            let key_bytes: &[u8; 32] = key_bits
                .try_into()
                .map_err(|_| SignatureError::Malformed("Ed25519 key length".into()))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
                .map_err(|e| SignatureError::Malformed(format!("Ed25519 key: {e}")))?;
            let sig = ed25519_dalek::Signature::from_slice(signature).map_err(invalid)?;
            signature::Verifier::verify(&key, signed_data, &sig).map_err(invalid)
        }
    }
}

fn rsa_key(
    key_oid: ObjectIdentifier,
    key_bits: &[u8],
) -> Result<rsa::RsaPublicKey, SignatureError> {
    if key_oid != oids::RSA_ENCRYPTION && key_oid != oids::RSASSA_PSS {
        return Err(SignatureError::KeyMismatch(format!(
            "RSA signature with {key_oid} key"
        )));
    }
    use rsa::pkcs1::DecodeRsaPublicKey;
    rsa::RsaPublicKey::from_pkcs1_der(key_bits)
        .map_err(|e| SignatureError::Malformed(format!("RSA key: {e}")))
}

/// Generic ECDSA verification over the RustCrypto curve types.
mod ecdsa_verify {
    use super::SignatureError;
    use ecdsa::{der::Signature as DerSignature, VerifyingKey};
    use signature::hazmat::PrehashVerifier;

    /// Curves for which `ecdsa::VerifyingKey` supports DER signatures and SEC1 keys.
    pub trait Curve: ecdsa::EcdsaCurve {
        fn verify(key: &[u8], sig: &[u8], hash: &[u8]) -> Result<(), SignatureError>;
    }

    macro_rules! impl_curve {
        ($curve:ty) => {
            impl Curve for $curve {
                fn verify(key: &[u8], sig: &[u8], hash: &[u8]) -> Result<(), SignatureError> {
                    let key = VerifyingKey::<$curve>::from_sec1_bytes(key)
                        .map_err(|_| SignatureError::Malformed("EC public key".into()))?;
                    let sig = DerSignature::<$curve>::from_bytes(sig)
                        .map_err(|_| SignatureError::InvalidSignature)?;
                    key.verify_prehash(hash, &sig)
                        .map_err(|_| SignatureError::InvalidSignature)
                }
            }
        };
    }
    impl_curve!(p256::NistP256);
    impl_curve!(p384::NistP384);
    impl_curve!(p521::NistP521);

    pub fn verify<C: Curve>(key: &[u8], sig: &[u8], hash: &[u8]) -> Result<(), SignatureError> {
        C::verify(key, sig, hash)
    }
}

/// Size in bits of an RSA public key, or `None` for other key types.
pub fn rsa_key_size(public_key: &SubjectPublicKeyInfoOwned) -> Option<usize> {
    let oid = public_key.algorithm.oid;
    if oid != oids::RSA_ENCRYPTION && oid != oids::RSASSA_PSS {
        return None;
    }
    use rsa::traits::PublicKeyParts;
    rsa_key(oid, public_key.subject_public_key.raw_bytes())
        .ok()
        .map(|k| k.n().bit_width() as usize)
}

/// Whether an algorithm may be used, with a reason if not
/// (`AlgorithmUsageConstraint` in pyhanko-certvalidator).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmUsageConstraint {
    /// `true` if the algorithm may be used.
    pub allowed: bool,
    /// Why the algorithm may not be used.
    pub failure_reason: Option<String>,
}

impl AlgorithmUsageConstraint {
    /// An "allowed" constraint.
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            failure_reason: None,
        }
    }

    /// A "not allowed" constraint with a reason.
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            failure_reason: Some(reason.into()),
        }
    }
}

/// Policy hook deciding which algorithms are acceptable
/// (`AlgorithmUsagePolicy` in pyhanko-certvalidator).
pub trait AlgorithmUsagePolicy: Send + Sync + std::fmt::Debug {
    /// Whether a digest algorithm may be used at `moment`.
    fn digest_algorithm_allowed(
        &self,
        algorithm: &ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint;

    /// Whether a signature algorithm may be used at `moment` with `public_key`.
    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint;

    /// Minimum RSA modulus size, used to configure RFC 5280 path validation.
    fn min_rsa_key_size(&self) -> usize {
        2048
    }
}

/// Deny-list policy (`DisallowWeakAlgorithmsPolicy` in pyhanko-certvalidator).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisallowWeakAlgorithmsPolicy {
    /// Digest algorithm names considered weak (`md2`, `md5`, `sha1`, ...).
    pub weak_hash_algos: Vec<String>,
    /// Signature mechanism names considered weak.
    pub weak_signature_algos: Vec<String>,
    /// Minimum RSA key size in bits.
    pub rsa_key_size_threshold: usize,
}

/// pyhanko-certvalidator's `DEFAULT_WEAK_HASH_ALGOS`.
pub const DEFAULT_WEAK_HASH_ALGOS: [&str; 3] = ["md2", "md5", "sha1"];

impl Default for DisallowWeakAlgorithmsPolicy {
    fn default() -> Self {
        Self {
            weak_hash_algos: DEFAULT_WEAK_HASH_ALGOS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            weak_signature_algos: Vec::new(),
            rsa_key_size_threshold: 2048,
        }
    }
}

impl DisallowWeakAlgorithmsPolicy {
    /// Policy with a custom weak-hash list and the other defaults.
    pub fn with_weak_hash_algos(algos: &[&str]) -> Self {
        Self {
            weak_hash_algos: algos.iter().map(|s| (*s).to_owned()).collect(),
            ..Self::default()
        }
    }

    fn is_weak_hash(&self, name: &str) -> bool {
        self.weak_hash_algos.iter().any(|w| w == name)
    }
}

impl AlgorithmUsagePolicy for DisallowWeakAlgorithmsPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &ObjectIdentifier,
        _moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        let name =
            digest_algorithm_name(algorithm).map_or_else(|| algorithm.to_string(), str::to_owned);
        if self.is_weak_hash(&name) {
            AlgorithmUsageConstraint::denied(format!("Digest algorithm {name} is banned"))
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }

    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
        public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        let digest = match algorithm.oid {
            oids::MD2_WITH_RSA => Some("md2"),
            oids::MD5_WITH_RSA => Some("md5"),
            _ => SignatureMechanism::from_algorithm_identifier(algorithm, None)
                .ok()
                .and_then(|m| m.digest())
                .map(DigestAlgorithm::name),
        };
        if let Some(d) = digest.filter(|d| self.is_weak_hash(d)) {
            return AlgorithmUsageConstraint::denied(format!("Digest algorithm {d} is banned"));
        }
        let mech_name =
            SignatureMechanism::from_algorithm_identifier(algorithm, Some(DigestAlgorithm::Sha256))
                .map(|m| m.name())
                .unwrap_or("unknown");
        if self.weak_signature_algos.iter().any(|w| w == mech_name) {
            return AlgorithmUsageConstraint::denied(format!(
                "Signature algorithm {mech_name} is banned"
            ));
        }
        if let Some(size) = public_key.and_then(rsa_key_size) {
            if size < self.rsa_key_size_threshold {
                return AlgorithmUsageConstraint::denied(format!(
                    "Key size {size} for algorithm {mech_name} is considered too small; policy mandates >= {}",
                    self.rsa_key_size_threshold
                ));
            }
        }
        AlgorithmUsageConstraint::allowed()
    }

    fn min_rsa_key_size(&self) -> usize {
        self.rsa_key_size_threshold
    }
}

/// Helper: parse a DER `AlgorithmIdentifier`.
pub fn parse_algorithm_identifier(der: &[u8]) -> Result<AlgorithmIdentifierOwned, SignatureError> {
    AlgorithmIdentifierOwned::from_der(der).map_err(|e| SignatureError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_oids_round_trip() {
        for d in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            assert_eq!(DigestAlgorithm::from_oid(&d.oid()), Some(d));
            assert_eq!(d.digest(b"abc").len(), d.output_len());
        }
    }

    #[test]
    fn rsa_encryption_needs_contextual_digest() {
        let alg = AlgorithmIdentifierOwned {
            oid: oids::RSA_ENCRYPTION,
            parameters: None,
        };
        assert!(matches!(
            SignatureMechanism::from_algorithm_identifier(&alg, None),
            Err(SignatureError::AlgorithmNotSupported(_))
        ));
        assert_eq!(
            SignatureMechanism::from_algorithm_identifier(&alg, Some(DigestAlgorithm::Sha384)),
            Ok(SignatureMechanism::RsaPkcs1v15(DigestAlgorithm::Sha384))
        );
    }

    #[test]
    fn pss_defaults_are_sha1_salt_20() {
        let alg = AlgorithmIdentifierOwned {
            oid: oids::RSASSA_PSS,
            parameters: None,
        };
        let mech = SignatureMechanism::from_algorithm_identifier(&alg, None).expect("pss");
        assert_eq!(
            mech,
            SignatureMechanism::RsaPss(PssParameters {
                digest: DigestAlgorithm::Sha1,
                mgf1_digest: DigestAlgorithm::Sha1,
                salt_length: 20
            })
        );
    }

    #[test]
    fn weak_hash_policy() {
        let policy = DisallowWeakAlgorithmsPolicy::default();
        assert!(!policy.digest_algorithm_allowed(&oids::SHA1, None).allowed);
        assert!(policy.digest_algorithm_allowed(&oids::SHA256, None).allowed);
        let sha1_rsa = AlgorithmIdentifierOwned {
            oid: oids::SHA1_WITH_RSA,
            parameters: None,
        };
        assert!(
            !policy
                .signature_algorithm_allowed(&sha1_rsa, None, None)
                .allowed
        );
        let lenient = DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&["md2", "md5"]);
        assert!(
            lenient
                .signature_algorithm_allowed(&sha1_rsa, None, None)
                .allowed
        );
    }
}
