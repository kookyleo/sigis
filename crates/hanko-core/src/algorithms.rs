// Derived from pyhanko-certvalidator `sig_validate.py`, `util.py` and
// `policy_decl.py` (MIT, see LICENSE-pyHanko).

//! Digest and signature algorithms.
//!
//! - [`DigestAlgorithm`]: MD5, SHA-1, SHA-2, SHA-3 and SHAKE256 digests.
//! - [`SignatureMechanism`]: an `AlgorithmIdentifier` resolved to a concrete
//!   mechanism (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA, DSA, Ed25519, Ed448),
//!   including the
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
    /// MD5 (weak; only to report legacy material).
    Md5,
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
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE256 with a 512-bit output (RFC 8419; `id-shake256-len` with
    /// any length parameter is treated the same way, as pyHanko does).
    Shake256,
}

impl DigestAlgorithm {
    /// Every supported digest algorithm.
    pub const ALL: [Self; 11] = [
        Self::Md5,
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Shake256,
    ];

    /// Resolve an asn1crypto digest name (`sha256`, `sha3_256`, ...).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == name)
    }

    /// Resolve a digest algorithm OID.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Some(match *oid {
            oids::SHA1 => Self::Sha1,
            oids::SHA224 => Self::Sha224,
            oids::SHA256 => Self::Sha256,
            oids::SHA384 => Self::Sha384,
            oids::SHA512 => Self::Sha512,
            oids::MD5 => Self::Md5,
            oids::SHA3_224 => Self::Sha3_224,
            oids::SHA3_256 => Self::Sha3_256,
            oids::SHA3_384 => Self::Sha3_384,
            oids::SHA3_512 => Self::Sha3_512,
            oids::SHAKE256 | oids::SHAKE256_LEN => Self::Shake256,
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
            Self::Md5 => oids::MD5,
            Self::Sha3_224 => oids::SHA3_224,
            Self::Sha3_256 => oids::SHA3_256,
            Self::Sha3_384 => oids::SHA3_384,
            Self::Sha3_512 => oids::SHA3_512,
            Self::Shake256 => oids::SHAKE256,
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
            Self::Md5 => "md5",
            Self::Sha3_224 => "sha3_224",
            Self::Sha3_256 => "sha3_256",
            Self::Sha3_384 => "sha3_384",
            Self::Sha3_512 => "sha3_512",
            Self::Shake256 => "shake256",
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
            Self::Sha512 | Self::Sha3_512 | Self::Shake256 => 64,
            Self::Md5 => 16,
            Self::Sha3_224 => 28,
            Self::Sha3_256 => 32,
            Self::Sha3_384 => 48,
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
            Self::Md5 => md5::Md5::digest(data).to_vec(),
            Self::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
            Self::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
            Self::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
            Self::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
            Self::Shake256 => {
                use sha3::digest::{ExtendableOutput, Update, XofReader};
                let mut hasher = sha3::Shake256::default();
                hasher.update(data);
                let mut out = vec![0u8; 64];
                hasher.finalize_xof().read(&mut out);
                out
            }
        }
    }

    /// Whether the algorithm is SHA-1 or a SHA-2 digest (asn1crypto encodes
    /// these with explicit NULL parameters).
    pub fn is_sha1_or_sha2(self) -> bool {
        matches!(
            self,
            Self::Sha1 | Self::Sha224 | Self::Sha256 | Self::Sha384 | Self::Sha512
        )
    }
}

/// asn1crypto name of a digest algorithm OID, including ones we do not
/// implement.
pub fn digest_algorithm_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    match *oid {
        oids::MD2 => Some("md2"),
        oids::SHAKE128 => Some("shake128"),
        oids::SHAKE256_LEN => Some("shake256_len"),
        _ => DigestAlgorithm::from_oid(oid).map(DigestAlgorithm::name),
    }
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
        // SHAKE256 is an extendable-output function; pyca/cryptography does
        // not accept it for PSS.
        let digest = DigestAlgorithm::from_oid(&digest_oid)
            .filter(|d| *d != DigestAlgorithm::Shake256)
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
                    .filter(|d| *d != DigestAlgorithm::Shake256)
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
    /// DSA with the given digest; the domain parameters come from the
    /// public key.
    Dsa(DigestAlgorithm),
    /// Ed25519 (pure).
    Ed25519,
    /// Ed448 (pure, empty context).
    Ed448,
}

impl SignatureMechanism {
    /// The pyHanko / asn1crypto name of the mechanism.
    pub fn name(&self) -> &'static str {
        match self {
            Self::RsaPkcs1v15(_) => "rsassa_pkcs1v15",
            Self::RsaPss(_) => "rsassa_pss",
            Self::Ecdsa(_) => "ecdsa",
            Self::Dsa(_) => "dsa",
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
        }
    }

    /// The digest the mechanism applies to the message, if any.
    pub fn digest(&self) -> Option<DigestAlgorithm> {
        match self {
            Self::RsaPkcs1v15(d) | Self::Ecdsa(d) | Self::Dsa(d) => Some(*d),
            Self::RsaPss(p) => Some(p.digest),
            Self::Ed25519 | Self::Ed448 => None,
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
            oids::MD5_WITH_RSA | oids::MD5_WITH_RSA_OIW => Self::RsaPkcs1v15(Md5),
            oids::SHA1_WITH_RSA | oids::SHA1_WITH_RSA_OIW => Self::RsaPkcs1v15(Sha1),
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
            // asn1crypto knows no digest for the ECDSA-with-SHA3 OIDs, so
            // pyhanko-certvalidator takes the digest from context for them.
            oids::EC_PUBLIC_KEY
            | oids::ECDSA_GENERIC
            | oids::ECDSA_WITH_SHA3_224
            | oids::ECDSA_WITH_SHA3_256
            | oids::ECDSA_WITH_SHA3_384
            | oids::ECDSA_WITH_SHA3_512 => Self::Ecdsa(contextual()?),
            oids::DSA_WITH_SHA1 | oids::DSA_WITH_SHA_OIW | oids::DSA_WITH_SHA1_OIW => {
                Self::Dsa(Sha1)
            }
            oids::DSA_WITH_SHA224 => Self::Dsa(Sha224),
            oids::DSA_WITH_SHA256 => Self::Dsa(Sha256),
            oids::DSA => Self::Dsa(contextual()?),
            oids::ED25519 => Self::Ed25519,
            oids::ED448 => Self::Ed448,
            other => {
                let name = match other {
                    oids::ML_DSA_44 | oids::ML_DSA_65 | oids::ML_DSA_87 => "ml-dsa".to_owned(),
                    oids::MD2_WITH_RSA => "rsassa_pkcs1v15 with md2".to_owned(),
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
    let mechanism =
        SignatureMechanism::from_algorithm_identifier(algorithm, context.contextual_digest)?;
    if matches!(mechanism, SignatureMechanism::Dsa(_)) && public_key.algorithm.parameters.is_none()
    {
        return Err(SignatureError::DsaParametersUnavailable);
    }

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

    let prehash = |digest: DigestAlgorithm| -> Result<Vec<u8>, SignatureError> {
        if context.prehashed {
            if signed_data.len() != digest.output_len() {
                return Err(SignatureError::InvalidSignature);
            }
            Ok(signed_data.to_vec())
        } else {
            Ok(digest.digest(signed_data))
        }
    };
    // pyca/cryptography accepts no extendable-output function for RSA,
    // ECDSA or DSA.
    if mechanism.digest() == Some(DigestAlgorithm::Shake256) {
        return Err(SignatureError::AlgorithmNotSupported(format!(
            "Signature mechanism {} with shake256 is not supported.",
            mechanism.name()
        )));
    }
    let key_bits = public_key.subject_public_key.raw_bytes();
    let invalid = |_| SignatureError::InvalidSignature;

    match mechanism {
        SignatureMechanism::RsaPkcs1v15(digest) => {
            let key = rsa_key(key_oid, key_bits)?;
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(invalid)?;
            let hash = prehash(digest)?;
            match digest {
                DigestAlgorithm::Md5 => pkcs1_verify::<md5::Md5>(key, &hash, &sig),
                DigestAlgorithm::Sha1 => pkcs1_verify::<sha1::Sha1>(key, &hash, &sig),
                DigestAlgorithm::Sha224 => pkcs1_verify::<sha2::Sha224>(key, &hash, &sig),
                DigestAlgorithm::Sha256 => pkcs1_verify::<sha2::Sha256>(key, &hash, &sig),
                DigestAlgorithm::Sha384 => pkcs1_verify::<sha2::Sha384>(key, &hash, &sig),
                DigestAlgorithm::Sha512 => pkcs1_verify::<sha2::Sha512>(key, &hash, &sig),
                DigestAlgorithm::Sha3_224 => pkcs1_verify::<sha3::Sha3_224>(key, &hash, &sig),
                DigestAlgorithm::Sha3_256 => pkcs1_verify::<sha3::Sha3_256>(key, &hash, &sig),
                DigestAlgorithm::Sha3_384 => pkcs1_verify::<sha3::Sha3_384>(key, &hash, &sig),
                DigestAlgorithm::Sha3_512 => pkcs1_verify::<sha3::Sha3_512>(key, &hash, &sig),
                DigestAlgorithm::Shake256 => Err(signature::Error::new()),
            }
            .map_err(invalid)
        }
        SignatureMechanism::RsaPss(params) => {
            let key = rsa_key(key_oid, key_bits)?;
            let hash = prehash(params.digest)?;
            if params.mgf1_digest != params.digest || !params.digest.is_sha1_or_sha2() {
                // The rsa crate ties MGF1 to the message digest; verify the
                // encoding directly (RFC 8017 §9.1.2), as pyca does.
                return pss_verify_any(&key, signature, &hash, &params);
            }
            let sig = rsa::pss::Signature::try_from(signature).map_err(invalid)?;
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
                _ => return pss_verify_any(&key, signature, &hash, &params),
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
            let hash = prehash(digest)?;
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
        SignatureMechanism::Ed448 => {
            if key_oid != oids::ED448 {
                return Err(SignatureError::KeyMismatch(format!(
                    "Ed448 signature with {key_oid} key"
                )));
            }
            if context.prehashed {
                return Err(SignatureError::AlgorithmNotSupported(
                    "prehashed Ed448".into(),
                ));
            }
            let key_bytes: &[u8; 57] = key_bits
                .try_into()
                .map_err(|_| SignatureError::Malformed("Ed448 key length".into()))?;
            let key = ed448_goldilocks::VerifyingKey::from_bytes(key_bytes)
                .map_err(|e| SignatureError::Malformed(format!("Ed448 key: {e}")))?;
            let sig = ed448_goldilocks::Signature::from_slice(signature).map_err(invalid)?;
            key.verify_raw(&sig, signed_data)
                .map_err(|_| SignatureError::InvalidSignature)
        }
        SignatureMechanism::Dsa(digest) => {
            if key_oid != oids::DSA {
                return Err(SignatureError::KeyMismatch(format!(
                    "DSA signature with {key_oid} key"
                )));
            }
            let spki_der = public_key
                .to_der()
                .map_err(|e| SignatureError::Malformed(format!("DSA key: {e}")))?;
            let spki = spki::SubjectPublicKeyInfoRef::from_der(&spki_der)
                .map_err(|e| SignatureError::Malformed(format!("DSA key: {e}")))?;
            // Only the FIPS 186 sizes (L, N) = (1024, 160), (2048, 224),
            // (2048, 256), (3072, 256) are accepted.
            let key = dsa::VerifyingKey::try_from(spki)
                .map_err(|e| SignatureError::Malformed(format!("DSA key: {e}")))?;
            let sig = dsa::Signature::from_der(signature)
                .map_err(|_| SignatureError::InvalidSignature)?;
            let hash = prehash(digest)?;
            key.verify_prehash(&hash, &sig).map_err(invalid)
        }
    }
}

/// RSASSA-PKCS1-v1_5 verification of a message digest with `D`'s
/// `DigestInfo` prefix.
fn pkcs1_verify<D>(
    key: rsa::RsaPublicKey,
    hash: &[u8],
    sig: &rsa::pkcs1v15::Signature,
) -> Result<(), signature::Error>
where
    D: Digest + const_oid::AssociatedOid,
{
    rsa::pkcs1v15::VerifyingKey::<D>::new(key).verify_prehash(hash, sig)
}

/// RSASSA-PSS verification for any combination of message digest and MGF1
/// digest (RFC 8017 §8.1.2 and §9.1.2). `m_hash` is the message digest.
fn pss_verify_any(
    key: &rsa::RsaPublicKey,
    signature: &[u8],
    m_hash: &[u8],
    params: &PssParameters,
) -> Result<(), SignatureError> {
    use rsa::traits::PublicKeyParts;
    let invalid = SignatureError::InvalidSignature;
    // RSAVP1 and I2OSP.
    if signature.len() != key.size() {
        return Err(invalid);
    }
    let s = rsa::BoxedUint::from_be_slice(signature, key.n_bits_precision())
        .map_err(|_| SignatureError::InvalidSignature)?;
    if s >= *key.n().as_ref() {
        return Err(invalid);
    }
    // RSAVP1: m = s^e mod n (square and multiply; public values only).
    let n = key.n();
    let mut m = rsa::BoxedUint::one_with_precision(s.bits_precision());
    for byte in key.e().to_be_bytes().iter() {
        for i in (0..8).rev() {
            m = m.mul_mod(&m, n);
            if (byte >> i) & 1 == 1 {
                m = m.mul_mod(&s, n);
            }
        }
    }
    let em_bits = (key.n().bit_width() as usize).saturating_sub(1);
    let em_len = em_bits.div_ceil(8);
    let m_bytes = m.to_be_bytes();
    let significant = m_bytes.iter().skip_while(|b| **b == 0).count();
    if significant > em_len {
        return Err(invalid);
    }
    let mut em = vec![0u8; em_len];
    em[em_len - significant..].copy_from_slice(&m_bytes[m_bytes.len() - significant..]);

    // EMSA-PSS-VERIFY.
    let h_len = params.digest.output_len();
    let s_len = params.salt_length;
    if m_hash.len() != h_len || em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
        return Err(invalid);
    }
    let db_len = em_len - h_len - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..h_len];
    let zero_bits = 8 * em_len - em_bits;
    let top_mask = (0xffu16 << (8 - zero_bits)) as u8;
    if masked_db[0] & top_mask != 0 {
        return Err(invalid);
    }
    // MGF1 with the MGF digest.
    let mut db = Vec::with_capacity(db_len);
    let mut counter: u32 = 0;
    while db.len() < db_len {
        let mut input = h.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        db.extend(params.mgf1_digest.digest(&input));
        counter = counter.wrapping_add(1);
    }
    db.truncate(db_len);
    for (d, m) in db.iter_mut().zip(masked_db) {
        *d ^= m;
    }
    db[0] &= !top_mask;
    let ps_len = em_len - h_len - s_len - 2;
    if db[..ps_len].iter().any(|b| *b != 0) || db[ps_len] != 0x01 {
        return Err(invalid);
    }
    let salt = &db[db_len - s_len..];
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    if params.digest.digest(&m_prime) != h {
        return Err(invalid);
    }
    Ok(())
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

/// Size in bits of a DSA public key (the bit length of `p`), or `None` for
/// other key types or unreadable parameters.
pub fn dsa_key_size(public_key: &SubjectPublicKeyInfoOwned) -> Option<usize> {
    if public_key.algorithm.oid != oids::DSA {
        return None;
    }
    let params = public_key.algorithm.parameters.as_ref()?;
    let mut reader = der::SliceReader::new(params.value()).ok()?;
    let p = der::asn1::UintRef::decode(&mut reader).ok()?;
    let bytes = p.as_bytes();
    let first = *bytes.first()?;
    Some(bytes.len() * 8 - first.leading_zeros() as usize)
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

    /// For CMS policies (pyHanko `CMSAlgorithmUsagePolicy`): whether the
    /// message digest algorithm may be combined with the signature
    /// algorithm. `None` (the default) means the policy is not a CMS
    /// policy; CMS validation then applies the default rule (the digest
    /// implied by the signature algorithm, RFC 8933).
    fn digest_combination(
        &self,
        _signature_algorithm: &AlgorithmIdentifierOwned,
        _message_digest_algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
    ) -> Option<AlgorithmUsageConstraint> {
        None
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
    /// Minimum DSA key size in bits (size of `p`; pyHanko's default is
    /// 3192).
    pub dsa_key_size_threshold: usize,
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
            dsa_key_size_threshold: 3192,
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
        let sized = if mech_name.starts_with("rsa") {
            public_key
                .and_then(rsa_key_size)
                .map(|size| (size, self.rsa_key_size_threshold))
        } else if mech_name == "dsa" {
            public_key
                .and_then(dsa_key_size)
                .map(|size| (size, self.dsa_key_size_threshold))
        } else {
            None
        };
        if let Some((size, threshold)) = sized.filter(|(size, threshold)| size < threshold) {
            return AlgorithmUsageConstraint::denied(format!(
                "Key size {size} for algorithm {mech_name} is considered too small; policy mandates >= {threshold}"
            ));
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
        for d in DigestAlgorithm::ALL {
            assert_eq!(DigestAlgorithm::from_oid(&d.oid()), Some(d));
            assert_eq!(DigestAlgorithm::from_name(d.name()), Some(d));
            assert_eq!(d.digest(b"abc").len(), d.output_len());
            assert_eq!(digest_algorithm_name(&d.oid()), Some(d.name()));
        }
        assert_eq!(
            DigestAlgorithm::from_oid(&oids::SHAKE256_LEN),
            Some(DigestAlgorithm::Shake256)
        );
        assert_eq!(
            digest_algorithm_name(&oids::SHAKE256_LEN),
            Some("shake256_len")
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn new_digests_known_answers() {
        assert_eq!(
            hex(&DigestAlgorithm::Md5.digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&DigestAlgorithm::Sha3_256.digest(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(&DigestAlgorithm::Shake256.digest(b"abc")),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
             d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }

    #[test]
    fn sha3_ecdsa_takes_the_digest_from_context() {
        let alg = AlgorithmIdentifierOwned {
            oid: oids::ECDSA_WITH_SHA3_256,
            parameters: None,
        };
        assert!(SignatureMechanism::from_algorithm_identifier(&alg, None).is_err());
        assert_eq!(
            SignatureMechanism::from_algorithm_identifier(&alg, Some(DigestAlgorithm::Sha256))
                .expect("mechanism"),
            SignatureMechanism::Ecdsa(DigestAlgorithm::Sha256)
        );
    }

    #[test]
    fn shake256_is_rejected_outside_eddsa() {
        let key = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: oids::RSA_ENCRYPTION,
                parameters: None,
            },
            subject_public_key: der::asn1::BitString::from_bytes(&[0]).expect("bits"),
        };
        let alg = AlgorithmIdentifierOwned {
            oid: oids::RSA_ENCRYPTION,
            parameters: None,
        };
        let ctx = SignatureValidationContext {
            contextual_digest: Some(DigestAlgorithm::Shake256),
            prehashed: false,
        };
        assert!(matches!(
            validate_signature(b"sig", b"data", &key, &alg, &ctx),
            Err(SignatureError::AlgorithmNotSupported(_))
        ));
    }

    #[test]
    fn prehashed_input_must_have_the_digest_length() {
        let key = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: oids::EC_PUBLIC_KEY,
                parameters: Some(der::Any::from(&oids::SECP256R1)),
            },
            subject_public_key: der::asn1::BitString::from_bytes(&[4; 65]).expect("bits"),
        };
        let alg = AlgorithmIdentifierOwned {
            oid: oids::ECDSA_WITH_SHA256,
            parameters: None,
        };
        let ctx = SignatureValidationContext {
            contextual_digest: None,
            prehashed: true,
        };
        assert!(matches!(
            validate_signature(b"sig", b"short", &key, &alg, &ctx),
            Err(SignatureError::InvalidSignature)
        ));
    }

    #[test]
    fn dsa_key_size_threshold() {
        // The PKITS DSA CA key has a 1024-bit p.
        // Run-time manifest directory: the target directory is shared
        // between worktrees (see hanko_testdata::manifest_dir).
        let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        let path = std::path::Path::new(&dir)
            .join("../hanko-testdata/data/pyhanko-certvalidator/nist_pkits/certs/DSACACert.crt");
        let der = std::fs::read(&path).expect("PKITS DSA CA certificate");
        let cert = crate::cert::Cert::from_der(&der).expect("cert");
        let key = cert.public_key();
        assert_eq!(dsa_key_size(&key), Some(1024));
        let alg = AlgorithmIdentifierOwned {
            oid: oids::DSA_WITH_SHA1,
            parameters: None,
        };
        let policy = DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]);
        let c = policy.signature_algorithm_allowed(&alg, None, Some(&key));
        assert!(!c.allowed);
        assert_eq!(
            c.failure_reason.as_deref(),
            Some(
                "Key size 1024 for algorithm dsa is considered too small; policy mandates >= 3192"
            )
        );
        let lenient = DisallowWeakAlgorithmsPolicy {
            dsa_key_size_threshold: 1024,
            ..policy
        };
        assert!(
            lenient
                .signature_algorithm_allowed(&alg, None, Some(&key))
                .allowed
        );
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
