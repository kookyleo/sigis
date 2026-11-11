//! Object identifiers used by this crate.
//!
//! They are defined here, with their dotted values, instead of being taken
//! from the `const-oid` database, so that the meaning of every OID in the
//! validation code is visible and does not depend on database naming.

use const_oid::ObjectIdentifier as Oid;

macro_rules! oids {
    ($($(#[$m:meta])* $name:ident = $value:literal;)*) => {
        $( $(#[$m])* pub const $name: Oid = Oid::new_unwrap($value); )*
    };
}

oids! {
    // Digest algorithms.
    /// MD2 (weak; recognized only to reject it).
    MD2 = "1.2.840.113549.2.2";
    /// MD5 (weak; recognized only to reject it).
    MD5 = "1.2.840.113549.2.5";
    /// SHA-1.
    SHA1 = "1.3.14.3.2.26";
    /// SHA-224.
    SHA224 = "2.16.840.1.101.3.4.2.4";
    /// SHA-256.
    SHA256 = "2.16.840.1.101.3.4.2.1";
    /// SHA-384.
    SHA384 = "2.16.840.1.101.3.4.2.2";
    /// SHA-512.
    SHA512 = "2.16.840.1.101.3.4.2.3";
    /// SHA3-256.
    SHA3_224 = "2.16.840.1.101.3.4.2.7";
    /// SHA3-256.
    SHA3_256 = "2.16.840.1.101.3.4.2.8";
    /// SHA3-384.
    SHA3_384 = "2.16.840.1.101.3.4.2.9";
    /// SHA3-512.
    SHA3_512 = "2.16.840.1.101.3.4.2.10";
    /// SHAKE128.
    SHAKE128 = "2.16.840.1.101.3.4.2.11";
    /// SHAKE256 (fixed 512-bit output in CMS, RFC 8419).
    SHAKE256 = "2.16.840.1.101.3.4.2.12";
    /// `id-shake256-len` (SHAKE256 with an explicit output length).
    SHAKE256_LEN = "2.16.840.1.101.3.4.2.18";

    // RSA.
    /// rsaEncryption (key type; also a CMS signature algorithm meaning PKCS#1 v1.5).
    RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    /// md2WithRSAEncryption.
    MD2_WITH_RSA = "1.2.840.113549.1.1.2";
    /// md5WithRSAEncryption.
    MD5_WITH_RSA = "1.2.840.113549.1.1.4";
    /// sha1WithRSAEncryption.
    SHA1_WITH_RSA = "1.2.840.113549.1.1.5";
    /// id-mgf1.
    MGF1 = "1.2.840.113549.1.1.8";
    /// id-RSASSA-PSS.
    RSASSA_PSS = "1.2.840.113549.1.1.10";
    /// sha256WithRSAEncryption.
    SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    /// sha384WithRSAEncryption.
    SHA384_WITH_RSA = "1.2.840.113549.1.1.12";
    /// sha512WithRSAEncryption.
    SHA512_WITH_RSA = "1.2.840.113549.1.1.13";
    /// sha224WithRSAEncryption.
    SHA224_WITH_RSA = "1.2.840.113549.1.1.14";
    /// md5WithRSA (OIW secsig; asn1crypto `md5_rsa`).
    MD5_WITH_RSA_OIW = "1.3.14.3.2.3";
    /// sha1WithRSA (OIW secsig; asn1crypto `sha1_rsa`).
    SHA1_WITH_RSA_OIW = "1.3.14.3.2.29";

    // Elliptic curves.
    /// id-ecPublicKey.
    EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    /// secp256r1 (P-256).
    SECP256R1 = "1.2.840.10045.3.1.7";
    /// secp384r1 (P-384).
    SECP384R1 = "1.3.132.0.34";
    /// secp521r1 (P-521).
    SECP521R1 = "1.3.132.0.35";
    /// ecdsa-with-SHA1.
    ECDSA_WITH_SHA1 = "1.2.840.10045.4.1";
    /// `ecdsa` (asn1crypto): the ECDSA arc, digest taken from context.
    ECDSA_GENERIC = "1.2.840.10045.4";
    /// ecdsa-with-SHA224.
    ECDSA_WITH_SHA224 = "1.2.840.10045.4.3.1";
    /// ecdsa-with-SHA256.
    ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
    /// ecdsa-with-SHA384.
    ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    /// ecdsa-with-SHA512.
    ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";
    /// id-ecdsa-with-sha3-224.
    ECDSA_WITH_SHA3_224 = "2.16.840.1.101.3.4.3.9";
    /// id-ecdsa-with-sha3-256.
    ECDSA_WITH_SHA3_256 = "2.16.840.1.101.3.4.3.10";
    /// id-ecdsa-with-sha3-384.
    ECDSA_WITH_SHA3_384 = "2.16.840.1.101.3.4.3.11";
    /// id-ecdsa-with-sha3-512.
    ECDSA_WITH_SHA3_512 = "2.16.840.1.101.3.4.3.12";

    // EdDSA.
    /// id-Ed25519.
    ED25519 = "1.3.101.112";
    /// id-Ed448.
    ED448 = "1.3.101.113";

    // DSA.
    /// id-dsa.
    DSA = "1.2.840.10040.4.1";
    /// dsa-with-sha1.
    DSA_WITH_SHA1 = "1.2.840.10040.4.3";
    /// dsaWithSHA (OIW secsig; asn1crypto `sha1_dsa`).
    DSA_WITH_SHA_OIW = "1.3.14.3.2.13";
    /// dsaWithSHA1 (OIW secsig; asn1crypto `sha1_dsa`).
    DSA_WITH_SHA1_OIW = "1.3.14.3.2.27";
    /// dsa-with-sha224.
    DSA_WITH_SHA224 = "2.16.840.1.101.3.4.3.1";
    /// dsa-with-sha256.
    DSA_WITH_SHA256 = "2.16.840.1.101.3.4.3.2";

    // ML-DSA (FIPS 204).
    /// id-ml-dsa-44.
    ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
    /// id-ml-dsa-65.
    ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
    /// id-ml-dsa-87.
    ML_DSA_87 = "2.16.840.1.101.3.4.3.19";

    // Certificate and CRL extensions.
    /// id-ce-keyUsage.
    CE_KEY_USAGE = "2.5.29.15";
    /// id-ce-basicConstraints.
    CE_BASIC_CONSTRAINTS = "2.5.29.19";
    /// id-ce-cRLNumber.
    CE_CRL_NUMBER = "2.5.29.20";
    /// id-ce-cRLReasons.
    CE_CRL_REASONS = "2.5.29.21";
    /// id-ce-holdInstructionCode.
    CE_HOLD_INSTRUCTION_CODE = "2.5.29.23";
    /// id-ce-invalidityDate.
    CE_INVALIDITY_DATE = "2.5.29.24";
    /// id-ce-deltaCRLIndicator.
    CE_DELTA_CRL_INDICATOR = "2.5.29.27";
    /// id-ce-issuingDistributionPoint.
    CE_ISSUING_DISTRIBUTION_POINT = "2.5.29.28";
    /// id-ce-certificateIssuer.
    CE_CERTIFICATE_ISSUER = "2.5.29.29";
    /// id-ce-cRLDistributionPoints.
    CE_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    /// id-ce-authorityKeyIdentifier.
    CE_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    /// id-ce-extKeyUsage.
    CE_EXT_KEY_USAGE = "2.5.29.37";
    /// id-ce-freshestCRL.
    CE_FRESHEST_CRL = "2.5.29.46";
    /// id-ce-expiredCertsOnCRL.
    CE_EXPIRED_CERTS_ON_CRL = "2.5.29.60";
    /// id-pe-authorityInfoAccess.
    PE_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";

    // OCSP.
    /// id-ad-ocsp.
    AD_OCSP = "1.3.6.1.5.5.7.48.1";
    /// id-pkix-ocsp-basic.
    OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
    /// id-pkix-ocsp-nonce.
    OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";
    /// id-pkix-ocsp-crl.
    OCSP_CRL = "1.3.6.1.5.5.7.48.1.3";
    /// id-pkix-ocsp-nocheck.
    OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";
    /// id-pkix-ocsp-archive-cutoff.
    OCSP_ARCHIVE_CUTOFF = "1.3.6.1.5.5.7.48.1.6";
    /// id-kp-OCSPSigning.
    KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    // CMS content types.
    /// `id-data`.
    CT_DATA = "1.2.840.113549.1.7.1";
    /// `id-signedData`.
    CT_SIGNED_DATA = "1.2.840.113549.1.7.2";
    /// `id-envelopedData`.
    CT_ENVELOPED_DATA = "1.2.840.113549.1.7.3";
    /// `id-digestedData`.
    CT_DIGESTED_DATA = "1.2.840.113549.1.7.5";
    /// `id-encryptedData`.
    CT_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";
    /// `id-ct-authData`.
    CT_AUTHENTICATED_DATA = "1.2.840.113549.1.9.16.1.2";
    /// `id-ct-TSTInfo` (RFC 3161).
    CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";

    // Extended key usages.
    /// `anyExtendedKeyUsage`.
    KP_ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";
    /// `id-kp-serverAuth`.
    KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    /// `id-kp-clientAuth`.
    KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    /// `id-kp-codeSigning`.
    KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    /// `id-kp-emailProtection`.
    KP_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
    /// `id-kp-timeStamping`.
    KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
    /// Microsoft document signing.
    KP_DOCUMENT_SIGNING = "1.3.6.1.4.1.311.10.3.12";
    /// Adobe Authentic Documents Trust.
    KP_ADOBE_AUTHENTIC_DOCUMENTS_TRUST = "1.2.840.113583.1.1.5";

    // CMS / ESS / CAdES attributes.
    /// `id-aa-CMSAlgorithmProtection` (RFC 6211).
    CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52";
    /// `counterSignature`.
    COUNTER_SIGNATURE = "1.2.840.113549.1.9.6";
    /// `id-aa-ets-contentTimestamp`.
    AA_CONTENT_TIMESTAMP = "1.2.840.113549.1.9.16.2.20";
    /// `id-aa-ets-signerAttr`.
    AA_SIGNER_ATTRIBUTES = "0.4.0.1733.2.3";
    /// `id-aa-ets-signerAttrV2` (ETSI EN 319 122-1).
    AA_SIGNER_ATTRIBUTES_V2 = "0.4.0.19122.1.1";
    /// Adobe `RevocationInfoArchival` attribute.
    ADBE_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8";
    /// id-contentType.
    CONTENT_TYPE = "1.2.840.113549.1.9.3";
    /// id-messageDigest.
    MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    /// id-signingTime.
    SIGNING_TIME = "1.2.840.113549.1.9.5";
    /// id-aa-signingCertificate (RFC 2634).
    AA_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
    /// id-aa-signatureTimeStampToken (RFC 3161).
    AA_SIGNATURE_TIME_STAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
    /// id-aa-ets-sigPolicyId (RFC 5126).
    AA_ETS_SIG_POLICY_ID = "1.2.840.113549.1.9.16.2.15";
    /// id-aa-ets-commitmentType (RFC 5126).
    AA_ETS_COMMITMENT_TYPE = "1.2.840.113549.1.9.16.2.16";
    /// id-aa-signingCertificateV2 (RFC 5035).
    AA_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
    /// id-spq-ets-uri.
    SPQ_ETS_URI = "1.2.840.113549.1.9.16.5.1";
    /// id-spq-ets-unotice.
    SPQ_ETS_UNOTICE = "1.2.840.113549.1.9.16.5.2";
    /// id-cti-ets-proofOfOrigin.
    CTI_PROOF_OF_ORIGIN = "1.2.840.113549.1.9.16.6.1";
    /// id-cti-ets-proofOfReceipt.
    CTI_PROOF_OF_RECEIPT = "1.2.840.113549.1.9.16.6.2";
    /// id-cti-ets-proofOfDelivery.
    CTI_PROOF_OF_DELIVERY = "1.2.840.113549.1.9.16.6.3";
    /// id-cti-ets-proofOfSender.
    CTI_PROOF_OF_SENDER = "1.2.840.113549.1.9.16.6.4";
    /// id-cti-ets-proofOfApproval.
    CTI_PROOF_OF_APPROVAL = "1.2.840.113549.1.9.16.6.5";
    /// id-cti-ets-proofOfCreation.
    CTI_PROOF_OF_CREATION = "1.2.840.113549.1.9.16.6.6";
}
