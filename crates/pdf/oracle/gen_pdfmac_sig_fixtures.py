"""Generate PDF MAC fixtures where the MAC is attached to a signature.

Derived from pyHanko 0.38.1 `pkgs/pyhanko/tests/test_pdfmac.py`
(MIT, see crates/pdf/LICENSE-pyHanko): the `MacLocation.IN_SIG` cases
of the PDF MAC tests sign documents, which needs lane D's signer. Until
that lands, pyHanko 0.38.1 produces these documents, and hanko-pdf's
`tests/pdfmac.rs` validates their MACs.

Usage (from the repository root, with pyHanko 0.38.1 and Certomancer):

    python crates/pdf/oracle/gen_pdfmac_sig_fixtures.py

Output: `crates/testdata/data/lanes/b/pdfmac-sig/<test>-<enc>.pdf`,
where `<enc>` is `standard` or `pubkey`. Each file is checked with
pyHanko itself before it is written: good cases must validate, bad cases
must fail MAC validation with the message the upstream test expects.

Encryption keys, salts and signatures are random, so regenerated files
differ byte-wise; their MAC verdicts do not. The signing time is the
current time (no validation time is involved: only the MAC is checked).
"""

import hashlib
import pathlib
import re
import sys
from io import BytesIO

import yaml
from asn1crypto import cms, core
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    KeyLabel,
)
from pyhanko.pdf_utils import generic, writer
from pyhanko.pdf_utils.crypt import (
    PubKeySecurityHandler,
    SimpleEnvelopeKeyDecrypter,
    StandardSecurityHandler,
    pdfmac,
)
from pyhanko.pdf_utils.crypt.api import PdfMacStatus
from pyhanko.pdf_utils.font.basic import get_courier
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko.sign.general import simple_cms_attribute
from pyhanko.sign.signers import cms_embedder
from pyhanko_certvalidator.registry import SimpleCertificateStore

ROOT = pathlib.Path(__file__).resolve().parents[3]
CRYPTO_DIR = ROOT / 'crates/testdata/data/pyhanko/crypto'
OUT_DIR = ROOT / 'crates/testdata/data/lanes/b/pdfmac-sig'

DUMMY_PASSWORD = "secret"

with open(CRYPTO_DIR / 'certomancer.yml') as _inf:
    _CFG = CertomancerConfig(
        yaml.safe_load(_inf),
        key_search_dir=str(CRYPTO_DIR),
        lazy_load_keys=True,
    )
TESTING_CA = _CFG.get_pki_arch(ArchLabel('testing-ca'))
TESTING_CA_ECDSA = _CFG.get_pki_arch(ArchLabel('testing-ca-ecdsa'))

FROM_ECC_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA_ECDSA.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA_ECDSA.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs(
        [
            TESTING_CA_ECDSA.get_cert(CertLabel('root')),
            TESTING_CA_ECDSA.get_cert(CertLabel('interm')),
        ]
    ),
)

DUMMY_TS = timestamps.DummyTimeStamper(
    tsa_cert=TESTING_CA.get_cert(CertLabel('tsa')),
    tsa_key=TESTING_CA.key_set.get_private_key(KeyLabel('tsa')),
    certs_to_embed=SimpleCertificateStore.from_certs(
        [TESTING_CA.get_cert(CertLabel('root'))]
    ),
)

PUBKEY_TEST_DECRYPTER = SimpleEnvelopeKeyDecrypter.load(
    str(CRYPTO_DIR / 'keys-rsa/signer.key.pem'),
    str(CRYPTO_DIR / 'testing-ca/interm/decrypter1.cert.pem'),
    b'secret',
)

ENCRYPTION_TYPES = ('standard', 'pubkey')


def init_sample_doc(encryption_type, writer_class=PdfFileWriter):
    w = writer_class(stream_xrefs=False)
    resources = generic.DictionaryObject(
        {
            generic.pdf_name('/Font'): generic.DictionaryObject(
                {generic.pdf_name('/F1'): get_courier(w)}
            )
        }
    )
    stream_content = '''
    BT
        /F1 12 Tf 40 700 Td 12 TL
        (Hello ISO/TS 32004!) Tj
    ET
    '''
    stream = generic.StreamObject(stream_data=stream_content.encode('latin1'))
    page = writer.PageObject(
        contents=w.add_object(stream),
        media_box=(0, 0, 595.28, 841.89),
        resources=resources,
    )
    w.insert_page(page)
    if encryption_type == 'pubkey':
        sh = PubKeySecurityHandler.build_from_certs(
            [PUBKEY_TEST_DECRYPTER.cert], compat_entries=False
        )
        w._assign_security_handler(sh)
    else:
        w.encrypt(DUMMY_PASSWORD, compat_entries=False)
    return w


def sign(w, md_algorithm=None):
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    if md_algorithm:
        meta = signers.PdfSignatureMetadata(
            field_name='Sig', md_algorithm=md_algorithm
        )
    return signers.sign_pdf(w, meta, signer=FROM_ECC_CA)


def dummy_decrypt(r, ignore_mac=False):
    if ignore_mac:
        r._validate_pdf_mac = id
    if isinstance(r.security_handler, PubKeySecurityHandler):
        return r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    return r.decrypt(DUMMY_PASSWORD)


# --- token handlers of the upstream tests (MacLocation.IN_SIG) -------------


def _alg_protection(handler, md=None, mac=True):
    fields = {
        'digest_algorithm': cms.DigestAlgorithm(
            {'algorithm': md or handler.md_algorithm}
        )
    }
    if mac is True:
        fields['mac_algorithm'] = handler.mac_algo_ident
    elif mac:
        fields['mac_algorithm'] = mac
    return cms.CMSAlgorithmProtection(fields)


class AlterKey(pdfmac.PdfMacTokenHandler):
    def _get_mac_keying_info(self, dry_run):
        mac_key, ri = super()._get_mac_keying_info(dry_run)
        ek = ri.chosen['encrypted_key']
        ri.chosen['encrypted_key'] = bytes(reversed(ek.native))
        return mac_key, ri


class AlterSalt(pdfmac.PdfMacTokenHandler):
    @classmethod
    def from_key_mat(cls, file_encryption_key, kdf_salt, md_algorithm):
        return super().from_key_mat(
            file_encryption_key=file_encryption_key,
            kdf_salt=bytes(32),
            md_algorithm=md_algorithm,
        )


class AppendAuthAttr(pdfmac.PdfMacTokenHandler):
    def compute_mac(self, mac_key, data_to_mac):
        return super().compute_mac(
            mac_key=mac_key, data_to_mac=cms.CMSAttributes([]).dump()
        )


def _attrs_handler(make):
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(self, message_digest):
            return cms.CMSAttributes(make(self, message_digest))

    return Handler


def _ct(value='pdf_mac_integrity_info'):
    return simple_cms_attribute('content_type', value)


def _md(value):
    return simple_cms_attribute('message_digest', value)


AttrMultival = _attrs_handler(
    lambda h, md: [
        _ct(),
        _md(md),
        cms.CMSAttribute(
            {
                'type': cms.CMSAttributeType('cms_algorithm_protection'),
                'values': (_alg_protection(h), _alg_protection(h)),
            }
        ),
    ]
)
AttrDuplicated = _attrs_handler(
    lambda h, md: [
        _ct(),
        _md(md),
        simple_cms_attribute('cms_algorithm_protection', _alg_protection(h)),
        simple_cms_attribute('cms_algorithm_protection', _alg_protection(h)),
    ]
)
DigestAlgoMismatch = _attrs_handler(
    lambda h, md: [
        _ct(),
        _md(md),
        simple_cms_attribute(
            'cms_algorithm_protection', _alg_protection(h, md='sha3_512')
        ),
    ]
)
MacAlgoMismatch = _attrs_handler(
    lambda h, md: [
        _ct(),
        _md(md),
        simple_cms_attribute(
            'cms_algorithm_protection',
            _alg_protection(
                h, mac=cms.HmacAlgorithm({'algorithm': 'sha512'})
            ),
        ),
    ]
)
MacAlgoMissing = _attrs_handler(
    lambda h, md: [
        _ct(),
        _md(md),
        simple_cms_attribute(
            'cms_algorithm_protection', _alg_protection(h, mac=None)
        ),
    ]
)
DuplicateContentType = _attrs_handler(
    lambda h, md: [
        cms.CMSAttribute(
            {
                'type': cms.CMSAttributeType('content_type'),
                'values': ('data', 'pdf_mac_integrity_info'),
            }
        ),
        _md(md),
    ]
)
NoContentType = _attrs_handler(lambda h, md: [_md(md)])
WrongContentType = _attrs_handler(lambda h, md: [_ct('data'), _md(md)])
NoMd = _attrs_handler(lambda h, md: [_ct()])
BadMd = _attrs_handler(
    lambda h, md: [_ct(), _md(hashlib.sha256(b'\xde\xad\xbe\xef').digest())]
)


class WithUnauthAttrs(pdfmac.PdfMacTokenHandler):
    def build_pdfmac_token(self, *args, **kwargs):
        token = super().build_pdfmac_token(*args, **kwargs)
        token['content']['unauth_attrs'] = cms.CMSAttributes([_ct('data')])
        return token


class NoKdf(pdfmac.PdfMacTokenHandler):
    def _get_mac_keying_info(self, dry_run):
        mac_key, ri = super()._get_mac_keying_info(dry_run)
        del ri.chosen['key_derivation_algorithm']
        return mac_key, ri


class TooManyRecipients(pdfmac.PdfMacTokenHandler):
    def _format_auth_data(self, *args, **kwargs):
        ad = super()._format_auth_data(*args, **kwargs)
        ris = ad['recipient_infos']
        ris.append(ris[0])
        return ad


class WrongRecipientType(pdfmac.PdfMacTokenHandler):
    def _format_auth_data(self, recipient_info, *args, **kwargs):
        return super()._format_auth_data(
            *args,
            recipient_info=cms.RecipientInfo(
                {
                    'ori': cms.OtherRecipientInfo(
                        {
                            'ori_type': '2.999',
                            'ori_value': core.OctetString(b'\xde\xad\xbe\xef'),
                        }
                    )
                }
            ),
            **kwargs,
        )


class WrongEncContentType(pdfmac.PdfMacTokenHandler):
    def _format_auth_attrs(self, message_digest):
        hash_fun = getattr(hashlib, self.md_algorithm)
        return super()._format_auth_attrs(
            hash_fun(b'\xde\xad\xbe\xef').digest()
        )

    def _format_auth_data(self, *args, **kwargs):
        ad = super()._format_auth_data(*args, **kwargs)
        ad['encap_content_info'] = cms.EncapsulatedContentInfo(
            {
                'content_type': 'data',
                'content': core.ParsableOctetString(b'\xde\xad\xbe\xef'),
            }
        )
        return ad


class WrongTokenContentType(pdfmac.PdfMacTokenHandler):
    def build_pdfmac_token(self, *args, **kwargs):
        return cms.ContentInfo(
            {
                'content_type': 'data',
                'content': core.OctetString(b'\xde\xad\xbe\xef'),
            }
        )


class MissingSigDigest(pdfmac.PdfMacTokenHandler):
    def _format_message(self, document_digest, signature_digest):
        return super()._format_message(document_digest, signature_digest=None)


class SigWrongSigDigest(pdfmac.PdfMacTokenHandler):
    def _format_message(self, document_digest, signature_digest):
        dummy = hashlib.sha256(b'\xde\xad\xbe\xef').digest()
        return super()._format_message(document_digest, signature_digest=dummy)


class SigWrongDocumentDigest(pdfmac.PdfMacTokenHandler):
    def _format_message(self, document_digest, signature_digest):
        dummy = hashlib.sha256(b'\xde\xad\xbe\xef').digest()
        return super()._format_message(
            dummy, signature_digest=signature_digest
        )


WITH_HANDLER = {
    'test_alter_key': (AlterKey, "Failed to unwrap"),
    'test_alter_salt': (AlterSalt, "Failed to unwrap"),
    'test_append_auth_attr': (AppendAuthAttr, "token has invalid MAC"),
    'test_cms_algorithm_protection_attr_multival': (
        AttrMultival,
        "Multiple CMS algorithm protection attributes present",
    ),
    'test_cms_algorithm_protection_attr_duplicated': (
        AttrDuplicated,
        "Multiple CMS algorithm protection attributes",
    ),
    'test_cms_algorithm_protection_digest_algo_mismatch': (
        DigestAlgoMismatch,
        "Digest algorithm does not match",
    ),
    'test_cms_algorithm_protection_mac_algo_mismatch': (
        MacAlgoMismatch,
        "MAC mechanism does not match",
    ),
    'test_cms_algorithm_protection_mac_algo_missing': (
        MacAlgoMissing,
        "attribute not valid for authenticated data",
    ),
    'test_duplicate_content_type_attr': (
        DuplicateContentType,
        "Content type not found in authenticated attributes",
    ),
    'test_no_content_type_attr': (
        NoContentType,
        "Content type not found in authenticated attributes",
    ),
    'test_wrong_content_type_attr': (
        WrongContentType,
        "content type.*must be id-pdfMacIntegrityInfo",
    ),
    'test_no_md': (NoMd, "Message digest not found"),
    'test_bad_md': (BadMd, "messageDigest attribute does not match"),
    'test_with_unauth_attrs': (
        WithUnauthAttrs,
        "PDF MAC tokens cannot have unauthenticated attributes",
    ),
    'test_no_kdf': (NoKdf, "key derivation.*identified as pdfMacWrapKdf"),
    'test_too_many_recipients': (
        TooManyRecipients,
        "requires exactly one recipientInfo",
    ),
    'test_wrong_recipient_type': (
        WrongRecipientType,
        "must be.*PasswordRecipientInfo",
    ),
    'test_wrong_enc_content_type': (
        WrongEncContentType,
        "must be.*pdfMacIntegrityInfo",
    ),
    'test_wrong_token_content_type': (
        WrongTokenContentType,
        "must be.*type AuthenticatedData",
    ),
    'test_missing_sig_digest': (
        MissingSigDigest,
        "could not find signature digest",
    ),
    'test_sig_wrong_sig_digest': (
        SigWrongSigDigest,
        "Signature digest does not match value in",
    ),
    'test_sig_wrong_document_digest': (
        SigWrongDocumentDigest,
        "Document digest does not match value in",
    ),
}


# --- documents --------------------------------------------------------------


def with_handler(handler_cls, enc):
    w = init_sample_doc(enc)
    w._mac_handler_cls = handler_cls
    return sign(w)


def mac_with_signature_no_full_coverage(enc):
    out = sign(init_sample_doc(enc))
    r = PdfFileReader(out)
    dummy_decrypt(r, ignore_mac=True)
    w = IncrementalPdfFileWriter.from_reader(r)
    w.digest_aware_write = True
    w.root['/Foo'] = generic.pdf_name('/Bar')
    w.update_root()
    w.write_in_place()
    return out


def _manipulated_writer(manipulator):
    class Writer(PdfFileWriter):
        def set_custom_trailer_entry(self, key, value):
            if key == '/AuthCode':
                value = manipulator(self, value)
            super().set_custom_trailer_entry(key, value)

    return Writer


def manipulate_with_sig(enc, manipulator):
    return sign(init_sample_doc(enc, _manipulated_writer(manipulator)))


def _del_sig_ref(_w, value):
    del value['/SigObjRef']
    return value


def _direct_sig_ref(_w, value):
    value['/SigObjRef'] = generic.DictionaryObject()
    return value


def _sig_ref_not_dict(w, value):
    value['/SigObjRef'] = w.add_object(generic.pdf_name('/Bleh'))
    return value


def _sig_ref_not_sig(w, value):
    value['/SigObjRef'] = w.add_object(generic.DictionaryObject())
    return value


def _indirect(w, value):
    return w.add_object(value)


def manipulatable_sign(manipulate_cms):
    import asyncio

    w = init_sample_doc('standard')
    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)
    sig_obj_ref = cms_writer.send(
        cms_embedder.SigObjSetup(sig_placeholder=sig_obj)
    )
    ac_dict = generic.DictionaryObject(
        {
            generic.pdf_name('/MACLocation'): generic.pdf_name(
                '/AttachedToSig'
            ),
            generic.pdf_name('/SigObjRef'): sig_obj_ref,
        }
    )
    w.set_custom_trailer_entry(generic.pdf_name('/AuthCode'), ac_dict)
    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm='sha256')
    )
    content_info = asyncio.run(
        FROM_ECC_CA.async_sign(
            data_digest=prep_digest.document_digest,
            digest_algorithm='sha256',
        )
    )
    manipulate_cms(content_info)
    cms_writer.send(content_info)
    return output


def _signer_infos_multi(ci):
    sis = ci['content']['signer_infos']
    sis.append(sis[0])


def _signer_infos_zero(ci):
    ci['content']['signer_infos'] = cms.SignerInfos([])


def pdf_mac_timestamp():
    w = init_sample_doc('standard')
    out = BytesIO()
    w.write(out)
    w = IncrementalPdfFileWriter(out)
    w.encrypt("secret")
    signers.PdfTimeStamper(timestamper=DUMMY_TS).timestamp_pdf(
        w, md_algorithm='sha256', in_place=True
    )
    return out


def cases():
    for enc in ENCRYPTION_TYPES:
        yield 'test_sign_crypt_aes256_with_mac', enc, None, (
            lambda enc=enc: sign(init_sample_doc(enc))
        )
        yield 'test_signature_nondefault_hash', enc, None, (
            lambda enc=enc: sign(init_sample_doc(enc), md_algorithm='sha384')
        )
        for name, (cls, msg) in WITH_HANDLER.items():
            yield name, enc, msg, (lambda cls=cls, enc=enc: with_handler(cls, enc))
        yield (
            'test_mac_with_signature_no_full_coverage',
            enc,
            "must have /ByteRange covering the entire file",
            lambda enc=enc: mac_with_signature_no_full_coverage(enc),
        )
        for name, manip, msg in [
            ('test_ac_dict_indirect', _indirect, "AuthCode.*indirect"),
            ('test_missing_sig_ref', _del_sig_ref, "requires /SigObjRef"),
            (
                'test_malformed_sig_ref_direct',
                _direct_sig_ref,
                "must be an indirect reference",
            ),
            (
                'test_malformed_sig_ref_not_dictionary',
                _sig_ref_not_dict,
                "does not point to a dictionary",
            ),
            (
                'test_malformed_sig_ref_not_signature',
                _sig_ref_not_sig,
                "Failed to retrieve signature contents",
            ),
        ]:
            yield name, enc, msg, (
                lambda manip=manip, enc=enc: manipulate_with_sig(enc, manip)
            )
    # the upstream test ignores its encryption_type parameter
    yield 'test_pdf_mac_timestamp', 'standard', None, pdf_mac_timestamp
    for name, manip, msg in [
        (
            'test_signer_info_cardinality_multi',
            _signer_infos_multi,
            "exactly 1 signerInfo",
        ),
        (
            'test_signer_info_cardinality_zero',
            _signer_infos_zero,
            "exactly 1 signerInfo",
        ),
        (
            'test_pdf_mac_attr_missing',
            id,
            "exactly 1 pdfMacData unsigned attribute",
        ),
    ]:
        yield name, 'standard', msg, (lambda manip=manip: manipulatable_sign(manip))


def check(out, expected_error):
    r = PdfFileReader(out)
    result = dummy_decrypt(r)
    if expected_error is None:
        assert result.mac_status == PdfMacStatus.SUCCESSFUL, result
        exts = {
            int(ext.get_object()['/ExtensionLevel'])
            for ext in r.root['/Extensions']['/ISO_']
        }
        assert 32004 in exts
    else:
        assert result.mac_status == PdfMacStatus.FAILED, result
        assert re.search(
            expected_error, result.mac_failure_reason, re.IGNORECASE
        ), result.mac_failure_reason


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, enc, msg, make in cases():
        out = make()
        check(out, msg)
        fname = OUT_DIR / f'{name}-{enc}.pdf'
        fname.write_bytes(out.getvalue())
        print(f'{fname.name}: {"good" if msg is None else msg}', file=sys.stderr)


if __name__ == '__main__':
    main()
