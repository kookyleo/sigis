"""Produce authentically signed selected-revocation metadata adversaries.

These fixtures exercise the bounded proof profile, not ordinary revocation
compatibility. Generation verifies signatures; it does not validate a path,
run the native API, or claim reference verdicts for the new profile.
"""
import argparse
import copy
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import sys

from asn1crypto import core, crl, ocsp
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PINNED = Path('/tmp/pyhanko-oracle/src/v0.38.1')
sys.path[:0] = [str(PINNED / 'pkgs/pyhanko'),
                str(PINNED / 'pkgs/pyhanko/src'),
                str(PINNED / 'internal/common-test-utils/src')]
from certomancer.registry import ArchLabel
from pyhanko_testing_commons.test_data.samples import CERTOMANCER

BASE = Path(__file__).resolve().parent.parent
HASH = lambda b: hashlib.sha256(b).hexdigest()


def receipt(path):
    path = Path(path).resolve()
    b = path.read_bytes()
    return {'path': str(path), 'length': len(b), 'sha256': HASH(b)}


class FixtureUnassignedReason(crl.CRLReason):
    # A reserved ENUMERATED value is an intentionally unsupported signed input.
    # This local ASN.1 subclass does not change the installed parser or validator.
    _map = dict(crl.CRLReason._map, **{})
    _map[7] = 'unassigned_fixture_reason'
    _reverse_map = None


def duplicate_extension(exts):
    exts.append(exts[0].copy())


def append_unknown(exts, cls):
    exts.append(cls({'extn_id': '1.2.3.4.550', 'critical': True,
                    'extn_value': b'\x05\x00'}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--receipt-dir', type=Path, required=True)
    a = p.parse_args()
    assert __debug__, 'Assertions must remain enabled'
    assert importlib.metadata.version('pyhanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    a.out = a.out.resolve()
    a.receipt_dir = a.receipt_dir.resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    a.receipt_dir.mkdir(parents=True, exist_ok=True)
    arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca'))
    source_ocsp_path = BASE / '2020-12-25/ocsp-signer2.der'
    source_crl_path = BASE / '2020-12-25/crl-interm.der'
    source_root_crl_path = BASE / '2020-12-25/crl-root.der'
    original_ocsp = ocsp.OCSPResponse.load(source_ocsp_path.read_bytes())
    original_crl = crl.CertificateList.load(source_crl_path.read_bytes())
    original_root_crl = crl.CertificateList.load(source_root_crl_path.read_bytes())
    keys = {}
    public = {}
    for name in ['interm', 'interm-ocsp', 'root']:
        key_info = arch.key_set.get_private_key(name)
        keys[name] = serialization.load_der_private_key(key_info.dump(), password=None)
        public[name] = crypto_x509.load_der_x509_certificate(arch.get_cert(name).dump()).public_key()
    files = []
    cases = []
    crypto_controls = []

    def write_case(name, raw, kind, mutation, expected='reject', target='leaf', description=None):
        path = a.out / (name + '.der')
        if path.exists() and path.read_bytes() != raw:
            raise RuntimeError(f'Refusing to overwrite different immutable fixture: {path}')
        path.write_bytes(raw)
        files.append(dict(file=path.name, length=len(raw), sha256=HASH(raw)))
        cases.append(dict(id=name, kind=kind, target=target, mutation=mutation,
                          expected_proof=expected, file=path.name,
                          description=description or mutation))

    def sign_ocsp(name, mutate, mutation, expected='reject'):
        outer = original_ocsp.copy()
        basic = outer['response_bytes']['response'].parsed.copy()
        mutate(basic['tbs_response_data'])
        tbs = basic['tbs_response_data'].dump(force=True)
        basic['signature'] = keys['interm-ocsp'].sign(tbs, padding.PKCS1v15(), hashes.SHA256())
        outer['response_bytes']['response'] = basic
        raw = outer.dump(force=True)
        parsed = ocsp.OCSPResponse.load(raw)['response_bytes']['response'].parsed
        public['interm-ocsp'].verify(parsed['signature'].native,
                                    parsed['tbs_response_data'].dump(),
                                    padding.PKCS1v15(), hashes.SHA256())
        assert parsed['certs'][0].dump() == arch.get_cert('interm-ocsp').dump()
        crypto_controls.append(dict(file=name + '.der', tbs_sha256=HASH(parsed['tbs_response_data'].dump()),
                                    signature_valid=True, actual_signer='interm-ocsp',
                                    signer_sha256=HASH(arch.get_cert('interm-ocsp').dump())))
        write_case(name, raw, 'ocsp', mutation, expected)

    def sign_crl(name, mutate, mutation, expected='reject', root=False):
        value = (original_root_crl if root else original_crl).copy()
        mutate(value['tbs_cert_list'])
        tbs = value['tbs_cert_list'].dump(force=True)
        key = 'root' if root else 'interm'
        value['signature'] = keys[key].sign(tbs, padding.PKCS1v15(), hashes.SHA256())
        raw = value.dump(force=True)
        parsed = crl.CertificateList.load(raw)
        public[key].verify(parsed['signature'].native, parsed['tbs_cert_list'].dump(),
                           padding.PKCS1v15(), hashes.SHA256())
        crypto_controls.append(dict(file=name + '.der', tbs_sha256=HASH(parsed['tbs_cert_list'].dump()),
                                    signature_valid=True, actual_signer=key,
                                    signer_sha256=HASH(arch.get_cert(key).dump())))
        write_case(name, raw, 'crl', mutation, expected, 'ancestor' if root else 'leaf')

    def single(t):
        return t['responses'][0]

    def revoked(t):
        return single(t)['cert_status'].chosen

    def reason(t, name):
        revoked(t)['revocation_reason'] = name

    def ocsp_ext(t, ext, response=False):
        name = 'response_extensions' if response else 'single_extensions'
        obj = t if response else single(t)
        exts = obj[name]
        if exts.native is None:
            obj[name] = [ext]
        else:
            obj[name].append(ext)

    sign_ocsp('ocsp-key-compromise', lambda t: None, 'explicit KeyCompromise', 'eligible')
    sign_ocsp('ocsp-reason-absent', lambda t: reason(t, None), 'reason absent')
    sign_ocsp('ocsp-reason-unspecified', lambda t: reason(t, 'unspecified'), 'reason unspecified')
    sign_ocsp('ocsp-reason-hold', lambda t: reason(t, 'certificate_hold'), 'certificateHold')
    sign_ocsp('ocsp-reason-remove', lambda t: reason(t, 'remove_from_crl'), 'removeFromCRL')
    sign_ocsp('ocsp-reason-unassigned', lambda t: reason(t, FixtureUnassignedReason(7)), 'unassigned reason ENUMERATED7')
    sign_ocsp('ocsp-revocation-fraction', lambda t: revoked(t).__setitem__('revocation_time', core.GeneralizedTime('20201201000000.5Z')), 'fractional revocationTime')
    sign_ocsp('ocsp-produced-fraction', lambda t: t.__setitem__('produced_at', core.GeneralizedTime('20201225000000.5Z')), 'fractional producedAt')
    sign_ocsp('ocsp-this-update-fraction', lambda t: single(t).__setitem__('this_update', core.GeneralizedTime('20201225000000.5Z')), 'fractional thisUpdate')
    sign_ocsp('ocsp-next-update-fraction', lambda t: single(t).__setitem__('next_update', core.GeneralizedTime('20201225001000.5Z')), 'fractional nextUpdate')
    sign_ocsp('ocsp-duplicate-single', lambda t: t['responses'].append(single(t).copy()), 'duplicate matching SingleResponse')
    sign_ocsp('ocsp-response-unknown-critical', lambda t: ocsp_ext(t, ocsp.ResponseDataExtension({'extn_id':'1.2.3.4.551','critical':True,'extn_value':b'\x05\x00'}), True), 'unknown critical response extension')
    sign_ocsp('ocsp-single-unknown-critical', lambda t: ocsp_ext(t, ocsp.SingleResponseExtension({'extn_id':'1.2.3.4.552','critical':True,'extn_value':b'\x05\x00'})), 'unknown critical single extension')
    def duplicate_nonce(t):
        ext = ocsp.ResponseDataExtension({'extn_id':'nonce', 'extn_value':b'proof-profile duplicate nonce'})
        ocsp_ext(t, ext, True)
        ocsp_ext(t, ext.copy(), True)
    sign_ocsp('ocsp-duplicate-response-extension', duplicate_nonce, 'duplicate response extension OID')
    def duplicate_single_ext(t):
        ext = ocsp.SingleResponseExtension({'extn_id':'1.2.3.4.553','extn_value':b'\x05\x00'})
        ocsp_ext(t, ext)
        ocsp_ext(t, ext.copy())
    sign_ocsp('ocsp-duplicate-single-extension', duplicate_single_ext, 'duplicate single extension OID')
    def invalidity_ocsp(t):
        ocsp_ext(t, ocsp.SingleResponseExtension({'extn_id':'2.5.29.24', 'extn_value':core.GeneralizedTime('20201001000000Z')}))
    sign_ocsp('ocsp-invalidity-date', invalidity_ocsp, 'invalidityDate dependency')
    sign_ocsp('ocsp-good', lambda t: single(t).__setitem__('cert_status', ocsp.CertStatus({'good':None})), 'Good at same reference', 'good-control')
    sign_ocsp('ocsp-revocation-earlier', lambda t: revoked(t).__setitem__('revocation_time', core.GeneralizedTime('20201101000000Z')), 'effective event differs from CRL Dec1', 'eligible')

    def entry(t):
        return t['revoked_certificates'][0]

    def crl_reason(t, value):
        if value is None:
            entry(t)['crl_entry_extensions'] = None
        else:
            entry(t)['crl_entry_extensions'][0]['extn_value'] = value

    sign_crl('crl-key-compromise', lambda t: None, 'explicit KeyCompromise', 'eligible')
    sign_crl('crl-reason-absent', lambda t: crl_reason(t, None), 'reason absent')
    sign_crl('crl-reason-unspecified', lambda t: crl_reason(t, 'unspecified'), 'reason unspecified')
    sign_crl('crl-reason-hold', lambda t: crl_reason(t, 'certificate_hold'), 'certificateHold')
    sign_crl('crl-reason-remove', lambda t: crl_reason(t, 'remove_from_crl'), 'removeFromCRL')
    sign_crl('crl-reason-unassigned', lambda t: crl_reason(t, FixtureUnassignedReason(7)), 'unassigned reason ENUMERATED7')
    sign_crl('crl-invalidity-date', lambda t: entry(t)['crl_entry_extensions'].append(crl.CRLEntryExtension({'extn_id':'invalidity_date','extn_value':core.GeneralizedTime('20201001000000Z')})), 'invalidityDate dependency')
    sign_crl('crl-revocation-fraction', lambda t: entry(t).__setitem__('revocation_date', {'general_time':core.GeneralizedTime('20201201000000.5Z')}), 'fractional revocationDate')
    sign_crl('crl-this-update-fraction', lambda t: t.__setitem__('this_update', {'general_time':core.GeneralizedTime('20201211000000.5Z')}), 'fractional thisUpdate')
    sign_crl('crl-duplicate-entry', lambda t: t['revoked_certificates'].append(entry(t).copy()), 'duplicate matching revoked entry')
    sign_crl('crl-duplicate-entry-extension', lambda t: duplicate_extension(entry(t)['crl_entry_extensions']), 'duplicate entry extension OID')
    sign_crl('crl-duplicate-extension', lambda t: duplicate_extension(t['crl_extensions']), 'duplicate CRL extension OID')
    sign_crl('crl-unknown-critical', lambda t: append_unknown(t['crl_extensions'], crl.TBSCertListExtension), 'unknown critical CRL extension')
    sign_crl('crl-entry-unknown-critical', lambda t: append_unknown(entry(t)['crl_entry_extensions'], crl.CRLEntryExtension), 'unknown critical CRL entry extension')
    sign_crl('crl-delta', lambda t: t['crl_extensions'].append(crl.TBSCertListExtension({'extn_id':'delta_crl_indicator','critical':True,'extn_value':254})), 'delta CRL dependency')
    def partial_reasons(t):
        for extension in t['crl_extensions']:
            if extension['extn_id'].native == 'issuing_distribution_point':
                idp = extension['extn_value'].parsed.copy()
                idp['only_some_reasons'] = {'key_compromise'}
                extension['extn_value'] = idp
                return
        raise AssertionError('missing original signed IDP')
    sign_crl('crl-partial-reasons', partial_reasons, 'incomplete reason coverage despite authentic leaf event')
    sign_crl('crl-good', lambda t: t.__setitem__('revoked_certificates', None), 'Good at same reference', 'good-control')
    sign_crl('crl-revocation-earlier', lambda t: entry(t).__setitem__('revocation_date', {'utc_time':'201101000000Z'}), 'effective event differs from OCSP Dec1', 'eligible')
    sign_crl('root-crl-unknown-critical', lambda t: append_unknown(t['crl_extensions'], crl.TBSCertListExtension), 'ancestor selected CRL unknown critical extension', root=True)
    sign_crl('root-crl-duplicate-extension', lambda t: duplicate_extension(t['crl_extensions']), 'ancestor selected CRL duplicate extension OID', root=True)
    sign_crl('root-crl-this-update-fraction', lambda t: t.__setitem__('this_update', {'general_time':core.GeneralizedTime('20201211000000.5Z')}), 'ancestor selected CRL fractional thisUpdate', root=True)

    manifest = {'scope':'Tests-first signed metadata adversaries. Signature checks only; no native/CV/reference path execution.',
                'current_time':'2020-12-25T00:00:00Z','architecture':'testing-ca',
                'actual_signer_keys':['interm-ocsp','interm','root'],
                'private_keys_written':False,'cases':cases,'files':files,
                'source_inputs':[receipt(p) for p in [source_ocsp_path,source_crl_path,source_root_crl_path]],
                'versions':{n:importlib.metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto','certomancer']},
                'assertions_enabled':__debug__,'provider_exclusions':[]}
    manifest_path = a.out/'manifest.json'
    manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    runtime = {'interpreter':receipt(sys.executable),'python':sys.version,
               'modules':[receipt(inspect.getfile(module)) for module in [ocsp,crl,crypto_x509]],
               'generator':receipt(__file__),'source_inputs':manifest['source_inputs'],
               'manifest':receipt(manifest_path),'versions':manifest['versions'],
               'assertions_enabled':__debug__,'crypto_signature_controls':crypto_controls,
               'native_calls':0,'cargo_calls':0,'path_validation_calls':0,
               'network_calls':0,'provider_exclusions':[]}
    (a.receipt_dir/'generation-receipt.json').write_text(json.dumps(runtime,indent=2)+'\n')
    print(json.dumps({'files':len(files),'signature_controls':len(crypto_controls),'manifest':receipt(manifest_path)}))

if __name__ == '__main__':
    main()
