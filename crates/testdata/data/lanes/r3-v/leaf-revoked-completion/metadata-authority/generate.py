"""Authentic CA-MAIN revocation and copied issuer-signature OCSP adversaries.

This tests-first packet never constructs a validation status. It signs actual
OCSP/CRL TBS values with existing immutable Certomancer keys and independently
verifies the intended good and bad signature boundaries. The copied issuer
certificate is deliberately NOT re-signed: its preserved issuer signature no
longer authenticates its changed SPKI.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

from asn1crypto import crl, ocsp, x509
from cryptography import x509 as cx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from freezegun import freeze_time

PINNED = Path('/tmp/pyhanko-oracle/src/v0.38.1')
sys.path[:0] = [str(PINNED / 'pkgs/pyhanko'), str(PINNED / 'pkgs/pyhanko/src'),
                str(PINNED / 'internal/common-test-utils/src')]
from certomancer.registry import ArchLabel
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.authority import CertTrustAnchor
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
)
from pyhanko_certvalidator.validate import async_validate_path
import pyhanko_certvalidator.revinfo.validate_ocsp as reference_ocsp

H = lambda b: hashlib.sha256(b).hexdigest()
NOW = '2020-12-25T00:00:00Z'


def rec(path):
    path = Path(path).resolve()
    b = path.read_bytes()
    return {'path': str(path), 'length': len(b), 'sha256': H(b)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--fixture-root', type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument('--out', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--receipt-dir', type=Path, required=True)
    a = p.parse_args()
    assert __debug__
    assert importlib.metadata.version('pyhanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    a.out = a.out.resolve()
    a.fixture_root = a.fixture_root.resolve()
    a.receipt_dir = a.receipt_dir.resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    a.receipt_dir.mkdir(parents=True, exist_ok=True)
    arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca'))
    root = arch.get_cert('root')
    issuer = arch.get_cert('interm')
    leaf = arch.get_cert('signer1')
    real_responder = arch.get_cert('interm-ocsp')
    original_ocsp_file = a.fixture_root / '2020-12-25/ocsp-signer1.der'
    original_root_crl_file = a.fixture_root / '2020-12-25/crl-root.der'
    original_leaf_crl_file = a.fixture_root / '2020-12-25/crl-interm.der'
    original_ocsp = ocsp.OCSPResponse.load(original_ocsp_file.read_bytes())
    original_root_crl = crl.CertificateList.load(original_root_crl_file.read_bytes())
    root_key = serialization.load_der_private_key(arch.key_set.get_private_key('root').dump(), None)
    fake_key = serialization.load_der_private_key(arch.key_set.get_private_key('signer1').dump(), None)
    root_public = cx.load_der_x509_certificate(root.dump()).public_key()
    real_issuer_public = cx.load_der_x509_certificate(issuer.dump()).public_key()
    responder_public = cx.load_der_x509_certificate(real_responder.dump()).public_key()
    leaf_public = cx.load_der_x509_certificate(leaf.dump()).public_key()
    files = []

    def write(name, data):
        path = a.out / name
        if path.exists() and path.read_bytes() != data:
            raise RuntimeError(f'Refusing to overwrite different immutable bytes: {path}')
        path.write_bytes(data)
        files.append(dict(file=name, length=len(data), sha256=H(data)))
        return data

    # Existing roots/leafs are copied byte for byte; no certificate trust is invented.
    for label, value in [('root', root), ('interm', issuer), ('signer1', leaf), ('signer2', arch.get_cert('signer2'))]:
        write(f'cert-{label}.der', value.dump())
    write('root-good.crl.der', original_root_crl.dump())
    write('real-delegated-good.ocsp.der', original_ocsp.dump())
    genuine_basic = original_ocsp['response_bytes']['response'].parsed
    responder_public.verify(genuine_basic['signature'].native,
                            genuine_basic['tbs_response_data'].dump(),
                            padding.PKCS1v15(), hashes.SHA256())

    # A real current-valid CA is the target. Its actual root signs the event.
    revoked_root = original_root_crl.copy()
    entry = crl.RevokedCertificate({
        'user_certificate': issuer.serial_number,
        'revocation_date': x509.Time({'utc_time': '201201000000Z'}),
        'crl_entry_extensions': [{'extn_id': 'crl_reason', 'extn_value': 'key_compromise'}],
    })
    entries = revoked_root['tbs_cert_list']['revoked_certificates']
    if entries.native is None:
        revoked_root['tbs_cert_list']['revoked_certificates'] = [entry]
    else:
        assert all(e['user_certificate'].native != issuer.serial_number for e in entries)
        entries.append(entry)
    root_tbs = revoked_root['tbs_cert_list'].dump(force=True)
    revoked_root['signature'] = root_key.sign(root_tbs, padding.PKCS1v15(), hashes.SHA256())
    revoked_raw = write('root-revokes-intermediate.crl.der', revoked_root.dump(force=True))
    parsed_root = crl.CertificateList.load(revoked_raw)
    root_public.verify(parsed_root['signature'].native, parsed_root['tbs_cert_list'].dump(),
                       padding.PKCS1v15(), hashes.SHA256())

    # Copy issuer DN, serial and issuer-signature BIT STRING but replace SPKI
    # with the distinct real signer1 key. The preserved certificate signature
    # necessarily fails on this changed TBS.
    fake_issuer = issuer.copy()
    fake_issuer['tbs_certificate']['subject_public_key_info'] = leaf.public_key.copy()
    fake_issuer_raw = write('fake-issuer-copied-signature.der', fake_issuer.dump(force=True))
    fake_issuer = x509.Certificate.load(fake_issuer_raw)
    assert fake_issuer.issuer.dump() == issuer.issuer.dump()
    assert fake_issuer.subject.dump() == issuer.subject.dump()
    assert fake_issuer.serial_number == issuer.serial_number
    assert bytes(fake_issuer['signature_value']) == bytes(issuer['signature_value'])
    assert fake_issuer.public_key.dump() != issuer.public_key.dump()
    assert fake_issuer.public_key.dump() == leaf.public_key.dump()
    try:
        root_public.verify(fake_issuer['signature_value'].native,
                           fake_issuer['tbs_certificate'].dump(),
                           padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        fake_certificate_rejected = True
    else:
        raise AssertionError('changed fake issuer TBS unexpectedly passed the preserved certificate signature')

    forged_authority = original_ocsp.copy()
    basic = forged_authority['response_bytes']['response'].parsed.copy()
    baseline_certid = basic['tbs_response_data']['responses'][0]['cert_id'].dump()
    actual_certid = basic['tbs_response_data']['responses'][0]['cert_id']
    assert actual_certid['issuer_name_hash'].native == issuer.subject.sha1
    assert actual_certid['issuer_key_hash'].native == issuer.public_key.sha1
    assert actual_certid['serial_number'].native == leaf.serial_number
    assert basic['tbs_response_data']['responses'][0]['cert_status'].name == 'good'
    basic['tbs_response_data']['responder_id'] = ocsp.ResponderId({'by_name': fake_issuer.subject})
    basic['certs'] = [fake_issuer]
    basic_tbs = basic['tbs_response_data'].dump(force=True)
    basic['signature'] = fake_key.sign(basic_tbs, padding.PKCS1v15(), hashes.SHA256())
    forged_authority['response_bytes']['response'] = basic
    forged_raw = write('fake-issuer-signed-good.ocsp.der', forged_authority.dump(force=True))
    reparsed = ocsp.OCSPResponse.load(forged_raw)['response_bytes']['response'].parsed
    assert reparsed['tbs_response_data']['responses'][0]['cert_id'].dump() == baseline_certid
    leaf_public.verify(reparsed['signature'].native, reparsed['tbs_response_data'].dump(),
                       padding.PKCS1v15(), hashes.SHA256())
    try:
        real_issuer_public.verify(reparsed['signature'].native, reparsed['tbs_response_data'].dump(),
                                  padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        real_issuer_cannot_verify = True
    else:
        raise AssertionError('fake-key OCSP unexpectedly verified under the real issuer key')
    # Independently retain a signature-only rejection control for this same TBS.
    bad = forged_authority.copy()
    bad_basic = bad['response_bytes']['response'].parsed.copy()
    signature = bytearray(bad_basic['signature'].native)
    signature[0] ^= 1
    bad_basic['signature'] = bytes(signature)
    bad['response_bytes']['response'] = bad_basic
    bad_raw = write('fake-issuer-bad-raw-signature.ocsp.der', bad.dump(force=True))
    bad_parsed = ocsp.OCSPResponse.load(bad_raw)['response_bytes']['response'].parsed
    assert bad_parsed['tbs_response_data'].dump() == reparsed['tbs_response_data'].dump()
    try:
        leaf_public.verify(bad_parsed['signature'].native, bad_parsed['tbs_response_data'].dump(),
                           padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        bad_signature_rejected = True
    else:
        raise AssertionError('raw signature bit-flip control unexpectedly verified')

    # Actual outer SHA256 signature authenticates a TBS that itself claims
    # SHA384. Matching both algorithm identifiers is a distinct proof boundary.
    leaf_base = crl.CertificateList.load(original_leaf_crl_file.read_bytes())
    write('leaf-real-key-compromise.crl.der', leaf_base.dump())
    mismatch = leaf_base.copy()
    mismatch['tbs_cert_list']['signature'] = {'algorithm':'sha384_rsa'}
    interm_key = serialization.load_der_private_key(arch.key_set.get_private_key('interm').dump(), None)
    mismatch_tbs = mismatch['tbs_cert_list'].dump(force=True)
    mismatch['signature'] = interm_key.sign(mismatch_tbs,padding.PKCS1v15(),hashes.SHA256())
    mismatch_raw = write('leaf-crl-inner-sha384-outer-sha256.der',mismatch.dump(force=True))
    parsed_mismatch = crl.CertificateList.load(mismatch_raw)
    real_issuer_public.verify(parsed_mismatch['signature'].native,
        parsed_mismatch['tbs_cert_list'].dump(),padding.PKCS1v15(),hashes.SHA256())
    assert parsed_mismatch['signature_algorithm']['algorithm'].native == 'sha256_rsa'
    assert parsed_mismatch['tbs_cert_list']['signature']['algorithm'].native == 'sha384_rsa'

    source_inputs = [rec(original_ocsp_file), rec(original_root_crl_file), rec(original_leaf_crl_file)]
    crypto = {'genuine_delegated_ocsp_signature_valid': True,
              'root_revoked_intermediate_crl_signature_valid': True,
              'fake_issuer_certificate_signature_invalid': fake_certificate_rejected,
              'fake_issuer_copies_real_issuer_dn_serial_signature_bits': True,
              'fake_issuer_spki_is_distinct_actual_signer1_key': True,
              'fake_key_ocsp_signature_valid': True,
              'fake_key_ocsp_not_verifiable_by_actual_issuer': real_issuer_cannot_verify,
              'full_original_leaf_actual_issuer_certid_unchanged': True,
              'bad_raw_ocsp_signature_rejected': bad_signature_rejected,
              'bad_signature_tbs_identical': True,
              'crl_algorithm_mismatch_actual_outer_sha256_signature_valid':True,
              'crl_algorithm_mismatch_signed_inner_sha384_outer_sha256':True}
    manifest = {'scope':'Tests-first real cryptographic authority adversaries; no native execution',
                'current_time':NOW,'root_revocation_time':'2020-12-01T00:00:00Z',
                'files':files,'source_inputs':source_inputs,'crypto_controls':crypto,
                'private_keys_written':False,'versions':{n:importlib.metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto','certomancer']},
                'assertions_enabled':__debug__,'provider_exclusions':[]}
    (a.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')

    # Reference operations must parse the SAME immutable DER consumed by
    # native tests. Full certificate DER, not serial alone, defines whether
    # the target is the intermediate: signer1 and interm share serial4097.
    frozen_root = x509.Certificate.load((a.out/'cert-root.der').read_bytes())
    frozen_issuer = x509.Certificate.load((a.out/'cert-interm.der').read_bytes())
    frozen_leaf = x509.Certificate.load((a.out/'cert-signer1.der').read_bytes())
    frozen_revoked_leaf = x509.Certificate.load((a.out/'cert-signer2.der').read_bytes())
    object_diagnostics = {
        'issuer_current_der_sha256':H(issuer.dump()),
        'issuer_frozen_der_sha256':H(frozen_issuer.dump()),
        'issuer_cached_public_key_sha256':H(issuer.public_key.dump()),
        'issuer_frozen_public_key_sha256':H(frozen_issuer.public_key.dump()),
    }
    (a.receipt_dir/'pre-reference-object-diagnostics.json').write_text(json.dumps(object_diagnostics,indent=2)+'\n')
    async def reference():
        cases = [
            ('intermediate-current-good', frozen_issuer, 'root-good.crl.der', None, True),
            ('intermediate-current-revoked', frozen_issuer, 'root-revokes-intermediate.crl.der', None, False),
            ('real-delegated-good', frozen_leaf, 'root-good.crl.der', 'real-delegated-good.ocsp.der', True),
            ('fake-issuer-signed-good', frozen_leaf, 'root-good.crl.der', 'fake-issuer-signed-good.ocsp.der', None),
            ('fake-issuer-bad-raw-signature', frozen_leaf, 'root-good.crl.der', 'fake-issuer-bad-raw-signature.ocsp.der', False),
            ('leaf2-real-current-revoked', frozen_revoked_leaf, 'leaf-real-key-compromise.crl.der', None, False),
            ('leaf2-crl-inner-outer-mismatch', frozen_revoked_leaf, 'leaf-crl-inner-sha384-outer-sha256.der', None, False),
        ]
        result = []
        for name, target, crl_name, ocsp_name, expected in cases:
            policy = CertRevTrustPolicy(RevocationCheckingPolicy(
                ee_certificate_rule=(RevocationCheckingRule.OCSP_REQUIRED if ocsp_name else RevocationCheckingRule.CRL_REQUIRED),
                intermediate_ca_cert_rule=RevocationCheckingRule.CRL_REQUIRED),
                freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION)
            vc = ValidationContext(trust_roots=[frozen_root],other_certs=[frozen_issuer],
                crls=[(a.out/crl_name).read_bytes()] + ([] if crl_name == 'root-good.crl.der' or target.dump() == frozen_issuer.dump() else [(a.out/'root-good.crl.der').read_bytes()]),
                ocsps=[] if ocsp_name is None else [(a.out/ocsp_name).read_bytes()],
                allow_fetching=False, revinfo_policy=policy)
            path = ValidationPath(trust_anchor=CertTrustAnchor(frozen_root),
                                  interm=[] if target.dump() == frozen_issuer.dump() else [frozen_issuer],
                                  leaf=target)
            row = {'case':name,'target_sha256':H(target.dump()),'current_time':NOW,
                   'observed_current_time':datetime.now(timezone.utc).isoformat(),
                   'point_in_time_validation':vc.timing_params.point_in_time_validation,
                   'crl':rec(a.out/crl_name),'ocsp':None if ocsp_name is None else rec(a.out/ocsp_name)}
            try:
                await async_validate_path(vc,path)
                row.update(accepted=True,exception=None)
            except Exception as error:
                row.update(accepted=False,exception={'class':type(error).__name__,'message':str(error)})
            result.append(row)
            (a.receipt_dir/'reference-progress-final.json').write_text(json.dumps(result,indent=2)+'\n')
            if expected is not None:
                assert row['accepted'] == expected, row
        return result
    with freeze_time(NOW):
        results = asyncio.run(reference())
    runtime = {'scope':'Fresh same-byte pinned public async_validate_path comparison; NO new API/native execution',
               'interpreter':rec(sys.executable),'python':sys.version,'generator':rec(__file__),
               'module_sources':[rec(inspect.getfile(module)) for module in [reference_ocsp,ocsp,crl,cx]],
               'versions':manifest['versions'],'assertions_enabled':__debug__,
               'manifest':rec(a.out/'manifest.json'),'crypto_controls':crypto,
               'source_inputs':source_inputs,'object_diagnostics':object_diagnostics,'public_reference_calls':len(results),'cases':results,
               'network_calls':0,'native_calls':0,'cargo_calls':0,'provider_exclusions':[]}
    (a.receipt_dir/'generation-and-reference.json').write_text(json.dumps(runtime,indent=2)+'\n')
    print(json.dumps({'files':len(files),'public_reference_calls':len(results),'cases':[{k:r[k] for k in ['case','accepted','exception']} for r in results], 'manifest':rec(a.out/'manifest.json')}))

if __name__ == '__main__':
    main()
