"""Fresh, genuinely signed issuer-Name encoding controls; no native execution."""

import asyncio
import argparse
from datetime import datetime, timezone
from hashlib import sha256, new as hash_new
from importlib.metadata import version
import json
from pathlib import Path

from asn1crypto import cms, ocsp, pem, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.validate import async_validate_ac


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
parser.add_argument("--upstream-cv", type=Path, default=Path("/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator"))
args = parser.parse_args()
OUT = args.output.resolve()
OUT.mkdir(parents=True, exist_ok=True)
FIX = args.repo / "crates/testdata/data/pyhanko-certvalidator/attribute-certs/basic-aa"
KEY = args.upstream_cv / "tests/fixtures/attribute-certs/keys/aa.key.pem"
AT = datetime(2019, 12, 12, tzinfo=timezone.utc)


def raw(path):
    value = path.read_bytes()
    return pem.unarmor(value)[2] if pem.detect(value) else value


def digest(value):
    return sha256(value).hexdigest()


def main():
    assert version('pyhanko') == '0.38.1'
    assert version('pyhanko-certvalidator') == '0.33.0'
    aa = x509.Certificate.load(raw(FIX / 'interm/role-aa.crt'))
    alice = x509.Certificate.load(raw(FIX / 'people-ca/alice.crt'))
    bob = x509.Certificate.load(raw(FIX / 'people-ca/bob.crt'))
    base = cms.AttributeCertificateV2.load(raw(FIX / 'aa/alice-role-with-rev.attr.crt'))
    key = serialization.load_pem_private_key(KEY.read_bytes(), password=None)
    public = key.public_key()
    assert public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == aa.public_key.dump()
    assert base['signature_algorithm']['algorithm'].native == 'sha256_rsa'
    assert base['ac_info']['signature']['algorithm'].native == 'sha256_rsa'
    base_name = base['ac_info']['issuer'].chosen['issuer_name'][0].chosen.untag()
    assert base_name.dump() == aa.subject.dump()

    alternate = aa.subject.copy()
    changed = []
    for rdn in alternate.chosen:
        for atv in rdn:
            if atv['type'].native == 'common_name':
                assert atv['value'].name == 'utf8_string'
                value = atv['value'].native
                atv['value'] = x509.DirectoryString(name='printable_string', value=value)
                changed.append({'oid': atv['type'].dotted, 'text': value,
                                'old_type': 'utf8_string', 'new_type': 'printable_string'})
    assert len(changed) == 1
    assert alternate.dump() != aa.subject.dump()
    assert alternate.native == aa.subject.native
    assert alternate.hashable == aa.subject.hashable
    assert alternate == aa.subject

    variant = base.copy()
    variant['ac_info']['issuer'].chosen['issuer_name'] = x509.GeneralNames([
        x509.GeneralName(name='directory_name', value=alternate),
    ])
    variant['ac_info'] = cms.AttributeCertificateInfoV2.load(variant['ac_info'].dump(force=True))
    variant['signature'] = key.sign(variant['ac_info'].dump(), padding.PKCS1v15(), hashes.SHA256())
    variant = cms.AttributeCertificateV2.load(variant.dump(force=True), strict=True)
    assert variant.dump() != base.dump()
    assert variant['ac_info']['issuer'].chosen['issuer_name'][0].chosen.untag().dump() == alternate.dump()
    public.verify(base['signature'].native, base['ac_info'].dump(), padding.PKCS1v15(), hashes.SHA256())
    public.verify(variant['signature'].native, variant['ac_info'].dump(), padding.PKCS1v15(), hashes.SHA256())
    for field in ['serial_number', 'holder', 'attributes', 'att_cert_validity_period', 'extensions', 'signature']:
        assert base['ac_info'][field].dump() == variant['ac_info'][field].dump(), field

    original_response = ocsp.OCSPResponse.load(raw(FIX / 'alice-all-good.ors'))

    def response_for_name(name):
        response = original_response.copy()
        basic = response['response_bytes']['response'].parsed.copy()
        assert basic['signature_algorithm']['algorithm'].native == 'sha256_rsa'
        info = basic['tbs_response_data']['responses'][0]
        cert_id = info['cert_id']
        hash_name = cert_id['hash_algorithm']['algorithm'].native
        assert hash_name in ('sha1', 'sha256')
        assert cert_id['serial_number'].native == base['ac_info']['serial_number'].native
        assert cert_id['issuer_key_hash'].native == getattr(aa.public_key, hash_name)
        assert info['cert_status'].name == 'good'
        cert_id['issuer_name_hash'] = hash_new(hash_name, name.dump()).digest()
        basic['tbs_response_data'] = ocsp.ResponseData.load(basic['tbs_response_data'].dump(force=True))
        basic['signature'] = key.sign(basic['tbs_response_data'].dump(), padding.PKCS1v15(), hashes.SHA256())
        public.verify(basic['signature'].native, basic['tbs_response_data'].dump(), padding.PKCS1v15(), hashes.SHA256())
        response['response_bytes']['response'] = basic
        return ocsp.OCSPResponse.load(response.dump(force=True), strict=True)

    actual = response_for_name(aa.subject)
    encoded = response_for_name(alternate)
    bad = actual.copy()
    basic = bad['response_bytes']['response'].parsed.copy()
    signature = bytearray(basic['signature'].native)
    signature[-1] ^= 1
    basic['signature'] = bytes(signature)
    bad['response_bytes']['response'] = basic

    files = {
        'aa.der': aa.dump(), 'holder-alice.der': alice.dump(), 'holder-bob.der': bob.dump(),
        'base-ac.der': base.dump(), 'alternate-name-ac.der': variant.dump(),
        'original-good.ocsp.der': original_response.dump(),
        'actual-aa-name-good.ocsp.der': actual.dump(),
        'alternate-ac-name-good.ocsp.der': encoded.dump(),
        'actual-aa-name-bad-signature.ocsp.der': bad.dump(),
    }
    for name, value in files.items():
        (OUT / name).write_bytes(value)

    cases = [
        ('base_original_positive', base, original_response, alice),
        ('base_resigned_actual_name_positive', base, actual, alice),
        ('alternate_ac_actual_aa_name', variant, actual, alice),
        ('alternate_ac_matching_alternate_name_positive', variant, encoded, alice),
        ('base_ac_alternate_name_response', base, encoded, alice),
        ('alternate_ac_missing_response', variant, None, alice),
        ('alternate_ac_wrong_holder', variant, actual, bob),
        ('base_actual_name_bad_signature', base, bad, alice),
    ]
    rows = []
    policy = CertRevTrustPolicy(RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.OCSP_REQUIRED,
        intermediate_ca_cert_rule=RevocationCheckingRule.OCSP_REQUIRED,
    ))

    async def run():
        for case, ac, response, holder in cases:
            ctx = ValidationContext(
                trust_roots=[aa], other_certs=[aa], moment=AT,
                revinfo_policy=policy, ocsps=[] if response is None else [response],
                crls=[], allow_fetching=False,
            )
            row = {'case': case, 'ac_sha256': digest(ac.dump()),
                   'response_sha256': None if response is None else digest(response.dump()),
                   'holder_sha256': digest(holder.dump()),
                   'issuer_name_der_sha256': digest(ac['ac_info']['issuer'].chosen['issuer_name'][0].chosen.untag().dump())}
            try:
                result = await async_validate_ac(ac, ctx, holder_cert=holder)
                row.update(accepted=True, aa_path_length=len(result.aa_path),
                           approved_attributes=sorted(result.approved_attributes))
            except Exception as error:
                row.update(accepted=False, error_class=type(error).__name__, message=str(error))
            finally:
                await ctx.aclose()
            rows.append(row)
            if case in ('base_original_positive', 'base_resigned_actual_name_positive'):
                assert row['accepted'], 'Positive control failed; experiment remains preparation only: ' + str(row)
            expected = case in (
                'base_original_positive', 'base_resigned_actual_name_positive',
                'alternate_ac_matching_alternate_name_positive',
            )
            assert row['accepted'] == expected, row
            print(json.dumps(row), flush=True)

    try:
        asyncio.run(run())
        complete = True
        failure = None
    except Exception as error:
        complete = False
        failure = str(error)
    output = {
        'kind': 'fresh pinned public async_validate_ac experiment; no native execution',
        'complete': complete, 'failure': failure, 'executed_utc': datetime.now(timezone.utc).isoformat(),
        'versions': {'pyhanko': version('pyhanko'), 'certvalidator': version('pyhanko-certvalidator')},
        'validation_time': AT.isoformat(),
        'context': {'trust_anchor': 'actual AA certificate', 'allow_fetching': False,
                    'ee_rule': 'OCSP_REQUIRED', 'intermediate_rule': 'OCSP_REQUIRED',
                    'supplied_crls': 0, 'fallback_to_crl': False},
        'changes': changed, 'name_native_equal': alternate.native == aa.subject.native,
        'name_hashable_equal': alternate.hashable == aa.subject.hashable,
        'name_der_equal': alternate.dump() == aa.subject.dump(),
        'actual_aa_name_sha1': aa.subject.sha1.hex(), 'alternate_ac_name_sha1': alternate.sha1.hex(),
        'aa_spki_sha256': digest(aa.public_key.dump()),
        'both_AC_signatures_verified_with_actual_AA_key': True,
        'both_good_responses_signatures_verified_with_actual_AA_key': True,
        'public_validation_calls': len(rows), 'records': rows,
        'files': [{'file': name, 'sha256': digest(value), 'length': len(value)} for name, value in files.items()],
        'private_key_copied_or_written': False, 'native_verdict_claim': False, 'upstream_credit': 0,
    }
    (OUT / 'results.json').write_text(json.dumps(output, indent=2) + '\n')
    if not complete:
        raise SystemExit(failure)


if __name__ == '__main__':
    main()
