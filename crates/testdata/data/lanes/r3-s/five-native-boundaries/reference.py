#!/usr/bin/env python3
"""Run five unchanged originals and real same-input native-boundary peers.

Plain test output only. These controls do not make the missing deprecated or
object-provenance protocols into passing upstream ports.
"""
import argparse
import asyncio
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--native-data', type=Path, required=True)
args = parser.parse_args()
if not __debug__:
    raise RuntimeError('Reference assertions must remain enabled')

pdf_tests = '/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/tests/test_internal_utils.py'
cv_tests = '/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator/tests/test_registry.py'
for source, names in [(cv_tests, ['test_system_trust_fallback_deprecated',
                                 'test_extra_trust_roots_deprecated']),
                      (pdf_tests, ['test_name_encode_fail',
                                   'test_text_string_no_bytes_available',
                                   'test_dictionary_setvalue_guard'])]:
    subprocess.run([sys.executable, '-B', '-m', 'pytest', '-q', '-p',
                    'no:cacheprovider', *[source + '::' + name for name in names]],
                   check=True)

from asn1crypto import pem, x509
from pyhanko.pdf_utils import generic, misc
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError


def cert(directory, filename):
    raw = (args.native_data / 'pyhanko-certvalidator' / directory / filename).read_bytes()
    if pem.detect(raw):
        _, _, raw = pem.unarmor(raw)
    return x509.Certificate.load(raw)


root = cert('testing-ca-ed25519', 'root.cert.pem')
intermediate = cert('testing-ca-ed25519', 'interm.cert.pem')
leaf = cert('testing-ca-ed25519', 'signer.cert.pem')
unrelated = cert('testing-ca-ed448', 'root.cert.pem')


async def real_path_cases():
    for label, roots, expected in [('empty_roots', [], False),
                                    ('explicit_root', [root], True),
                                    ('unrelated_root', [unrelated], False),
                                    ('added_root', [unrelated, root], True)]:
        context = ValidationContext(
            trust_roots=roots, other_certs=[root, intermediate],
            moment=datetime(2020, 11, 1, tzinfo=timezone.utc),
            allow_fetching=False, revocation_mode='soft-fail')
        validator = CertificateValidator(leaf, validation_context=context)
        try:
            path = await validator.async_validate_usage(set())
        except PathBuildingError:
            assert not expected, label
            print('REGISTRY_PEER', label, 'DENY')
        else:
            assert expected, label
            assert [c.dump() for c in path] == [root.dump(), intermediate.dump(), leaf.dump()]
            print('REGISTRY_PEER', label, 'VALID')

    changed = bytearray(leaf.dump())
    changed[-1] ^= 1
    forged = x509.Certificate.load(bytes(changed))
    context = ValidationContext(
        trust_roots=[unrelated, root], other_certs=[intermediate],
        moment=datetime(2020, 11, 1, tzinfo=timezone.utc),
        allow_fetching=False, revocation_mode='soft-fail')
    try:
        await CertificateValidator(forged, validation_context=context).async_validate_usage(set())
    except PathValidationError as error:
        assert 'signature' in str(error).lower()
        print('REGISTRY_PEER forged_signature DENY')
    else:
        raise AssertionError('A trusted issuer must not rescue a forged leaf signature')


asyncio.run(real_path_cases())

try:
    generic.pdf_name('NoSlashHere').write_to_stream(BytesIO())
except misc.PdfWriteError as error:
    assert 'Could not serialise name object' in str(error)
    print('PDF_PEER bare_name_writer=REJECT native_difference=ACCEPT')
else:
    raise AssertionError('Original bare-name writer must refuse')
out = BytesIO()
generic.pdf_name('/NoSlashHere').write_to_stream(out)
assert out.getvalue() == b'/NoSlashHere'

try:
    generic.TextStringObject('generic text string').original_bytes
except misc.PdfError as error:
    assert 'No information' in str(error)
    print('PDF_PEER fresh_text_original_bytes=REJECT native_representation=MATERIALIZED')
else:
    raise AssertionError('Fresh Python text has no original encoding information')
assert generic.pdf_string(b'generic text string').original_bytes == b'generic text string'

for operation in ['assignment', 'setdefault']:
    dictionary = generic.DictionaryObject()
    try:
        if operation == 'assignment':
            dictionary['/A'] = 1
        else:
            dictionary.setdefault(generic.pdf_name('/A'), 1)
    except ValueError as error:
        assert 'must be PdfObject' in str(error)
        assert len(dictionary) == 0
        print('PDF_PEER raw_integer_' + operation + '=REJECT')
    else:
        raise AssertionError('Original raw integer guard must refuse')
dictionary = generic.DictionaryObject()
dictionary['/A'] = generic.NumberObject(1)
assert dictionary.setdefault(generic.pdf_name('/A'), generic.NumberObject(2)) == 1
assert dictionary['/A'] == 1
print('PDF_PEER explicit_object_default=PRESERVE_EXISTING')
print('SUMMARY originals=5 passed; PKI peers=5 matched; PDF differences=explicit; new_original_credit=0')
