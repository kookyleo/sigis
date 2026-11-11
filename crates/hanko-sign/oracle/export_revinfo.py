"""Export OCSP responses and CRLs of the Certomancer test PKI at the pinned
times that pyHanko's signing tests freeze the clock to.

Usage: python export_revinfo.py <crypto-dir> <out-dir>

For every architecture, time and OCSP service, writes an OCSP response
(without nonce) for every certificate the service covers, as
``<arch>/<time>/ocsp-<cert label>.der``; for every CRL repository, the CRL
at that time as ``<arch>/<time>/crl-<repo label>.der``. These are the
responses Certomancer's live services (``pki_services`` in pyHanko's tests)
return at that time. Signatures are deterministic for RSA keys.
"""

import os
import sys
from datetime import datetime, timezone

from asn1crypto import ocsp
from certomancer.registry import ArchLabel, CertomancerConfig

ARCHS = [
    'testing-ca',
    'testing-ca-ecdsa',
    'testing-ca-ocsp-no-nextupdate',
    'testing-ca-with-aa',
    'unrelated-tsa',
]
TIMES = [
    '2020-01-20', '2020-10-01', '2020-10-10', '2020-11-01', '2020-11-20',
    '2020-12-01', '2020-12-05', '2021-11-01', '2025-11-01', '2025-12-01',
    '2028-02-01', '2028-12-01', '2035-11-01', '2040-11-01',
]


def cert_id(cert, issuer):
    return ocsp.CertId({
        'hash_algorithm': {'algorithm': 'sha1'},
        'issuer_name_hash': issuer.subject.sha1,
        'issuer_key_hash': issuer.public_key.sha1,
        'serial_number': cert.serial_number,
    })


def main():
    crypto_dir, out_dir = sys.argv[1], sys.argv[2]
    cfg = CertomancerConfig.from_file(
        os.path.join(crypto_dir, 'certomancer.yml'), key_search_dir=crypto_dir
    )
    count = 0
    for arch_name in ARCHS:
        arch = cfg.get_pki_arch(ArchLabel(arch_name))
        services = arch.service_registry
        for t in TIMES:
            at = datetime.fromisoformat(t).replace(tzinfo=timezone.utc)
            d = os.path.join(out_dir, arch_name, t)
            os.makedirs(d, exist_ok=True)
            for info in services.list_ocsp_responders():
                responder = services.summon_responder(info.label, at_time=at)
                issuer_label = info.resolve_issuer_cert(arch)
                issuer = arch.get_cert(issuer_label)
                for iss, specs in arch.enumerate_certs_by_issuer():
                    if str(iss) != str(info.for_issuer):
                        continue
                    for spec in specs:
                        try:
                            cert = arch.get_cert(spec.label)
                        except Exception:
                            continue
                        if cert.issuer != issuer.subject:
                            continue
                        try:
                            single = responder.format_single_ocsp_response(
                                cert_id(cert, issuer), issuer
                            )
                        except Exception:
                            continue
                        resp = responder.assemble_simple_ocsp_responses([single])
                        with open(os.path.join(d, f'ocsp-{spec.label}.der'), 'wb') as f:
                            f.write(resp.dump())
                        count += 1
            for info in services.list_crl_repos():
                try:
                    crl = services.get_crl(info.label, at_time=at)
                except Exception:
                    continue
                with open(os.path.join(d, f'crl-{info.label}.der'), 'wb') as f:
                    f.write(crl.dump())
                count += 1
    print(count)


if __name__ == '__main__':
    main()
