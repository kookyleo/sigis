"""Export the Certomancer test PKI used by pyHanko's signing tests.

Writes DER certificates and a manifest (JSON) per architecture to
``crates/testdata/data/lanes/d/pki/<arch>/``. Private keys are not
copied: the manifest names the key file in ``data/pyhanko/crypto/`` (pyHanko's
public test keys) and its passphrase.

Usage: python export_pki.py <crypto-dir> <out-dir>

Certomancer signs RSA certificates deterministically; ECDSA and DSA
signatures use a random nonce, so re-running the script yields different (but
equivalent) certificates for those architectures.
"""

import json
import os
import sys

from certomancer.registry import ArchLabel, CertomancerConfig

ARCHS = [
    'testing-ca',
    'testing-ca-ecdsa',
    'testing-ca-ed25519',
    'testing-ca-ed448',
    'testing-ca-dsa',
    'testing-ca-mldsa',
    'testing-ca-with-errors',
    'testing-ca-ocsp-no-nextupdate',
    'testing-ca-with-aa',
    'unrelated-tsa',
]


def main():
    crypto_dir, out_dir = sys.argv[1], sys.argv[2]
    cfg = CertomancerConfig.from_file(
        os.path.join(crypto_dir, 'certomancer.yml'), key_search_dir=crypto_dir
    )
    summary = {}
    skipped = []
    for arch_name in ARCHS:
        arch = cfg.get_pki_arch(ArchLabel(arch_name))
        arch_dir = os.path.join(out_dir, arch_name)
        os.makedirs(arch_dir, exist_ok=True)
        certs = {}
        for _issuer, specs in arch.enumerate_certs_by_issuer():
            for spec in specs:
                label = str(spec.label)
                try:
                    cert = arch.get_cert(spec.label)
                except Exception as e:  # e.g. sha512_dsa, unknown to asn1crypto
                    skipped.append(f'{arch_name}/{label}: {e.__class__.__name__}')
                    continue
                fname = f'{label}.crt'
                with open(os.path.join(arch_dir, fname), 'wb') as f:
                    f.write(cert.dump())
                revocation = None
                if spec.revocation is not None:
                    revocation = {
                        'revoked_since': spec.revocation.revoked_since.isoformat(),
                        'reason': spec.revocation.reason.native,
                    }
                certs[label] = {
                    'file': fname,
                    'subject_key': str(spec.subject_key),
                    'issuer': str(spec.issuer),
                    'revocation': revocation,
                }
        keys = {}
        key_set = arch.key_set
        for label, key in key_set._dict.items():
            keys[str(label)] = {
                'path': os.path.relpath(str(key.path), crypto_dir) if key.path else None,
                'password': key.password.decode() if key.password else None,
            }
        services = arch.service_registry
        ocsp = {
            str(i.label): {
                'for_issuer': str(i.for_issuer),
                'responder_cert': str(i.responder_cert),
                'signing_key': str(i.signing_key),
            }
            for i in services.list_ocsp_responders()
        }
        crl = {
            str(i.label): {
                'for_issuer': str(i.for_issuer),
                'signing_key': str(i.signing_key),
                'simulated_update_schedule_days':
                    i.simulated_update_schedule.days,
            }
            for i in services.list_crl_repos()
        }
        tsa = {
            str(i.label): {
                'signing_key': str(i.signing_key),
                'signing_cert': str(i.signing_cert),
            }
            for i in services.list_time_stamping_services()
        }
        manifest = {
            'arch': arch_name,
            'certs': certs,
            'keys': keys,
            'ocsp': ocsp,
            'crl_repos': crl,
            'tsa': tsa,
        }
        with open(os.path.join(arch_dir, 'manifest.json'), 'w') as f:
            json.dump(manifest, f, indent=1, sort_keys=True)
        summary[arch_name] = len(certs)
    print(json.dumps({'certs': summary, 'skipped': skipped}))


if __name__ == '__main__':
    main()
