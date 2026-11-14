"""Generate historical CRLs for supplemental strict signing-policy controls.

This is source support, not a recorded run. When explicitly executed, only the
pinned original Ed25519 CA fixture keys sign revocation evidence. The token PDF
key, original certificates and software-module stores are never replaced. Normal
Certomancer lazy certificate materialization is used solely for exact byte checks
before any CRL is issued; it is not a zero-certificate-construction claim.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import platform
import sys


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), length=len(raw), sha256=digest(raw))


def main():
    assert __debug__ and sys.flags.optimize == 0
    if len(sys.argv) != 2:
        raise SystemExit("Usage: create_policy_revinfo.py ABSOLUTE_NEW_ARTIFACT_DIRECTORY")
    destination = Path(sys.argv[1])
    assert destination.is_absolute() and not destination.exists(), "Never replace an existing artifact directory"
    fixture = Path(__file__).resolve().parent
    input_manifest = json.loads((fixture / "inputs.json").read_text())
    assert input_manifest["architecture"] == "testing-ca-ed25519"
    at_time = datetime(2020, 11, 1, tzinfo=timezone.utc)

    # Imports and signing occur only in the explicitly executed program, never
    # while source-only review/AST parsing reads this helper.
    import certomancer
    from certomancer.registry import CertLabel, KeyLabel, ServiceLabel
    from certomancer.registry import keys as key_registry
    from certomancer.registry import pki_arch as architecture_module
    from certomancer.registry.svc_config import crl as crl_config_module
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from pyhanko_testing_commons.test_data import samples

    versions = {name: importlib.metadata.version(name) for name in
                ["pyhanko", "pyhanko-certvalidator", "certomancer", "cryptography", "asn1crypto"]}
    assert versions["pyhanko"] == "0.38.1" and versions["pyhanko-certvalidator"] == "0.33.0"
    architecture = samples.TESTING_CA_ED25519
    configuration_path = Path(samples.CERTOMANCER_CONFIG_PATH).resolve()
    ca_key_inputs = []
    for label, filename in [("root", "root_ca.key.pem"), ("interm", "intermediate_ca.key.pem")]:
        actual_path = Path(architecture.key_set[KeyLabel(label)].path).resolve()
        expected_path = configuration_path.parent / "keys-ed25519" / filename
        assert actual_path == expected_path.resolve(), "Unexpected original CA key source"
        ca_key_inputs.append(dict(label=label, input_file=identity(actual_path),
                                  use="Pinned CA certificate materialization and CRL signature only; no key bytes emitted"))

    original_signer_key_path = Path(architecture.key_set[KeyLabel("signer1")].path).resolve()
    assert original_signer_key_path == (configuration_path.parent / "keys-ed25519" / "signer.key.pem").resolve()
    original_signer_key_input = identity(original_signer_key_path)
    assert original_signer_key_input["sha256"] == input_manifest["private_key_input"]["sha256"]

    # The existing frozen public DER files are authoritative. A mismatch aborts
    # BEFORE creating the destination or issuing any CRL; no cache injection,
    # fixture replacement or replacement certificate/key generation is allowed.
    certificates = {}
    certificate_rows = []
    assert {item["label"] for item in input_manifest["certificates"]} == {"root", "interm", "signer1"}
    for item in input_manifest["certificates"]:
        path = fixture / item["file"]
        raw = path.read_bytes()
        assert len(raw) == item["length"] and digest(raw) == item["sha256"]
        actual = architecture.get_cert(CertLabel(item["label"]))
        actual_der = actual.dump()
        assert actual_der == raw, "Pinned configured certificate does not equal frozen original DER"
        parsed = x509.load_der_x509_certificate(raw)
        assert isinstance(parsed.public_key(), Ed25519PublicKey)
        certificates[item["label"]] = (actual, parsed)
        certificate_rows.append(dict(label=item["label"], authoritative_input=identity(path),
                                     architecture_der_length=len(actual_der), architecture_der_sha256=digest(actual_der),
                                     byte_equal=True, subject_der_sha256=digest(actual.subject.dump()),
                                     serial_number=str(parsed.serial_number)))

    destination.mkdir(mode=0o700, parents=True)
    crls = []
    for issuer_label, target_label in [("root", "interm"), ("interm", "signer1")]:
        service_label = ServiceLabel(issuer_label)
        service = architecture.service_registry.get_crl_repo_info(service_label)
        assert str(service.signing_key) == issuer_label
        issuer, issuer_crypto = certificates[issuer_label]
        target, target_crypto = certificates[target_label]
        assert target.issuer.dump() == issuer.subject.dump()
        original = architecture.service_registry.get_crl(service_label, at_time=at_time)
        raw = original.dump()
        parsed = x509.load_der_x509_crl(raw)
        tbs = original["tbs_cert_list"]
        assert tbs["issuer"].dump() == issuer.subject.dump()
        assert parsed.issuer == issuer_crypto.subject
        assert parsed.signature_algorithm_oid.dotted_string == "1.3.101.112"
        # Verify actual returned signature with the actual frozen issuer's public
        # key. A failed crypto check raises; no fixture is labelled authenticated.
        issuer_crypto.public_key().verify(parsed.signature, parsed.tbs_certlist_bytes)
        assert parsed.tbs_certlist_bytes == tbs.dump()
        assert parsed.signature == original["signature"].native
        this_update = tbs["this_update"].native
        next_update = tbs["next_update"].native
        assert this_update.tzinfo is not None and next_update.tzinfo is not None
        assert this_update <= at_time < next_update
        target_revocation = parsed.get_revoked_certificate_by_serial_number(target_crypto.serial_number)
        assert target_revocation is None, "Original policy-positive target is revoked at fixture time"
        filename = f"policy-{issuer_label}.crl.der"
        output = destination / filename
        output.write_bytes(raw)
        crl_number = parsed.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        crls.append(dict(issuer_label=issuer_label, service_label=str(service_label), filename=filename,
                         output=identity(output), requested_at=at_time.isoformat(),
                         issuer_certificate_sha256=digest(issuer.dump()),
                         issuer_subject_der_sha256=digest(issuer.subject.dump()),
                         actual_crl_issuer_der_sha256=digest(tbs["issuer"].dump()),
                         signature_algorithm_oid=parsed.signature_algorithm_oid.dotted_string,
                         tbs_length=len(parsed.tbs_certlist_bytes), tbs_sha256=digest(parsed.tbs_certlist_bytes),
                         signature_length=len(parsed.signature), signature_sha256=digest(parsed.signature),
                         cryptography_signature_verified=True, this_update=this_update.isoformat(),
                         next_update=next_update.isoformat(), crl_number=crl_number,
                         revoked_entry_count=len(parsed), target_label=target_label,
                         target_certificate_sha256=digest(target.dump()), target_serial_number=str(target_crypto.serial_number),
                         target_not_in_revoked_entries=True))

    modules = [certomancer, key_registry, architecture_module, crl_config_module, cryptography, samples]
    record = dict(kind="Historical strict-policy CRL fixture generation from pinned original Ed25519 CA keys",
                  host=platform.node(), pid=__import__("os").getpid(), interpreter=identity(sys.executable),
                  python=sys.version, assertions_enabled=__debug__, packages=versions,
                  generation_helper=identity(__file__), architecture="testing-ca-ed25519",
                  requested_at=at_time.isoformat(), original_configuration=identity(configuration_path),
                  original_input_manifest=identity(fixture / "inputs.json"),
                  module_sources=[identity(inspect.getsourcefile(module)) for module in modules],
                  original_ca_key_inputs=ca_key_inputs,
                  original_signer_source_key_input=dict(input_file=original_signer_key_input,
                      use="Pinned configured signer public-key materialization for exact certificate crosscheck only; never token readback, CRL signing or PDF signing"),
                  certificate_crosschecks=certificate_rows, crls=crls,
                  materialization_scope="Pinned architecture's normal lazy get_cert materializes original configured certificates solely for exact frozen-DER crosscheck; may read original CA keys",
                  policy_scope="Supplemental 2020-11-01 hard-fail policy contexts only; original five no-fetcher bodies unchanged",
                  limitations="Cryptographic signature/issuer/time/target absence verified here; actual path/revocation-policy acceptance is proved only by separate native/oracle consumers",
                  token_private_key_readback=False, replacement_key_generation=False,
                  provider_module_operations=False, token_store_changes=False, pdf_signing_operations=False)
    manifest = destination / "policy-revinfo-manifest.json"
    manifest.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(dict(manifest=str(manifest), manifest_sha256=identity(manifest)["sha256"],
                          crls=[dict(file=row["filename"], sha256=row["output"]["sha256"]) for row in crls])))


if __name__ == "__main__":
    main()
