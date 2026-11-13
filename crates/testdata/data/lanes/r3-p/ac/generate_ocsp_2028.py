"""Export genuine pinned Certomancer AC OCSP at the requested validation time.

Test fixture regeneration. Never rewrite the 2020 signing fixture and
never adjust a validator's policy/time or preload the new response as evidence.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[6]

EXPECTED = {
    "ac.der": "b650abefb4270855a7bb3aba8879044c64d52ef1969178ed66d9073f4c150909",
    "aa.der": "f99a3526088b5fd5aec2e6cc48ced611ef77de337b11c782f0363de4359d7e8b",
    "root.der": "8de3a2712e46d0ea6e9b5f234457aee5e9c7bed69fdf7feed0c5a98649688a3c",
    "root-aa.der": "57b9e80c61bdb208e67f02a4949d251e0552564728c9262f6cbea66520830b06",
}

def digest(data):
    return sha256(data).hexdigest()

def iso(value):
    return value.isoformat().replace("+00:00", "Z")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--at", default="2028-02-01T00:00:00Z")
    args = parser.parse_args()
    at = datetime.fromisoformat(args.at.replace("Z", "+00:00"))
    assert at == datetime(2028, 2, 1, tzinfo=timezone.utc)
    inputs = Path(args.inputs)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    raw = {name: (inputs / name).read_bytes() for name in EXPECTED}
    records = {name: {"path": str((inputs / name).resolve()), "bytes": len(data),
                      "sha256": digest(data)} for name, data in raw.items()}
    print("AC_2028_INPUT " + json.dumps(records), file=sys.stderr, flush=True)
    assert {name: row["sha256"] for name, row in records.items()} == EXPECTED
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"

    from asn1crypto import cms, ocsp, x509
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from certomancer.registry import ArchLabel, CertLabel
    from pyhanko_testing_commons.test_data.samples import CERTOMANCER
    from pyhanko_certvalidator.util import extract_ac_issuer_dir_name
    import certomancer.services
    import certomancer.registry.pki_arch

    arch = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
    # Same public cert/AC identities as the ACTUAL native produced PDF input.
    assert arch.get_attr_cert(CertLabel("alice-role-with-rev")).dump() == raw["ac.der"]
    for label, name in [("leaf-aa", "aa.der"), ("root", "root.der"), ("root-aa", "root-aa.der")]:
        assert arch.get_cert(CertLabel(label)).dump() == raw[name]
    ac = cms.AttributeCertificateV2.load(raw["ac.der"], strict=True)
    aa = x509.Certificate.load(raw["aa.der"], strict=True)
    issuer_name = extract_ac_issuer_dir_name(ac)
    assert issuer_name.dump() == aa.subject.dump()
    serial = ac["ac_info"]["serial_number"].native
    cert_id = ocsp.CertId({
        "hash_algorithm": {"algorithm": "sha1"},
        "issuer_name_hash": issuer_name.sha1,
        "issuer_key_hash": aa.public_key.sha1,
        "serial_number": serial,
    })
    services = arch.service_registry
    matches = [info for info in services.list_ocsp_responders()
               if str(info.label) == "leaf-aa" and info.is_aa_responder]
    assert len(matches) == 1
    info = matches[0]
    assert arch.get_cert(info.resolve_issuer_cert(arch)).dump() == raw["aa.der"]
    responder = services.summon_responder(info.label, at_time=at)
    # Public service methods used by export_revinfo.py, explicitly for the AC.
    single = responder.format_single_ocsp_response(cert_id, aa)
    response = responder.assemble_simple_ocsp_responses([single], nonce=None)
    encoded = response.dump()
    parsed = ocsp.OCSPResponse.load(encoded, strict=True)
    assert parsed["response_status"].native == "successful"
    basic = parsed["response_bytes"]["response"].parsed
    data = basic["tbs_response_data"]
    assert len(data["responses"]) == 1
    actual = data["responses"][0]
    assert actual["cert_id"].dump() == cert_id.dump()
    assert actual["cert_status"].name == "good"
    assert actual["this_update"].native == at
    assert data["produced_at"].native == at
    assert actual["next_update"].native > at
    assert responder.responder_cert.dump() == raw["aa.der"]
    assert [cert.dump() for cert in basic["certs"]] == [raw["aa.der"]]
    assert basic["signature_algorithm"]["algorithm"].native == "sha256_rsa"
    public_key = crypto_x509.load_der_x509_certificate(raw["aa.der"]).public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    public_key.verify(basic["signature"].native, data.dump(), padding.PKCS1v15(), hashes.SHA256())

    original_path = inputs / "ac-ocsp.der"
    original = original_path.read_bytes()
    old_basic = ocsp.OCSPResponse.load(original, strict=True)["response_bytes"]["response"].parsed
    old_single = old_basic["tbs_response_data"]["responses"][0]
    assert old_single["cert_id"].dump() == cert_id.dump()
    old_hash = digest(original)
    filename = "ocsp-alice-role-with-rev-2028-02-01.der"
    (out / filename).write_bytes(encoded)
    public_dir = out / "bound-public-inputs"
    public_dir.mkdir(exist_ok=True)
    for name, value in raw.items():
        (public_dir / name).write_bytes(value)
    source_files = {
        "generator": Path(__file__),
        "certomancer_services": Path(certomancer.services.__file__),
        "certomancer_registry": Path(certomancer.registry.pki_arch.__file__),
        "existing_pkc_exporter": (REPO / "crates/pades-sign/oracle/export_revinfo.py"),
    }
    metadata = {
        "purpose": "current-time2028 AC response for test factory mapping; not historical AC retiming",
        "pyhanko": version("pyhanko"), "certvalidator": version("pyhanko-certvalidator"),
        "certomancer": version("certomancer"), "interpreter": sys.executable,
        "actual_inputs": records, "at": iso(at),
        "response": {"file": filename, "bytes": len(encoded), "sha256": digest(encoded),
                     "signature_valid_with_actual_aa": True, "signature_algorithm": "sha256_rsa",
                     "produced_at": iso(data["produced_at"].native),
                     "this_update": iso(actual["this_update"].native),
                     "next_update": iso(actual["next_update"].native), "status": "good",
                     "issuer_name_hash": cert_id["issuer_name_hash"].native.hex(),
                     "issuer_key_hash": cert_id["issuer_key_hash"].native.hex(),
                     "serial_number": str(serial), "cert_id_sha256": digest(cert_id.dump()),
                     "nonce": None, "responder_certificate_sha256": digest(raw["aa.der"])},
        "original2020": {"path": str(original_path.resolve()), "sha256": old_hash,
                         "this_update": iso(old_single["this_update"].native),
                         "next_update": iso(old_single["next_update"].native),
                         "same_exact_cert_id": True, "unchanged": original_path.read_bytes() == original},
        "source_pins": {name: {"path": str(path.resolve()), "sha256": digest(path.read_bytes())}
                        for name, path in source_files.items()},
        "main_source_head": subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip(),
        "whole_ac_validation": "not executed by exporter; root must validate through unchanged native fetch/policy API",
        "no_private_key_copied": True, "new_unique_credit": 0,
    }
    assert all((inputs / name).read_bytes() == value for name, value in raw.items())
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata), flush=True)

if __name__ == "__main__":
    main()
