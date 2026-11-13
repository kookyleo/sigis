"""Generate fixed signed RFC3161 request-binding fixtures with pinned pyHanko.

Only public DER is written. All modifications occur in the request supplied to
DummyTimeStamper before it builds and signs TSTInfo. No network is used.
"""
from datetime import datetime, timezone
from hashlib import sha256, sha384
from importlib.metadata import version
import inspect
import json
from pathlib import Path
import sys
from unittest.mock import patch

from asn1crypto import algos, cms
from certomancer.registry.common import ServiceLabel
import pyhanko.sign.timestamps.api as ts_api
import pyhanko.sign.timestamps.common_utils as ts_common
import pyhanko.sign.timestamps.dummy_client as ts_dummy
import pyhanko.sign.validation.generic_cms as ts_validation
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_testing_commons.test_utils import signing_commons
from pyhanko_testing_commons.test_utils.signing_commons import (
    FROM_CA, ROOT_CERT, TESTING_CA, TSA_CERT,
)

ROOT = Path(__file__).resolve().parent
NOW = datetime(2020, 11, 1, tzinfo=timezone.utc)
PREIMAGE = b"HTTP TSA request binding\x00probe\xff"
NONCE = int.from_bytes(bytes.fromhex("0102030405060708"), "big")
SERIAL = int.from_bytes(bytes.fromhex("0102030405060709"), "big")
VERSIONS = {"pyHanko": version("pyHanko"), "certvalidator": version("pyhanko-certvalidator")}
assert VERSIONS == {"pyHanko": "0.38.1", "certvalidator": "0.33.0"}


def save(relative, data):
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": relative, "sha256": sha256(data).hexdigest(), "length": len(data)}


def nonce_hex(value):
    return None if value is None else value.to_bytes(8, "big").hex()


def algorithm(name, parameters="null"):
    # Setting parameters=None is intentional: mature ASN.1 encoding omits it.
    result = algos.DigestAlgorithm({"algorithm": name, "parameters": None})
    if parameters == "null":
        from asn1crypto import core
        result["parameters"] = core.Null()
    return result


specs = {
    "matching-sha256-null": {},
    "matching-sha256-absent": {"parameters": "absent"},
    "matching-sha384": {"request_algorithm": "sha384"},
    "independent-cms-sha512": {"cms_digest": "sha512"},
    "algorithm-only": {"change_algorithm": True},
    "digest-only": {"change_digest": True},
    "both": {"change_algorithm": True, "change_digest": True},
    "wrong-nonce": {"change_algorithm": True, "nonce_change": "wrong"},
    "missing-nonce": {"change_algorithm": True, "nonce_change": "missing"},
    "no-nonce-valid": {"include_nonce": False},
    "no-nonce-algorithm": {"include_nonce": False, "change_algorithm": True},
    "no-nonce-digest": {"include_nonce": False, "change_digest": True},
}

cases = {}
for name, spec in specs.items():
    request_algorithm = spec.get("request_algorithm", "sha256")
    digest = sha384(PREIMAGE).digest() if request_algorithm == "sha384" else sha256(PREIMAGE).digest()
    include_nonce = spec.get("include_nonce", True)
    cms_digest = spec.get("cms_digest", "sha256")
    stamper = DummyTimeStamper(
        tsa_cert=TSA_CERT,
        tsa_key=TESTING_CA.key_set.get_private_key("tsa"),
        certs_to_embed=FROM_CA.cert_registry,
        fixed_dt=NOW,
        include_nonce=include_nonce,
        override_md=cms_digest,
    )
    with patch.object(ts_api, "get_nonce", return_value=NONCE):
        expected_nonce, request = stamper.request_cms(digest, request_algorithm)
    # The native formatter emits NULL for SHA2 request algorithms. Response
    # compatibility is tested separately in the modified pre-sign request.
    request["message_imprint"]["hash_algorithm"] = algorithm(request_algorithm, "null")
    assert expected_nonce == (NONCE if include_nonce else None)
    modified = request.copy()
    if spec.get("parameters") == "absent":
        modified["message_imprint"]["hash_algorithm"] = algorithm(request_algorithm, "absent")
    if spec.get("change_algorithm"):
        modified["message_imprint"]["hash_algorithm"] = algorithm("sha384")
    if spec.get("change_digest"):
        changed = bytearray(digest)
        changed[0] ^= 1
        modified["message_imprint"]["hashed_message"] = bytes(changed)
    if spec.get("nonce_change") == "wrong":
        modified["nonce"] = cms.Integer(NONCE + 1)
    elif spec.get("nonce_change") == "missing":
        del modified["nonce"]
    with patch.object(ts_dummy, "get_nonce", return_value=SERIAL):
        response = stamper.request_tsa_response(modified)
    token = response["time_stamp_token"]
    signed_info = token["content"]["encap_content_info"]["content"].contents
    tst_info = token["content"]["encap_content_info"]["content"].parsed
    assert signed_info == tst_info.dump()
    assert tst_info["message_imprint"].dump() == modified["message_imprint"].dump()
    assert tst_info["nonce"].native == modified["nonce"].native
    assert tst_info["gen_time"].native == NOW
    assert tst_info["serial_number"].native == SERIAL
    row = {
        "request": save(f"{name}/request.der", request.dump()),
        "modified_request": save(f"{name}/modified-request.der", modified.dump()),
        "signer_input": save(f"{name}/signer-input.der", signed_info),
        "response": save(f"{name}/response.der", response.dump()),
        "token": save(f"{name}/token.der", token.dump()),
        "request_algorithm_oid": request["message_imprint"]["hash_algorithm"]["algorithm"].dotted,
        "request_algorithm_der_hex": request["message_imprint"]["hash_algorithm"].dump().hex(),
        "request_digest_hex": request["message_imprint"]["hashed_message"].native.hex(),
        "token_algorithm_oid": tst_info["message_imprint"]["hash_algorithm"]["algorithm"].dotted,
        "token_algorithm_der_hex": tst_info["message_imprint"]["hash_algorithm"].dump().hex(),
        "token_digest_hex": tst_info["message_imprint"]["hashed_message"].native.hex(),
        "expected_nonce_hex": nonce_hex(expected_nonce),
        "token_nonce_hex": nonce_hex(tst_info["nonce"].native),
        "cms_digest_algorithm": cms_digest,
        "cms_digest_algorithm_oid": token["content"]["signer_infos"][0]["digest_algorithm"]["algorithm"].dotted,
        "request_parameters_profile": "null",
        "parameters_profile": spec.get("parameters", "null"),
        "mutation_before_signing": spec,
    }
    cases[name] = row

crl = TESTING_CA.service_registry.get_crl(ServiceLabel("root"), at_time=NOW)
sources = {}
for module in [ts_api, ts_common, ts_dummy, ts_validation, signing_commons]:
    path = Path(inspect.getsourcefile(module)).resolve()
    sources[str(path)] = sha256(path.read_bytes()).hexdigest()
manifest = {
    "schema_version": 1,
    "evidence_kind": "Fresh fixed-time signed public fixtures; no HTTP/native execution or upstream credit",
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "versions": VERSIONS,
    "runtime": {"python_executable": sys.executable, "python_version": sys.version},
    "validation_time": "2020-11-01T00:00:00Z",
    "preimage_hex": PREIMAGE.hex(),
    "fixed_nonce_hex": nonce_hex(NONCE),
    "fixed_tst_serial_hex": nonce_hex(SERIAL),
    "trust_root": save("root.der", ROOT_CERT.dump()),
    "tsa_cert": save("tsa.der", TSA_CERT.dump()),
    "revocation_mode": "require",
    "allow_fetching": False,
    "crls": [save("root-crl.der", crl.dump())],
    "crl_this_update": crl["tbs_cert_list"]["this_update"].native.isoformat(),
    "crl_next_update": crl["tbs_cert_list"]["next_update"].native.isoformat(),
    "signer_input_format": "TSTInfo DER, exact CMS encapsulated/signed content",
    "modified_request_format": "TimeStampReq DER copied from request and mutated before DummyTimeStamper signs",
    "generator": {"path": "generate.py", "sha256": sha256(Path(__file__).read_bytes()).hexdigest()},
    "validation_driver": {"path": "validate.py", "sha256": sha256((ROOT / "validate.py").read_bytes()).hexdigest()},
    "sources_sha256": sources,
    "cases": cases,
    "private_keys_written": False,
    "HTTP_calls": 0,
    "new_upstream_credit": 0,
}
(ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"signed_fixture_cases": len(cases), "revocation_mode": "require", "HTTP_calls": 0, "upstream_credit": 0}))
