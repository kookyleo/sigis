"""Fresh public token validation on the exact committed fixed-time files.

The declared-imprint callback establishes genuine CMS signature and required
TSA path/revocation checks independently of request binding. The second callback
hashes the actual preimage using the token's declared algorithm. No HTTP runs.
"""
import argparse
import asyncio
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path

from asn1crypto import cms, crl, tsp, x509
from cryptography.hazmat.primitives import hashes
from pyhanko.sign.timestamps.common_utils import handle_tsp_response
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
from pyhanko.sign.validation.status import TimestampSignatureStatus
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.util import get_pyca_cryptography_hash

ROOT = Path(__file__).resolve().parent
VERSIONS = {"pyHanko": version("pyHanko"), "certvalidator": version("pyhanko-certvalidator")}
assert VERSIONS == {"pyHanko": "0.38.1", "certvalidator": "0.33.0"}
manifest = json.loads((ROOT / "manifest.json").read_text())
opened = []


def read(meta):
    path = (ROOT / meta["path"]).resolve()
    data = path.read_bytes()
    actual_hash = sha256(data).hexdigest()
    assert actual_hash == meta["sha256"] and len(data) == meta["length"]
    opened.append({"opened_path": str(path), "sha256": actual_hash, "length": len(data)})
    return data


root_data = read(manifest["trust_root"])
root = x509.Certificate.load(root_data)
tsa_data = read(manifest["tsa_cert"])
crls = [crl.CertificateList.load(read(meta)) for meta in manifest["crls"]]
now = datetime.fromisoformat(manifest["validation_time"].replace("Z", "+00:00"))
preimage = bytes.fromhex(manifest["preimage_hex"])


def raw(value):
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, ValidationPath):
        return {"type": type(value).__name__, "certificates_sha256": [
            sha256(cert.dump()).hexdigest() for cert in value.iter_certs(include_root=True)
        ]}
    if isinstance(value, x509.Certificate):
        return {"type": type(value).__name__, "der_sha256": sha256(value.dump()).hexdigest(),
                "subject": value.subject.human_friendly, "serial": value.serial_number}
    return {"type": type(value).__name__, "string": str(value)}


def context():
    return ValidationContext(
        trust_roots=[root], crls=crls, moment=now,
        revocation_mode=manifest["revocation_mode"], allow_fetching=False,
    )


async def run(output):
    results = {}
    for name, case in manifest["cases"].items():
        request = tsp.TimeStampReq.load(read(case["request"]))
        modified = tsp.TimeStampReq.load(read(case["modified_request"]))
        signed_input = read(case["signer_input"])
        response = tsp.TimeStampResp.load(read(case["response"]))
        token_data = read(case["token"])
        token = cms.ContentInfo.load(token_data)
        assert response["time_stamp_token"].dump() == token_data
        assert token["content"]["encap_content_info"]["content"].contents == signed_input
        info = token["content"]["encap_content_info"]["content"].parsed
        assert info["message_imprint"].dump() == modified["message_imprint"].dump()
        assert info["nonce"].native == modified["nonce"].native
        row = {
            "request_sha256": case["request"]["sha256"], "token_sha256": case["token"]["sha256"],
            "request_algorithm_oid": request["message_imprint"]["hash_algorithm"]["algorithm"].dotted,
            "request_digest_hex": request["message_imprint"]["hashed_message"].native.hex(),
            "token_algorithm_oid": info["message_imprint"]["hash_algorithm"]["algorithm"].dotted,
            "token_digest_hex": info["message_imprint"]["hashed_message"].native.hex(),
        }
        # This existing Python acquisition component checks status/nonce only.
        # It is neither concrete HTTP acquisition nor request-imprint validation.
        try:
            returned = handle_tsp_response(response, request["nonce"].native)
            row["raw_python_acquisition_component"] = {
                "accepted": True, "returned_token_sha256": sha256(returned.dump()).hexdigest()
            }
        except Exception as exc:
            row["raw_python_acquisition_component"] = {
                "accepted": False, "error_class": type(exc).__name__, "message": str(exc)
            }
        declared = info["message_imprint"]["hashed_message"].native
        for mode in ["declared-imprint", "actual-preimage"]:
            queried = []

            def expected(algorithm):
                queried.append(algorithm)
                if mode == "declared-imprint":
                    return declared
                digest = hashes.Hash(get_pyca_cryptography_hash(algorithm))
                digest.update(preimage)
                return digest.finalize()

            try:
                # Read the actual same token file afresh for each public call.
                same_token = cms.ContentInfo.load(read(case["token"]))
                result = await validate_tst_signed_data(same_token["content"], context(), expected)
                status = TimestampSignatureStatus(**result)
                row[mode] = {
                    "valid": status.valid, "intact": status.intact, "trusted": status.trusted,
                    "bottom_line": None,
                    "callback_algorithms": queried,
                    "raw_status": {key: raw(value) for key, value in result.items()},
                }
            except Exception as exc:
                row[mode] = {"error_class": type(exc).__name__, "message": str(exc),
                             "callback_algorithms": queried}
        results[name] = row
    out = {
        "versions": VERSIONS, "executed_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "Fresh public Python validation of exact signed fixture files; no HTTP/native replay or upstream credit",
        "manifest_sha256": sha256((ROOT / "manifest.json").read_bytes()).hexdigest(),
        "driver_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "validation_profile": {
            "time": manifest["validation_time"], "revocation_mode": manifest["revocation_mode"],
            "allow_fetching": False, "trust_root_sha256": manifest["trust_root"]["sha256"],
            "tsa_cert_sha256": manifest["tsa_cert"]["sha256"], "crl_sha256": [m["sha256"] for m in manifest["crls"]],
        },
        "results": results, "opened_inputs": opened,
        "public_token_validator_calls": 2 * len(results),
        "raw_python_acquisition_component_calls": len(results),
        "HTTP_calls": 0, "new_upstream_credit": 0,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(out, indent=2) + "\n")
    # Genuine CMS signatures, trusted TSA path and required revocation must all
    # pass even for request-binding negatives. This is not a trust waiver.
    expected_path = [manifest["trust_root"]["sha256"], manifest["tsa_cert"]["sha256"]]
    for name, row in results.items():
        declared = row["declared-imprint"]
        assert declared.get("valid") and declared.get("intact") and declared.get("trusted"), (name, declared)
        assert declared["raw_status"]["trust_problem_indic"] is None
        assert declared["raw_status"]["validation_path"]["certificates_sha256"] == expected_path
        actual = row["actual-preimage"]
        assert actual.get("valid") is True and actual["raw_status"]["trust_problem_indic"] is None, (name, actual)
        assert actual["raw_status"]["validation_path"]["certificates_sha256"] == expected_path
    print(json.dumps({"cases": len(results), "declared_imprint_CMS_signature_and_required_path_green": len(results),
                      "public_token_validator_calls": 2 * len(results), "HTTP_calls": 0, "upstream_credit": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    asyncio.run(run(parser.parse_args().output))
