"""Fresh real-signature timestamp-imprint policy probes for the pinned oracle.

Supplemental V consumer regressions, with zero additional upstream credit.
The original Python final LTA API accepts the denied-imprint cases: native
rejection is deliberately stricter, not a fabricated differential agreement.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import logging
from pathlib import Path
import sys


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def iso(value):
    return value.astimezone(timezone.utc).isoformat() if isinstance(value, datetime) else value


async def generate(output: Path) -> None:
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    from freezegun import freeze_time
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign import signers, timestamps
    from pyhanko.sign.attributes import TSTProvider, UnsignedAttributeProviderSpec
    from pyhanko.sign.validation import ades, generic_cms
    from pyhanko.sign.validation.policy_decl import (
        CertificateFetchingRule, PdfSignatureValidationSpec,
        RevinfoOnlineFetchingRule, RevocationInfoGatheringSpec,
        SignatureValidationSpec,
    )
    from pyhanko_certvalidator.context import CertValidationPolicySpec, ValidationContext
    from pyhanko_certvalidator.ltv.poe import (
        KnownPOE, POEManager, POEType, digest_for_poe,
    )
    from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
    from pyhanko_certvalidator.policy_decl import AlgorithmUsageConstraint, AlgorithmUsagePolicy
    from pyhanko_certvalidator.registry import SimpleTrustManager
    from pyhanko_testing_commons.test_utils.live_http import live_pki_services
    from pyhanko_testing_commons.test_utils.signing_commons import (
        FROM_CA, ROOT_CERT, TESTING_CA, TSA_CERT,
    )
    from tests.test_ades_validation import (
        DEFAULT_SIG_VALIDATION_SPEC, _generate_pades_test_doc,
    )

    output.mkdir(parents=True, exist_ok=True)
    signed_at = datetime(2020, 11, 20, tzinfo=timezone.utc)
    validation_time = datetime(2029, 11, 20, tzinfo=timezone.utc)
    phase = {"name": "generation"}
    http = []

    class ImprintPolicy(AlgorithmUsagePolicy):
        def __init__(self, mode, cutoff):
            self.mode, self.cutoff, self.calls = mode, cutoff, []

        def signature_algorithm_allowed(self, algo, moment, public_key=None):
            return AlgorithmUsageConstraint(allowed=True)

        def digest_algorithm_allowed(self, algo, moment):
            digest = algo["algorithm"].native
            denied = digest == "sha512" and (
                self.mode == "permanent"
                or self.mode == "timed" and (moment is None or moment > self.cutoff)
            )
            self.calls.append({"digest": digest, "moment": iso(moment),
                               "denied": denied, "phase": phase["name"]})
            return AlgorithmUsageConstraint(
                allowed=not denied,
                not_allowed_after=self.cutoff if denied else None,
                failure_reason="timestamp imprint policy" if denied else None,
            )

    stamp = timestamps.DummyTimeStamper(
        tsa_cert=TSA_CERT, tsa_key=TESTING_CA.key_set.get_private_key("tsa"),
        certs_to_embed=FROM_CA.cert_registry, override_md="sha256",
    )

    class SignatureTimestamp(UnsignedAttributeProviderSpec):
        def unsigned_attr_providers(self, signature, signed_attrs, digest_algorithm):
            yield TSTProvider("sha512", data_to_ts=signature, timestamper=stamp)

    signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
    )
    signer.unsigned_attr_prov_spec = SignatureTimestamp()
    cases = [
        ("default_policy", "default", None, True, False, "passed"),
        ("explicit_allow", "allow", None, True, False, "passed"),
        ("imprint_permanent", "permanent", None, True, False, "stricter_reject"),
        ("imprint_after_2025", "timed", "2025-12-31T23:59:59+00:00", True, False, "stricter_reject"),
        ("imprint_after_2019", "timed", "2019-12-31T23:59:59+00:00", True, False, "stricter_reject"),
        ("imprint_after_2030", "timed", "2030-12-31T23:59:59+00:00", True, False, "passed"),
        ("independent_signature_poe", "timed", "2025-12-31T23:59:59+00:00", True, True, "passed"),
        ("no_material_poe", "allow", None, False, False, "rejected"),
    ]

    def describe(result):
        api = result.api_status
        return {
            "ades_subindic": result.ades_subindic.name,
            "best_signature_time": iso(getattr(result, "best_signature_time", None)),
            "failure_msg": result.failure_msg,
            "api": None if api is None else {
                "intact": api.intact, "valid": api.valid, "trusted": api.trusted,
                "bottom_line": getattr(api, "bottom_line", None),
            },
        }

    with live_pki_services() as services:
        services.register(TESTING_CA)
        for key, original in list(services._routes.items()):
            async def record(request, _original=original):
                request_body = await request.read()
                response = await _original(request)
                http.append({
                    "phase": phase["name"], "method": request.method,
                    "path": request.path, "status": response.status,
                    "content_type": response.content_type,
                    "request": encoded(request_body),
                    "response": encoded(response.body or b""),
                })
                return response
            services._routes[key] = record

        with freeze_time(signed_at, real_asyncio=True):
            vc = ValidationContext(trust_roots=[ROOT_CERT], allow_fetching=True)
            document = await _generate_pades_test_doc(
                services, signer=signer, vc=vc, timestamper=stamp,
                use_pades_lta=False, md_algorithm="sha256",
            )
            await vc.aclose()
        pdf = document.getvalue()
        (output / "signature-imprint-sha512.pdf").write_bytes(pdf)
        document_cases = []
        for identifier, mode, cutoff_text, material_poe, signature_poe, native in cases:
            with freeze_time(validation_time, real_asyncio=True):
                reader = PdfFileReader(BytesIO(pdf))
                assert len(reader.embedded_signatures) == 1, "No independent document timestamp"
                signature = reader.embedded_signatures[0]
                signature_bytes = signature.signer_info["signature"].native
                dss = ades._dss_to_local_knowledge(reader)
                facts = list(dss.assert_existence_known_at(signed_at)) if material_poe else []
                assert all(fact.digest != digest_for_poe(signature_bytes) for fact in facts)
                if signature_poe:
                    facts.append(KnownPOE(
                        poe_type=POEType.PROVIDED, digest=digest_for_poe(signature_bytes),
                        poe_time=signed_at,
                    ))
                dss = replace(dss, known_poes=facts)
                cutoff = datetime.fromisoformat(cutoff_text) if cutoff_text else None
                policy = None if mode == "default" else ImprintPolicy(mode, cutoff)
                spec = SignatureValidationSpec(
                    cert_validation_policy=CertValidationPolicySpec(
                        trust_manager=SimpleTrustManager.build([ROOT_CERT]),
                        algorithm_usage_policy=policy,
                        revinfo_policy=DEFAULT_SIG_VALIDATION_SPEC.cert_validation_policy.revinfo_policy,
                    ),
                    local_knowledge=dss,
                    revinfo_gathering_policy=RevocationInfoGatheringSpec(
                        online_fetching_rule=RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH,
                        certificate_fetching_rule=CertificateFetchingRule.NEVER_FETCH,
                    ),
                )
                phase["name"] = identifier + ":lta"
                result = await ades.ades_lta_validation(signature, PdfSignatureValidationSpec(spec))
                token = next(generic_cms.extract_tst_data_iter(signature.signer_info, signed=False))
                info = token["encap_content_info"]["content"].parsed
                assert info["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha512"
                assert token["signer_infos"][0]["digest_algorithm"]["algorithm"].native == "sha256"
                assert info["message_imprint"]["hashed_message"].native == hashlib.sha512(signature_bytes).digest()

                # Observe the original helper without changing its crypto,
                # control flow or register argument semantics.
                direct_poe, register_calls = POEManager(), []
                original_register = direct_poe.register
                def record_register(data, *args, **kwargs):
                    result = original_register(data, *args, **kwargs)
                    if data == signature_bytes:
                        register_calls.append({
                            "positional": [iso(value) for value in args],
                            "keyword_dt": iso(kwargs.get("dt")),
                            "actual_poe_time": iso(result.poe_time),
                            "actual_poe_type": iso(getattr(result.poe_type, "name", result.poe_type)),
                        })
                    return result
                direct_poe.register = record_register
                phase["name"] = identifier + ":signature_ts"
                async with ades._operation_scoped_spec(spec) as scoped_spec:
                    ts_result = await ades._process_signature_ts(
                        signature, scoped_spec, direct_poe, ValidationTimingInfo.now(), token,
                    )
                registered = [p for p in direct_poe if p.digest == digest_for_poe(signature_bytes)]
                item = {
                    "id": identifier, "mode": mode, "cutoff": cutoff_text,
                    "material_poe": material_poe, "provided_signature_poe": signature_poe,
                    "native_expectation": native,
                    "oracle": describe(result), "oracle_signature_timestamp": describe(ts_result),
                    "oracle_direct_signature_poe": iso(registered[0].poe_time) if registered else None,
                    "oracle_direct_register_calls": register_calls,
                    "known_poes": [{"digest": encoded(p.digest), "time": iso(p.poe_time)} for p in facts],
                    "policy_calls": policy.calls if policy else [],
                }
                if native == "stricter_reject":
                    assert item["oracle"]["ades_subindic"] == "OK", "Record the real Python acceptance"
                    assert not register_calls, "Denied imprint cannot call the helper's POE registration"
                if native == "passed":
                    assert item["oracle"]["ades_subindic"] == "OK"
                if native == "rejected":
                    assert item["oracle"]["ades_subindic"] == "NO_POE"
                assert item["oracle_signature_timestamp"]["ades_subindic"] == "OK"
                assert all(item["oracle_signature_timestamp"]["api"][key]
                           for key in ["intact", "valid", "trusted"])
                document_cases.append(item)
                print(json.dumps({"case": identifier, "oracle": item["oracle"],
                                  "native_expectation": native,
                                  "direct_register_calls": register_calls}), flush=True)

    def material(kind):
        values = {h["response"] for h in http if h["phase"] != "generation"
                  and h["status"] == 200 and h["content_type"] == kind}
        return sorted(values)

    manifest = {
        "pyhanko": version("pyhanko"), "certvalidator": version("pyhanko-certvalidator"),
        "oracle_kind": "fresh_generation_and_live_original_api", "unique_upstream_credit": 0,
        "related_upstream_functions": [
            "pyhanko/test_ades_validation.py::test_pades_hash_algorithm_banned_but_poe_ok",
            "pyhanko/test_ades_validation.py::test_pades_multi_sig_timestamp_algo_hedge_ok",
        ],
        "file": "signature-imprint-sha512.pdf", "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
        "field_name": "Sig1", "signed_at": iso(signed_at), "validation_time": iso(validation_time),
        "trust_root": encoded(ROOT_CERT.dump()),
        "timestamp_cms_digest_oid": "2.16.840.1.101.3.4.2.1",
        "timestamp_imprint_digest_oid": "2.16.840.1.101.3.4.2.3",
        "current_crls": material("application/pkix-crl"),
        "current_ocsps": material("application/ocsp-response"),
        "cases": document_cases, "http": http,
        "original_api_calls": len(cases) * 2,
        "compatibility": [
            "Python final LTA accepts denied-imprint cases; stricter native POE invariant is separate.",
            "The original helper gates register calls, but passes genTime positionally as poe_type; dt defaults to now.",
        ],
    }
    assert manifest["current_crls"] or manifest["current_ocsps"]
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"complete": len(document_cases), "original_api_calls": len(cases) * 2,
                      "http_exchanges": len(http), "pdf_sha256": manifest["pdf_sha256"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/tmp/pyhanko-oracle/src/v0.38.1"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for path in [Path("/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator/src"),
                 args.source / "internal/common-test-utils/src", args.source / "pkgs/pyhanko/src",
                 args.source / "pkgs/pyhanko"]:
        sys.path.insert(0, str(path))
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(generate(args.output))


if __name__ == "__main__":
    main()
