"""Generate fresh validation-side seed fixtures using pinned pyHanko 0.38.1.

Run with /tmp/pyhanko-oracle/venv/bin/python. This translates the seed validator
assertions in tests/test_seed_values.py into signed PDFs. Signer-side failures
are recorded only as provenance; these fixtures earn no upstream function passes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
from importlib.metadata import version
from io import BytesIO
from pathlib import Path
import sys


def configure_sources(source: Path) -> None:
    for path in [source / "internal/common-test-utils/src", source / "pkgs/pyhanko/src", source / "pkgs/pyhanko"]:
        sys.path.insert(0, str(path))


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


async def generate(output: Path, resume: bool = False) -> None:
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    from asn1crypto import x509
    from freezegun.api import freeze_time
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign import fields, signers, timestamps
    from pyhanko.sign.validation import async_validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    from pyhanko_testing_commons.test_data.samples import UNRELATED_TSA
    from pyhanko_testing_commons.test_utils.signing_commons import (
        DUMMY_TS, FROM_CA, INTERM_CERT, ROOT_CERT, SELF_SIGN, dummy_ocsp_vc,
    )
    from tests.test_seed_values import prepare_sv_field

    sf = fields.SigSeedSubFilter
    ff = fields.SigSeedValFlags
    cf = fields.SigCertConstraintFlags
    mdp = fields.MDPPerm
    lock = fields.SeedLockDocument
    cases = []

    def add(identifier, group, source, sv, *, seed=True, ignore=False,
            ts="trusted", strict=False, raw=None, field_lock=False,
            exception=None, trust_signer=True, **metadata):
        cases.append(dict(id=identifier, group=group, source=source, sv=sv,
                          expected_seed=seed, ignore=ignore, ts=ts, strict=strict,
                          raw=raw, field_lock=field_lock, exception=exception,
                          trust_signer=trust_signer, metadata=metadata))

    def spec(**kwargs):
        return fields.SigSeedValueSpec(**kwargs)

    def cert_spec(**kwargs):
        return spec(cert=fields.SigCertConstraints(**kwargs))

    # Exact validation-side cases in test_sv_sign_md_req / test_sv_sign_md_hint.
    required_digest = spec(flags=ff.DIGEST_METHOD, digest_methods=["sha256", "sha512"])
    add("no_seed_control", "digest", "test_sv_sign_md_hint", None)
    add("digest_required_sha1_reject", "digest", "test_sv_sign_md_req", required_digest,
        seed=False, ignore=True, md_algorithm="sha1")
    add("digest_required_default_sha256", "digest", "test_sv_sign_md_req", required_digest)
    add("digest_required_sha512", "digest", "test_sv_sign_md_req", required_digest, md_algorithm="sha512")
    for digest in ["sha1", None, "sha512"]:
        add(f"digest_hint_{digest or 'default'}", "digest", "test_sv_sign_md_hint",
            spec(digest_methods=["sha256", "sha512"]), md_algorithm=digest)

    reasons = spec(flags=ff.REASONS, reasons=["I agree", "Works for me"])
    for value, name, accepted in [("Aw yiss", "wrong", False), (None, "missing", False),
                                  ("I agree", "allowed", True)]:
        add(f"reason_required_{name}", "reasons", "test_sv_sign_reason_req", reasons,
            seed=accepted, ignore=not accepted, reason=value)
    for label, values in [("none", None), ("empty", []), ("dot", ["."])]:
        for value, name in [("Aw yiss", "text"), (".", "dot"), (None, "omitted")]:
            add(f"reason_prohibited_{label}_{name}", "reasons", "test_sv_sign_reason_prohibited",
                spec(flags=ff.REASONS, reasons=values), seed=value is None,
                ignore=value is not None, reason=value)

    # test_sv_timestamp_url verifies fetching separately. These offline extensions
    # retain its timestamp-required constraint and test trusted/missing/untrusted.
    ts_spec = spec(timestamp_server_url="http://seed.invalid/tsa", timestamp_required=True)
    add("timestamp_required_trusted", "timestamp", "test_sv_timestamp_url", ts_spec)
    add("timestamp_required_missing", "timestamp", "test_sv_timestamp_url", ts_spec,
        seed=False, ignore=True, ts="none")
    add("timestamp_required_untrusted", "timestamp", "test_sv_timestamp_url", ts_spec,
        seed=False, ignore=True, ts="untrusted")
    add("timestamp_optional_missing", "timestamp", "test_sv_timestamp_url",
        spec(timestamp_server_url="http://seed.invalid/tsa"), ts="none")

    required_subfilter = spec(flags=ff.SUBFILTER, subfilters=[sf.PADES])
    add("subfilter_required_mismatch", "subfilter", "test_sv_sign_subfilter_req", required_subfilter,
        seed=False, ignore=True, subfilter=sf.ADOBE_PKCS7_DETACHED, md_algorithm="sha1")
    add("subfilter_required_pades", "subfilter", "test_sv_sign_subfilter_req", required_subfilter)
    add("subfilter_hint_adobe", "subfilter", "test_sv_sign_subfilter_hint",
        spec(subfilters=[sf.PADES]), subfilter=sf.ADOBE_PKCS7_DETACHED, md_algorithm="sha1")
    add("subfilter_hint_default_pades", "subfilter", "test_sv_sign_subfilter_hint", spec(subfilters=[sf.PADES]))
    add("subfilter_unknown_then_supported", "subfilter", "test_sv_subfilter_unsupported_partial",
        required_subfilter, ignore=True, subfilter=sf.PADES,
        raw={"/SubFilter": ["/not.implemented", sf.PADES.value]})

    approval = spec(seed_signature_type=fields.SeedSignatureType())
    certify = spec(seed_signature_type=fields.SeedSignatureType(mdp.FILL_FORMS))
    add("mdp_approval", "mdp", "test_sv_mdp_no_certify", approval)
    add("mdp_forbidden_certification", "mdp", "test_sv_mdp_no_certify", approval,
        seed=False, ignore=True, certify=True)
    add("mdp_certification", "mdp", "test_sv_mdp_must_certify", certify, certify=True)
    add("mdp_missing_certification", "mdp", "test_sv_mdp_must_certify", certify,
        seed=False, ignore=True)
    add("mdp_wrong_permission", "mdp", "test_sv_mdp_must_certify", certify,
        seed=False, ignore=True, certify=True, docmdp_permissions=mdp.NO_CHANGES)
    for permission in [mdp.NO_CHANGES, mdp.FILL_FORMS, mdp.ANNOTATE]:
        add(f"lock_certify_{permission.value}", "mdp", "test_sv_lock_certify",
            spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.LOCK), certify=True,
            docmdp_permissions=permission)
    for permission in [mdp.FILL_FORMS, mdp.ANNOTATE]:
        add(f"lock_ignore_certify_{permission.value}", "mdp", "test_sv_lock_certify",
            spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.LOCK), certify=True,
            docmdp_permissions=permission, seed=False, ignore=True)
    add("lock_approval", "mdp", "test_sv_lock_certify",
        spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.LOCK))
    for permission in [mdp.FILL_FORMS, mdp.ANNOTATE]:
        add(f"no_lock_certify_{permission.value}", "mdp", "test_sv_no_lock_certify",
            spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.DO_NOT_LOCK), certify=True,
            docmdp_permissions=permission)
    add("no_lock_approval", "mdp", "test_sv_no_lock_certify",
        spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.DO_NOT_LOCK))
    add("no_lock_forbidden_certify_1", "mdp", "test_sv_no_lock_certify",
        spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.DO_NOT_LOCK), certify=True,
        docmdp_permissions=mdp.NO_CHANGES, seed=False, ignore=True)
    add("field_lock_compatible", "mdp", "test_field_lock_compat",
        spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.LOCK), field_lock=True)
    add("field_lock_conflict", "mdp", "test_field_lock_compat",
        spec(flags=ff.LOCK_DOCUMENT, lock_document=lock.DO_NOT_LOCK), field_lock=True,
        ignore=True, seed=False)

    for name, subject, accepted in [
        ("alice", {"common_name": "Alice"}, True),
        ("alice_country", {"common_name": "Alice", "country_name": "BE"}, True),
        ("wrong", {"common_name": "Alice & Bob", "country_name": "BE"}, False),
    ]:
        add(f"cert_subject_dn_{name}", "certificate", "test_cert_constraint_subject_dn",
            cert_spec(flags=cf.SUBJECT_DN, subject_dn=x509.Name.build(subject)),
            seed=accepted, ignore=not accepted)
    add("cert_subject_dn_hint", "certificate", "test_cert_constraint_subject_dn",
        cert_spec(subject_dn=x509.Name.build({"common_name": "Not Alice"})))
    for name, subjects, accepted in [
        ("match", [FROM_CA.signing_cert], True),
        ("match_multiple", [FROM_CA.signing_cert, SELF_SIGN.signing_cert], True),
        ("wrong", [DUMMY_TS.tsa_cert], False),
    ]:
        add(f"cert_subject_{name}", "certificate", "test_cert_constraint_subject",
            cert_spec(flags=cf.SUBJECT, subjects=subjects), seed=accepted, ignore=not accepted)
    add("cert_subject_hint", "certificate", "test_cert_constraint_subject",
        cert_spec(subjects=[DUMMY_TS.tsa_cert]))
    for name, issuers, accepted in [
        ("root", [ROOT_CERT], True), ("intermediate", [INTERM_CERT], True),
        ("multiple", [INTERM_CERT, SELF_SIGN.signing_cert], True),
        ("wrong", [SELF_SIGN.signing_cert], False),
    ]:
        add(f"cert_issuer_{name}", "certificate", "test_cert_constraint_issuer",
            cert_spec(flags=cf.ISSUER, issuers=issuers), seed=accepted,
            ignore=not accepted, validation_context=dummy_ocsp_vc())
    add("cert_issuer_hint", "certificate", "test_cert_constraint_issuer",
        cert_spec(issuers=[SELF_SIGN.signing_cert]))
    add("cert_issuer_path_missing", "certificate", "test_cert_constraint_issuer",
        cert_spec(flags=cf.ISSUER, issuers=[ROOT_CERT]),
        seed=False, ignore=True, trust_signer=False)
    for name, usages, accepted in [
        ("match", ["11XXXXXX0"], True), ("or", ["11XXXXXX0", "10XXXXXX0"], True),
        ("wrong", ["10XXXXXX0"], False), ("empty", [], False),
    ]:
        add(f"cert_ku_{name}", "certificate",
            "test_cert_constraint_key_usage_ok" if accepted else "test_cert_constraint_key_usage_not_ok",
            cert_spec(flags=cf.KEY_USAGE,
                      key_usage=[fields.SigCertKeyUsage.read_from_sv_string(value) for value in usages]),
            seed=accepted, ignore=not accepted)
    for name, common_name, accepted in [("match", "Alice", True), ("wrong", "Alice & Bob", False)]:
        add(f"cert_composite_{name}", "certificate", "test_cert_constraint_composite",
            cert_spec(flags=cf.ISSUER | cf.SUBJECT_DN, issuers=[INTERM_CERT],
                      subject_dn=x509.Name.build({"common_name": common_name, "country_name": "BE"})),
            seed=accepted, ignore=not accepted, validation_context=dummy_ocsp_vc())

    add("mandatory_legal_attestation", "unsupported", "test_sv_flag_unsupported",
        spec(flags=ff.LEGAL_ATTESTATION, legal_attestations=["abc"]),
        seed=None, ignore=True, exception="NotImplementedError")
    add("mandatory_cert_reserved", "unsupported", "test_sv_cert_flag_unsupported",
        cert_spec(flags=cf.RESERVED), seed=None, ignore=True, exception="NotImplementedError")
    add("mandatory_cert_oid", "unsupported", "test_sv_cert_flag_unsupported",
        cert_spec(flags=cf.OID), seed=None, ignore=True, exception="NotImplementedError")
    add("mandatory_unknown_subfilter", "unsupported", "test_sv_subfilter_unsupported",
        required_subfilter, seed=None, ignore=True, exception="NotImplementedError",
        raw={"/SubFilter": ["/not.implemented"]})
    add("mandatory_unknown_filter", "unsupported", "test_sv_deserialisation",
        spec(flags=ff.FILTER), seed=None, ignore=True, exception="SigningError",
        raw={"/Filter": "/not.implemented"})
    add("mandatory_future_version", "unsupported", "test_sv_version",
        spec(flags=ff.V, sv_dict_version=4), seed=None, ignore=True, exception="SigningError")
    add("mandatory_unknown_flag", "unsupported", "test_sv_deserialisation",
        spec(), seed=None, ignore=True, exception="ValueError", raw={"/Ff": 1 << 20})
    add("mandatory_appearance_unverifiable", "unsupported", "test_sv_flag_appearance_required",
        spec(flags=ff.APPEARANCE_FILTER, appearance="test"), ignore=True, strict=True)
    # These require no embedded Adobe revinfo and never invoke a service.
    add("revinfo_required_missing", "unsupported", "test_sv_sign_addrevinfo_req",
        spec(flags=ff.ADD_REV_INFO, add_rev_info=True), seed=False, ignore=True)
    add("revinfo_forbidden_absent", "unsupported", "test_sv_sign_addrevinfo_req",
        spec(flags=ff.ADD_REV_INFO, add_rev_info=False))

    output.mkdir(parents=True, exist_ok=True)
    document = {
        "pyhanko": "0.38.1", "certvalidator": "0.33.0",
        "validation_time": "2020-11-01T00:00:00Z",
        "trust_root": b64(ROOT_CERT.dump()),
        "signing_certificate": b64(FROM_CA.signing_cert.dump()),
        "intermediate_certificate": b64(INTERM_CERT.dump()),
        "context": "dummy_ocsp_vc(): testing-ca root, weak_hash_algos empty, no fetching, soft-fail",
        "cases": [],
    }
    if resume and (output / "manifest.json").exists():
        document["cases"] = json.loads((output / "manifest.json").read_text())["cases"]
    completed = {case["id"] for case in document["cases"]}
    unrelated = timestamps.DummyTimeStamper(
        tsa_cert=UNRELATED_TSA.get_cert("tsa"),
        tsa_key=UNRELATED_TSA.key_set.get_private_key("tsa"),
        certs_to_embed=[UNRELATED_TSA.get_cert("root")],
    )

    def raw_value(value):
        if isinstance(value, list):
            return generic.ArrayObject([raw_value(item) for item in value])
        if isinstance(value, str) and value.startswith("/"):
            return generic.pdf_name(value)
        if isinstance(value, int):
            return generic.NumberObject(value)
        return generic.pdf_string(value)

    with freeze_time("2020-11-01"):
        for case in cases:
            if case["id"] in completed:
                continue
            writer = IncrementalPdfFileWriter(prepare_sv_field(case["sv"], case["field_lock"]))
            if case["raw"]:
                _, _, field_ref = next(fields.enumerate_sig_fields(writer))
                sv_ref = field_ref.get_object().raw_get("/SV")
                writer.mark_update(sv_ref)
                for key, value in case["raw"].items():
                    sv_ref.get_object()[generic.pdf_name(key)] = raw_value(value)
            metadata_kwargs = dict(case["metadata"])
            if "validation_context" in metadata_kwargs:
                # Context construction must happen inside freeze_time as well.
                metadata_kwargs["validation_context"] = dummy_ocsp_vc()
            metadata = signers.PdfSignatureMetadata(field_name="Sig", **metadata_kwargs)
            timestamper = {"trusted": DUMMY_TS, "none": None, "untrusted": unrelated}[case["ts"]]
            signer = signers.PdfSigner(metadata, FROM_CA, timestamper=timestamper)
            signer._ignore_sv = case["ignore"]
            stream = await signer.async_sign_pdf(writer)
            pdf_bytes = stream.getvalue()
            filename = f"{case['id']}.pdf"
            (output / filename).write_bytes(pdf_bytes)
            embedded = PdfFileReader(BytesIO(pdf_bytes)).embedded_signatures[0]
            validation_context = dummy_ocsp_vc() if case["trust_signer"] else ValidationContext(
                trust_roots=[], allow_fetching=False, weak_hash_algos=set(),
            )
            try:
                status = await async_validate_pdf_signature(embedded, validation_context, skip_diff=True)
            except Exception as error:
                oracle = {"outcome": "exception", "exception": {
                    "type": type(error).__name__, "message": str(error),
                }}
                assert case["exception"] == type(error).__name__, (case["id"], oracle)
            else:
                error = status.seed_value_constraint_error
                oracle = {
                    "outcome": "status", "has_seed_values": status.has_seed_values,
                    "seed_value_ok": status.seed_value_ok, "bottom_line": status.bottom_line,
                    "intact": status.intact, "valid": status.valid, "trusted": status.trusted,
                    "md_algorithm": embedded.md_algorithm,
                    "subfilter": str(embedded.sig_object["/SubFilter"]),
                    "docmdp_level": embedded.docmdp_level.value if embedded.docmdp_level else None,
                    "reason": str(embedded.sig_object["/Reason"]) if "/Reason" in embedded.sig_object else None,
                    "error": None if error is None else {
                        "type": type(error).__name__, "message": str(error),
                        "ades_subindication": error.ades_subindication.name,
                    },
                }
                assert case["exception"] is None, (case["id"], oracle)
                assert status.seed_value_ok == case["expected_seed"], (case["id"], oracle)
                if case["expected_seed"]:
                    assert status.bottom_line, (case["id"], oracle)
                else:
                    assert not status.bottom_line, (case["id"], oracle)
            document["cases"].append({
                "id": case["id"], "group": case["group"], "file": filename,
                "source": f"pyhanko/test_seed_values.py::{case['source']}",
                "ignore_seed_during_signing": case["ignore"],
                "trust_signer": case["trust_signer"],
                "expectation": "stricter" if case["strict"] else "parity",
                "divergence": "Rust rejects mandatory named appearance constraints that the oracle only warns about." if case["strict"] else None,
                "oracle": oracle,
            })
            (output / "manifest.json").write_text(json.dumps(document, indent=2) + "\n")
            print(f"{case['id']}: {oracle.get('seed_value_ok', oracle.get('exception'))}", flush=True)
    print(f"Generated {len(document['cases'])} cases.", flush=True)
    await dangling_filter_fixture(output)


async def dangling_filter_fixture(output: Path) -> None:
    """Keep the optional-Filter parser rejection separate from the 75-case matrix."""
    from freezegun.api import freeze_time
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign import fields, signers
    from pyhanko.sign.validation import async_validate_pdf_signature
    from pyhanko.sign.validation.generic_cms import async_validate_cms_signature
    from pyhanko_testing_commons.test_utils.signing_commons import DUMMY_TS, FROM_CA, dummy_ocsp_vc
    from tests.test_seed_values import prepare_sv_field

    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    output.mkdir(parents=True, exist_ok=True)
    with freeze_time("2020-11-01"):
        writer = IncrementalPdfFileWriter(prepare_sv_field(fields.SigSeedValueSpec()))
        _, _, field = next(fields.enumerate_sig_fields(writer))
        seed = field.get_object().raw_get("/SV")
        writer.mark_update(seed)
        seed.get_object()[generic.pdf_name("/Filter")] = generic.IndirectObject(999999, 0, writer)
        signer = signers.PdfSigner(signers.PdfSignatureMetadata(field_name="Sig"), FROM_CA, timestamper=DUMMY_TS)
        signer._ignore_sv = True
        stream = await signer.async_sign_pdf(writer)
        pdf = stream.getvalue()
        embedded = PdfFileReader(BytesIO(pdf)).embedded_signatures[0]
        cms = await async_validate_cms_signature(
            embedded.signed_data, raw_digest=embedded.compute_digest(),
            validation_context=dummy_ocsp_vc(),
        )
        assert cms.intact and cms.valid and cms.trusted
        try:
            await async_validate_pdf_signature(embedded, dummy_ocsp_vc(), skip_diff=True)
        except Exception as error:
            assert type(error).__name__ == "PdfStrictReadError", error
            assert "999999" in str(error), error
            result = {"type": type(error).__name__, "message": str(error)}
        else:
            raise AssertionError("A dangling optional /Filter must reject")
    (output / "optional_filter_dangling.pdf").write_bytes(pdf)
    (output / "optional_filter_dangling.json").write_text(json.dumps({
        "pyhanko": "0.38.1", "source": "test_sv_deserialisation parser extension",
        "root_seed_flags": 0, "oracle": result,
        "cms_intact": True, "cms_valid": True, "cms_trusted": True,
    }, indent=2) + "\n")
    print(f"optional_filter_dangling: {result}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/tmp/pyhanko-oracle/src/v0.38.1"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true", help="Continue an interrupted fixture export")
    parser.add_argument("--dangling-filter-only", action="store_true", help="Generate only the additional optional-Filter rejection case")
    arguments = parser.parse_args()
    configure_sources(arguments.source)
    logging.basicConfig(level=logging.ERROR)
    asyncio.run(dangling_filter_fixture(arguments.output) if arguments.dangling_filter_only
                else generate(arguments.output, arguments.resume))


if __name__ == "__main__":
    main()
