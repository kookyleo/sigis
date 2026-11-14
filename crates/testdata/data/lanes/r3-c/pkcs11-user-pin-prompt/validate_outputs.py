"""Fresh full-PDF validation of ACTUAL native outputs under equal peer profiles.

Request: {"cases":[{"label":"rsa","pdf":"...","modified_pdf":"...",
                    "password_file":"optional UTF-8 fixture file", "expect_mac":false}],
          "moments":["2020-11-01T00:00:00Z", "<native NOW>"],
          "assert_frozen_positive":true}. Root/intermediate/leaf default to the
committed public fixtures. Context roots are explicit; embedded CMS must carry
its own intermediate. No private key/provider/signing operation occurs here.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from io import BytesIO
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import warnings

from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.pdf_utils.crypt.api import AuthStatus, PdfMacStatus
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

OPENED = []


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, role):
    p = Path(path).resolve()
    raw = p.read_bytes()
    OPENED.append(dict(path=str(p), role=role, length=len(raw), sha256=digest(raw)))
    return raw


def identity(path):
    p = Path(path).resolve()
    raw = p.read_bytes()
    return dict(path=str(p), length=len(raw), sha256=digest(raw))


def validate_one(raw, moment, roots, leaf, intermediate, modified, *, password=None, expect_mac=False):
    # Only actual parser/validator exceptions become exception-shaped refusal.
    # Assertions below are NEVER caught and reclassified as a denied verdict.
    try:
        reader = PdfFileReader(BytesIO(raw), strict=True)
    except Exception as error:
        if not modified:
            raise
        return dict(exception_type=type(error).__name__, exception_message=str(error),
                    rejected=True, scope="Actual modified-byte parser exception; no invented status fields")
    authentication = dict(encrypted=reader.encrypted, password_supplied=password is not None,
                          expect_mac=expect_mac)
    if reader.encrypted:
        assert password is not None, "Encrypted output requires an explicit document fixture password"
        try:
            auth = reader.decrypt(password)
        except Exception as error:
            if not modified:
                raise
            return dict(exception_type=type(error).__name__, exception_message=str(error),
                        rejected=True, authentication=authentication,
                        scope="Actual modified-byte decryption/MAC exception; no CMS validation fallback")
        authentication.update(status=auth.status.name, mac_status=auth.mac_status.name,
                              mac_failure_reason=auth.mac_failure_reason)
        # A MAC failure is an authentication failure in the pinned reader. Do
        # not use a computed key from a failed result to validate CMS anyway.
        if auth.status == AuthStatus.FAILED or auth.mac_status == PdfMacStatus.FAILED:
            if not modified:
                raise AssertionError("Original native output failed actual PDF authentication/MAC")
            return dict(rejected=True, authentication=authentication,
                        scope="Actual modified-byte authentication/MAC refusal; CMS was not evaluated")
        if expect_mac:
            assert auth.mac_status == PdfMacStatus.SUCCESSFUL, "Expected MAC must be actually verified"
    else:
        assert not expect_mac, "Expected PDF MAC requires actual encrypted document authentication"
    try:
        sigs = reader.embedded_regular_signatures
    except Exception as error:
        if not modified:
            raise
        return dict(exception_type=type(error).__name__, exception_message=str(error),
                    rejected=True, authentication=authentication,
                    scope="Actual modified-byte signature extraction exception; no invented status fields")
    assert not reader.embedded_timestamp_signatures, "Unexpected document timestamp requires original full LTA profile"
    assert len(sigs) == 1
    signature = sigs[0]
    assert signature.field_name == "Sig1"
    unsigned = signature.signer_info["unsigned_attrs"]
    if unsigned.native is not None:
        assert not any(attr["type"].native == "signature_time_stamp_token" for attr in unsigned), "Unexpected TST must not be bypassed by a Basic fallback"
    with freeze_time(moment):
        # Native point_in_time_validation(false): freeze NOW and leave moment
        # unspecified instead of constructing a historical context.
        context = ValidationContext(trust_roots=roots, allow_fetching=False,
                                    revocation_mode="soft-fail", time_tolerance=timedelta(seconds=1))
        try:
            with warnings.catch_warnings(record=True) as observed:
                warnings.simplefilter("always")
                status = validate_pdf_signature(signature, signer_validation_context=context)
        except Exception as error:
            if not modified:
                raise
            return dict(exception_type=type(error).__name__, exception_message=str(error),
                        rejected=True, authentication=authentication, scope="Actual modified-byte validation exception; no invented status fields")
    path = None if status.validation_path is None else [cert.dump() for cert in status.validation_path]
    result = dict(authentication=authentication, intact=status.intact, valid=status.valid, trusted=status.trusted,
                  bottom_line=status.bottom_line, coverage=status.coverage.name,
                  modification_level=status.modification_level.name,
                  md_algorithm=status.md_algorithm, signature_mechanism=status.pkcs7_signature_mechanism,
                  signer_sha256=digest(status.signing_cert.dump()),
                  path_sha256=None if path is None else [digest(cert) for cert in path],
                  trust_indication=None if status.trust_problem_indic is None else status.trust_problem_indic.name,
                  summary=status.summary(), field=signature.field_name,
                  claimed_signing_time=None if signature.self_reported_timestamp is None else signature.self_reported_timestamp.isoformat(),
                  warnings=[dict(category=item.category.__name__, message=str(item.message)) for item in observed])
    assert status.signing_cert.dump() == leaf.dump()
    if not modified:
        assert status.intact and status.valid and status.coverage.name == "ENTIRE_FILE"
    if roots and status.bottom_line:
        assert path == [roots[0].dump(), intermediate.dump(), leaf.dump()]
    if not roots:
        assert not status.trusted and not status.bottom_line
    if modified:
        assert not status.intact and not status.bottom_line
    elif roots and moment > leaf["tbs_certificate"]["validity"]["not_after"].native + timedelta(seconds=1):
        assert not status.trusted and not status.bottom_line, "Actual NOW after leaf expiry must retain refusal"
    return result


def main():
    assert __debug__ and sys.flags.optimize == 0
    request = json.loads(read(sys.argv[1], "request"))
    fixture = Path(__file__).resolve().parent
    root = x509.Certificate.load(read(request.get("root", fixture / "root.der"), "root"))
    intermediate = x509.Certificate.load(read(request.get("intermediate", fixture / "interm.der"), "intermediate"))
    leaf = x509.Certificate.load(read(request.get("leaf", fixture / "signer1.der"), "leaf"))
    rows = []
    for case in request["cases"]:
        assert not ("password" in case and "password_file" in case), "Document password selectors are mutually exclusive"
        password = case.get("password")
        if "password_file" in case:
            password = read(case["password_file"], "document fixture password input; contents never emitted").decode("utf-8")
        assert password is None or isinstance(password, str)
        expect_mac = case.get("expect_mac", False)
        assert isinstance(expect_mac, bool)
        raw = read(case["pdf"], "actual native output")
        variants = [(False, raw)]
        if case.get("modified_pdf"):
            variants.append((True, read(case["modified_pdf"], "actual native modified-byte control")))
        for moment_text in request["moments"]:
            moment = datetime.fromisoformat(moment_text.replace("Z", "+00:00"))
            assert moment.tzinfo is not None
            for modified, blob in variants:
                for has_root in [True, False]:
                    result = validate_one(blob, moment, [root] if has_root else [], leaf, intermediate, modified,
                                          password=password, expect_mac=expect_mac)
                    row = dict(label=case["label"], moment=moment.isoformat(), modified=modified,
                               explicit_root=has_root, pdf_sha256=digest(blob), status=result,
                               document_password_supplied=password is not None, expected_mac=expect_mac)
                    rows.append(row)
                    if request.get("assert_frozen_positive") and not modified and has_root and moment == datetime(2020, 11, 1, tzinfo=timezone.utc):
                        assert result["bottom_line"] and result["trusted"]
    record = dict(kind="Fresh same-actual-native-output full PDF peers, not original fixture replay",
                  runtime=dict(interpreter=identity(sys.executable), python=sys.version, host=platform.node(),
                               assertions_enabled=__debug__, optimize=sys.flags.optimize,
                               packages={name:importlib.metadata.version(name) for name in ["pyhanko", "pyhanko-certvalidator"]}),
                  profile=dict(point_in_time_validation=False, moment_source="frozen NOW; no explicit moment parameter",
                               time_tolerance_seconds=1, revocation_mode="soft-fail", allow_fetching=False,
                               trust_roots="explicit root or explicit empty", other_certs=[],
                               intermediate_source="actual CMS, never preloaded"),
                  statuses=rows, opened_inputs=OPENED)
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
