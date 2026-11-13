"""Supplemental policy composition reference, zero original IDs.

Certificate preparation is reference-generated fixture material, never native
PDF proof. `check` reads the exact native output only when signing succeeded.
"""

import asyncio
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
from datetime import datetime
from io import BytesIO

from asn1crypto import algos, core, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import InvalidCertificateError, PathBuildingError, PathValidationError


TIME = "2020-11-01T00:00:00Z"
PDF_SIGNER_SHA = "7170096d60fc6ee9fe1c3067a24d0b1dca01a42961a0c08aa8ad26cb3bc849c6"
SETTINGS_SHA = "cd18586bce329f604fce902ea1dd051b40d26088f1b97766f5d0594febe403cb"
CV_USAGE_SHA = "ce43e832c4b03dba222acbdbcf3140771ac1470e44e75738089dd5036c176574"
STATUS_SHA = '2a4fea2f16271dc72ce4b2385ef4176f0fdee593ee5eb2d70f4fed315f90ebab'
OPENED = []


def read(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    OPENED.append(dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    return data


def versions_and_sources():
    assert sys.flags.optimize == 0
    versions = dict(
        pyhanko=importlib.metadata.version("pyhanko"),
        certvalidator=importlib.metadata.version("pyhanko-certvalidator"),
    )
    assert versions == dict(pyhanko="0.38.1", certvalidator="0.33.0"), versions
    for path, expected in [
        ("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/src/pyhanko/sign/signers/pdf_signer.py", PDF_SIGNER_SHA),
        ("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/src/pyhanko/sign/validation/settings.py", SETTINGS_SHA),
        ("/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator/src/pyhanko_certvalidator/validate.py", CV_USAGE_SHA),
        ('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/src/pyhanko/sign/validation/status.py', STATUS_SHA),
    ]:
        assert hashlib.sha256(read(path)).hexdigest() == expected, path
    # Bind actual imported implementation bytes too; editable roots may differ.
    import inspect
    import pyhanko.sign.signers.pdf_signer as pdf_signer
    import pyhanko.sign.validation.settings as settings
    import pyhanko_certvalidator.validate as cv_validate
    import pyhanko.sign.validation.status as status_module
    for module, expected in [(pdf_signer, PDF_SIGNER_SHA), (settings, SETTINGS_SHA), (cv_validate, CV_USAGE_SHA), (status_module, STATUS_SHA)]:
        assert hashlib.sha256(read(inspect.getfile(module))).hexdigest() == expected
    return versions


def prepare(request):
    leaf = x509.Certificate.load(read(request["leaf"]))
    issuer = x509.Certificate.load(read(request["intermediate"]))
    root = x509.Certificate.load(read(request["root"]))
    key = serialization.load_pem_private_key(read(request["issuer_key"]), password=b"secret")
    assert key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == issuer.public_key.dump()
    assert set(leaf.key_usage_value.native) == {"digital_signature", "non_repudiation"}
    assert leaf.extended_key_usage_value is None
    target = Path(request["directory"]).resolve()
    target.mkdir(exist_ok=False)
    variants = {}
    for name, eku, remove_ku in [
        ("base", None, False),
        ("any-eku", ["any_extended_key_usage"], False),
        ("exact-eku", ["time_stamping"], False),
        ("other-eku", ["server_auth"], False),
        ("missing-ku", None, True),
    ]:
        cert = x509.Certificate.load(leaf.dump())
        tbs = cert["tbs_certificate"]
        extensions = [ext for ext in tbs["extensions"] if ext["extn_id"].native != "extended_key_usage" and not (remove_ku and ext["extn_id"].native == "key_usage")]
        if eku is not None:
            extensions.append(x509.Extension(dict(extn_id="extended_key_usage", critical=False, extn_value=x509.ExtKeyUsageSyntax(eku))))
        tbs["extensions"] = x509.Extensions(extensions)
        algorithm = algos.SignedDigestAlgorithm(dict(algorithm="sha256_rsa"))
        tbs["signature"] = algorithm
        cert["signature_algorithm"] = algorithm
        cert["signature_value"] = core.OctetBitString(key.sign(tbs.dump(), padding.PKCS1v15(), hashes.SHA256()))
        # Every variant is actually issued by the original intermediate.
        key.public_key().verify(cert["signature_value"].native, tbs.dump(), padding.PKCS1v15(), hashes.SHA256())
        path = target / (name + ".der")
        path.write_bytes(cert.dump())
        variants[name] = dict(path=str(path), sha256=hashlib.sha256(read(path)).hexdigest())
    return dict(variant_origin="REFERENCE_GENERATED_CERTIFICATES_NOT_NATIVE_PDFS", variants=variants,
                root_sha256=hashlib.sha256(root.dump()).hexdigest())


def constraints(value):
    assert set(value) == {"key_usage", "key_usage_forbidden", "extd_key_usage", "explicit_extd_key_usage_required", "match_all_key_usages"}
    args = {}
    for key in ["key_usage", "key_usage_forbidden", "extd_key_usage"]:
        items = value[key]
        assert items is None or isinstance(items, list) and all(isinstance(item, str) for item in items)
        if items is not None:
            assert len(items) == len(set(items))
        args[key] = None if items is None else set(items)
    for key in ["explicit_extd_key_usage_required", "match_all_key_usages"]:
        assert type(value[key]) is bool
        args[key] = value[key]
    return KeyUsageConstraints(**args)


def check(request):
    case = request["case"]
    assert set(case) == {"id", "variant", "context", "legacy", "policy", "native_ok", "oracle_policy_ok", "core_policy_ok", "error_contains"}
    assert case["variant"] in {"base", "any-eku", "exact-eku", "other-eku", "missing-ku"}
    assert case["context"] in {"valid", "none", "empty-roots", "require-revinfo", "expired", "deny-digest"}
    assert isinstance(case["id"], str) and case["id"]
    assert isinstance(case["legacy"], list) and all(isinstance(item, str) for item in case["legacy"])
    assert len(case["legacy"]) == len(set(case["legacy"]))
    for field in ["native_ok", "oracle_policy_ok", "core_policy_ok"]:
        assert type(case[field]) is bool
    cert = x509.Certificate.load(read(request["leaf"]))
    root = x509.Certificate.load(read(request["root"]))
    intermediate = x509.Certificate.load(read(request["intermediate"]))
    policy = constraints(case["policy"]) if case["policy"] is not None else None
    policy_ok, error = True, None
    # This is the actual policy API, not a hand-implemented OR/AND model.
    if policy is not None:
        try:
            policy.validate(cert)
        except InvalidCertificateError as exc:
            policy_ok, error = False, str(exc)
    elif case["context"] != "none":
        context = ValidationContext(trust_roots=[root], other_certs=[intermediate],
                                    moment=datetime.fromisoformat(TIME), allow_fetching=False,
                                    revocation_mode="soft-fail")
        try:
            asyncio.run(CertificateValidator(cert, intermediate_certs=[intermediate], validation_context=context).async_validate_usage(set(case["legacy"])))
        except InvalidCertificateError as exc:
            policy_ok, error = False, str(exc)
    assert policy_ok == case["oracle_policy_ok"], (case, policy_ok, error)
    result = dict(policy_ok=policy_ok, policy_error=error, full_native_pdf_checked=False,
                  comparison="ACTUAL_PINNED_POLICY_API; full policy is additive composition, not metadata support")
    if case["context"] in {"empty-roots", "require-revinfo", "expired"}:
        try:
            guard_context = ValidationContext(
                trust_roots=[] if case["context"] == "empty-roots" else [root],
                other_certs=[intermediate], allow_fetching=False,
                moment=datetime.fromisoformat("2050-11-01T00:00:00Z" if case["context"] == "expired" else TIME),
                revocation_mode="require" if case["context"] == "require-revinfo" else "soft-fail",
            )
        except ValueError as exc:
            # Exact pinned constructor preflight, not any ValueError accepted
            # as policy evidence. Native's eventual denial phase may differ.
            assert case["context"] == "require-revinfo"
            assert str(exc) == "revocation data is not optional and allow_fetching is False, however crls and ocsps are both None, meaning that no validation can happen"
            result.update(guard_rejected=True, guard_phase="context-construction", guard_error_type=type(exc).__name__, guard_error=str(exc))
        else:
            try:
                asyncio.run(CertificateValidator(cert, intermediate_certs=[intermediate], validation_context=guard_context).async_validate_usage(set()))
            except (PathBuildingError, PathValidationError) as exc:
                result.update(guard_rejected=True, guard_phase="path-validation", guard_error_type=type(exc).__name__, guard_error=str(exc))
            else:
                raise AssertionError("mandatory independent context control was waived")
    elif case["context"] == "deny-digest":
        from pyhanko.sign.signers import ExternalSigner, PdfSignatureMetadata, PdfSigner
        from pyhanko.sign.general import SigningError
        from pyhanko_certvalidator.policy_decl import AlgorithmUsageConstraint, DisallowWeakAlgorithmsPolicy

        class DenySha256(DisallowWeakAlgorithmsPolicy):
            def digest_algorithm_allowed(self, algorithm, moment):
                return AlgorithmUsageConstraint(algorithm["algorithm"].native != "sha256")

        guard_context = ValidationContext(trust_roots=[root], algorithm_usage_policy=DenySha256())
        metadata = PdfSignatureMetadata(field_name="Sig1", md_algorithm="sha256", validation_context=guard_context)
        # Only probe the real digest selection gate. ExternalSigner's dummy
        # bytes are never signed, emitted or offered as integrity/trust proof.
        selector = PdfSigner(metadata, ExternalSigner(cert, None, signature_value=256))
        try:
            selector._select_md_algorithm(None)
        except SigningError as exc:
            assert "sha256 is not allowed" in str(exc)
            result.update(guard_rejected=True, guard_error_type=type(exc).__name__, guard_error=str(exc))
        else:
            raise AssertionError("caller document digest denial was waived")
    if request.get("pdf") is not None:
        assert case["native_ok"] is True
        assert policy_ok is True, "an emitted PDF must meet the complete explicit policy"
        pdf = read(request["pdf"])
        reader = PdfFileReader(BytesIO(pdf))
        assert len(reader.embedded_signatures) == 1
        signature = reader.embedded_signatures[0]
        assert signature.field_name == "Sig1"
        context = ValidationContext(trust_roots=[root], other_certs=[intermediate],
                                    moment=datetime.fromisoformat(TIME), allow_fetching=False,
                                    revocation_mode="soft-fail")
        # Preserve the raw public PDF facade result too. Pinned status.py
        # default_usage_constraints reconstructs only KU/EKU, dropping three
        # fields, so its result is not the complete policy predicate above.
        raw_status = validate_pdf_signature(signature, context, key_usage_settings=policy)
        assert raw_status.intact and raw_status.valid
        assert raw_status.md_algorithm == "sha256"
        assert raw_status.signing_cert.dump() == cert.dump()
        assert raw_status.coverage.name == "ENTIRE_FILE"
        known_optional_eku_gap = case["id"] in {"missing-eku-optional", "any-eku-optional"}
        assert raw_status.trusted == (not known_optional_eku_gap)
        assert raw_status.bottom_line == (not known_optional_eku_gap)
        raw_indication = raw_status.trust_problem_indic
        if known_optional_eku_gap:
            assert raw_indication.name == "CHAIN_CONSTRAINTS_FAILURE"
        result["raw_pdf_facade"] = dict(
            trusted=raw_status.trusted, bottom_line=raw_status.bottom_line,
            trust_indication=None if raw_indication is None else raw_indication.name,
            summary=raw_status.summary(),
        )
        # AND composition: the real five-field certificate policy already
        # passed, and this same PDF must independently pass full cryptographic
        # and PKIX validation. Use the SAME context, roots and time. This
        # component does not pretend to repair or reproduce the raw facade.
        status = validate_pdf_signature(signature, context, key_usage_settings=KeyUsageConstraints(key_usage=set(), extd_key_usage=None))
        assert status.intact and status.valid and status.trusted and status.bottom_line
        assert status.md_algorithm == "sha256"
        assert status.signing_cert.dump() == cert.dump()
        assert len(status.validation_path) == 3
        assert status.coverage.name == "ENTIRE_FILE"
        assert status.modification_level.name == "NONE"
        summary = status.summary()
        assert "INTACT" in summary and "TRUSTED" in summary
        result.update(full_native_pdf_checked=True, pdf_sha256=hashlib.sha256(pdf).hexdigest(), signer_sha256=hashlib.sha256(cert.dump()).hexdigest(),
                      intact=status.intact, valid=status.valid, trusted=status.trusted,
                      bottom_line=status.bottom_line, path_len=3, coverage=status.coverage.name,
                      modification_level=status.modification_level.name)
    return result


versions = versions_and_sources()
mode = sys.argv[1]
assert mode in {"prepare", "check"}
request = json.loads(read(sys.argv[2]))
with freeze_time(TIME):
    result = prepare(request) if mode == "prepare" else check(request)
result.update(versions=versions, opened_inputs=OPENED)
print(json.dumps(result, sort_keys=True))
