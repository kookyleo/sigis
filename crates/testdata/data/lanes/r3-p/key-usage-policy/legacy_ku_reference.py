"""Fresh original legacy presign and same-actual-native-output boundary proof."""
import hashlib
import importlib.metadata
import inspect
import json
from datetime import datetime
from io import BytesIO
from pathlib import Path
import sys

from asn1crypto import keys, x509
from cryptography.hazmat.primitives import serialization
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.errors import InvalidCertificateError
from pyhanko_certvalidator.registry import SimpleCertificateStore
import pyhanko.sign.signers.pdf_signer as pdf_signer
import pyhanko.sign.signers.pdf_cms as pdf_cms
import pyhanko_certvalidator.validate as cv_validate

OPENED = []
TIME = "2020-11-01T00:00:00Z"


def read(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    OPENED.append(dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    return data


def vc(root, intermediate):
    return ValidationContext(trust_roots=[root], other_certs=[intermediate],
                             moment=datetime.fromisoformat(TIME),
                             allow_fetching=False, revocation_mode="soft-fail")


assert importlib.metadata.version("pyHanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
for module, digest in [
    (pdf_signer, "7170096d60fc6ee9fe1c3067a24d0b1dca01a42961a0c08aa8ad26cb3bc849c6"),
    (pdf_cms, "fb0bcd49d707f6f98b6641d3711979f8ec2ec14769779026ac8a6801a25ab0fa"),
    (cv_validate, "ce43e832c4b03dba222acbdbcf3140771ac1470e44e75738089dd5036c176574"),
]:
    assert hashlib.sha256(read(inspect.getfile(module))).hexdigest() == digest
request = json.loads(read(sys.argv[1]))
cert = x509.Certificate.load(read(request["leaf"]))
root = x509.Certificate.load(read(request["root"]))
intermediate = x509.Certificate.load(read(request["intermediate"]))
input_pdf = read(request["input"])
key = serialization.load_pem_private_key(read(request["signer_key"]), password=b"secret")
assert key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == cert.public_key.dump()
assert (cert.key_usage_value is None) == request["missing_ku"]
store = SimpleCertificateStore()
store.register_multiple([intermediate, root])
signer = signers.SimpleSigner(signing_cert=cert, signing_key=keys.PrivateKeyInfo.load(
    key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())), cert_registry=store)
result = dict(case=request["case"], versions={"pyhanko": "0.38.1", "certvalidator": "0.33.0"})
with freeze_time(TIME):
    context = vc(root, intermediate) if request["attached"] else None
    metadata = signers.PdfSignatureMetadata(field_name="Sig1", md_algorithm="sha256",
                                            validation_context=context,
                                            signer_key_usage=set(request["legacy"]))
    try:
        reference = signers.sign_pdf(IncrementalPdfFileWriter(BytesIO(input_pdf)), metadata, signer)
    except InvalidCertificateError as exc:
        assert request["attached"] and request["legacy"]
        missing = set(request["legacy"]) - (set() if request["missing_ku"] else {"non_repudiation", "digital_signature"})
        assert len(missing) == 1
        assert str(exc) == "The X.509 certificate provided is not valid for the purpose of " + next(iter(missing)).replace("_", " ")
        result.update(original_signing_ok=False, error_type=type(exc).__name__, error=str(exc))
    else:
        assert request["expected_ok"]
        reference_bytes = reference.getvalue()
        out = Path(request["reference_output"])
        out.write_bytes(reference_bytes)
        # Reference-produced PDFs are separate from actual native outputs.
        result.update(original_signing_ok=True, reference_output_sha256=hashlib.sha256(read(out)).hexdigest())
    assert result["original_signing_ok"] == request["expected_ok"]
    if request["native_pdf"] is not None:
        native = read(request["native_pdf"])
        signatures = PdfFileReader(BytesIO(native)).embedded_signatures
        assert len(signatures) == 1 and signatures[0].field_name == "Sig1"
        sig = signatures[0]
        assert sig.signer_cert.dump() == cert.dump()
        # The same legacy predicate is meaningful on attached-context calls;
        # absent-context signing intentionally does not perform usage validation.
        requirements = set(request["legacy"]) if request["attached"] else set()
        status = validate_pdf_signature(sig, vc(root, intermediate),
            key_usage_settings=KeyUsageConstraints(key_usage=requirements))
        assert status.intact and status.valid
        assert status.signing_cert.dump() == cert.dump() and status.md_algorithm == "sha256"
        assert status.coverage.name == "ENTIRE_FILE" and status.modification_level.name == "NONE"
        assert status.trusted == request["expected_ok"]
        assert status.bottom_line == request["expected_ok"]
        if not request["expected_ok"]:
            assert status.trust_problem_indic.name == "CHAIN_CONSTRAINTS_FAILURE"
        result["same_native_output"] = dict(pdf_sha256=hashlib.sha256(native).hexdigest(),
            intact=status.intact, valid=status.valid, trusted=status.trusted,
            bottom_line=status.bottom_line, coverage=status.coverage.name,
            trust_indication=None if status.trust_problem_indic is None else status.trust_problem_indic.name)
result["opened_inputs"] = OPENED
print(json.dumps(result, sort_keys=True))
