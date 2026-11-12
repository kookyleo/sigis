"""Generate/recheck exact validator-integrity inputs with pyHanko 0.38.1.

The two originating test functions remain lane S-owned. Generation is distinct
from Rust replay and earns no passing-function count. Existing shared inputs
are read-only. All generated files are confined to the output directory.
"""

import argparse
import base64
import hashlib
import json
import logging
from importlib.metadata import version
from io import BytesIO
from pathlib import Path
import sys


TIME = "2020-11-01T00:00:00Z"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path("/tmp/pyhanko-oracle/src/v0.38.1"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    for path in [args.source / "internal/common-test-utils/src", args.source / "pkgs/pyhanko/src"]:
        sys.path.insert(0, str(path))
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    from freezegun import freeze_time
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign import signers
    from pyhanko.sign.diff_analysis import NO_CHANGES_DIFF_POLICY, SuspiciousModification
    from pyhanko.sign.validation import SignatureCoverageLevel, validate_pdf_signature
    from pyhanko.sign.validation.settings import KeyUsageConstraints
    from pyhanko_testing_commons.test_data.samples import MINIMAL, PDF_DATA_DIR
    from pyhanko_testing_commons.test_utils.signing_commons import FROM_CA, ROOT_CERT, notrust_v_context, simple_v_context

    args.output.mkdir(parents=True, exist_ok=True)
    if not args.replay:
        with freeze_time(TIME):
            writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
            signed = signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name="Sig1"), signer=FROM_CA)
            clean = signed.getvalue()
            (args.output / "clean-signature.pdf").write_bytes(clean)

            # Exact test_tamper_sig_obj mutation, including write_in_place().
            writer = IncrementalPdfFileWriter(signed)
            signature_dictionary = writer.prev.embedded_signatures[0].sig_object
            signature_dictionary["/Bleh"] = generic.BooleanObject(False)
            writer.update_container(signature_dictionary)
            writer.write_in_place()
            (args.output / "tampered-signature.pdf").write_bytes(signed.getvalue())

            # Independent modification guard: original coverage remains complete.
            stream = BytesIO(clean)
            writer = IncrementalPdfFileWriter(stream)
            page = writer.root["/Pages"]["/Kids"][0].get_object()
            page["/Rotate"] = generic.NumberObject(90)
            writer.update_container(page)
            writer.write_in_place()
            (args.output / "page-modified.pdf").write_bytes(stream.getvalue())

    def validate(value, *, mode="default", trusted=True, lenient_ku=False):
        with freeze_time(TIME):
            reader = PdfFileReader(BytesIO(value))
            embedded = reader.embedded_signatures[0]
            context = simple_v_context() if trusted else notrust_v_context()
            kwargs = dict(skip_diff=mode == "skip_diff")
            if mode == "no_changes":
                kwargs["diff_policy"] = NO_CHANGES_DIFF_POLICY
            if lenient_ku:
                kwargs["key_usage_settings"] = KeyUsageConstraints(key_usage=set())
            status = validate_pdf_signature(embedded, signer_validation_context=context, **kwargs)
            names = {
                "NONE": "None", "LTA_UPDATES": "LtaUpdates", "FORM_FILLING": "FormFilling",
                "ANNOTATIONS": "Annotations", "OTHER": "Other",
            }
            return {
                "mode": mode,
                "sha256": hashlib.sha256(value).hexdigest(),
                "valid": status.valid,
                "intact": status.intact,
                "trusted": status.trusted,
                "coverage": status.coverage.name,
                "modification_level": status.modification_level.name,
                "modification_level_rust": names[status.modification_level.name],
                "bottom_line": status.bottom_line,
                "docmdp_ok": status.docmdp_ok,
                "summary": status.summary(),
                "diff_none": embedded.diff_result is None,
                "diff_suspicious": isinstance(embedded.diff_result, SuspiciousModification),
                "byte_range": list(embedded.byte_range),
            }

    document = {
        "pyhanko": "0.38.1", "certvalidator": "0.33.0", "validation_time": TIME,
        "trust_root": base64.b64encode(ROOT_CERT.dump()).decode("ascii"),
        "upstream_functions": [
            "pyhanko/test_diff_analysis.py::test_tamper_sig_obj",
            "pyhanko/test_diff_analysis.py::test_anomalous_coverage",
        ],
    }
    tampered = (args.output / "tampered-signature.pdf").read_bytes()
    document["tamper"] = []
    for mode in ["default", "no_changes", "skip_diff"]:
        status = validate(tampered, mode=mode, trusted=False)
        assert status["diff_none"] if mode == "skip_diff" else status["diff_suspicious"]
        assert status["coverage"] == "CONTIGUOUS_BLOCK_FROM_START"
        assert status["modification_level"] == "OTHER"
        document["tamper"].append(status)

    document["anomalous"] = []
    for name, expected in [
        ("tail-uncovered.pdf", SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START),
        ("signature-gap-too-big.pdf", SignatureCoverageLevel.UNCLEAR),
        ("one-byterange.pdf", SignatureCoverageLevel.UNCLEAR),
        ("weird-byterange.pdf", SignatureCoverageLevel.UNCLEAR),
    ]:
        status = validate((Path(PDF_DATA_DIR) / "coverage-anomalies" / name).read_bytes(), lenient_ku=True)
        assert status["valid"] and status["intact"] and not status["trusted"]
        assert status["coverage"] == expected.name
        assert not status["bottom_line"]
        assert "NONSTANDARD_COVERAGE" in status["summary"]
        document["anomalous"].append(dict(name=name, **status))

    document["clean_control"] = validate((args.output / "clean-signature.pdf").read_bytes())
    assert document["clean_control"]["coverage"] == "ENTIRE_FILE"
    assert document["clean_control"]["bottom_line"]
    document["modification_control"] = validate((args.output / "page-modified.pdf").read_bytes())
    changed = document["modification_control"]
    assert changed["coverage"] == "ENTIRE_REVISION"
    assert changed["valid"] and changed["intact"] and changed["trusted"]
    assert changed["modification_level"] == "OTHER"
    assert not changed["docmdp_ok"] and not changed["bottom_line"]
    manifest = args.output / "manifest.json"
    if args.replay:
        assert json.loads(manifest.read_text()) == document
    else:
        manifest.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"oracle_validation_calls": 9, "original_parameter_cases": 7,
                      "unique_upstream_functions": 2, "replay": args.replay}))


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    main()
