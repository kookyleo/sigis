"""Fresh original post-sign assertions on exact native P7 bytes, not original signing."""
import argparse
from contextlib import redirect_stdout
from hashlib import sha256
from importlib.metadata import version
from io import StringIO
import json
from pathlib import Path
import runpy
import sys

CASES = {
    "test_pades_live_ac_presign_validation": 9,
    "test_pades_lta_live_ac_presign_validation": 4,
    "test_cades_signer_attrs_autofill_dss": 1,
    "test_cades_signer_attrs_validate_acs": 15,
    "test_cades_signer_attrs_validate_acs_no_claimed": 11,
    "test_cades_signer_attrs_validate_acs_wrong_vc": 10,
    "test_cades_signer_attrs_validate_acs_missing_vc": 9,
}


def main():
    parser = argparse.ArgumentParser()
    for name in ["case", "backend", "pdf", "root", "aa-root", "ac", "assertions-script"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    assert args.case in CASES and args.backend in {"requests", "aiohttp"}
    inputs = {"pdf": args.pdf, "root": args.root, "aa_root": args.aa_root, "ac": args.ac}
    raw = {label: Path(path).read_bytes() for label, path in inputs.items()}
    opened = {label: {"path": str(Path(inputs[label]).resolve()), "bytes": len(data),
                      "sha256": sha256(data).hexdigest()} for label, data in raw.items()}
    assertions = Path(args.assertions_script)
    preparse = {"case": args.case, "backend_label": args.backend, "opened": opened,
                "pyhanko": version("pyhanko"), "certvalidator": version("pyhanko-certvalidator"),
                "assertions_script_sha256": sha256(assertions.read_bytes()).hexdigest(),
                "helper_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}
    # Actual output receipt BEFORE parsing/validation. No frozen verdict replay.
    print("P7_PY_OPEN " + json.dumps(preparse), file=sys.stderr, flush=True)
    assert preparse["pyhanko"] == "0.38.1" and preparse["certvalidator"] == "0.33.0"
    # Refuse a silent change to the reviewed unchanged59-assertion oracle tails.
    assert preparse["assertions_script_sha256"] == "bc4cf6726e9a467631a790138c887e07bdac728c6b3ce7d0f25a4063b91bc960"
    from certomancer.registry import ArchLabel, CertLabel
    from pyhanko_testing_commons.test_data.samples import CERTOMANCER
    architecture = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
    # The legacy exact tails build their original PKI policies internally.
    # Verify those are the ACTUAL supplied native roots/AC, not another PKI.
    assert architecture.get_cert(CertLabel("root")).dump() == raw["root"]
    assert architecture.get_cert(CertLabel("root-aa")).dump() == raw["aa_root"]
    assert architecture.get_attr_cert(CertLabel("alice-role-with-rev")).dump() == raw["ac"]
    original_argv = sys.argv
    capture = StringIO()
    try:
        sys.argv = [str(assertions), args.case, args.pdf, args.backend]
        with redirect_stdout(capture):
            runpy.run_path(str(assertions), run_name="__main__")
    finally:
        sys.argv = original_argv
    actual_stdout = capture.getvalue()
    assert "PASS exact upstream assertions" in actual_stdout, actual_stdout
    # Reopen after validation to prove the validator input file was not replaced.
    assert all(Path(inputs[label]).read_bytes() == data for label, data in raw.items())
    print(json.dumps({**preparse, "assertion_tail_passed": True,
                      "original_assertions": CASES[args.case],
                      "original_full_signing_function_executed": False,
                      "reference_kind": "fresh original assertion tail over actual native PDF",
                      "native_count_credit": 0,
                      "assertion_stdout": actual_stdout}), flush=True)


if __name__ == "__main__":
    main()
