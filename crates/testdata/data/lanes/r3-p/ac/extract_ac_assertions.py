# SPDX-License-Identifier: MIT
"""Extract exact pinned post-signing assertions without requiring source at runtime."""

import argparse
import ast
import hashlib
import json
import textwrap
from pathlib import Path

CASES = (
    "test_pades_live_ac_presign_validation",
    "test_pades_lta_live_ac_presign_validation",
    "test_cades_signer_attrs_autofill_dss",
    "test_cades_signer_attrs_validate_acs",
    "test_cades_signer_attrs_validate_acs_no_claimed",
    "test_cades_signer_attrs_validate_acs_wrong_vc",
    "test_cades_signer_attrs_validate_acs_missing_vc",
)

HEADER = '''# SPDX-License-Identifier: MIT
# Derived from pyHanko 0.38.1, copyright (c) 2020-2026 Matthias Valvekens.
# See LICENSE-pyHanko and ac-assertions-source.json in this directory.
"""Exact post-signing assertion tails for freshly generated Rust AC PDFs.

No upstream source checkout is needed when this fixture executes.
"""

import asyncio
import importlib.metadata
import json
import sys
from io import BytesIO
from pathlib import Path

from asn1crypto import cms
from certomancer.registry import ArchLabel, CertLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"

'''

RUNNER = '''
def main():
    if sys.argv[1:] == ["--list"]:
        print(json.dumps(ASSERTION_COUNTS, sort_keys=True))
        return
    name, output, backend = sys.argv[1:]
    if name not in ASSERTION_COUNTS or backend not in {"requests", "aiohttp"}:
        raise ValueError("Unknown exact AC case or fetcher backend")
    with freeze_time("2020-11-01"), live_pki_services() as services:
        arch = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
        services.register(arch)
        globals().update(
            pki_arch=arch,
            pki_services=services,
            out=BytesIO(Path(output).read_bytes()),
        )
        if backend == "aiohttp":
            from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
            fetcher_backend = AIOHttpFetcherBackend()
        else:
            from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
            fetcher_backend = RequestsFetcherBackend()
        async def execute():
            try:
                globals()["fetchers"] = fetcher_backend.get_fetchers()
                await globals()[name]()
            finally:
                await fetcher_backend.close()
        asyncio.run(execute())
    print("PASS exact upstream assertions", name, backend)


if __name__ == "__main__":
    main()
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--helper-source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source_bytes = args.source.read_bytes()
    source = source_bytes.decode()
    lines = source.splitlines(keepends=True)
    nodes = {node.name: node for node in ast.parse(source).body if isinstance(node, ast.AsyncFunctionDef)}
    helper_bytes = args.helper_source.read_bytes()
    helper_source = helper_bytes.decode()
    helper = next(node for node in ast.parse(helper_source).body if isinstance(node, ast.FunctionDef) and node.name == "live_ac_vcs")
    helper_text = "".join(helper_source.splitlines(keepends=True)[helper.lineno - 1:helper.end_lineno])
    generated = HEADER + helper_text + "\n\n"
    expected = {}
    manifest = {
        "pyhanko": "0.38.1",
        "pyhanko_commit": "580f49498f76a00bda11d5a3fd86f7af3f0da75e",
        "certvalidator": "0.33.0",
        "source": {
            "repository_path": "pkgs/pyhanko/tests/test_pades.py",
            "sha256": digest(source_bytes),
        },
        "helper_source": {
            "repository_path": "internal/common-test-utils/src/pyhanko_testing_commons/test_utils/signing_commons.py",
            "sha256": digest(helper_bytes),
            "function": "live_ac_vcs",
            "first_line": helper.lineno,
            "last_line": helper.end_lineno,
            "extracted_sha256": digest(helper_text.encode()),
        },
        "selection": "LTA: function body after the first signing with-block; others: first assignment to r through function end. Preserve every selected statement, comment and nested assertion; only dedent/indent into a parameter-free async wrapper.",
        "cases": {},
    }
    for name in CASES:
        node = nodes[name]
        if name == "test_pades_lta_live_ac_presign_validation":
            tail = node.body[1:]
        else:
            start = next(index for index, statement in enumerate(node.body) if isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "r" for target in statement.targets))
            tail = node.body[start:]
        extracted = "".join(lines[tail[0].lineno - 1:tail[-1].end_lineno])
        body = textwrap.dedent(extracted)
        generated += f"async def {name}():\n" + textwrap.indent(body, "    ") + "\n\n"
        expected[name] = [ast.dump(statement, include_attributes=False) for statement in tail]
        manifest["cases"][name] = {
            "first_line": tail[0].lineno,
            "last_line": tail[-1].end_lineno,
            "assertions": sum(isinstance(child, ast.Assert) for statement in tail for child in ast.walk(statement)),
            "source_tail_sha256": digest(extracted.encode()),
        }
    counts = {name: case["assertions"] for name, case in manifest["cases"].items()}
    generated += "ASSERTION_COUNTS = " + repr(counts) + "\n" + RUNNER
    generated_nodes = {node.name: node for node in ast.parse(generated).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in CASES:
        assert [ast.dump(statement, include_attributes=False) for statement in generated_nodes[name].body] == expected[name]
        assert counts[name] > 0
    assert ast.dump(generated_nodes["live_ac_vcs"], include_attributes=False) == ast.dump(helper, include_attributes=False)
    manifest["generated_sha256"] = digest(generated.encode())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "ac_assertions.py").write_text(generated)
    (args.output_dir / "ac-assertions-source.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"source_sha256": manifest["source"]["sha256"], "assertions": counts}, sort_keys=True))


if __name__ == "__main__":
    main()
