"""Pinned detached CLI and same-output checks, with explicit runtime receipts.

The test helper reproduces the original local fixture clock and post-validation.
Native product commands keep their real clock. Supplied CRL export is an
explicit fixture provider for independent native validation, not native HTTP.
"""
import argparse
import hashlib
import importlib
import importlib.metadata
import json
import os
import sys
from datetime import datetime
from pathlib import Path

if sys.flags.optimize != 0:
    raise RuntimeError("Pinned reference assertions must remain enabled")

import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
import asyncio
import tzlocal
from asn1crypto import cms, pem, tsp, x509
from click.testing import CliRunner
from freezegun import freeze_time
from pyhanko.cli import cli_root
import pyhanko.cli
from pyhanko.sign.validation import async_validate_detached_cms
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import (
    TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519,
)
from pyhanko_testing_commons.test_utils.live_http import live_pki_services


def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--root", required=True)
parser.add_argument("--timestamp", action="store_true")
parser.add_argument("--export-revinfo", type=Path)
parser.add_argument("--native-response", action="append", type=Path, default=[])
parser.add_argument("mode", choices=["cli", "verify"])
parser.add_argument("architecture", choices=["rsa", "ecdsa", "ed25519"])
parser.add_argument("argv", nargs=argparse.REMAINDER)
args = parser.parse_args()
assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
assert Path(pyhanko.cli.__file__).resolve().is_relative_to(
    Path("/tmp/pyhanko-oracle/src/v0.38.1")
)
architectures = {"rsa": TESTING_CA, "ecdsa": TESTING_CA_ECDSA,
                 "ed25519": TESTING_CA_ED25519}
moment = datetime(2020, 8, 1, tzinfo=tzlocal.get_localzone())
record = {"mode": args.mode, "architecture": args.architecture,
          "python": snapshot(sys.executable), "python_invocation": sys.executable,
          "driver": snapshot(__file__), "cli_module": snapshot(pyhanko.cli.__file__),
          "pyhanko": importlib.metadata.version("pyhanko"),
          "certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
          "optimize": sys.flags.optimize, "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"),
          "moment": moment.isoformat(), "cwd": str(Path.cwd())}
record["source_modules"] = {
    name: snapshot(importlib.import_module(name).__file__)
    for name in [
        "pyhanko.cli.commands.signing.simple",
        "pyhanko.cli.commands.signing.plugin",
        "certomancer.services",
        "pyhanko.sign.signers.pdf_cms",
        "pyhanko.sign.validation.generic_cms",
        "pyhanko_certvalidator.validate",
        "pyhanko_testing_commons.test_data.samples",
        "pyhanko_testing_commons.test_utils.live_http",
        "certomancer.registry.pki_arch",
    ]
}
# Editable commons may resolve through a different source checkout. Match the
# actual bytes with the immutable pinned tree, without pretending paths match.
pinned = Path("/tmp/pyhanko-oracle/src/v0.38.1")
for name, relative in {
    "pyhanko.cli.commands.signing.plugin": "pkgs/pyhanko-cli/src/pyhanko/cli/commands/signing/plugin.py",
    "pyhanko.cli.commands.signing.simple": "pkgs/pyhanko-cli/src/pyhanko/cli/commands/signing/simple.py",
    "pyhanko_testing_commons.test_data.samples": "internal/common-test-utils/src/pyhanko_testing_commons/test_data/samples.py",
    "pyhanko_testing_commons.test_utils.live_http": "internal/common-test-utils/src/pyhanko_testing_commons/test_utils/live_http.py",
}.items():
    expected = snapshot(pinned / relative)
    assert record["source_modules"][name]["sha256"] == expected["sha256"], name
    record["source_modules"][name]["pinned_comparison"] = expected

with freeze_time(moment):
    # CLI TSA requests use the actual test-owned listener. Only post-validation
    # runs inside the original PKI issuer/revocation fixture services.
    run_validation = True
    if args.mode == "cli":
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        result = CliRunner().invoke(cli_root, argv)
        record.update(argv=argv, code=result.exit_code, output=result.output,
                      exception=None if result.exception is None else
                      {"type": type(result.exception).__name__, "text": str(result.exception)})
        run_validation = result.exit_code == 0
    if run_validation:
        with live_pki_services() as services:
            arch = architectures[args.architecture]
            services.register(arch)
            raw = Path(args.output).read_bytes()
            armor = pem.detect(raw)
            label = None
            if armor:
                label, _, raw = pem.unarmor(raw)
            ci = cms.ContentInfo.load(raw)
            assert ci["content_type"].native == "signed_data"
            sd = ci["content"]
            assert sd["encap_content_info"]["content"].native is None
            if args.mode == "verify" and args.timestamp:
                unsigned = sd["signer_infos"][0]["unsigned_attrs"]
                timestamps = [a["values"][0] for a in unsigned
                              if a["type"].native == "signature_time_stamp_token"]
                assert len(timestamps) == 1
                token = timestamps[0].dump()
                native_pairs = []
                for response_path in args.native_response:
                    request_path = response_path.with_name(response_path.name.replace("response-", "request-", 1))
                    request = tsp.TimeStampReq.load(request_path.read_bytes())
                    response = tsp.TimeStampResp.load(response_path.read_bytes())
                    assert response["status"]["status"].native in ("granted", "granted_with_mods")
                    returned = response["time_stamp_token"]
                    info = returned["content"]["encap_content_info"]["content"].parsed
                    assert request["nonce"].native == info["nonce"].native
                    req_imprint, resp_imprint = request["message_imprint"], info["message_imprint"]
                    assert req_imprint["hash_algorithm"]["algorithm"].native == resp_imprint["hash_algorithm"]["algorithm"].native
                    assert req_imprint["hashed_message"].native == resp_imprint["hashed_message"].native
                    native_pairs.append({"request": snapshot(request_path), "response": snapshot(response_path),
                                         "matches_actual_native_CMS_token": returned.dump() == token,
                                         "nonce": request["nonce"].native,
                                         "digest_algorithm": req_imprint["hash_algorithm"]["algorithm"].native,
                                         "imprint": req_imprint["hashed_message"].native.hex()})
                assert sum(pair["matches_actual_native_CMS_token"] for pair in native_pairs) == 1
                record["native_TSA_request_pairs"] = native_pairs

            root_bytes = Path(args.root).read_bytes()
            if pem.detect(root_bytes):
                root_bytes = pem.unarmor(root_bytes)[2]
            with Path(args.input).open("rb") as input_stream:
                status = asyncio.run(async_validate_detached_cms(
                    input_stream, sd,
                    signer_validation_context=ValidationContext(
                        trust_roots=[x509.Certificate.load(root_bytes)], allow_fetching=True,
                    ),
                ))
            assert status.bottom_line, status.pretty_print_details()
            assert (status.timestamp_validity is not None) == args.timestamp
            record.update(input=snapshot(args.input), signed_output=snapshot(args.output),
                          bottom_line=status.bottom_line, intact=status.intact,
                          valid=status.valid, trusted=status.trusted,
                          has_timestamp=status.timestamp_validity is not None,
                          pem=armor, pem_label=label)
            if args.export_revinfo is not None:
                args.export_revinfo.mkdir()
                evidence = []
                for index, repository in enumerate(arch.service_registry.list_crl_repos()):
                    encoded = arch.service_registry.get_crl(repository.label, at_time=moment).dump()
                    path = args.export_revinfo / f"crl-{index}.der"
                    with path.open("xb") as target:
                        target.write(encoded)
                    evidence.append(snapshot(path))
                assert evidence
                record["crls"] = evidence
                with (args.export_revinfo / "metadata.json").open("x") as target:
                    json.dump(record, target, indent=2)
                    target.write("\n")
print(json.dumps(record))
