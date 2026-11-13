"""Fresh pinned CLI and same-output validation for encrypted PEM signatures.

Only fixture/reference validation uses the upstream historical clock. Native
signing is an actual product subprocess with its normal current clock.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
from datetime import datetime
from pathlib import Path

if sys.flags.optimize != 0:
    raise RuntimeError("Pinned reference assertions must remain enabled")

import pyhanko
pyhanko.__path__.append(
    "/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko"
)
from asn1crypto import pem, x509
from click.testing import CliRunner
from freezegun import freeze_time
import tzlocal
from pyhanko.cli import cli_root
import pyhanko.cli
from pyhanko.cli._ctx import CLIContext, PasswordPrompter, UXContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import (
    TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448,
)
from pyhanko_testing_commons.test_utils.live_http import live_pki_services


def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


class Prompter(PasswordPrompter):
    def __init__(self, password):
        self.password = password

    def prompt_for_password(self, prompt):
        return self.password


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["cli", "verify"])
parser.add_argument("architecture", choices=["rsa", "ecdsa", "ed25519", "ed448"])
parser.add_argument("--password", default="ownersecret")
parser.add_argument("--root")
parser.add_argument("--output")
parser.add_argument("--export-revinfo", type=Path)
parser.add_argument("argv", nargs=argparse.REMAINDER)
args = parser.parse_args()
assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
assert Path(pyhanko.cli.__file__).resolve().is_relative_to(
    Path("/tmp/pyhanko-oracle/src/v0.38.1")
)
architectures = {"rsa": TESTING_CA, "ecdsa": TESTING_CA_ECDSA,
                 "ed25519": TESTING_CA_ED25519, "ed448": TESTING_CA_ED448}
moment = datetime(2020, 8, 1, tzinfo=tzlocal.get_localzone())
record = {"mode": args.mode, "architecture": args.architecture,
          "python": snapshot(sys.executable), "driver": snapshot(__file__),
          "python_invocation": sys.executable,
          "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"),
          "cli_module": snapshot(pyhanko.cli.__file__),
          "pyhanko": importlib.metadata.version("pyhanko"),
          "certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
          "optimize": sys.flags.optimize, "cwd": str(Path.cwd()),
          "moment": moment.isoformat()}
with freeze_time(moment):
    if args.mode == "cli":
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        result = CliRunner().invoke(
            cli_root, argv,
            obj=CLIContext(ux=UXContext(prompter=Prompter(args.password))),
        )
        record.update(argv=argv, code=result.exit_code, output=result.output,
                      exception=None if result.exception is None else
                      {"type": type(result.exception).__name__,
                       "message": str(result.exception)})
    else:
        root_data = Path(args.root).read_bytes()
        if pem.detect(root_data):
            root_data = pem.unarmor(root_data)[2]
        root = x509.Certificate.load(root_data)
        with live_pki_services() as services:
            arch = architectures[args.architecture]
            services.register(arch)
            with Path(args.output).open("rb") as stream:
                reader = PdfFileReader(stream)
                assert reader.encrypted
                assert reader.decrypt("ownersecret").status.name == "OWNER"
                signatures = reader.embedded_regular_signatures
                assert len(signatures) == 1
                status = validate_pdf_signature(
                    signatures[0], signer_validation_context=ValidationContext(
                        trust_roots=[root], allow_fetching=True,
                    ),
                )
                assert status.bottom_line, status.pretty_print_details()
                assert status.intact and status.valid and status.trusted
                record.update(output=snapshot(args.output), root=snapshot(args.root),
                              intact=status.intact, valid=status.valid,
                              trusted=status.trusted, bottom_line=status.bottom_line)
            args.export_revinfo.mkdir()
            evidence = []
            for index, repository in enumerate(arch.service_registry.list_crl_repos()):
                crl = arch.service_registry.get_crl(repository.label, at_time=moment)
                encoded = crl.dump()
                name = f"crl-{index}.der"
                with (args.export_revinfo / name).open("xb") as target:
                    target.write(encoded)
                evidence.append({"path": name, "length": len(encoded),
                                 "sha256": hashlib.sha256(encoded).hexdigest()})
            assert evidence
            metadata = {"provider": "explicit signed Certomancer fixture CRLs; not native HTTP",
                        "moment": moment.isoformat(), "architecture": args.architecture,
                        "output_sha256": record["output"]["sha256"],
                        "root_sha256": record["root"]["sha256"], "crls": evidence}
            with (args.export_revinfo / "metadata.json").open("x") as target:
                json.dump(metadata, target, indent=2)
                target.write("\n")
print(json.dumps(record))
