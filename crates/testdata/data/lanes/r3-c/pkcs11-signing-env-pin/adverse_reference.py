"""Fresh zero-ID probes for BOTH configured certificate sources.

These probes do not alter or stand in for the unchanged five-item original.
Actual outcomes are recorded before a native error expectation is chosen.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys

from asn1crypto import x509
from click.testing import CliRunner
from freezegun import freeze_time
import yaml
from pyhanko.cli import cli_root
from pyhanko_testing_commons.test_data.samples import MINIMAL
from validate_outputs import validate_one


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), length=len(raw), sha256=digest(raw))


def main():
    assert __debug__ and sys.flags.optimize == 0
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).resolve().parent
    provider = destination / "provider"
    assert provider.is_dir() and Path(os.environ["SOFTHSM2_CONF"]).resolve() == provider / "softhsm2.conf"
    module = Path(os.environ["PKCS11_TEST_MODULE"]).resolve()
    root = x509.Certificate.load((fixture / "root.der").read_bytes())
    intermediate = x509.Certificate.load((fixture / "interm.der").read_bytes())
    leaf = x509.Certificate.load((fixture / "signer1.der").read_bytes())
    hp11 = importlib.import_module("pyhanko.sign.pkcs11")
    cfg = importlib.import_module("pyhanko.config.pkcs11")
    actual_open = hp11.open_pkcs11_session
    actual_load = cfg.load_certs_from_pemder
    actual_sign = hp11.PKCS11Signer.async_sign_raw
    events = []
    def observed_open(*args, **kwargs):
        events.append(dict(entry="open_pkcs11_session", module=str(args[0]), authenticated=kwargs.get("user_pin") is not None))
        return actual_open(*args, **kwargs)
    def observed_load(paths):
        names = tuple(paths)
        events.append(dict(entry="file_certificate_load", files=[identity(name) if Path(name).exists() else dict(path=str(Path(name).resolve()), exists=False) for name in names]))
        yield from actual_load(names)
    async def observed_sign(signer, data, digest_algorithm, dry_run=False):
        events.append(dict(entry="async_sign_raw", dry_run=dry_run, input_length=len(data), input_sha256=digest(data), digest_algorithm=digest_algorithm))
        result = await actual_sign(signer, data, digest_algorithm, dry_run=dry_run)
        events.append(dict(entry="async_sign_raw.return", dry_run=dry_run, length=len(result), sha256=digest(result)))
        return result
    hp11.open_pkcs11_session = observed_open
    cfg.load_certs_from_pemder = observed_load
    hp11.PKCS11Signer.async_sign_raw = observed_sign
    rows = []
    native_now = datetime.now(timezone.utc)
    try:
        for label, pull, file in [("missing-pull-valid-file", "absent-certificate-label", "interm.crt"),
                                  ("missing-file-valid-token", "interm", "absent-intermediate.crt")]:
            case = destination / label
            case.mkdir(exist_ok=False)
            runner = CliRunner(env={"PYHANKO_PKCS11_PIN": "1234"})
            with runner.isolated_filesystem():
                Path("input.pdf").write_bytes(MINIMAL)
                Path("interm.crt").write_bytes(intermediate.dump())
                configured = {"pkcs11-setups": {"test": {"module-path": str(module), "token-criteria": {"label": "tested25519"},
                    "cert-label": "signer1", "key-label": None, "other-certs-to-pull": pull, "other-certs": file}}}
                Path("pyhanko.yml").write_text(yaml.safe_dump(configured))
                for name in ["input.pdf", "interm.crt", "pyhanko.yml"]:
                    (case / ("before-" + name)).write_bytes(Path(name).read_bytes())
                start = len(events)
                args = ["sign", "addsig", "--field", "Sig1", "pkcs11", "--p11-setup", "test", "input.pdf", "output.pdf"]
                with freeze_time("2020-11-01"):
                    result = runner.invoke(cli_root, args)
                after = {}
                for name in ["input.pdf", "interm.crt", "pyhanko.yml", "output.pdf"]:
                    if Path(name).exists():
                        raw = Path(name).read_bytes()
                        (case / ("after-" + name)).write_bytes(raw)
                        after[name] = dict(length=len(raw), sha256=digest(raw))
                    else:
                        after[name] = None
                assert after["input.pdf"]["sha256"] == digest(MINIMAL)
                assert after["pyhanko.yml"]["sha256"] == digest((case / "before-pyhanko.yml").read_bytes())
                statuses = []
                if after["output.pdf"] is not None and after["output.pdf"]["length"]:
                    raw = Path("output.pdf").read_bytes()
                    for moment in [datetime(2020, 11, 1, tzinfo=timezone.utc), native_now]:
                        for has_root in [True, False]:
                            statuses.append(dict(moment=moment.isoformat(), explicit_root=has_root,
                                status=validate_one(raw, moment, [root] if has_root else [], leaf, intermediate, False)))
                row = dict(label=label, arguments=args, exit_code=result.exit_code, exception_type=None if result.exception is None else type(result.exception).__name__,
                           stdout=result.stdout, stderr=result.stderr, output=result.output, actual_events=events[start:], after=after,
                           statuses=statuses, expected_error_assumed=False)
                (case / "receipt.json").write_text(json.dumps(row, indent=2) + "\n")
                rows.append(row)
    finally:
        hp11.open_pkcs11_session = actual_open
        cfg.load_certs_from_pemder = actual_load
        hp11.PKCS11Signer.async_sign_raw = actual_sign
    record = dict(kind="Fresh two adverse actual CliRunner probes; zero immutable original IDs", host=platform.node(),
                  interpreter=identity(sys.executable), python=sys.version, assertions_enabled=__debug__,
                  packages={name:importlib.metadata.version(name) for name in ["pyhanko", "pyhanko-certvalidator", "python-pkcs11"]},
                  clock_scope=dict(body="2020-11-01", separate_actual_NOW=native_now.isoformat()),
                  module=identity(module), configuration=identity(provider / "softhsm2.conf"), cases=rows,
                  note="No error expectation is inferred from a missing duplicate source; actual result is authoritative")
    (destination / "record.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(dict(record=str(destination / "record.json"), sha256=identity(destination / "record.json")["sha256"], outcomes=[dict(label=row["label"], exit_code=row["exit_code"], output=row["after"]["output.pdf"]) for row in rows])))


if __name__ == "__main__":
    main()
