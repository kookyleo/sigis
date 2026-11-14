"""One fresh zero-ID prompted CLI probe per already-provisioned private store.

Never run two credential probes in this process: a shared successful token login
can mask a wrong USER PIN. This source does not alter the unchanged originals.
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

# The launcher clears these before any project/provider import.
PIN_NAMES = ("PYHANKO_PKCS11_PIN", "PYHANKO_PKCS11_SIGNING_PIN")
INITIAL_PIN_ENVIRONMENT = {name: name in os.environ for name in PIN_NAMES}
assert not any(INITIAL_PIN_ENVIRONMENT.values())

from asn1crypto import x509
from click.testing import CliRunner
from freezegun import freeze_time
import yaml
from pyhanko.cli import cli_root
from pyhanko.cli._ctx import CLIContext, PasswordPrompter, UXContext
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
    assert len(sys.argv) == 3
    destination = Path(sys.argv[1]).resolve()
    label = sys.argv[2]
    choices = {"missing-pull-valid-file", "missing-file-valid-token", "wrong-user-pin"}
    assert label in choices
    provider = destination / "provider"
    assert provider.is_dir() and Path(os.environ["SOFTHSM2_CONF"]).resolve() == provider / "softhsm2.conf"
    assert not any(name in os.environ for name in PIN_NAMES)
    fixture = Path(__file__).resolve().parent
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
        pin = kwargs.get("user_pin")
        events.append(dict(entry="open_pkcs11_session", module=str(args[0]),
                           authenticated=pin is not None, user_pin_sha256=digest(pin.encode()) if isinstance(pin, str) else None))
        try:
            result = actual_open(*args, **kwargs)
        except Exception as error:
            events.append(dict(entry="open_pkcs11_session.error", exception_type=type(error).__name__))
            raise
        events.append(dict(entry="open_pkcs11_session.return", actual_type=f"{type(result).__module__}.{type(result).__qualname__}"))
        return result

    def observed_load(paths):
        names = tuple(paths)
        events.append(dict(entry="file_certificate_load", files=[identity(name) if Path(name).exists() else dict(path=str(Path(name).resolve()), exists=False) for name in names]))
        for cert in actual_load(names):
            events.append(dict(entry="file_certificate_load.return", der_sha256=digest(cert.dump())))
            yield cert

    async def observed_sign(signer, data, digest_algorithm, dry_run=False):
        events.append(dict(entry="async_sign_raw", dry_run=dry_run, input_length=len(data), input_sha256=digest(data), digest_algorithm=digest_algorithm))
        result = await actual_sign(signer, data, digest_algorithm, dry_run=dry_run)
        events.append(dict(entry="async_sign_raw.return", dry_run=dry_run, length=len(result), sha256=digest(result)))
        return result

    class ProbePrompter(PasswordPrompter):
        def prompt_for_password(self, prompt):
            events.append(dict(entry="ProbePrompter.prompt_for_password", label=prompt,
                               result_present=True, result_sha256=digest(credential.encode())))
            return credential

    hp11.open_pkcs11_session = observed_open
    cfg.load_certs_from_pemder = observed_load
    hp11.PKCS11Signer.async_sign_raw = observed_sign
    credential = "not-the-token-user-pin" if label == "wrong-user-pin" else "1234"
    native_now = datetime.now(timezone.utc)
    pull = "absent-certificate-label" if label == "missing-pull-valid-file" else "interm"
    file = "absent-intermediate.crt" if label == "missing-file-valid-token" else "interm.crt"
    runner = CliRunner()
    try:
        with runner.isolated_filesystem():
            Path("input.pdf").write_bytes(MINIMAL)
            Path("interm.crt").write_bytes(intermediate.dump())
            configured = {"pkcs11-setups": {"test": {"module-path": str(module), "token-criteria": {"label": "tested25519"},
                "cert-label": "signer1", "key-label": None, "other-certs-to-pull": pull, "other-certs": file}}}
            Path("pyhanko.yml").write_text(yaml.safe_dump(configured))
            before = {name: identity(name) for name in ["input.pdf", "interm.crt", "pyhanko.yml"]}
            for name in before:
                (destination / ("before-" + name)).write_bytes(Path(name).read_bytes())
            assert not Path("output.pdf").exists()
            args = ["sign", "addsig", "--field", "Sig1", "pkcs11", "--p11-setup", "test", "input.pdf", "output.pdf"]
            with freeze_time("2020-11-01"):
                result = runner.invoke(cli_root, args, obj=CLIContext(ux=UXContext(prompter=ProbePrompter())))
            after = {}
            for name in ["input.pdf", "interm.crt", "pyhanko.yml", "output.pdf"]:
                if Path(name).exists():
                    raw = Path(name).read_bytes()
                    (destination / ("after-" + name)).write_bytes(raw)
                    after[name] = dict(length=len(raw), sha256=digest(raw))
                else:
                    after[name] = None
            for name in before:
                assert before[name]["sha256"] == after[name]["sha256"]
            # Record actual output publication, including any partial empty file.
            # No upstream failure expectation is guessed from duplicate sources.
            statuses = []
            if after["output.pdf"] is not None and after["output.pdf"]["length"]:
                raw = Path("output.pdf").read_bytes()
                for moment in [datetime(2020, 11, 1, tzinfo=timezone.utc), native_now]:
                    for has_root in [True, False]:
                        statuses.append(dict(moment=moment.isoformat(), explicit_root=has_root,
                            status=validate_one(raw, moment, [root] if has_root else [], leaf, intermediate, False)))
            assert "1234" not in result.output and credential not in result.output
            record = dict(kind="One fresh clean-store prompted adverse reference; zero original IDs", label=label,
                host=platform.node(), pid=os.getpid(), parent_pid=os.getppid(), interpreter=identity(sys.executable),
                python=sys.version, assertions_enabled=__debug__, production_PIN_environment_at_entry=INITIAL_PIN_ENVIRONMENT,
                packages={name: importlib.metadata.version(name) for name in ["pyhanko", "pyhanko-certvalidator", "python-pkcs11"]},
                module=identity(module), configuration=identity(provider / "softhsm2.conf"), provisioning_receipt=identity(provider / "receipt.json"),
                clock_scope=dict(body="2020-11-01", separate_actual_NOW=native_now.isoformat()), arguments=args,
                exit_code=result.exit_code, exception_type=None if result.exception is None else type(result.exception).__name__,
                stdout=result.stdout, stderr=result.stderr, output=result.output, before=before, after=after, statuses=statuses,
                actual_events=events, expected_error_assumed=False, native_C_Sign_call_count=None,
                note="One process/private store per probe; fixture credential is supplied only by the explicit probe prompter")
            (destination / "record.json").write_text(json.dumps(record, indent=2) + "\n")
    finally:
        hp11.open_pkcs11_session = actual_open
        cfg.load_certs_from_pemder = actual_load
        hp11.PKCS11Signer.async_sign_raw = actual_sign
    print(json.dumps(dict(record=str(destination / "record.json"), sha256=identity(destination / "record.json")["sha256"],
                          exit_code=record["exit_code"], output=record["after"]["output.pdf"])))


if __name__ == "__main__":
    main()
