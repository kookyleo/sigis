"""Run fresh CLI validation cases against pyHanko 0.38.1 native HTTP doubles."""
import json
import sys
import hashlib
import importlib.metadata
from pathlib import Path

sys.path.insert(0, '/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli')
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')

from click.testing import CliRunner
from freezegun import freeze_time
from pyhanko.cli import cli_root
from pyhanko.cli._ctx import CLIContext, UXContext, PasswordPrompter
from pyhanko_testing_commons.test_data.samples import (
    TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448,
)
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
# Exact upstream test double; avoid importing an optional tests namespace.
class DummyPrompter(PasswordPrompter):
    def __init__(self, password):
        self.password = password

    def prompt_for_password(self, prompt: str) -> str:
        return self.password


architectures = dict(rsa=TESTING_CA, ecdsa=TESTING_CA_ECDSA,
                     ed25519=TESTING_CA_ED25519, ed448=TESTING_CA_ED448)
results = []
for case in json.load(sys.stdin):
    with freeze_time(case['now']):
        with live_pki_services() as services:
            if case['mocks']:
                services.register(architectures[case['arch']])
            input_path=Path(case['args'][-1]).resolve()
            input_bytes=input_path.read_bytes()
            result = CliRunner().invoke(
                cli_root, case['args'],
                obj=CLIContext(ux=UXContext(prompter=DummyPrompter(case['password'] or ''))),
            )
            if result.exit_code == 0:
                assert result.exception is None, (result.exception, result.output)
            results.append(dict(code=result.exit_code, stdout=result.stdout,
                                output=result.output,
                                exception_type=type(result.exception).__name__ if result.exception is not None else None,
                                python=sys.executable,
                                pyhanko_version=importlib.metadata.version('pyHanko'),
                                certvalidator_version=importlib.metadata.version('pyhanko-certvalidator'),
                                cli_module=sys.modules['pyhanko.cli'].__file__,
                                script=str(Path(__file__).resolve()),
                                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                input_path=str(input_path),
                                input_sha256=hashlib.sha256(input_bytes).hexdigest(),
                                input_length=len(input_bytes),
                                argv=case['args'],now=case['now'],mocks=case['mocks']))
json.dump(results, sys.stdout)
