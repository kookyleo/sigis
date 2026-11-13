"""Execute a fresh pinned CLI invocation with upstream's password prompter."""
import sys
import logging
import hashlib
import importlib.metadata
import json
from pathlib import Path
from _pytest.logging import LogCaptureHandler
# Reproduce the upstream pytest log-capture formatter order, including exc_text.
logging.getLogger().addHandler(LogCaptureHandler())
from contextlib import ExitStack
from datetime import datetime, timezone
from click.testing import CliRunner
from freezegun import freeze_time
import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
from pyhanko.cli import cli_root
import pyhanko.cli
import pyhanko_certvalidator
from pyhanko.cli._ctx import CLIContext, UXContext, PasswordPrompter
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
from pyhanko_testing_commons.test_data.samples import TESTING_CA,TESTING_CA_ECDSA,TESTING_CA_ED25519,TESTING_CA_ED448
password=sys.argv[1].rstrip('\r\n');architecture=sys.argv[2];args=sys.argv[3:]
assert importlib.metadata.version('pyhanko') == '0.38.1'
assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
assert Path(pyhanko.cli.__file__).resolve().is_relative_to(Path('/tmp/pyhanko-oracle/src/v0.38.1'))
def file_record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
class Prompter(PasswordPrompter):
    def prompt_for_password(self,prompt):return password
with freeze_time(datetime(2020,8,1,tzinfo=timezone.utc)):
    with ExitStack() as stack:
        if '--with-validation-info' in args or args[:2]==['sign','timestamp']:
            services=stack.enter_context(live_pki_services())
            services.register({'rsa':TESTING_CA,'ecdsa':TESTING_CA_ECDSA,'ed25519':TESTING_CA_ED25519,'ed448':TESTING_CA_ED448}[architecture])
        result=CliRunner().invoke(cli_root,args,obj=CLIContext(ux=UXContext(prompter=Prompter())))
        print('SIGNING_ORACLE_CLI ' + json.dumps({
            'python': file_record(sys.executable), 'driver': file_record(__file__),
            'cli_module': file_record(pyhanko.cli.__file__),
            'validator_module': file_record(pyhanko_certvalidator.__file__),
            'pyhanko_version': importlib.metadata.version('pyhanko'),
            'certvalidator_version': importlib.metadata.version('pyhanko-certvalidator'),
            'cwd': str(Path.cwd()), 'argv': args, 'architecture': architecture,
            'moment': datetime.now(timezone.utc).isoformat(),
            'code': result.exit_code, 'output': result.output,
            'exception': None if result.exception is None else type(result.exception).__name__,
        }), file=sys.stderr)
        print(result.exit_code);print(result.output,end='')
