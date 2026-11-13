# The original upstream function is loaded unchanged and actually executed.
"""Independent pinned Python CLI baseline, with its own isolated live sidecar.

Acceptance requires an actual completed execution receipt; source alone earns no credit. It never
validates native output or substitutes a saved verdict. No package is installed.
"""
import argparse
import dis
from hashlib import sha256
import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import traceback

P_EXPECTED = '364fd4b8095c5c4b2f1bdce2ad6c0fa43923c80e88f1aebe19187269d840892e'
parser = argparse.ArgumentParser()
parser.add_argument('--server-script', required=True)
parser.add_argument('--crypto', required=True)
parser.add_argument('--artifacts', required=True)
parser.add_argument('--upstream', default='/tmp/pyhanko-oracle/src/pyHanko/internal/integration-tests/tests/test_live_certomancer.py')
parser.add_argument('--cli-source-root', default='/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
parser.add_argument('--dependency-overlay')
args = parser.parse_args()
out = Path(args.artifacts).resolve()
out.mkdir(parents=True, exist_ok=False)
sha = lambda p: sha256(Path(p).read_bytes()).hexdigest()
upstream = Path(args.upstream).resolve()
assert sha(upstream) == P_EXPECTED
receipt = {'kind': 'fresh ORIGINAL pinned Python CLI source execution; not a native-output validation',
           'upstream': str(upstream), 'upstream_sha256_before': sha(upstream),
           'function': 'test_pades_lta_live_with_cli', 'unique_function_credit': 0,
           'whole_upstream_function_completed': False, 'actual_invocations': [],
           'original_LTA_statuses': [], 'original_DSS_counts': []}
# Optional previously provisioned dependencies are explicit, isolated and
# recorded. Never install into or modify the oracle environment here.
if args.dependency_overlay:
    overlay = Path(args.dependency_overlay).resolve()
    assert overlay.is_dir()
    sys.path.insert(0, str(overlay))
    receipt['explicit_dependency_overlay'] = str(overlay)
server = None
previous_env = os.environ.get('LIVE_CERTOMANCER_HOST_URL')
previous_profile = sys.getprofile()
exit_code = 1
try:
    assert version('pyhanko') == '0.38.1'
    assert version('pyhanko-certvalidator') == '0.33.0'
    import pyhanko
    import pyhanko.sign
    pyhanko.__path__.append(str(Path(args.cli_source_root).resolve()))
    from pyhanko.cli import cli_root
    import pyhanko.cli
    cli_file = Path(pyhanko.cli.__file__).resolve()
    assert cli_file.is_relative_to(Path(args.cli_source_root).resolve())
    receipt.update({'pyhanko': version('pyhanko'), 'certvalidator': version('pyhanko-certvalidator'),
                    'cli_module': str(cli_file), 'cli_module_sha256': sha(cli_file),
                    'core_module': str(Path(pyhanko.sign.__file__).resolve()),
                    'core_module_name': 'pyhanko.sign',
                    'core_module_sha256': sha(pyhanko.sign.__file__)})
    with (out / 'sidecar.stderr.log').open('w') as stderr:
        server = subprocess.Popen([sys.executable, args.server_script, '--crypto', args.crypto,
                                   '--time', 'now'], stdout=subprocess.PIPE, stderr=stderr, text=True)
        ready = queue.Queue()
        def read_ready():
            ready.put(server.stdout.readline())
        threading.Thread(target=read_ready, daemon=True).start()
        started = json.loads(ready.get(timeout=30))
        assert started['url'].startswith('http://127.0.0.1:') and started['time'] == 'now'
        receipt['owned_sidecar'] = {'pid': server.pid, 'readiness': started,
                                   'script_sha256': sha(args.server_script)}
        os.environ['LIVE_CERTOMANCER_HOST_URL'] = started['url']
        spec = importlib.util.spec_from_file_location('sigis_original_live_cli_reference', upstream)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.CERTOMANCER_HOST_URL == started['url'] and module.SKIP_LIVE is False
        expected_argv = ['sign','addsig','--with-validation-info','--use-pades-lta',
                         '--timestamp-url', started['url'] + '/testing-ca/tsa/tsa',
                         'pkcs12','--p12-setup','test','in.pdf','out.pdf','credential.p12']
        pending = {}
        def observe(frame, event, result):
            # Python profiles coroutine suspension as a return as well.
            # Observe only its actual bytecode return, not an await yield.
            actual_return = event == 'return' and dis.opname[frame.f_code.co_code[frame.f_lasti]] in {'RETURN_VALUE', 'RETURN_CONST'}
            if actual_return and frame.f_code.co_filename == str(upstream):
                if frame.f_code.co_name == '_check_pades_result' and 'status' in frame.f_locals:
                    status = frame.f_locals['status']
                    ades = frame.f_locals['ades_status']
                    receipt['original_LTA_statuses'].append({
                        'valid': status.valid, 'trusted': status.trusted,
                        'modification_level': status.modification_level.name,
                        'ades_subindic': ades.ades_subindic.standard_name})
                if frame.f_code.co_name == '_check' and 'dss' in frame.f_locals:
                    dss = frame.f_locals['dss']
                    receipt['original_DSS_counts'].append({'crls': len(dss.crls), 'ocsps': len(dss.ocsps)})
            # Passive observation of the ORIGINAL CliRunner call, not a
            # replacement for CliRunner, cli_root, its signer or checker.
            if frame.f_code.co_name != 'invoke' or not frame.f_code.co_filename.endswith('/click/testing.py'):
                return
            caller = frame.f_back
            if caller is None or caller.f_code.co_filename != str(upstream) or caller.f_code.co_name != receipt['function']:
                return
            if event == 'call':
                argv = list(frame.f_locals['args'])
                assert argv == expected_argv
                inputs = {}
                for name in ['in.pdf','credential.p12','root.crt','pyhanko.yml']:
                    data = Path(name).read_bytes()
                    inputs[name] = {'length': len(data), 'sha256': sha256(data).hexdigest()}
                pending[id(frame)] = {'argv': argv, 'cwd': str(Path.cwd()), 'inputs': inputs}
            elif event == 'return':
                row = pending.pop(id(frame))
                row.update({'exit_code': result.exit_code, 'output': result.output,
                            'exception': None if result.exception is None else type(result.exception).__name__})
                for name in ['out.pdf','root.crt']:
                    if Path(name).is_file():
                        data = Path(name).read_bytes()
                        (out / name).write_bytes(data)
                        row[name] = {'length': len(data), 'sha256': sha256(data).hexdigest()}
                receipt['actual_invocations'].append(row)
        sys.setprofile(observe)
        # This executes the unchanged complete original body, including its
        # fresh PFX/config/download flows, exact argv and ALL nested assertions.
        module.test_pades_lta_live_with_cli()
        sys.setprofile(previous_profile)
        assert len(receipt['actual_invocations']) == 1 and not pending
        assert receipt['actual_invocations'][0]['exit_code'] == 0
        assert len(receipt['original_LTA_statuses']) == 1
        assert receipt['original_LTA_statuses'][0]['valid'] and receipt['original_LTA_statuses'][0]['trusted']
        assert receipt['original_LTA_statuses'][0]['modification_level'] == 'LTA_UPDATES'
        assert receipt['original_DSS_counts'] == [{'crls': 1, 'ocsps': 1}]
        receipt['whole_upstream_function_completed'] = True
        receipt['exception'] = None
        exit_code = 0
except Exception as error:
    receipt['exception'] = {'class': type(error).__name__, 'message': str(error),
                            'traceback': traceback.format_exc()}
finally:
    sys.setprofile(previous_profile)
    if previous_env is None:
        os.environ.pop('LIVE_CERTOMANCER_HOST_URL', None)
    else:
        os.environ['LIVE_CERTOMANCER_HOST_URL'] = previous_env
    if server is not None:
        # Only this script's actual child is stopped. No process-name or
        # unrelated-service/session operation is performed.
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)
    receipt['upstream_sha256_after'] = sha(upstream)
    if receipt['upstream_sha256_after'] != receipt['upstream_sha256_before']:
        receipt['whole_upstream_function_completed'] = False
        exit_code = 1
    receipt['reference_helper_sha256'] = sha(__file__)
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
raise SystemExit(exit_code)
