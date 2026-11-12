"""Run pinned CSCWithCertomancer on loopback; test keys only, no public listener."""

import argparse
import asyncio
import importlib.metadata
import json
import os
import socket
import sys
from pathlib import Path

# Keep optional CSC dependencies isolated from the shared oracle environment.
DEPS = Path(os.environ.get(
    'HANKO_CSC_ORACLE_DEPS',
    '/home/l/.codex/artifacts/sigis/round3/l-csc/oracle-deps',
))
if DEPS.is_dir():
    sys.path.insert(0, str(DEPS))
# Normal installed packages are also supported; exact versions below are required.

from aiohttp import web
from certomancer.registry import ArchLabel, CertLabel, CertomancerConfig
from csc_dummy.csc_dummy_server import CSCWithCertomancer, DummyServiceParams


async def serve(args):
    assert importlib.metadata.version('pyHanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    assert importlib.metadata.version('certomancer-csc-dummy') == '0.4.2'
    assert importlib.metadata.version('python-pae') == '0.1.0'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    sock.listen(128)
    sock.setblocking(False)
    url = f'http://127.0.0.1:{sock.getsockname()[1]}'
    cfg = CertomancerConfig.from_file(
        str(Path(args.crypto) / 'certomancer.yml'),
        key_search_dir=args.crypto,
        external_url_prefix=url,
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    service = CSCWithCertomancer(
        cfg, service_params=DummyServiceParams(hash_pinning_required=True)
    )
    service.register_routes()
    runner = web.AppRunner(service.app, access_log=None)
    await runner.setup()
    await web.SockSite(runner, sock).start()
    print(json.dumps({
        'url': url, 'root_der': arch.get_cert(CertLabel('root')).dump().hex(),
        'csc_version': '0.4.2', 'pae_version': '0.1.0',
    }), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--crypto', required=True)
    asyncio.run(serve(parser.parse_args()))
