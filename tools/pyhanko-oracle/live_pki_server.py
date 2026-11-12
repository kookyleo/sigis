"""Serve pinned Certomancer PKI over actual loopback HTTP for Rust tests.

The process binds only 127.0.0.1:0, prints one readiness JSON record, and
never connects to an external host. The caller owns its lifetime. Service
URLs in freshly generated certificates use this actual ephemeral port.
"""

import argparse
import asyncio
import json
import socket
from datetime import datetime
from pathlib import Path

from aiohttp import web
from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist
from certomancer.registry import ArchLabel, CertLabel, CertomancerConfig


async def serve(args):
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
    fixed = datetime.fromisoformat(args.time.replace('Z', '+00:00'))
    app = AsyncIllusionist(arch, at_time=fixed).build_app()

    async def certificate(request):
        label = request.match_info['label']
        try:
            cert = arch.get_cert(CertLabel(label))
        except KeyError:
            raise web.HTTPNotFound()
        return web.Response(body=cert.dump(), content_type='application/pkix-cert')

    app.router.add_get('/_certomancer/any-cert/testing-ca/{label}.crt', certificate)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.SockSite(runner, sock).start()
    print(json.dumps({'url': url, 'time': args.time, 'architectures': ['testing-ca']}), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--crypto', required=True)
    parser.add_argument('--time', required=True)
    asyncio.run(serve(parser.parse_args()))


if __name__ == '__main__':
    main()
