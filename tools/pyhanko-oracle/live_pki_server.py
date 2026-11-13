"""Serve pinned Certomancer PKI over actual loopback HTTP for Rust tests.

The process binds only 127.0.0.1:0, prints one readiness JSON record, and
never connects to an external host. The caller owns its lifetime. Service
URLs in freshly generated certificates use this actual ephemeral port.
"""

import argparse
import asyncio
import importlib.metadata
import json
import socket
from collections import Counter
from datetime import datetime
from urllib.parse import urlsplit
from pathlib import Path

from aiohttp import web
from asn1crypto import pem
from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist
from certomancer.registry import (
    ArchLabel, CertLabel, CertomancerConfig, CertomancerObjectNotFoundError,
)


async def serve(args):
    assert importlib.metadata.version('pyHanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
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
    fixed = None if args.time == 'now' else datetime.fromisoformat(args.time.replace('Z', '+00:00'))
    app = AsyncIllusionist(arch, at_time=fixed).build_app()

    # Bound diagnostic cardinality. Do not record form bodies or passphrases.
    requests = Counter()

    def record(request, status):
        key = (request.method, request.path, status)
        if key in requests or len(requests) < 256:
            requests[key] += 1

    @web.middleware
    async def count_requests(request, handler):
        if request.path == '/_sigis/requests':
            return await handler(request)
        try:
            response = await handler(request)
        except web.HTTPException as error:
            record(request, error.status)
            raise
        except Exception:
            record(request, 500)
            raise
        record(request, response.status)
        return response

    app.middlewares.append(count_requests)

    async def request_counts(request):
        return web.json_response({'requests': [
            {'method': method, 'path': path, 'status': status, 'count': count}
            for (method, path, status), count in sorted(requests.items())
        ]})

    app.router.add_get('/_sigis/requests', request_counts)

    async def certificate(request):
        label = request.match_info['label']
        try:
            cert = arch.get_cert(CertLabel(label))
        except (KeyError, CertomancerObjectNotFoundError):
            raise web.HTTPNotFound()
        return web.Response(body=cert.dump(), content_type='application/pkix-cert')

    app.router.add_get('/_certomancer/any-cert/testing-ca/{label}.crt', certificate)

    async def pfx_download(request):
        form = await request.post()
        label = form.get('cert')
        if not isinstance(label, str) or not label:
            raise web.HTTPBadRequest(reason='A certificate label is required')
        # Only this synthetic credential is needed by the live integrations.
        if label != 'signer1-long':
            raise web.HTTPNotFound()
        password = form.get('passphrase', '')
        if not isinstance(password, str):
            raise web.HTTPBadRequest(reason='Passphrase must be a string')
        data = arch.package_pkcs12(
            CertLabel(label), password=password.encode('utf8') or None
        )
        return web.Response(body=data, content_type='application/x-pkcs12')

    app.router.add_post('/_certomancer/pfx-download/testing-ca', pfx_download)

    def repository_certificate(label, use_pem):
        async def serve_certificate(request):
            cert = arch.service_registry.get_cert_from_repo(label)
            if cert is None:
                raise web.HTTPNotFound()
            data = cert.dump()
            if use_pem:
                data = pem.armor('certificate', data)
            return web.Response(
                body=data,
                content_type='application/x-pem-file' if use_pem else 'application/pkix-cert',
            )
        return serve_certificate

    # Certomancer's AIA links point to the DER authority route. Keep PEM as a
    # separate explicit route, preserving strict fetchers' encoding boundary.
    for repo in arch.service_registry.list_cert_repos():
        for use_pem in (False, True):
            path = urlsplit(repo.issuer_cert_url(use_pem=use_pem)).path
            app.router.add_get(path, repository_certificate(repo.label, use_pem))
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
