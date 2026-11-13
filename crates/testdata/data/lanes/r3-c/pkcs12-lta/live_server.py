"""Current-time loopback Certomancer services for actual CLI LTA commands.

Adapted from the reviewed root live fixture. No existing listener or service is
modified. Every certificate URL uses this process's actual ephemeral listener.
The owner must stop only this process after its test completes.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import signal
import socket
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
import certomancer
from aiohttp import web
from asn1crypto import pem
from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist
from certomancer.registry import (
    ArchLabel, CertLabel, CertomancerConfig, CertomancerObjectNotFoundError,
)


ARCHITECTURES = {
    "rsa": ("testing-ca", "keys-rsa"),
    "ecdsa": ("testing-ca-ecdsa", "keys-ecdsa"),
    "ed25519": ("testing-ca-ed25519", "keys-ed25519"),
}


def file_record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def certificate_record(cert):
    data = cert.dump()
    validity = cert["tbs_certificate"]["validity"]
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "not_before": validity["not_before"].native.isoformat(),
            "not_after": validity["not_after"].native.isoformat()}


async def serve(args):
    assert importlib.metadata.version("pyhanko") == "0.38.1"
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    started = datetime.now(timezone.utc)
    # These existing pinned certificates expire in 2030. Never waive expiry.
    assert datetime(2020, 1, 1, tzinfo=timezone.utc) <= started
    assert started < datetime(2030, 1, 1, tzinfo=timezone.utc)
    crypto = Path(args.crypto).resolve()
    artifacts = Path(args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    sock.setblocking(False)
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    architecture, key_directory = ARCHITECTURES[args.architecture]
    config = CertomancerConfig.from_file(
        str(crypto / "certomancer.yml"), key_search_dir=str(crypto),
        external_url_prefix=url,
    )
    arch = config.get_pki_arch(ArchLabel(architecture))
    certificates = {
        label: arch.get_cert(CertLabel(label))
        for label in ["root", "interm", "signer1-long", "tsa"]
    }
    for cert in certificates.values():
        validity = cert["tbs_certificate"]["validity"]
        assert validity["not_before"].native <= started
        assert started < validity["not_after"].native
    (artifacts / "credential.p12").write_bytes(
        arch.package_pkcs12(CertLabel("signer1-long"), password=b"secret")
    )
    for label, cert in certificates.items():
        (artifacts / f"{label}.der").write_bytes(cert.dump())

    # None is the library's real current-clock mode. No process clock override,
    # modified validity interval or preloaded OCSP/CRL is used.
    app = AsyncIllusionist(arch, at_time=None).build_app()
    requests = Counter()

    def record(request, status):
        key = (request.method, request.path, status)
        if key in requests or len(requests) < 256:
            requests[key] += 1

    @web.middleware
    async def count_requests(request, handler):
        if request.path == "/_sigis/requests":
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
        return web.json_response({"requests": [
            {"method": method, "path": path, "status": status, "count": count}
            for (method, path, status), count in sorted(requests.items())
        ]})

    app.router.add_get("/_sigis/requests", request_counts)

    async def certificate(request):
        label = request.match_info["label"]
        if label not in certificates:
            raise web.HTTPNotFound()
        try:
            cert = arch.get_cert(CertLabel(label))
        except (KeyError, CertomancerObjectNotFoundError):
            raise web.HTTPNotFound()
        return web.Response(body=cert.dump(), content_type="application/pkix-cert")

    app.router.add_get(
        f"/_certomancer/any-cert/{architecture}/{{label}}.crt", certificate
    )

    async def pfx_download(request):
        form = await request.post()
        if form.get("cert") != "signer1-long":
            raise web.HTTPNotFound()
        password = form.get("passphrase", "")
        if not isinstance(password, str):
            raise web.HTTPBadRequest(reason="Passphrase must be a string")
        data = arch.package_pkcs12(
            CertLabel("signer1-long"), password=password.encode("utf8") or None
        )
        return web.Response(body=data, content_type="application/x-pkcs12")

    app.router.add_post(
        f"/_certomancer/pfx-download/{architecture}", pfx_download
    )

    def repository_certificate(label, use_pem):
        async def serve_certificate(request):
            cert = arch.service_registry.get_cert_from_repo(label)
            if cert is None:
                raise web.HTTPNotFound()
            data = cert.dump()
            if use_pem:
                data = pem.armor("CERTIFICATE", data)
            return web.Response(
                body=data,
                content_type=("application/x-pem-file" if use_pem
                              else "application/pkix-cert"),
            )
        return serve_certificate

    # The issuer DER and PEM routes are distinct. Do not serve a PEM envelope at
    # the DER AIA URL, or silently relax the native strict fetcher's DER contract.
    for repository in arch.service_registry.list_cert_repos():
        for use_pem in (False, True):
            path = urlsplit(repository.issuer_cert_url(use_pem=use_pem)).path
            app.router.add_get(
                path, repository_certificate(repository.label, use_pem)
            )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.SockSite(runner, sock).start()
    ready = {
        "kind": "current live test-owned Certomancer loopback server",
        "url": url, "architecture": args.architecture,
        "architecture_label": architecture, "clock": "current UTC",
        "started_utc": started.isoformat(),
        "pyhanko": importlib.metadata.version("pyhanko"),
        "certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
        "certomancer": importlib.metadata.version("certomancer"),
        "sys_executable": sys.executable, "python": file_record(sys.executable), "driver": file_record(__file__),
        "certomancer_module": file_record(certomancer.__file__),
        "aiohttp_module": file_record(aiohttp.__file__),
        "configuration": file_record(crypto / "certomancer.yml"),
        "key_files": [file_record(path) for path in
                      sorted((crypto / key_directory).glob("*.pem"))],
        "certificates": {label: certificate_record(cert)
                         for label, cert in certificates.items()},
        "exported_pfx": file_record(artifacts / "credential.p12"),
        "exported_root": file_record(artifacts / "root.der"),
        "root_url": f"{url}/_certomancer/any-cert/{architecture}/root.crt",
        "pfx_url": f"{url}/_certomancer/pfx-download/{architecture}",
        "tsa_url": f"{url}/{architecture}/tsa/tsa",
        "metrics_url": f"{url}/_sigis/requests",
        "fixture_adaptation": "Existing signer1-long, not modified signer1 validity",
        "new_unique_credit": 0,
    }
    (artifacts / "server-ready.json").write_text(json.dumps(ready, indent=2) + "\n")
    print(json.dumps(ready), flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await runner.cleanup()
        (artifacts / "server-final-metrics.json").write_text(json.dumps({
            "requests": [
                {"method": method, "path": path, "status": status, "count": count}
                for (method, path, status), count in sorted(requests.items())
            ], "stopped_utc": datetime.now(timezone.utc).isoformat(),
        }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crypto", required=True)
    parser.add_argument("--architecture", choices=ARCHITECTURES, required=True)
    parser.add_argument("--artifacts", required=True)
    asyncio.run(serve(parser.parse_args()))


if __name__ == "__main__":
    main()
