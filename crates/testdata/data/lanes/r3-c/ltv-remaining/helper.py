"""Test-owned current-time services and original CLI LTV assertion peers.

No provenance artifacts. Original function bodies are compiled unchanged, with
current-time signer1-long credentials replacing their frozen-2020 signer fixture.
"""
import ast
import asyncio
from datetime import datetime, timezone
from io import BytesIO
import importlib.metadata
import os
from pathlib import Path
import shutil
import socket
import sys
from urllib.parse import urlsplit

assert __debug__ and sys.flags.optimize == 0
assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"

SOURCE = Path(__file__).resolve().parent / "upstream"


async def serve():
    from aiohttp import web
    from asn1crypto import pem
    from certomancer.registry import ArchLabel, CertLabel, CertomancerConfig
    from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist
    architecture, directory, crypto = sys.argv[2:]
    directory, crypto = Path(directory), Path(crypto)
    labels = {"rsa":"testing-ca", "ecdsa":"testing-ca-ecdsa", "ed25519":"testing-ca-ed25519"}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    sock.setblocking(False)
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    cfg = CertomancerConfig.from_file(str(crypto / "certomancer.yml"), key_search_dir=str(crypto), external_url_prefix=base)
    arch = cfg.get_pki_arch(ArchLabel(labels[architecture]))
    now = datetime.now(timezone.utc)
    for label in ["root", "interm", "signer1-long", "tsa"]:
        cert = arch.get_cert(CertLabel(label))
        validity = cert["tbs_certificate"]["validity"].native
        assert validity["not_before"] <= now < validity["not_after"]
    (directory / "credential.p12").write_bytes(arch.package_pkcs12(CertLabel("signer1-long"), password=b"secret"))
    (directory / "root.der").write_bytes(arch.get_cert(CertLabel("root")).dump())
    app = AsyncIllusionist(arch, at_time=None).build_app()

    def repository_route(label, use_pem):
        async def handler(request):
            cert = arch.service_registry.get_cert_from_repo(label)
            if cert is None:
                raise web.HTTPNotFound()
            raw = cert.dump()
            return web.Response(body=pem.armor("CERTIFICATE", raw) if use_pem else raw,
                                content_type="application/x-pem-file" if use_pem else "application/pkix-cert")
        return handler

    for repo in arch.service_registry.list_cert_repos():
        for use_pem in [False, True]:
            app.router.add_get(urlsplit(repo.issuer_cert_url(use_pem=use_pem)).path,
                               repository_route(repo.label, use_pem))
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.SockSite(runner, sock).start()
    url = f"{base}/{labels[architecture]}/tsa/tsa"
    (directory / "tsa-url.txt").write_text(url)
    print(url, flush=True)
    await asyncio.Event().wait()


def cli_imports():
    import pyhanko
    pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
    from pyhanko.cli import cli_root
    from click.testing import CliRunner
    return cli_root, CliRunner


def original_functions(filename, names, namespace):
    source = SOURCE / filename
    nodes = ast.parse(source.read_text()).body
    selected = []
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            node.decorator_list = []  # pytest parameter generation is performed by Rust.
            selected.append(node)
    assert {n.name for n in selected} == set(names)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)


def reference():
    import yaml
    from asn1crypto import pem
    from certomancer.registry import CertLabel
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.decode_limits import DecodeLimits
    from pyhanko_testing_commons.test_data.samples import TESTING_CA
    cli_root, CliRunner = cli_imports()
    root, kind, timestamp = Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4] == "yes"
    peer = root / "reference"
    peer.mkdir()
    shutil.copy(root / "input.pdf", peer / "input.pdf")
    if (root / "before-ltv.pdf").exists():
        shutil.copy(root / "before-ltv.pdf", peer / "output.pdf")
    os.chdir(peer)

    def write_config(cfg):
        Path("pyhanko.yml").write_text(yaml.safe_dump(cfg))

    def write_cert(arch, label, name):
        Path(name).write_bytes(pem.armor("CERTIFICATE", arch.get_cert(label).dump()))
        return name

    namespace = {"cli_root":cli_root, "INPUT_PATH":"input.pdf", "SIGNED_OUTPUT_PATH":"output.pdf", "OUTPUT_PATH":"out.pdf",
                 "DUMMY_PASSPHRASE":"secret", "PdfFileReader":PdfFileReader, "CertLabel":CertLabel,
                 "TESTING_CA":TESTING_CA, "_write_config":write_config, "_write_cert":write_cert,
                 "FLAG":"--no-decode-limits", "BytesIO":BytesIO, "DecodeLimits":DecodeLimits}
    original_functions("test_cli_ltv.py", ["test_cli_lta_update", "test_cli_ltvfix", "test_cli_ltvfix_require_signed_field"], namespace)
    runner = CliRunner()
    url = (root / "tsa-url.txt").read_text()
    args = {"pki_arch_name":"current-time long certificate adaptation", "timestamp_url":url,
            "cli_runner":runner, "root_cert":str(root / "root.der"), "p12_keys":str(root / "credential.p12")}
    if kind == "lta":
        namespace["test_cli_lta_update"](**args)
    elif kind == "ltvfix":
        namespace["test_cli_ltvfix"](**args, with_lta_timestamp=timestamp)
    elif kind == "unsigned":
        namespace["test_cli_ltvfix_require_signed_field"](runner)
    else:
        write_config({"pkcs12-setups":{"test":{"pfx-file":str(root / "credential.p12"), "pfx-passphrase":"secret"}},
                      "validation-contexts":{"test":{"trust":str(root / "root.der"), "trust-replace":True}}})
        original_functions("test_cli_decode_limits.py", ["_check_flag", "_read_output", "_addsig_args", "test_addsig", "test_validate", "test_ltaupdate", "test_ltvfix"], namespace)
        if kind.startswith("decode-addsig-"):
            lta = kind == "decode-addsig-lta"
            group = ("--validation-context", "test", "--use-pades-lta") if lta else ()
            namespace["test_addsig"](runner, None, None, url, group, int(lta))
        elif kind.startswith("decode-validate-"):
            namespace["test_validate"](runner, None, kind.removeprefix("decode-validate-"))
        else:
            namespace["test_ltaupdate" if kind == "decode-ltaupdate" else "test_ltvfix"](runner, None, url)
    print("Original body assertions passed:", kind)


def verify():
    from asn1crypto import x509
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.decode_limits import DecodeLimits
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    directory = Path(sys.argv[2])
    data = (directory / "signed.pdf").read_bytes()
    cert = x509.Certificate.load((directory / "root.der").read_bytes())
    reader = PdfFileReader(BytesIO(data), decode_limits=DecodeLimits.for_trusted_input())
    assert len(reader.embedded_regular_signatures) == 1
    signature = reader.embedded_regular_signatures[0]
    context = ValidationContext(trust_roots=[cert], allow_fetching=True, revocation_mode="hard-fail")
    status = validate_pdf_signature(signature, context)
    assert status.intact and status.valid and status.trusted and status.bottom_line, status
    untrusted = validate_pdf_signature(signature, ValidationContext(trust_roots=[], allow_fetching=False))
    assert not untrusted.bottom_line
    print("Same native PDF: intact, valid, trusted; empty roots denied")


if sys.argv[1] == "serve":
    asyncio.run(serve())
elif sys.argv[1] == "reference":
    reference()
elif sys.argv[1] == "verify":
    verify()
else:
    raise ValueError(sys.argv[1])
