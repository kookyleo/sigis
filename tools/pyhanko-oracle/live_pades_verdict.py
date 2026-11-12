"""Fresh pinned LTA verdict for an actual Rust-produced live Certomancer PDF.

Invoked by the root live PAdES integration suite.
This script does not sign, replay a stored verdict or inject intermediate certs.
"""

import asyncio
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
from pathlib import Path
import sys

import aiohttp
from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    RevocationInfoGatheringSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager


async def verdict(pdf_bytes, roots, session):
    reader = PdfFileReader(BytesIO(pdf_bytes))
    signature = next(s for s in reader.embedded_signatures if s.field_name == "Sig1")
    spec = PdfSignatureValidationSpec(
        SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=SimpleTrustManager.build(trust_roots=roots),
                revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
            ),
            revinfo_gathering_policy=RevocationInfoGatheringSpec(
                fetcher_backend=AIOHttpFetcherBackend(session, per_request_timeout=10)
            ),
        )
    )
    try:
        result = await ades_lta_validation(signature, spec)
    except Exception as error:
        return {
            "valid": False,
            "trusted": False,
            "error_class": type(error).__name__,
            "error": str(error),
        }
    status = result.api_status
    level = None if status is None else status.modification_level
    return {
        "valid": False if status is None else status.valid,
        "intact": False if status is None else status.intact,
        "trusted": False if status is None else status.trusted,
        "modification_level": None if level is None else level.name,
        "ades_subindic": result.ades_subindic.standard_name,
    }


async def main():
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    data = Path(sys.argv[1]).read_bytes()
    root = x509.Certificate.load(Path(sys.argv[2]).read_bytes(), strict=True)
    async with aiohttp.ClientSession() as session:
        correct = await verdict(data, [root], session)
        empty_roots = await verdict(data, [], session)
    return {
        "kind": "fresh pinned public ades_lta_validation over actual Rust output",
        "pyhanko": version("pyhanko"),
        "certvalidator": version("pyhanko-certvalidator"),
        "pdf_sha256": sha256(data).hexdigest(),
        "root_sha256": sha256(root.dump()).hexdigest(),
        "validation_time": sys.argv[3],
        "correct": correct,
        "empty_roots": empty_roots,
    }


if __name__ == "__main__":
    with freeze_time(sys.argv[3], real_asyncio=True):
        print(json.dumps(asyncio.run(main())))
