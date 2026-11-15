"""Public full-LTA check of the unchanged subsecond live CLI regression input."""
import asyncio
from io import BytesIO
import json
from importlib.metadata import version
from pathlib import Path
import sys

from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    CertificateFetchingRule,
    PdfSignatureValidationSpec,
    RevinfoOnlineFetchingRule,
    RevocationInfoGatheringSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager


async def validate(data, root):
    spec = PdfSignatureValidationSpec(SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(trust_roots=[root]),
            revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
        ),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY,
            certificate_fetching_rule=CertificateFetchingRule.NEVER_FETCH,
        ),
    ))
    reader = PdfFileReader(BytesIO(data))
    result = await ades_lta_validation(reader.embedded_signatures[0], spec)
    status = result.api_status
    assert status is not None and status.intact and status.valid and status.trusted
    return {"ades_subindic": result.ades_subindic.standard_name,
            "intact": status.intact, "valid": status.valid, "trusted": status.trusted}


if __name__ == "__main__":
    assert __debug__ and sys.flags.optimize == 0
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    data = Path(sys.argv[1]).read_bytes()
    root = x509.Certificate.load(Path(sys.argv[2]).read_bytes())
    with freeze_time(sys.argv[3], real_asyncio=True):
        print(json.dumps(asyncio.run(validate(data, root))))
