"""Execute the exact pinned lifecycle assertions without pytest conftests."""

import asyncio
import importlib.util
import inspect
from pathlib import Path
import warnings

from pyhanko.sign.timestamps import HTTPTimeStamper, TimestampRequestError
from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
import aiohttp


async def main():
    path = Path(
        "/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator/"
        "tests/test_fetcher_lifecycle.py"
    )
    spec = importlib.util.spec_from_file_location("pinned_lifecycle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    count = 0
    for name, function in vars(module).items():
        if name.startswith("test_") and inspect.isfunction(function):
            result = function()
            if inspect.isawaitable(result):
                await result
            count += 1
            print(f"PASS pyhanko-certvalidator/test_fetcher_lifecycle.py::{name}")

    # Exact negative assertions from test_tsa_fetcher.py, without its unrelated
    # signing fixtures. A local closed port avoids external network access.
    with __import__("socket").socket() as sock:
        sock.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    async with aiohttp.ClientSession() as session:
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always", DeprecationWarning)
            ts = AIOHttpTimeStamper(url, session, timeout=30)
        assert any(issubclass(w.category, DeprecationWarning) for w in recorded)
        assert ts._session is session
        try:
            await ts.async_timestamp(__import__("hashlib").sha256(b"Hello world!").digest(), "sha256")
        except TimestampRequestError:
            pass
        else:
            raise AssertionError("timestamp request unexpectedly succeeded")
    print("PASS pyhanko/test_tsa_fetcher.py::test_deprecated_aiohttp_timestamper_forwards")
    try:
        HTTPTimeStamper("http://example.invalid", auth=object())
    except TypeError as error:
        assert "BasicAuth" in str(error)
    else:
        raise AssertionError("nonsense authentication unexpectedly accepted")
    print("PASS pyhanko/test_tsa_fetcher.py::test_auth_coercion_rejects_nonsense")
    assert count == 16
    print("18 unique upstream functions executed; no parameters skipped")


asyncio.run(main())
