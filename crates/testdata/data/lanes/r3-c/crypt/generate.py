"""Export exact upstream oversized encrypted inputs (pyHanko 0.38.1, MIT)."""

from pathlib import Path

from pyhanko_testing_commons.test_data.samples import (
    PUBKEY_TEST_DECRYPTER,
    minimal_with_oversized_objstm,
)

HERE = Path(__file__).resolve().parent
for method in ("password", "pubkey"):
    writer = minimal_with_oversized_objstm()
    if method == "password":
        writer.encrypt("ownersecret", "usersecret")
    else:
        writer.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    with (HERE / f"oversized-{method}.pdf").open("wb") as output:
        writer.write(output)
