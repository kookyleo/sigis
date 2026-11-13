# Mixed signer/timestamp registry regression

Frozen encrypted output from the pyHanko-derived local test fixtures (MIT).
Public certificates only; password secret is a test fixture value.
Output SHA25629b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2.
This newer physically retained input does not recover the overwritten7075 case.
Both timing profiles and separate-role positives must match the fresh pinned
oracle. The supplemental regression adds zero upstream-function credit.
See docs/lanes/round3/l-mixed-context.md for source/binary/input receipts.

The timestamp and plain outer SignedData were extracted from that exact PDF.
The unvisited token adds only the original ECC public signer certificate to
its unsigned CertificateSet; its original SignerInfo/signed attributes remain
unchanged. Private CMS tests verify that token as a real trusted positive
before proving an unvisited token cannot register its extra certificate.
Exact extraction hashes are retained in round3/l-next/mixed-token-extraction.json
and mixed-unvisited-token-extraction.json.
