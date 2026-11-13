# Standalone stamp input

minimal.pdf is copied verbatim from pyHanko0.38.1 shared test data
(pdf/minimal.pdf), distributed under the upstream MIT license. SHA256:
0e8bbc125c7bc3bb13dedf28990ae93aa375387481ba67a0471806c89a1cfd16.
Only this runtime fixture is included by the standalone stamp increment.
The oversized decode specimen has its own README and pinned generator.

## Encrypted runtime read input

minimal-aes256.pdf is the exact MINIMAL_AES256 sample from pinned pyHanko
0.38.1 testing commons (MIT),1403 bytes,SHA256:
eda8c19fae7b63e715f0936d0359b698bc81ab69107e159507842f08dce8b69a.
The runtime_read test executes the original addfields failure assertions
over these bytes;the fixture itself is not a recorded passing outcome.
Other runtime/validation engines are outside this one-function increment.
