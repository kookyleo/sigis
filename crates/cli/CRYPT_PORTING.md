# Crypt independent port

Scope: password/public-key PDF encryption and decryption. Original tests were translated before implementation.
Unique functions: 23 total / 23 locally passed /0 skipped/0 pending. Accepted counts require L gate.

All21 original functions retain30 password/key-format/force/passfile/permission/negative cases. The two decode-limit decryption functions retain6 command cases. Each maps to the same-named crypt test; full IDs are in PORTING.md. All successful artifacts assert authentication/removal and first-page Hello content. OpenSSL key-container diagnostics can differ; meaningful semantic errors retain upstream substrings.

Oracle evidence: 36 fresh pinned CLI status/message comparisons and18 fresh successful-artifact authentication/page comparisons per complete crypt run. Historical source-only crypt suite30/30 is separate. Fixtures are replayed inputs, never recorded verdict assertions.

No provider skips. Fresh native evidence: increment-crypt-tests.log; current cumulative projection uses its own preserved Cargo-produced executable, not the full-source binary. Build/tests/clippy/fmt receipts record actual scheduler host/slot.
