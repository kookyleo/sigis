# Same OLD native Adobe outputs: frozen-producer LTA regression

## Delivered result and boundary

Both physically retained **old pre-RIA native producer PDFs** were freshly validated through the existing unchanged pinned public Python helper. Correct separate main/AA trust returns final OK, current API intact/valid/trusted/bottom_line true and actual `cms.RoleSyntax` with `bigboss@example.com`. Wrong-AA-root controls deny the authenticated role. Both helper processes exited 0: two primary profiles plus two wrong-AA validations, four fresh public calls total.

No new native execution occurred. Native behavior on these exact old bytes remains unknown until root installs/runs the draft. In particular, the earlier observed native NO_POE is not retrospectively changed by the fresh Python result or by successful native validation of different newly produced PDFs. This artifact adds zero unique upstream-function credit.

## Immutable public inputs and historical provenance

`fixtures/requests/cms-adobe.pdf` is 48,340 bytes, SHA-256 `c61dfabab6dea0e83f924e41cb95a2ae14e530ea7d759d285c9ebfa77566f97f`.

`fixtures/aiohttp/cms-adobe.pdf` is 48,340 bytes, SHA-256 `fb38975943cd7c71c7ac5bbec500f33da1b827bb641795c168f75d82ff796a96`.

They were copied byte-for-byte from `/home/l/.codex/artifacts/sigis/round3-launch/p-capture-integration/p7-final-v1/adobe-output/{requests,aiohttp}/cms-adobe.pdf`; they were not regenerated, re-signed, retimed or modified. The old `receipt.json` and `test.log` were copied into `prior-receipts/` without changing their original files. Those old logs preserve native NO_POE/API bottom line true versus same-output Python OK. The old retained receipt does not specify a producer git head, so none is inferred here.

Shared public identity pins (also independently copied for each label):

| Public object | SHA-256 |
| --- | --- |
| Main root |8de3a2712e46d0ea6e9b5f234457aee5e9c7bed69fdf7feed0c5a98649688a3c|
| AA root |57b9e80c61bdb208e67f02a4949d251e0552564728c9262f6cbea66520830b06|
| Actual AC |b650abefb4270855a7bb3aba8879044c64d52ef1969178ed66d9073f4c150909|
| Actual AC OCSP |0a2f1f902b1db9794e9df41c30c242b7be980986db21b5f33252feeb32de070d|
| Actual AA leaf, `fixtures/aa.der` |f99a3526088b5fd5aec2e6cc48ced611ef77de337b11c782f0363de4359d7e8b|
| Signed Adobe RIA value |c928027ba88d621e89290fc1d96632a809c6de38cbfb7dad9c1dc6d88c064e75|

The PDFs are plain Adobe `/adbe.pkcs7.detached`, field `Sig1`, with five other PKCs, one AC and seven total CertificateChoices. They contain no DSS. PDF MAC/decryption is inapplicable; no password/decryption workaround is used. Public input hashes were frozen in `preparse.json` before either oracle subprocess could parse them. File lengths, original paths and all helper/source/input hashes are in `receipt.json` and `fixtures/manifest.json`.

## Original primary validation profile

The existing `tools/pyhanko-oracle/cms_adobe_verdict.py` was copied byte-identically into this artifact and invoked with its unchanged positional arguments. It retains the original public `ades_lta_validation` specification:

- pyHanko 0.38.1 and pyhanko-certvalidator 0.33.0;
- time frozen at 2020-11-01T00:00:00Z, public default timing construction;
- separate actual main root and actual AA root;
- REQUIRE_REVINFO for both;
- original default NO_HISTORICAL_FETCH/current-online capability, default public fetcher backend, no explicit local-knowledge, timestamp-role or supplied-POE override;
- genuine scoped Certomancer mock PKI service responses, normal validation and cryptographic authentication.

The requests/aiohttp names label the old producer provenance. As in the original helper, they do not force two different validation backends or imply two native HTTP implementations. The native draft uses the existing recorded `Services` retrieval adapter with actual AC/AA-bound opt-in OCSP, exactly as the original native Adobe caller. Recorded retrieval is not claimed to be fresh network evidence. Neither validation context receives other certificates, revocation responses or proofs in advance; signed RIA ingestion must happen inside production validation.

No offline profile was probed, and no offline positive is assumed or substituted for this primary profile.

## Reproducible fresh reference execution

`freeze-and-run.py` copies the existing public inputs/helper, writes before-parse receipts, runs the two helper processes sequentially with the pinned interpreter and captures stdout/stderr. The child environment excludes PYTHONPATH and pytest overrides and disables bytecode; no installed packages or venv files are changed. Source hashes before/after are identical, and original old input/receipt bytes are rechecked unchanged afterward. Native source reference is candidate `42e5ba31d79b284ecb469c4861c510c23875c5b5`; no Rust code was executed.

Existing fresh results:

- `requests-stdout.json`, `requests-stderr.log`;
- `aiohttp-stdout.json`, `aiohttp-stderr.log`;
- `run.log`, `run.stderr`, `receipt.json`.

Direct helper reproduction with **new output paths**, preserving these original receipts:

```sh
PYTHONDONTWRITEBYTECODE=1 /tmp/pyhanko-oracle/venv/bin/python -I \
  /home/l/.codex/artifacts/sigis/round3-launch/adobe-old-native-next/cms_adobe_verdict.py \
  /home/l/.codex/artifacts/sigis/round3-launch/adobe-old-native-next/fixtures/requests/cms-adobe.pdf \
  /home/l/.codex/artifacts/sigis/round3-launch/adobe-old-native-next/fixtures/requests/root.der \
  /home/l/.codex/artifacts/sigis/round3-launch/adobe-old-native-next/fixtures/requests/root-aa.der \
  /home/l/.codex/artifacts/sigis/round3-launch/adobe-old-native-next/fixtures/requests/attribute-certificate.der \
  /home/l/.codex/artifacts/sigis/round3-launch/adobe-old-native-next/fixtures/requests/ac-ocsp.der \
  requests 2020-11-01T00:00:00Z
```

Replace the directory and label with `aiohttp` for the second original file. The existing helper preserves all original tail assertions, verifies typed ASN.1 role structure and runs the supplemental wrong-AA control. This is new validation of old bytes, not another full original upstream pytest invocation or new native signing.

## Root test installation and acceptance

`root-test-draft.rs` is a single supplemental function looping exactly the two old provenance labels. It is not installed, compiled or executed. To review/install later:

1. Copy `fixtures/` to `crates/testdata/data/lanes/r3-v/adobe-old-native/` and the draft to `tests/round3_adobe_old_native.rs`. No dependency or lock change is required; it uses the existing root test support and public production APIs.
2. The test hashes every retained input before parsing; checks plain/no-DSS Adobe structure and exact signed RIA/AC/OCSP identity; configures the actual public roots, original require/current-time builder path and the existing AC-bound Services provider; asserts contexts start without other certs, revinfo or supplied POEs.
3. It calls full native LTA with independent AA context and the wrong-AA control, preserving the caller contexts. It collects both native outputs before parity assertions, checks actual typed native `RoleSyntax`, final native OK versus mandatory fresh same-old-output Python final OK, current trust/integrity and wrong-AA refusal. No signing or modified document is introduced.
4. Run through the normal Cargo wrapper after root's current gate; capture source/compiler/input evidence. Until that actual native execution returns, the SAME OLD native byte gap remains explicitly unverified.

Final OK equality is a new supplemental status-parity guard, not an invented assertion added to the unique upstream function's original count. Preserve the faithful original Adobe caller and the independent BASIC/FULL29b and RIA adversarial suites. No global cache/target/config, service, private key or other worktree was changed here.
