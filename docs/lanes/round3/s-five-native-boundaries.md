# Five registry/PDF exclusions: native contract batch

This batch executes five real native controls adjacent to the five inherited
exclusions. It adds no wrapper/model/API or relaxed assertion. The controls
protect actual trust validation, parser/writer roundtrips and dictionary
mutations; they do not turn partial coverage into passing original ports.

| Original | Native control | Classification retained |
| --- | --- | --- |
| CV `test_system_trust_fallback_deprecated` | Empty anchors plus a real untrusted certificate chain reject; the same chain with an explicit root validates. | Deprecated implicit-root entry/runtime warning absent. |
| CV `test_extra_trust_roots_deprecated` | Adding the actual root changes membership and permits a real validated Ed25519 path; unrelated roots do not grant trust. | Deprecated keyword/runtime warning absent; normal explicit roots already work. |
| PDF `test_name_encode_fail` | Native prefix normalization, serialization and parsing roundtrip; malformed reader input still rejects. | No-slash construction history is erased; native writer accepts the normalized value, unlike Python. |
| PDF `test_text_string_no_bytes_available` | Fresh ASCII/Unicode/empty strings materialize bytes and roundtrip through the real writer/parser. | Unknown-origin information and its rejecting accessor are not native states. |
| PDF `test_dictionary_setvalue_guard` | Real integer conversion, typed entry-default preservation, replacement and dictionary serialization roundtrip. | Native set accepts integer conversion and lacks dynamic setdefault; the original two raw-integer guards remain unported. |

The native tests are `registry_language_boundaries` (two) and
`object_model_boundaries` (three). These five wrappers add **zero original
passes**. The five exclusions remain explicit; no missing-method compile
failure, warning-only shim, synthetic raw-object model or fake rejection is
used. Boolean was already accepted and is not counted again.

`crates/testdata/data/lanes/r3-s/five-native-boundaries/reference.py` runs the
five unchanged pinned originals and real PKI checks on the same native fixture
files. Its PDF probes preserve Python's refusals and the disclosed native
representation/conversion differences. Typed-object positive controls remain.
It writes plain output, without hash/ELF/JSON evidence collection.

## Actual validation

Base main1ce1fae1. Native changed-package tests: **726passed,0failed,0ignored**,
including all five new controls and the forged-leaf signature refusal. The
five unchanged pinned originals pass; five same-input PKI outcomes match
(empty/unrelated root deny, explicit/added root validate, forged signature deny).
The PDF probes preserve the expected Python/native differences explicitly.

All-target workspace clippy with -Dwarnings and formatting checks pass. An
initial unrelated-root fixture path was corrected to the existing Ed448 root;
that missing-file preparation failure is not a product behavioral RED.

## Historical gate on the original1ce1fae1 base

The normal workspace command was executed and returned101: Root
`tests/round3_generic_dsa.rs:55` has two failures because PKCS11_TEST_MODULE is
unset. This shared fixture-configuration failure is outside S's files, not a
failure of the new native controls. L/P coordination is requested for ordinary
SoftHSM setup and removal of obsolete mandatory proof variables. Workspace
acceptance is **blocked**, never reported as zero-failure. No other-lane file,
provider, shared venv, ignore or production API was changed.

A subsequent focused Root generic-DSA run supplied the existing real SoftHSM
module/tool, raw-DSA capability, Python overlay and oracle through Cargo's
worker environment configuration. Both tests then reached
`tests/round3_generic_dsa.rs:149` and failed because a persistent evidence
directory is mandatory. This confirms an obsolete shared-harness requirement
beyond ordinary provider availability. The actual run used vm2064 slot0;
`shared-ordinary-setup.log` retains its two failures. No proof directory or
collector was recreated to bypass that requirement. L/P must remove the
shared guard before a normal workspace gate can succeed for this packet.

Plain command logs are under
`~/.codex/artifacts/sigis/round3/s/five-native-boundaries/`. No hash/ELF/JSON
proof pipeline or independent review was added. The initial preparation/fmt
failures remain in the plain logs. Central accepted counts stay
S824/819/5/0, CV133/131/2/0 and PDF406/403/3/0; these related controls add no
original passing credit.

## Current-main integration

The old shared blockers above were already removed by accepted Root027fafa8; they were not recreated or bypassed. The three S commits were curated onto current mainfb6cd010 alongside the independent P static-signing-PIN increment. The normal combined workspace passes 2399 tests / 0 failed / 25 inherited ignored across 251 test/doc reports; all-target clippy-Dwarnings and fmt pass. Focused native boundaries pass 5/5, fresh unchanged originals 5 PASS and same-input PKI peers 5/5 match. All five exclusions and their exact model differences remain unchanged; this supplies zero original credit. Current acceptance is recorded in [the supplemental batch note](p-static-s5-supplement.md).
