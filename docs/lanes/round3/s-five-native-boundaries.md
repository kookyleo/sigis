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

Validation results will be recorded after execution. Central accepted counts
remain S824/819/5/0, CV133/131/2/0 and PDF406/403/3/0.
