# Boolean dunder finite native profile

This tests-first packet covers exactly one proposed original:
`pyhanko/test_internal_utils.py::test_bool_dunders` at pinned pyHanko0.38.1,
complete function SHA256
`3cb06319a4783870a8c847e68a62bf11d65d30f12d2fdd7eeefc684f87accb2c`.
L approved this finite language/diagnostic translation in
`round3-launch/s-boolean-dunders-decision/l-assignment.md`. It is a testable
profile, not acceptance or literal Python representation parity.

`mapping.json` retains every original assertion and all eleven individual
comparisons/checks across the nine statements, including both comparisons in
each final chain. `original_test_bool_dunders.py` is the unchanged complete
function source, not an independently executed substitute for the original.

| Statement | Existing native operation | Disclosed adaptation |
| --- | --- | --- |
| B1 | Compare parsed Boolean Objects. | Object equality domain. |
| B2 | Parsed true differs from parsed empty PDF String. | Python raw empty str becomes a PDF String Object. |
| B3 | Parsed false differs from that empty PDF String. | Same explicit type-domain mapping. |
| B4 | `Object::as_bool` yields true. | Explicit scalar projection replaces implicit truthiness. |
| B5 | `Object::as_bool` yields false. | Same scalar projection. |
| B6 | Parsed true equals `Object::from` its bool projection. | Reconstruct into Object; no heterogeneous equality trait. |
| B7 | Parsed false equals `Object::from` its bool projection. | Same reconstruction. |
| B8 | Actual Object Debug equals actual scalar bool Display, and Display is `true`. | Object str maps to scalar Display, with lowercase diagnostic spelling. Both chained comparisons remain. |
| B9 | Actual Object Debug equals actual scalar bool Display, and Display is `false`. | Same diagnostic/formatting adaptation and both comparisons. |

The only native test is `boolean_dunders::test_bool_dunders`. Its three exact
inputs are `true`, `false` and `()` (no trailing newline), parsed by real
`generic::read_object`, `ParseContext` and `misc::Cursor`. Setup controls check
actual variants and complete consumption. There is no custom Boolean wrapper,
Object Display implementation, uppercase synthesis, Item Debug, Hash surrogate,
production/model change or extra original-function credit. Provider and runtime
exclusions for this scalar profile are none.

The native code and this source mapping are committed before any reference
execution. No Cargo/native execution is currently authorized; no GREEN or RED
native outcome, executable identity or native/reference agreement is claimed.
Root will schedule current-source native checks and any complete gate later.
An actual initial GREEN is legitimate; missing APIs or fabricated REDs are not
part of this packet.

The separate reference runner must use the pinned interpreter with `-B`:

```sh
/tmp/pyhanko-oracle/venv/bin/python -B \
  crates/testdata/data/lanes/r3-s/boolean-dunders/original_boolean_oracle.py \
  --output /absolute/new/reference-attempt-directory
```

It invokes pytest on the full unchanged pinned test module/function, records
applicable fixture names and all three phases, then separately probes actual
product Boolean objects and the exact three fixture bytes. Python's actual
`True`/`False` repr/str is preserved. The runner sets no product shim and
disables only pytest's disk cache provider. It records real interpreter/module
versions, assertion/bytecode flags, opened inputs, code/source hashes and socket
audit events; existing bytecode reads remain visible because `-B` suppresses
writes, not reads. Stdlib receipt setup precedes the audit hook and is disclosed
by the runner source. A separate launcher must preserve raw stdout/stderr and
actual command/exit/time/source identity, including any failed attempt.

Accepted counts remain S824/818/6/0 and PDF406/402/4/0. Proposed Boolean1 receives
no credit before Root review/gating/ledger transaction. Both deprecated CV
originals and the Name/Text/dictionary originals remain unchanged exclusions.
No trust-verdict, general object-model, dual-object formatting or full-port
claim follows from this scalar language profile.
