# Functional USER-PIN harness cleanup

On accepted main `ec052ce1`, only P's `cc55d2bd` helper cleanup remained new.
Root curated it as `8c04d3b7`: one USER-PIN support file, 27 added/30 removed
lines. Current preflight/Env helpers, Root common support and the later dedicated
signing callback remain unchanged. The old `65a` compatibility patch and earlier
provider/static production versions were not imported again.

Caller input/config/sentinel preservation now compares canonical paths and exact
bytes. Revocation request assertions compare actual requested certificate DER,
replacing file/transport fingerprint records. Functional same-output oracle IPC
and its payload identity checks remain, as do provider, roles, credentials,
certificate sources, clocks, PDF integrity/path/trust, MAC and tamper assertions.
This adds no original ID or production/API/dependency/lock change.

Root's normal default USER target passed **8/8**, with no named provenance or
optional provider/oracle selectors present in the parent environment. The first
plain workspace run ended **2431 passed / 5 failed / 31 ignored**: all five
failures occurred before DSA operations because this host could not discover
SoftHSM in default paths. Its log remains `workspace-no-resource-selectors.log`.
An early progress statement inferred Root success from advancement under
no-fail-fast; it was corrected after reading the failures. No failed run is green.

The existing SDK module/tool and pinned oracle/overlay were then selected using
ordinary functional Cargo env arguments. Root DSA3 and import2 passed; unchanged
source passed the complete workspace **2436 passed / 0 failed / 31 inherited
native ignored**, across256 test/doc reports. Workspace all-target clippy-Dwarnings
and fmt passed. No record directory, source commit, CLI digest, immutable ELF or
evidence selector was supplied. Exact commands and plain logs are under
`~/.codex/artifacts/sigis/round3-launch/p-user-pin-byte-comparisons/`.
Counts remain **1431 total / 1421 passed / 10 skipped / 0 pending**; the eight
provider originals retain their existing four-pass/four-exclusion dispositions.
