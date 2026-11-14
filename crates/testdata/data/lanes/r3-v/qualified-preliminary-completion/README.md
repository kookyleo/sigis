# Preliminary completion diagnostics

Supplemental tests/design only, zero original-function credit. Production is
accepted6b35096d/source134be605. These are freshly generated public test inputs,
not C caller imports or old recordings. Tests first, no production repair.

Nine genuine RSA2048 CMS signatures contain cryptographically valid signature
TSTs. The signed leaf chains exercise DNS NameConstraints, unknown critical
extension, subordinate path length, explicit policy mismatch, wrong certificate
issuer signature, DS-only vs NR, and authentic revocation CRLs. Test-only keys
are ephemeral and not persisted. Exact output lengths/hashes and policy cases
are in manifest.json; producer/runtime evidence is retained under
round3/v/qualified-preliminary-completion/oracle/.

A claimed signing time2020 is not real-world proof of existence. The fixed TST
must be actually validated under the caller's current policy before selecting
its time for any hypothetical best-time clone. No test registers new material
POE or promotes a supplied error path. Historical-time calls are explicit
controls; they are not current-time completion and do not establish archival
proof. The revoked cases have real2021CRLs; historical2020 use may lack
appropriate evidence and is not assumed to pass.

The private design under examination retains validationTime=current and all
original policy, changing only bestSignatureTime to authenticated signature
proof time. A genuine full ordinary CMS check is required, not getters/tracer
state or a direct KU check. Public WithTime's successful result on an actual
uncompleted mandatory constraint is a fail-closed hardening RED independently
of final LTA's refusal. No production default, time API, profile, policy, backend
or context changes are implemented.

The finite-policy case has explicit CMS PKIX params. PhaseA public WithTime has
no separate PKIX-params argument; its result is labelled as not carrying those
options and cannot be claimed as a complete same-policy validation. Existing
anchor/context-based restrictions remain real consumers. A later result companion
for same-decision PDF/TSA reporting is a separate design, not a new provider or
an approved API in this packet.

The generated material and adapters use the repository license; pyHanko-derived
usage follows LICENSE-pyHanko. Do not regenerate inputs to overwrite executed
hashes. Keep the d8f diagnostic/intentional RED frozen in its separate worktree.
