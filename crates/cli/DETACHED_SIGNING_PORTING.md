# Accepted detached PEM/DER CLI slice

Source `21323f9c389cf754af36e6248c58c628c4c05b27`; pyHanko0.38.1 /
certvalidator0.33.0. Accepted CLI counts are252/185/0/67. Exactly two new
functions are credited; prior183 remain once. Immutable ownership is unchanged.

| Immutable function | Parameter matrix | Native assertions |
| --- | --- | --- |
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_detached` |timestamp false/true × RSA/ECDSA/Ed25519 × PEM/DER =12|actual native CMS/signature/content/encoding, required TSA presence, equal-evidence trusted and empty-root-denied native status, fresh same-output reference|
| `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_detached_no_field_arg` |RSA1|actual exit1, exact field-incompatibility diagnostic and unchanged output sentinel|

The Rust mappings are `detached_signing::test_cli_addsig_pemder_detached` and
`detached_signing::test_cli_addsig_pemder_detached_no_field_arg`. The original
function names and source bodies retain their immutable mapping. Parameters,
supplementary functions, oracle calls and archived process receipts are counted
separately from these two unique functions.

Both native outputs and separate fresh reference commands are real executions.
Fresh same-native-output validation is not a fixture verdict or a fresh whole
upstream pytest run. Native TSA request/response bytes freeze before the separate
reference request; actual tokens bind the native signature, nonce and digest.
Claimed time without TSA is distinguished from timestamp evidence. Root current
CLI91088a34 and its actual test ELFs/input/source proof are independently bound;
old focus1a1/owner evidence is historical. Matched fixture time and explicit
revocation material are recorded; signed fixture evidence is not live HTTP PKI
acquisition. Output writing is not described as atomic rename.

Additional tests require field-error priority, encoding conflicts/duplicate
flags, mandatory unknown configuration/usage/context/runtime refusals, effective
settings and selected setup/raw material constraints before I/O where promised.
They do not add original IDs or imply all future CLI/provider/reader-state flows
are implemented. No attached signing fallback, implicit trusted-root default or
weaker validation context is used to force agreement. The accepted ordinary
PEM/P12/reader paths are preserved.

After all six current-source gates, measured native results are2061/
2058/3/0 across206 reports (discovered/pass/ignore/
fail; entire workspace, not detached-only). See
`docs/lanes/round3/l-detached-backend-context.md`, the central append-only ledger,
and `detached-next-integration/` current independent evidence. Complete-port or
universal fail-closed claims remain unsupported.
