# P one Env PIN token-signing original: bounded implementation

Accepted compiled source: `473b7cbddef5df4aaaefef5a0f7075953927d0b3`.

Exactly test_cli_addsig_pkcs11_with_setup_and_env_pin is approved for tests-first implementation. All five full original root_cert_data rows execute with actual effective Ed25519 confirmed from collection/fixture precedence. No other nine provider originals or P-owned ID is accepted.

Temporary paths: new pkcs11_signing.rs; minimal typed/runtime handoff in pkcs11_config_frontend.rs; lib.rs only module declaration/borrowed-runtime argument. P exclusively owns CLIlib until freeze/Lhandoff. Reuse mature real Pkcs11Signer/PdfSigner and continuing authenticated reader/state/context/usage/signing APIs, no software fallback, private-key export, implicit token-certificate trust or fresh default reader. Preserve every selected setup requirement, full five MAIN policy, timing/freshness/PKIX/AC/algorithm, strict remaining decode budget and MAC state.

A NEW private isolated SoftHSM store may import the existing fixture Ed25519key/cert+root/intermediate certificate objects before module initialization. Record real extension/DSO/auth/EDDSA/session/sign calls and both resident/file certificate sources; do not invent a sign-call count. Positive scope is actual env user PIN; no new signingPIN/prompt callback or secret logging. Unsupported mandatory requests reject. Full tests-first original fixture/teardown, actual baseline, signed PDF identity/chain/coverage/intact/valid/trust, same actual output peers and empty-root/modified-byte refusals are required. Original2020and native NOW profiles stay explicit without retiming/POE tricks. The old valid-profile supplemental migration stays an UNAPPLIED L proposal.

Exact L authority: [p-cli-signing-env-pin-approval.md](/home/l/.codex/artifacts/sigis/round3-launch/p-cli-signing-env-pin-approval.md). Those original message bytes are also hash-bound in the final metadata manifest; time-specific statements in them are historical message context.

