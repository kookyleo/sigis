# Disabled bootstrap semantic mapping

Test-only packet based on Root candidate134be605. Production is unchanged.
Only upstream CV0.33.0 test_fetcher_lifecycle.py::test_bootstrap_without_fetching_owns_nothing
is eligible. Its complete unchanged body requires ownerNone, fetching_allowedFalse,
and harmless explicitclose. L approves this mapping for Disabled only: actual
native CRL/OCSP components are absent and fetching_allowed() is false. Supplied(empty)
has Python manager-presenceTrue versus native component-availabilityFalse; it is
not normalized into Disabled and supplies no original-function proof here.

The identically named root test reuses real consumer/fixture helpers. It also
requires exact caller component identity, a reachable legacy provider positive,
no legacy fallback under Disabled, mandatory revocation-information refusal with
an intact valid CMS, and sufficient signed-local-evidence success. CMS bytes are
newly signed by the native test; CRL/OCSP bodies are committed-fixture replay.
The separate Python runner freshly executes the unchanged original through pytest
and probes None/default-factory/close identity without network. It records actual
interpreter/module/source identities and assertions-enabled state. The unused
requests_mock plugin is disabled explicitly because its import probes IPv6 bind;
this excludes no original fixture, parameter or provider.

First native execution compiled and failed only the new positive-control Debug
snapshot: actual provider counters legitimately change. That failed log/ELF is
retained; the test now checks exact component Arcs and caller configuration.
This is not an implementation RED or repair. No production modification or
runtime-accessor/manager-shaped adapter is introduced. Execution receipts and
fresh same-native-byte comparisons are delivered in the external artifact packet.
No acceptance count is changed by this test-only proposal.
