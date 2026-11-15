# Subsecond OCSP historical-control regression

The unchanged PDF was produced by the real Rust CLI in Root's live integration
on 2026-11-15. The public root certificate accompanies its embedded evidence;
no credential, timestamp, revocation response or signed input was edited.
The source live fixture is derived from the MIT-licensed pyHanko test PKI.

Actual OCSP thisUpdate/producedAt is 04:48:36.125430Z, signature TST is
04:48:36.624176Z and document TST is 04:48:36.817761Z. The original failing
validation reference was the whole second 04:48:36Z. Pinned pyHanko0.38.1 with
LOCAL_ONLY/NEVER_FETCH returns NO_POE there, retaining intact/valid/trusted API
status; at04:48:37Z the same bytes yield full-LTA OK. Both instants are explicit
regression inputs, not newly fabricated historical observation or POE.

This fixture tests strict historical revocation-evidence eligibility. Ordinary
current-time freshness and the original live CLI assertions remain separate.
