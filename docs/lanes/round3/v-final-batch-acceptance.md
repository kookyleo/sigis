# V final batch acceptance

Accepted one original: `pyhanko/test_ades_validation.py::test_embedded_cades_pre_revoke_with_poe`. Its unchanged body is active in `ades_validation`; `round3_leaf_revocation_completion::original_pre_revoke_full_native_closure` also exercises native CMS/TST signing, November1 full path validation and December25 WithTime closure.

Six author commits through4483acbe were curated onto current maind1740401 as ea0caeb6,2e8c5339,b860349c,d6a18396,d9b92089,33bd7be3. Complete current MAIN validation and authenticated selected evidence authorize only the currently valid, later-KeyCompromise leaf profile. Pure failed-status promotion, expired/CA/cutoff recovery, invalid timestamps, mandatory usage/message policy and qualification refusals remain closed. Current revocation facts remain visible; this does not claim generic historical or full LTA recovery.

Normal-wrapper workspace passes2389tests/0failed/25ignored across248test/doc reports. Workspace all-target clippy-Dwarnings and fmt pass. Root reran the unchanged pinned original:1PASS; the author's same-native-CMS AdES peer also passes1/1. The first integrated run failed doctest E0460; the unchanged-source retry after coordinating Cargo jobs passed. No failed attempt is counted green.

V is47/47/0/0; overall1431/1419passed/8skipped/4pending. Supplemental tests and fixtures add zero upstream IDs. Remaining pending originals are the two CLI signing-PIN and two CLI historical-validation functions. Plain logs and commit mapping are in `/home/l/.codex/artifacts/sigis/round3-launch/v-final-integration/`; no new provenance pipeline or evidence JSON was required.
