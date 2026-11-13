# Public full-LTA registry profiles: retained29b

## Outcome and scope

The fresh pinned public `ades_lta_validation` result is **NO_POE with current API intact/valid/trusted/bottom_line all true and timestamp trusted true**, for both public `ValidationTimingInfo.point_in_time_validation=false` and `true` at 2020-11-01T00:00:00Z. This is an observed full-LTA result, not an extrapolation from the previously accepted legacy BASIC-profile refusals. No expected verdict was injected.

The root-test draft encodes these two actual full-LTA expectations. Native compilation/execution has not occurred: current native behavior is unknown. A stricter native failure, if later observed, would be a compatibility gap to diagnose; this artifact establishes no new native fail-open finding and earns zero unique-function credit. Do not change the existing eight-profile BASIC regression's expected refusals to make full LTA match.

Reference environment: pyHanko 0.38.1, pyhanko-certvalidator 0.33.0, `/tmp/pyhanko-oracle/venv/bin/python`. Native source reference: `45a8b44262dac39e7a13942beeb1eba50a922585`, before any later minimal V RIA ingestion patch. Only artifact files were written. No Cargo, worktree/source edit, package/environment edit, registry replacement, service or process interference occurred.

## Exact public profiles

Both use the same physically retained encrypted PDF and actual public roots, hashed before parsing:

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| different-generation-reproducer.pdf |26213|29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2|
| testing-ca-ecdsa-root.der |648|ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90|
| testing-ca-root.der |976|2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa|

Immutable artifact copies are under `inputs/`. This is newer retained29b, not a recreation of lost7075. MAC authentication uses the public fixture password `secret` and actually succeeds before validation. Exactly one regular signature, field `Sig`, is selected.

Policy is explicit ECC-then-RSA roots, `CertRevTrustPolicy(NO_REVOCATION)`, default `DisallowWeakAlgorithmsPolicy`, one-second tolerance, no preloaded local knowledge/proofs, `LOCAL_ONLY` revinfo and `NEVER_FETCH` certificates. This corresponds to native context roots and absent fetchers without weakening the explicit no-revocation profile. There is no explicit timestamp policy or AC policy; the public AdES API inherits the certificate policy. Rust `LtaOptions` exposes only optional known POEs and AC context, so separate/shared/equal-distinct timestamp-role variants are not invented here.

The public input timing flag is supplied as requested in each call. `CertValidationPolicySpec.build_validation_context_kwargs` always passes the provided validation moment to its constructed `ValidationContext`; that legacy constructor treats an explicit moment as point-in-time. This internal construction behavior is preserved, not patched to mimic Rust's explicit timing override. The public timing flag still reaches handler bootstrap, but fetching is disabled for both profiles. Root's Rust draft passes the two supported native timing flags and records them exactly.

## Full observed statuses

Both primary calls return:

- Final indication `NO_POE`; failure `Unable to construct plausible past validation path [AdESIndeterminate.NO_POE]`.
- Current API intact, valid, trusted and bottom line true; no main trust problem or algorithm horizon; full-revision/file coverage and DocMDP success.
- Main path: ECC root `ccc40983…` -> ECC intermediate `563435c97dca8ee1ba43f084d9330e66f0dee1b83bac98d03ff181b37ea00b5e` -> signer `899920fac432386b36a5a0cbccd5c681a215df2accf35e0280560fef8749555a`.
- Timestamp intact/valid/trusted, time 2020-11-01T00:00:00Z; path RSA root `2b6dea78…` -> TSA `31d7cc1589f388928dec5e1c6ccd2f973d0881dfa9d4874ca3caf0926918a7a6`. The extra RSA intermediate embedded in the token is not needed by this actual TSA path.
- Best signature time 2020-11-01T00:00:00Z; no oldest document-timestamp evidence record and no signature-not-before bound.

`result.json` preserves all normalized API dataclass fields, certificate identities, complete result representations, validation objects, original errors and source hashes. `stderr.log` preserves the real insufficient-revinfo/time-slide diagnostics: no pre-2020 revocation evidence for the ECC intermediate exists. Current API trust is therefore not a successful archival conclusion; final NO_POE remains significant.

## Why this differs from legacy BASIC: source plus actual trace

`trace.py` uses only Python's observational `sys.setprofile` facility around the unchanged public helper. It observes the original registry function's actual arguments, return values and retained certificate before/after. No subclass, monkeypatch, custom registry, result override or changed registration order is installed. It retains store objects solely to keep trace identities stable; the two traced calls match every compared semantic status field from the two primary calls.

`registration-events.json` contains 28 actual registration returns. Both timing profiles have the same sequence; store1/store5 correspond to the initial with-time handlers:

1. Context construction registers ECC root first. The RSA root has the same issuer/serial and is refused by the trustless certificate registry, while the separate trust manager still contains both configured anchors.
2. Main `cms_basic_validation` registers the ECC intermediate `563435…` successfully **before** attached signature-TST validation. There is no observed DSS/bootstrap certificate registration that would justify reversing this conclusion.
3. TST `cms_basic_validation` then tries to register RSA intermediate `0e8fa78719…`; actual return is false, retaining ECC `563435…` for that issuer/serial. Thus first-wins behavior remains active, but the winner differs from the legacy BASIC call sequence.
4. Full LTA subsequently calls `_process_signature_ts`, which bootstraps fresh handlers (store2/store6). Its genuine token validation can register the RSA intermediate there; the validated TSA still chains directly to the configured RSA root.
5. `_ades_past_signature_validation` independently bootstraps historical handlers (store3/store7), registers the main ECC CMS material, then the genuine past-validation attempt fails for missing revocation evidence. No waiver converts that to final OK.

Pinned primary source establishes this order:

- `pyhanko/sign/validation/ades.py:877-938`: `_ades_basic_validation` calls main `generic_cms.cms_basic_validation` first.
- `ades.py:1058-1075`: full with-time validation invokes that block; `ades.py:1120-1160` processes the signature timestamp afterward using the existing contexts.
- `ades.py:2281-2315`: full LTA runs with-time validation before later timestamp/past stages.
- `ades.py:2026-2054`: `_process_signature_ts` supplies fresh bootstrapped handlers to public timestamp validation.
- `ades.py:1415-1440`: past-signature validation creates independent historical handlers and registers the main CMS certificates.
- `generic_cms.py:552-557`: the actual main/TST `other_certs` registration point.
- `pyhanko_certvalidator/registry.py:163-180`: unchanged first-issuer/serial-wins implementation.
- In contrast, legacy `pdf_embedded.py:860-884` calls `collect_timing_info` **before** main `cms_basic_validation`, explaining the accepted legacy BASIC RSA-first refusal.

Current-read hashes for these primary sources and before/after hashes for helper-used sources are in `verification.json` and the result receipt. The fresh trace is evidence about actual public full-LTA semantics; it is not a new Rust result or a reason to relax the independent BASIC guard.

## Files and reproduction

- `oracle.py`: standalone public-API helper; primary run exits 0 with two successful returned results and no validation exception.
- `trace.py`: observational wrapper; second run exits 0 with two additional public calls and 28 registration events.
- `result.json`/`stdout.json`/`stderr.log`: primary evidence.
- `traced-result.json`/`traced-stdout.json`/`traced-stderr.log`/`registration-events.json`: independent observation evidence.
- `verification.json`: all important hashes, exact semantic comparison and four total fresh public calls (two primary plus two observed).
- `root-test-draft.rs`: artifact-only root integration test; records both native results before assertions, preserves caller immutability, checks successful MAC authentication, final indication, actual paths/signers and full API status. Not compiled, run or installed.

```sh
PYTHONDONTWRITEBYTECODE=1 /tmp/pyhanko-oracle/venv/bin/python -I /home/l/.codex/artifacts/sigis/round3-launch/lta-registry-next/oracle.py \
  --pdf /home/l/D/kooky/sigis/crates/testdata/data/lanes/r3-s/mixed-context/different-generation-reproducer.pdf \
  --ecc-root /home/l/D/kooky/sigis/crates/testdata/data/lanes/r3-s/mixed-context/testing-ca-ecdsa-root.der \
  --rsa-root /home/l/D/kooky/sigis/crates/testdata/data/lanes/r3-s/mixed-context/testing-ca-root.der \
  --native-source-head 45a8b44262dac39e7a13942beeb1eba50a922585 \
  --output /path/to/new-result.json
```

To reproduce the trace, run `trace.py` with the same arguments plus `--events /path/to/new-events.json`. Avoid overwriting these frozen original receipts. No provider network service or overlay is required.

## Root acceptance handoff

Install only the test draft after reviewing its current APIs, run its focused baseline through the repository Cargo wrapper, and preserve its actual result before any production change. Native outcome is presently unknown. Keep the existing eight-profile BASIC suite in the same acceptance scope. That paired coverage can detect a future change that incorrectly conflates legacy BASIC TS-first state with full-LTA main-first semantics; one suite cannot substitute for the other.

The forthcoming RIA importer adds another context clone, while baseline LTA already clones for DSS. This fact alone proves neither a new weakening nor a fix. Require actual paired source/input native evidence before attributing any changed trust result to constructor/clone ordering. Preserve no-historical-network rules, algorithm/POE cutoffs, caller security state and final NO_POE where proof is absent. No V original-function mapping or global fail-closed claim follows from this supplemental test.
