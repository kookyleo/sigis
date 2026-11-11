# XML signature lanes (plan)

Status: plan, 2026-11-12. Owner: the lead. The crates exist as interface
skeletons (`crates/xmldsig`, `xades`, `asic`, `ooxml`, `odf`, `xsig`, and
`cades` for CMS outside PDF). Layers and rules are in `docs/crates.md`. No
implementation lane has started yet.

## 1. Goals and non-goals

- Verify, and later sign: XML-DSig, XAdES (EN 319 132) B/T/LT/LTA, ASiC-S and
  ASiC-E (EN 319 162) with XAdES or CAdES, OOXML package signatures
  (ECMA-376 Part 2 §12) and ODF signatures (ODF 1.2 Part 3 §5), all reported
  in the `ades-model` terms and served through `sigis-xsig` and `sigis-sign`.
- Security first: untrusted XML is hostile input. Every lane keeps the
  "never accept what the reference rejects" rule of `docs/hanko-lanes.md`
  §5.3: on every corpus and differential suite, the port must not accept an
  input that the reference implementations reject.
- Non-goal for now: XML Encryption, XPath/XSLT transforms (rejected by
  policy), non-ETSI XML signature profiles beyond what the corpora require.

## 2. Reference corpora and oracles (priority order)

| Priority | Source | Use | License / handling |
| ---: | --- | --- | --- |
| 1 | **libxmlsec1** test suite (`tests/` vectors: merlin, aleksey, phaos, ...) | Core XML-DSig conformance (`xmldsig`), C14N | MIT-style; vectors copied with license into `crates/testdata/data/xmlsec/` |
| 2 | **Apache Santuario** (Java) test vectors (`interop`, `ihc`, `xsw`-related tests) | Core conformance, interop, wrapping attacks | Apache-2.0; vectors copied with license |
| 3 | **EU DSS** (Digital Signature Service) | XAdES / ASiC / CAdES conformance, reference verdicts as a CI oracle | **LGPL-2.1**: never linked or copied into this repo. A separate repository (and container) runs DSS; CI sends inputs and compares verdicts (differential, like the pyHanko oracle). Only verdicts (JSON) are stored here |
| 4 | **signxml** (Python) | Second oracle for XML-DSig / XAdES; already used by lane E's trusted-list differential test | Apache-2.0; runs in the oracle venv |
| 5 | **LibreOffice** | ODF signatures (and OOXML) as produced by a real office suite; differential verify of produced files | MPL-2.0; run as an external tool (headless), not linked |
| 6 | **Apache POI** | OOXML signatures (`SignatureInfo`); differential verify of produced files | Apache-2.0; run as an external tool (JVM), not linked |

Plus XML-signature-wrapping (XSW) corpora: the published XSW attack
classes (Somorovsky et al., "On Breaking SAML" and follow-ups; the
`xsw` tests of Santuario and of SAML toolkits), adapted to plain XML-DSig and
XAdES. All corpora live under `crates/testdata/data/<corpus>/` with a README
naming origin, version and license, as for the pyHanko fixtures.

## 3. Acceptance thresholds

1. **Core (`xmldsig`, lane X1): zero failures** on the libxmlsec1 suite, the
   Santuario suite and the XSW suite (every "must reject" case rejected,
   every "must verify" case verified, with the reference's reason class).
   - Planned backend: a thin wrapper over the `bergshamra` crate (BSD-2) plus
     the policy layer already specified in `sigis_xmldsig::XmlDsigPolicy`
     (reference whitelist, XSW defence through "only consume what was
     signed", transform and size limits, no DTDs). Fixes to `bergshamra` go
     upstream first (§1 reuse rule of `docs/hanko-lanes.md`).
   - Lane E already wrote C14N 1.0/1.1, Exclusive C14N and XML-DSig
     verification on `roxmltree` for trusted lists (`crates/eutl/src/xml/`).
     X1 measures both candidates on the corpora and keeps one; `eutl` then
     uses `xmldsig` instead of its private copy.
   - **Fallback**: if no pure-Rust candidate reaches zero failures, the core
     (only canonicalization and signature verification) falls back to
     **libxmlsec1 via FFI** in a separate crate (`xmldsig-xmlsec`), the only
     crate allowed to contain `unsafe` (a documented exception to
     `#![forbid(unsafe_code)]`); the policy layer stays in Rust.
2. **Upper layers (`xades`, `asic`, `cades`, `ooxml`, `odf`): at most 12k lines
   of production Rust in total.** If an estimate exceeds this, the lane stops
   and reports; the lead decides between scope cuts and an external engine.
3. **OOXML and ODF**: signing is enabled only with **at least 50 positive and
   50 negative samples** per format (real documents from Office, LibreOffice,
   POI; tampered variants), and a **differential test against POI (OOXML) and
   LibreOffice (ODF)** on every sample and every document the port produces.
   Below that, the crate stays **verify-only** (signing returns
   `HankoError::Unsupported`).
4. As everywhere: no `unwrap`/`panic` on untrusted input, fuzz targets for
   every parser (XML, ZIP), gate green per phase.

## 4. Lanes

| Lane | Crates | Scope | Depends on | Acceptance |
| --- | --- | --- | --- | --- |
| X0 Corpora & oracles | `crates/testdata/data/{xmlsec,santuario,xsw,dss,...}`, oracle tooling | Import corpora with licenses; DSS oracle in a separate repository with a JSON verdict API; LibreOffice / POI runners for the differential tests | — | Corpora reproducible from pinned sources; oracle verdicts recorded |
| X1 XML-DSig core | `xmldsig` | §3.1; `bergshamra` wrapper or fallback; policy; fuzzing | X0 | Zero failures on libxmlsec1, Santuario, XSW |
| X2 AdES on XML and CMS | `xades`, `cades`, `asic` | XAdES B/T/LT/LTA verify then sign; CAdES for non-PDF content (reusing `cms` and `pades-sign`'s CMS code); ASiC-S/E | X1, lane A (`pki-*`, `cms`) | DSS differential: never more lenient; ≤12k lines with X3 |
| X3 Office documents | `ooxml`, `odf` | Package signature verify; signing only after §3.3 | X1, X2 | §3.3 samples and differentials; verify-only otherwise |
| L (lead) | `xsig`, `sign` | Facade wiring, service integration behind a flag | X1–X3 | Gate green; layering check |

Merge order: X0 → X1 → X2 → X3, with the lead wiring `xsig` and `sign` as
each lands. The pyHanko lanes (A–E) are unaffected, apart from lane E's
`eutl` switching to `xmldsig` after X1.

## 5. Open decisions (lead / Leo)

- Hosting of the DSS oracle repository and its CI (LGPL isolation).
- Whether OOXML/ODF signing is in scope for the first service release
  (default: verify-only).
- Whether the libxmlsec1 FFI fallback is acceptable at all, or whether
  missing the zero-failure bar should instead shrink the supported feature
  set.
