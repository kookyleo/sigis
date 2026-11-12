# PDF-MAC PAdES oracle inputs

Owner of upstream function: S. Validator assistance: V. Baseline: pyHanko 0.38.1,
certvalidator 0.33.0. No native Rust signing, signing-session implementation,
validation acceptance or additional V function pass is claimed by these files.

The original decorated `test_pdf_mac_pades` ran unchanged. Its body asserts
`ades_status.api_status.bottom_line`; its `pdf_mac_good` decorator additionally
asserts successful PDF-MAC authentication and ISO extension level 32004.
The function has one original parameter case, using STANDARD encryption and
password `secret`, frozen at 2020-11-01T00:00:00Z. HTTP TSA and PKI services are
provided by the original upstream fixture.

- `exact.pdf`: encrypted PAdES-LTA output from that exact upstream test.
- `root.der` / `root.pem`: exact ECDSA trust root used by the test.
- `mac-token-mutated.pdf`: same file with one bit flipped in the final standalone
  CMS AuthenticatedData MAC value, inside its excluded token slot.
- `document-mutated.pdf`: same file with a benign header byte flipped, outside the
  excluded token slot, to test the authenticated document digest.
- `manifest.json`: frozen time, base64 trust root, six independent oracle cases,
  authentication/MAC results, main LTA status and timestamp-validation traces.
- `upstream-evidence.json`: original function outcome, its direct LTA result,
  timestamp traces and six real local HTTP service exchanges.
- `upstream-pytest.log`, `upstream/good/test_pdf_mac_pades.pdf`: original pytest
  output and the output preserved only after its complete decorator passed.

The positive oracle result is deliberately **NO_POE**, with trusted/intact/valid
CMS and `api_status.bottom_line == true`. It must not be relabelled AdES OK.
The failure is `Unable to construct plausible past validation path`; recorded
signature/document timestamp validations themselves return OK. The final MAC
location is `/Standalone`; the earlier signing workflow must not be used to
assume the final trailer points to a signature-attached MAC.

The ordinary MAC-rejection cases stop at failed authentication. Two explicitly
labelled diagnostics show the layer boundary: skipping MAC verification solely
to inspect unchanged CMS, and continuing LTA after ordinary MAC failure while
Python retains its key. The latter has FAILED/FAILED authentication but can still
return the same NO_POE result with a true API bottom line. Neither diagnostic is
an authenticated acceptance case.

Recheck fixed bytes from the repository root:

```sh
/tmp/pyhanko-oracle/venv/bin/python crates/pades/oracle/pdfmac_oracle.py --output crates/testdata/data/lanes/r3-v/pdfmac --replay
```

Generation uses the same command without `--replay` and invokes only the exact
pinned upstream function. Encryption material, timestamp fields and signatures
can vary on regeneration; the manifest binds the actual preserved bytes by
SHA-256. Repeated original function executions still count as one unique function.
