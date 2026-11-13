# Exact CMS main-signer fixture

The manifest pins the complete public DER certificate extracted from the genuine
owner56ba digital-only profile. It was signed with the existing intermediate key;
its serial/key intentionally match signer1 while its signed KU and DER differ.
No old LTA PDF/test or unexecuted projection is imported. Tests sign new actual
CMS using the matching existing fixture key, verify chain/integrity and ESS,
and bind every manifest/certificate read by actual path/length/SHA256 receipts.
No private key or new provider is introduced. Zero upstream IDs.
