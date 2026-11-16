# Deliverable AI-Use Record (DAUR)

The Deliverable AI-Use Record (DAUR) is a published specification from Avok Systems Inc. for a signed record of how AI was used to produce a document delivered to a government buyer or another client. The record states which AI tools were used, on which sections and for what, and who reviewed the result, and it can carry a check of whether each web address, DOI and arXiv number the document cites resolved when the producer checked it. Anyone can verify a record offline in a browser with the free verifier in this repository.

A record that verifies proves who signed what about which file and when. It does not show that the declaration is true or that the document is accurate, and the verifier is not an AI detector.

## What is in this repository

| Folder | Contents |
|---|---|
| `spec/` | The specification, version 0.2 (draft for pilot use), its JSON Schemas, result codes and threat model |
| `verifier/` | The verifier: one HTML file with Avok's pilot trust list 2026.11.4 built in, with its source and build script |
| `src/daur/data/` | Files the verifier build reads: the two schemas (identical to those in `spec/`) and the list of reserved trust-list identifiers |
| `trust/` | The pilot trust list 2026.11.4 (roots, manifest and the revocation list of 10 November 2026) and the certificate policy and relying-party terms that apply to it |
| `docs/` | A verifier guide for contracting officers, and prices |
| `sample/` | A sample deliverable, SITEKEEPER's public sample report for a fictional client, with its signed record, its citation check and a reading copy of the record |
| `disclosure/` | A technical disclosure of the record and its verification, dated 14 November 2026 |

## Verify the sample yourself

1. Save `verifier/Avok_Attest_Verifier_pilot_2026.11.4.html` and check that its SHA-256 is `8e882474e9734c91cf4f3f37ec9acea12faecba8646f5830d60e73cdad1268ee` (`sha256sum` on Linux or macOS, `certutil -hashfile <file> SHA256` on Windows).
2. Open it in a browser. The page makes no network request (its Content Security Policy sets `connect-src 'none'`), so it works with the network off.
3. Load `sample/sitekeeper-sample-report.pdf` as the deliverable and `sample/sitekeeper-sample-report.pdf.daur.cose` as the record.
4. Compare the trust list fingerprint shown with the result against `3382739d23cab3607ab1f83c34904c4cb9e1496b02224252a0140693a4a77f78`, the fingerprint of the pilot trust list 2026.11.4.

The result reads PASS, with a note that the browser did not recompute the hashes of the PDF's page sections (`REGION_NOT_RECOMPUTED`). The record itself says that its accountable person has not yet reviewed the PDF for this record and that it will be reissued after that review: a verifier reports what was signed, including such a statement.

## Rebuild the verifier from its source

```
cd verifier
npm ci
DAUR_TRUST_DIR=../trust/pilot-2026.11.4 npm run build
sha256sum index.html
```

The build writes `index.html`, whose SHA-256 equals that of `Avok_Attest_Verifier_pilot_2026.11.4.html` (checked on 15 November 2026 with Node 22 and the package versions pinned in `package-lock.json`). `DAUR_TRUST_DIR` names the trust list to build in and is required in this repository.

## Status

Specification 0.2 is a draft for pilot use: fields, codes and header labels may change before version 1.0. Avok Systems Inc. operates the pilot trust list under `trust/POLICY.md`, which states where the root key is held and who operates it; the list has had no third-party audit. The signing toolkit is supplied to customers under licence and is not in this repository.

## Prices, security reports and contact

Prices are in `docs/pricing.md`. To report a vulnerability, see `SECURITY.md`. Avok Systems Inc., 6021 Yonge Street, Unit 312, Toronto ON M2M 3W2, Canada; bd@avoksystems.ca; 647-732-9912.

## Licences

The verifier source and build files are under the Apache License 2.0 (`LICENSE`). The specification and its schemas are under the Creative Commons Attribution 4.0 International licence (`spec/LICENSE-CC-BY-4.0.txt`). Avok Attest and DAUR are names of Avok Systems Inc. No conformance with any external program is claimed until that program says so.
