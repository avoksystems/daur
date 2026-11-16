# Avok Attest HTML verifier

`Avok_Attest_Verifier_pilot_2026.11.4.html` is a single file with inline CSS and JavaScript, SHA-256 `8e882474e9734c91cf4f3f37ec9acea12faecba8646f5830d60e73cdad1268ee`. It makes no network request (its Content Security Policy sets `default-src 'none'` and `connect-src 'none'`), works from `file://`, and carries Avok's pilot trust list `ca.avoksystems.attest.pilot` 2026.11.4 from `../trust/pilot-2026.11.4/`, with the list's identifier and version shown at the top of the page. Another trust list can be loaded from a `.pem` file and its manifest `.json`, and a current revocation list can be loaded beside it.

## What it verifies

- The SHA-256 of the deliverable against the signed record; a different file name is reported as a warning. The record's signing certificate subject and serial are compared with the certificate semantically (`src/dn.js`).
- The COSE_Sign1 signature with WebCrypto: ES256 (P-256) and Ed25519 (where the browser supports it).
- The X.509 chain from `x5chain` to the trust list, judged at the signing time: validity, basic constraints, key usage, the signing certificate's extended key usage (specification 11.4) and the manifest's windows. Without a path to a trust anchor, revocation is not evaluated, and an informational `REVOCATION_NOT_EVALUATED` says so.
- The RFC 3161 time-stamp token: the CMS signature over the signed attributes, the message digest, the imprint over the signature bytes, `SigningCertificateV2`, the critical time-stamping extended key usage and the time-stamping authority's chain at `genTime`.
- Revocation at the signing time, from CRLs in the record's snapshot, in the loaded trust list or in revocation list files loaded beside it; the result says which data decided. OCSP responses are not evaluated in the browser: an OCSP-only snapshot is UNSUPPORTED in the strict profile.
- The protected snapshot commitment (header -70003) against the snapshot (-70002); a record of version 0.1 uses 7003 and 7002, and a label of the other version is ignored (`HEADER_LABEL_NOT_FOR_VERSION`).
- The trust-list pin (header -70004): `STALE_TRUST_STATE` when the bundled list is older than the pinned version, `TRUST_LIST_DIGEST_DIFFERS` when the same version has different content.
- Retroactive invalidity dates from the trust manifest.
- The schema validity of the record (a small built-in validator for the keywords the DAUR schema uses).
- Region hashes: byte ranges always, Markdown heading sections and text paragraph ranges. PDF page text and DOCX regions are shown as "not recomputed in browser".

## Build

```
npm ci
DAUR_TRUST_DIR=../trust/pilot-2026.11.4 npm run build    # writes index.html and dist/core.mjs
sha256sum index.html                                    # equals the SHA-256 above
```

The build inlines the trust list named by `DAUR_TRUST_DIR`, the JSON Schemas and the reserved-identifier list from `../src/daur/data/`, and the result codes from `../spec/result-codes.json`, so rebuild after changing any of them. Avok's test suite, which runs the bundled core against the test vectors, is kept with the reference implementation and is not in this repository, so `npm test` does not run here.

## Sources

`src/verify.js` is the core; `src/cbor.js` a minimal CBOR codec; `src/tsa.js` RFC 3161; `src/pki.js` trust lists, paths and CRLs on top of `@peculiar/x509`; `src/dn.js` RFC 4514 names and serial numbers; `src/regions.js` region recomputation; `src/schema.js` the schema validator; `src/statement.js` the plain-language statement; `src/ui.js`, `src/style.css` and `src/index.template.html` the page.
