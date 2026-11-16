# Avok Attest: verifier guide for contracting officers

Avok Systems Inc., 10 November 2026. Verifier release 0.2.0 with Avok's pilot trust list 2026.11.4. Questions: bd@avoksystems.ca, 647-732-9912.

You have a deliverable and a record file (`.daur.cose` or `.daur.json`). The record is the contractor's signed statement of how AI was used. Checking it needs no account and no network connection. A PASS tells you who signed what about which file, and when. It does not tell you the statement is true.

## 1. Use the right verifier and trust list

Get the verifier page and the trust list from your contracting authority or from Avok (`verifier/Avok_Attest_Verifier_pilot_2026.11.4.html` in Avok's published repository, SHA-256 `8e882474e9734c91cf4f3f37ec9acea12faecba8646f5830d60e73cdad1268ee`), never from the contractor whose record you are checking. A verifier built with a test list, whose private key is published, proves nothing. A list's id and version are labels anyone can copy; only its fingerprint identifies it. Compare the trust list fingerprint shown beside the verdict with the one your contract or contracting authority names (Avok's pilot list, version 2026.11.4: `3382739d23cab3607ab1f83c34904c4cb9e1496b02224252a0140693a4a77f78`), or enter it as the expected fingerprint (`--trust-fingerprint` on the command line) so that any other list gives FAIL `TRUST_LIST_FINGERPRINT_MISMATCH`. Leave the profile on strict, the default.

The statement PDF is a reading copy and its box is not evidence. Verify the record yourself.

## 2. Read the result

PASS: the record was signed with the certificate named on the next line, which chains to a root on your trust list, over this exact file; the certificate was valid and not revoked at the signing time according to the revocation list named on the "Revocation:" line; the record has not changed since. Revocation lists come from the trust list's operator, never from the contractor; if your contracting authority names the current one, enter its hash as the expected revocation list (`--crl-fingerprint`) and any other gives FAIL `CRL_NOT_THE_EXPECTED_ONE`.

PASS with warnings: signature and binding held, but something is weaker. Read every code.

FAIL: do not rely on the record. A hash mismatch usually means you hold another version of the file: ask for the exact file or a new record. For an untrusted root or a fingerprint mismatch, check step 1. Otherwise treat the deliverable as if no record had been supplied and raise it with the contractor in writing.

TEST: a red bar and every result marked TEST. A list built on the published test keys proves nothing, whatever its label; outside test mode it gives FAIL `TEST_TRUST_LIST`.

## 3. Read who signed

The next line, `Signed with a certificate issued to <CN>, <O>`, comes from the certificate; the pilot authority checks the organization's legal name before issuing. In strict, the organization in the statement must be the one in the certificate (`PRODUCER_ORG_DIFFERS`), and the accountable person must be the person a named-signer certificate was issued to (`ACCOUNTABLE_PERSON_DIFFERS`). With an organization seal certificate the organization names the person, and the result says so.

## 4. The warnings that matter

- `FILE_NOT_CHECKED`: no deliverable was loaded. Load it and verify again.
- `REGION_NOT_RECOMPUTED`: the browser did not check a PDF or Word file's section hashes; the command line does.
- `TIMESTAMP_MISSING`, `REVOCATION_MISSING` or `REVOCATION_STALE` (pilot profile only): the time is the signer's own claim, or the revocation data is missing or too old.

## 5. Who issued the time-stamp

The result names the time-stamp issuer and the anchor it chains to; the list, not the name, decides. Avok's pilot list, version 2026.11.4, accepts time-stamps only from the DigiCert, Sectigo and GlobalSign time-stamping certificate authorities it names, so the time depends on neither the signer nor Avok. If the line says the time-stamp comes from the signer's own certificate authority, the time is not independent of the signer.

## 6. What PASS does not mean

It does not prove that AI was used only as described, that any review happened, or that the deliverable is accurate. Evidence files are the contractor's, bound by hash; the verifier checks that a file you supply is the one bound, never that it is true. Truth rests with the accountable person, as on a paper declaration. The verifier is not an AI detector. Keep the deliverable and the record together on the contract file.
