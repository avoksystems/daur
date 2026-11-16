# Signed, region-level records of AI use in documents, verifiable offline

Technical disclosure. Published by Avok Systems Inc., Toronto, Canada, on the date of its first public posting. This document is published so that the methods it describes are available to the public and cannot be claimed in a later patent by anyone. It was drafted with an AI system and released by Avok Systems Inc. The normative detail is in the DAUR specification version 0.2, published with this disclosure; where the two differ, the specification describes the built system and this disclosure also describes variants.

## 1. Field and problem

Organisations that deliver reports, analyses, designs and other documents to governments and clients are increasingly asked to state whether and how AI tools were used in producing them. Today the statement is a form or a paragraph: it is not bound to the file it describes, it does not say which parts of the document the tools touched, it cannot be checked by the recipient without contacting the producer, and it says nothing about whether cited sources exist. A recipient who receives a revised file cannot tell whether the statement still applies, or to which sections.

The methods below produce, beside each deliverable, a signed and time-stamped record that binds a declaration of AI use to the exact file and to named regions of it, and a verifier that checks the record with no network connection.

## 2. Summary

A record is a canonical JSON document (RFC 8785) containing: the deliverable's whole-file SHA-256 digest; a list of regions, each with a typed selector, the identifier of a content extraction method and the SHA-256 digest of the region's canonical content; entries describing each AI tool used (tool and model identifiers and versions, provider, hosting location, use category, time, the regions affected); entries describing human review, including the explicit case of no review; the producing organisation and an accountable person; references to the rules the record answers; the identifier of a fixed declaration text; and evidence entries that bind supporting files, such as a citation check report, by their digests.

The record is signed as a COSE_Sign1 structure (RFC 9052) with the signer's certificate chain in the protected header (RFC 9360). The protected header also commits to a trust-list pin and to an ordered list of digests of the revocation evidence the signer captured before signing. An RFC 3161 time-stamp token over the signature bytes, from a time-stamping authority independent of the signer, and the revocation evidence itself are carried in the unprotected header.

A verifier, either a command-line program or a single HTML file running the Web Cryptography API, holds a trust list and never opens a network connection. It checks the file and region digests, the signature, the time-stamp, the certificate chain and the revocation state at the time-stamped signing time, compares the trust list it holds with the one the record pins and with a fingerprint the relying party expects, and reports one of a small set of outcomes with coded findings. When the file has changed, it recomputes each declared region and reports which regions changed and whether those regions were declared as AI-affected.

## 3. The record

### 3.1 Deliverable identity

The record names the file and gives the SHA-256 digest of its exact bytes, its size and media type, a producer-assigned identifier and version, and optionally the identifier of the contract or solicitation it is delivered under.

### 3.2 Regions

Each region has a selector type and reference. Types and reference grammars include: page range of a PDF (`pages 3-5`); heading of a Markdown or word-processing document, formed from the heading level marks and the heading text, with an occurrence suffix for repeated headings and a preamble region for text before the first heading; section identifier meaningful to a named extraction method; byte range of any file; and paragraph range. Further types in variants: worksheet and cell range of a spreadsheet; slide number of a presentation; file path or path and line range inside a code archive; time range of audio or video; message identifier inside an email archive.

Each hashed region names an extraction method. Methods in the published specification: raw bytes of a range; Markdown sections split on ATX headings outside fenced code blocks; PDF page text as returned by a named extractor family, canonicalised per page and joined by a form feed; word-processing sections grouped by heading paragraph styles; and paragraph ranges. Canonical text is Unicode NFC with line endings normalised to LF, trailing whitespace removed from each line using an explicitly enumerated whitespace set, leading and trailing blank lines removed and no trailing newline, then UTF-8. Variants add: removal of soft hyphens; removal of run-level formatting; exclusion of running headers and footers detected by repetition across pages; spreadsheet values rather than formulas, or both; slide text in reading order. A new method always takes a new identifier, so that a verifier that does not implement a method reports that it could not recompute rather than guessing.

A producer can enumerate regions automatically: one per PDF page, one per heading section, or fixed byte blocks of any other file. An AI-use entry with no declared location applies to all automatic regions.

In a variant for large documents, region digests are the leaves of a hash tree whose root is in the record, so that a holder can later reveal a subset of regions with inclusion proofs without revealing the rest.

### 3.3 AI-use entries

Each entry records the tool and model identifier and version, and where available the identifier returned by the model-serving interface at the moment of use (for example a `model` field or system fingerprint in an API response); the provider and the jurisdiction where the model was hosted; the use category (drafting, editing, summarising, translating, analysing data, generating code, generating images, searching, checking citations, and others); the extent (none, assistive, substantial); the time or period of use; and the regions affected.

These facts can be captured in several ways, all within this disclosure: from a metadata file the producer completes; by a plug-in in the editor that observes each AI interaction and the region into which output is inserted or that is edited in dependence on it; by a wrapper around the model API client that records identifiers from each response; or by importing the provider's usage logs and matching them to the document by time and content.

### 3.4 Human review, accountability and declaration

Review entries state the method (full read, sample read, technical check, other, or none) with a free-text statement, so that a record can truthfully declare that no person reviewed the output. The record names the producing organisation and an accountable person, and states whether that person is named in the signing certificate or named by the organisation. The declaration text is fixed by an identifier and stated in more than one language; a producer may substitute a buyer's own form text under its own identifier.

### 3.5 Rule references

The record may reference the rules it answers, such as a procurement manual section, a contract clause or a disclosure form, each with an identifier, a version or date and, optionally, structured answers to the questions the rule asks.

### 3.6 Evidence bound by digest

Evidence entries name a type, a file name, the SHA-256 digest of the file and an optional summary. The file is delivered beside the record, not inside it. A verifier given the file checks its digest and, for known evidence types, that the evidence describes the same deliverable digest and that any summary in the record matches the evidence, reporting a match, a missing file, an unknown type, a digest mismatch, evidence for another file, or a summary mismatch.

One evidence type is a citation check report. The checker extracts addresses from the deliverable (for Markdown, with CommonMark and GitHub-flavoured rules, so that punctuation inside link targets is kept), restricts checks to http and https addresses that resolve to public network addresses, applies a per-request and a total deadline, and records for each reference its location and one of: resolved, unresolved, blocked (the server refused automated requests), error, or not checked. The report states that a resolved address existed and answered when the check ran, not that the source supports the statement that cites it. In a variant, the checker also records a digest of each retrieved page and the matching of quoted text against it.

## 4. Signing

### 4.1 Envelope

The canonical record is the payload of a COSE_Sign1 structure with tag 18, signed with ES256 or EdDSA. The protected header carries the algorithm, the content type, the certificate chain (`x5chain`) and private-use header parameters for: the digests of the revocation snapshot items, as an ordered list checked by count and position; and the trust-list pin (list identifier, version and fingerprint). The unprotected header carries the time-stamp token and the revocation snapshot items (CRLs or OCSP responses). Because the digests are signed and the items are not, a verifier detects removal or replacement of a stapled item even though the items themselves sit outside the signed bytes. The same envelope is also offered wrapped in JSON with base64 fields for systems that cannot handle binary files.

### 4.2 Time-stamp

The signer obtains an RFC 3161 time-stamp token whose message imprint is a digest of the COSE signature bytes, from a time-stamping authority whose trust anchor the trust list names for time-stamping only. The verifier checks the token's signature (RSA PKCS#1 v1.5 or PSS with SHA-256, SHA-384 or SHA-512, or ECDSA on P-256, P-384 or P-521), requires the signing-certificate attribute (ESSCertID or ESSCertIDv2), builds the authority's chain to an anchor listed for time-stamping, and uses the token's time as the signing time for every other check. A record without a token is only accepted in a lenient profile, where the signer's own clock is reported as such.

### 4.3 Certificates

A certificate authority for the trust list issues two kinds of signing certificate, marked by different certificate policy identifiers: an organisation seal, which names an organisation and no person, and a named-signer certificate, which names a person within an organisation. Each certificate names exactly one organisation; a verifier fails a record whose declared producing organisation differs from it. With a named-signer certificate, the declared accountable person must be the person named; with a seal, the verifier reports that the organisation named the person and that the certificate does not. Issuance can start from a key pair, a public key or a certificate signing request, so that private keys never leave the producer. The authority checks the organisation's legal name in a public registry before issuing.

## 5. Trust lists

A trust list is a directory holding a canonical JSON manifest, a file of root certificates and the authority's revocation lists. The manifest gives the list identifier and version, the roots with their SHA-256 fingerprints and the purposes each root may serve (signing records, or time-stamping), a maximum age for revocation evidence, an expected next version date, and a flag marking a test list. The list's fingerprint is the SHA-256 digest of the canonical manifest, and it is the list's identity: an identifier and version are labels that anyone can copy, so a relying party compares the fingerprint the verifier shows with one its contract or authority names, or passes the expected fingerprint so that any other list fails.

The verifier validates the manifest against a schema before reading anything from it. Identifiers reserved for a known operator are bound to that operator's roots, so a list that reuses a reserved identifier with other roots fails. A list built on published test keys is recognised by those keys whatever its label, and every result under it is marked as a test.

## 6. Verification

The verifier performs a fixed sequence with no network access at any step:

1. Parse and validate the envelope and the record against the schema; reject unknown versions as unsupported rather than failed.
2. Compare the file's SHA-256 digest with the record; on a mismatch, recompute each region with its named method and classify it as unchanged, modified, missing or not recomputed, reporting separately the changed regions that were declared as AI-affected. An intact file whose regions do not reproduce with a different extractor gives a warning, not a failure.
3. Verify the COSE signature with the leaf certificate.
4. Verify the time-stamp token and take the signing time from it.
5. Recompute the digests of the stapled revocation items and compare them, by count and position, with the signed list.
6. Build the chain from the leaf to a root the trust list names for signing, checking validity at the signing time, key usage and the certificate policy.
7. Decide revocation at the signing time from the evidence: the stapled items, the trust list's own revocation lists and any later list the relying party supplies, preferring the latest that covers the signing time, honouring invalidity dates recorded after the fact, and treating evidence as valid only if it was issued no longer than the list's maximum age before the signing time. The result names the list that decided, with its issue time and digest. A relying party may pass the expected digest of the current revocation list, so that any other list fails.
8. Compare the pinned trust-list identifier, version and fingerprint with the list held and with any expected fingerprint; report a stale or different list rather than a silent pass or fail.
9. Check the producing organisation and the accountable person against the certificate.
10. Check evidence files supplied with the record.

Outcomes are: pass; pass with warnings; fail; unsupported; and test (for lists built on test keys). A strict profile, the default, turns a missing time-stamp, missing or stale revocation evidence and a carrier read without its source file into failures; a lenient profile reports them as warnings. The verifier reads no clock; a relying party may supply a verification time to learn whether the list was past its expected next version at that time.

The HTML verifier is a single file with the trust list built in and a content security policy that forbids network connections. It escapes and neutralises all text taken from records before display, including direction-override characters, so that a record cannot make the page say something it does not. A human-readable statement can be rendered from a record; the statement reports the outcome of the check that was run when it was made, says that the statement is not evidence, and never presents the record as verified in itself.

## 7. Carriage

The record travels as a sidecar file beside the deliverable, or inside it as a custom assertion of the C2PA content credential format, labelled under the publisher's domain, for formats that carry C2PA manifests. A verifier reading a record from such a carrier without the original source file reports that the source digest was not checked, which fails in the strict profile, and reports separately whether the C2PA signer is trusted. A record may be mapped to the C2PA AI disclosure assertion for consumers that read only that assertion.

## 8. Variants disclosed

The following are disclosed as variants whether or not the published reference implementation builds them.

1. Selective prompt disclosure. For each prompt, the capture component draws a random salt of at least 128 bits and computes SHA-256 over the salt and a canonical encoding of the prompt text and its metadata (model identifier, time, use category). The record carries the commitments, the regions each commitment is linked to and the count of commitments per region, and a flag stating whether client data entered any prompt. Prompts and salts stay in an encrypted store for a retention period the record states. To answer an auditor's question about a region, the holder discloses only the prompts and salts linked to that region; the auditor recomputes each commitment offline and checks that the number disclosed equals the signed count for the region, which proves the disclosure is complete for that region. Commitments may be the leaves of a hash tree whose root alone is in the record.
2. Signed trust-state bundles. The verifier ships with a bundle of signing anchors, time-stamping anchors, a revocation ledger with invalidity dates, a bundle version and date, signed by a trust-list authority key embedded in the verifier; updates are signed bundle files accepted only if their version is greater than the one installed; the verifier reports how many versions its bundle is behind the version a record pins.
3. Revisions. A record names the record it supersedes by digest, forming a chain across versions of a deliverable, so that a relying party can see which regions changed between versions and which AI uses were added.
4. Several signers. A prime contractor's record references, by digest, the records of subcontractors for the regions they produced, and the verifier checks each.
5. Batch verification. A verifier checks a folder of deliverables and records and produces a signed summary of the outcomes.
6. Keys in hardware. The signing key is held in a hardware token or platform key store and the record states the key protection class.
7. Transparency. Record digests are appended to a public append-only log, and the record carries an inclusion proof, so that a producer cannot later deny issuing a record.
8. Procurement integration. A procurement portal accepts the record with the deliverable, verifies it on receipt with the list the authority names, and stores the outcome with the contract file.
9. Other content. The same record structure applies to spreadsheets, presentations, source code archives, datasets, images, audio, video and email, with the selector types and extraction methods listed in section 3.2.

## 9. References

- RFC 8785, JSON Canonicalization Scheme. RFC 9052, CBOR Object Signing and Encryption (COSE): Structures and Process. RFC 9360, COSE header parameters for carrying X.509 certificates. RFC 3161, Time-Stamp Protocol. RFC 5816, ESSCertIDv2 update to RFC 3161. RFC 5280, X.509 certificate and CRL profile. RFC 6960, OCSP.
- C2PA Technical Specification, versions 2.2 and 2.4 (the latter adds an AI disclosure assertion).
- DAUR specification version 0.2, schemas and test vectors, published with this disclosure by Avok Systems Inc.
