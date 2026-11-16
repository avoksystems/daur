# Avok Attest specification, version 0.2

Deliverable AI-Use Record (DAUR): a per-deliverable, offline-verifiable record of how AI was used to produce a document delivered to a government buyer.

Licence: this specification is published under the Creative Commons Attribution 4.0 International licence (CC BY 4.0). You may share and adapt it with attribution to Avok Systems Inc. The reference implementation is licensed separately (Apache-2.0).

Status: draft 0.2, for pilot use. Fields, codes and header labels may change before 1.0. Changes are listed in CHANGELOG.md of the reference repository. Records written under this version carry `daur_version` `0.2`. A verifier of this version accepts records whose `daur_version` is `0.1` or `0.2` and applies the rules of this version to both (vector 26). The two record versions differ in the DAUR header labels (9.1) and in the members only a 0.2 record may carry (`evidence`, `evidence_refs`, section 4.9).

Editor: Avok Systems Inc., bd@avoksystems.ca.

## Revision history

- 0.1 (2026-11-08): first public draft.
- 0.2 (2026-11-10): verification rules tightened, DAUR header labels moved to the private-use range, evidence bound to the record and a citation check; every change is numbered in CHANGELOG.md under 0.2.0 and named in the section it changes.
- 0.1.1 (2026-11-08): renamed the C2PA assertion label to `ca.avoksystems.daur.v1` and the test trust list to `ca.avoksystems.attest.test`; added the signing-certificate extended key usage rule (11.4); stated the reference implementation's behaviour as the normative rule for the points an independent implementation found open (snapshot mismatch wording, revocation without a trust path, semantic subject comparison, a present but invalid token, unresolvable regions, DOCX sections and paragraphs, the whitespace set, the heading grammar, manifest purposes, trust directory globs, encoding and signature shape, the newer-verifier case, the TSA's scope, path length, the revocation date, code multiplicity, wrapper recognition and file names, C2PA reading); corrected two regime descriptions in 8.1; added interoperability notes (11.9) and the expected.json format (appendix C).

## 1. Scope

This specification defines:

- the Deliverable AI-Use Record (DAUR), a JSON record describing how AI tools were used to produce one deliverable, bound to the exact bytes of that deliverable and to named regions within it;
- a signature envelope for the record, based on COSE_Sign1 with an X.509 certificate chain, an RFC 3161 time-stamp token, a revocation snapshot, a protected commitment to that snapshot and a protected trust-list pin;
- a trust-list format that a verifier carries, including retroactive invalidity dates;
- a verification procedure with two profiles (pilot and strict), result codes and a plain-language statement;
- a C2PA carriage for the record.

A DAUR is a declaration by the producer. This specification does not define how to detect AI-generated text, does not certify producers or deliverables, and does not judge the quality of a deliverable. Software that implements it is described as "designed to meet" this specification; no conformance mark exists.

## 2. Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

Three roles are defined:

- a producer creates and signs records;
- a verifier checks an envelope against a deliverable and a trust list;
- a trust-list operator publishes trust lists.

A conforming producer, verifier or trust-list operator satisfies every MUST that applies to its role. Test vectors that exercise the requirements are listed in appendix C.

## 3. Terminology

- Deliverable: the file handed to the buyer, identified by its exact bytes.
- Record: the JSON object defined in section 4.
- Envelope: the COSE_Sign1 message defined in section 9 that carries the canonical record and the signature.
- Region: a named part of the deliverable with a hash over its canonical text or bytes (section 6).
- Signing time: the instant at which the verifier judges certificate validity; the time-stamp token's genTime when present and valid, otherwise the record's `created` time (section 11.3).
- Revocation snapshot: the CRLs or OCSP responses the producer held when signing, carried in the envelope.
- Trust list: the set of root certificates, manifest and invalidity dates a verifier accepts (section 10).
- Carrier: an asset in which a C2PA manifest carrying the envelope is embedded (section 12).

## 4. Record model

### 4.1 Overview

A record is a JSON object (RFC 8259). The normative schema is `daur-v0.2.schema.json` (JSON Schema draft 2020-12), published beside this document. Where this prose and the schema differ, the schema governs structure and the prose governs meaning. Records MUST NOT contain properties other than those defined; the schema sets `additionalProperties` to false at every object.

Top-level properties, all REQUIRED except `evidence`:

| Property | Type | Meaning |
| --- | --- | --- |
| `daur_version` | string, `"0.2"` (or `"0.1"` for a record of the previous version) | Record format version. Producers of this version write `"0.2"`. |
| `deliverable` | object | What was delivered (4.2). |
| `producer` | object | Who produced and signed it (4.3). |
| `ai_use` | array of objects | Each AI tool use (4.4); empty when no AI was used. |
| `human_review` | object | How a person reviewed the output (4.6). |
| `regime_references` | array of objects | Answers to disclosure regimes (4.7, section 8). |
| `declaration` | object | The signed declaration text (4.8, section 7). |
| `created` | string, RFC 3339 | When the record was created; UTC with a `Z` suffix is RECOMMENDED. |
| `evidence` | array of objects | OPTIONAL. Supporting files bound to the record by hash (4.9). Record version 0.2 only. |

All strings are Unicode. Unless stated otherwise a string MUST be between 1 and 2000 characters.

In a record of version 0.2 no string, member names included, may contain a C0 control character (U+0000 to U+001F), DEL (U+007F), a C1 control character (U+0080 to U+009F) or a Unicode bidirectional control (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), with one exception: a line feed (U+000A) is allowed in `human_review.statement`, in `declaration.text` and in the answers of `regime_references`, the producer's multi-line statements. A verifier reports a breach as `SCHEMA_INVALID` (vector 51), and a producer refuses to create or sign such a record. The schema cannot express the rule, so both reference verifiers check it beside the schema. A record of version 0.1 is not rejected for these characters (vector 52); 11.8 still governs how they are shown.

### 4.2 `deliverable`

| Property | Type | Rule |
| --- | --- | --- |
| `title` | string | Title of the deliverable as it appears to the buyer. |
| `contract_reference` | string | Contract, task authorisation or solicitation number. |
| `deliverable_id` | string | Deliverable identifier under the contract. |
| `file_name` | string | File name without directories (no `/` or `\`), at most 255 characters. |
| `file_sha256` | string | Lowercase hexadecimal SHA-256 of the exact bytes of the deliverable, 64 characters. |
| `version` | string | Deliverable version label. |
| `media_type` | string | Media type of the deliverable, for example `application/pdf`. |

The deliverable is the file as delivered. When a C2PA manifest is later embedded in the file (section 12), `file_sha256` refers to the file before embedding.

### 4.3 `producer`

| Property | Type | Rule |
| --- | --- | --- |
| `organisation.legal_name` | string | Registered legal name. It MUST equal an organisation (O) value of the signing certificate's subject under the comparison of 11.4. |
| `organisation.jurisdiction` | string | Jurisdiction of incorporation, for example `Canada (federal)`. |
| `organisation.business_number` | string | Business or registration number in that jurisdiction. |
| `accountable_person.name` | string | Person who takes responsibility for the deliverable. With a named-signer certificate it MUST be the certificate's common name; with an organisation seal certificate it is a person the organisation names, and verifiers say so (11.4). |
| `accountable_person.role` | string | Their role or title. |
| `signing_certificate.subject` | string | RFC 4514 string of the signing certificate subject. Attribute types outside the nine RFC 4514 short names MAY be written with a registered descriptor (`title`, `serialNumber`, `emailAddress`, see 11.4) or in dotted-decimal form; the reference producer writes `title` and otherwise follows RFC 4514. |
| `signing_certificate.serial` | string | Certificate serial number as lowercase hexadecimal without prefix or separators; leading zeros are permitted and verifiers compare the numeric value (11.4). |
| `signing_certificate.sha256_fingerprint` | string | Lowercase hexadecimal SHA-256 of the DER certificate. |

`signing_certificate` MUST describe the end-entity certificate in the envelope's `x5chain` (section 11.4). A producer MAY create the record without this object and let the signing step fill it in; the signed record MUST contain it.

### 4.4 `ai_use` entries

Each entry describes one tool used for one purpose. A tool used for two purposes is two entries. All properties are REQUIRED except `extent_percent`.

| Property | Type | Rule |
| --- | --- | --- |
| `tool` | string | Product name as marketed. |
| `model` | string | Model family or name. |
| `model_version` | string | Version or snapshot identifier as reported by the provider; `unknown` when not available. |
| `provider` | string | Legal entity operating the model. |
| `hosting_jurisdiction` | string | Jurisdiction in which prompts and outputs were processed. |
| `category` | enum | `none`, `research`, `drafting`, `editing`, `translation`, `summarisation`, `analysis`, `code_generation`, `image_generation`, `other`. |
| `extent` | enum | `none`, `minor`, `substantial`, `predominant` (4.5). |
| `extent_percent` | number 0 to 100 | OPTIONAL estimate of the share of the deliverable's content affected. |
| `locus` | array of regions | Where in the deliverable the tool's output appears (section 6). Empty when the use left no locatable trace, for example research. |
| `data_exposed.government_or_client_data` | boolean | Whether any data received from the buyer or client was provided to the tool. |
| `data_exposed.classes` | array of strings | Classes of data provided, in the buyer's vocabulary (for example `Protected A`); empty when none. |
| `retention` | string | What the provider retains and for how long, as understood by the producer. |
| `training_opt_out` | boolean or `"unknown"` | Whether the provider was bound not to train on the data. |
| `dates.start`, `dates.end` | ISO 8601 dates | Period of use, inclusive. |
| `evidence_refs` | array of evidence ids | OPTIONAL. Evidence entries (4.9) that bear on this use. Record version 0.2 only. |

A record with no AI use MUST have an empty `ai_use` array or entries whose `category` and `extent` are both `none`.

### 4.5 Extent vocabulary

| Value | Meaning |
| --- | --- |
| `none` | The tool produced no content that appears in the deliverable. |
| `minor` | Isolated wording, formatting or look-ups; the structure and substance are the producer's. |
| `substantial` | Sections or analyses were drafted or materially reshaped by the tool and then revised by a person. |
| `predominant` | Most of the content originates from the tool; the producer's work is selection and review. |

`extent_percent`, when present, SHOULD be consistent with the vocabulary: `minor` below 15, `substantial` 15 to 60, `predominant` above 60. Verifiers do not enforce this; buyers may.

### 4.6 `human_review`

| Property | Type | Rule |
| --- | --- | --- |
| `reviewer_role` | string | Role of the reviewer. |
| `method` | enum | `full_read`, `sampled`, `citation_verification`, `technical_check`, `other`, and from record version 0.2 `none` (meanings below). |
| `date` | ISO 8601 date | When the review was completed. |
| `statement` | string, at most 4000 characters | What was done, in the producer's words. REQUIRED, except with the method `none`, where it is OPTIONAL. |
| `evidence_refs` | array of evidence ids | OPTIONAL. Evidence entries (4.9) that record the review, for example a citation check or a review note. Record version 0.2 only. |

| `method` | Meaning |
| --- | --- |
| `full_read` | A person read the whole deliverable. |
| `sampled` | A person read a sample of the deliverable. |
| `citation_verification` | A person checked the deliverable's citations against their sources. |
| `technical_check` | A person checked the deliverable technically (figures, code, calculations). |
| `other` | Another kind of review, described only by the producer's `statement`. |
| `none` | No person reviewed the deliverable before the record was made. |

`none` is a valid and expected disclosure: a producer whose deliverable was not reviewed by a person says so with `none`, not with `other`. A record of version 0.1 MUST NOT use `none` (the schema rejects it). `reviewer_role` and `date` remain REQUIRED with every method; with `none` they name who made the disclosure and when, and a verifier does not present them as a review. With `none`, `statement` is OPTIONAL; when present, every surface prints it after the fixed sentence as `The producer adds: <statement>`, so that nothing the producer wrote reads as part of the sentence that no person reviewed the deliverable (vectors 50 and 81). The method is the producer's statement: no verifier check, code or result depends on it.

### 4.7 `regime_references`

Each entry carries `regime` (an identifier from section 8), an OPTIONAL `regime_name` (free text, at most 300 characters, REQUIRED in practice when `regime` is `OTHER`) and `answers`, an object whose keys are question identifiers matching `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` and whose values are strings of at most 4000 characters.

### 4.8 `declaration`

`text` is the declaration the accountable person makes, at most 4000 characters. `template_id` names the template it was taken from (section 7), or a producer-defined identifier when the text is bespoke. The verifier displays `text`; it does not interpret it.

### 4.9 `evidence`

A record of version 0.2 MAY list supporting files that the producer chose to bind to it. The record carries each file's name, media type and SHA-256, not the file: the file travels beside the record and is given to a verifier separately (11.10). A record of version 0.1 MUST NOT carry `evidence` or `evidence_refs` (the schema rejects them).

| Property | Type | Rule |
| --- | --- | --- |
| `id` | string | `E` followed by a number without leading zeros (`E1`, `E2`, ...), unique within the record. Producers number entries from `E1` in the order attached. |
| `type` | enum | `citation-check` (the output of the citation check, 4.10), `tool-log` (an export of an AI tool's activity log, bound by hash as exported), `review-note` (a note of the human review), `other`. |
| `description` | string | What the file is, in the producer's words. |
| `file_name` | string | File name without directories, at most 255 characters. |
| `media_type` | string | Media type of the file. |
| `sha256` | string | Lowercase hexadecimal SHA-256 of the file's exact bytes. |
| `size` | integer | OPTIONAL. Length of the file in bytes. |
| `created` | string, RFC 3339 | OPTIONAL. When the file was made (for a citation check, its finish time). |
| `produced_by` | string | OPTIONAL. The tool or person that made the file. |
| `summary` | object | OPTIONAL. A small object whose member names match `^[a-z][a-z0-9_]{0,63}$` and whose values are strings of at most 2000 characters or non-negative integers. For `citation-check` it carries at least `references`, `resolved`, `unresolved` and `not_checked` (counts, 4.10); the reference producer copies it from the citation-check file. |

Every id in an `evidence_refs` array (on an `ai_use` entry or on `human_review`) MUST name an entry of `evidence`, and ids MUST be unique. The schema cannot express either rule; verifiers check both and report a breach as `SCHEMA_INVALID`, and producers refuse to create or sign such a record. The `summary` is signed with the record and is what the producer stated; the details are in the file. Evidence is made by the producer and is what the producer chose to attach. A verifier checks its integrity (a supplied file is the one bound to the record) and its consistency (a supplied citation check was made for this deliverable and carries the summary the record states, 11.10), never that its content is true or complete (section 14). A citation check in particular is the producer's own run of the tool: a buyer who wants the strong check runs `daur evidence citations` on the deliverable themselves and reads the sources.

The reference producer attaches files with `daur create --evidence <type>=<path>` (repeatable) and `--evidence-desc <id-or-index>=<text>`; it hashes each file, fills the entry, and for a citation check copies the file's `summary` as it is and refuses a file made for a deliverable with another SHA-256 or whose summary the record could not state as it is (a member that is neither a non-negative integer nor text). `daur sign --evidence <path>` (repeatable) refuses to sign when a file given would fail 11.10.

### 4.10 Citation check

`daur evidence citations --file <deliverable> --out <citations.json>` extracts the references cited in a deliverable (http and https URLs, DOIs `10.<registrant>/<suffix>` and arXiv identifiers, from Markdown, plain text, PDF and DOCX) and asks each address whether it answers, once, at the time of the check. What it shows: each cited address existed and answered (or did not) when the check ran. What it does not show: that the source says what the deliverable claims, that the source is reliable, or that the address will answer later. A buyer that wants the first must read the sources.

A reference is taken whole, because a cut address is reported as missing when the source exists. In Markdown, an inline link or image `[text](destination "title")`, an autolink `<scheme:...>` and a link reference definition `[id]: destination "title"` give their destination as CommonMark defines it: in angle brackets, or a run without spaces and control characters whose parentheses balance, followed by an optional title; backslash escapes and entity references in it are resolved, and every other character, apostrophes included, belongs to it. A bare URL in prose, in PDF page text or in DOCX paragraph text starts at `http://` or `https://`, runs to white space or to one of `<`, `>`, `"` and the backtick, and then ends by the GFM extended autolink rules: trailing `?`, `!`, `.`, `,`, `:`, `*`, `_` and `~` are not part of it, nor is a closing parenthesis, bracket or brace with no partner inside the URL, nor an entity-like `&name;` at its end, nor the closing quotation mark of a quotation opened just before it; apostrophes and other characters inside it are kept. A PDF link annotation's URI and a DOCX hyperlink's target are taken whole. A URL found as a link destination is not taken again as a bare URL, and a URL in the text of a Markdown link is not a reference (its destination is). `reference` records the reference as written; `url` records the address as asked, with characters outside the RFC 3986 set percent-encoded as UTF-8, existing percent escapes left as they are, and a non-ASCII host name in its IDNA form.

The output is one JSON file in RFC 8785 canonical form (so its SHA-256 is stable), with members `header` (`format` `avok-attest-citation-check-v1`, `tool`, `version`, `deliverable_file_name`, `deliverable_sha256`, `started`, `finished`, `offline`, `timeout_seconds`, `max_references`, `resolver_base`, `allow_private`), `statement` (the sentence above on what the check shows), `summary` (`references`, `resolved`, `unresolved`, `blocked`, `error`, `not_checked`) and `references`, one object per distinct reference in order of first appearance: `reference` (as written), `kind` (`url`, `doi`, `arxiv`), `location` (`line N`, `page N` or `heading <text>`, the first place it appears), `url` (the address asked), `status`, `http_status`, `final_url`, `content_type`, `title` (the first 200 characters of an HTML page's title), `detail` (a short reason when the status is not `resolved`) and `checked` (RFC 3339, the time of the contact attempt, absent when the address was not contacted). `status` is `resolved` when the address answered with a success status (2xx, after redirects), `blocked` for 401, 403 and 429 (the server answered but refused an automated client), `unresolved` for a name that does not resolve and for 404 and 410, `error` for anything else (a timeout, another status, a broken connection, too many redirects), and `not_checked` when the check ran with `--offline` or after `--max` references. The reference tool asks with HEAD and falls back to GET, follows at most ten redirects, waits one second between requests to the same host and names itself and its version in the User-Agent. DOIs are asked at `https://doi.org/`, arXiv identifiers at `https://arxiv.org/abs/`.

The check contacts the addresses it finds in the document, from the machine it runs on, and the report records the fact and time of each contact attempt. Because the document may come from someone else, the reference tool limits what those contacts can do. It contacts only `http` and `https` addresses; a link of any other scheme (`file`, `ftp`, `mailto`, `data`, `javascript` and so on) is listed as `not_checked` with the reason and never opened. Before each request, and again for every redirect target, it resolves the host and refuses loopback, private, link-local (169.254.169.254 included), multicast, unspecified, reserved and other non-global addresses, IPv4 and IPv6 (an IPv4-mapped IPv6 address is judged as IPv4), and bare host names without a dot: these are `not_checked` with the reason `address not public`. It then connects to the address it checked, not to a second DNS answer, and therefore uses no proxy. `--allow-private` turns the refusal off, for tests on a local server, and the header's `allow_private` says so. It removes any user name and password from an address before the request and records the reference without them, and sends no cookies and no Referer. It reads a response body only for `text/html`, only to find the title, at most 262 144 bytes and without decompressing it, and it runs every request under an absolute deadline, per reference (`--timeout`) and for the whole run (`--total-timeout`), including while the status line and headers arrive: when the deadline passes, the connection is closed and the reference is `error`, `timed out`, so a server that sends one byte at a time cannot hold the check open. Page titles, final addresses and reasons are untrusted text: control characters and bidirectional control characters are removed, whitespace is collapsed and titles are capped at 200 characters; a verifier that shows text from a record or a report escapes it and makes no link from it.

## 5. Encoding, canonicalisation and files

### 5.1 Canonical form

The signed payload is the record serialised with the JSON Canonicalization Scheme (RFC 8785, JCS) and encoded as UTF-8. Producers MUST sign the JCS form. Verifiers MUST parse the payload, re-canonicalise it and compare the bytes; any difference is `ENVELOPE_MALFORMED` (section 11.7).

Records SHOULD avoid non-integral numbers; `extent_percent` is the only numeric field and SHOULD be an integer.

### 5.2 Media type and file names

The media type of a record and of the signed payload is `application/vnd.avok.daur+json`.

For a deliverable named `<file>`, producers SHOULD write:

- `<file>.daur.cose`: the COSE_Sign1 envelope, binary, authoritative;
- `<file>.daur.json`: a JSON wrapper for human inspection with two properties, `record` (the record as a JSON object) and `signature` (an object with `cose_sign1_b64`, the base64 of the envelope bytes, RFC 4648 section 4).

A verifier recognises a wrapper by content, not by file extension: an envelope file whose first byte after an optional UTF-8 byte order mark (EF BB BF) and any JSON whitespace (U+0020, U+0009, U+000A, U+000D) is `{` is parsed as a wrapper, the byte order mark being ignored, and anything else as the binary COSE_Sign1 (vector 41). `cose_sign1_b64` is decoded under RFC 4648 section 4 strictly: only the 64 alphabet characters and up to two `=` at the end, a length that is a multiple of four, and no whitespace or line breaks; anything else is `ENVELOPE_MALFORMED`. A verifier given the wrapper MUST verify the embedded envelope and MUST compare the JCS form of `record` with the signed payload; a difference is `RECORD_ALTERED`, while a `record` whose members are merely in another order is the same record (vector 25). The wrapper is never authoritative.

## 6. Regions

### 6.1 Region object

| Property | Type | Rule |
| --- | --- | --- |
| `type` | enum | `page_range`, `heading`, `section_id`, `byte_range`, `paragraph_range`. |
| `ref` | string | Reference in the grammar of 6.2, at most 500 characters. |
| `sha256` | string | OPTIONAL lowercase hexadecimal SHA-256 of the canonical content of the region. |
| `extraction_method` | string | REQUIRED when `sha256` is present (and vice versa): identifier of the method in 6.4. |

A region without `sha256` is declared but not verifiable; verifiers report `REGION_UNHASHED`.

### 6.2 Reference grammar

| Type | Grammar | Example |
| --- | --- | --- |
| `page_range` | `page N` or `pages N-M`, 1-based inclusive | `pages 3-5` |
| `heading` | `#` marks for the level, one space, the heading text; for repeated headings a space and `[k]` where k is the occurrence number; `(preamble)` for text before the first heading | `## 2. Scores`, `## Notes [2]` |
| `section_id` | an identifier meaningful to the named extraction method | `sec-4` |
| `byte_range` | `bytes S-E`, 0-based inclusive offsets | `bytes 1024-4096` |
| `paragraph_range` | `paragraph N` or `paragraphs N-M`, 1-based inclusive | `paragraphs 6-8` |

Heading references are formed as follows, for Markdown (`daur-markdown-atx-sections-v1`) and DOCX (`daur-docx-heading-sections-v1`) alike:

- Whitespace in this section is the set listed in 6.3, and nothing else (U+0085 is whitespace, U+FEFF is not).
- The reference is the `#` marks for the heading level (one to six), a single space (U+0020) and the heading text with surrounding whitespace removed. Trailing `#` characters are removed from the heading text together with any whitespace between the text and them, whether or not a space precedes them (so `## Title ##` and `## Title#` both give `## Title`); a `#` elsewhere in the text is kept.
- Only an ATX heading that starts at column 0 counts: one to six `#` characters followed by at least one space or tab. An indented `#` line, a `#` not followed by a space or tab, and a seventh `#` make the line ordinary text.
- A fenced code block opens on a line whose first characters after any leading whitespace are three or more backticks or three or more tildes, and closes at the next line whose first characters after any leading whitespace start with the same three-character marker (a line that starts with U+FEFF is therefore never a fence line, vector 42); a line inside a fence, and the fence lines themselves, are never headings.
- The k in `[k]` is the occurrence number of an otherwise identical reference in document order: the first occurrence has no suffix, the second is `[2]`, the third `[3]` (vector 36).
- A range reference (`page_range`, `byte_range`, `paragraph_range`) is read after removing surrounding whitespace; its keyword and number are separated by one or more whitespace characters, whitespace may surround the `-`, and its numbers are ASCII digits.
- `(preamble)` names the text before the first heading; it is only enumerated when its canonical text is not empty.

### 6.3 Canonical text

Text regions are hashed over their canonical text: Unicode NFC; CR LF and CR replaced by LF; trailing whitespace removed from every line; leading and trailing blank lines removed (a blank line is one that is empty after that removal); UTF-8 encoding; no trailing newline. The empty string hashes to the SHA-256 of zero bytes; a text region whose canonical text is empty (an image-only PDF page, say) therefore binds nothing, which is inherent to text regions.

Trailing whitespace is the set of code points for which Python's `str.isspace()` is true, listed here so that no implementation needs Python to reproduce it: U+0009 to U+000D, U+001C to U+001F, U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F and U+3000. Nothing else is whitespace for this purpose: in particular U+FEFF is content, so a leading byte order mark in a Markdown file is part of the first line (which is then not a heading) and is hashed. Implementations MUST NOT use a language's default whitespace class (JavaScript's `\s` and `String.prototype.trim`, for instance, include U+FEFF and exclude U+001C to U+001F and U+0085). This set is the only whitespace in this specification wherever text is trimmed or collapsed on the way to a result: canonical text, heading text and fence lines (6.2), range references (6.2), distinguished names and serial numbers (11.4), the organisation and person comparison (11.4), times and trust-list versions.

For `daur-pdf-page-text-v1` each page's text is canonicalised on its own, the per-page results are joined with a single U+000C, and the joined bytes are hashed without a second canonicalisation (a form feed is whitespace, so a second pass would alter the result when a page is empty).

### 6.4 Extraction methods

| Identifier | Applies to | Content hashed |
| --- | --- | --- |
| `daur-bytes-v1` | `byte_range`, any file | The raw bytes of the inclusive range. `E` MUST be below the file length. |
| `daur-markdown-atx-sections-v1` | `heading`, Markdown | Split on ATX headings (1 to 6 `#` followed by a space) that are outside fenced code blocks (``` or ~~~ fences). A section is the heading line and every line up to the next heading of any level. Canonical text of the section. |
| `daur-pdf-page-text-v1` | `page_range`, PDF | Text of each page as returned by pypdf `Page.extract_text()` (pypdf 4 or later), canonicalised per page; pages are joined with a single form feed (U+000C) and the result is not canonicalised again (6.3). |
| `daur-docx-heading-sections-v1` | `heading`, DOCX | Body paragraphs (as python-docx `Document.paragraphs` exposes them: in document order, table cell paragraphs excluded) grouped into sections. A section starts at a paragraph whose style name is `Title` (level 1) or `Heading N` (level N, matched case-insensitively) and runs to the paragraph before the next heading paragraph of any level, so a level 1 section does not contain its level 2 subsections; paragraphs before the first heading form the `(preamble)` region, as for Markdown. The `ref` is formed as in 6.2 from the heading paragraph's text. The section's paragraph texts (the heading paragraph included) are joined with LF and canonicalised. |
| `daur-paragraphs-v1` | `paragraph_range` | DOCX: the body paragraphs in document order as python-docx `Document.paragraphs` exposes them, heading paragraphs and empty paragraphs included, table cell paragraphs excluded. Text and Markdown (after NFC and line ending normalisation): a block boundary is one or more consecutive lines that are empty or contain only U+0020 and U+0009; blocks whose canonical text is empty are not counted; fenced code receives no special handling, so a blank line inside a fence separates blocks. The paragraphs of the range are canonicalised individually and joined with LF. |

New methods MUST use a new identifier. A verifier that does not implement a method MUST report `REGION_NOT_RECOMPUTED` rather than guess. Page text extraction is implementation-sensitive; a region computed with one extractor may not reproduce with another, which is why the identifier pins the extractor family and why a mismatch on an intact file is a warning, not a failure (11.6).

### 6.5 Automatic regions

A producer tool offering automatic regions ("auto") SHOULD enumerate: PDF, one `page_range` per page; DOCX, one `heading` per heading section; Markdown, one `heading` per ATX section; any other file, `byte_range` regions of 64 KiB (65 536 bytes) in order, the last one shorter. An `ai_use` entry with no declared locus and `extent` other than `none` receives all natural regions.

## 7. Declaration templates

Template identifiers match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`. Four templates are defined by this version. New records SHOULD use `avok-attest-declaration-v0.2-en` or `-fr`, and the reference producer uses the English one by default. The 0.1 templates remain valid identifiers.

`avok-attest-declaration-v0.2-en`:

> This record describes how artificial intelligence tools were used in producing the deliverable identified above, and what review, if any, followed. To the best of the producer's knowledge after the review, if any, described in this record, the statements in this record are accurate. This record is a declaration by the producer. It is not a certification by any third party, and it does not assess the quality or accuracy of the deliverable. Where a citation check is attached, it reports which cited addresses answered when the check ran; it does not establish that a source supports the statement that cites it.

`avok-attest-declaration-v0.2-fr`:

> Le présent dossier décrit la manière dont des outils d'intelligence artificielle ont été utilisés pour produire le livrable désigné ci-dessus, ainsi que l'examen qui a suivi, le cas échéant. À la connaissance du producteur, après l'examen décrit dans le présent dossier, le cas échéant, les énoncés qui y figurent sont exacts. Ce dossier est une déclaration du producteur. Il ne constitue pas une certification par un tiers et n'évalue ni la qualité ni l'exactitude du livrable. Lorsqu'une vérification des citations est jointe, elle indique quelles adresses citées ont répondu au moment de la vérification; elle n'établit pas qu'une source appuie l'énoncé qui la cite.

The 0.2 wording replaces two statements of the 0.1 text: "takes responsibility for its content", which reached beyond AI use to the whole deliverable, and "has reviewed the deliverable", which the record asserted even where its human-review section described something narrower. The 0.2 wording is pending review by counsel and may change before 1.0. A producer MAY substitute a buyer's own form text under its own identifier, as the next paragraph allows.

`avok-attest-declaration-v0.1-en`:

> This record describes how artificial intelligence tools were used in producing the deliverable identified above. The accountable person named in this record has reviewed the deliverable as described under human review and takes responsibility for its content. This record is a declaration by the producer. It is not a certification by any third party and it does not assess the quality or accuracy of the deliverable.

`avok-attest-declaration-v0.1-fr`:

> Le présent dossier décrit la manière dont des outils d'intelligence artificielle ont été utilisés pour produire le livrable désigné ci-dessus. La personne responsable nommée dans ce dossier a examiné le livrable selon la méthode décrite à la rubrique Examen humain et assume la responsabilité de son contenu. Ce dossier est une déclaration du producteur. Il ne constitue pas une certification par un tiers et n'évalue ni la qualité ni l'exactitude du livrable.

A producer that uses a template identifier MUST use its text verbatim. A producer MAY use its own text under its own identifier.

## 8. Regime references

### 8.1 Regime identifiers

The identifiers below name disclosure regimes a buyer may ask about. The descriptions are identification aids only: this specification does not interpret any regime, and producers MUST consult the regime text itself.

| Identifier | Identifies |
| --- | --- |
| `GSAR_552_239_7001` | US General Services Administration Acquisition Regulation clause 552.239-7001. |
| `CA_SCM_2302` | California, State Contracting Manual section 2302 (Department of General Services). |
| `CA_CEC_50` | California Energy Commission form CEC-50. |
| `US_COMMERCE_FAIR` | US Department of Commerce AI use provisions identified as FAIR. |
| `USTDA_AI_CLAUSE` | US Trade and Development Agency AI clause. |
| `UK_PPN_017` | United Kingdom Procurement Policy Note 017. |
| `TBS_GENAI_GUIDE` | Treasury Board of Canada Secretariat guide on the use of generative AI. |
| `NDAA_FY2026_S1532` | US National Defense Authorization Act for fiscal year 2026, section 1532. |
| `OTHER` | Any other regime, named in `regime_name`. |

### 8.2 Question catalogue

Any regime reference MAY answer these common questions; regime-specific identifiers are also permitted.

| Question id | Question |
| --- | --- |
| `ai_used` | Was AI used in producing the deliverable? |
| `tools_and_models` | Which tools, models and providers were used? |
| `extent_and_locus` | To what extent, and in which parts of the deliverable? |
| `data_exposed` | Was government or client data exposed to the tool, and what classes? |
| `hosting_jurisdiction` | Where was the tool hosted and where was data processed? |
| `training_opt_out` | Was the data excluded from provider training? |
| `human_review` | How was the output reviewed by a person? |
| `accountable_person` | Who is accountable for the deliverable? |

Answers are free text and are signed with the record. They repeat information held in structured fields so that a reader of the regime's form can be served directly; the structured fields govern when the two disagree.

## 9. Signature envelope

### 9.1 COSE_Sign1 profile

The envelope is a COSE_Sign1 message (RFC 9052) tagged with CBOR tag 18. The payload is the canonical record (5.1) and MUST be present (detached payloads are not permitted). `external_aad` is empty.

Protected header parameters:

| Label (record 0.2) | Label (record 0.1) | Name | Value | Requirement |
| --- | --- | --- | --- | --- |
| 1 | 1 | alg | `-7` (ES256) or `-8` (EdDSA, Ed25519) | REQUIRED |
| 3 | 3 | content type | the text string `application/vnd.avok.daur+json` | REQUIRED |
| 33 | 33 | x5chain (RFC 9360) | DER certificates, end-entity first; a single bstr for one certificate, an array of bstr otherwise | REQUIRED |
| -70003 | 7003 | DAUR revocation-snapshot commitment | array of bstr, each the 32-byte SHA-256 of the item at the same index of the revocation snapshot | REQUIRED when the snapshot is present |
| -70004 | 7004 | DAUR trust-list pin | map with text keys `trust_list_id`, `version`, `sha256` (10.4) | RECOMMENDED; strict verifiers warn when absent |

Unprotected header parameters:

| Label (record 0.2) | Label (record 0.1) | Name | Value | Requirement |
| --- | --- | --- | --- | --- |
| -70001 | 7001 | DAUR time-stamp token | bstr, DER `TimeStampToken` (RFC 3161) whose message imprint is SHA-256 of the signature bytes | RECOMMENDED (pilot), REQUIRED (strict) |
| -70002 | 7002 | DAUR revocation snapshot | array of bstr, each a DER CRL (RFC 5280) or a DER `OCSPResponse` (RFC 6960) | RECOMMENDED (pilot), REQUIRED (strict) |

Label range. RFC 9052 section 11.1 sets the registration procedures of the IANA "COSE Header Parameters" registry by integer value (registry read 2026-11-10 at `https://www.iana.org/assignments/cose`): 1 to 255 Standards Action With Expert Review, 256 to 65535 Specification Required, greater than 65535 Expert Review, -1 to -65536 delegated to the "COSE Header Algorithm Parameters" registry, and integers less than -65536 Private Use. The labels 7001 to 7004 used by record version 0.1 therefore lie in the Specification Required range, which earlier drafts wrongly called private; they are not registered. Record version 0.2 uses the private-use labels -70001 to -70004. Registration of the four parameters will be requested if the format is published as a stable specification; until then the private-use labels apply. Elsewhere in this specification the parameters are named by their record 0.2 labels; in a record of version 0.1 the label in the second column takes its place.

Labels and record version (vectors 26, 44 and 45). A producer writing a record with `daur_version` `0.2` MUST use the labels of the first column only. A verifier reads the DAUR parameters under the labels of the record's own `daur_version`: 7001 to 7004 when it is `0.1`, -70001 to -70004 otherwise (`0.2`, or a value the schema rejects). A DAUR parameter under the other version's label is treated as absent, and the verifier records the informational `HEADER_LABEL_NOT_FOR_VERSION` naming the label; the outcome then follows from the absence (a missing time-stamp, snapshot, commitment or pin). The labels are scoped to envelopes whose content type is `application/vnd.avok.daur+json`.

The protected header MUST be encoded with CBOR deterministic encoding (RFC 8949 section 4.2.1). Signers MUST use raw `r || s` ECDSA signatures for ES256 as required by RFC 9053. Deterministic ECDSA (RFC 6979) is RECOMMENDED. The deterministic encoding and the `x5chain` shape (a single bstr for one certificate) are producer requirements: a verifier does not reject a protected header that is not deterministically encoded (the signature covers the bytes as sent) and accepts a one-element `x5chain` array (11.5 step 1).

### 9.2 Signing procedure

1. Fill `producer.signing_certificate` from the end-entity certificate.
2. Validate the record against the schema; refuse to sign an invalid record unless explicitly producing a test case.
3. Gather the revocation snapshot the signer holds for its own certificate chain (CRLs or OCSP responses, DER). Compute the SHA-256 of each item.
4. Build the protected header with labels 1, 3, 33, -70003 (when the snapshot is not empty) and -70004 (the pin of the trust list the signer expects verifiers to hold).
5. Compute the signature over `Sig_structure` (RFC 9052 section 4.4) with the canonical payload.
6. Obtain a time-stamp token over the signature bytes (RFC 3161, imprint SHA-256) and place it under label -70001.
7. Place the snapshot under label -70002 and encode the message.

The snapshot MUST be fixed before step 5 because the protected header commits to it. A verifier that finds items under -70002 that do not match -70003 treats the snapshot as replaced (11.5).

### 9.3 CDDL

```
DAUR-Envelope = #6.18(COSE_Sign1)

DAUR-Protected = {
  1 => -7 / -8,
  3 => "application/vnd.avok.daur+json",
  33 => bstr / [ 2* bstr ],
  ? -70003 => [ + bstr .size 32 ],
  ? -70004 => { "trust_list_id" => tstr, "version" => tstr, "sha256" => tstr, * tstr => tstr }
}

DAUR-Unprotected = {
  ? -70001 => bstr,          ; DER TimeStampToken
  ? -70002 => [ + bstr ]     ; DER CRLs or OCSPResponses
}
```

For a record of version 0.1 the same structure applies with 7003, 7004, 7001 and 7002 in place of -70003, -70004, -70001 and -70002.

## 10. Trust lists

### 10.1 Contents

A trust list is a directory containing:

- `avok-pilot-roots.pem` (or any `*.pem`): root certificates in PEM;
- a manifest JSON file (10.2);
- OPTIONAL CRL files (`*.crl`, `*.crl.pem`, `*.crl.der`) that supplement the envelope's snapshot; the trust list fingerprint does not cover them (10.4).

A verifier reads root certificates from every `*.pem` file and CRLs from every `*.crl` and `*.crl.der` file and from every PEM CRL block, including the `*.crl.pem` files; a `*.crl.pem` file therefore contributes CRLs and not roots (it SHOULD contain no certificate block). The manifest is the `*.json` file whose top level has a `roots` member. Only roots listed in the manifest are anchors in any case.

A verifier MUST ship with a bundled trust list and MUST allow the user to supply another one. A trust list supplied to a verifier MUST be a directory that contains a manifest; a list without a manifest (a single PEM file, or a directory with no manifest) is `TRUST_LIST_INVALID`, FAIL in the strict profile and WARN in the pilot profile, and the reference command-line verifier's `--trust` option names such a directory. Roots that are not listed in the manifest MUST NOT be anchors when a manifest is present. A verifier MUST display the name, identifier, version and fingerprint (10.4) of the trust list it used, next to the outcome: the reference command line prints `Trust list: <name>, <id> <version>, fingerprint <64 hex>` on the line directly under the outcome, the browser verifier shows the same inside its verdict banner, and the statement PDF inside its check box.

### 10.2 Manifest

| Property | Type | Rule |
| --- | --- | --- |
| `trust_list_id` | string | Stable identifier of the list in reverse-domain form, for example `ca.avoksystems.attest.pilot`: ASCII lower-case letters, digits, dots and hyphens only, matching `^[a-z0-9]+([.-][a-z0-9]+)*$` (so no separator at either end or next to another), at most 128 characters. The test list published with the reference implementation is `ca.avoksystems.attest.test`; its root key is public and it establishes no identity. The identifier is a label: anyone can write any identifier into a manifest, and only the fingerprint (10.4) identifies a list. Identifiers under `ca.avoksystems.attest.` are reserved (10.7). |
| `trust_list_name` | string | Display name. |
| `trust_list_version` | string | Version (10.3). |
| `issued` | RFC 3339 | When this version was published. |
| `roots[]` | array | One entry per root: `subject`, `serial`, `sha256_fingerprint` (DER SHA-256, lowercase hex), `not_before`, `not_after` (the window during which the list trusts the root, RFC 3339), `pem_file`, `purposes`. `purposes` is an array of `daur-signing` and `time-stamping`; an entry without the member is listed for both, and a member that is not an array of strings lists the root for nothing. A root anchors a signer path only when listed for `daur-signing` and a time-stamping certificate's path only when listed for `time-stamping` (11.4). `daur ca trust --timestamp-root <pem>` adds public time-stamping roots with `purposes: ["time-stamping"]`. |
| `test` | boolean | OPTIONAL. `true` marks a test list (10.6); a value that is not a boolean makes the manifest invalid (below). |
| `revocation_max_age` | string | OPTIONAL. ISO 8601 duration of the form `PnD` or `PTnH` (for example `P8D` for a weekly CRL). Revocation data that covers T establishes "not revoked" only when its `thisUpdate` is at most this long before T (11.5 step 8). Another form makes the manifest invalid (below). |
| `next_update` | RFC 3339 | OPTIONAL. When the operator expects to publish the next version. A verifier reads no clock: it records the informational `TRUST_LIST_PAST_NEXT_UPDATE` when the signing time, or a verification time the user supplies (`daur verify --verification-time`), is after it. |
| `invalidity_dates[]` | array | Zero or more entries `{ "certificate_sha256": hex, "invalid_from": RFC 3339, "reason": string }` (10.5). |
| `generator`, `notes` | string | Informational. |

A verifier validates the manifest before it reads anything else from it. The structure is given by the JSON Schema `spec/trust-manifest-v0.2.schema.json` (packaged as `data/trust-manifest-v0.2.schema.json`; both reference verifiers use it): the members above have the types and forms the table gives (`trust_list_version` the grammar of 10.3, times RFC 3339 and real calendar times, `sha256_fingerprint` and `certificate_sha256` lowercase hexadecimal, `purposes` an array of the two purpose names, `revocation_max_age` `PnD` or `PTnH`), and `trust_list_id`, `trust_list_version` and `roots` are REQUIRED. Three rules sit beside the schema because a schema cannot state them. The manifest is I-JSON (RFC 7493): no object has two members with the same name, no string holds a lone surrogate, and every number is an integer whose magnitude is at most 2^53-1, which every JSON reader holds exactly. No string, member names included, carries a C0 or C1 control character, DEL or a bidirectional control. A manifest that breaks any rule is `TRUST_LIST_INVALID`, FAIL in both profiles: the verifier reads nothing from it (no root of the list is an anchor, and no identifier, name, version or fingerprint is shown), stops, and gives no other finding (vectors 55 to 57 and 67 to 73). Only a trust list with no manifest at all keeps the pilot profile's WARN (10.1). The reference CA (`daur ca init`, `daur ca trust`) refuses to write a manifest that breaks a rule. A file that is not JSON at all is not taken for a manifest.

### 10.3 Versions

`trust_list_version` MUST be `YYYY.MM`, optionally followed by `.N` for a further revision and by `-label` for a human label, for example `2026.03-pilot`. Versions are ordered by their numeric components; the label is ignored for ordering. Two versions whose numeric components are equal are the same version and MUST have the same content.

### 10.4 Trust list fingerprint and pin

The fingerprint of a trust list is the lowercase hexadecimal SHA-256 of the JCS (RFC 8785) canonical form of its manifest JSON. It is the only thing that identifies a list. The `trust_list_id`, `trust_list_name` and `trust_list_version` are labels that anyone can copy into a manifest of their own, and a time-stamping or root certificate's names are chosen by whoever controls the list's root, so a relying party MUST NOT treat a matching identifier, version or certificate name as evidence that it holds the list it expects.

A contract or contracting authority that relies on records names the fingerprint of the trust list to use. A verifier takes it as an OPTIONAL input (`daur verify`, `daur c2pa read` and `daur render` take `--trust-fingerprint <hex>`; the Python library the keyword argument `trust_fingerprint`; the browser core the input member `trustFingerprint`; the browser verifier the field "Expected trust list fingerprint"; case, colons and white space are ignored). When it is given and differs from the loaded list's fingerprint, the outcome is FAIL `TRUST_LIST_FINGERPRINT_MISMATCH` in both profiles (vector 58), and when it matches the verifier records the informational `TRUST_LIST_FINGERPRINT_MATCH` (vector 59). When it is not given in the strict profile, the verifier records the informational `TRUST_LIST_FINGERPRINT_NOT_CHECKED`, whose message tells the reader to compare the fingerprint shown under the outcome with the one their contract or contracting authority names.

Whether the fingerprint was compared is part of the outcome, in every profile. When no expected fingerprint was given, the reference command line prints a pass as `PASS (trust list fingerprint not compared)` (and `PASS with warnings (<codes>) (trust list fingerprint not compared)`), the browser verifier's banner carries the sentence "Trust list fingerprint not compared: check it against the one your contract names." inside the verdict, and the statement PDF's check box says the fingerprint was not compared. When it was given and matched, the command line prints `PASS (trust list fingerprint matches the expected one)`, and the banner and the check box say "Trust list fingerprint matches the expected one.". JSON output carries `"trust_fingerprint_checked": false` or `true`. The exit status does not depend on it (11.2).

The fingerprint covers the manifest and, through the root fingerprints the manifest lists, the roots. It does not cover revocation lists. CRLs are renewed far more often than a list version is published (the pilot renews its CRL before every signing session), and a trust directory carries them beside the manifest by design, so the same fingerprint identifies a directory with the current CRL, with an older one or with none: anyone who passes the directory on, the producer included, can remove or replace its CRLs without changing the fingerprint. A matching fingerprint therefore says nothing about revocation. A relying party obtains the current revocation list from the trust list operator, not from the producer, and supplies it to the verifier (`daur verify --crl`, or the page's revocation lists); when the contracting authority publishes the current list's SHA-256, the verifier checks it (`--crl-fingerprint`, 11.5 step 8). The result line `Revocation: decided by ...` (11.5 step 8) says which list decided, where it came from and its SHA-256, and says when no later list was available.

The pin placed under protected label -70004 is a CBOR map with text keys:

- `trust_list_id`: the manifest's `trust_list_id`;
- `version`: the manifest's `trust_list_version`;
- `sha256`: the fingerprint of the list.

The pin records which trust state the producer expected a verifier to hold. It is covered by the signature and cannot be changed after signing.

### 10.5 Retroactive invalidity

An `invalidity_dates` entry declares that the certificate with the given fingerprint is not to be trusted for any signature whose signing time is at or after `invalid_from`, regardless of the certificate's own validity period and regardless of CRL or OCSP status. Signatures with an earlier signing time remain valid. The mechanism lets a trust-list operator respond to a compromise or a debarment that the issuing CA has not, or not yet, reflected in its revocation data, and lets it set the effective date independently of CRL publication times.

Operators MUST publish a new version of the list when adding an entry. Verifiers MUST apply entries to every certificate in the signer's path, to the trust anchor and to the time-stamping certificate's path.

### 10.6 Test lists

A trust list is a test list when any of the following holds: its manifest carries a `test` member with any value other than `false`; its `trust_list_id` ends in `.test`; or any of its anchors has a public key equal to one of the published test keys. Keys are compared by the public key itself, not by its encoding in a certificate: both verifiers re-encode the key as its canonical DER SubjectPublicKeyInfo and compare the SHA-256 of that. The canonical form is, for an EC key, the AlgorithmIdentifier `id-ecPublicKey` with the named curve and the uncompressed point (04, X, Y), a compressed point being decompressed first; for an RSA key, `rsaEncryption` with NULL parameters and an RSAPublicKey whose modulus and exponent are minimal DER integers; for an Ed25519 key, `id-Ed25519` without parameters and the 32-byte key; any other key is hashed as the certificate carries it. This is the form Python's `cryptography` writes, so the registry's hashes are those of `public_bytes(DER, SubjectPublicKeyInfo)` (vector 76: the published test root key as a compressed point). The published test keys are those under `vectors/keys/` of the reference repository, listed in the registry `data/reserved-lists.json` (10.7); they include the root key the 0.1.x vectors used. The key rule applies whatever the manifest says, and also to a list without a manifest, so editing a test list's manifest does not make it a real one (vectors 53 and 54). A test list establishes no identity: its root keys are typically published so that anyone can exercise the format. A verifier MUST NOT report PASS from a test list unless the user has explicitly put it in test mode; outside test mode the outcome is FAIL with `TEST_TRUST_LIST`, in both profiles (vector 27). In test mode every result MUST be labelled as a test result: the reference command-line verifier takes `--allow-test-trust` on `daur verify`, `daur c2pa read` and `daur render` and then prints `TEST RESULT (test trust list: proves nothing about any real signer)` as the first line, before the outcome; the Python library takes the keyword argument `allow_test_trust` and the browser core the input member `allowTestTrust`; JSON output carries `"test_trust_list": true` whenever the list is a test list, and its `result` reads `TEST PASS`, `TEST PASS with warnings` or `TEST FAIL` (the browser core also `TEST UNSUPPORTED`). A command-line verifier exits 4 for a pass obtained from a test list (11.2), so that a script that reads only the exit status cannot take a test pass for a real one. The browser verifier shows the same sentence in a persistent red bar whenever the bundled or loaded list is a test list, offers test mode as an explicit choice that is off by default, and never shows a test-list verdict in the colour of a pass ("TEST PASS" or "TEST FAIL"). The list shipped in `trust/` of the reference repository is a test list (`test` true, identifier `ca.avoksystems.attest.test`, root `CN=Avok Attest TEST Root (published key),O=Avok Attest test vectors,C=CA`), and every vector except vectors 27, 53 to 57, 67 to 73 and 76 is verified in test mode. The reference producer tools refuse a published test key unless told the material is for tests: `daur ca init` for the root key and `daur ca issue` for the key it certifies (both `--test`), `daur key new --force` over a file that holds one (`--test`), and `daur sign` (`--allow-test-key`; library `allow_test_key`), each with a message that says why.

### 10.7 Reserved identifiers

Trust list identifiers beginning `ca.avoksystems.attest.` are reserved for lists that Avok Systems publishes, and so is `ca.avoksystems.attest` itself. A small registry, `data/reserved-lists.json` in the reference package (schema `data/reserved-lists.schema.json`), shipped with both reference verifiers and bundled into the browser page, names each reserved identifier with its whole root set: every root the list may carry, by SHA-256 fingerprint, with the purposes it is listed for and whether the list must carry it.

- `ca.avoksystems.attest.pilot`: for `daur-signing` exactly the Avok pilot root, SHA-256 fingerprint `383db6cfad937c250d9c1d0973839a7d12bd99bdbfdd3f3ad234deda1f156b25`, which is required; for `time-stamping` only the certificates with SHA-256 fingerprints `ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd` (DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1), `b53ac15cc1afb6e2ac06828f555bb3bf5bad8b2bac1733ce4cb7aafe729356de` (Sectigo Public Time Stamping Root R46) and `6afbc07c724c6f75c7743392f32bf5780bd5dd39268544d4882e7aec1add0282` (GlobalSign Timestamping Root R45), each permitted and none required.
- `ca.avoksystems.attest.test`: the test root of the reference repository, whose key is published, listed for `daur-signing` and `time-stamping` and required, and the test time-stamping root, listed for `time-stamping` and permitted.

A list that claims a registered identifier is FAIL `TRUST_LIST_ID_RESERVED` in both profiles when it lacks a required root, carries an anchor outside the registered set, or lists a registered root for other purposes than the registered ones (vector 54); so is a list that claims an unregistered identifier under the reserved prefix. The registry also lists the SubjectPublicKeyInfo SHA-256 of every published test key (10.6). It is data: a new reserved list, a new root of a reserved list or a new test key is a new registry version, not a change of rule. Avok updates the registry with each pilot list version that changes the roots, so a verifier release that predates such a list version refuses it until it carries the new registry.

## 11. Verification

### 11.1 Inputs and profiles

Inputs: the deliverable bytes (OPTIONAL, see 11.6), the envelope (`.daur.cose` or `.daur.json`), a trust list (10.1), a profile, whether test mode is on (10.6), and OPTIONAL further CRLs, a verification time (11.5 step 8, 10.2), evidence files (11.10), the expected trust list fingerprint (10.4) and expected revocation list fingerprints (11.5 step 8). The strict profile is the default of every reference tool (`daur verify`, `daur c2pa read`, `daur render` and the browser verifier); the pilot profile is chosen explicitly, and a verifier using it states before the outcome that a missing time-stamp and missing revocation data are warnings in that profile (the reference tools print `Pilot profile: a missing time-stamp and missing revocation data are warnings in this profile, not failures; use the strict profile for a contractual result.`).

| Aspect | `pilot` | `strict` |
| --- | --- | --- |
| Time-stamp token (-70001) | RECOMMENDED; absence is WARN `TIMESTAMP_MISSING`, validity judged at `created` | REQUIRED; absence is FAIL `TIMESTAMP_MISSING` |
| Revocation data covering the signing time | RECOMMENDED; absence is WARN `REVOCATION_MISSING` or `REVOCATION_STALE` | REQUIRED; absence is FAIL `REVOCATION_MISSING` |
| Snapshot commitment (-70003) consistent with -70002 | Mismatch is WARN `REVOCATION_SNAPSHOT_MISMATCH` | Mismatch is FAIL `REVOCATION_SNAPSHOT_MISMATCH` |
| Trust-list pin (-70004) | Absence is informational | Absence is WARN `TRUST_PIN_MISSING` |
| Trust list without a manifest (10.1) | WARN `TRUST_LIST_INVALID` | FAIL `TRUST_LIST_INVALID` |
| Manifest that breaks the rules of 10.2 | FAIL `TRUST_LIST_INVALID` | FAIL `TRUST_LIST_INVALID` |
| Test list outside test mode (10.6) | FAIL `TEST_TRUST_LIST` | FAIL `TEST_TRUST_LIST` |
| No expected trust list fingerprint given (10.4) | Nothing recorded | Informational `TRUST_LIST_FINGERPRINT_NOT_CHECKED` |
| Everything else | Identical | Identical |

### 11.2 Outcome

The outcome is PASS, FAIL or UNSUPPORTED. FAIL is reported when at least one FAIL finding exists. UNSUPPORTED is reported when there is no FAIL finding but the verifier lacks a capability that the profile requires for this record (11.7, 11.9); it is neither a pass nor a failure, names the missing capability, and tells the reader to use a verifier that has it (the reference command-line verifier has every capability). Every finding carries a code (11.7) and a message; the outcome's list of FAIL codes and list of WARN codes name each code once, in the order first recorded, even when several findings share it (three schema violations are one `SCHEMA_INVALID`), and informational codes are not part of either list. A PASS with WARN findings MUST be shown as a pass with warnings and MUST list the codes; a verifier MUST NOT hide warnings. Command-line verifiers exit 0 on PASS, 2 on FAIL, 3 on UNSUPPORTED and 4 on a PASS obtained from a test list in test mode (10.6), with or without warnings. The reference command line exits 1 when an error prevented verification (an unreadable trust directory, say) and 64 on a usage error (a missing or unknown option); neither prints a verdict.

### 11.3 Time

The signing time T is determined once and used for every time-dependent check:

1. If label -70001 is present and the token verifies (11.5 step 6), T is the token's `genTime`.
2. Otherwise T is the record's `created` value, and the verifier records WARN `VALIDITY_JUDGED_AT_CREATED` (both profiles). `TIMESTAMP_MISSING` is recorded only when label -70001 is absent. A token that is present but fails step 6 yields `TIMESTAMP_INVALID` (FAIL in both profiles) together with `VALIDITY_JUDGED_AT_CREATED`, and not `TIMESTAMP_MISSING` (vectors 20 and 22).
3. If neither is available the envelope is `ENVELOPE_MALFORMED`.

A valid token whose `genTime` precedes `created` by more than five minutes yields WARN `TIMESTAMP_BEFORE_CREATED`. The verifier's own clock is never used to judge validity; records remain verifiable after certificates expire.

### 11.4 Certification path

The path starts at `x5chain[0]` (the end-entity certificate). Each certificate is linked to its issuer by name and by signature; issuer and subject names (and the issuer names of CRLs and of a token's signer identifier) are compared as the sequence of decoded RDNs described for the subject comparison below, with values compared exactly, or by their exact DER when a name cannot be decoded; candidate issuers are the other certificates of `x5chain` and the trust anchors listed for the path's purpose (10.2): `daur-signing` for the signer's path, `time-stamping` for the time-stamping certificate's path. A signer path that would end at a root listed for time-stamping only is `UNTRUSTED_ROOT`, and the message says that the root is listed for time-stamping only (vector 31). Accepted certificate signatures are RSA PKCS#1 v1.5 and RSASSA-PSS, ECDSA on P-256, P-384 and P-521, and Ed25519; a certificate in the path signed with SHA-1 or MD5 is `CHAIN_INVALID`, and so is an authentic CRL signed with SHA-1 or MD5, which is then not used as evidence. The path ends when a certificate is itself a trust anchor or is signed by a trust anchor. Anchors are matched by SHA-256 fingerprint of the DER certificate. Path length is at most six certificates, counted from `x5chain[0]` up to and including the certificate at which the path reaches the trust list (a certificate that is itself an anchor, or the last certificate signed by an anchor). The verifier looks for an anchor that signed the current certificate before it looks in `x5chain` for the next certificate, so a root carried in `x5chain` after the last certificate it signed is never reached and never counted: a leaf, five intermediates and the root (seven certificates in `x5chain`) is within the limit, and a leaf with six intermediates is not. An anchor held only in the trust list is not counted either. A longer path is `UNTRUSTED_ROOT`.

At time T the verifier checks: every certificate in the path and the anchor is within its validity period (else `CERT_EXPIRED_AT_SIGNING`); the anchor is within its manifest window (else `UNTRUSTED_ROOT`); the end-entity certificate is not a CA and, when key usage is present, has `digitalSignature` (else `CHAIN_INVALID`); intermediates are CAs with `keyCertSign` when key usage is present (else `CHAIN_INVALID`); no certificate in the path or the anchor is listed under `invalidity_dates` with `invalid_from` at or before T (else `CERT_INVALID_RETROACTIVELY`).

When the end-entity signing certificate carries an extendedKeyUsage extension, the set MUST include id-kp-documentSigning (1.3.6.1.5.5.7.3.36), id-kp-emailProtection (1.3.6.1.5.5.7.3.4) or anyExtendedKeyUsage (2.5.29.37.0); a certificate whose extended key usage is limited to id-kp-timeStamping and/or id-kp-OCSPSigning MUST be rejected with `CHAIN_INVALID`. A signing certificate with no extendedKeyUsage extension remains acceptable. This rule applies to the signer's path only; the time-stamping certificate is governed by 11.5 step 6, which requires id-kp-timeStamping alone.

The end-entity certificate MUST match `producer.signing_certificate.sha256_fingerprint` (else `SIGNER_MISMATCH`). With a matching fingerprint, `subject` and `serial` are compared semantically, and a difference in either yields WARN `SIGNER_DETAILS_DIFFER`: the record's subject string is parsed as an RFC 4514 distinguished name into RDNs, and the sequence of RDNs (in the string's order, which is the reverse of the DER order) is compared with the certificate's subject RDN by RDN, each RDN as the set of its attribute type and value pairs; attribute types are compared as OIDs, accepting the dotted form and the descriptors `CN`, `L`, `ST`, `O`, `OU`, `C`, `STREET`, `DC`, `UID` (RFC 4514), `title`, `SN`/`surname`, `GN`/`givenName`, `initials`, `generationQualifier`, `serialNumber`, `pseudonym`, `dnQualifier`, `businessCategory`, `postalCode`, `postalAddress`, `name`, `description`, `emailAddress`/`email`, and the single letters `T` (title) and `E` (emailAddress) that some libraries emit, all case-insensitively; values are compared as Unicode strings after RFC 4514 unescaping (`\` before a special character, `\hh` for a UTF-8 byte, and the leading `#hex` form for a BER-encoded string type, whose hexadecimal digits come in pairs with nothing between them); the separator `;` and whitespace (the set of 6.3) around separators and around `=` are accepted, and an unescaped whitespace character at either end of a value is removed. The certificate side is read from the DER the certificate carries, not from a re-encoding: UTF8String as UTF-8, PrintableString, IA5String, VisibleString and NumericString as ASCII, BMPString as UTF-16BE, UniversalString as UTF-32BE (code points above U+10FFFF and surrogates are invalid) and TeletexString (T61String) as ISO 8859-1; any other value type, and any value that does not decode, makes the name unreadable. Any error on either side while comparing is a difference, `SIGNER_DETAILS_DIFFER`, and never stops verification. Both verifiers are tested against one generated corpus (`verifier/test/fixtures/parity-corpus.json`) and vector 43. Serial numbers are compared as integers (`1001` and `01001` are the same serial). A subject string the parser cannot read differs. Both reference verifiers implement this comparison (`daur/dn.py`, `verifier/src/dn.js`).

The producer named in the record is bound to the certificate. The signing certificate MUST carry exactly one organisation (O, 2.5.4.10) value, and `producer.organisation.legal_name` is compared with it; the two are equal when they are the same after removing leading and trailing whitespace, replacing every internal run of whitespace by one U+0020 and applying the Unicode default lower-case mapping (Python `str.lower`, ECMAScript `String.prototype.toLowerCase`), whitespace being the set listed in 6.3. When the certificate carries no O value, more than one (in one RDN or several), or a value that is not equal, the verifier records `PRODUCER_ORG_DIFFERS`: WARN in the pilot profile, FAIL in the strict profile (vectors 28 and 61).

Two certificate policy identifiers, minted under the UUID arc 2.25 (ITU-T X.667, no registration needed), say what kind of party a certificate names:

| Policy | UUID | OID |
| --- | --- | --- |
| Avok Attest organisation seal | `eaee1f9c-06a4-42c2-9927-8a0a43146159` | `2.25.312275758782348157821337947671413154137` |
| Avok Attest named signer | `161f973b-1648-4762-8d58-fa32b2c3f21d` | `2.25.29407044435090518585266348200233792029` |

`daur ca issue --profile seal` asserts the first in a certificatePolicies extension and `--profile signer` the second. A certificate whose certificatePolicies holds the organisation seal policy and not the named-signer policy is an organisation seal certificate; any other certificate, including one with neither policy or with no certificatePolicies extension, is treated as a named-signer certificate. With an organisation seal certificate, `producer.accountable_person.name` is the organisation's declaration: the verifier records the informational `ACCOUNTABLE_PERSON_DECLARED`, and every surface prints `(named by the organisation; not in the certificate)` beside the name (vector 29). With any other certificate, the name MUST equal the certificate's single common name (CN, 2.5.4.3), compared as the organisation is: equal gives the informational `ACCOUNTABLE_PERSON_IN_CERT`, and otherwise the verifier records `ACCOUNTABLE_PERSON_DIFFERS`, WARN in the pilot profile and FAIL in the strict profile (vectors 60 and 62). The certificate binds the organisation in every case and the person only in a named-signer certificate. Before anything taken from the record, a verifier states whom the certificate was issued to, as `Signed with a certificate issued to <CN>, <O>` with the values taken from the certificate (11.8).

For the time-stamping certificate only the path rules of this section apply (validity periods, the anchor's manifest window, CA flags, key usage, path length, invalidity dates), reported as `TIMESTAMP_INVALID`; the `SIGNER_MISMATCH` paragraph and the extended key usage rule above do not (its extended key usage is governed by 11.5 step 6), and revocation of the time-stamping certificate is not evaluated in this version, also for public time-stamping authorities listed with `daur ca trust --timestamp-root` (backlog); a compromised TSA certificate is withdrawn through `invalidity_dates` (10.5).

### 11.5 Procedure

1. Parse the envelope. For a wrapper (5.2), decode `cose_sign1_b64`. Decode the COSE_Sign1; check the tag, the four-element array, the protected header map, `alg` in {ES256, EdDSA} (a CBOR integer) and content type. Any failure is `ENVELOPE_MALFORMED`. The verifier does not check that the protected header is deterministically encoded and accepts `x5chain` as a single bstr or as an array of one or more bstr (9.1).
2. Parse the payload as JSON and check it equals its own JCS form (else `ENVELOPE_MALFORMED`). Validate against the schema (else `SCHEMA_INVALID`, continuing where possible). For a wrapper, check JCS(`record`) equals the payload (else `RECORD_ALTERED`).
3. Verify the signature over `Sig_structure` with the end-entity public key (else `SIGNATURE_INVALID`). An ES256 signature that is DER-encoded or not exactly 64 bytes, and an `alg` that does not match the key type (ES256 with a key other than P-256, EdDSA with a key other than Ed25519), are `SIGNATURE_INVALID` as well.
4. Check the snapshot commitment: if -70003 is present, -70002 MUST be present with the same number of items and each item's SHA-256 MUST equal the committed digest at the same index; if -70003 is absent and -70002 is present the snapshot is uncommitted. Either failure is `REVOCATION_SNAPSHOT_MISMATCH` (WARN pilot, FAIL strict). Snapshot items remain usable as revocation evidence because CRLs and OCSP responses are signed by their issuers.
5. Check the trust-list pin: compare `trust_list_id`, `version` and `sha256` with the verifier's manifest. Same id and verifier version lower than pinned: WARN `STALE_TRUST_STATE` naming both versions, in both profiles. Same id and version but different digest: WARN `TRUST_LIST_DIGEST_DIFFERS`. Same id and verifier version higher than pinned: informational `TRUST_LIST_NEWER`, with no digest comparison (the manifests differ by construction). Same id, version and digest: informational `TRUST_PIN_MATCH`. Versions that cannot be ordered: WARN `TRUST_LIST_VERSION_UNORDERED`. Different id: informational `TRUST_LIST_ID_DIFFERS`. No manifest on the verifier side: WARN `TRUST_PIN_UNCHECKED`.
6. Time-stamp: if -70001 is present, parse the `TimeStampToken`; check exactly one `SignerInfo`, the signer certificate present in the token, the signed attributes (content type `id-ct-TSTInfo`; message digest of the `TSTInfo` computed with the SignerInfo digest algorithm, which is SHA-256, SHA-384 or SHA-512; `SigningCertificateV2` or `SigningCertificate`, one of which MUST be present (RFC 3161 section 2.4.1 as updated by RFC 5816; vector 66): in a `SigningCertificateV2` each `ESSCertIDv2` names its own hash algorithm, SHA-256 when absent, and one of them MUST identify the signer certificate; a `SigningCertificate` with a SHA-1 `ESSCertID` is accepted as a certificate identifier), the CMS signature (RSA PKCS#1 v1.5 or RSASSA-PSS with SHA-256, SHA-384 or SHA-512 and an RSA key of at least 2048 bits, RSASSA-PSS with the MGF1 hash equal to the signature hash; ECDSA on P-256, P-384 or P-521 with those hashes; Ed25519), a critical extended key usage containing only `id-kp-timeStamping`, the message imprint equal to SHA-256 of the signature bytes, and a certification path for the TSA certificate that satisfies the path rules of 11.4 at `genTime` (including invalidity dates; the TSA's path is built from the token's certificates and the trust list, so the TSA root MUST be in the trust list and listed for `time-stamping`). Any failure is `TIMESTAMP_INVALID` in both profiles; a token whose CMS signature verifies but whose path ends at no anchor listed for time-stamping is reported with the message "TSA root not in the trust list for time-stamping". Tokens from public authorities (DigiCert, Sectigo, GlobalSign and others) verify under these rules; the reference repository tests ten of them (`tests/fixtures/public-tsa/`). The message imprint stays SHA-256. Determine T (11.3).
7. Build and check the signer's path at T (11.4).
8. Revocation at T for the end-entity certificate, evaluated only when step 7 found a path to a trust anchor; otherwise the verifier records the informational `REVOCATION_NOT_EVALUATED` and no WARN or FAIL (vector 11 is `UNTRUSTED_ROOT` alone). The issuer is the next certificate in the path, or the anchor. The evidence is the snapshot (label -70002), the CRLs of the trust list and any CRL the verifier is given (`daur verify --crl`, the browser core's `crls` input); only data that verifies under the issuer's key counts, a CRL carrying the DeltaCRLIndicator or IssuingDistributionPoint extension (a delta, partitioned or indirect CRL) does not cover the certificate and therefore never establishes "not revoked", though its entries count under (a), and intermediate certificates are not evaluated for revocation in this version (an operator withdraws one through `invalidity_dates`). The evidence is weighed in this order. (a) Any authentic data listing the certificate as revoked with a revocation date at or before T gives `CERT_REVOKED_AT_SIGNING`, whatever the data's publication time and whether or not it is a delta or partitioned CRL (vector 65); the date compared is the CRL entry's `revocationDate` (or the OCSP `revocationTime`). (b) A later CRL, that is an authentic CRL from the trust list or given to the verifier whose `thisUpdate` is at least 24 hours after T, decides on its own, regardless of the snapshot: it gives `CERT_REVOKED_AT_SIGNING` when it lists the certificate with a `revocationDate` or an `invalidityDate` at or before T (vector 33), and otherwise establishes "not revoked" (vector 34), provided its `thisUpdate` is not after the certificate's `notAfter` (an entry may leave a CRL once the certificate has expired, RFC 5280 section 3.3). (c) Otherwise, data whose window covers T (`thisUpdate` at or before T and `nextUpdate` absent or at or after T) establishes "not revoked" when the trust manifest sets no `revocation_max_age` or when `T - thisUpdate` is at most that duration; covering data that is older is stale (vector 32). The `invalidityDate` of an entry in data that is not a later CRL is ignored, retroactive invalidity being expressed through the trust manifest's `invalidity_dates`. Data present but not covering T, or covering but older than `revocation_max_age`, is `REVOCATION_STALE` (WARN pilot, FAIL `REVOCATION_MISSING` strict). No authentic data is `REVOCATION_MISSING` (WARN pilot, FAIL strict). When (a), (b) or (c) decided, the verifier records which evidence decided: informational `REVOCATION_DECIDED_BY_LATER_CRL` or `REVOCATION_DECIDED_BY_SNAPSHOT` (the latter covers the snapshot and trust-list CRLs that are not later). Every result names that evidence on every surface, on the line under the trust list line (the command line, the browser verifier's banner, the statement PDF's check box): `Revocation: decided by <evidence>, issued <thisUpdate>, SHA-256 <hash>`, where `<evidence>` is `the list stapled at signing`, `the OCSP response stapled at signing`, `a later list from the trust directory`, `a later list supplied to this check`, or, for a list that covers T and is not later, `a list from the trust directory` or `a list supplied to this check`, and the hash is the SHA-256 of the DER encoding of that CRL or OCSP response. When the decision does not rest on a later list and none was available, the line is followed by `No later revocation list was available to this check; a revocation recorded afterwards with an earlier invalidity date would not be seen. Obtain the current list from the trust list operator, not from the producer.` When no data decided, the line reads `Revocation: not decided;` and the reason. JSON output lists every CRL loaded under `details.crls_loaded`, each with `source` (`stapled`, `trust_directory` or `supplied`), `issuer`, `this_update`, `next_update` and `sha256`; the command line lists them among the details. A verifier takes OPTIONAL expected revocation list fingerprints (`daur verify`, `daur render` and `daur c2pa read` take `--crl-fingerprint <hex>`, repeatable; the Python library `crl_fingerprints`; the browser core `crlFingerprints`; the browser verifier the field "Expected revocation list fingerprint"; case, colons and white space ignored): each must be the SHA-256 of a loaded CRL, else FAIL `CRL_NOT_THE_EXPECTED_ONE` in both profiles (vector 74), and a match is the informational `CRL_FINGERPRINT_MATCH`. A contracting authority that publishes the SHA-256 of the current list beside the trust list fingerprint thereby lets a relying party show that the list it was given is the current one (10.4). A CRL or certificate signed with SHA-1 or MD5 is `CHAIN_INVALID` (11.4). A delegated OCSP responder certificate must be within its validity period at T.
9. Deliverable: compute SHA-256 of the bytes and compare with `file_sha256` (else `HASH_MISMATCH`). The deliverable's basename (the name without directories, compared exactly and case-sensitively) that differs from `file_name` is WARN `FILE_NAME_MISMATCH`; for a C2PA carrier read without the source asset the carrier's own basename is the name compared (12.3). No deliverable supplied is WARN `FILE_NOT_CHECKED`, and regions are then not evaluated (11.6).
10. Regions (11.6).
11. Evidence files, when the record lists evidence or files were supplied (11.10).
12. Produce the statement (11.8).

### 11.6 Regions

Regions are evaluated only when a deliverable was supplied; without one, `FILE_NOT_CHECKED` is the only finding about the file and regions are not mentioned. For each region with a `sha256` in every `ai_use[].locus`, recompute the hash with the named method. Unknown method or type: `REGION_NOT_RECOMPUTED`, informational when the whole-file hash matched (the bytes are those signed, so the region is too, and a verifier says that the file is byte-identical to the one signed and the region text was not recomputed) and WARN otherwise. No hash: WARN `REGION_UNHASHED`. Mismatch or unresolvable reference (heading not found, page, byte or paragraph range out of bounds, malformed reference) when the file hash also mismatched: FAIL `REGION_HASH_MISMATCH`, naming the region, so that the reader learns which parts changed. Mismatch or unresolvable reference when the file hash matched: WARN `REGION_EXTRACTION_DIFFERS`, because the signed bytes are intact and the difference lies in extraction. Verifiers SHOULD report the number of regions checked and the list of mismatched references.

### 11.7 Result codes

FAIL codes:

| Code | Meaning |
| --- | --- |
| `HASH_MISMATCH` | The deliverable's SHA-256 differs from `file_sha256` (or, for an embedded carrier, the C2PA hard binding failed). |
| `SIGNATURE_INVALID` | The COSE signature does not verify with the end-entity key. |
| `UNTRUSTED_ROOT` | No path to a trust anchor listed for `daur-signing`, or the anchor is outside the manifest window at T. |
| `CERT_EXPIRED_AT_SIGNING` | A certificate in the path, or the anchor, was outside its validity period at T. |
| `CERT_REVOKED_AT_SIGNING` | Authentic revocation data lists the certificate as revoked at or before T. |
| `CERT_INVALID_RETROACTIVELY` | The trust list declares a certificate in the path invalid from a time at or before T. |
| `TIMESTAMP_MISSING` | Strict profile and no token. |
| `TIMESTAMP_INVALID` | Token malformed, imprint mismatch, TSA signature or path invalid, TSA root not listed for time-stamping, TSA certificate invalid at genTime. |
| `RECORD_ALTERED` | The record presented beside the envelope (wrapper or C2PA copy) differs from the signed payload. |
| `REGION_HASH_MISMATCH` | A region hash does not reproduce and the file hash also failed. |
| `SCHEMA_INVALID` | The signed record violates the schema. |
| `ENVELOPE_MALFORMED` | The envelope, header, payload canonical form or content type is wrong. |
| `CHAIN_INVALID` | A certificate violates the profile rules of 11.4 (CA flag, key usage, the signing certificate's extended key usage, or a SHA-1 or MD5 signature on a certificate in the path or on an authentic CRL). |
| `SIGNER_MISMATCH` | `producer.signing_certificate` names a different certificate than `x5chain[0]`. |
| `PRODUCER_ORG_DIFFERS` | Strict profile and the signing certificate does not carry exactly one O value equal to `producer.organisation.legal_name` (11.4). |
| `ACCOUNTABLE_PERSON_DIFFERS` | Strict profile, a certificate that is not an organisation seal, and `producer.accountable_person.name` is not its common name (11.4). |
| `SOURCE_HASH_NOT_CHECKED` | Strict profile and a C2PA carrier read without the source asset (12.3). |
| `C2PA_SIGNER_UNTRUSTED` | Strict profile and the C2PA claim signer does not chain to a `daur-signing` root of the trust list (12.4). |
| `C2PA_SIGNER_DIFFERS` | Strict profile and the C2PA claim signer is not the DAUR signer (12.4). |
| `EVIDENCE_HASH_MISMATCH` | A supplied file has the name of an evidence entry but another SHA-256 (11.10). Both profiles. |
| `EVIDENCE_NOT_FOR_THIS_FILE` | A supplied citation check that matches its entry by hash was made for another deliverable (11.10). Both profiles. |
| `EVIDENCE_SUMMARY_MISMATCH` | A supplied citation check that matches its entry by hash has another summary than the record states (11.10). Both profiles. |
| `CRL_NOT_THE_EXPECTED_ONE` | An expected revocation list fingerprint was given and no loaded CRL has that SHA-256 (11.5 step 8). Both profiles. |
| `REVOCATION_MISSING` | Strict profile and no revocation data covering T that is within `revocation_max_age`. |
| `TEST_TRUST_LIST` | The trust list is a test list (10.6) and the verifier is not in test mode. Both profiles. |
| `TRUST_LIST_FINGERPRINT_MISMATCH` | An expected trust list fingerprint was given and the loaded list's fingerprint differs (10.4). Both profiles. |
| `TRUST_LIST_ID_RESERVED` | The list claims a reserved identifier without exactly its registered root set (10.7). Both profiles. |
| `TRUST_LIST_INVALID` | The manifest breaks the rules of 10.2 (both profiles), or the strict profile and the trust list has no manifest (10.1). |
| `REVOCATION_SNAPSHOT_MISMATCH` | Strict profile and either -70003 is present while -70002 is absent or does not match it (count or digests), or -70002 is present while -70003 is absent (uncommitted), as 11.5 step 4 says. An envelope with neither label is not a mismatch; its missing data is `REVOCATION_MISSING`. |

WARN codes:

| Code | Profile | Meaning |
| --- | --- | --- |
| `TIMESTAMP_MISSING` | pilot | No token; T taken from `created`. |
| `VALIDITY_JUDGED_AT_CREATED` | both | T taken from `created`. |
| `TIMESTAMP_BEFORE_CREATED` | both | Token predates `created` by more than five minutes. |
| `REVOCATION_MISSING` | pilot | No authentic revocation data. |
| `REVOCATION_STALE` | pilot | Revocation data present but not covering T, or covering T but older than `revocation_max_age`. |
| `REVOCATION_SNAPSHOT_MISMATCH` | pilot | -70003 present with -70002 absent or not matching it, or -70002 present with -70003 absent (11.5 step 4). Neither label present is not a mismatch. |
| `STALE_TRUST_STATE` | both | The verifier's trust list is older than the version pinned by the signer; the message names both versions. Never silently accepted. |
| `TRUST_LIST_DIGEST_DIFFERS` | both | Same list and version, different content. |
| `TRUST_LIST_VERSION_UNORDERED` | both | Versions cannot be ordered. |
| `TRUST_PIN_UNCHECKED` | both | The verifier has no manifest to compare the pin with. |
| `TRUST_PIN_MISSING` | strict | No pin in the protected header. |
| `TRUST_LIST_INVALID` | pilot | The trust list has no manifest (10.1). |
| `SIGNER_DETAILS_DIFFER` | both | Subject or serial text differs although the fingerprint matches. |
| `PRODUCER_ORG_DIFFERS` | pilot | The signing certificate does not carry exactly one O value equal to `producer.organisation.legal_name` (11.4). |
| `ACCOUNTABLE_PERSON_DIFFERS` | pilot | A certificate that is not an organisation seal, and `producer.accountable_person.name` is not its common name (11.4). |
| `REGION_NOT_RECOMPUTED` | both | Method or type not available to this verifier and the file hash did not match (informational when it matched, 11.6). |
| `REGION_UNHASHED` | both | Region declared without a hash. |
| `REGION_EXTRACTION_DIFFERS` | both | Region hash differs although the file is intact. |
| `FILE_NAME_MISMATCH` | both | File name differs from `file_name`. |
| `FILE_NOT_CHECKED` | both | No deliverable supplied. |
| `TIMESTAMP_NOT_VERIFIED` | both | Reserved for a verifier that cannot validate RFC 3161 tokens (a constrained browser build, say) and parses the token without checking it. Both reference verifiers always validate tokens and therefore never emit it. |
| `SOURCE_HASH_NOT_CHECKED` | pilot | C2PA carrier verified without the source asset (12.3). |
| `C2PA_SIGNER_DIFFERS` | pilot | The C2PA claim signer is not the DAUR signer (12.4). |
| `C2PA_SIGNER_UNTRUSTED` | pilot | The C2PA claim signer does not chain to a `daur-signing` root of the trust list (12.4). |
| `EVIDENCE_UNKNOWN` | both | A supplied file matches no evidence entry by hash or name (11.10). |

Outcome code: `UNSUPPORTED` (11.2) is reported with the name of the missing capability when a verifier's only reason to FAIL would be a capability it does not have; the reference browser verifier reports it in the strict profile for a revocation snapshot made only of OCSP responses (11.9). A verifier MUST NOT report UNSUPPORTED when it has another FAIL finding.

Every code has a class, a one-sentence meaning and what to do next in `spec/result-codes.json`; verifiers SHOULD show the meaning beside the code, as the reference command line, browser verifier and statement PDF do.

Informational codes (`REGION_NOT_RECOMPUTED` when the file hash matched, `TRUST_PIN_MATCH`, `TRUST_PIN_MISSING` in pilot, `ACCOUNTABLE_PERSON_IN_CERT`, `ACCOUNTABLE_PERSON_DECLARED`, `REVOCATION_DECIDED_BY_LATER_CRL`, `REVOCATION_DECIDED_BY_SNAPSHOT`, `TRUST_LIST_PAST_NEXT_UPDATE`, `CRL_UNREADABLE` (a CRL given to the verifier that cannot be parsed and is ignored), `TRUST_LIST_ID_DIFFERS`, `TRUST_LIST_NEWER`, `REVOCATION_NOT_EVALUATED`, `C2PA_STATE`, `HEADER_LABEL_NOT_FOR_VERSION` (a DAUR parameter under a label of the other record version, ignored, 9.1), `EVIDENCE_MATCH` and `EVIDENCE_NOT_SUPPLIED` (11.10), `TRUST_LIST_FINGERPRINT_NOT_CHECKED` (strict profile, no expected fingerprint given, 10.4), `TRUST_LIST_FINGERPRINT_MATCH`, `CRL_FINGERPRINT_MATCH` (11.5 step 8) and `TIMESTAMP_FROM_SIGNER_CA` (11.8)) do not affect the outcome and are not listed in it. Verifiers MAY add informational codes; they MUST NOT add FAIL or WARN codes without a new version of this specification.

### 11.8 Plain-language statement

Text from a record, a certificate, a CRL, a time-stamp token, a trust manifest, an evidence entry, a citation report or a file name is untrusted. Before a verifier prints or draws such text it MUST replace every C0 and C1 control character, DEL and bidirectional control listed in 4.1 with a visible escape `\uXXXX` (four upper-case hexadecimal digits), so that no record can move the cursor, clear the screen or reorder the text around it. The only exception is a line feed inside the producer's multi-line statements (4.1), which becomes a real line break followed by an indent. This applies to the command line, the web page and the statement PDF; JSON output carries the same characters as JSON escapes. In the reference implementation the rule is `daur.display.display_text` and `verifier/src/display.js`.

A rendered statement (the reference `daur render` PDF) is a convenience copy of the record for reading, not evidence: anyone can make one, against any trust list, and it is not signed. It MUST NOT carry an unqualified verdict. Its first box is titled `Check run when this page was made` and gives the outcome word (`PASSED`, `PASSED WITH WARNINGS`, `FAILED`, `NOT CHECKED` when no trust list was given, or `TEST PASSED`, `TEST PASSED WITH WARNINGS`, `TEST FAILED` for a test list), the date and time of rendering, the verifier version, the profile, the trust list's name, identifier, version and fingerprint, and the fixed sentence `This box is not evidence. Anyone can make this page. To rely on the record, verify the deliverable and the record yourself with the verifier and the trust list fingerprint your contract names.` The reference renderer colours the box grey-blue for a pass, red for a failure, amber for a test list and grey, with a diagonal `NOT CHECKED` mark on every page, when nothing was checked; it uses no green. Every page carries a one-line status in its header (the outcome word and the rendering time). Text in a right-to-left script or a script that needs shaping, which the renderer cannot draw correctly, is replaced where it occurs by a visible placeholder and a note, and the note is repeated once at the top of the page it falls on.

A verifier MUST first state, from the signing certificate and not from the record, `Signed with a certificate issued to <CN>, <O>` (the certificate's common name and organisation values; a missing value is shown as `(no common name)` or `(no organisation)`), followed by ` (this certificate is not trusted by your list)` when the signer's path ends at no anchor of the trust list (11.4) or the anchor does not cover the signing time, and then where the signing time came from: `Time-stamp issued by <CN>, <O>, under <anchor CN>, <anchor O> (anchor fingerprint <first 16 hex digits>...)` (the time-stamping certificate's names, then the trust anchor its path ends at) when T is a verified token's `genTime`, or `Time taken from the signer's own clock` when T is `created`. A time-stamp gives time independent of the signer only when the time-stamping authority is another party, and the authority's names prove nothing by themselves (10.4): whoever controls a list's root can issue a time-stamping certificate with any name. When the token's anchor and the signer's anchor are the same certificate, the line ends with `(the time-stamp comes from the signer's own certificate authority; it is not independent of the signer)` and the verifier records the informational `TIMESTAMP_FROM_SIGNER_CA`. `daur ca trust` lists the CA's own root for `daur-signing` only unless the operator gives `--root-also-timestamping` (`--root-signing-only` is accepted and changes nothing). It MUST then present a statement derived from the signed record (never from an unsigned copy) that names the producer, the deliverable (title, identifier, version, contract, file name and SHA-256), each AI use in one sentence (tool, model, provider, hosting jurisdiction, category, extent, dates, locus, data exposure, retention and training opt-out), the human review (`Human review: <method words> by the <role> on <date>.` for the first four methods; `Human review (described by the producer): the <role> on <date>.` for `other`; `Human review: none. No person reviewed the deliverable before this record was made.` for `none`, never worded as a review; each followed by the producer's `statement`), the accountable person (with ` (named by the organisation; not in the certificate)` after the name when an organisation seal certificate signed the record), the record creation time and, when present, the time-stamp time and the TSA, followed by the declaration text verbatim. After a FAIL the statement is headed `Statement (from a record that FAILED; do not rely on it)` on every surface. When the record lists evidence, or evidence files were supplied, a verifier also shows an Evidence section listing each entry (type, description, file name, a short form of its SHA-256 and its summary, labelled as stated in the record) and whether its file was supplied and matched, and each supplied file that matched no entry.

### 11.9 Interoperability notes

- RFC 8785 number serialisation is required of every implementation. `extent_percent` is a JSON number that only SHOULD be an integer, so a payload may carry `40.5` or `1e21`, and the canonical form of such a number is the ECMAScript `Number.prototype.toString` output that RFC 8785 specifies; a verifier that re-serialises numbers any other way will report `ENVELOPE_MALFORMED` on a valid envelope. The reference Python implementation uses the `rfc8785` package and refuses non-integral floats it cannot serialise identically; the browser relies on `JSON.stringify`.
- `daur-pdf-page-text-v1` is defined by pypdf's `Page.extract_text()`. The vectors were built with pypdf 6.17.0 (`constraints-ci.txt`), and an implementation in another language cannot reproduce the method exactly; this is why a page-text mismatch on an intact file is WARN `REGION_EXTRACTION_DIFFERS` and never FAIL, and why a verifier that does not implement the method reports `REGION_NOT_RECOMPUTED` (the browser verifier does so for PDF and DOCX regions).
- The browser verifier does not evaluate OCSP responses: for a snapshot made only of OCSP responses it reports UNSUPPORTED in the strict profile, naming the capability and pointing to the command-line verifier, and WARN `REVOCATION_MISSING` in the pilot profile (vector 23, which the command-line verifier passes). It does not recompute PDF page or DOCX regions; when the file hash matched it says so and records the informational `REGION_NOT_RECOMPUTED`. Both reference verifiers implement everything else in section 11, including the semantic subject comparison of 11.4, the token validation of step 6 and the informational `REVOCATION_NOT_EVALUATED`.
- Both reference verifiers implement the 0.2 rules of 10.2, 10.6, 11.4 and 11.5 step 8 identically: test lists, root purposes, the token and certificate algorithms, the organisation comparison, revocation freshness and later CRLs (the browser core takes further CRLs as its `crls` input and a verification time as `verificationTime`). The C2PA rules of 12.3 and 12.4 exist only in the command-line verifier, because the browser verifier reads no C2PA manifest.
- An implementation reproduces a vector (appendix C) by comparing its FAIL codes and WARN codes as sets with `expected.json`; messages and informational codes are not part of the contract.

### 11.10 Evidence

Evidence files are OPTIONAL inputs (`daur verify --evidence <path>`, repeatable; the browser verifier's evidence area; the library's `evidence` argument; the browser core's `evidence` input of `{ name, bytes }` objects). A verifier compares each supplied file with the record's `evidence` entries:

- a file whose SHA-256 equals an entry's `sha256`: informational `EVIDENCE_MATCH`. When the entry's `type` is `citation-check`, the file must be a readable citation check: its bytes decode as UTF-8 and do not start with a byte order mark (EF BB BF; a verifier refuses it rather than skip it, so that both reference verifiers read the same files), they parse as a JSON object, and that object has a `header` object whose `format` is `avok-attest-citation-check-v1`. A file that matches a `citation-check` entry by hash and is not a readable citation check (a wrong or missing `format`, no `header`, not JSON, a byte order mark) is FAIL `EVIDENCE_SUMMARY_MISMATCH` in both profiles, because the summary the record states is not backed by it (vectors 77 to 80); every surface says that the supplied file is not a readable citation check and why. A readable citation check is also compared with the record: a `header.deliverable_sha256` other than the record's `deliverable.file_sha256` (compared in lower case) is FAIL `EVIDENCE_NOT_FOR_THIS_FILE` (vector 63), and a `summary` that is not equal to the entry's `summary` (compared in RFC 8785 canonical form; an absent summary equals nothing) is FAIL `EVIDENCE_SUMMARY_MISMATCH` (vector 64), both in both profiles;
- otherwise, a file whose name (without directories, compared exactly) equals an entry's `file_name`: FAIL `EVIDENCE_HASH_MISMATCH`, in both profiles, because the producer bound another file under that name;
- otherwise: WARN `EVIDENCE_UNKNOWN`, in both profiles;
- an entry for which no file matched by hash or name: informational `EVIDENCE_NOT_SUPPLIED`.

Evidence never turns a FAIL into a PASS, and its absence never fails a record (vectors 46 to 49). Every surface shows where the counts of a citation check come from: the file's own counts, labelled `checked against the supplied file`, when the file was supplied and agrees; both, labelled `the supplied file says` and `the record states`, when it disagrees; and the record's, labelled `stated by the producer; not checked`, when the file was not supplied. `daur render --evidence <path>` lets the statement PDF show a supplied file as matched. Each expected outcome in appendix C names the evidence files the verifier is given.

## 12. C2PA carriage

### 12.1 Assertion

A C2PA manifest MAY carry a DAUR in a custom assertion with the label `ca.avoksystems.daur.v1` (C2PA requires custom assertion labels to start with the owning entity's domain in reverse order). The assertion data is a CBOR map with two text keys:

- `record`: the record as a CBOR map (the JSON record converted to CBOR);
- `cose_sign1_b64`: a text string holding the base64 (RFC 4648 section 4) of the envelope bytes.

The envelope remains the authoritative signature. A reader MUST verify the envelope by section 11; the C2PA claim signature and hard binding are reported in addition and do not substitute for it.

Implementations built on c2pa-rs will observe the label reported as `ca.avoksystems.daur` because that library treats a `.v1` suffix as the implicit first version. Readers MUST accept both spellings.

### 12.2 Embedded and sidecar manifests

Where the C2PA library supports the asset type, the manifest is embedded in a copy of the asset (the carrier). Otherwise, and whenever embedding fails, the manifest is written as a sidecar file named `<file>.c2pa` whose hard binding covers all bytes of the asset.

### 12.3 Hash binding

A reader locates the manifest in the JUMBF `c2pa` superbox embedded in the carrier (for PDF, the C2PA library's PDF handler finds it) or in a sidecar `.c2pa` file given beside the asset (`daur c2pa read --file <asset> --manifest <asset>.c2pa`), takes the active manifest's `ca.avoksystems.daur.v1` assertion (12.1), decodes `cose_sign1_b64` and verifies the envelope by section 11. Embedding changes the bytes of the carrier, so `file_sha256` in the record refers to the source asset, not to the carrier. A reader of an embedded carrier MUST either obtain the source asset and verify the hash, or report `SOURCE_HASH_NOT_CHECKED`, FAIL in the strict profile and WARN in the pilot profile, and say before the outcome `File not verified: no source asset supplied; only the hashed text regions were checked.` (the reference reader prints it on the first line, after the test-list label when there is one); the reference reader takes the source as `daur c2pa read --source <original file>` and then verifies the envelope against the source exactly as `daur verify` would. Without the source, the carrier itself is the file compared: its own basename is compared with `file_name` (so a carrier named `report.c2pa.pdf` for a deliverable `report.pdf` receives `FILE_NAME_MISMATCH`), text regions (`page_range`, `heading`, `paragraph_range`) are unaffected by embedding and MUST still be recomputed on the carrier, and `byte_range` regions are skipped with `REGION_NOT_RECOMPUTED`. A carrier whose C2PA hard binding fails (validation state `Invalid`) is `HASH_MISMATCH`. The result of a carrier read without the source says nothing about bytes outside the hashed text regions (threat model T3), which is why the strict profile fails it; buyers who rely on C2PA carriage SHOULD require the source asset (vector 35).

For a sidecar manifest the asset bytes are unchanged and verification is complete.

### 12.4 Signer relationship

The C2PA claim SHOULD be signed with the DAUR signing certificate. A different claim signer yields `C2PA_SIGNER_DIFFERS`, and a claim signer that does not chain to a root the trust list lists for `daur-signing` (the C2PA validation state is not `Trusted` when the reader is given those roots) yields `C2PA_SIGNER_UNTRUSTED`; each is WARN in the pilot profile and FAIL in the strict profile. A valid C2PA hard binding is evidence about the carrier bytes only when a trusted key made it. The record copy inside the assertion MUST equal the signed payload (else `RECORD_ALTERED`).

## 13. Relationship to C2PA

C2PA (Coalition for Content Provenance and Authenticity) specification 2.x already provides much of the signature machinery used here: the claim signature is a COSE_Sign1 with the certificate chain in the protected header (`x5chain`), an RFC 3161 time-stamp in the unprotected `sigTst2` header, and stapled revocation information (OCSP) in the unprotected `rVals` header, together with hard bindings from the manifest to the asset bytes. DAUR reuses those building blocks and does not claim conformance to C2PA.

DAUR adds three things that C2PA does not define:

1. A commitment to the revocation snapshot inside the protected header (label -70003). In C2PA the stapled revocation values sit only in the unprotected header and can be replaced after signing without invalidating the claim signature. Under DAUR, the digests of the snapshot are signed, so the revocation evidence a verifier sees is the evidence the signer relied on. A replaced or stripped snapshot is detected.
2. A pin of the trust-list version inside the protected header (label -70004). The signer records which trust list (identifier, version and digest) it expected verifiers to hold. A verifier with an older list learns that its trust state is stale and says so (`STALE_TRUST_STATE`) rather than passing or failing silently on outdated roots or missing invalidity dates.
3. Retroactive invalidity dates in the trust list (10.5). Trust-list operators can withdraw trust in a certificate from a chosen date without waiting for, or depending on, the issuing CA's revocation data, and signatures time-stamped before that date remain valid.

Beyond the signature, DAUR defines content C2PA does not: the AI-use record itself (tools, extent, locus, data exposure, human review, regime answers and declaration), region hashes that let a reader see which parts of a document changed, the pilot and strict verification profiles with their result codes, and a plain-language statement for contracting officers. Section 12 shows how a DAUR travels inside a C2PA manifest when a buyer's tooling already reads C2PA.

## 14. Security considerations

See `threat-model.md` beside this document. In summary: the record binds to exact bytes and to region content; the signature binds the record to a certificate; the time-stamp binds the signature to a time that is independent of the signer when the time-stamping authority is another party; the snapshot commitment binds revocation evidence to the signature; the trust-list pin and invalidity dates give the trust-list operator a voice after signing; and region hashes, extraction identifiers and the strict profile limit what an attacker can change without detection. Nothing here establishes that the declaration is true: a producer can lie in a record. Evidence (4.9) is what the producer chose to attach; a verifier checks its integrity, not its truth, and a producer can omit a file that would tell against it. A citation check (4.10) shows that cited addresses answered when it ran, not that the sources support the deliverable. The mechanism makes the declaration attributable, time-fixed and tamper-evident, which is what a buyer can hold a producer to.

## 15. Registrations and extensibility

- Media type: `application/vnd.avok.daur+json` (vendor tree; registration with IANA is intended).
- COSE header labels -70001 to -70004 (record version 0.2): private use (RFC 9052 section 11.1, integers less than -65536), scoped to envelopes whose content type is the media type above. Record version 0.1 used 7001 to 7004, which lie in the registry's Specification Required range and are not registered; verifiers read them only in a 0.1 record (9.1). Registration will be requested if the format is published.
- C2PA assertion label: `ca.avoksystems.daur.v1`.
- Schema identifier: `https://avoksystems.ca/attest/schemas/daur-v0.2.schema.json`. The schema enumerates `daur_version` values `0.1` and `0.2`.
- Extraction method identifiers: `daur-*-v1` as listed in 6.4; third parties SHOULD use a reverse-domain prefix.
- Trust list identifiers: reverse-domain form; `ca.avoksystems.attest.pilot` is the pilot list and `ca.avoksystems.attest.test` the published-key test list.
- Future versions change `daur_version`; a verifier MUST refuse a version it does not implement with `SCHEMA_INVALID`. A verifier of version 0.2 implements `0.1` and `0.2` and verifies both under the 0.2 rules.

## Appendix A. Example record

```json
{
  "daur_version": "0.2",
  "deliverable": {
    "title": "Sensor fusion options",
    "contract_reference": "W0000-000000/001/ZZ",
    "deliverable_id": "D-002",
    "file_name": "report.md",
    "file_sha256": "6f3c1d4ea1a8c8e2d0b4f1a2c3d4e5f60718293a4b5c6d7e8f9012345678abcd",
    "version": "1.0",
    "media_type": "text/markdown"
  },
  "producer": {
    "organisation": { "legal_name": "Example Consulting Ltd.", "jurisdiction": "Canada (federal)", "business_number": "000000000" },
    "accountable_person": { "name": "Example Signer", "role": "Director" },
    "signing_certificate": {
      "subject": "CN=Example Signer,title=Director,O=Example Consulting Ltd.,C=CA",
      "serial": "1001",
      "sha256_fingerprint": "4d0f0a7e3b6c9d2e1f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e"
    }
  },
  "ai_use": [
    {
      "tool": "Example Assistant",
      "model": "example-large",
      "model_version": "2026-01",
      "provider": "Example Provider Ltd.",
      "hosting_jurisdiction": "Canada",
      "category": "drafting",
      "extent": "substantial",
      "extent_percent": 40,
      "locus": [
        { "type": "heading", "ref": "## 2. Scores", "sha256": "0d2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f607", "extraction_method": "daur-markdown-atx-sections-v1" }
      ],
      "data_exposed": { "government_or_client_data": false, "classes": [] },
      "retention": "Prompts and outputs deleted by the provider after 30 days",
      "training_opt_out": true,
      "dates": { "start": "2026-02-10", "end": "2026-02-27" }
    }
  ],
  "human_review": {
    "reviewer_role": "Director",
    "method": "full_read",
    "date": "2026-03-01",
    "statement": "The accountable person read the complete deliverable and checked every figure against its source.",
    "evidence_refs": ["E1"]
  },
  "regime_references": [
    { "regime": "TBS_GENAI_GUIDE", "answers": { "ai_used": "Yes, for drafting.", "human_review": "Full read by the Director on 2026-03-01." } }
  ],
  "declaration": {
    "text": "This record describes how artificial intelligence tools were used in producing the deliverable identified above, and what review, if any, followed. To the best of the producer's knowledge after the review, if any, described in this record, the statements in this record are accurate. This record is a declaration by the producer. It is not a certification by any third party, and it does not assess the quality or accuracy of the deliverable. Where a citation check is attached, it reports which cited addresses answered when the check ran; it does not establish that a source supports the statement that cites it.",
    "template_id": "avok-attest-declaration-v0.2-en"
  },
  "created": "2026-03-02T15:00:00Z",
  "evidence": [
    { "id": "E1", "type": "citation-check", "description": "Check of the addresses cited in the deliverable (daur evidence citations)", "file_name": "citations.json", "media_type": "application/json", "sha256": "3a19893dc96fc61de25a299f0fd3862109bb52d524cf8c7cc9c607fb0cec742d", "size": 1108, "created": "2026-03-01T12:00:00Z", "produced_by": "daur evidence citations 0.2.0", "summary": { "references": 4, "resolved": 3, "unresolved": 0, "blocked": 1, "error": 0, "not_checked": 0 } }
  ]
}
```

The hashes in this example are placeholders; the vectors in the reference repository carry real values.

## Appendix B. Verification checklist for a contracting officer

1. Obtain the deliverable and its `.daur.cose` file from the producer.
2. Run `daur verify --file <deliverable> --envelope <deliverable>.daur.cose --trust <the trust directory named in your contract> --profile strict`, or open the verifier page named in your contract offline, choose the strict profile and drop both files on it. Never use the `trust/` directory of the reference repository: it is a test list whose root key is published (10.6).
3. Read the first line: PASS, PASS with warnings, or FAIL with codes. Codes are explained in section 11.7.
4. Read the statement that follows: it is generated from the signed record and tells you who used which tool, where, on what data, and who reviewed and signed.
5. Keep the deliverable and the envelope together; either one alone proves nothing.

## Appendix C. Test vectors

The reference repository publishes vectors under `vectors/`, each with a synthetic deliverable, the envelope and the expected outcome per profile. They cover valid sidecar envelopes (PDF, DOCX, Markdown, Ed25519), C2PA carriage (embedded PDF, sidecar Markdown; the expected outcomes name the sidecar envelopes and source deliverables, the carriers are exercised by the reference tests), a tampered file, a tampered wrapper record, a wrong key, an expired certificate, a missing time-stamp, an untrusted root, a revoked certificate, a region mismatch, a schema violation, a stale revocation snapshot, retroactive invalidity after and before the declared date, a stale verifier trust state, a time-stamp token whose TSA certificate carries an extended key usage beyond time-stamping, a record signed with a time-stamping certificate (rejected by the extended key usage rule of 11.4), a present token whose imprint does not match, an OCSP response as the revocation snapshot, a signer issued by an intermediate CA carried in `x5chain`, a wrapper whose record has its members in another order, duplicate headings (vector 36), Markdown paragraph ranges (vector 37), byte ranges (vector 38), an uncommitted revocation snapshot (vector 39), a Markdown file and a wrapper that start with a byte order mark (vectors 40 and 41), U+0085 and U+FEFF at the edges of heading and fence lines (vector 42), a subject that only the semantic comparison matches (vector 43), a record that declares `daur_version` `0.1` (vector 26), and a valid envelope verified against the test list outside test mode (vector 27, `TEST_TRUST_LIST`), a record naming an organisation the certificate does not (vector 28) and an organisation seal certificate with a declared accountable person (vector 29), a token from an RSA time-stamping authority under a root listed for time-stamping only (vector 30) a signer certificate issued under that root (vector 31), a clean CRL older than the trust list's `revocation_max_age` (vector 32), a later CRL listing the revocation at or before the signing time (vector 33) or after it (vector 34), an embedded carrier changed outside its text regions and re-embedded with an untrusted claim signer (vector 35), each record version's header labels in a record of the other version (vectors 44 and 45, 9.1), and a record with two evidence entries whose files are supplied (vector 46), supplied with one altered (vector 47), not supplied (vector 48) or replaced by an unknown file (vector 49), a record whose human review method is `none` (vector 50), control characters in a 0.2 record and in a 0.1 record (vectors 51 and 52, 4.1 and 11.8), test lists recognised by their keys after their manifests were edited (vectors 53 to 57, 10.6), a reserved identifier claimed by another root (vector 54, 10.7), an expected trust list fingerprint that the list does not and does have (vectors 58 and 59, 10.4), an accountable person who is not the named signer (vector 60), a certificate with two O values (vector 61), a certificate with no Avok Attest policy (vector 62, 11.4), and a citation check made for another deliverable (vector 63) or whose summary differs from the record's (vector 64, 11.10), a delta CRL listing the revocation before the signing time (vector 65, 11.5 step 8) and a token without a signing-certificate attribute (vector 66, 11.5 step 6), manifests that break the rules of 10.2 (an upper-case identifier, a trailing dot and a `test` string, vectors 55 to 57; a zero-width space, a Cyrillic letter, a fullwidth dot, a soft hyphen and a doubled dot in an identifier made to look like the pilot list's, an identifier given as an array and an integer above 2^53, vectors 67 to 73), an expected revocation list fingerprint that no loaded CRL has and that one has (vectors 74 and 75, 11.5 step 8), a root carrying a published test key as a compressed EC point (vector 76, 10.6), files bound as a citation check that are not readable citation checks (another format, no header, a byte order mark, not JSON; vectors 77 to 80, 11.10) and the review method `none` with and without a statement (vectors 50 and 81, 4.6). Verifiers claiming to be designed to meet this specification SHOULD reproduce every expected outcome.

Each vector folder holds `expected.json` with these members: `name`; `description`; `deliverable` and `envelope` (file names within the folder; the envelope is a `.daur.cose` file or, for the wrapper vectors, a `.daur.json` file); `mode` (`sidecar`; `c2pa` when a carrier is also present, in which case `c2pa` names it and the outcome is still that of the sidecar envelope; or `c2pa-carrier`, where the outcome is that of reading the carrier named in `c2pa.carrier` without the source asset, which verifiers without C2PA support skip, vector 35); `allow_test_trust` (whether the vector is verified in test mode, 10.6; `true` for every vector except 27, 53 to 57, 67 to 73 and 76); `trust`, OPTIONAL, a trust directory inside the vector folder used instead of `vectors/trust/` (vectors 53 to 57, 67 to 73 and 76); `trust_fingerprint`, OPTIONAL, the expected trust list fingerprint the verifier is given (10.4, vectors 58 and 59); `crls`, OPTIONAL, CRL files in the folder that the verifier is given besides the trust list (vectors 33, 34, 65, 74 and 75); `crl_fingerprints`, OPTIONAL, the expected revocation list fingerprints the verifier is given (11.5 step 8, vectors 74 and 75); `evidence`, OPTIONAL, evidence files in the folder that the verifier is given (11.10; an empty list means none, vectors 46 to 49, 63, 64 and 77 to 80); `profile`, `result` and `codes` (a headline for the README, equal to one of the profiles below); `profiles`, an object with a `pilot` and a `strict` member, each `{ "result": "PASS" | "FAIL", "fail_codes": [...], "warn_codes": [...] }`; and `browser`, OPTIONAL, of the same shape, the outcome of a verifier with the reference browser verifier's stated limits (11.9) where it differs from `profiles` (vectors 06, 13 and 23), whose `result` may be `UNSUPPORTED` with an `unsupported` list of capabilities. `statement_includes` and `statement_excludes`, OPTIONAL, are lists of text that the generated statement (11.8) MUST contain and MUST NOT contain (vectors 50 to 52 and 81). An implementation reproduces the vector when, for each profile, its outcome equals `result` and its FAIL and WARN codes equal `fail_codes` and `warn_codes` as sets (each code once, 11.2). Informational codes and messages are not compared, nor is the statement text beyond `statement_includes` and `statement_excludes`. The trust list for every vector is `vectors/trust/`, a test list (10.6), unless `trust` names another.

## Appendix D. References

- RFC 2119, RFC 8174: requirement keywords.
- RFC 3161: Internet X.509 PKI Time-Stamp Protocol. RFC 5816: ESSCertIDv2 update.
- RFC 4648: base encodings. RFC 4514: string representation of distinguished names. RFC 4519: LDAP schema for user applications (attribute descriptors).
- RFC 5280: X.509 certificates and CRLs. RFC 6960: OCSP.
- RFC 6979: deterministic ECDSA.
- RFC 8259: JSON. RFC 8785: JSON Canonicalization Scheme.
- RFC 8949: CBOR. RFC 9052, RFC 9053: COSE (RFC 9052 section 11.1 for the header parameter label ranges). RFC 9360: COSE X.509 header parameters.
- IANA, "CBOR Object Signing and Encryption (COSE)" registries, "COSE Header Parameters", https://www.iana.org/assignments/cose.
- C2PA technical specification 2.x, Coalition for Content Provenance and Authenticity.
