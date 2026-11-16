# Avok Attest pilot certificate policy and relying-party terms

Version 0.2, 10 November 2026. Applies to the pilot trust list `ca.avoksystems.attest.pilot` from version 2026.11.4. It does not apply to the test list `ca.avoksystems.attest.test` of the reference repository, whose root key is published. This is a pilot arrangement for Avok's own records and for design partners. It is not a public certification service, and no third party has audited it.

## 1. What the pilot certificate authority does

Avok Systems Inc. operates a root certificate authority for the pilot. It issues signer and organisation seal certificates to Avok and to organisations that take part in the pilot. It issues no time-stamping certificates for the pilot list (section 4). Each trust-list release lists the pilot root, its fingerprint and validity window, the public authorities' time-stamping CA certificates it accepts, any retroactive invalidity dates and the `revocation_max_age` that bounds how old revocation data may be at the signing time. Each release carries a version of the form YYYY.MM.N and the SHA-256 of its canonical manifest, the trust list fingerprint; records pin the version they were signed under. Only the fingerprint identifies a release: the identifier and version are labels. The identifier `ca.avoksystems.attest.pilot` is reserved: both reference verifiers refuse a list that claims it unless it lists exactly the registered root set, that is the pilot root for record signing (daur-signing) only and, for time-stamping only, no certificate other than the three of section 4 (`TRUST_LIST_ID_RESERVED`, specification 10.7). The registry that names this set (`src/daur/data/reserved-lists.json`, which the HTML verifier build reads) is updated with each pilot list version that changes the roots, for example when a time-stamping authority moves to a new CA; a verifier older than that list version refuses it until it carries the new registry.

## 2. Where the root key is held and who operates it

The pilot root key is held on an Avok computer that is connected to the internet. The certificate authority is operated by an AI agent under the direction of Avok's owner: the agent runs the `daur` commands that issue certificates, renew the revocation list and export the trust list, and the owner decides what is issued and revoked. No hardware security module is used. This arrangement suits Avok's own records and pilots. Before any third party relies on the list, Avok recommends, and intends, moving the root key to an offline machine (`docs/key-ceremony.md`, section 8).

## 3. How certificates are issued

A signer certificate names the organisation (O), the accountable person (CN) and that person's role (title), with the country. An organisation seal certificate names the organisation (O) and a seal name (CN, for example "Example Consulting Ltd. Attest seal") and no person. Before issuing, Avok confirms the organisation's legal name against its public corporate record and confirms the requester's authority through a written request from an officer of that organisation.

Certificates are issued from a public key or a certificate request (`daur ca issue --public-key` or `--csr`): the organisation makes its key pair on its own equipment (`daur key new`) and sends only the public key or a request. Avok never holds a signer's private key. The subject always comes from Avok's vetting, never from the request. Certificates are valid for at most 400 days, and `daur ca issue` refuses a longer `--days` for the signer and seal profiles. Serial numbers are random. The profile is a non-CA certificate with the digitalSignature and nonRepudiation key usages and the extended key usages id-kp-documentSigning and id-kp-emailProtection, which satisfies the signing-certificate rule of specification 11.4.

Each certificate asserts one certificate policy identifier, minted under the UUID arc 2.25 (ITU-T X.667):

| Policy | UUID | OID | Issued by |
| --- | --- | --- | --- |
| Avok Attest organisation seal | `eaee1f9c-06a4-42c2-9927-8a0a43146159` | `2.25.312275758782348157821337947671413154137` | `daur ca issue --profile seal` |
| Avok Attest named signer | `161f973b-1648-4762-8d58-fa32b2c3f21d` | `2.25.29407044435090518585266348200233792029` | `daur ca issue --profile signer` |

A record signed with a seal certificate may name any accountable person; verifiers print that the person is named by the organisation and not in the certificate. A record signed with a named-signer certificate must name the certificate's own person, or it fails in the strict profile (`ACCOUNTABLE_PERSON_DIFFERS`). A verifier treats a certificate with neither policy as a named-signer certificate.

## 4. Time-stamping

The pilot list accepts time-stamps only from three public time-stamping authorities, DigiCert, Sectigo and GlobalSign. It lists, with the purpose time-stamping only, each authority's time-stamping CA certificate as a trust anchor: DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1 (a dated issuing CA under DigiCert Trusted Root G4), Sectigo Public Time Stamping Root R46 (in the form issued under USERTrust RSA Certification Authority) and GlobalSign Timestamping Root R45 (in the form issued under GlobalSign Root CA - R6). None of the three is a self-signed root. When an authority moves its time-stamping service to a new CA (DigiCert dates its issuing CAs), tokens from the new CA fail with "TSA root not in the trust list" until Avok publishes a list version that adds it; Avok watches the authorities' announcements and adds the successor before the old CA stops issuing. The pilot root is listed for record signing (daur-signing) only, so no time-stamp issued under it verifies against the pilot list. A record verified under the strict profile must carry a token from one of these authorities; under the pilot profile a missing token is a warning.

Avok has no contract with these authorities. It uses their public services as published, sends at most one request every 15 seconds to each (Sectigo's published guidance for its free service, https://sectigo.com/resources/time-stamping-server) and tries the next authority when one does not answer. Their availability is not guaranteed by Avok or, to Avok, by them.

`daur tsa serve` exists for tests and for an operator who chooses to run a service under its own trust list. A time-stamp from a service the signer's own organisation runs does not give time independent of the signer, and the pilot list does not accept one.

## 5. Revocation

An organisation may ask for revocation at any time by email from an address on its request of record; Avok also revokes on evidence of key compromise or misuse. The revocation list is renewed whenever a record is signed under the pilot list and at least before every signing session (`daur ca crl`), and is listed in the trust directory. The trust list fingerprint covers the manifest and the roots only, not the revocation list: the list is renewed without changing the fingerprint, so a copy of the trust directory passed on by anyone, a producer included, may hold an older revocation list or none. A relying party obtains the current revocation list from Avok, the operator of the list, not from the producer, and gives it to the verifier (`daur verify --crl`; with `--crl-fingerprint` when the contracting authority names its SHA-256). The verifier's line `Revocation: decided by ...` names the list that decided, where it came from and its SHA-256, and says when no later list was available. Verifiers accept revocation data as evidence only when it covers the signing time and is no older than the list's `revocation_max_age`; a revocation list issued at least 24 hours after the signing time decides on its own (specification 11.5 step 8). Where a compromise is found to pre-date the revocation, the trust manifest records an invalidity date for the certificate, and records time-stamped after that date verify as CERT_INVALID_RETROACTIVELY. Revocation of the public time-stamping authorities' certificates is not evaluated in this version; Avok withdraws one through an invalidity date if it learns of a compromise.

## 6. What a relying party may conclude

A PASS result means: the record was signed with a key whose certificate chains to a root the verifier's trust list accepts for signing, that certificate was within its validity window and not known to be revoked at the time-stamped signing time, the record has not changed since signing, and the deliverable file is the exact file the record names. A PASS result does not mean the statements in the record are true, that the deliverable is of any particular quality, or that any third party has examined it. Warnings reported with a PASS weaken it in the way the verifier states; a relying party decides whether to accept them. Given section 2, a relying party should weigh that the root key is held online and that the list has not been audited.

## 7. Limits of the pilot

The trust list, this policy and the services may change between releases; the version pinned in a record identifies which rules applied when it was signed. Avok makes no warranty to relying parties under the pilot and accepts no liability for reliance beyond what the law requires. Questions and revocation requests: bd@avoksystems.ca.

## 8. Terms the published test material is under

The keys, certificates and trust list under `vectors/` and `trust/` of the reference repository exist only to make the test vectors reproducible. They are published on purpose and must never be used to sign a real record. A verifier that is given the test list reports its identifier, `ca.avoksystems.attest.test`, and never reports PASS from it outside test mode.
