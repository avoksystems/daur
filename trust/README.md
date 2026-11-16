# Avok's pilot trust list, version 2026.11.4

`pilot-2026.11.4/` holds the trust list `ca.avoksystems.attest.pilot`, version 2026.11.4, issued on 10 November 2026: the roots (`avok-pilot-roots.pem`), the manifest (`avok-pilot-trust-manifest.json`) and the revocation list issued with it (`avok-pilot.crl.pem`, next update 17 November 2026). Its fingerprint, the SHA-256 of the canonical manifest that records pin, is `3382739d23cab3607ab1f83c34904c4cb9e1496b02224252a0140693a4a77f78`. The list's identifier and version are labels anyone can copy; only the fingerprint identifies it.

The list names the pilot root for record signing only and, for time-stamping only, the time-stamping certificate authorities of DigiCert, Sectigo and GlobalSign, so it accepts no time-stamp from a service Avok runs. `POLICY.md` in this folder is the certificate policy and the relying-party terms that apply to the list, including where the root key is held and who operates it.

The revocation list in this folder is a copy as of its issue date. A relying party obtains the current revocation list from Avok, the operator of the list, not from the producer of a record (`POLICY.md`, section 5).

| File | SHA-256 |
|---|---|
| `avok-pilot-roots.pem` | `dd29c451ad5eae1a651dce18142c4ee2d8f1d2792af2956af5eda5e04cd3c283` |
| `avok-pilot-trust-manifest.json` | `5069ef6f753d7bd30b87a5bc7cee45fda0e16c4caa919a7c99bf7b2b7e475d21` |
| `avok-pilot.crl.pem` | `f2502a3cdedba67a5eb9a96131d3cf0f1a06ed6022d00448ac7ac2460c9c33e6` |
