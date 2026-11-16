# Security policy

## Reporting a vulnerability

Report security issues in the specification, the HTML verifier or the pilot trust list to bd@avoksystems.ca, with "Avok Attest security" in the subject line. Include the version or file hash, the steps to reproduce and the impact you believe it has. Please do not open a public issue for a vulnerability before we have responded.

We acknowledge reports within five business days and aim to give an assessment within fifteen. We ask reporters to give us ninety days before public disclosure, and we credit reporters who want to be credited.

## Scope

In scope: anything that lets a record pass verification when it should not (forged or transplanted signatures, tampering not detected, time or revocation checks bypassed, trust-list checks bypassed), anything that makes a valid record fail in a way an attacker can trigger, and any network access from the HTML verifier.

Out of scope: the truthfulness of what a producer declares, and the operational security of keys held by producers.

## Supported versions

Version 0.2 of the specification and verifier release 0.2.0 with the pilot trust list 2026.11.4. Fixes are published as new versions.

## Keys

This repository contains no private keys. Revocation requests for certificates under the pilot trust list follow `trust/POLICY.md`, section 5.
