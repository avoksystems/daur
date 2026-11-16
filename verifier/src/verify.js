// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Core verification for the browser and Node verifier. Mirrors daur/verify.py; see the
// specification, section 11. Codes and messages follow the Python reference where feasible.

import * as x509 from "@peculiar/x509";
import { CborTag, decode as cborDecode, sigStructure } from "./cbor.js";
import { PURPOSE_SIGNING, PURPOSE_TIME_STAMPING, TrustStore, buildPath, checkPathAt, compareVersions, fingerprint, normaliseFingerprint, revocationStatus } from "./pki.js";
import { recompute } from "./regions.js";
import { evidenceErrors, validate as validateSchema } from "./schema.js";
import { plainStatement } from "./statement.js";
import { displayText, recordTextErrors } from "./display.js";
import { parseManifestText } from "./manifest.js";
import { OID_COMMON_NAME, OID_ORGANISATION, certNameDers, nameMatches, nameValues, sameText, serialMatches } from "./dn.js";
import { TimestampError, parseToken, verifyImprint } from "./tsa.js";
import { base64Decode, bytesEqual, formatRfc3339, jcsBytes, normaliseSerial, parseRfc3339, pemBlocks, sha256, sha256Hex, utf8 } from "./util.js";

function utf8Prefix(bytes) {
  return new TextDecoder().decode(bytes.slice(0, 10));
}
import SCHEMA from "./schema.generated.js";
import RESULT_CODES from "./result-codes.generated.js";
import TRUST_BUNDLE from "./trust-bundle.generated.js";

export const MEDIA_TYPE = "application/vnd.avok.daur+json";
export const VERIFIER_VERSION = "0.2.0";
export const BUNDLED_TRUST = TRUST_BUNDLE;
// spec/result-codes.json: class, one-sentence meaning and what to do next for every code.
export const CODES = RESULT_CODES.codes;
export function codeInfo(code) {
  return CODES[code] || null;
}
// Certificate policy identifiers under the UUID arc 2.25 (specification 11.4; daur/ca.py).
export const OID_POLICY_SEAL = "2.25.312275758782348157821337947671413154137";
export const OID_POLICY_SIGNER = "2.25.29407044435090518585266348200233792029";
// Printed beside the accountable person when a seal certificate signed the record (11.8).
export const PERSON_NAMED_BY_ORGANISATION = " (named by the organisation; not in the certificate)";

// One DER element at `at`: { tag, start (of the content), end }.
function derElement(bytes, at) {
  const tag = bytes[at];
  let len = bytes[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error("unsupported DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[start + i];
    start += n;
  }
  if (start + len > bytes.length) throw new Error("truncated DER");
  return { tag, start, end: start + len };
}

// An OBJECT IDENTIFIER's content octets in dotted form; BigInt, because arcs under 2.25 are 128-bit
// numbers (the X.509 library cannot print them).
function oidText(bytes) {
  const arcs = [];
  let value = 0n;
  for (const b of bytes) {
    value = (value << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(value);
      value = 0n;
    }
  }
  if (!arcs.length) return "";
  const first = arcs[0] < 80n ? arcs[0] / 40n : 2n;
  return [first, arcs[0] - first * 40n, ...arcs.slice(1)].map(String).join(".");
}

// The policy identifiers of a certificatePolicies extension value (RFC 5280 4.2.1.4).
export function policyIdentifiers(extnValue) {
  const bytes = new Uint8Array(extnValue);
  const seq = derElement(bytes, 0);
  if (seq.tag !== 0x30) throw new Error("certificatePolicies is not a SEQUENCE");
  const out = [];
  for (let at = seq.start; at < seq.end; ) {
    const info = derElement(bytes, at);
    const oid = derElement(bytes, info.start);
    if (info.tag !== 0x30 || oid.tag !== 0x06) throw new Error("malformed PolicyInformation");
    out.push(oidText(bytes.subarray(oid.start, oid.end)));
    at = info.end;
  }
  return out;
}

// "seal" for a certificate with the organisation seal policy, else "signer": a certificate with
// neither policy, or both, or an unreadable extension, is treated as a named-signer certificate.
function certificateType(cert) {
  try {
    const ext = cert.extensions.find((e) => e.type === "2.5.29.32");
    const policies = ext ? policyIdentifiers(ext.value) : [];
    return policies.includes(OID_POLICY_SEAL) && !policies.includes(OID_POLICY_SIGNER) ? "seal" : "signer";
  } catch {
    return "signer";
  }
}
const ALG_ES256 = -7;
const ALG_EDDSA = -8;
const ALG_NAMES = { [ALG_ES256]: "ES256", [ALG_EDDSA]: "EdDSA" };
const CREATED_TOLERANCE_MS = 5 * 60 * 1000;
// The first output line of every result obtained in test mode (specification 10.6).
export const TEST_RESULT_LINE = "TEST RESULT (test trust list: proves nothing about any real signer)";
// The first output line of every result in the pilot profile (specification 11.1).
// Specification 11.8: appended to the certificate line when the signer's path ends at no anchor.
export const UNTRUSTED_SIGNER_NOTE = "(this certificate is not trusted by your list)";
// The heading of the statement after a FAIL, the same on every surface.
export const FAILED_STATEMENT_HEADING = "Statement (from a record that FAILED; do not rely on it)";
// Specification 11.8: appended to the time-stamp line when the token and the signer chain to the same anchor.
export const TIMESTAMP_FROM_SIGNER_CA_NOTE = "(the time-stamp comes from the signer's own certificate authority; it is not independent of the signer)";
// Specification 10.4: the fingerprint note of the outcome line, the page banner and the statement box.
export const FINGERPRINT_NOT_COMPARED = "trust list fingerprint not compared";
export const FINGERPRINT_MATCHES = "trust list fingerprint matches the expected one";
export const FINGERPRINT_NOT_COMPARED_SENTENCE = "Trust list fingerprint not compared: check it against the one your contract names.";
// Review V4 N3: the revocation data that decided, named on every surface (specification 11.5 step 8).
export const NO_LATER_LIST_NOTE =
  "No later revocation list was available to this check; a revocation recorded afterwards with an earlier invalidity date would not be seen. Obtain the current list from the trust list operator, not from the producer.";
const CRL_SOURCE_WORDS = { stapled: "stapled at signing", trust_directory: "from the trust directory", supplied: "supplied to this check" };

export function revocationPhrase(decided) {
  if (decided.kind === "ocsp") return "the OCSP response stapled at signing";
  const source = decided.source || "supplied";
  if (source === "stapled") return "the list stapled at signing";
  return `a ${decided.evidence === "later_crl" ? "later " : ""}list ${CRL_SOURCE_WORDS[source] || source}`;
}

export function revocationNote(details) {
  const decided = (details.revocation || {}).decided_by;
  return decided && decided.evidence !== "later_crl" && !decided.later_available ? NO_LATER_LIST_NOTE : "";
}

export function revocationLine(details) {
  const r = details.revocation;
  if (!r) return "";
  const decided = r.decided_by;
  if (decided) return `Revocation: decided by ${revocationPhrase(decided)}, issued ${decided.this_update}, SHA-256 ${decided.sha256}`;
  return displayText(`Revocation: not decided; ${r.detail || ""}`);
}

async function crlSummary(crl, source) {
  let thisUpdate = null;
  let nextUpdate = null;
  try {
    thisUpdate = formatRfc3339(crl.thisUpdate);
    nextUpdate = crl.nextUpdate ? formatRfc3339(crl.nextUpdate) : null;
  } catch {
    // dates the parser could not read
  }
  return { source, issuer: crl.issuer, this_update: thisUpdate, next_update: nextUpdate, sha256: await sha256Hex(new Uint8Array(crl.rawData)) };
}

// Each expected revocation list fingerprint must be the SHA-256 of a loaded CRL (review V4 N3).
function checkCrlFingerprints(result, expected) {
  if (!expected || !expected.length) return;
  const loaded = [...new Set((result.details.crls_loaded || []).map((c) => c.sha256))].sort();
  const checked = [];
  for (const value of expected) {
    const want = normaliseFingerprint(value);
    const matched = loaded.includes(want);
    checked.push({ sha256: want, matched });
    if (matched) result.info("CRL_FINGERPRINT_MATCH", `a loaded revocation list has the expected SHA-256 ${want}`);
    else result.fail("CRL_NOT_THE_EXPECTED_ONE", `no loaded revocation list has the expected SHA-256 ${want}; the lists loaded have ${loaded.length ? loaded.join(", ") : "none"}`);
  }
  result.details.crl_fingerprints = checked;
}

export const PILOT_PROFILE_LINE =
  "Pilot profile: a missing time-stamp and missing revocation data are warnings in this profile, not failures; use the strict profile for a contractual result.";

export class Result {
  constructor(profile) {
    this.profile = profile;
    this.findings = [];
    this.details = {};
    this.record = null;
    this.statement = "";
    this.testTrustList = false;
    // Specification 10.4: whether an expected trust list fingerprint was given, and whether it matched.
    this.trustFingerprintChecked = false;
    this.trustFingerprintMatched = false;
  }
  // Lines shown before the outcome: the test-list label and the pilot caveat.
  preamble() {
    const lines = [];
    if (this.testTrustList) lines.push(TEST_RESULT_LINE);
    if (this.profile === "pilot") lines.push(PILOT_PROFILE_LINE);
    return lines;
  }
  fail(code, message) {
    this.findings.push({ severity: "FAIL", code, message });
  }
  warn(code, message) {
    this.findings.push({ severity: "WARN", code, message });
  }
  info(code, message) {
    this.findings.push({ severity: "INFO", code, message });
  }
  // Specification 11.2 and 11.9: this verifier lacks a capability the profile requires here.
  unsupported(capability, message) {
    this.findings.push({ severity: "UNSUPPORTED", code: "UNSUPPORTED", message, capability });
  }
  get result() {
    if (this.findings.some((f) => f.severity === "FAIL")) return "FAIL";
    if (this.findings.some((f) => f.severity === "UNSUPPORTED")) return "UNSUPPORTED";
    return "PASS";
  }
  get unsupportedCapabilities() {
    return unique(this.findings.filter((f) => f.severity === "UNSUPPORTED").map((f) => f.capability));
  }
  // "Time-stamp issued by <CN>, <O>", or that the time is the signer's own (specification 11.8).
  timestampLine() {
    const ts = this.details.timestamp;
    if (this.details.signing_time_source === "timestamp" && ts) {
      let line = `Time-stamp issued by ${(ts.tsa_common_name || []).join(", ") || "(no common name)"}, ${(ts.tsa_organisation || []).join(", ") || "(no organisation)"}`;
      const a = ts.anchor;
      if (a) line += `, under ${(a.common_name || []).join(", ") || "(no common name)"}, ${(a.organisation || []).join(", ") || "(no organisation)"} (anchor fingerprint ${a.sha256_fingerprint.slice(0, 16)}...)`;
      if (ts.from_signer_ca) line += ` ${TIMESTAMP_FROM_SIGNER_CA_NOTE}`;
      return displayText(line);
    }
    if (this.details.signing_time_source === "record.created") return "Time taken from the signer's own clock";
    return "";
  }
  // One entry per FAIL, WARN and UNSUPPORTED code: { code, meaning, next } from spec/result-codes.json.
  explanations() {
    const codes = unique([...this.failCodes, ...this.warnCodes, ...(this.result === "UNSUPPORTED" ? ["UNSUPPORTED"] : [])]);
    return codes.map((code) => ({ code, ...(codeInfo(code) || { meaning: "", next: "" }) }));
  }
  get failCodes() {
    return unique(this.findings.filter((f) => f.severity === "FAIL").map((f) => f.code));
  }
  get warnCodes() {
    return unique(this.findings.filter((f) => f.severity === "WARN").map((f) => f.code));
  }
  // "Signed with a certificate issued to <CN>, <O>", from the certificate (specification 11.8).
  // True when the signer's path ends at an anchor of the trust list that covers it (11.4).
  get signerTrusted() {
    return Boolean(this.details.trust_anchor) && !this.findings.some((f) => f.code === "UNTRUSTED_ROOT");
  }
  certificateLine() {
    const s = this.details.signer;
    if (!s) return "";
    const cn = (s.common_name || []).join(", ") || "(no common name)";
    const org = (s.organisation || []).join(", ") || "(no organisation)";
    return displayText(`Signed with a certificate issued to ${cn}, ${org}${this.signerTrusted ? "" : ` ${UNTRUSTED_SIGNER_NOTE}`}`);
  }
  // "Revocation: decided by <evidence>, issued <thisUpdate>, SHA-256 <hash>" (review V4 N3).
  revocationLine() {
    return revocationLine(this.details);
  }
  revocationNote() {
    return revocationNote(this.details);
  }
  // "Trust list: <name>, <id> <version>, fingerprint <64 hex>" (specification 10.4).
  trustListLine() {
    const d = this.details;
    if (d.trust_list_invalid) return "Trust list: the manifest breaks the rules of specification 10.2; nothing was read from it";
    if (!d.trust_list_fingerprint) return "Trust list: (no manifest, so no fingerprint)";
    return displayText(`Trust list: ${d.trust_list_name || "(no name)"}, ${d.trust_list_id || "(no identifier)"} ${d.trust_list_version || "(unversioned)"}, fingerprint ${d.trust_list_fingerprint}`);
  }
  // `result` of the JSON output: PASS, FAIL, UNSUPPORTED, or the TEST forms in test mode (10.6).
  get reportedResult() {
    if (!this.testTrustList) return this.result;
    if (this.result === "FAIL") return "TEST FAIL";
    if (this.result === "UNSUPPORTED") return "TEST UNSUPPORTED";
    return this.warnCodes.length ? "TEST PASS with warnings" : "TEST PASS";
  }
  summaryLine() {
    if (this.result === "FAIL") return `FAIL (${this.failCodes.join(", ")})`;
    if (this.result === "UNSUPPORTED") return `UNSUPPORTED (${this.unsupportedCapabilities.join(", ")}): use the command-line verifier`;
    if (this.warnCodes.length) return `PASS with warnings (${this.warnCodes.join(", ")})`;
    return "PASS";
  }
  // What became of the trust list fingerprint (specification 10.4).
  fingerprintNote() {
    if (!this.trustFingerprintChecked) return FINGERPRINT_NOT_COMPARED;
    return this.trustFingerprintMatched ? FINGERPRINT_MATCHES : "";
  }
  // The outcome as the command line prints it: a pass carries the fingerprint note in brackets.
  outcomeLine() {
    const note = this.fingerprintNote();
    return this.result === "PASS" && note ? `${this.summaryLine()} (${note})` : this.summaryLine();
  }
  toJSON() {
    return {
      result: this.reportedResult,
      profile: this.profile,
      test_trust_list: this.testTrustList,
      trust_fingerprint_checked: this.trustFingerprintChecked,
      fail_codes: this.failCodes,
      warn_codes: this.warnCodes,
      unsupported: this.unsupportedCapabilities,
      findings: this.findings,
      details: this.details,
      statement: this.statement,
      record: this.record,
    };
  }
}

function unique(items) {
  return [...new Set(items)];
}

// `value` when it is a JSON object, else an empty one (schema failures are reported separately).
function obj(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

export async function loadBundledTrust() {
  return TrustStore.fromPem(TRUST_BUNDLE.pem, TRUST_BUNDLE.manifest);
}

// The manifest text is parsed as I-JSON and checked against the rules of specification 10.2 before
// anything is read from it; text that is not JSON at all throws, as JSON.parse does.
export async function loadTrust(pemText, manifestJsonText = null) {
  if (!manifestJsonText) return TrustStore.fromPem(pemText, null);
  const { value, problems } = parseManifestText(manifestJsonText);
  return TrustStore.fromPem(pemText, value, problems);
}

/** Split .daur.cose or .daur.json bytes into { coseBytes, wrapperRecord }. */
export function loadEnvelope(bytes) {
  // Specification 5.2: an optional UTF-8 byte order mark, then JSON whitespace, then "{" is a wrapper.
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) bytes = bytes.subarray(3);
  let i = 0;
  while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x0a || bytes[i] === 0x0d || bytes[i] === 0x09)) i++;
  if (bytes[i] === 0x7b) {
    let wrapper;
    try {
      wrapper = JSON.parse(utf8(bytes));
    } catch (err) {
      throw new Error(`JSON wrapper is not valid JSON: ${err.message}`);
    }
    if (!wrapper || typeof wrapper !== "object" || !("record" in wrapper) || !("signature" in wrapper)) throw new Error("JSON wrapper must carry 'record' and 'signature'");
    const b64 = wrapper.signature && wrapper.signature.cose_sign1_b64;
    if (typeof b64 !== "string") throw new Error("JSON wrapper signature must carry 'cose_sign1_b64'");
    return { coseBytes: base64Decode(b64), wrapperRecord: wrapper.record };
  }
  return { coseBytes: bytes, wrapperRecord: null };
}

function decodeSign1(bytes) {
  // Specification section 9.1 requires CBOR tag 18 and section 11.5 step 1 checks it.
  let obj = cborDecode(bytes);
  if (!(obj instanceof CborTag)) throw new Error("envelope is not tagged; CBOR tag 18 (COSE_Sign1) is required");
  if (obj.tag !== 18) throw new Error(`unexpected CBOR tag ${obj.tag}; expected 18 (COSE_Sign1)`);
  obj = obj.value;
  if (!Array.isArray(obj) || obj.length !== 4) throw new Error("COSE_Sign1 must be an array of four elements");
  const [protectedBytes, unprotected, payload, signature] = obj;
  if (!(protectedBytes instanceof Uint8Array)) throw new Error("protected header must be a byte string");
  if (!(unprotected instanceof Map)) throw new Error("unprotected header must be a map");
  if (payload === null) throw new Error("detached payloads are not permitted in DAUR envelopes");
  if (!(payload instanceof Uint8Array)) throw new Error("payload must be a byte string");
  if (!(signature instanceof Uint8Array)) throw new Error("signature must be a byte string");
  let header = new Map();
  if (protectedBytes.length) {
    header = cborDecode(protectedBytes);
    if (!(header instanceof Map)) throw new Error("protected header must be a map");
  }
  if (!header.has(1)) throw new Error("protected header lacks alg (label 1)");
  if (!(header.get(1) in ALG_NAMES)) throw new Error(`unsupported algorithm ${header.get(1)}`);
  return { protectedBytes, header, unprotected, payload, signature };
}

function x5chain(header) {
  const v = header.get(33);
  if (v === undefined) return [];
  if (v instanceof Uint8Array) return [v];
  if (Array.isArray(v) && v.every((i) => i instanceof Uint8Array)) return v;
  throw new Error("x5chain must be a byte string or an array of byte strings");
}

// Specification 9.1: the DAUR header labels of each record version. Record 0.2 uses the private-use
// range (RFC 9052 section 11.1, integers less than -65536); record 0.1 used 7001 to 7004.
export const LABELS_V02 = Object.freeze({ timestamp: -70001, revocation: -70002, snapshotDigest: -70003, trustPin: -70004 });
export const LABELS_V01 = Object.freeze({ timestamp: 7001, revocation: 7002, snapshotDigest: 7003, trustPin: 7004 });
export function labelsForVersion(version) {
  return version === "0.1" ? LABELS_V01 : LABELS_V02;
}

function snapshotOf(unprotected, labels) {
  const label = labels.revocation;
  const v = unprotected.get(label);
  if (v === undefined) return [];
  if (!Array.isArray(v) || !v.every((i) => i instanceof Uint8Array)) throw new Error(`header ${label} must be an array of byte strings`);
  return v;
}

function digestsOf(header, labels) {
  const label = labels.snapshotDigest;
  const v = header.get(label);
  if (v === undefined) return null;
  if (!Array.isArray(v) || !v.every((i) => i instanceof Uint8Array && i.length === 32)) throw new Error(`header ${label} must be an array of 32-byte digests`);
  return v;
}

function pinOf(header, labels) {
  const label = labels.trustPin;
  const v = header.get(label);
  if (v === undefined) return null;
  if (!(v instanceof Map)) throw new Error(`header ${label} must be a map`);
  const pin = {};
  for (const [k, val] of v) {
    if (typeof k !== "string" || typeof val !== "string") throw new Error(`header ${label} keys and values must be text strings`);
    pin[k] = val;
  }
  for (const req of ["trust_list_id", "version", "sha256"]) if (!(req in pin)) throw new Error(`header ${label} lacks ${req}`);
  return pin;
}

// The certificate's key type must be the one the alg header names (ES256: ECDSA on P-256,
// EdDSA: Ed25519); any other pairing is SIGNATURE_INVALID rather than a WebCrypto error.
async function verifyCose(alg, cert, signature, tbs) {
  const key = await cert.publicKey.export();
  const type = key.algorithm.name;
  if (alg === ALG_ES256) {
    if (type !== "ECDSA" || key.algorithm.namedCurve !== "P-256") throw new Error(`alg ES256 requires a P-256 ECDSA key, the certificate carries ${type}`);
    if (signature.length !== 64) return false;
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, tbs);
  }
  if (type !== "Ed25519") throw new Error(`alg EdDSA requires an Ed25519 key, the certificate carries ${type}`);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, tbs);
}

/**
 * Verify an envelope.
 * @param {object} input { envelope: Uint8Array, deliverable: Uint8Array|null, fileName: string|null, trust: TrustStore,
 *   profile: 'pilot'|'strict' (default strict), allowTestTrust: boolean (test mode, specification 10.6),
 *   crls: [Uint8Array (DER or PEM) | string (PEM)] further CRLs, verificationTime: Date for the next_update note,
 *   evidence: [{ name: string, bytes: Uint8Array }] evidence files delivered beside the record (specification 11.10),
 *   trustFingerprint: string, the trust list fingerprint the relying party expects (specification 10.4),
 *   crlFingerprints: [string] SHA-256 values of revocation lists the relying party expects (11.5 step 8) }
 */
export async function verify(input) {
  const profile = input.profile || "strict";
  if (!["pilot", "strict"].includes(profile)) throw new Error("profile must be pilot or strict");
  const trust = input.trust;
  const result = new Result(profile);
  result.details.verifier = `avok-attest-verifier ${VERIFIER_VERSION} (browser)`;
  const expectedFingerprint = input.trustFingerprint ?? null;
  result.trustFingerprintChecked = expectedFingerprint !== null && String(expectedFingerprint).trim() !== "";
  if (trust.manifestInvalid) {
    // Specification 10.2: nothing is read from a manifest that breaks the rules, and no verdict can rest on it.
    result.details.trust_list_invalid = true;
    for (const problem of trust.manifestProblems.slice(0, 20)) result.fail("TRUST_LIST_INVALID", `trust list manifest: ${problem}`);
    return result;
  }
  if (trust.version) result.details.trust_list_version = trust.version;
  if (trust.id) result.details.trust_list_id = trust.id;
  if (trust.name) result.details.trust_list_name = trust.name;
  if (trust.fingerprint) result.details.trust_list_fingerprint = trust.fingerprint;
  checkTrustList(result, trust, profile, Boolean(input.allowTestTrust));
  checkTrustFingerprint(result, trust, profile, input.trustFingerprint ?? null);
  const extraCrls = [];
  for (const item of input.crls || []) {
    try {
      const text = typeof item === "string" ? item : null;
      const bytes = item instanceof Uint8Array ? item : null;
      const pem = text ?? (bytes && utf8Prefix(bytes) === "-----BEGIN" ? utf8(bytes) : null);
      if (pem !== null) {
        const blocks = pemBlocks(pem, "X509 CRL");
        if (!blocks.length) throw new Error("no PEM CRL block");
        for (const der of blocks) extraCrls.push(new x509.X509Crl(der));
      } else extraCrls.push(new x509.X509Crl(bytes));
    } catch (err) {
      result.info("CRL_UNREADABLE", `a supplied CRL cannot be parsed and was ignored: ${err.message}`);
    }
  }
  // Review V4 N3: every revocation list loaded, with its source and SHA-256, is part of the result.
  result.details.crls_loaded = [];
  for (const crl of trust.crls) result.details.crls_loaded.push(await crlSummary(crl, "trust_directory"));
  for (const crl of extraCrls) result.details.crls_loaded.push(await crlSummary(crl, "supplied"));

  // 1. Envelope
  let msg;
  let wrapperRecord = null;
  try {
    const loaded = loadEnvelope(input.envelope);
    wrapperRecord = loaded.wrapperRecord;
    msg = decodeSign1(loaded.coseBytes);
  } catch (err) {
    result.fail("ENVELOPE_MALFORMED", err.message);
    return result;
  }
  const alg = msg.header.get(1);
  result.details.algorithm = ALG_NAMES[alg];
  if (msg.header.get(3) !== MEDIA_TYPE) result.fail("ENVELOPE_MALFORMED", `content type is ${JSON.stringify(msg.header.get(3))}, expected ${JSON.stringify(MEDIA_TYPE)}`);

  // 2. Payload and record
  let record = null;
  try {
    record = JSON.parse(utf8(msg.payload));
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      result.fail("ENVELOPE_MALFORMED", "payload is not a JSON object");
      record = null;
    } else if (!bytesEqual(jcsBytes(record), msg.payload)) {
      result.fail("ENVELOPE_MALFORMED", "payload is not in RFC 8785 canonical form");
    }
  } catch (err) {
    result.fail("ENVELOPE_MALFORMED", `payload is not JSON: ${err.message}`);
  }
  result.record = record;
  // Specification 9.1: read the DAUR labels of the record's own version; the other version's labels
  // are ignored, as if the parameter were absent, and noted.
  const recordVersion = record ? record.daur_version : undefined;
  const labels = labelsForVersion(recordVersion);
  const other = labels === LABELS_V01 ? LABELS_V02 : LABELS_V01;
  for (const label of [other.timestamp, other.revocation, other.snapshotDigest, other.trustPin]) {
    if (msg.header.has(label) || msg.unprotected.has(label)) {
      result.info(
        "HEADER_LABEL_NOT_FOR_VERSION",
        `header label ${label} does not belong to record version ${typeof recordVersion === "string" ? recordVersion : "(unknown)"} and was ignored (specification 9.1)`,
      );
    }
  }
  if (record) {
    for (const err of [...validateSchema(record, SCHEMA), ...evidenceErrors(record), ...recordTextErrors(record)].slice(0, 20)) result.fail("SCHEMA_INVALID", err);
  }
  if (wrapperRecord !== null && record) {
    try {
      if (!bytesEqual(jcsBytes(wrapperRecord), msg.payload)) result.fail("RECORD_ALTERED", "the record in the JSON wrapper differs from the signed payload");
    } catch (err) {
      result.fail("RECORD_ALTERED", `the record in the JSON wrapper cannot be canonicalised: ${err.message}`);
    }
  }

  // 3. Certificates and signature
  let certs = [];
  try {
    certs = x5chain(msg.header).map((der) => new x509.X509Certificate(der));
  } catch (err) {
    result.fail("ENVELOPE_MALFORMED", `x5chain is unusable: ${err.message}`);
  }
  if (!certs.length) {
    result.fail("ENVELOPE_MALFORMED", "x5chain is missing from the protected header");
    result.statement = record ? safeStatement(record, null, null) : "";
    return result;
  }
  const leaf = certs[0];
  // The subject as the DER the certificate carries (verifier/src/dn.js reads it directly).
  let leafSubjectDer = new Uint8Array(0);
  try {
    leafSubjectDer = certNameDers(leaf.rawData).subject;
  } catch {
    // an unreadable subject matches nothing and contributes no values
  }
  const leafFp = await fingerprint(leaf);
  result.details.signer = {
    subject: leaf.subject,
    serial: normaliseSerial(leaf.serialNumber),
    sha256_fingerprint: leafFp,
    not_before: formatRfc3339(leaf.notBefore),
    not_after: formatRfc3339(leaf.notAfter),
    common_name: nameValues(leafSubjectDer, OID_COMMON_NAME),
    organisation: nameValues(leafSubjectDer, OID_ORGANISATION),
    certificate_type: certificateType(leaf),
  };
  let signatureOk = false;
  try {
    signatureOk = await verifyCose(alg, leaf, msg.signature, sigStructure(msg.protectedBytes, msg.payload));
  } catch (err) {
    result.fail("SIGNATURE_INVALID", `signature could not be checked: ${err.message}`);
    signatureOk = null;
  }
  if (signatureOk === false) result.fail("SIGNATURE_INVALID", "COSE_Sign1 signature does not verify with the end-entity certificate");

  if (record) {
    const sc = obj(obj(record.producer).signing_certificate);
    const fp = String(sc.sha256_fingerprint || "").toLowerCase();
    if (fp && fp !== leafFp) result.fail("SIGNER_MISMATCH", "record names a signing certificate other than the one in x5chain");
    else if (fp) {
      // Specification 11.4: semantic comparison of the subject (RDN by RDN) and the serial (as integers).
      const differing = [];
      if (!serialMatches(String(sc.serial || ""), leaf.serialNumber)) differing.push("serial");
      if (!nameMatches(String(sc.subject || ""), leafSubjectDer)) differing.push("subject");
      if (differing.length) result.warn("SIGNER_DETAILS_DIFFER", `signing certificate ${differing.join(" and ")} in the record differ from the certificate`);
    }
    checkProducerNames(result, record, profile);
  }

  // 3b. Snapshot commitment
  let snapshot = [];
  try {
    snapshot = snapshotOf(msg.unprotected, labels);
    const digests = digestsOf(msg.header, labels);
    const report = profile === "strict" ? result.fail.bind(result) : result.warn.bind(result);
    if (digests === null) {
      if (snapshot.length) report("REVOCATION_SNAPSHOT_MISMATCH", `revocation snapshot present but not committed in the protected header (${labels.snapshotDigest})`);
      result.details.snapshot_commitment = "absent";
    } else if (!snapshot.length) {
      report("REVOCATION_SNAPSHOT_MISMATCH", "protected header commits to a revocation snapshot that is missing from the envelope");
      result.details.snapshot_commitment = "snapshot_missing";
    } else {
      let same = snapshot.length === digests.length;
      if (same) {
        for (let i = 0; i < snapshot.length; i++) {
          if (!bytesEqual(await sha256(snapshot[i]), digests[i])) same = false;
        }
      }
      if (!same) {
        report("REVOCATION_SNAPSHOT_MISMATCH", `revocation snapshot digests do not match the protected commitment (${snapshot.length} item(s) present, ${digests.length} committed)`);
        result.details.snapshot_commitment = "mismatch";
      } else result.details.snapshot_commitment = "verified";
    }
  } catch (err) {
    result.fail("ENVELOPE_MALFORMED", err.message);
  }
  for (const item of snapshot) {
    try {
      result.details.crls_loaded.push(await crlSummary(new x509.X509Crl(item), "stapled"));
    } catch {
      // an OCSP response, or not revocation data at all
    }
  }
  checkCrlFingerprints(result, input.crlFingerprints || []);

  // 3c. Trust-list pin
  try {
    const pin = pinOf(msg.header, labels);
    if (!pin) {
      if (profile === "strict") result.warn("TRUST_PIN_MISSING", `no trust-list pin in the protected header (${labels.trustPin})`);
      else result.info("TRUST_PIN_MISSING", `no trust-list pin in the protected header (${labels.trustPin})`);
    } else {
      result.details.trust_pin = pin;
      if (!trust.manifest) result.warn("TRUST_PIN_UNCHECKED", `envelope pins trust list ${pin.trust_list_id} ${pin.version} but the verifier has no manifest to compare`);
      else if (pin.trust_list_id !== trust.id) result.info("TRUST_LIST_ID_DIFFERS", `envelope pins trust list ${JSON.stringify(pin.trust_list_id)}; verifier uses ${JSON.stringify(trust.id)}`);
      else {
        const order = compareVersions(trust.version, pin.version);
        if (order === null) result.warn("TRUST_LIST_VERSION_UNORDERED", `cannot order verifier trust list version ${JSON.stringify(trust.version)} against pinned ${JSON.stringify(pin.version)}`);
        else if (order < 0) {
          result.warn("STALE_TRUST_STATE", `verifier trust list ${trust.id} is at version ${trust.version}, older than the pinned version ${pin.version}; update the trust list before relying on this result`);
        } else if (order === 0 && pin.sha256.toLowerCase() !== trust.digest) result.warn("TRUST_LIST_DIGEST_DIFFERS", `trust list ${trust.id} ${trust.version} differs from the pinned copy (digest mismatch)`);
        else if (order > 0) result.info("TRUST_LIST_NEWER", `verifier trust list version ${trust.version} is newer than the pinned ${pin.version}`);
        else result.info("TRUST_PIN_MATCH", `trust list ${trust.id} ${trust.version} matches the pinned version`);
      }
    }
  } catch (err) {
    result.fail("ENVELOPE_MALFORMED", err.message);
  }

  // 4. Time-stamp and signing time
  let created = null;
  if (record && typeof record.created === "string") created = parseRfc3339(record.created);
  let signingTime = null;
  let tsInfo = null;
  let tsSource = "record.created";
  const token = msg.unprotected.get(labels.timestamp);
  if (token !== undefined) {
    if (!(token instanceof Uint8Array)) result.fail("TIMESTAMP_INVALID", `header ${labels.timestamp} must be a byte string`);
    else {
      const check = await verifyTimestampToken(token, msg.signature, trust);
      tsInfo = check.info;
      for (const message of check.errors) result.fail("TIMESTAMP_INVALID", message);
      if (check.info && !check.errors.length) {
        signingTime = tsInfo.genTime;
        tsSource = "timestamp";
      }
      if (tsInfo) {
        const anchor = check.anchor;
        result.details.timestamp = {
          gen_time: formatRfc3339(tsInfo.genTime),
          tsa: tsInfo.tsaCert.subject,
          tsa_common_name: tsaNames(tsInfo.tsaCert, OID_COMMON_NAME),
          tsa_organisation: tsaNames(tsInfo.tsaCert, OID_ORGANISATION),
          serial: tsInfo.serialHex,
          policy: tsInfo.policy,
          accuracy_seconds: tsInfo.accuracySeconds,
        };
        if (anchor) {
          result.details.timestamp.anchor = {
            subject: anchor.cert.subject,
            common_name: tsaNames(anchor.cert, OID_COMMON_NAME),
            organisation: tsaNames(anchor.cert, OID_ORGANISATION),
            sha256_fingerprint: anchor.fingerprint,
          };
        }
      }
    }
  } else if (profile === "strict") result.fail("TIMESTAMP_MISSING", `strict profile requires an RFC 3161 time-stamp token (header ${labels.timestamp})`);
  else result.warn("TIMESTAMP_MISSING", "no RFC 3161 time-stamp token; signing time taken from the record");

  if (!signingTime) {
    if (created) {
      signingTime = created;
      tsSource = "record.created";
      result.warn("VALIDITY_JUDGED_AT_CREATED", `certificate validity judged at the record's created time ${formatRfc3339(created)}`);
    } else result.fail("ENVELOPE_MALFORMED", "no usable signing time (no time-stamp and no parsable created field)");
  } else if (created && signingTime.getTime() < created.getTime() - CREATED_TOLERANCE_MS) {
    result.warn("TIMESTAMP_BEFORE_CREATED", "the time-stamp predates the record's created time by more than five minutes");
  }
  checkNextUpdate(result, trust, signingTime, input.verificationTime || null);
  if (signingTime) {
    result.details.signing_time = formatRfc3339(signingTime);
    result.details.signing_time_source = tsSource;
  }

  // 5 and 6. Path and revocation at the signing time
  if (signingTime) {
    const pr = await buildPath(certs, trust, PURPOSE_SIGNING);
    if (pr.anchor) result.details.trust_anchor = { subject: pr.anchor.cert.subject, sha256_fingerprint: pr.anchor.fingerprint };
    await checkPathAt(result, pr, signingTime, "signing certificate", "UNTRUSTED_ROOT", trust);
    // Specification 11.8: a token under the signer's own anchor gives no time independent of the signer.
    const ts = result.details.timestamp;
    if (pr.anchor && tsSource === "timestamp" && ts && ts.anchor && ts.anchor.sha256_fingerprint === pr.anchor.fingerprint) {
      ts.from_signer_ca = true;
      result.info(
        "TIMESTAMP_FROM_SIGNER_CA",
        `the time-stamping certificate and the signing certificate chain to the same anchor (${pr.anchor.cert.subject}); the time-stamp comes from the signer's own certificate authority and is not independent of the signer`,
      );
    }
    // Revocation (11.5 step 8) is evaluated only when a path to a trust anchor exists.
    if (!pr.anchor) result.info("REVOCATION_NOT_EVALUATED", "revocation was not evaluated because the signing certificate has no path to a trust anchor");
    else {
      const issuer = pr.path.length > 1 ? pr.path[1] : pr.anchor.cert;
      const status = await revocationStatus(leaf, issuer, signingTime, snapshot, trust, extraCrls, trust.revocationMaxAgeMs);
      for (const message of status.weak || []) result.fail("CHAIN_INVALID", message);
      result.details.revocation = { status: status.status, detail: status.detail, snapshot_items: snapshot.length };
      if ((status.decidedBy === "later_crl" || status.decidedBy === "snapshot") && status.thisUpdate) {
        const decided = {
          evidence: status.decidedBy,
          kind: "crl",
          source: status.source,
          this_update: formatRfc3339(status.thisUpdate),
          sha256: await sha256Hex(new Uint8Array(status.evidence.rawData)),
          later_available: Boolean(status.laterAvailable),
        };
        result.details.revocation.decided_by = decided;
        const note = revocationNote(result.details);
        const message = `revocation was decided by ${revocationPhrase(decided)}, issued ${decided.this_update}, SHA-256 ${decided.sha256}`;
        if (status.decidedBy === "later_crl") result.info("REVOCATION_DECIDED_BY_LATER_CRL", `${message}, at least 24 hours after the signing time`);
        else result.info("REVOCATION_DECIDED_BY_SNAPSHOT", `${message}, which covers the signing time${note ? `. ${note}` : ""}`);
      }
      if (status.status === "revoked") result.fail("CERT_REVOKED_AT_SIGNING", status.detail);
      else if (status.status === "stale") {
        if (profile === "strict") result.fail("REVOCATION_MISSING", status.detail);
        else result.warn("REVOCATION_STALE", status.detail);
      } else if (status.status === "unknown") {
        if (profile === "strict" && status.ocspOnly) {
          // Specification 11.9: the only evidence is OCSP, which this verifier does not evaluate.
          result.unsupported(
            "OCSP revocation responses",
            `${status.detail}; the strict profile needs them evaluated, so this verifier cannot give a verdict: use the command-line verifier (daur verify)`,
          );
        } else if (profile === "strict") result.fail("REVOCATION_MISSING", "strict profile requires revocation data covering the signing time");
        else result.warn("REVOCATION_MISSING", status.detail);
      }
    }
  }

  // 7. Deliverable and regions
  if (record) await checkDeliverable(result, record, input.deliverable || null, input.fileName || null);

  // 7b. Evidence files given beside the record (specification 11.10)
  if (record) await checkEvidence(result, record, input.evidence || []);

  // 8. Statement
  if (record) {
    const st = tsSource === "timestamp" && tsInfo ? formatRfc3339(tsInfo.genTime) : null;
    const note = (result.details.signer || {}).certificate_type === "seal" ? PERSON_NAMED_BY_ORGANISATION : "";
    result.statement = safeStatement(record, st, st ? tsInfo.tsaCert.subject : null, note);
  }
  return result;
}

function tsaNames(cert, oid) {
  try {
    return nameValues(certNameDers(cert.rawData).subject, oid);
  } catch {
    return [];
  }
}

// Specification 11.4: bind the named organisation to the certificate and say who names the person.
function checkProducerNames(result, record, profile) {
  const signer = result.details.signer || {};
  const orgs = signer.organisation || [];
  const cns = signer.common_name || [];
  const report = profile === "strict" ? result.fail.bind(result) : result.warn.bind(result);
  const producer = obj(record.producer);
  const legal = String(obj(producer.organisation).legal_name ?? "");
  // Exactly one O value: with two, either name would otherwise satisfy the check.
  if (orgs.length !== 1 || !sameText(legal, orgs[0])) {
    let issued;
    if (!orgs.length) issued = "carries no organisation (O) attribute";
    else if (orgs.length > 1) issued = `carries ${orgs.length} organisation (O) values (${orgs.map((o) => JSON.stringify(o)).join(", ")}); exactly one is required`;
    else issued = `is issued to ${JSON.stringify(orgs[0])}`;
    report("PRODUCER_ORG_DIFFERS", `the record names the organisation ${JSON.stringify(legal)}, but the signing certificate ${issued}`);
  }
  const person = String(obj(producer.accountable_person).name ?? "");
  if (signer.certificate_type === "seal") {
    result.info(
      "ACCOUNTABLE_PERSON_DECLARED",
      `the record was signed with an organisation seal certificate; the accountable person ${JSON.stringify(person)} is named by the organisation and is not in the certificate`,
    );
  } else if (cns.length === 1 && sameText(person, cns[0])) result.info("ACCOUNTABLE_PERSON_IN_CERT", `the accountable person ${JSON.stringify(person)} is the certificate's common name`);
  else {
    report(
      "ACCOUNTABLE_PERSON_DIFFERS",
      `the record names the accountable person ${JSON.stringify(person)}, but the signing certificate is a named-signer certificate issued to ${cns.map((c) => JSON.stringify(c)).join(", ") || "no common name"}`,
    );
  }
}

// Specification 10.1 and 10.6: the trust list must carry a manifest, and a test list is accepted
// only in test mode.
// Specification 10.2 (backlog L3): note when the list's next_update has passed. No clock is read.
function checkNextUpdate(result, trust, signingTime, verificationTime) {
  const due = trust.nextUpdate;
  if (!due) return;
  for (const [label, when] of [["signing time", signingTime], ["verification time supplied", verificationTime]]) {
    if (when && when > due) {
      result.info("TRUST_LIST_PAST_NEXT_UPDATE", `the ${label} ${formatRfc3339(when)} is after the trust list's next_update ${formatRfc3339(due)}; a newer list may exist`);
    }
  }
}

function checkTrustList(result, trust, profile, allowTestTrust) {
  if (!trust.manifest) {
    const message = "trust list has no manifest; the trust list must be a directory containing a manifest (specification 10.1)";
    if (profile === "strict") result.fail("TRUST_LIST_INVALID", message);
    else result.warn("TRUST_LIST_INVALID", message);
  }
  const reserved = trust.reservedIdError();
  if (reserved) result.fail("TRUST_LIST_ID_RESERVED", reserved);
  const reasons = trust.testReasons();
  if (reasons.length) {
    result.testTrustList = true;
    if (!allowTestTrust) {
      result.fail(
        "TEST_TRUST_LIST",
        `trust list ${trust.id || "(unnamed)"} is a test list (${reasons.join("; ")}); its results prove nothing about any real signer, and a verifier reports PASS from it only in test mode`,
      );
    }
  }
}

// Specification 10.4: only the fingerprint identifies a trust list; the identifier and version are labels.
function checkTrustFingerprint(result, trust, profile, expected) {
  const have = trust.fingerprint || "";
  if (expected !== null && expected !== undefined && String(expected).trim() !== "") {
    const want = normaliseFingerprint(expected);
    result.trustFingerprintMatched = want === have;
    if (want !== have) result.fail("TRUST_LIST_FINGERPRINT_MISMATCH", `the loaded trust list has the fingerprint ${have || "(none: it has no manifest)"}, not the expected ${want}`);
    else result.info("TRUST_LIST_FINGERPRINT_MATCH", `the loaded trust list has the expected fingerprint ${have}`);
  } else if (profile === "strict") {
    result.info(
      "TRUST_LIST_FINGERPRINT_NOT_CHECKED",
      `no expected trust list fingerprint was given; compare the fingerprint ${have || "(none: the list has no manifest)"} with the one your contract or contracting authority names`,
    );
  }
}

export const TSA_ROOT_NOT_LISTED = "TSA root not in the trust list for time-stamping";

/**
 * Specification 11.5 step 6 for a token over `data` (the COSE signature bytes): CMS signature,
 * time-stamping EKU, SHA-256 imprint, then the TSA's path to an anchor listed for time-stamping,
 * checked at genTime. Returns { info, errors }; every error is a TIMESTAMP_INVALID message.
 */
export async function verifyTimestampToken(token, data, trust) {
  let info;
  try {
    info = await parseToken(token);
  } catch (err) {
    return { info: null, errors: [err instanceof TimestampError ? err.message : `time-stamp token could not be processed: ${err.message}`] };
  }
  try {
    await verifyImprint(info, data);
  } catch (err) {
    return { info, errors: [err.message] };
  }
  const tsaPath = await buildPath([info.tsaCert, ...info.certs], trust, PURPOSE_TIME_STAMPING);
  if (!tsaPath.anchor) return { info, errors: [`${TSA_ROOT_NOT_LISTED} (${tsaPath.error})`], anchor: null };
  const probe = new Result("strict");
  if (await checkPathAt(probe, tsaPath, info.genTime, "time-stamping certificate", "TIMESTAMP_INVALID", trust, "TIMESTAMP_INVALID", false)) return { info, errors: [], anchor: tsaPath.anchor };
  return { info, errors: probe.findings.filter((f) => f.severity === "FAIL").map((f) => f.message), anchor: tsaPath.anchor };
}

// header.format of a report made by daur evidence citations (specification 4.10).
export const CITATION_FORMAT = "avok-attest-citation-check-v1";

// { report, why }: the report when `bytes` is a readable citation check (UTF-8 without a byte order
// mark, a JSON object, a header object whose format is CITATION_FORMAT), else why not. Mirrors
// daur/evidence.py read_citation_report (review V4 N4).
export function readCitationReport(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return { report: null, why: "it starts with a UTF-8 byte order mark" };
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { report: null, why: "it is not UTF-8" };
  }
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    return { report: null, why: "it is not JSON" };
  }
  if (!report || typeof report !== "object" || Array.isArray(report)) return { report: null, why: "it is not a JSON object" };
  const header = report.header;
  if (!header || typeof header !== "object" || Array.isArray(header)) return { report: null, why: "it has no header" };
  if (header.format !== CITATION_FORMAT) return { report: null, why: `its header.format is ${header.format === undefined ? "null" : JSON.stringify(header.format)}, not ${CITATION_FORMAT}` };
  return { report, why: "" };
}

function sameJson(a, b) {
  try {
    return bytesEqual(jcsBytes(a), jcsBytes(b));
  } catch {
    return false;
  }
}

const SUMMARY_ORDER = ["references", "resolved", "unresolved", "blocked", "error", "not_checked"];
export function summaryText(summary) {
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) return "";
  const keys = [...SUMMARY_ORDER.filter((k) => k in summary), ...Object.keys(summary).filter((k) => !SUMMARY_ORDER.includes(k))];
  return keys.map((k) => `${k.replace(/_/g, " ")} ${summary[k]}`).join(", ");
}

// Specification 11.10: a supplied citation check must be the one made for this deliverable and carry
// the summary the record states. Mirrors daur/evidence.py citation_problems.
function citationProblems(entry, report, record) {
  const want = String(obj(record.deliverable).file_sha256 || "").toLowerCase();
  const got = report.header.deliverable_sha256;
  const label = `evidence ${entry.id} (${entry.file_name})`;
  const problems = [];
  if (typeof got !== "string" || got.toLowerCase() !== want) {
    problems.push(["EVIDENCE_NOT_FOR_THIS_FILE", `${label}: the citation check was made for a file with SHA-256 ${got}, not for the deliverable this record describes (${want})`]);
  }
  if (!sameJson(report.summary, entry.summary)) {
    problems.push(["EVIDENCE_SUMMARY_MISMATCH", `${label}: the supplied citation check says ${summaryText(report.summary) || "nothing"}, the record states ${summaryText(entry.summary) || "nothing"}`]);
  }
  return problems;
}

// Specification 11.10: compare supplied files with the record's evidence entries. A file whose hash
// equals an entry is EVIDENCE_MATCH (informational); a file named like an entry whose hash differs is
// FAIL EVIDENCE_HASH_MISMATCH; a file matching no entry is WARN EVIDENCE_UNKNOWN; an entry with no
// file is EVIDENCE_NOT_SUPPLIED (informational). Mirrors daur/evidence.py.
export async function checkEvidence(result, record, supplied) {
  const entries = Array.isArray(record.evidence) ? record.evidence.filter((e) => e && typeof e === "object" && !Array.isArray(e)) : [];
  if (!entries.length && !supplied.length) return;
  const status = new Map();
  const unknown = [];
  for (const item of supplied) {
    const name = String(item.name || "").split(/[\\/]/).pop();
    const digest = await sha256Hex(item.bytes);
    const byHash = entries.map((e, i) => [e, i]).filter(([e]) => String(e.sha256 || "").toLowerCase() === digest);
    if (byHash.length) {
      for (const [e, i] of byHash) {
        const st = { status: "matched", supplied_as: name };
        status.set(i, st);
        result.info("EVIDENCE_MATCH", `evidence ${e.id} (${e.file_name}): the file ${JSON.stringify(name)} has the SHA-256 the record states`);
        if (e.type !== "citation-check") continue;
        const { report, why } = readCitationReport(item.bytes);
        if (!report) {
          // Review V4 N4: a file bound as the citation check that is not one cannot back the summary.
          result.fail(
            "EVIDENCE_SUMMARY_MISMATCH",
            `evidence ${e.id} (${e.file_name}): the supplied file is not a readable citation check of format ${CITATION_FORMAT} (${why}), so the summary the record states is not backed by it`,
          );
          st.summary_checked = "unreadable";
          st.unreadable = why;
          continue;
        }
        const problems = citationProblems(e, report, record);
        for (const [code, message] of problems) result.fail(code, message);
        st.file_summary = report.summary && typeof report.summary === "object" && !Array.isArray(report.summary) ? report.summary : null;
        st.summary_checked = problems.length ? "inconsistent" : "consistent";
      }
      continue;
    }
    const byName = entries.map((e, i) => [e, i]).filter(([e]) => e.file_name === name);
    if (byName.length) {
      for (const [e, i] of byName) {
        if ((status.get(i) || {}).status !== "matched") status.set(i, { status: "hash_mismatch", supplied_as: name, supplied_sha256: digest });
        result.fail("EVIDENCE_HASH_MISMATCH", `evidence ${e.id} (${e.file_name}): the file supplied under that name has SHA-256 ${digest}, the record states ${e.sha256}`);
      }
      continue;
    }
    unknown.push(name);
    result.warn("EVIDENCE_UNKNOWN", `the file ${JSON.stringify(name)} (SHA-256 ${digest}) matches no evidence entry of the record by hash or name`);
  }
  const listing = [];
  entries.forEach((e, i) => {
    const st = status.get(i) || { status: "not_supplied" };
    if (st.status === "not_supplied") result.info("EVIDENCE_NOT_SUPPLIED", `evidence ${e.id} (${e.file_name}) was not supplied, so its file was not checked`);
    const summary = e.summary && typeof e.summary === "object" && !Array.isArray(e.summary) ? e.summary : null;
    listing.push({ id: e.id, type: e.type, description: e.description, file_name: e.file_name, sha256: e.sha256, summary, ...st });
  });
  result.details.evidence = listing;
  if (unknown.length) result.details.evidence_unknown = unknown;
}

// A record that fails the schema may not have the shape the statement expects.
function safeStatement(record, signingTime, tsa, personNote = "") {
  try {
    return plainStatement(record, signingTime, tsa, personNote);
  } catch {
    return "(no statement: the signed record does not have the expected structure)";
  }
}

async function checkDeliverable(result, record, bytes, fileName) {
  const d = obj(record.deliverable);
  if (!bytes) {
    result.warn("FILE_NOT_CHECKED", "no deliverable supplied; file hash and regions were not checked");
    return;
  }
  const actual = await sha256Hex(bytes);
  result.details.file_sha256 = actual;
  const fileOk = actual === String(d.file_sha256 || "").toLowerCase();
  if (!fileOk) result.fail("HASH_MISMATCH", `deliverable SHA-256 ${actual} does not match the record's ${d.file_sha256}`);
  if (fileName && d.file_name && fileName !== d.file_name) result.warn("FILE_NAME_MISMATCH", `file name ${JSON.stringify(fileName)} differs from the record's ${JSON.stringify(d.file_name)}`);
  let checked = 0;
  const mismatched = [];
  const notRecomputed = [];
  for (const entry of Array.isArray(record.ai_use) ? record.ai_use : []) {
    for (const region of Array.isArray(obj(entry).locus) ? entry.locus : []) {
      if (!region || typeof region !== "object") {
        result.warn("REGION_NOT_RECOMPUTED", `region entry ${JSON.stringify(region)} is malformed and was not checked`);
        continue;
      }
      if (!region.sha256) {
        result.warn("REGION_UNHASHED", `region ${JSON.stringify(region.ref)} is declared without a hash`);
        continue;
      }
      let actualHash;
      let detail = "";
      try {
        actualHash = await recompute(bytes, d.media_type, region);
      } catch (err) {
        actualHash = "";
        detail = err.message;
      }
      if (actualHash === null) {
        notRecomputed.push(region.ref);
        // Specification 11.6: informational when the whole file matched, since its bytes are those signed.
        const msg = `region ${JSON.stringify(region.ref)} (${region.type}, ${region.extraction_method}): not recomputed in this browser verifier`;
        if (fileOk) result.info("REGION_NOT_RECOMPUTED", `${msg}; the file is byte-identical to the one signed, so its text was not recomputed here`);
        else result.warn("REGION_NOT_RECOMPUTED", msg);
        continue;
      }
      checked += 1;
      if (actualHash !== region.sha256) {
        mismatched.push(region.ref);
        const msg = `region ${JSON.stringify(region.ref)} (${region.type}) does not match${detail ? `: ${detail}` : ""}`;
        if (fileOk) result.warn("REGION_EXTRACTION_DIFFERS", `${msg} although the file bytes are intact; the extraction differs`);
        else result.fail("REGION_HASH_MISMATCH", msg);
      }
    }
  }
  result.details.regions_checked = checked;
  result.details.regions_mismatched = mismatched;
  result.details.regions_not_recomputed = notRecomputed;
}

export { displayText, jsonText, recordTextErrors } from "./display.js";

// Building blocks used by the Node tests (verifier/test/public-tsa.test.mjs, tsa-algorithms).
export { PURPOSE_SIGNING, PURPOSE_TIME_STAMPING, RESERVED_LISTS, TrustStore, buildPath, canonicalSpki, reservedRootProblems } from "./pki.js";
export { manifestProblems, parseManifestText } from "./manifest.js";
export { parseToken, verifyImprint } from "./tsa.js";
