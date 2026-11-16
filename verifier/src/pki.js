// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Trust lists, certification paths and CRL evaluation on top of @peculiar/x509.

import * as x509 from "@peculiar/x509";
import * as asn1js from "asn1js";
import { stripWs } from "./whitespace.js";
import { crlIssuerDer, issuerKey, nameKey, subjectKey } from "./dn.js";
import { formatRfc3339, jcsBytes, normaliseSerial, parseRfc3339, pemBlocks, sha256Hex, toHex } from "./util.js";
import RESERVED from "./reserved-lists.generated.js";
import { manifestProblems } from "./manifest.js";

// data/reserved-lists.json (specification 10.6 and 10.7): reserved identifiers and the published test keys.
export const RESERVED_LISTS = RESERVED;

// An identifier as compared for reservation and for the ".test" suffix: lower case, no trailing dots.
export function normaliseListId(text) {
  return stripWs(String(text ?? "")).toLowerCase().replace(/\.+$/, "");
}

// A fingerprint as given by a person: case, colons and white space do not matter.
export function normaliseFingerprint(text) {
  return String(text ?? "").toLowerCase().replace(/[:\s]/g, "");
}

if (typeof globalThis.crypto !== "undefined") {
  x509.cryptoProvider.set(globalThis.crypto);
}

const MAX_PATH_LENGTH = 6;

// Specification 10.2: root purposes; a manifest entry without a purposes member is listed for both.
export const PURPOSE_SIGNING = "daur-signing";
export const PURPOSE_TIME_STAMPING = "time-stamping";
const ALL_PURPOSES = [PURPOSE_SIGNING, PURPOSE_TIME_STAMPING];

// ISO 8601 durations of the forms PnD and PTnH (revocation_max_age), in milliseconds; null otherwise.
export function parseDuration(text) {
  const m = /^P(?:([0-9]+)D|T([0-9]+)H)$/.exec(String(text));
  if (!m) return null;
  return m[1] !== undefined ? Number(m[1]) * 86400000 : Number(m[2]) * 3600000;
}

function purposesOf(entry) {
  if (!("purposes" in entry)) return new Set(ALL_PURPOSES);
  const value = entry.purposes;
  if (!Array.isArray(value) || !value.every((p) => typeof p === "string")) return new Set();
  return new Set(value.filter((p) => ALL_PURPOSES.includes(p)));
}

// SHA-1 and MD5 signatures on certificates and CRLs are CHAIN_INVALID (specification 11.4).
const WEAK_SIGNATURE_OIDS = {
  "1.2.840.113549.1.1.5": "SHA-1",
  "1.2.840.10045.4.1": "SHA-1",
  "1.2.840.10040.4.3": "SHA-1",
  "1.2.840.113549.1.1.4": "MD5",
  "1.2.840.113549.1.1.3": "MD5",
};

function signatureOid(signed) {
  try {
    const parsed = asn1js.fromBER(signed.rawData);
    // Certificate and CertificateList: SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING }
    return parsed.result.valueBlock.value[1].valueBlock.value[0].valueBlock.toString();
  } catch {
    return "";
  }
}

export function weakSignature(signed) {
  return WEAK_SIGNATURE_OIDS[signatureOid(signed)] || null;
}

// Specification 11.4: a signing certificate that carries an extendedKeyUsage extension must
// include one of these purposes; an EKU limited to id-kp-timeStamping or id-kp-OCSPSigning is
// CHAIN_INVALID. The rule does not apply to the time-stamping certificate's path (RFC 3161
// requires id-kp-timeStamping alone there; tsa.js checks it).
const SIGNER_EKU_ACCEPTED = ["1.3.6.1.5.5.7.3.36", "1.3.6.1.5.5.7.3.4", "2.5.29.37.0"];

// Specification 10.6: a public key is compared as the SHA-256 of its canonical DER
// SubjectPublicKeyInfo, not as the certificate encodes it (review V4 N1). EC keys: the uncompressed
// point under the named curve; RSA keys: minimal integers and NULL parameters; Ed25519: the bare
// algorithm identifier. This is the form Python's cryptography writes (daur/trust.py spki_sha256).
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_RSA = "1.2.840.113549.1.1.1";
const OID_ED25519 = "1.3.101.112";
const CURVES = {
  "1.2.840.10045.3.1.7": { size: 32, p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn, b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn },
  "1.3.132.0.34": {
    size: 48,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
  },
  "1.3.132.0.35": {
    size: 66,
    p: (1n << 521n) - 1n,
    b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
  },
};

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function bytesToBig(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigToBytes(value, size) {
  const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

// An EC point as 04 || X || Y; a compressed point is decompressed (every curve here has p = 3 mod 4).
function uncompressedPoint(point, curve) {
  if (point[0] === 0x04 && point.length === 1 + 2 * curve.size) return point;
  if ((point[0] !== 0x02 && point[0] !== 0x03) || point.length !== 1 + curve.size) return null;
  const { p, b } = curve;
  const x = bytesToBig(point.subarray(1));
  if (x >= p) return null;
  const rhs = (((x * x) % p) * x - 3n * x + b) % p;
  const r = ((rhs % p) + p) % p;
  let y = modPow(r, (p + 1n) / 4n, p);
  if ((y * y) % p !== r) return null;
  if (Number(y & 1n) !== (point[0] & 1)) y = p - y;
  const out = new Uint8Array(1 + 2 * curve.size);
  out[0] = 0x04;
  out.set(bigToBytes(x, curve.size), 1);
  out.set(bigToBytes(y, curve.size), 1 + curve.size);
  return out;
}

function minimalInteger(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0 && !(bytes[i + 1] & 0x80)) i++;
  return bytes.subarray(i);
}

export function canonicalSpki(spkiDer) {
  const raw = new Uint8Array(spkiDer);
  try {
    const parsed = asn1js.fromBER(raw.slice().buffer);
    if (parsed.offset === -1) return raw;
    const [algId, bits] = parsed.result.valueBlock.value;
    const oid = algId.valueBlock.value[0].valueBlock.toString();
    const key = new Uint8Array(bits.valueBlock.valueHexView);
    const der = (node) => new Uint8Array(node.toBER());
    if (oid === OID_EC_PUBLIC_KEY) {
      const curveOid = algId.valueBlock.value[1].valueBlock.toString();
      const curve = CURVES[curveOid];
      const point = curve ? uncompressedPoint(key, curve) : null;
      if (!point) return raw;
      return der(new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID_EC_PUBLIC_KEY }), new asn1js.ObjectIdentifier({ value: curveOid })] }), new asn1js.BitString({ valueHex: point })] }));
    }
    if (oid === OID_RSA) {
      const inner = asn1js.fromBER(key.slice().buffer).result;
      const [n, e] = inner.valueBlock.value.map((i) => new asn1js.Integer({ valueHex: minimalInteger(new Uint8Array(i.valueBlock.valueHexView)) }));
      const rsaKey = der(new asn1js.Sequence({ value: [n, e] }));
      return der(new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID_RSA }), new asn1js.Null()] }), new asn1js.BitString({ valueHex: rsaKey })] }));
    }
    if (oid === OID_ED25519) {
      return der(new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID_ED25519 })] }), new asn1js.BitString({ valueHex: key })] }));
    }
  } catch {
    // a key this verifier cannot re-encode is hashed as the certificate carries it
  }
  return raw;
}

export async function fingerprint(cert) {
  return toHex(new Uint8Array(await cert.getThumbprint("SHA-256")));
}

export function parseVersion(text) {
  const m = /^([0-9]+(?:\.[0-9]+)*)(?:-[A-Za-z0-9._]+)?$/.exec(stripWs(String(text)));
  if (!m) return null;
  return m[1].split(".").map((x) => parseInt(x, 10));
}

export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return String(a) === String(b) ? 0 : null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function purposeText(purposes) {
  return [...purposes].sort().join(" and ") || "no purpose";
}

// How `anchors` (fingerprint to a Set of purposes) differ from the root set a registry entry names
// (specification 10.7). Mirrors daur/trust.py reserved_root_problems.
export function reservedRootProblems(entry, anchors) {
  const registered = new Map(entry.anchors.map((a) => [a.sha256, a]));
  const problems = [];
  for (const fp of [...anchors.keys()].sort()) {
    const purposes = anchors.get(fp);
    const reg = registered.get(fp);
    if (!reg) problems.push(`its root ${fp} (${purposeText(purposes)}) is not one of the registered roots`);
    else if (purposeText(purposes) !== purposeText(reg.purposes)) problems.push(`its root ${reg.name} (${fp}) is listed for ${purposeText(purposes)}, registered for ${purposeText(reg.purposes)}`);
  }
  for (const a of entry.anchors) if (a.required && !anchors.has(a.sha256)) problems.push(`the registered ${purposeText(a.purposes)} root ${a.name} (${a.sha256}) is missing`);
  return problems;
}

export class TrustStore {
  constructor() {
    this.anchors = []; // { cert, fingerprint, notBefore, notAfter }
    this.crls = [];
    this.manifest = null;
    this.digest = null;
    // Specification 10.2: why the manifest found may not be used. The manifest is then not read
    // (manifest stays null, no root is an anchor) and the verifier reports TRUST_LIST_INVALID.
    this.manifestProblems = [];
  }

  get manifestInvalid() {
    return this.manifestProblems.length > 0;
  }

  // `problems` are those found while parsing the manifest text (parseManifestText); a manifest
  // object given without them is checked here.
  static async fromPem(pemText, manifest = null, problems = null) {
    const store = new TrustStore();
    if (manifest !== null) {
      const found = problems ?? manifestProblems(manifest);
      if (found.length) {
        store.manifestProblems = [...found];
        for (const der of pemBlocks(pemText, "X509 CRL")) store.crls.push(new x509.X509Crl(der));
        return store;
      }
    }
    store.manifest = manifest;
    if (manifest) store.digest = await sha256Hex(jcsBytes(manifest));
    const listed = new Map();
    if (manifest && Array.isArray(manifest.roots)) {
      for (const root of manifest.roots) listed.set(String(root.sha256_fingerprint || "").toLowerCase().replace(/:/g, ""), root);
    }
    for (const der of pemBlocks(pemText, "CERTIFICATE")) {
      const cert = new x509.X509Certificate(der);
      const fp = await fingerprint(cert);
      if (manifest && !listed.has(fp)) continue;
      const entry = listed.get(fp) || {};
      if (!store.anchors.some((a) => a.fingerprint === fp)) {
        store.anchors.push({
          cert,
          fingerprint: fp,
          spki: await sha256Hex(canonicalSpki(cert.publicKey.rawData)),
          notBefore: entry.not_before ? parseRfc3339(entry.not_before) : null,
          notAfter: entry.not_after ? parseRfc3339(entry.not_after) : null,
          purposes: purposesOf(entry),
        });
      }
    }
    for (const der of pemBlocks(pemText, "X509 CRL")) store.crls.push(new x509.X509Crl(der));
    return store;
  }

  get version() {
    return this.manifest ? String(this.manifest.trust_list_version || "") : null;
  }

  get id() {
    return this.manifest ? String(this.manifest.trust_list_id || "") : null;
  }

  // revocation_max_age in milliseconds; null when absent or malformed.
  get revocationMaxAgeMs() {
    return this.manifest && "revocation_max_age" in this.manifest ? parseDuration(this.manifest.revocation_max_age) : null;
  }

  get nextUpdate() {
    return this.manifest && "next_update" in this.manifest ? parseRfc3339(String(this.manifest.next_update)) : null;
  }

  // Why this is a test list (specification 10.6): a manifest test member other than false, an
  // identifier ending in ".test" (case-insensitive, trailing dots removed), or an anchor whose public
  // key is a published test key. Empty when it is not one. Mirrors daur/trust.py test_reasons.
  testReasons() {
    const reasons = [];
    const m = this.manifest;
    if (m && "test" in m && m.test !== false) reasons.push(`its manifest says test ${JSON.stringify(m.test)}`);
    if (m && normaliseListId(m.trust_list_id).endsWith(".test")) reasons.push(`its identifier ${JSON.stringify(this.id)} ends in .test`);
    const testKeys = new Map(RESERVED.test_keys.map((k) => [k.spki_sha256, k.name]));
    for (const anchor of this.anchors) {
      const name = testKeys.get(anchor.spki);
      if (name) reasons.push(`the root ${anchor.cert.subject} has the published test key ${name}`);
    }
    return reasons;
  }

  get isTest() {
    return this.testReasons().length > 0;
  }

  // Specification 10.7: a reserved identifier claimed by a list whose roots are not the registered set:
  // every required root present, no root outside the set, each with exactly its registered purposes.
  reservedIdError() {
    if (!this.manifest) return null;
    const claimed = normaliseListId(this.manifest.trust_list_id);
    if (!RESERVED.reserved_prefixes.some((p) => claimed.startsWith(p) || claimed === p.replace(/\.$/, ""))) return null;
    for (const entry of RESERVED.lists) {
      if (entry.trust_list_id !== claimed) continue;
      const anchors = new Map(this.anchors.map((a) => [a.fingerprint, a.purposes]));
      const problems = reservedRootProblems(entry, anchors);
      if (!problems.length) return null;
      return `trust list ${JSON.stringify(this.id)} claims the reserved identifier ${entry.trust_list_id}, but ${problems.join("; ")}`;
    }
    return `trust list ${JSON.stringify(this.id)} uses an identifier under a reserved prefix (${RESERVED.reserved_prefixes.join(", ")}) that is not registered`;
  }

  get name() {
    return this.manifest && this.manifest.trust_list_name !== undefined && this.manifest.trust_list_name !== null ? String(this.manifest.trust_list_name) : null;
  }

  // The trust list fingerprint: SHA-256 of the JCS-canonical manifest (specification 10.4).
  get fingerprint() {
    return this.digest;
  }

  find(fp, purpose = null) {
    return this.anchors.find((a) => a.fingerprint === fp && (!purpose || a.purposes.has(purpose))) || null;
  }

  anchorsForIssuer(issuer, purpose = null) {
    // issuer is a nameKey (verifier/src/dn.js); daur/trust.py anchors_for_issuer uses the same rule.
    return this.anchors.filter((a) => subjectKey(a.cert) === issuer && (!purpose || a.purposes.has(purpose)));
  }

  invalidFrom(fp) {
    if (!this.manifest || !Array.isArray(this.manifest.invalidity_dates)) return null;
    let best = null;
    for (const entry of this.manifest.invalidity_dates) {
      if (String(entry.certificate_sha256 || "").toLowerCase().replace(/:/g, "") !== fp) continue;
      const when = parseRfc3339(entry.invalid_from);
      if (!when) continue;
      if (!best || when < best.when) best = { when, reason: entry.reason || "" };
    }
    return best;
  }
}

export async function certSignedBy(cert, issuerCert) {
  try {
    return await cert.verify({ publicKey: issuerCert.publicKey, signatureOnly: true });
  } catch {
    return false;
  }
}

/**
 * Build a path from certs[0] to a trust anchor listed for `purpose`. Returns { path, anchor, error }.
 * When no such anchor is reached but the path would end at an anchor listed for another purpose,
 * the error says so (specification 10.2).
 */
export async function buildPath(certs, trust, purpose = null) {
  const result = await buildPathFor(certs, trust, purpose);
  if (!result.anchor && purpose) {
    const other = await buildPathFor(certs, trust, null);
    if (other.anchor) {
      const listed = [...other.anchor.purposes].sort().join(" and ") || "no purpose";
      result.error = `the path ends at ${other.anchor.cert.subject}, which the trust list lists for ${listed} only, not for ${purpose}`;
    }
  }
  return result;
}

async function buildPathFor(certs, trust, purpose) {
  if (!certs.length) return { path: [], anchor: null, error: "no certificates" };
  const path = [certs[0]];
  const pool = certs.slice(1);
  let current = certs[0];
  while (path.length <= MAX_PATH_LENGTH) {
    const fp = await fingerprint(current);
    const direct = trust.find(fp, purpose);
    if (direct) return { path, anchor: direct, error: null };
    for (const anchor of trust.anchorsForIssuer(issuerKey(current), purpose)) {
      if (await certSignedBy(current, anchor.cert)) return { path, anchor, error: null };
    }
    let found = false;
    for (const candidate of pool) {
      if (candidate !== current && subjectKey(candidate) === issuerKey(current) && (await certSignedBy(current, candidate))) {
        path.push(candidate);
        current = candidate;
        found = true;
        break;
      }
    }
    if (!found) return { path, anchor: null, error: `no trusted issuer found for ${current.issuer}` };
  }
  return { path, anchor: null, error: "certification path too long" };
}

class CertificateParseError extends Error {}

// BasicConstraints CA flag (null when absent) and KeyUsage bits (null when absent). A certificate
// whose extensions the parser rejects is reported as CHAIN_INVALID by checkPathAt.
function isCa(cert) {
  try {
    const ext = cert.getExtension("2.5.29.19");
    return ext ? Boolean(ext.ca) : null;
  } catch (err) {
    throw new CertificateParseError(`certificate extensions cannot be parsed: ${err.message}`);
  }
}

function keyUsage(cert) {
  try {
    const ext = cert.getExtension("2.5.29.15");
    return ext ? ext.usages : null;
  } catch (err) {
    throw new CertificateParseError(`certificate extensions cannot be parsed: ${err.message}`);
  }
}

// ExtendedKeyUsage purposes as OID strings, null when the extension is absent.
function extendedKeyUsage(cert) {
  try {
    const ext = cert.getExtension("2.5.29.37");
    return ext ? [...ext.usages] : null;
  } catch (err) {
    throw new CertificateParseError(`certificate extensions cannot be parsed: ${err.message}`);
  }
}

/**
 * Record findings for a path at time `when`. Returns true when sound. `signerEku` applies the
 * signing-certificate extended key usage rule of 11.4 to the end-entity certificate; pass false
 * for a time-stamping certificate's path.
 */
export async function checkPathAt(result, pr, when, label, untrustedCode, trust, retroCode = "CERT_INVALID_RETROACTIVELY", signerEku = true) {
  let ok = true;
  if (!pr.anchor) {
    result.fail(untrustedCode, `${label}: ${pr.error || "no trusted root"}`);
    ok = false;
  } else {
    if ((pr.anchor.notBefore && when < pr.anchor.notBefore) || (pr.anchor.notAfter && when > pr.anchor.notAfter)) {
      result.fail(untrustedCode, `${label}: trust list does not cover the root at ${formatRfc3339(when)}`);
      ok = false;
    }
    if (!(pr.anchor.cert.notBefore <= when && when <= pr.anchor.cert.notAfter)) {
      result.fail("CERT_EXPIRED_AT_SIGNING", `${label}: root certificate not valid at ${formatRfc3339(when)}`);
      ok = false;
    }
  }
  if (trust) {
    const all = pr.anchor ? [...pr.path, pr.anchor.cert] : [...pr.path];
    for (const cert of all) {
      const declared = trust.invalidFrom(await fingerprint(cert));
      if (declared && when >= declared.when) {
        const reason = declared.reason ? ` (${declared.reason})` : "";
        result.fail(retroCode, `${label}: trust list declares ${cert.subject} invalid from ${formatRfc3339(declared.when)}${reason}; signing time ${formatRfc3339(when)}`);
        ok = false;
      }
    }
  }
  pr.path.forEach((cert, i) => {
    let ca;
    let ku;
    let eku = null;
    try {
      ca = isCa(cert);
      ku = keyUsage(cert);
      if (i === 0 && signerEku) eku = extendedKeyUsage(cert);
    } catch (err) {
      result.fail("CHAIN_INVALID", `${label}: certificate ${i} cannot be parsed: ${err.message}`);
      ok = false;
      return;
    }
    const weak = weakSignature(cert);
    if (weak) {
      result.fail("CHAIN_INVALID", `${label}: certificate ${cert.subject} is signed with ${weak}; SHA-1 and MD5 signatures are not accepted`);
      ok = false;
    }
    if (!(cert.notBefore <= when && when <= cert.notAfter)) {
      result.fail(
        "CERT_EXPIRED_AT_SIGNING",
        `${label}: certificate ${cert.subject} not valid at ${formatRfc3339(when)} (valid ${formatRfc3339(cert.notBefore)} to ${formatRfc3339(cert.notAfter)})`,
      );
      ok = false;
    }
    if (i === 0) {
      if (ca === true) {
        result.fail("CHAIN_INVALID", `${label}: end-entity certificate is marked as a CA`);
        ok = false;
      }
      if (ku !== null && !(ku & x509.KeyUsageFlags.digitalSignature)) {
        result.fail("CHAIN_INVALID", `${label}: end-entity certificate lacks the digitalSignature key usage`);
        ok = false;
      }
      if (eku !== null && !eku.some((oid) => SIGNER_EKU_ACCEPTED.includes(oid))) {
        result.fail(
          "CHAIN_INVALID",
          `${label}: end-entity certificate's extended key usage (${eku.join(", ")}) includes none of id-kp-documentSigning, id-kp-emailProtection or anyExtendedKeyUsage`,
        );
        ok = false;
      }
    } else {
      if (ca !== true) {
        result.fail("CHAIN_INVALID", `${label}: intermediate ${cert.subject} is not a CA`);
        ok = false;
      }
      if (ku !== null && !(ku & x509.KeyUsageFlags.keyCertSign)) {
        result.fail("CHAIN_INVALID", `${label}: intermediate ${cert.subject} lacks keyCertSign`);
        ok = false;
      }
    }
  });
  return ok;
}

// Specification 11.5 step 8: a CRL whose thisUpdate is at least this long after T decides on its own.
export const LATER_CRL_GRACE_MS = 24 * 60 * 60 * 1000;

// Delta, partitioned and indirect CRLs do not cover the certificate (backlog L2).
function partialCrl(crl) {
  try {
    return crl.extensions.some((e) => e.type === "2.5.29.27" || e.type === "2.5.29.28");
  } catch {
    return true;
  }
}

/**
 * Revocation status of `cert` at `when` (specification 11.5 step 8). `snapshot` is the envelope's revocation snapshot;
 * the trust store's CRLs and `extraCrls` (X509Crl objects the verifier was given) are supplied
 * data. Evidence is weighed as in daur/verify.py: a revocation at or before T in any authentic
 * data; then a later CRL (thisUpdate at least 24 hours after T), which decides on its own; then
 * data covering T whose thisUpdate is at most `maxAgeMs` before T. OCSP responses are not
 * evaluated in the browser; they count as unknown.
 */
export async function revocationStatus(cert, issuerCert, when, snapshot, trust, extraCrls = [], maxAgeMs = null) {
  const stapledRaw = [];
  let ocspItems = 0;
  // Review V4 N3: where each CRL came from, so that the result names the data that decided.
  const origin = new Map();
  for (const crl of trust.crls) origin.set(crl, "trust_directory");
  for (const crl of extraCrls) origin.set(crl, "supplied");
  for (const item of snapshot) {
    try {
      const crl = new x509.X509Crl(item);
      stapledRaw.push(crl);
      origin.set(crl, "stapled");
    } catch {
      ocspItems += 1;
    }
  }
  const weak = [];
  // Delta, partitioned and indirect CRLs are evidence of revocation (step 1), never of "not revoked".
  const partial = [];
  const usable = async (list) => {
    const out = [];
    for (const crl of list) {
      let ok = false;
      try {
        ok = nameKey(crlIssuerDer(crl.rawData)) === subjectKey(issuerCert) && (await crl.verify({ publicKey: issuerCert }));
      } catch {
        ok = false;
      }
      if (!ok) continue;
      const algorithm = weakSignature(crl);
      if (algorithm) weak.push(`CRL issued ${formatRfc3339(crl.thisUpdate)} by ${crl.issuer} is signed with ${algorithm}; SHA-1 and MD5 signatures are not accepted`);
      else (partialCrl(crl) ? partial : out).push(crl);
    }
    return out;
  };
  const stapled = await usable(stapledRaw);
  const supplied = await usable([...trust.crls, ...extraCrls]);
  const status = weighRevocation(cert, when, stapled, supplied, ocspItems, maxAgeMs, partial);
  status.weak = weak;
  if (status.evidence) status.source = origin.get(status.evidence) || "supplied";
  return status;
}

function weighRevocation(cert, when, stapled, supplied, ocspItems, maxAgeMs, partial = []) {
  const serial = normaliseSerial(cert.serialNumber);
  const entryOf = (crl) => crl.entries.find((e) => normaliseSerial(e.serialNumber) === serial) || null;
  const later = supplied.filter((c) => c.thisUpdate.getTime() >= when.getTime() + LATER_CRL_GRACE_MS);
  const current = supplied.filter((c) => !later.includes(c));
  // 1. A revocation at or before T in any authentic data, whatever its publication time, delta and
  // partitioned CRLs included.
  for (const crl of [...later, ...current, ...stapled, ...partial]) {
    const entry = entryOf(crl);
    if (entry && entry.revocationDate <= when) {
      const isPartial = partial.includes(crl);
      const late = later.includes(crl) || (isPartial && crl.thisUpdate.getTime() >= when.getTime() + LATER_CRL_GRACE_MS);
      return {
        status: "revoked",
        detail: `${isPartial ? "delta or partitioned CRL" : "CRL"} issued ${formatRfc3339(crl.thisUpdate)} lists serial ${serial} revoked at ${formatRfc3339(entry.revocationDate)}`,
        decidedBy: late ? "later_crl" : "snapshot",
        thisUpdate: crl.thisUpdate,
        evidence: crl,
        laterAvailable: later.length > 0,
      };
    }
  }
  // 2. Later CRLs decide on their own.
  const cleanLater = [];
  for (const crl of later) {
    const entry = entryOf(crl);
    const invalid = entry ? entry.invalidity || null : null;
    if (entry && invalid && invalid <= when) {
      return {
        status: "revoked",
        detail: `later CRL issued ${formatRfc3339(crl.thisUpdate)} lists serial ${serial} with invalidity date ${formatRfc3339(invalid)}, at or before the signing time`,
        decidedBy: "later_crl",
        thisUpdate: crl.thisUpdate,
        evidence: crl,
        laterAvailable: true,
      };
    }
    if (crl.thisUpdate <= cert.notAfter) cleanLater.push(crl);
  }
  if (cleanLater.length) {
    const newest = cleanLater.reduce((a, b) => (b.thisUpdate > a.thisUpdate ? b : a));
    return {
      status: "good",
      detail: `CRL issued ${formatRfc3339(newest.thisUpdate)}, after the signing time, does not list the certificate as revoked at the signing time`,
      decidedBy: "later_crl",
      thisUpdate: newest.thisUpdate,
      evidence: newest,
      laterAvailable: true,
    };
  }
  // 3. Data whose window covers T and that is fresh enough.
  const covering = [];
  const tooOld = [];
  let stale = false;
  for (const crl of [...current, ...stapled]) {
    if (crl.thisUpdate <= when && (!crl.nextUpdate || when <= crl.nextUpdate)) {
      if (maxAgeMs !== null && when.getTime() - crl.thisUpdate.getTime() > maxAgeMs) tooOld.push(crl.thisUpdate);
      else covering.push(crl);
    } else stale = true;
  }
  const newestOf = (dates) => dates.reduce((a, b) => (b > a ? b : a));
  if (covering.length) {
    // The newest covering list decides; of lists issued at the same time, the first listed.
    const chosen = covering.reduce((a, b) => (b.thisUpdate > a.thisUpdate ? b : a));
    const newest = chosen.thisUpdate;
    return {
      status: "good",
      detail: `revocation data covering the signing time (thisUpdate ${formatRfc3339(newest)}) shows the certificate as not revoked`,
      decidedBy: "snapshot",
      thisUpdate: newest,
      evidence: chosen,
      laterAvailable: false,
    };
  }
  if (tooOld.length) {
    return { status: "stale", detail: `revocation data covering the signing time is older than the trust list's revocation_max_age (newest thisUpdate ${formatRfc3339(newestOf(tooOld))})` };
  }
  if (stale) return { status: "stale", detail: "revocation data present but none covers the signing time" };
  if (ocspItems) return { status: "unknown", ocspOnly: true, detail: `${ocspItems} OCSP response(s) in the snapshot are not evaluated by the browser verifier` };
  return { status: "unknown", detail: "no authentic revocation data for the signing certificate" };
}
