// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// RFC 3161 time-stamp token parsing and verification with WebCrypto.

import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1js from "asn1js";
import * as cms from "@peculiar/asn1-cms";
import * as tsp from "@peculiar/asn1-tsp";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { RsaSaPssParams } from "@peculiar/asn1-rsa";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import { issuerKey, nameKey } from "./dn.js";
import { bytesEqual, normaliseSerial, sha256, toHex } from "./util.js";

const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";
const OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12";
const OID_MGF1 = "1.2.840.113549.1.1.8";
// Specification 11.5 step 6: accepted digest algorithms and CMS signature algorithms.
const DIGESTS = { "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512" };
const SIGNATURES = {
  "1.2.840.113549.1.1.1": { kind: "rsa", hash: null }, // rsaEncryption: the hash is the SignerInfo digest algorithm
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
  "1.2.840.113549.1.1.10": { kind: "pss" },
  "1.2.840.10045.4.3.2": { kind: "ecdsa", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { kind: "ecdsa", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { kind: "ecdsa", hash: "SHA-512" },
  "1.3.101.112": { kind: "ed25519" },
};
const EC_WIDTH = { "P-256": 32, "P-384": 48, "P-521": 66 };
const MIN_RSA_BITS = 2048;

async function digest(name, bytes) {
  return new Uint8Array(await crypto.subtle.digest(name, bytes));
}
export const OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

export class TimestampError extends Error {}

function derSet(items) {
  const parts = items.map((i) => new Uint8Array(i));
  const bodyLen = parts.reduce((n, p) => n + p.length, 0);
  let header;
  if (bodyLen < 128) header = [0x31, bodyLen];
  else {
    const lenBytes = [];
    let n = bodyLen;
    while (n > 0) {
      lenBytes.unshift(n & 0xff);
      n >>= 8;
    }
    header = [0x31, 0x80 | lenBytes.length, ...lenBytes];
  }
  const out = new Uint8Array(header.length + bodyLen);
  out.set(header, 0);
  let off = header.length;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function fixedWidth(bytes, width) {
  let y = new Uint8Array(bytes);
  while (y.length > width && y[0] === 0) y = y.slice(1);
  if (y.length > width) throw new TimestampError("ECDSA integer too long");
  const out = new Uint8Array(width);
  out.set(y, width - y.length);
  return out;
}

// The certificate identifiers of a SigningCertificateV2 (RFC 5035: each ESSCertIDv2 names its hash
// algorithm, SHA-256 when absent) or SigningCertificate (RFC 2634: SHA-1 ESSCertID) attribute
// value, as [{ hash, value }]; hash is null for an algorithm outside the accepted set.
function essCertIds(attrValue, v2) {
  const parsed = asn1js.fromBER(attrValue);
  const seq = parsed.offset === -1 ? null : parsed.result;
  const certs = seq instanceof asn1js.Sequence ? seq.valueBlock.value[0] : null;
  if (!(certs instanceof asn1js.Sequence)) throw new TimestampError(`malformed ${v2 ? "SigningCertificateV2" : "SigningCertificate"} attribute`);
  return certs.valueBlock.value.map((id) => {
    const parts = id instanceof asn1js.Sequence ? id.valueBlock.value : [];
    let i = 0;
    let hash = v2 ? "SHA-256" : "SHA-1";
    if (v2 && parts[0] instanceof asn1js.Sequence) {
      const oid = parts[0].valueBlock.value[0];
      hash = oid instanceof asn1js.ObjectIdentifier ? DIGESTS[oid.valueBlock.toString()] || null : null;
      i = 1;
    }
    if (!(parts[i] instanceof asn1js.OctetString)) throw new TimestampError("malformed ESSCertID");
    return { hash, value: new Uint8Array(parts[i].valueBlock.valueHexView) };
  });
}

async function identifiesCert(ids, certDer) {
  for (const id of ids) {
    if (id.hash && bytesEqual(id.value, await digest(id.hash, certDer))) return true;
  }
  return false;
}

// Verify a SignerInfo signature with the algorithms specification 11.5 step 6 accepts.
async function verifyCmsSignature(cert, signatureAlgorithm, signature, data, digestName) {
  const spec = SIGNATURES[signatureAlgorithm.algorithm];
  const keyAlg = cert.publicKey.algorithm || {};
  const spki = cert.publicKey.rawData;
  const sig = new Uint8Array(signature.buffer ? signature.buffer : signature);
  if (!spec) throw new TimestampError(`unsupported TSA signature algorithm ${signatureAlgorithm.algorithm}`);
  if (spec.kind === "rsa" || spec.kind === "pss") {
    if (!/^RSA/.test(keyAlg.name || "")) throw new TimestampError(`unsupported TSA signature algorithm ${signatureAlgorithm.algorithm} for a ${keyAlg.name} key`);
    if ((keyAlg.modulusLength || 0) < MIN_RSA_BITS) throw new TimestampError(`TSA RSA key has ${keyAlg.modulusLength} bits; at least ${MIN_RSA_BITS} are required`);
    if (spec.kind === "rsa") {
      const hash = spec.hash || digestName;
      const key = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
      return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, data);
    }
    let params;
    try {
      params = AsnConvert.parse(signatureAlgorithm.parameters, RsaSaPssParams);
    } catch (err) {
      throw new TimestampError(`malformed RSASSA-PSS parameters: ${err.message}`);
    }
    const hash = DIGESTS[params.hashAlgorithm.algorithm];
    let mgfHash = null;
    if (params.maskGenAlgorithm.algorithm === OID_MGF1 && params.maskGenAlgorithm.parameters) {
      mgfHash = DIGESTS[AsnConvert.parse(params.maskGenAlgorithm.parameters, AlgorithmIdentifier).algorithm] || null;
    }
    if (!hash || mgfHash !== hash || params.trailerField !== 1) throw new TimestampError(`unsupported RSASSA-PSS parameters (hash ${hash || params.hashAlgorithm.algorithm}, MGF1 hash ${mgfHash})`);
    const key = await crypto.subtle.importKey("spki", spki, { name: "RSA-PSS", hash }, false, ["verify"]);
    return crypto.subtle.verify({ name: "RSA-PSS", saltLength: params.saltLength }, key, sig, data);
  }
  if (spec.kind === "ecdsa") {
    const width = EC_WIDTH[keyAlg.namedCurve];
    if (keyAlg.name !== "ECDSA" || !width) throw new TimestampError(`unsupported TSA key ${keyAlg.name} ${keyAlg.namedCurve || ""} for ECDSA`.trim());
    const sv = AsnConvert.parse(signature, ECDSASigValue);
    const raw = new Uint8Array(2 * width);
    raw.set(fixedWidth(sv.r, width), 0);
    raw.set(fixedWidth(sv.s, width), width);
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: keyAlg.namedCurve }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: spec.hash }, key, raw, data);
  }
  if (keyAlg.name !== "Ed25519") throw new TimestampError(`unsupported TSA signature algorithm Ed25519 for a ${keyAlg.name} key`);
  const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, sig, data);
}

/**
 * Parse and internally verify a TimeStampToken.
 * Returns { genTime, serialHex, policy, nonce, imprint, accuracySeconds, tsaCert, certs }.
 * Chain trust is decided by the caller.
 */
export async function parseToken(tokenBytes) {
  let signedData;
  let tstBytes;
  try {
    const ci = AsnConvert.parse(tokenBytes, cms.ContentInfo);
    if (ci.contentType !== cms.id_signedData) throw new TimestampError("token is not CMS SignedData");
    signedData = AsnConvert.parse(ci.content, cms.SignedData);
    if (signedData.encapContentInfo.eContentType !== tsp.id_ct_tstInfo) throw new TimestampError("token content is not TSTInfo");
    const econtent = signedData.encapContentInfo.eContent;
    if (!econtent || !econtent.single) throw new TimestampError("token has no TSTInfo content");
    tstBytes = new Uint8Array(econtent.single.buffer);
  } catch (err) {
    if (err instanceof TimestampError) throw err;
    throw new TimestampError(`malformed TimeStampToken: ${err.message}`);
  }
  let tst;
  try {
    tst = AsnConvert.parse(tstBytes, tsp.TSTInfo);
  } catch (err) {
    throw new TimestampError(`malformed TSTInfo: ${err.message}`);
  }
  if (signedData.signerInfos.length !== 1) throw new TimestampError("token must contain exactly one SignerInfo");
  const si = signedData.signerInfos[0];
  const certs = (signedData.certificates || []).filter((c) => c.certificate).map((c) => new x509.X509Certificate(AsnConvert.serialize(c.certificate)));
  if (!certs.length) throw new TimestampError("token carries no certificates");

  let tsaCert = null;
  if (si.sid.issuerAndSerialNumber) {
    const serial = normaliseSerial(toHex(new Uint8Array(si.sid.issuerAndSerialNumber.serialNumber)));
    const issuer = nameKey(AsnConvert.serialize(si.sid.issuerAndSerialNumber.issuer));
    tsaCert = certs.find((c) => normaliseSerial(c.serialNumber) === serial && issuerKey(c) === issuer) || null;
  } else if (si.sid.subjectKeyIdentifier) {
    const ski = toHex(new Uint8Array(si.sid.subjectKeyIdentifier.buffer));
    tsaCert = certs.find((c) => {
      const ext = c.getExtension("2.5.29.14");
      return ext && toHex(new Uint8Array(ext.keyId ? ext.keyId : [])) === ski;
    }) || null;
  }
  if (!tsaCert) throw new TimestampError("signer certificate not found in token");

  if (!si.signedAttrs || !si.signedAttrs.length) throw new TimestampError("token lacks signed attributes");
  const attr = (oid) => si.signedAttrs.find((a) => a.attrType === oid);
  const ct = attr(cms.id_contentType);
  const ctValue = ct ? asn1js.fromBER(ct.attrValues[0]) : null;
  if (!ctValue || ctValue.offset === -1 || !(ctValue.result instanceof asn1js.ObjectIdentifier) || ctValue.result.valueBlock.toString() !== tsp.id_ct_tstInfo) {
    throw new TimestampError("signed content-type attribute missing or wrong");
  }
  const md = attr(cms.id_messageDigest);
  if (!md) throw new TimestampError("signed message-digest attribute missing");
  const digestName = DIGESTS[si.digestAlgorithm.algorithm];
  if (!digestName) throw new TimestampError(`unsupported digest algorithm ${si.digestAlgorithm.algorithm}`);
  const mdValue = new Uint8Array(AsnConvert.parse(md.attrValues[0], cms.MessageDigest).buffer);
  if (!bytesEqual(mdValue, await digest(digestName, tstBytes))) throw new TimestampError("message-digest attribute does not match TSTInfo");
  const certDer = new Uint8Array(tsaCert.rawData);
  const sc2 = attr(OID_SIGNING_CERT_V2);
  const sc1 = attr(OID_SIGNING_CERT);
  // RFC 3161 section 2.4.1 as updated by RFC 5816: one of the two attributes is required (review V3 L2).
  if (!sc2 && !sc1) throw new TimestampError("the token carries neither SigningCertificate nor SigningCertificateV2 (RFC 3161 section 2.4.1, RFC 5816)");
  if (sc2 && !(await identifiesCert(essCertIds(sc2.attrValues[0], true), certDer))) throw new TimestampError("SigningCertificateV2 does not match the signer certificate");
  if (sc1 && !(await identifiesCert(essCertIds(sc1.attrValues[0], false), certDer))) throw new TimestampError("SigningCertificate does not match the signer certificate");

  const tbs = derSet(si.signedAttrs.map((a) => AsnConvert.serialize(a)));
  let ok = false;
  try {
    ok = await verifyCmsSignature(tsaCert, si.signatureAlgorithm, si.signature, tbs, digestName);
  } catch (err) {
    if (err instanceof TimestampError) throw err;
    throw new TimestampError(`TSA signature could not be checked: ${err.message}`);
  }
  if (!ok) throw new TimestampError("TSA signature is invalid");

  // RFC 3161 section 2.3 and specification 11.5 step 6: critical EKU with id-kp-timeStamping only.
  let eku;
  try {
    eku = tsaCert.getExtension("2.5.29.37");
  } catch (err) {
    throw new TimestampError(`TSA certificate extensions cannot be parsed: ${err.message}`);
  }
  if (!eku) throw new TimestampError("TSA certificate lacks the time-stamping EKU");
  if (!eku.usages.includes(OID_TIME_STAMPING)) throw new TimestampError("TSA certificate EKU does not include id-kp-timeStamping");
  if (eku.usages.some((oid) => oid !== OID_TIME_STAMPING)) throw new TimestampError("TSA certificate EKU must contain only id-kp-timeStamping");
  if (!eku.critical) throw new TimestampError("TSA certificate EKU is not marked critical");

  if (tst.messageImprint.hashAlgorithm.algorithm !== OID_SHA256) throw new TimestampError("unsupported imprint algorithm");
  const acc = tst.accuracy;
  const accuracySeconds = acc ? (acc.seconds || 0) + (acc.millis || 0) / 1000 + (acc.micros || 0) / 1e6 : null;
  return {
    genTime: new Date(tst.genTime),
    serialHex: toHex(new Uint8Array(tst.serialNumber)).replace(/^0+(?=.)/, ""),
    policy: tst.policy,
    nonce: tst.nonce ? toHex(new Uint8Array(tst.nonce)) : null,
    imprint: new Uint8Array(tst.messageImprint.hashedMessage.buffer),
    accuracySeconds,
    tsaCert,
    certs: certs.filter((c) => c !== tsaCert),
  };
}

export async function verifyImprint(info, signature) {
  if (!bytesEqual(info.imprint, await sha256(signature))) throw new TimestampError("time-stamp imprint does not match the signature bytes");
}
