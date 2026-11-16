// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Distinguished names and serial numbers as they appear in a record (specification 4.3 and 11.4).
// Mirrors daur/dn.py: the record's RFC 4514 string is parsed into RDNs and compared attribute by
// attribute with the certificate's DER name, so that `title=`, `T=` and `2.5.4.12=` describe the
// same name; serial numbers are compared as integers. verifier/test/dn.test.mjs checks parity
// against strings produced by the Python package.

import { collapseWs, isWs, lstripWs, stripWs } from "./whitespace.js";

// RFC 4514 short names, RFC 4519 descriptors and the single letters other libraries emit.
export const DESCRIPTORS = {
  CN: "2.5.4.3",
  L: "2.5.4.7",
  ST: "2.5.4.8",
  O: "2.5.4.10",
  OU: "2.5.4.11",
  C: "2.5.4.6",
  STREET: "2.5.4.9",
  DC: "0.9.2342.19200300.100.1.25",
  UID: "0.9.2342.19200300.100.1.1",
  TITLE: "2.5.4.12",
  T: "2.5.4.12",
  SN: "2.5.4.4",
  SURNAME: "2.5.4.4",
  GN: "2.5.4.42",
  GIVENNAME: "2.5.4.42",
  INITIALS: "2.5.4.43",
  GENERATIONQUALIFIER: "2.5.4.44",
  SERIALNUMBER: "2.5.4.5",
  PSEUDONYM: "2.5.4.65",
  DNQUALIFIER: "2.5.4.46",
  BUSINESSCATEGORY: "2.5.4.15",
  POSTALCODE: "2.5.4.17",
  POSTALADDRESS: "2.5.4.16",
  NAME: "2.5.4.41",
  DESCRIPTION: "2.5.4.13",
  EMAILADDRESS: "1.2.840.113549.1.9.1",
  EMAIL: "1.2.840.113549.1.9.1",
  E: "1.2.840.113549.1.9.1",
};

const SPECIALS = ' "#+,;<=>\\';
const HEX = /^[0-9a-fA-F]$/;
// ASN.1 string types, with their text encodings. T61String is read as ISO 8859-1 in both verifiers.
const STRING_TAGS = { 0x0c: "utf-8", 0x13: "ascii", 0x16: "ascii", 0x1a: "ascii", 0x12: "ascii", 0x14: "latin1", 0x1e: "utf-16be", 0x1c: "utf-32be" };

export class DNError extends Error {}

// Split on unescaped separator characters; a backslash escapes the next character.
function split(text, separators) {
  const parts = [];
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\\" && i + 1 < text.length) {
      current += text.slice(i, i + 2);
      i += 1;
    } else if (separators.includes(ch)) {
      parts.push(current);
      current = "";
    } else current += ch;
  }
  parts.push(current);
  return parts;
}

function decodeUtf8(bytes) {
  // ignoreBOM keeps a leading U+FEFF as content, as Python's utf-8 codec does.
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

function unescape(value) {
  const bytes = [];
  const enc = new TextEncoder();
  for (let i = 0; i < value.length; ) {
    const ch = value[i];
    if (ch !== "\\") {
      const cp = value.codePointAt(i);
      if (cp >= 0xd800 && cp <= 0xdfff) throw new DNError("lone surrogate");
      const str = String.fromCodePoint(cp);
      bytes.push(...enc.encode(str));
      i += str.length;
      continue;
    }
    if (i + 1 >= value.length) throw new DNError("trailing backslash");
    const next = value[i + 1];
    if (SPECIALS.includes(next)) {
      bytes.push(...enc.encode(next));
      i += 2;
    } else if (i + 2 < value.length && HEX.test(next) && HEX.test(value[i + 2])) {
      bytes.push(parseInt(value.slice(i + 1, i + 3), 16));
      i += 3;
    } else throw new DNError(`invalid escape in ${JSON.stringify(value)}`);
  }
  try {
    return decodeUtf8(new Uint8Array(bytes));
  } catch {
    throw new DNError("escaped bytes are not UTF-8");
  }
}

// Decode the content of an ASN.1 string value, as daur/dn.py _decode_string does.
function decodeString(tag, content) {
  const encoding = STRING_TAGS[tag];
  if (!encoding) throw new DNError(`unsupported value type 0x${tag.toString(16).padStart(2, "0")}`);
  if (encoding === "utf-32be") {
    if (content.length % 4) throw new DNError("value is not valid text");
    let out = "";
    for (let i = 0; i < content.length; i += 4) {
      const cp = ((content[i] << 24) >>> 0) + (content[i + 1] << 16) + (content[i + 2] << 8) + content[i + 3];
      if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) throw new DNError("value is not valid text");
      out += String.fromCodePoint(cp);
    }
    return out;
  }
  if (encoding === "ascii") {
    if (content.some((b) => b > 0x7f)) throw new DNError("value is not valid text");
    return String.fromCharCode(...content);
  }
  if (encoding === "latin1") return String.fromCharCode(...content);
  if (encoding === "utf-16be") {
    if (content.length % 2) throw new DNError("value is not valid text");
    let out = "";
    for (let i = 0; i < content.length; i += 2) out += String.fromCharCode((content[i] << 8) | content[i + 1]);
    if (!out.isWellFormed()) throw new DNError("value is not valid text");
    return out;
  }
  try {
    return decodeUtf8(content);
  } catch {
    throw new DNError("value is not valid text");
  }
}

// [tag, content start, content end] of the DER element at offset.
function readTlv(der, offset) {
  if (offset + 2 > der.length) throw new DNError("truncated DER");
  const tag = der[offset];
  let length = der[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || start + count > der.length) throw new DNError("unsupported length encoding");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + der[start + i];
    start += count;
  }
  if (start + length > der.length) throw new DNError("truncated DER");
  return [tag, start, start + length];
}

function decodeHexValue(text) {
  const hex = text.slice(1);
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex)) throw new DNError("invalid hex value");
  const der = new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
  if (der.length < 2) throw new DNError("hex value too short");
  const [tag, start, end] = readTlv(der, 0);
  if (end !== der.length) throw new DNError("hex value length mismatch");
  return decodeString(tag, der.slice(start, end));
}

// Remove surrounding whitespace (6.3) that is not escaped (RFC 4514 escapes a leading or trailing space).
function stripUnescaped(value) {
  let v = lstripWs(value);
  while (v.length && isWs(v[v.length - 1])) {
    const body = v.slice(0, -1);
    const trailingBackslashes = body.length - body.replace(/\\+$/, "").length;
    if (trailingBackslashes % 2 === 1) break;
    v = body;
  }
  return v;
}

// Code-point order, as Python sorts strings (UTF-16 code-unit order differs above U+FFFF).
function cmpStr(a, b) {
  const x = [...a];
  const y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d) return d < 0 ? -1 : 1;
  }
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
}

function sortedPairs(pairs) {
  return pairs.sort((a, b) => cmpStr(a[0], b[0]) || cmpStr(a[1], b[1]));
}

/**
 * Parse an RFC 4514 string into RDNs in string order (the last DER RDN first); each RDN is a sorted
 * array of [oid, value]. Throws DNError when the string cannot be read.
 */
export function parseRfc4514(text) {
  if (typeof text !== "string" || !stripWs(text)) throw new DNError("empty name");
  const rdns = [];
  for (const rdnText of split(text, ",;")) {
    const pairs = [];
    for (const atv of split(rdnText, "+")) {
      const eq = atv.indexOf("=");
      if (eq < 0) throw new DNError(`attribute without '=': ${JSON.stringify(atv)}`);
      const typeText = stripWs(atv.slice(0, eq));
      const valueText = stripUnescaped(atv.slice(eq + 1));
      let oid;
      if (/^[0-9]+(?:[.][0-9]+)+$/.test(typeText)) oid = typeText;
      else {
        oid = Object.prototype.hasOwnProperty.call(DESCRIPTORS, typeText.toUpperCase()) ? DESCRIPTORS[typeText.toUpperCase()] : undefined;
        if (!oid) throw new DNError(`unknown attribute type ${JSON.stringify(typeText)}`);
      }
      pairs.push([oid, valueText.startsWith("#") ? decodeHexValue(valueText) : unescape(valueText)]);
    }
    rdns.push(sortedPairs(pairs));
  }
  return rdns;
}

function decodeOid(content) {
  if (!content.length || content[content.length - 1] & 0x80) throw new DNError("malformed object identifier");
  const arcs = [];
  let value = 0n;
  for (const b of content) {
    value = (value << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(value);
      value = 0n;
    }
  }
  const first = arcs[0];
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].map(String).join(".");
}

function bytesOf(der) {
  return der instanceof Uint8Array ? der : new Uint8Array(der);
}

/**
 * The RDNs of a DER-encoded Name (ArrayBuffer or Uint8Array) in string order, as parseRfc4514 returns
 * them, read directly from the DER (as daur/dn.py der_name_rdns does) rather than through a library
 * that may decode UniversalString or T61String values differently.
 */
export function nameRdns(der) {
  der = bytesOf(der);
  const [tag, start, end] = readTlv(der, 0);
  if (tag !== 0x30 || end !== der.length) throw new DNError("a Name is a SEQUENCE");
  const out = [];
  let pos = start;
  while (pos < end) {
    const [setTag, sStart, sEnd] = readTlv(der, pos);
    if (setTag !== 0x31) throw new DNError("an RDN is a SET");
    const pairs = [];
    let p = sStart;
    while (p < sEnd) {
      const [seqTag, aStart, aEnd] = readTlv(der, p);
      if (seqTag !== 0x30) throw new DNError("an attribute is a SEQUENCE");
      const [oidTag, oStart, oEnd] = readTlv(der, aStart);
      if (oidTag !== 0x06) throw new DNError("attribute type is not an OID");
      const [vTag, vStart, vEnd] = readTlv(der, oEnd);
      if (vEnd !== aEnd) throw new DNError("attribute has extra content");
      pairs.push([decodeOid(der.slice(oStart, oEnd)), decodeString(vTag, der.slice(vStart, vEnd))]);
      p = aEnd;
    }
    if (!pairs.length) throw new DNError("empty RDN");
    out.push(sortedPairs(pairs));
    pos = sEnd;
  }
  return out.reverse();
}

function tbsElements(der) {
  const [, oStart] = readTlv(der, 0);
  const [, start, end] = readTlv(der, oStart);
  const elems = [];
  let pos = start;
  while (pos < end) {
    const [tag, , e] = readTlv(der, pos);
    elems.push([tag, der.slice(pos, e)]);
    pos = e;
  }
  return elems;
}

/** {issuer, subject} of a DER certificate as the DER Name bytes it carries. */
export function certNameDers(certDer) {
  let elems = tbsElements(bytesOf(certDer));
  if (elems.length && elems[0][0] === 0xa0) elems = elems.slice(1);
  return { issuer: elems[2][1], subject: elems[4][1] };
}

/** The issuer of a DER CRL as the DER Name bytes it carries. */
export function crlIssuerDer(crlDer) {
  let elems = tbsElements(bytesOf(crlDer));
  if (elems.length && elems[0][0] === 0x02) elems = elems.slice(1);
  return elems[1][1];
}

/**
 * The form in which names are compared for path building and CRL and token issuers (as daur/dn.py
 * name_key): the decoded RDN sequence, or the exact DER when it cannot be decoded.
 */
export function nameKey(der) {
  der = bytesOf(der);
  try {
    return `rdns:${JSON.stringify(nameRdns(der))}`;
  } catch {
    return `der:${[...der].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }
}

const keyCache = new WeakMap();
function certKeys(cert) {
  let k = keyCache.get(cert);
  if (!k) {
    try {
      const { issuer, subject } = certNameDers(cert.rawData);
      k = { issuer: nameKey(issuer), subject: nameKey(subject) };
    } catch {
      k = { issuer: "invalid-issuer", subject: "invalid-subject" };
    }
    keyCache.set(cert, k);
  }
  return k;
}

/** nameKey of a certificate's subject (an @peculiar/x509 X509Certificate). */
export function subjectKey(cert) {
  return certKeys(cert).subject;
}

/** nameKey of a certificate's issuer. */
export function issuerKey(cert) {
  return certKeys(cert).issuer;
}

function sameRdns(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].length !== b[i].length) return false;
    for (let j = 0; j < a[i].length; j++) if (a[i][j][0] !== b[i][j][0] || a[i][j][1] !== b[i][j][1]) return false;
  }
  return true;
}

/**
 * True when `text` names the same distinguished name as the DER name `der`. Any error while reading
 * either side is a difference (SIGNER_DETAILS_DIFFER), never an unhandled error.
 */
export function nameMatches(text, der) {
  try {
    return sameRdns(parseRfc4514(text), nameRdns(der));
  } catch {
    return false;
  }
}

/** True when the record's hexadecimal serial equals the certificate's serial (a hex string from @peculiar/x509). */
export function serialMatches(text, certSerialHex) {
  let clean = stripWs(String(text)).toLowerCase().replace(/:/g, "");
  if (clean.startsWith("0x")) clean = clean.slice(2);
  if (!/^[0-9a-f]+$/.test(clean)) return false;
  const cert = String(certSerialHex).toLowerCase().replace(/^0x/, "").replace(/:/g, "");
  if (!/^[0-9a-f]+$/.test(cert)) return false;
  return BigInt(`0x${clean}`) === BigInt(`0x${cert}`);
}

export const OID_COMMON_NAME = "2.5.4.3";
export const OID_ORGANISATION = "2.5.4.10";

/** Every value of attribute type `oid` in the DER name, in string order; [] when the name cannot be read. */
export function nameValues(der, oid) {
  try {
    return nameRdns(der).flatMap((rdn) => rdn.filter(([o]) => o === oid).map(([, v]) => v));
  } catch {
    return [];
  }
}

/**
 * The form in which names are compared (specification 11.4): surrounding whitespace removed, each
 * internal whitespace run replaced by one U+0020, then the Unicode default lower-case mapping.
 */
export function comparableText(value) {
  return collapseWs(String(value)).toLowerCase();
}

export function sameText(a, b) {
  return comparableText(a) === comparableText(b);
}
