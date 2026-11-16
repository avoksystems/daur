// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Small helpers: hex, base64, SHA-256, JCS (RFC 8785), RFC 3339, PEM.

import { stripWs } from "./whitespace.js";

export function toHex(bytes) {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function base64Decode(text) {
  // RFC 4648 section 4 strictly, as the Python verifier decodes it: no whitespace, padded to a multiple of four.
  if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) throw new Error("invalid base64: RFC 4648 section 4 base64 without whitespace, padded to a multiple of four, is required");
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64Encode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

export async function sha256Hex(bytes) {
  return toHex(await sha256(bytes));
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// RFC 8785. JSON.stringify follows ECMAScript number formatting, which is what JCS requires,
// and the default string sort compares UTF-16 code units, which is the JCS key order.
export function jcs(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("NaN and Infinity are not permitted in JCS");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new Error(`cannot canonicalise ${typeof value}`);
}

export function jcsBytes(value) {
  return new TextEncoder().encode(jcs(value));
}

const RFC3339 = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$/;

export function parseRfc3339(text) {
  const m = RFC3339.exec(stripWs(String(text)));
  if (!m) return null;
  const d = new Date(stripWs(String(text)).replace(/[tz]/g, (c) => c.toUpperCase()));
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatRfc3339(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function pemBlocks(text, label) {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`, "g");
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) out.push(base64Decode(m[1].replace(/[\r\n\t ]+/g, "")));
  return out;
}

export function derToPem(der, label) {
  const b64 = base64Encode(der).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${b64.trim()}\n-----END ${label}-----\n`;
}

// Strict UTF-8 that keeps a leading byte order mark, like Python's bytes.decode("utf-8"), so
// that a Markdown file starting with U+FEFF canonicalises to the same text in both verifiers.
export function utf8(bytes) {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

export function normaliseSerial(text) {
  return String(text).toLowerCase().replace(/^0x/, "").replace(/:/g, "").replace(/^0+(?=.)/, "");
}
