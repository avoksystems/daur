// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Trust manifest rules (specification 10.2): the schema trust-manifest-v0.2.schema.json, I-JSON
// (RFC 7493) numbers and member names, and no control, bidirectional or lone surrogate character in
// any string. Mirrors daur/trust.py manifest_problems and parse_manifest_text. A manifest that breaks
// a rule is not read at all; the verifier reports TRUST_LIST_INVALID.

import { validate } from "./schema.js";
import MANIFEST_SCHEMA from "./manifest-schema.generated.js";

export const IJSON_MAX = 2n ** 53n - 1n;
const BIDI = new Set([0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);

function unsafe(cp) {
  return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || BIDI.has(cp);
}

function where(path) {
  return path.length ? path.join("/") : "(root)";
}

function hex(cp) {
  return cp.toString(16).toUpperCase().padStart(4, "0");
}

function checkText(text, at, what, problems) {
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i += 1;
        continue;
      }
    }
    if (cp >= 0xd800 && cp <= 0xdfff) {
      problems.push(`${at}: ${what} contains the lone surrogate U+${hex(cp)}`);
      return;
    }
    if (unsafe(cp)) {
      problems.push(`${at}: ${what} contains U+${hex(cp)}, a control or bidirectional control character`);
      return;
    }
  }
}

function textProblems(value, path, problems, numbers) {
  if (typeof value === "string") checkText(value, where(path), "the text", problems);
  else if (Array.isArray(value)) value.forEach((v, i) => textProblems(v, [...path, i], problems, numbers));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      checkText(k, where([...path, k]), "the member name", problems);
      textProblems(v, [...path, k], problems, numbers);
    }
  } else if (numbers && typeof value === "number") {
    if (!Number.isInteger(value)) problems.push(`${where(path)}: the number ${value} is not an integer`);
    else if (!Number.isSafeInteger(value)) problems.push(`${where(path)}: the integer ${value} is outside the I-JSON range (at most 2^53-1 in magnitude)`);
  }
}

// RFC 3339 times as Python's datetime accepts them: a real calendar day, hour 0 to 23, minute and
// second 0 to 59, an offset under 24 hours (the schema has already checked the shape).
function validTime(text) {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-]([0-9]{2}):([0-9]{2}))$/.exec(text);
  if (!m) return false;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  if (year < 1 || month < 1 || month > 12 || day < 1) return false;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (day > days || hour > 23 || minute > 59 || second > 59) return false;
  if (m[8] !== "Z" && (Number(m[9]) > 23 || Number(m[10]) > 59)) return false;
  return true;
}

/**
 * Every way `manifest` breaks the rules of specification 10.2; empty when it may be used. With
 * `numbers` false the numbers were checked while the text was parsed (parseManifestText).
 */
export function manifestProblems(manifest, numbers = true) {
  const problems = [];
  textProblems(manifest, [], problems, numbers);
  for (const err of validate(manifest, MANIFEST_SCHEMA)) problems.push(err.replace(/^\//, ""));
  if (problems.length || !manifest || typeof manifest !== "object" || Array.isArray(manifest)) return problems;
  const times = [
    ["issued", manifest.issued],
    ["next_update", manifest.next_update],
  ];
  (manifest.roots || []).forEach((r, i) => times.push([`roots/${i}/not_before`, r.not_before], [`roots/${i}/not_after`, r.not_after]));
  (manifest.invalidity_dates || []).forEach((e, i) => times.push([`invalidity_dates/${i}/invalid_from`, e.invalid_from]));
  for (const [at, value] of times) if (value !== undefined && !validTime(value)) problems.push(`${at}: ${JSON.stringify(value)} is not a valid RFC 3339 time`);
  return problems;
}

/**
 * Parse manifest text as I-JSON: { value, problems }. Throws a SyntaxError when the text is not JSON
 * (as JSON.parse does). Duplicate member names, numbers that are not integers and integers outside
 * the I-JSON range are problems; the number is still returned (rounded) so that parsing can go on.
 */
export function parseManifestText(text) {
  const problems = [];
  const n = text.length;
  let i = 0;
  const fail = (message) => {
    throw new SyntaxError(`${message} at position ${i}`);
  };
  const ws = () => {
    while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  const string = () => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = text[i];
      const code = text.charCodeAt(i);
      if (c === '"') {
        i++;
        return out;
      }
      if (code < 0x20) fail("control character in string");
      if (c !== "\\") {
        out += c;
        i++;
        continue;
      }
      const e = text[i + 1];
      i += 2;
      if (e === '"' || e === "\\" || e === "/") out += e;
      else if (e === "b") out += "\b";
      else if (e === "f") out += "\f";
      else if (e === "n") out += "\n";
      else if (e === "r") out += "\r";
      else if (e === "t") out += "\t";
      else if (e === "u") {
        const h = text.slice(i, i + 4);
        if (!/^[0-9A-Fa-f]{4}$/.test(h)) fail("bad unicode escape");
        out += String.fromCharCode(parseInt(h, 16));
        i += 4;
      } else fail("bad escape");
    }
  };
  const NUMBER = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
  const number = (path) => {
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m || !m[0] || m[0] === "-") fail("unexpected character");
    i += m[0].length;
    if (m[2] !== undefined || m[3] !== undefined) problems.push(`${where(path)}: the number ${m[0]} is not an integer`);
    else {
      const big = BigInt(m[0]);
      if (big > IJSON_MAX || big < -IJSON_MAX) problems.push(`${where(path)}: the integer ${m[0]} is outside the I-JSON range (at most 2^53-1 in magnitude)`);
    }
    return Number(m[0]);
  };
  const value = (path) => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const out = {};
      const seen = new Set();
      ws();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected a member name");
        const key = string();
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        if (seen.has(key)) problems.push(`${where(path)}: the member name ${JSON.stringify(key)} occurs twice in one object`);
        seen.add(key);
        // As JSON.parse does: an own property, also for "__proto__"; the last occurrence wins.
        Object.defineProperty(out, key, { value: value([...path, key]), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return out;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const out = [];
      ws();
      if (text[i] === "]") {
        i++;
        return out;
      }
      for (;;) {
        out.push(value([...path, out.length]));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return out;
        }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return string();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    return number(path);
  };
  const result = value([]);
  ws();
  if (i !== n) fail("unexpected text after the JSON value");
  problems.push(...manifestProblems(result, false));
  return { value: result, problems };
}
