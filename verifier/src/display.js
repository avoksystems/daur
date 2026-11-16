// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Untrusted text on the screen (specification 11.8); mirrors daur/display.py. Every string the page
// shows that came from a record, a certificate, a CRL, a token, a trust manifest, an evidence entry,
// a citation report or a file name passes through displayText: C0 and C1 controls, DEL and the
// bidirectional controls become visible \uXXXX escapes.

const BIDI_CONTROLS = new Set(["\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]);
export const INDENT = "    ";

export function isUnsafe(ch) {
  const cp = ch.codePointAt(0);
  return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || BIDI_CONTROLS.has(ch);
}

function escapeChar(ch) {
  return `\\u${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
}

// With multiline, a line feed becomes a line break followed by an indent; otherwise it is escaped.
export function displayText(value, multiline = false, indent = INDENT) {
  const text = value === null || value === undefined ? "" : String(value);
  let out = "";
  for (const ch of text) {
    if (ch === "\n" && multiline) out += `\n${indent}`;
    else if (isUnsafe(ch)) out += escapeChar(ch);
    else out += ch;
  }
  return out;
}

// JSON.stringify with every unsafe character escaped (it escapes C0 controls itself but leaves DEL, C1
// and bidirectional controls raw; its indentation line feeds are structure and stay).
export function jsonText(value, replacer = null, space = 0) {
  return JSON.stringify(value, replacer, space).replace(/[\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function multilineAllowed(path) {
  if ((path[0] === "human_review" && path[1] === "statement" && path.length === 2) || (path[0] === "declaration" && path[1] === "text" && path.length === 2)) return true;
  return path.length === 4 && path[0] === "regime_references" && typeof path[1] === "number" && path[2] === "answers";
}

// Specification 4.1: strings of a 0.2 record carry no control or bidirectional control characters
// (a line feed is allowed in human_review.statement, declaration.text and regime answers). SCHEMA_INVALID.
export function recordTextErrors(record) {
  if (!record || typeof record !== "object" || Array.isArray(record) || record.daur_version !== "0.2") return [];
  const errors = [];
  const check = (text, path, key) => {
    const allowedLf = !key && multilineAllowed(path);
    for (const ch of text) {
      if (ch === "\n" && allowedLf) continue;
      if (isUnsafe(ch)) {
        const where = path.join("/") || "(root)";
        errors.push(`${where}: ${key ? "the member name" : "the text"} contains U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}, a control or bidirectional control character that a record of daur_version 0.2 may not carry`);
        return;
      }
    }
  };
  const walk = (value, path) => {
    if (typeof value === "string") check(value, path, false);
    else if (Array.isArray(value)) value.forEach((v, i) => walk(v, [...path, i]));
    else if (value && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) {
        check(k, [...path, k], true);
        walk(v, [...path, k]);
      }
    }
  };
  walk(record, []);
  return errors;
}
