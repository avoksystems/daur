// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// The one whitespace set of specification 6.3 (the characters for which Python's str.isspace() is
// true), used wherever a verification result depends on trimming or collapsing text. JavaScript's
// \s and String.prototype.trim() are never used for that: they include U+FEFF and exclude U+001C to
// U+001F and U+0085. Mirrors daur/whitespace.py.

export const WS_CLASS = "\\t\\n\\v\\f\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";

const LEADING = new RegExp(`^[${WS_CLASS}]+`);
const TRAILING = new RegExp(`[${WS_CLASS}]+$`);
const RUN = new RegExp(`[${WS_CLASS}]+`, "g");
const ONE = new RegExp(`^[${WS_CLASS}]$`);

export function isWs(ch) {
  return ch.length === 1 && ONE.test(ch);
}

export function lstripWs(text) {
  return String(text).replace(LEADING, "");
}

export function rstripWs(text) {
  return String(text).replace(TRAILING, "");
}

export function stripWs(text) {
  return rstripWs(lstripWs(text));
}

/** Surrounding whitespace removed and every internal run replaced by one U+0020. */
export function collapseWs(text) {
  return stripWs(text).replace(RUN, " ");
}
