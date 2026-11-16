// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Region recomputation available in the browser: byte ranges always, Markdown heading sections,
// and paragraph ranges for text and Markdown. PDF and DOCX regions are not recomputed here.

import { sha256Hex, utf8 } from "./util.js";
import { WS_CLASS, lstripWs, rstripWs, stripWs } from "./whitespace.js";

export const METHOD_BYTES = "daur-bytes-v1";
export const METHOD_MARKDOWN = "daur-markdown-atx-sections-v1";
export const METHOD_PARAGRAPHS = "daur-paragraphs-v1";
export const PREAMBLE_REF = "(preamble)";


export function canonicalText(text) {
  let t = text.normalize("NFC").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = t.split("\n").map((line) => rstripWs(line));
  while (lines.length && lines[0] === "") lines.shift();
  while (lines.length && lines[lines.length - 1] === "") lines.pop();
  return new TextEncoder().encode(lines.join("\n"));
}

const RANGE = new RegExp(`^(pages?|bytes|paragraphs?)[${WS_CLASS}]+([0-9]+)(?:[${WS_CLASS}]*-[${WS_CLASS}]*([0-9]+))?$`);

export function parseRangeRef(ref) {
  const m = RANGE.exec(stripWs(ref));
  if (!m) throw new Error(`cannot parse range reference ${JSON.stringify(ref)}`);
  const start = parseInt(m[2], 10);
  const end = m[3] !== undefined ? parseInt(m[3], 10) : start;
  if (end < start) throw new Error(`range end before start in ${JSON.stringify(ref)}`);
  const kind = { page: "pages", pages: "pages", bytes: "bytes", paragraph: "paragraphs", paragraphs: "paragraphs" }[m[1]];
  return { kind, start, end };
}

// Heading text and fence detection use the whitespace set of 6.3 (specification 6.2); the s flag makes
// U+2028 and U+2029 ordinary characters inside a line, as they are in the Python verifier.
const ATX = new RegExp(`^(#{1,6})[ \\t]+(.*?)[${WS_CLASS}]*#*[${WS_CLASS}]*$`, "s");
const FENCE = /^(`{3,}|~{3,})/;

export function markdownSections(text) {
  const t = text.normalize("NFC").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const sections = [];
  let ref = PREAMBLE_REF;
  let current = [];
  let fence = null;
  for (const line of t.split("\n")) {
    const f = FENCE.exec(lstripWs(line));
    if (f) {
      const marker = f[1][0].repeat(3);
      if (fence === null) fence = marker;
      else if (lstripWs(line).startsWith(fence)) fence = null;
      current.push(line);
      continue;
    }
    if (fence === null) {
      const m = ATX.exec(line);
      if (m) {
        sections.push([ref, current]);
        ref = `${m[1]} ${stripWs(m[2])}`;
        current = [line];
        continue;
      }
    }
    current.push(line);
  }
  sections.push([ref, current]);
  const out = [];
  for (const [r, body] of sections) {
    const joined = body.join("\n");
    if (r === PREAMBLE_REF && canonicalText(joined).length === 0) continue;
    out.push([r, joined]);
  }
  return out;
}

export async function markdownRegionHashes(text) {
  const seen = new Map();
  const out = new Map();
  for (const [ref, body] of markdownSections(text)) {
    const count = seen.get(ref) || 0;
    seen.set(ref, count + 1);
    const label = count === 0 ? ref : `${ref} [${count + 1}]`;
    out.set(label, await sha256Hex(canonicalText(body)));
  }
  return out;
}

export function textParagraphs(text) {
  const t = text.normalize("NFC").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return t.split(/\n[ \t]*\n+/).filter((b) => canonicalText(b).length > 0);
}

/**
 * Recompute a region hash. Returns a hex string, or null when the method is not available here.
 * Throws when the reference cannot be resolved against the file.
 */
export async function recompute(bytes, mediaType, region) {
  const method = region.extraction_method;
  if (!method) return null;
  if (region.type === "byte_range" && method === METHOD_BYTES) {
    const { kind, start, end } = parseRangeRef(region.ref);
    if (kind !== "bytes") throw new Error(`byte_range region needs a 'bytes S-E' reference`);
    if (end >= bytes.length && !(bytes.length === 0 && start === 0 && end === 0)) throw new Error(`byte range ${region.ref} exceeds file length ${bytes.length}`);
    return sha256Hex(bytes.slice(start, end + 1));
  }
  if (region.type === "heading" && method === METHOD_MARKDOWN) {
    const hashes = await markdownRegionHashes(utf8(bytes));
    if (!hashes.has(region.ref)) throw new Error(`heading ${JSON.stringify(region.ref)} not found`);
    return hashes.get(region.ref);
  }
  if (region.type === "paragraph_range" && method === METHOD_PARAGRAPHS && mediaType !== "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
    const { kind, start, end } = parseRangeRef(region.ref);
    if (kind !== "paragraphs") throw new Error(`paragraph_range region needs a 'paragraphs N-M' reference`);
    const paragraphs = textParagraphs(utf8(bytes));
    if (start < 1 || end > paragraphs.length) throw new Error(`paragraph range ${region.ref} outside document with ${paragraphs.length} paragraphs`);
    const parts = paragraphs.slice(start - 1, end).map(canonicalText);
    const total = parts.reduce((n, p) => n + p.length, 0) + Math.max(0, parts.length - 1);
    const joined = new Uint8Array(total);
    let off = 0;
    parts.forEach((p, i) => {
      if (i > 0) joined[off++] = 0x0a;
      joined.set(p, off);
      off += p.length;
    });
    return sha256Hex(joined);
  }
  return null;
}
