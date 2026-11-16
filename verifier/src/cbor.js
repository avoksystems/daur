// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Minimal CBOR (RFC 8949) decoder and deterministic encoder for COSE_Sign1.
// Integer keys are preserved: maps decode to JS Map objects.

export class CborTag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

export class CborError extends Error {}

export function decode(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const state = { view, pos: 0 };
  const value = readItem(state);
  if (state.pos !== view.length) throw new CborError(`trailing bytes after CBOR item (${view.length - state.pos})`);
  return value;
}

function need(state, n) {
  if (state.pos + n > state.view.length) throw new CborError("premature end of CBOR data");
}

function readArgument(state, info) {
  if (info < 24) return info;
  if (info === 24) {
    need(state, 1);
    return state.view[state.pos++];
  }
  if (info === 25) {
    need(state, 2);
    const v = (state.view[state.pos] << 8) | state.view[state.pos + 1];
    state.pos += 2;
    return v;
  }
  if (info === 26) {
    need(state, 4);
    const v = ((state.view[state.pos] << 24) >>> 0) + (state.view[state.pos + 1] << 16) + (state.view[state.pos + 2] << 8) + state.view[state.pos + 3];
    state.pos += 4;
    return v;
  }
  if (info === 27) {
    need(state, 8);
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(state.view[state.pos + i]);
    state.pos += 8;
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
  if (info === 31) return Infinity; // indefinite length
  throw new CborError(`reserved additional information ${info}`);
}

function readItem(state) {
  need(state, 1);
  const initial = state.view[state.pos++];
  const major = initial >> 5;
  const info = initial & 0x1f;
  switch (major) {
    case 0:
      return readArgument(state, info);
    case 1: {
      const n = readArgument(state, info);
      return typeof n === "bigint" ? -1n - n : -1 - n;
    }
    case 2:
    case 3: {
      const len = readArgument(state, info);
      if (len === Infinity) {
        const chunks = [];
        for (;;) {
          need(state, 1);
          if (state.view[state.pos] === 0xff) {
            state.pos++;
            break;
          }
          const chunk = readItem(state);
          chunks.push(major === 2 ? chunk : new TextEncoder().encode(chunk));
        }
        const total = chunks.reduce((a, c) => a + c.length, 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          out.set(c, off);
          off += c.length;
        }
        return major === 2 ? out : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(out);
      }
      need(state, len);
      const slice = state.view.slice(state.pos, state.pos + len);
      state.pos += len;
      return major === 2 ? slice : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(slice);
    }
    case 4: {
      const len = readArgument(state, info);
      const out = [];
      if (len === Infinity) {
        for (;;) {
          need(state, 1);
          if (state.view[state.pos] === 0xff) {
            state.pos++;
            break;
          }
          out.push(readItem(state));
        }
        return out;
      }
      for (let i = 0; i < len; i++) out.push(readItem(state));
      return out;
    }
    case 5: {
      const len = readArgument(state, info);
      const map = new Map();
      const add = (k, v) => {
        const key = typeof k === "bigint" ? k.toString() : k;
        if (map.has(key)) throw new CborError("duplicate map key");
        map.set(key, v);
      };
      if (len === Infinity) {
        for (;;) {
          need(state, 1);
          if (state.view[state.pos] === 0xff) {
            state.pos++;
            break;
          }
          add(readItem(state), readItem(state));
        }
        return map;
      }
      for (let i = 0; i < len; i++) add(readItem(state), readItem(state));
      return map;
    }
    case 6: {
      const tag = readArgument(state, info);
      return new CborTag(tag, readItem(state));
    }
    case 7: {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 23) return undefined;
      if (info === 25) {
        need(state, 2);
        const half = (state.view[state.pos] << 8) | state.view[state.pos + 1];
        state.pos += 2;
        return decodeHalf(half);
      }
      if (info === 26) {
        need(state, 4);
        const v = new DataView(state.view.buffer, state.view.byteOffset + state.pos, 4).getFloat32(0);
        state.pos += 4;
        return v;
      }
      if (info === 27) {
        need(state, 8);
        const v = new DataView(state.view.buffer, state.view.byteOffset + state.pos, 8).getFloat64(0);
        state.pos += 8;
        return v;
      }
      if (info < 20 || info === 24) {
        return { simple: readArgument(state, info) };
      }
      throw new CborError(`unsupported simple value ${info}`);
    }
    default:
      throw new CborError(`unknown major type ${major}`);
  }
}

function decodeHalf(half) {
  const exp = (half >> 10) & 0x1f;
  const mant = half & 0x3ff;
  let val;
  if (exp === 0) val = mant * 2 ** -24;
  else if (exp !== 31) val = (mant + 1024) * 2 ** (exp - 25);
  else val = mant === 0 ? Infinity : NaN;
  return half & 0x8000 ? -val : val;
}

// ---------------------------------------------------------------- encoder
function writeHead(out, major, n) {
  if (n < 24) out.push((major << 5) | n);
  else if (n < 0x100) out.push((major << 5) | 24, n);
  else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
  else if (n < 0x100000000) out.push((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  else {
    let big = BigInt(n);
    const bytes = [];
    for (let i = 0; i < 8; i++) {
      bytes.unshift(Number(big & 0xffn));
      big >>= 8n;
    }
    out.push((major << 5) | 27, ...bytes);
  }
}

function encodeItem(out, value) {
  if (value instanceof Uint8Array) {
    writeHead(out, 2, value.length);
    for (const b of value) out.push(b);
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    writeHead(out, 3, bytes.length);
    for (const b of bytes) out.push(b);
    return;
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    if (value >= 0) writeHead(out, 0, value);
    else writeHead(out, 1, -1 - value);
    return;
  }
  if (Array.isArray(value)) {
    writeHead(out, 4, value.length);
    for (const item of value) encodeItem(out, item);
    return;
  }
  if (value === null) {
    out.push(0xf6);
    return;
  }
  if (value === true || value === false) {
    out.push(value ? 0xf5 : 0xf4);
    return;
  }
  throw new CborError(`cannot encode ${typeof value}`);
}

// Encodes the subset needed for Sig_structure: arrays, byte strings, text and integers.
export function encode(value) {
  const out = [];
  encodeItem(out, value);
  return new Uint8Array(out);
}

export function sigStructure(protectedBytes, payload, externalAad = new Uint8Array(0)) {
  return encode(["Signature1", protectedBytes, externalAad, payload]);
}
