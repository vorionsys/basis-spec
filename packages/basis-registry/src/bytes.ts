// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Low-level byte primitives: base58btc, multibase ('z'), multihash
 * (sha2-256 / sha2-384), and a length-checked constant-time compare.
 *
 * NO heavy dependencies — only Node's built-in 'crypto' (imported by callers).
 * Each function fails CLOSED: a malformed input returns null, never a partial
 * or coerced value. timingSafeEqual is NEVER called on unequal-length buffers
 * (it throws ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH) — length is checked first.
 */

import { timingSafeEqual } from 'node:crypto';

// ---------------------------------------------------------------------------
// base58btc (Bitcoin alphabet)
// ---------------------------------------------------------------------------

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>();
  for (let i = 0; i < B58_ALPHABET.length; i++) {
    // index is in-bounds by construction
    m.set(B58_ALPHABET[i] as string, i);
  }
  return m;
})();

/** Encode bytes to base58btc. Deterministic; leading zero bytes => '1's. */
export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Convert the big-endian byte array to base58 via repeated division.
  const input = Array.from(bytes);
  const out: number[] = [];
  let start = zeros;
  while (start < input.length) {
    let remainder = 0;
    for (let i = start; i < input.length; i++) {
      const acc = (remainder << 8) + (input[i] as number);
      input[i] = Math.floor(acc / 58);
      remainder = acc % 58;
    }
    out.push(remainder);
    while (start < input.length && input[start] === 0) start++;
  }

  let result = '';
  for (let i = 0; i < zeros; i++) result += '1';
  for (let i = out.length - 1; i >= 0; i--) {
    result += B58_ALPHABET[out[i] as number];
  }
  return result;
}

/**
 * Decode a base58btc string. Returns null (fail-closed) on ANY character
 * outside the alphabet — never throws, never partially decodes.
 */
export function base58btcDecode(str: string): Uint8Array | null {
  if (str.length === 0) return new Uint8Array(0);
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;

  const bytes: number[] = [];
  for (let i = zeros; i < str.length; i++) {
    const ch = str[i] as string;
    const val = B58_MAP.get(ch);
    if (val === undefined) return null; // non-alphabet char => fail-closed
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      const acc = (bytes[j] as number) * 58 + carry;
      bytes[j] = acc & 0xff;
      carry = acc >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  // leading zeros already accounted for (out is zero-initialized)
  for (let i = 0; i < bytes.length; i++) {
    out[zeros + i] = bytes[bytes.length - 1 - i] as number;
  }
  return out;
}

// ---------------------------------------------------------------------------
// multibase ('z' = base58btc) — the ONLY multibase this lib emits/accepts
// ---------------------------------------------------------------------------

/** Multibase-encode bytes with the 'z' (base58btc) prefix. */
export function multibaseEncodeZ(bytes: Uint8Array): string {
  return 'z' + base58btcEncode(bytes);
}

/**
 * Decode a multibase string. ONLY the 'z' (base58btc) code is accepted; any
 * other multibase prefix (e.g. 'f' base16, 'm' base64) => null (fail-closed).
 * This is the did:key footgun guard: a 'did:key:f...' must not silently decode.
 */
export function multibaseDecodeZ(str: string): Uint8Array | null {
  if (str.length === 0 || str[0] !== 'z') return null;
  return base58btcDecode(str.slice(1));
}

// ---------------------------------------------------------------------------
// multihash (sha2-256 = 0x12, sha2-384 = 0x20)
// ---------------------------------------------------------------------------

/** Multihash code for sha2-256 (per the multicodec table). */
export const MH_SHA2_256 = 0x12;
/** Multihash code for sha2-384 (per the multicodec table). */
export const MH_SHA2_384 = 0x20;

/**
 * Wrap a raw digest in a multihash: varint(code) || varint(len) || digest.
 * Both code and length here are < 128 so each varint is a single byte. The
 * length byte MUST equal digest.length (enforced on decode).
 */
export function multihashEncode(code: number, digest: Uint8Array): Uint8Array {
  if (code < 0 || code > 0x7f) {
    throw new RangeError('multihash: code outside single-byte varint range');
  }
  if (digest.length > 0x7f) {
    throw new RangeError('multihash: digest longer than single-byte varint');
  }
  const out = new Uint8Array(2 + digest.length);
  out[0] = code;
  out[1] = digest.length;
  out.set(digest, 2);
  return out;
}

export interface DecodedMultihash {
  readonly code: number;
  readonly digest: Uint8Array;
}

/**
 * Decode a single-byte-varint multihash. FAIL-CLOSED:
 *  - too short (< 2 bytes) => null;
 *  - the declared length byte MUST equal the number of remaining bytes
 *    (a truncation/over-length attack on the length field) => null;
 *  - multi-byte varints (high bit set) are not supported here (none of this
 *    lib's codes/lengths need them) => null.
 */
export function multihashDecode(mh: Uint8Array): DecodedMultihash | null {
  if (mh.length < 2) return null;
  const code = mh[0] as number;
  const len = mh[1] as number;
  // reject multi-byte varint (continuation bit) for code or length
  if (code > 0x7f || len > 0x7f) return null;
  const digest = mh.subarray(2);
  // The declared length MUST match the actual remaining-byte count. This is
  // the truncation-acceptance hole the reviewer named: a decoder that trusts
  // the length without verifying the byte count would accept a short digest.
  if (digest.length !== len) return null;
  return { code, digest: new Uint8Array(digest) };
}

/**
 * Decode a multihash and require an EXACT code + digest length. Returns the
 * digest bytes or null. Used by id verification so a sha2-256 multihash can
 * never be accepted where a sha2-384 one is required and vice versa.
 */
export function multihashDecodeExact(
  mh: Uint8Array,
  expectCode: number,
  expectLen: number,
): Uint8Array | null {
  const d = multihashDecode(mh);
  if (d === null) return null;
  if (d.code !== expectCode) return null;
  if (d.digest.length !== expectLen) return null;
  return d.digest;
}

// ---------------------------------------------------------------------------
// constant-time equality (length-checked first — never throws)
// ---------------------------------------------------------------------------

/**
 * Constant-time byte equality. Length is compared FIRST (returning false on a
 * mismatch) so timingSafeEqual is only ever called on equal-length buffers and
 * can never throw ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  if (a.length === 0) return true;
  return timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// hex helpers (lowercase, the repo proof-chain convention for log hashes)
// ---------------------------------------------------------------------------

const HEX_RE = /^[0-9a-f]*$/;

/** Lowercase hex of bytes. */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Parse lowercase hex into bytes, requiring an EXACT byte length. Returns null
 * (fail-closed) on any non-[0-9a-f] char, odd length, or wrong length. Reject
 * uppercase so two encodings of one hash cannot both 'verify'.
 */
export function fromHexExact(str: string, expectLen: number): Uint8Array | null {
  if (typeof str !== 'string') return null;
  if (str.length !== expectLen * 2) return null;
  if (!HEX_RE.test(str)) return null;
  const out = new Uint8Array(expectLen);
  for (let i = 0; i < expectLen; i++) {
    out[i] = parseInt(str.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
