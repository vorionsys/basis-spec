// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { describe, it, expect } from 'vitest';
import {
  base58btcEncode,
  base58btcDecode,
  multibaseEncodeZ,
  multibaseDecodeZ,
  multihashEncode,
  multihashDecode,
  multihashDecodeExact,
  MH_SHA2_256,
  MH_SHA2_384,
  constantTimeEqual,
  toHex,
  fromHexExact,
} from '../bytes.js';

describe('base58btc round-trip + fail-closed', () => {
  it('round-trips arbitrary bytes including leading zeros', () => {
    for (const hex of ['00', '0000ff', 'deadbeef', '01020304', 'ff'.repeat(34)]) {
      const b = Uint8Array.from(Buffer.from(hex, 'hex'));
      const enc = base58btcEncode(b);
      const dec = base58btcDecode(enc);
      expect(dec).not.toBeNull();
      expect(toHex(dec as Uint8Array)).toBe(hex);
    }
  });
  it('matches a known vector ("hello world" -> StV1DL6CwTryKyV)', () => {
    expect(base58btcEncode(Uint8Array.from(Buffer.from('hello world')))).toBe('StV1DL6CwTryKyV');
  });
  it('rejects a non-alphabet char (0, O, I, l) => null', () => {
    expect(base58btcDecode('0OIl')).toBeNull();
    expect(base58btcDecode('abc!')).toBeNull();
  });
});

describe('multibase Z (base58btc) — only "z" accepted', () => {
  it('round-trips with the z prefix', () => {
    const b = Uint8Array.from([1, 2, 3, 4]);
    const enc = multibaseEncodeZ(b);
    expect(enc[0]).toBe('z');
    expect(toHex(multibaseDecodeZ(enc) as Uint8Array)).toBe('01020304');
  });
  it('rejects a non-z multibase prefix (f base16, m base64) => null', () => {
    expect(multibaseDecodeZ('f00')).toBeNull();
    expect(multibaseDecodeZ('mAQID')).toBeNull();
    expect(multibaseDecodeZ('')).toBeNull();
  });
});

describe('multihash — exact prefix bytes + truncation rejection', () => {
  it('sha2-256 multihash uses prefix 0x12 0x20', () => {
    const digest = new Uint8Array(32).fill(0xab);
    const mh = multihashEncode(MH_SHA2_256, digest);
    expect(mh[0]).toBe(0x12);
    expect(mh[1]).toBe(0x20);
    expect(mh.length).toBe(34);
  });
  it('sha2-384 multihash uses prefix 0x20 0x30 (NOT the garbled 0x97 0x01 0x30)', () => {
    const digest = new Uint8Array(48).fill(0xcd);
    const mh = multihashEncode(MH_SHA2_384, digest);
    expect(mh[0]).toBe(0x20);
    expect(mh[1]).toBe(0x30);
    expect(mh.length).toBe(50);
  });
  it('decode round-trips code + digest', () => {
    const digest = new Uint8Array(32).fill(0x11);
    const d = multihashDecode(multihashEncode(MH_SHA2_256, digest));
    expect(d).not.toBeNull();
    expect((d as { code: number }).code).toBe(MH_SHA2_256);
    expect(toHex((d as { digest: Uint8Array }).digest)).toBe('11'.repeat(32));
  });
  it('rejects a length-field/digest-length MISMATCH (truncation hole)', () => {
    // declared length 0x20 (32) but only 30 digest bytes present.
    const forged = new Uint8Array([0x12, 0x20, ...new Array(30).fill(0xaa)]);
    expect(multihashDecode(forged)).toBeNull();
  });
  it('rejects too-short buffer (< 2 bytes)', () => {
    expect(multihashDecode(new Uint8Array([0x12]))).toBeNull();
    expect(multihashDecode(new Uint8Array(0))).toBeNull();
  });
  it('multihashDecodeExact rejects a wrong code or wrong length', () => {
    const mh256 = multihashEncode(MH_SHA2_256, new Uint8Array(32).fill(1));
    expect(multihashDecodeExact(mh256, MH_SHA2_384, 48)).toBeNull(); // wrong code
    expect(multihashDecodeExact(mh256, MH_SHA2_256, 48)).toBeNull(); // wrong len
    expect(multihashDecodeExact(mh256, MH_SHA2_256, 32)).not.toBeNull();
  });
});

describe('constantTimeEqual — length-checked, never throws', () => {
  it('returns false on length mismatch without throwing', () => {
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
  it('true on equal content, false on differing', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });
  it('true on two empty buffers', () => {
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('fromHexExact — fail-closed', () => {
  it('parses exact-length lowercase hex', () => {
    const b = fromHexExact('aabb', 2);
    expect(b).not.toBeNull();
    expect(Array.from(b as Uint8Array)).toEqual([0xaa, 0xbb]);
  });
  it('rejects wrong length, uppercase, and non-hex', () => {
    expect(fromHexExact('aabb', 3)).toBeNull(); // wrong length
    expect(fromHexExact('AABB', 2)).toBeNull(); // uppercase
    expect(fromHexExact('zzzz', 2)).toBeNull(); // non-hex
    expect(fromHexExact('abc', 2)).toBeNull(); // odd
  });
});
