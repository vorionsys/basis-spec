// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { describe, it, expect } from 'vitest';
import {
  encodeEd25519DidKey,
  decodeEd25519DidKey,
  isValidEd25519DidKey,
  ed25519Multikey,
  decodeEd25519Multikey,
  normalizeToMultikey,
} from '../didkey.js';
import { multibaseEncodeZ } from '../bytes.js';
import { keyFromSeedByte, freshKey } from './helpers.js';

describe('did:key Ed25519 round-trip', () => {
  it('encode -> decode recovers the raw 32-byte key', () => {
    const k = keyFromSeedByte(3);
    const did = encodeEd25519DidKey(k.raw32);
    expect(did.startsWith('did:key:z')).toBe(true);
    const back = decodeEd25519DidKey(did);
    expect(back).not.toBeNull();
    expect(Array.from(back as Uint8Array)).toEqual(Array.from(k.raw32));
  });

  it('matches the well-known w3c did:key vector prefix z6Mk', () => {
    // The ed25519 multikey 0xed01 prefix always renders as base58 "z6Mk..."
    expect(freshKey().didKey.startsWith('did:key:z6Mk')).toBe(true);
  });

  it('multikey is exactly 34 bytes with 0xed 0x01 prefix', () => {
    const k = keyFromSeedByte(9);
    const mk = ed25519Multikey(k.raw32);
    expect(mk.length).toBe(34);
    expect(mk[0]).toBe(0xed);
    expect(mk[1]).toBe(0x01);
  });
});

describe('did:key fail-closed (malformed => null)', () => {
  it('missing did:key prefix => null', () => {
    expect(decodeEd25519DidKey('z6MkFoo')).toBeNull();
    expect(decodeEd25519DidKey('')).toBeNull();
  });

  it('non-z multibase (base16 f...) => null', () => {
    expect(decodeEd25519DidKey('did:key:f01020304')).toBeNull();
  });

  it('non-base58 char => null', () => {
    expect(decodeEd25519DidKey('did:key:z0OIl')).toBeNull();
  });

  it('KEY-TYPE CONFUSION: a non-ed25519 multikey (X25519 0xec01) => null', () => {
    // 0xec 0x01 || 32 bytes — a valid 34-byte multikey but WRONG codec.
    const x25519 = new Uint8Array([0xec, 0x01, ...new Array(32).fill(0xaa)]);
    const did = 'did:key:' + multibaseEncodeZ(x25519);
    expect(decodeEd25519DidKey(did)).toBeNull();
    expect(isValidEd25519DidKey(did)).toBe(false);
  });

  it('P-256 (0x1200) and secp256k1 (0xe701) multikeys => null', () => {
    const p256 = new Uint8Array([0x80, 0x24, ...new Array(33).fill(1)]); // 0x1200 varint
    const secp = new Uint8Array([0xe7, 0x01, ...new Array(33).fill(1)]);
    expect(decodeEd25519DidKey('did:key:' + multibaseEncodeZ(p256))).toBeNull();
    expect(decodeEd25519DidKey('did:key:' + multibaseEncodeZ(secp))).toBeNull();
  });

  it('right prefix but WRONG length (multikey != 34 bytes) => null', () => {
    const short = new Uint8Array([0xed, 0x01, ...new Array(30).fill(1)]); // 32B total
    expect(decodeEd25519DidKey('did:key:' + multibaseEncodeZ(short))).toBeNull();
    expect(decodeEd25519Multikey(short)).toBeNull();
  });
});

describe('normalizeToMultikey — length disambiguation', () => {
  it('accepts a KeyObject, raw32, and a multibase multikey to the SAME bytes', () => {
    const k = keyFromSeedByte(5);
    const fromKo = normalizeToMultikey(k.publicKey);
    const fromRaw = normalizeToMultikey(k.raw32);
    const fromStr = normalizeToMultikey(multibaseEncodeZ(ed25519Multikey(k.raw32)));
    const fromDid = normalizeToMultikey(k.didKey);
    expect(fromKo).not.toBeNull();
    expect(Array.from(fromKo as Uint8Array)).toEqual(Array.from(fromRaw as Uint8Array));
    expect(Array.from(fromStr as Uint8Array)).toEqual(Array.from(fromRaw as Uint8Array));
    expect(Array.from(fromDid as Uint8Array)).toEqual(Array.from(fromRaw as Uint8Array));
  });

  it('rejects a 33-byte raw blob (neither 32 nor 34) => null', () => {
    expect(normalizeToMultikey(new Uint8Array(33))).toBeNull();
  });

  it('rejects a 34-byte blob with a wrong codec => null', () => {
    expect(normalizeToMultikey(new Uint8Array([0xec, 0x01, ...new Array(32).fill(0)]))).toBeNull();
  });
});
