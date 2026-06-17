// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { describe, it, expect } from 'vitest';
import {
  mint,
  verify,
  registryRootFp,
  type CarGenesis,
} from '../identity.js';
import { verifyControl, MIN_CHALLENGE_BYTES } from '../control.js';
import { ed25519Multikey } from '../didkey.js';
import { multibaseEncodeZ } from '../bytes.js';
import { keyFromSeedByte, signBytes } from './helpers.js';

const rootKey = keyFromSeedByte(1);
const ctrlA = keyFromSeedByte(2);
const ctrlB = keyFromSeedByte(3);

function rootMultibase() {
  return multibaseEncodeZ(ed25519Multikey(rootKey.raw32));
}

function sortedControllers(): string[] {
  return [ctrlA.didKey, ctrlB.didKey].sort();
}

function goodGenesis(): CarGenesis {
  return {
    idSpec: 'car/v1',
    specVersion: 'basis-spec@1.2.0+sha256:abc',
    category: 'AGENT',
    controller: sortedControllers(),
    registryRoot: rootMultibase(),
  };
}

describe('CAR id mint -> verify happy path', () => {
  it('mints a well-formed id and verifies it true', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    expect(id.startsWith('car:')).toBe(true);
    const seg = id.split(':');
    expect(seg.length).toBe(4);
    expect(seg[2]).toBe('v1');
    const r = verify(id, g, rootKey.publicKey);
    expect(r.valid).toBe(true);
  });

  it('mint is deterministic (same inputs => same id)', () => {
    const g = goodGenesis();
    expect(mint(g, rootKey.publicKey)).toBe(mint(g, rootKey.publicKey));
  });

  it('registryRootFp depends only on the root key and matches the id segment', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const fp = registryRootFp(rootKey.publicKey);
    expect(fp).not.toBeNull();
    expect(id.split(':')[1]).toBe(fp);
  });

  it('verify accepts the root supplied as a multibase multikey string', () => {
    const g = goodGenesis();
    const id = mint(g, rootMultibase());
    expect(verify(id, g, rootMultibase()).valid).toBe(true);
  });
});

describe('CAR id verify — fail-closed (every false is a real assertion)', () => {
  it('TAMPERED genesis (changed specVersion) => false', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const tampered = { ...g, specVersion: 'basis-spec@9.9.9+sha256:evil' };
    const r = verify(id, tampered, rootKey.publicKey);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('id_hash_mismatch');
  });

  it('tampered category => false', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    expect(verify(id, { ...g, category: 'MODEL' }, rootKey.publicKey).valid).toBe(false);
  });

  it('EXTRA genesis key => false (cannot smuggle a hash-irrelevant field)', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const withExtra = { ...g, sneaky: 'field' } as unknown;
    const r = verify(id, withExtra, rootKey.publicKey);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('genesis_extra_or_missing_keys');
  });

  it('MISSING genesis key => false', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const { specVersion, ...missing } = g;
    void specVersion;
    expect(verify(id, missing as unknown, rootKey.publicKey).valid).toBe(false);
  });

  it('UNSORTED controller array => false', () => {
    const sorted = sortedControllers();
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const unsorted = { ...g, controller: [sorted[1], sorted[0]] };
    const r = verify(id, unsorted, rootKey.publicKey);
    expect(r.valid).toBe(false);
  });

  it('DUPLICATE controller => false (strict-ascending requires uniqueness)', () => {
    const g = { ...goodGenesis(), controller: [ctrlA.didKey, ctrlA.didKey] };
    // mint itself rejects (constructor); model the verify path with a hand id.
    expect(() => mint(g, rootKey.publicKey)).toThrow();
    const r = verify('car:x:v1:y', g, rootKey.publicKey);
    expect(r.valid).toBe(false);
  });

  it('MIXED-SUITE genesis (a non-ed25519 controller) => false', () => {
    const x25519Did = 'did:key:' + multibaseEncodeZ(new Uint8Array([0xec, 0x01, ...new Array(32).fill(7)]));
    const g = { ...goodGenesis(), controller: [x25519Did] };
    const r = verify('car:x:v1:y', g, rootKey.publicKey);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('genesis_controller_not_ed25519_didkey');
  });

  it('WRONG root key => false (fp mismatch)', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const otherRoot = keyFromSeedByte(42);
    // genesis still declares the original root, so genesis_root_mismatch fires
    const r = verify(id, g, otherRoot.publicKey);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('genesis_root_mismatch');
  });

  it('genesis.registryRoot pointing at a DIFFERENT root than the id => false', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const otherRoot = keyFromSeedByte(43);
    const g2 = { ...g, registryRoot: multibaseEncodeZ(ed25519Multikey(otherRoot.raw32)) };
    // verify with the otherRoot key: fp now matches g2.registryRoot but NOT
    // the id's fp segment => id_fp_mismatch.
    const r = verify(id, g2, otherRoot.publicKey);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('id_fp_mismatch');
  });

  it('bad id structure (wrong scheme / version / segment count) => false', () => {
    const g = goodGenesis();
    expect(verify('notcar:fp:v1:hash', g, rootKey.publicKey).reason).toBe('id_bad_scheme');
    expect(verify('car:fp:v2:hash', g, rootKey.publicKey).reason).toBe('id_bad_version');
    expect(verify('car:fp:v1', g, rootKey.publicKey).reason).toBe('id_bad_segment_count');
    expect(verify('car:fp:v1:', g, rootKey.publicKey).reason).toBe('id_empty_segment');
  });

  it('TRUNCATED idHash multihash (sha-384 length mismatch) => false', () => {
    const g = goodGenesis();
    const id = mint(g, rootKey.publicKey);
    const seg = id.split(':');
    // chop two base58 chars off the idHash segment -> bad multihash/multibase
    const broken = `${seg[0]}:${seg[1]}:${seg[2]}:${(seg[3] as string).slice(0, -3)}`;
    const r = verify(broken, g, rootKey.publicKey);
    expect(r.valid).toBe(false);
    expect(['id_hash_bad_multibase', 'id_hash_bad_multihash', 'id_hash_mismatch']).toContain(r.reason);
  });

  it('NON-CANONICALIZABLE genesis (NaN smuggled past types) => false, never throws', () => {
    const g = { ...goodGenesis(), specVersion: NaN as unknown as string };
    const r = verify('car:x:v1:y', g, rootKey.publicKey);
    expect(r.valid).toBe(false); // caught at type check (specVersion not string)
  });

  it('a non-object genesis (null / array / string) => false, never throws', () => {
    const id = mint(goodGenesis(), rootKey.publicKey);
    expect(verify(id, null, rootKey.publicKey).valid).toBe(false);
    expect(verify(id, [], rootKey.publicKey).valid).toBe(false);
    expect(verify(id, 'hi', rootKey.publicKey).valid).toBe(false);
  });
});

describe('mint — constructor rejects bad caller input (THROWS)', () => {
  it('throws when genesis.registryRoot does not match the supplied root key', () => {
    const g = goodGenesis();
    const otherRoot = keyFromSeedByte(99);
    expect(() => mint(g, otherRoot.publicKey)).toThrow();
  });
  it('throws on a structurally bad genesis', () => {
    expect(() => mint({ ...goodGenesis(), idSpec: 'car/v2' as 'car/v1' }, rootKey.publicKey)).toThrow();
  });
});

describe('verifyControl — holder-of-key proof, fail-closed', () => {
  const challenge = new Uint8Array(MIN_CHALLENGE_BYTES).fill(0x5a);

  it('verifies a real signature over a sufficiently long challenge', () => {
    const sig = signBytes(ctrlA.privateKey, challenge);
    expect(verifyControl(ctrlA.didKey, challenge, sig)).toBe(true);
  });

  it('rejects a signature by the WRONG key', () => {
    const sig = signBytes(ctrlB.privateKey, challenge);
    expect(verifyControl(ctrlA.didKey, challenge, sig)).toBe(false);
  });

  it('rejects a too-short challenge (anti-replay/empty-challenge contract)', () => {
    const short = new Uint8Array(MIN_CHALLENGE_BYTES - 1).fill(1);
    const sig = signBytes(ctrlA.privateKey, short);
    expect(verifyControl(ctrlA.didKey, short, sig)).toBe(false);
  });

  it('rejects a malformed did:key BEFORE crypto.verify => false', () => {
    const sig = signBytes(ctrlA.privateKey, challenge);
    expect(verifyControl('did:key:fNOTZ', challenge, sig)).toBe(false);
  });

  it('rejects a wrong-length signature => false', () => {
    expect(verifyControl(ctrlA.didKey, challenge, new Uint8Array(10))).toBe(false);
  });
});
