// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { describe, it, expect } from 'vitest';
import { detectEquivocation } from '../equivocation.js';
import { TransparencyLog, type LeafRecord, type Sth } from '../log.js';
import { keyFromSeedByte } from './helpers.js';

function regLeaf(i: number): LeafRecord {
  return { type: 'registration', carId: `car:r:v1:leaf${i}`, genesisHash: `${i}`.repeat(4) };
}

const signer = keyFromSeedByte(70);

function sthOf(log: TransparencyLog, logId = 'log-1'): Sth {
  return log.signSth(
    { sthVersion: 'v1', treeSize: log.size(), rootHash: log.rootHash(), logId },
    signer.privateKey,
    signer.publicKey,
  );
}

function logOf(n: number, mutateIndex?: number): TransparencyLog {
  const log = new TransparencyLog();
  for (let i = 0; i < n; i++) {
    log.append(i === mutateIndex ? regLeaf(900000 + i) : regLeaf(i));
  }
  return log;
}

describe('detectEquivocation — same-size divergent root', () => {
  it('two STHs same size, different root => equivocation + misbehavior certificate', () => {
    const a = sthOf(logOf(4));
    const b = sthOf(logOf(4, 1)); // size 4 but leaf 1 differs => different root
    expect(a.treeSize).toBe(b.treeSize);
    expect(a.rootHash).not.toBe(b.rootHash);
    const r = detectEquivocation(a, b);
    expect(r.equivocation).toBe(true);
    expect(r.kind).toBe('same_size_divergent_root');
    expect(r.misbehaviorCertificate).toEqual([a, b]);
  });

  it('two IDENTICAL same-size heads => NOT equivocation', () => {
    const a = sthOf(logOf(4));
    const b = sthOf(logOf(4));
    expect(a.rootHash).toBe(b.rootHash);
    const r = detectEquivocation(a, b);
    expect(r.equivocation).toBe(false);
    expect(r.reason).toBe('identical_heads');
  });
});

describe('detectEquivocation — non-extending (consistency failure)', () => {
  it('honest extension with a valid proof => NOT equivocation', () => {
    const oldLog = logOf(3);
    const newLog = logOf(8);
    const oldSth = sthOf(oldLog);
    const newSth = sthOf(newLog);
    const proof = newLog.consistencyProof(3, 8) as string[];
    const r = detectEquivocation(oldSth, newSth, proof);
    expect(r.equivocation).toBe(false);
    expect(r.reason).toBe('consistent_extension');
  });

  it('rewritten history + supplied (now-failing) proof => equivocation non_extending', () => {
    const newLog = logOf(8);
    const newSth = sthOf(newLog);
    const proof = newLog.consistencyProof(3, 8) as string[];
    // old tree claims a different leaf 1 => its root won't reconstruct.
    const forgedOld = sthOf(logOf(3, 1));
    const r = detectEquivocation(forgedOld, newSth, proof);
    expect(r.equivocation).toBe(true);
    expect(r.kind).toBe('non_extending');
    expect(r.misbehaviorCertificate).toEqual([forgedOld, newSth]);
  });

  it('ABSENT consistency proof for differing sizes => UNDETERMINED, never "consistent"', () => {
    const oldSth = sthOf(logOf(3));
    const newSth = sthOf(logOf(8));
    const r = detectEquivocation(oldSth, newSth);
    expect(r.equivocation).toBe(false);
    expect(r.reason).toBe('undetermined_no_consistency_proof');
  });
});

describe('detectEquivocation — domain + fail-closed', () => {
  it('two DIFFERENT logIds => not equivocation (two logs)', () => {
    const a = sthOf(logOf(4), 'log-A');
    const b = sthOf(logOf(4, 1), 'log-B');
    const r = detectEquivocation(a, b);
    expect(r.equivocation).toBe(false);
    expect(r.reason).toBe('different_logs');
  });

  it('malformed STH inputs => not equivocation, reasoned', () => {
    const a = sthOf(logOf(4));
    expect(detectEquivocation(null as unknown as Sth, a).equivocation).toBe(false);
    expect(detectEquivocation(a, undefined as unknown as Sth).equivocation).toBe(false);
  });
});
