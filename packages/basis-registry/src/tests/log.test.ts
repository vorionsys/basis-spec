// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  TransparencyLog,
  hashLeaf,
  hashLeafBytes,
  hashInterior,
  emptyRootBytes,
  leafBytes,
  type LeafRecord,
  type Sth,
} from '../log.js';
import {
  verifyInclusion,
  verifyConsistency,
  verifySthSignature,
  verifySthWitness,
} from '../verify.js';
import { toHex, fromHexExact } from '../bytes.js';
import { keyFromSeedByte, signBytes } from './helpers.js';
import { jcsBytes } from '../jcs.js';
import { ed25519Multikey } from '../didkey.js';
import { multibaseEncodeZ } from '../bytes.js';

function regLeaf(i: number): LeafRecord {
  return { type: 'registration', carId: `car:r:v1:leaf${i}`, genesisHash: `${i}`.repeat(4) };
}

function buildLog(n: number): { log: TransparencyLog; leaves: LeafRecord[] } {
  const log = new TransparencyLog();
  const leaves: LeafRecord[] = [];
  for (let i = 0; i < n; i++) {
    const leaf = regLeaf(i);
    leaves.push(leaf);
    log.append(leaf);
  }
  return { log, leaves };
}

function makeSth(log: TransparencyLog, logId = 'log-1'): Sth {
  const signer = keyFromSeedByte(70);
  return log.signSth(
    { sthVersion: 'v1', treeSize: log.size(), rootHash: log.rootHash(), logId },
    signer.privateKey,
    signer.publicKey,
  );
}

/** Non-null inclusion-path getter for tests (proof is known to exist). */
function pathOf(log: TransparencyLog, index: number): string[] {
  const proof = log.inclusionProof(index);
  if (proof === null) throw new Error(`no inclusion proof for index ${index}`);
  return [...proof.auditPath];
}

describe('RFC-6962 domain separation (second-preimage resistance)', () => {
  it('empty tree root = sha-256 of empty string', () => {
    const expected = createHash('sha256').update(new Uint8Array(0)).digest('hex');
    expect(toHex(emptyRootBytes())).toBe(expected);
    expect(expected).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('leaf hash uses 0x00 prefix, interior uses 0x01 prefix', () => {
    const data = new Uint8Array([9, 9, 9]);
    const leafH = hashLeafBytes(data);
    const manualLeaf = createHash('sha256').update(new Uint8Array([0x00, 9, 9, 9])).digest('hex');
    expect(toHex(leafH)).toBe(manualLeaf);

    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    const interior = hashInterior(a, b);
    const manualInterior = createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(a), Buffer.from(b)]))
      .digest('hex');
    expect(toHex(interior)).toBe(manualInterior);
  });

  it('a forged "leaf" whose bytes equal 0x01||a||b does NOT collide with interior(a,b)', () => {
    const a = new Uint8Array(32).fill(0xaa);
    const b = new Uint8Array(32).fill(0xbb);
    const interior = hashInterior(a, b); // H(0x01 || a || b)
    // Attacker presents the 64-byte concat a||b as a LEAF preimage.
    const forgedLeaf = hashLeafBytes(Buffer.concat([Buffer.from(a), Buffer.from(b)])); // H(0x00 || a || b)
    expect(toHex(forgedLeaf)).not.toBe(toHex(interior));
  });
});

describe('Merkle inclusion — every leaf verifies, wrong inputs fail', () => {
  for (const n of [1, 2, 3, 5, 8, 13]) {
    it(`N=${n}: inclusion proof verifies for every leaf`, () => {
      const { log, leaves } = buildLog(n);
      const sth = makeSth(log);
      for (let i = 0; i < n; i++) {
        const r = verifyInclusion({
          leafHash: hashLeaf(leaves[i] as LeafRecord),
          leafIndex: i,
          treeSize: n,
          auditPath: pathOf(log, i),
          sth,
        });
        expect(r.valid).toBe(true);
      }
    });
  }

  it('WRONG leaf hash => false', () => {
    const { log } = buildLog(5);
    const sth = makeSth(log);
    const r = verifyInclusion({
      leafHash: hashLeaf(regLeaf(999)),
      leafIndex: 2,
      treeSize: 5,
      auditPath: pathOf(log, 2),
      sth,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('root_mismatch');
  });

  it('WRONG index => false', () => {
    const { log, leaves } = buildLog(5);
    const sth = makeSth(log);
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[2] as LeafRecord),
      leafIndex: 3, // wrong
      treeSize: 5,
      auditPath: pathOf(log, 2),
      sth,
    });
    expect(r.valid).toBe(false);
  });

  it('TAMPERED audit path (one byte flipped) => false', () => {
    const { log, leaves } = buildLog(8);
    const sth = makeSth(log);
    const tampered = pathOf(log, 3);
    const first = tampered[0] as string;
    const bytes = fromHexExact(first, 32) as Uint8Array;
    bytes[0] = (bytes[0] as number) ^ 0xff;
    tampered[0] = toHex(bytes);
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[3] as LeafRecord),
      leafIndex: 3,
      treeSize: 8,
      auditPath: tampered,
      sth,
    });
    expect(r.valid).toBe(false);
  });

  it('TOO-SHORT audit path (one level dropped) => false', () => {
    const { log, leaves } = buildLog(8);
    const sth = makeSth(log);
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[3] as LeafRecord),
      leafIndex: 3,
      treeSize: 8,
      auditPath: pathOf(log, 3).slice(0, -1),
      sth,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('auditPath_wrong_length');
  });

  it('OVER-LONG audit path (extra level) => false', () => {
    const { log, leaves } = buildLog(8);
    const sth = makeSth(log);
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[3] as LeafRecord),
      leafIndex: 3,
      treeSize: 8,
      auditPath: [...pathOf(log, 3), '00'.repeat(32)],
      sth,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('auditPath_wrong_length');
  });

  it('non-32-byte hash in the path => false', () => {
    const { log, leaves } = buildLog(4);
    const sth = makeSth(log);
    const bad = pathOf(log, 1);
    bad[0] = 'abcd'; // 2 bytes
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[1] as LeafRecord),
      leafIndex: 1,
      treeSize: 4,
      auditPath: bad,
      sth,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('auditPath_malformed_hash');
  });
});

describe('Merkle inclusion — empty + single-leaf edge cases', () => {
  it('empty tree => no membership possible (treeSize 0 => false)', () => {
    const log = new TransparencyLog();
    const sth = makeSth(log); // treeSize 0, rootHash = empty root
    const r = verifyInclusion({
      leafHash: 'aa'.repeat(32),
      leafIndex: 0,
      treeSize: 0,
      auditPath: [],
      sth,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('empty_or_bad_treeSize');
  });

  it('inclusionProof on an empty tree => null', () => {
    expect(new TransparencyLog().inclusionProof(0)).toBeNull();
  });

  it('single-leaf tree: empty audit path, root = leaf hash', () => {
    const { log, leaves } = buildLog(1);
    const sth = makeSth(log);
    expect(sth.rootHash).toBe(hashLeaf(leaves[0] as LeafRecord));
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[0] as LeafRecord),
      leafIndex: 0,
      treeSize: 1,
      auditPath: [],
      sth,
    });
    expect(r.valid).toBe(true);
  });

  it('index >= treeSize => false', () => {
    const { log, leaves } = buildLog(3);
    const sth = makeSth(log);
    const r = verifyInclusion({
      leafHash: hashLeaf(leaves[0] as LeafRecord),
      leafIndex: 3,
      treeSize: 3,
      auditPath: [],
      sth,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('index_out_of_range');
  });
});

describe('Merkle consistency — append-only between m < n', () => {
  for (const [m, n] of [[1, 2], [1, 8], [3, 8], [5, 13], [6, 7], [4, 8], [7, 8]] as const) {
    it(`consistency (m=${m}, n=${n}) verifies for an honest extension`, () => {
      const { log: full } = buildLog(n);
      // old STH from a separate log built to size m with the SAME leaves.
      const oldLog = new TransparencyLog();
      for (let i = 0; i < m; i++) oldLog.append(regLeaf(i));
      const oldSth = makeSth(oldLog);
      const newSth = makeSth(full);
      const proof = full.consistencyProof(m, n) as string[];
      expect(proof).not.toBeNull();
      const r = verifyConsistency(oldSth, newSth, proof);
      expect(r.valid).toBe(true);
    });
  }

  it('FORGED/REWRITTEN history (old leaf changed) => consistency FALSE', () => {
    const m = 3;
    const n = 8;
    const { log: full } = buildLog(n);
    const newSth = makeSth(full);
    const proof = full.consistencyProof(m, n) as string[];

    // The "old" tree the attacker claims had a DIFFERENT leaf 1 — its root does
    // not match what the proof reconstructs from the (honest) new tree.
    const forgedOld = new TransparencyLog();
    forgedOld.append(regLeaf(0));
    forgedOld.append(regLeaf(424242)); // rewritten history
    forgedOld.append(regLeaf(2));
    const forgedOldSth = makeSth(forgedOld);
    const r = verifyConsistency(forgedOldSth, newSth, proof);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('old_root_mismatch');
  });

  it('proof crafted to satisfy only the NEW root (old root mismatch) => false', () => {
    const m = 5;
    const n = 13;
    const { log: full } = buildLog(n);
    const newSth = makeSth(full);
    const proof = full.consistencyProof(m, n) as string[];
    // Tamper the OLD STH root only; new root still reconstructs, old must fail.
    const oldLog = new TransparencyLog();
    for (let i = 0; i < m; i++) oldLog.append(regLeaf(i));
    const realOld = makeSth(oldLog);
    const fakeOld: Sth = { ...realOld, rootHash: 'cc'.repeat(32) };
    const r = verifyConsistency(fakeOld, newSth, proof);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('old_root_mismatch');
  });

  it('m >= n => false (m===n and m>n)', () => {
    const { log } = buildLog(5);
    const sth = makeSth(log);
    expect(verifyConsistency(sth, sth, []).reason).toBe('m_ge_n');
    const { log: log7 } = buildLog(7);
    const sth7 = makeSth(log7);
    expect(verifyConsistency(sth7, sth, []).reason).toBe('m_ge_n');
  });

  it('m === 0 => false (no first tree to extend)', () => {
    const empty = makeSth(new TransparencyLog());
    const { log } = buildLog(4);
    const sth4 = makeSth(log);
    const r = verifyConsistency(empty, sth4, []);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('m_nonpositive');
  });

  it('malformed proof hash => false', () => {
    const oldLog = new TransparencyLog();
    for (let i = 0; i < 3; i++) oldLog.append(regLeaf(i));
    const { log } = buildLog(8);
    const r = verifyConsistency(makeSth(oldLog), makeSth(log), ['xyz']);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('proof_malformed_hash');
  });

  it('consistencyProof out of range (m<=0, m>=n, n>size) => null', () => {
    const { log } = buildLog(5);
    expect(log.consistencyProof(0, 3)).toBeNull();
    expect(log.consistencyProof(3, 3)).toBeNull();
    expect(log.consistencyProof(3, 9)).toBeNull();
  });
});

describe('STH signature + witness — fail-closed', () => {
  it('verifies a real STH signature with the signer key', () => {
    const signer = keyFromSeedByte(70);
    const { log } = buildLog(4);
    const sth = makeSth(log);
    expect(verifySthSignature(sth, signer.publicKey)).toBe(true);
  });

  it('signature verified by the WRONG key => false', () => {
    const { log } = buildLog(4);
    const sth = makeSth(log);
    expect(verifySthSignature(sth, keyFromSeedByte(71).publicKey)).toBe(false);
  });

  it('EMPTY signature => false (not "valid by omission")', () => {
    const signer = keyFromSeedByte(70);
    const { log } = buildLog(4);
    const sth = { ...makeSth(log), signature: '' };
    expect(verifySthSignature(sth, signer.publicKey)).toBe(false);
  });

  it('TAMPERED body (rootHash changed) => signature fails the recompute', () => {
    const signer = keyFromSeedByte(70);
    const { log } = buildLog(4);
    const sth = { ...makeSth(log), rootHash: 'dd'.repeat(32) };
    expect(verifySthSignature(sth, signer.publicKey)).toBe(false);
  });

  it('signerKey swapped to attacker key but body unchanged => false', () => {
    const { log } = buildLog(4);
    const real = makeSth(log);
    const attacker = keyFromSeedByte(80);
    const swapped: Sth = {
      ...real,
      signerKey: multibaseEncodeZ(ed25519Multikey(attacker.raw32)),
    };
    // verifying against the attacker key fails (sig was by the real signer),
    // and verifying against the real signer also still works only for the real
    // body — the point: the swapped signerKey cannot make an attacker pass.
    expect(verifySthSignature(swapped, attacker.publicKey)).toBe(false);
  });

  it('holds + verifies ONE supplied witness cosignature', () => {
    const signer = keyFromSeedByte(70);
    const witness = keyFromSeedByte(90);
    const { log } = buildLog(4);
    const base = makeSth(log);
    // witness signs the SAME canonical sthBody
    const body = {
      sthVersion: base.sthVersion,
      treeSize: base.treeSize,
      rootHash: base.rootHash,
      logId: base.logId,
    };
    const wsig = signBytes(witness.privateKey, jcsBytes(body));
    const withWitness: Sth = {
      ...base,
      witnessCosignatures: [
        {
          witnessKey: multibaseEncodeZ(ed25519Multikey(witness.raw32)),
          signature: Buffer.from(wsig).toString('base64'),
        },
      ],
    };
    expect(verifySthSignature(withWitness, signer.publicKey)).toBe(true);
    expect(verifySthWitness(withWitness, witness.publicKey)).toBe(true);
    // absent witness => false (lib never fabricates one)
    expect(verifySthWitness(base, witness.publicKey)).toBe(false);
    // a witness key the RP did not get a sig for => false
    expect(verifySthWitness(withWitness, keyFromSeedByte(91).publicKey)).toBe(false);
  });
});
