// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0007 tests.
 *
 * The two most important assertions here are the ones that pin known Merkle
 * defects, because both produce distinct leaf sequences sharing a root — which
 * would let a compactor swap a range's contents while keeping its attested
 * root, defeating the entire point of the tree:
 *
 *   - domain separation (second-preimage)
 *   - odd-node PROMOTION rather than duplication (CVE-2012-2459)
 */

import { describe, it, expect } from 'vitest';
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { canonicalEventBytes } from '@vorionsys/basis-spec';

import {
  leafHash,
  nodeHash,
  merkleRoot,
  buildLevels,
  MerkleError,
} from '../tree.js';
import { auditPath, verifyPath, foldPath } from '../proof.js';
import {
  buildCompaction,
  buildDisclosure,
  verifyDisclosure,
  verifyAgainstRange,
} from '../disclosure.js';
import type { ChainEvent } from '../types.js';

// --- Fixtures ---------------------------------------------------------------

const KEYPAIR = generateKeyPairSync('ed25519');
const SIGNER = 'did:vorion:runtime#ed25519';
const PUBKEY = KEYPAIR.publicKey
  .export({ format: 'der', type: 'spki' })
  .subarray(-32)
  .toString('hex');
const KEYRING = { [SIGNER]: PUBKEY };

const hashable = (e: ChainEvent) => ({
  previousHash: e.previousHash,
  eventType: e.eventType,
  agentId: e.agentId,
  occurredAt: e.occurredAt,
  payload: e.payload,
});

/**
 * Build a contiguous, correctly-linked chain of n events.
 *
 * NOTE `agentId`, not just `prefix`: RFC-0002 EXCLUDES `eventId` from the
 * canonical hash input, so two events differing only in eventId produce an
 * identical leaf. Varying the prefix alone does not make a different range.
 */
function makeChain(n: number, prefix = 'e', agentId = 'agent:a1'): ChainEvent[] {
  const out: ChainEvent[] = [];
  let previousHash: string | null = null;
  for (let i = 0; i < n; i++) {
    const draft = {
      previousHash,
      eventType: 'decision_made',
      agentId,
      occurredAt: `2026-08-02T10:00:${String(i).padStart(2, '0')}.000Z`,
      payload: { type: 'decision_made', decision: i % 3 === 0 ? 'deny' : 'allow', seq: i },
    };
    const eventHash = createHash('sha256').update(canonicalEventBytes(draft)).digest('hex');
    out.push({ ...draft, eventId: `${prefix}${i}`, recordedAt: draft.occurredAt, eventHash });
    previousHash = eventHash;
  }
  return out;
}

/** Seal + sign a chain_compacted event around a payload. */
function sealCompaction(payload: unknown, previousHash: string | null): ChainEvent {
  const draft = {
    previousHash,
    eventType: 'chain_compacted',
    agentId: 'agent:a1',
    occurredAt: '2026-08-02T11:00:00.000Z',
    payload,
  };
  const bytes = canonicalEventBytes(draft);
  return {
    ...draft,
    eventId: 'compaction-1',
    recordedAt: draft.occurredAt,
    eventHash: createHash('sha256').update(bytes).digest('hex'),
    signedBy: SIGNER,
    signature: nodeSign(null, bytes, KEYPAIR.privateKey).toString('base64'),
  };
}

// ---------------------------------------------------------------------------

describe('merkle: known defects that must not be present', () => {
  it('CVE-2012-2459 — [a,b,c] and [a,b,c,c] must NOT share a root', () => {
    // Duplicating an odd last node instead of promoting it makes these two
    // DIFFERENT leaf sequences produce the SAME root, which lets a compactor
    // swap a range's contents while keeping its attested root. Promotion is
    // what prevents it.
    const [a, b, c] = ['aa', 'bb', 'cc'].map((s) =>
      createHash('sha256').update(s).digest('hex'),
    ) as [string, string, string];

    const three = merkleRoot([a, b, c]);
    const four = merkleRoot([a, b, c, c]);

    expect(three).not.toBe(four);

    // And spell out what the buggy construction would have produced, so a
    // future refactor that reintroduces duplication fails loudly here.
    const duplicated = nodeHash(nodeHash(a, b), nodeHash(c, c));
    expect(three).not.toBe(duplicated);
    expect(four).toBe(duplicated);
  });

  it('domain separation — a leaf hash is never an internal-node hash', () => {
    // Without the 0x00/0x01 prefixes an attacker can present an internal node
    // as a leaf. The prefixes put them in disjoint spaces.
    const ev = makeChain(1)[0]!;
    const leaf = leafHash(hashable(ev));
    const node = nodeHash(leaf, leaf);
    expect(leaf).not.toBe(node);

    // A leaf is sha256(0x00 || bytes), not sha256(bytes).
    const undomained = createHash('sha256')
      .update(canonicalEventBytes(hashable(ev)))
      .digest('hex');
    expect(leaf).not.toBe(undomained);
  });

  it('a leaf covers the canonical bytes, which EXCLUDE eventId', () => {
    // Subtle and worth pinning: RFC-0002 omits eventId from the hash input
    // because it is implementation-assigned. Two events differing only in
    // eventId therefore produce the SAME leaf — and the same eventHash. Within
    // a real chain this cannot collide, because previousHash differs. But a
    // test fixture that varies only the id is NOT constructing a different
    // range, which is exactly the mistake this assertion documents.
    const a = makeChain(1, 'a')[0]!;
    const b = makeChain(1, 'b')[0]!;
    expect(a.eventId).not.toBe(b.eventId);
    expect(leafHash(hashable(a))).toBe(leafHash(hashable(b)));

    // Vary anything the hash DOES cover and the leaves diverge.
    const c = makeChain(1, 'a', 'agent:different')[0]!;
    expect(leafHash(hashable(a))).not.toBe(leafHash(hashable(c)));
  });

  it('promotes rather than pads — an odd level keeps its last node verbatim', () => {
    const leaves = ['a', 'b', 'c'].map((s) => createHash('sha256').update(s).digest('hex'));
    const levels = buildLevels(leaves);
    expect(levels[0]).toHaveLength(3);
    expect(levels[1]).toHaveLength(2);
    expect(levels[1]![1]).toBe(leaves[2]); // promoted unchanged
  });
});

describe('merkle: audit paths', () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33]) {
    it(`every leaf proves membership in a ${n}-leaf tree`, () => {
      const chain = makeChain(n);
      const leaves = chain.map((e) => leafHash(hashable(e)));
      const root = merkleRoot(leaves);
      for (let i = 0; i < n; i++) {
        expect(verifyPath(leaves[i]!, auditPath(leaves, i), root)).toBe(true);
      }
    });
  }

  it('a tampered leaf does not fold to the root', () => {
    const chain = makeChain(8);
    const leaves = chain.map((e) => leafHash(hashable(e)));
    const root = merkleRoot(leaves);
    const tampered = { ...chain[3]!, payload: { type: 'decision_made', decision: 'allow', seq: 3 } };
    expect(verifyPath(leafHash(hashable(tampered)), auditPath(leaves, 3), root)).toBe(false);
  });

  it("a leaf does not verify against another leaf's path", () => {
    const chain = makeChain(8);
    const leaves = chain.map((e) => leafHash(hashable(e)));
    const root = merkleRoot(leaves);
    expect(verifyPath(leaves[2]!, auditPath(leaves, 5), root)).toBe(false);
  });

  it('a malformed path is a failed proof, not a thrown exception', () => {
    const leaves = makeChain(4).map((e) => leafHash(hashable(e)));
    expect(verifyPath(leaves[0]!, [{ hash: 'not-hex', side: 'right' }], merkleRoot(leaves))).toBe(false);
  });

  it('path length is logarithmic, not linear', () => {
    const leaves = makeChain(64).map((e) => leafHash(hashable(e)));
    expect(auditPath(leaves, 0)).toHaveLength(6); // log2(64)
  });

  it('folding an empty path returns the leaf itself (single-leaf tree)', () => {
    const leaves = makeChain(1).map((e) => leafHash(hashable(e)));
    expect(auditPath(leaves, 0)).toHaveLength(0);
    expect(foldPath(leaves[0]!, [])).toBe(leaves[0]);
    expect(merkleRoot(leaves)).toBe(leaves[0]);
  });
});

describe('merkle: fail-closed construction', () => {
  it('refuses a zero-leaf tree', () => {
    expect(() => merkleRoot([])).toThrow(MerkleError);
    expect(() => merkleRoot([])).toThrow(/zero leaves/);
  });

  it('refuses to compact a zero-length range', () => {
    expect(() =>
      buildCompaction({ compactionId: 'c', range: [], compactedAt: 'now' }),
    ).toThrow(/zero-length range/);
  });

  it('refuses a non-contiguous range', () => {
    // Compacting an arbitrary selection would attest to a range that never
    // existed in the chain.
    const chain = makeChain(5);
    const gappy = [chain[0]!, chain[2]!, chain[3]!];
    expect(() =>
      buildCompaction({ compactionId: 'c', range: gappy, compactedAt: 'now' }),
    ).toThrow(/not contiguous/);
  });

  it('rejects a salts array that does not align with the range', () => {
    expect(() =>
      buildCompaction({
        compactionId: 'c',
        range: makeChain(3),
        salts: ['aa'],
        compactedAt: 'now',
      }),
    ).toThrow(/does not match range length/);
  });
});

describe('disclosure: end to end', () => {
  const chain = makeChain(40);
  const payload = buildCompaction({
    compactionId: 'c-1',
    range: chain,
    compactedAt: '2026-08-02T11:00:00.000Z',
  });
  const compaction = sealCompaction(payload, chain[chain.length - 1]!.eventHash);

  it('discloses 3 of 40 and verifies at level "attested"', () => {
    const pkg = buildDisclosure({
      compaction,
      range: chain,
      disclose: ['e5', 'e17', 'e39'],
      keys: KEYRING,
    });

    const r = verifyDisclosure(pkg);
    expect(r.issues).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.level).toBe('attested');
    expect(r.disclosedCount).toBe(3);
    // The denominator is reported so a recipient sees how much they were NOT
    // shown. 3-of-4 and 3-of-40 are very different artefacts.
    expect(r.leafCount).toBe(40);
  });

  it('the package is self-contained — verification needs nothing else', () => {
    const pkg = buildDisclosure({ compaction, range: chain, disclose: ['e0'], keys: KEYRING });
    const roundTripped = JSON.parse(JSON.stringify(pkg));
    expect(verifyDisclosure(roundTripped).valid).toBe(true);
  });

  it('records the range anchors so a holder can re-attach the segment', () => {
    expect(payload.rangePreviousHash).toBe(chain[0]!.previousHash);
    expect(payload.rangeEventHash).toBe(chain[chain.length - 1]!.eventHash);
    expect(payload.firstEventId).toBe('e0');
    expect(payload.lastEventId).toBe('e39');
  });

  it('refuses to disclose an event not in the range', () => {
    expect(() =>
      buildDisclosure({ compaction, range: chain, disclose: ['ghost'], keys: KEYRING }),
    ).toThrow(/not present in the range/);
  });
});

describe('disclosure: fail-closed verification', () => {
  const chain = makeChain(8);
  const payload = buildCompaction({
    compactionId: 'c-1',
    range: chain,
    compactedAt: '2026-08-02T11:00:00.000Z',
  });
  const compaction = sealCompaction(payload, chain[7]!.eventHash);
  const good = buildDisclosure({ compaction, range: chain, disclose: ['e3'], keys: KEYRING });

  it('an UNSIGNED compaction attests nothing', () => {
    const unsigned = { ...compaction };
    delete (unsigned as Record<string, unknown>).signature;
    const r = verifyDisclosure({ ...good, compaction: unsigned });
    expect(r.valid).toBe(false);
    expect(r.level).toBe('none');
    expect(r.issues.map((i) => i.code)).toContain('compaction-unsigned');
  });

  it('a MISSING key is never a silent pass', () => {
    const r = verifyDisclosure({ ...good, keys: {} });
    expect(r.valid).toBe(false);
    expect(r.level).toBe('none');
    expect(r.issues.map((i) => i.code)).toContain('compaction-key-missing');
  });

  it('a tampered compaction payload fails on its own hash', () => {
    const tampered = {
      ...compaction,
      payload: { ...payload, leafCount: 3 },
    };
    const r = verifyDisclosure({ ...good, compaction: tampered });
    expect(r.valid).toBe(false);
    expect(r.issues.map((i) => i.code)).toContain('compaction-hash');
  });

  it('a leaf swapped for one outside the range fails membership', () => {
    const other = makeChain(3, 'x', 'agent:elsewhere');
    const bad = {
      ...good,
      disclosed: [{ ...good.disclosed[0]!, event: other[1]! }],
    };
    const r = verifyDisclosure(bad);
    expect(r.valid).toBe(false);
    expect(r.issues.map((i) => i.code)).toContain('membership');
  });

  it('a leafIndex outside the declared range is rejected', () => {
    const bad = { ...good, disclosed: [{ ...good.disclosed[0]!, leafIndex: 99 }] };
    const r = verifyDisclosure(bad);
    expect(r.valid).toBe(false);
    expect(r.issues.map((i) => i.code)).toContain('leaf-index');
  });
});

describe('disclosure: cross-check against a held range', () => {
  const chain = makeChain(8);
  const payload = buildCompaction({
    compactionId: 'c-1',
    range: chain,
    compactedAt: '2026-08-02T11:00:00.000Z',
  });
  const compaction = sealCompaction(payload, chain[7]!.eventHash);

  it('a holder of the events reaches level "full"', () => {
    const r = verifyAgainstRange(compaction, chain);
    expect(r.valid).toBe(true);
    expect(r.level).toBe('full');
    expect(r.merkleRoot).toBe(payload.merkleRoot);
  });

  it('catches a compaction that lies about what it summarizes', () => {
    // Every event is individually intact; the ROOT is wrong for this range.
    // That is the swap this check exists to catch.
    const otherRange = makeChain(8, 'y', 'agent:someone-else');
    const r = verifyAgainstRange(compaction, otherRange);
    expect(r.valid).toBe(false);
    expect(r.level).toBe('none');
    expect(r.issues.map((i) => i.code)).toContain('root-mismatch');
  });

  it('catches a count that disagrees with the range', () => {
    const r = verifyAgainstRange(compaction, chain.slice(0, 5));
    expect(r.valid).toBe(false);
    expect(r.issues.map((i) => i.code)).toContain('count-mismatch');
  });
});

describe('disclosure: salting', () => {
  const chain = makeChain(6);
  const salts = chain.map((_, i) => createHash('sha256').update(`s${i}`).digest('hex'));
  const payload = buildCompaction({
    compactionId: 'c-salted',
    range: chain,
    salts,
    compactedAt: '2026-08-02T11:00:00.000Z',
  });
  const compaction = sealCompaction(payload, chain[5]!.eventHash);

  it('marks the compaction salted and still verifies', () => {
    expect(payload.salted).toBe(true);
    const pkg = buildDisclosure({ compaction, range: chain, salts, disclose: ['e2'], keys: KEYRING });
    const r = verifyDisclosure(pkg);
    expect(r.issues).toEqual([]);
    expect(r.valid).toBe(true);
  });

  it('salting changes the root — identical events are no longer linkable', () => {
    const unsalted = buildCompaction({
      compactionId: 'c-plain',
      range: chain,
      compactedAt: '2026-08-02T11:00:00.000Z',
    });
    expect(payload.merkleRoot).not.toBe(unsalted.merkleRoot);
  });

  it('a disclosed leaf missing its salt can never be proved, and says so', () => {
    const pkg = buildDisclosure({ compaction, range: chain, salts, disclose: ['e2'], keys: KEYRING });
    const stripped = {
      ...pkg,
      disclosed: pkg.disclosed.map((d) => {
        const copy = { ...d };
        delete (copy as Record<string, unknown>).salt;
        return copy;
      }),
    };
    const r = verifyDisclosure(stripped);
    expect(r.valid).toBe(false);
    expect(r.issues.map((i) => i.code)).toContain('salt-missing');
  });
});
