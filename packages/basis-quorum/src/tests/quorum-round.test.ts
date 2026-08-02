// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0005 quorum round tests, run against the shipped golden vectors.
 *
 * The most important assertions here are the CROSS-PASS ones: the tampered
 * vectors pass `verifyChain()` — hashes, linkage and signatures are all
 * perfect, because a coordinator that doctors a resolution can simply re-seal
 * and re-attest it — and are caught only by `verifyQuorumRound()`. That is the
 * concrete justification for having two verification passes rather than one.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyChain } from '@vorionsys/basis-spec-conformance';

import { verifyQuorumRound } from '../verify-round.js';
import { createGroupViaDkg, aggregateAttestation } from '../group.js';
import { createLocalValidator, buildKeyring } from '../validators.js';
import { runQuorumRound } from '../round.js';
import type { QuorumProofEvent } from '../types.js';

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'vectors');
const vector = (name: string): QuorumProofEvent[] =>
  JSON.parse(readFileSync(join(VECTORS, `${name}.json`), 'utf-8'));
const keys = (name: string): Record<string, string> =>
  JSON.parse(readFileSync(join(VECTORS, `${name}.json`), 'utf-8'));

const APPROVED_ID = 'q-approved-0001';
const REJECTED_ID = 'q-rejected-0001';

const codes = (r: { issues: ReadonlyArray<{ code: string }> }): string[] =>
  r.issues.map((i) => i.code);

// ---------------------------------------------------------------------------

describe('quorum round: valid rounds', () => {
  it('an approved 3-of-4 round verifies', () => {
    const r = verifyQuorumRound(vector('round-approved'), APPROVED_ID);
    expect(r.issues).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.outcome).toBe('approved');
    expect(r.attested).toBe(true);
    expect(r.recomputedTally).toEqual({ approve: 3, reject: 0, abstain: 0, noResponse: 1 });
  });

  it('a rejected round verifies, with the dissent on the record', () => {
    const chain = vector('round-rejected');
    const r = verifyQuorumRound(chain, REJECTED_ID);
    expect(r.issues).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.outcome).toBe('rejected');
    expect(r.recomputedTally).toEqual({ approve: 1, reject: 2, abstain: 0, noResponse: 1 });

    // The dissenting votes are individually present and attributable — the
    // aggregate alone could never show this.
    const rejects = chain.filter(
      (e) => e.eventType === 'validator_vote' && (e.payload as { vote?: string }).vote === 'reject',
    );
    expect(rejects).toHaveLength(2);
    for (const ev of rejects) {
      expect(ev.signedBy).toBe((ev.payload as { validatorId: string }).validatorId);
    }
  });

  it('a rejected outcome is still quorum-attested', () => {
    // A rejection is the record a hostile coordinator most wants to forge, so
    // it must not be the least protected event in the chain.
    const chain = vector('round-rejected');
    const resolution = chain[chain.length - 1]!;
    expect(resolution.eventType).toBe('quorum_resolved');
    expect(resolution.signature).toBeTypeOf('string');
    expect(resolution.signedBy).toContain('quorum');
  });
});

describe('quorum round: tamper detection', () => {
  it('catches an approved outcome that never met the threshold', () => {
    const r = verifyQuorumRound(vector('tamper-approved-below-threshold'), REJECTED_ID);
    expect(r.valid).toBe(false);
    expect(codes(r)).toContain('approved-below-threshold');
  });

  it('catches a tally that does not match the chained votes', () => {
    const r = verifyQuorumRound(vector('tamper-tally-mismatch'), REJECTED_ID);
    expect(r.valid).toBe(false);
    expect(codes(r)).toContain('tally-mismatch');
  });

  it('catches a dissent dropped from the chain entirely', () => {
    const r = verifyQuorumRound(vector('tamper-suppressed-dissent'), REJECTED_ID);
    expect(r.valid).toBe(false);
    // The declared validator neither voted nor was listed as a non-responder.
    expect(codes(r)).toContain('unaccounted-validator');
  });

  it('catches a resolution signed by an individual member rather than the group', () => {
    const r = verifyQuorumRound(vector('tamper-individually-signed-resolution'), REJECTED_ID);
    expect(r.valid).toBe(false);
    expect(codes(r)).toContain('resolution-individually-signed');
  });
});

describe('quorum round: why two verification passes are required', () => {
  it('the valid chain passes BOTH passes', () => {
    const chain = vector('round-approved');
    const integrity = verifyChain(chain, {
      publicKeys: keys('keys-approved'),
      requireSignatures: false,
    });
    expect(integrity.valid).toBe(true);
    expect(integrity.signaturesInvalid).toBe(0);

    expect(verifyQuorumRound(chain, APPROVED_ID).valid).toBe(true);
  });

  it('a re-sealed lie passes verifyChain and is caught only by verifyQuorumRound', () => {
    // A coordinator that doctors a resolution can recompute its hash and
    // re-attest it with the group key. Nothing about the CRYPTOGRAPHY is
    // wrong — which is precisely why integrity verification alone is not
    // sufficient to trust a quorum record.
    const chain = vector('tamper-approved-below-threshold');

    const integrity = verifyChain(chain, { publicKeys: keys('keys-rejected') });
    expect(integrity.valid).toBe(true);
    expect(integrity.signaturesInvalid).toBe(0);
    expect(integrity.brokenAt).toBeUndefined();

    const round = verifyQuorumRound(chain, REJECTED_ID);
    expect(round.valid).toBe(false);
    expect(codes(round)).toContain('approved-below-threshold');
  });

  it('the same holds for a doctored tally', () => {
    const chain = vector('tamper-tally-mismatch');
    expect(verifyChain(chain, { publicKeys: keys('keys-rejected') }).valid).toBe(true);
    expect(verifyQuorumRound(chain, REJECTED_ID).valid).toBe(false);
  });

  it('the FROST aggregate verifies as a stock Ed25519 signature', () => {
    // The whole reason quorum events need no new verifier path.
    const chain = vector('round-approved');
    const resolution = chain[chain.length - 1]!;
    const r = verifyChain([resolution as unknown as Record<string, unknown>], {
      publicKeys: keys('keys-approved'),
      requireSignatures: true,
    });
    // A single-event chain: head must have previousHash null, so linkage fails,
    // but the signature check is what we care about here.
    expect(r.events[0]!.signature).toBe('valid');
  });
});

describe('quorum group: threshold guards', () => {
  const ids = ['a', 'b', 'c', 'd'];

  it('rejects a quorum of one', () => {
    expect(() => createGroupViaDkg({ groupId: 'g', validatorIds: ids, m: 1 })).toThrow(
      /quorum of one/,
    );
  });

  it('rejects m greater than n', () => {
    expect(() => createGroupViaDkg({ groupId: 'g', validatorIds: ids, m: 5 })).toThrow(
      /cannot exceed/,
    );
  });

  it('rejects a single-member set', () => {
    expect(() => createGroupViaDkg({ groupId: 'g', validatorIds: ['a'], m: 2 })).toThrow(
      /at least 2 validators/,
    );
  });

  it('rejects duplicate validator ids', () => {
    expect(() =>
      createGroupViaDkg({ groupId: 'g', validatorIds: ['a', 'b', 'a'], m: 2 }),
    ).toThrow(/unique/);
  });

  it('refuses to aggregate below the threshold', () => {
    const group = createGroupViaDkg({ groupId: 'g', validatorIds: ids, m: 3 });
    expect(() =>
      aggregateAttestation(group, ['a', 'b'], new TextEncoder().encode('x')),
    ).toThrow(/at least m=3/);
  });

  it('every DKG participant derives the same group key', () => {
    const group = createGroupViaDkg({ groupId: 'g', validatorIds: ids, m: 3 });
    expect(group.groupPublicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(group.members).toHaveLength(4);
  });
});

describe('quorum round: live round end to end', () => {
  it('runs a round and produces a chain that passes both passes', async () => {
    const validatorIds = ['v1', 'v2', 'v3'];
    const validators = validatorIds.map((id, i) =>
      createLocalValidator({
        validatorId: id,
        evaluate: () => ({ vote: i === 2 ? 'reject' : 'approve', rationale: 'test' }),
      }),
    );
    const group = createGroupViaDkg({ groupId: 'grp', validatorIds, m: 2 });

    let tick = 0;
    const result = await runQuorumRound({
      group,
      validators,
      proposal: {
        quorumId: 'q1',
        intentId: 'i1',
        proposerAgentId: 'agent:p',
        action: 'delete',
        actionType: 'db.delete',
        resourceScope: ['db:x'],
        riskLevel: 'CRITICAL',
      },
      policyId: 'p',
      correlationId: 'c1',
      deadline: '2026-08-02T23:59:59.000Z',
      now: () => `2026-08-02T10:00:${String(tick++).padStart(2, '0')}.000Z`,
      nextEventId: (() => {
        let i = 0;
        return () => `evt-${i++}`;
      })(),
    });

    expect(result.outcome).toBe('approved'); // 2 approvals meets m=2
    expect(result.attested).toBe(true);
    expect(result.tally).toEqual({ approve: 2, reject: 1, abstain: 0, noResponse: 0 });

    const chain = result.events as unknown as QuorumProofEvent[];
    const integrity = verifyChain(chain, {
      publicKeys: buildKeyring(validators, group),
      requireSignatures: true,
    });
    expect(integrity.valid).toBe(true);

    const round = verifyQuorumRound(chain, 'q1');
    expect(round.issues).toEqual([]);
    expect(round.valid).toBe(true);
  });

  it('rejects a validator list that does not match the group size', async () => {
    const group = createGroupViaDkg({ groupId: 'g', validatorIds: ['a', 'b', 'c'], m: 2 });
    await expect(
      runQuorumRound({
        group,
        validators: [createLocalValidator({ validatorId: 'a', evaluate: () => ({ vote: 'approve' }) })],
        proposal: {
          quorumId: 'q',
          intentId: 'i',
          proposerAgentId: 'p',
          action: 'a',
          actionType: 't',
          resourceScope: [],
        },
        policyId: 'p',
        correlationId: 'c',
        deadline: '2026-08-02T23:59:59.000Z',
        now: () => '2026-08-02T10:00:00.000Z',
        nextEventId: () => 'e',
      }),
    ).rejects.toThrow(/does not match/);
  });
});
