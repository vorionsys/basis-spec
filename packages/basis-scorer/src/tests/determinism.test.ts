// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Determinism tests.
 *
 *   DET-01  same chain twice => byte-identical ScoreResult JSON.
 *   DET-02  a permutation that preserves (instant, eventId) order-equivalence
 *           => identical result; an offset-vs-Z representation of the same
 *           instants => identical result (sort is on the PARSED instant, not
 *           the raw string); a true (instant, eventId) tie => FAIL_CLOSED.
 *   DET-03  a long chain (400+ successes) is stable across repeated scoring —
 *           a proxy for the cross-platform libm-ULP guard (the scaled-integer
 *           accumulator + round-half-even must not drift over many steps).
 *
 * A stable hash of the output is asserted so any drift is a one-line failure.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import type { ProofEvent } from '@vorionsys/basis-spec';
import { scoreChain } from '../scorer.js';
import type { ScoringPolicy } from '../types.js';
import { actionCycle, makeEvent, resetCycleSeq } from './helpers.js';

function stableHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex');
}

const POLICY: ScoringPolicy = {
  observationTier: 'GRAY_BOX',
  riskByActionType: { 'db.read': 'LOW', 'op.write': 'MEDIUM' },
};

function buildMixedChain(): ProofEvent[] {
  resetCycleSeq();
  return [
    ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' }),
    ...actionCycle({ actionType: 'op.write', baseIso: '2026-01-01T01:00:00Z', outcome: 'success' }),
    ...actionCycle({ actionType: 'op.write', baseIso: '2026-01-01T02:00:00Z', outcome: 'success' }),
    ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T03:00:00Z', outcome: 'fail' }),
  ];
}

describe('DET-01: same chain twice => byte-identical result', () => {
  it('two scoring passes produce the identical ScoreResult JSON', () => {
    const chain = buildMixedChain();
    const a = scoreChain(chain, POLICY);
    const b = scoreChain(chain, POLICY);
    expect(stableHash(a)).toBe(stableHash(b));
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('DET-02: ordering is on the parsed instant, not input order or raw string', () => {
  it('a shuffled input (same events) yields the identical result', () => {
    const chain = buildMixedChain();
    const shuffled = [...chain].reverse();
    const a = scoreChain(chain, POLICY);
    const b = scoreChain(shuffled, POLICY);
    expect(stableHash(a)).toBe(stableHash(b));
  });

  it('Z and +05:30 representing the SAME instant produce the same result', () => {
    // Two timestamps that are byte-different strings but the same instant.
    // The scorer sorts on the parsed instant, so swapping them is a no-op.
    resetCycleSeq();
    const utc = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'x-eq', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00Z',
      'eq-1',
    );
    const offset = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'x-eq2', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T05:30:00+05:30', // same instant as 00:00:00Z
      'eq-2',
    );
    // Risk fails closed to default for both (no linkage) — that is fine; the
    // point is the two orderings of equal-instant events are identical.
    const policy: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: {} };
    const a = scoreChain([utc, offset], policy);
    const b = scoreChain([offset, utc], policy);
    expect(stableHash(a)).toBe(stableHash(b));
    // And both timestamps were accepted (no FAIL_CLOSED on parse).
    expect(a.status).not.toBe('FAIL_CLOSED');
  });

  it('a true (instant, eventId) tie => FAIL_CLOSED to T0', () => {
    const dup1 = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'x', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00Z',
      'same-id',
    );
    const dup2 = makeEvent(
      'execution_failed',
      { type: 'execution_failed', executionId: 'x', actionId: 'a', error: 'e', durationMs: 1, retryable: false },
      '2026-01-01T00:00:00Z',
      'same-id', // identical eventId AND identical instant
    );
    const r = scoreChain([dup1, dup2], POLICY);
    expect(r.status).toBe('FAIL_CLOSED');
    expect(r.effectiveTier).toBe('T0');
    expect(r.error).toContain('nondeterministic_duplicate_key');
  });

  it('sub-millisecond-distinct timestamps stay distinct (no truncation)', () => {
    // Two events 456 nanoseconds-region apart. Date.parse would merge these;
    // our parser keeps them distinct, so the (instant, eventId) tie rule does
    // NOT fire and both are scored.
    const a = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'xa', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00.123456Z',
      'sub-a',
    );
    const b = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'xb', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00.123Z',
      'sub-b',
    );
    const policy: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: {} };
    const r = scoreChain([a, b], policy);
    expect(r.status).not.toBe('FAIL_CLOSED');
    expect(r.scoredEventCount).toBe(2);
  });
});

describe('DET-03: long chain stable across passes (scaled-integer accumulator)', () => {
  it('400+ successes produce a stable, repeatable score (no ULP drift)', () => {
    resetCycleSeq();
    const events: ProofEvent[] = [];
    let t = Date.parse('2026-01-01T00:00:00Z');
    for (let k = 0; k < 450; k++) {
      events.push(...actionCycle({ actionType: 'db.read', baseIso: new Date(t).toISOString(), outcome: 'success' }));
      t += 60_000;
    }
    const policy: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } };
    const r1 = scoreChain(events, policy);
    const r2 = scoreChain(events, policy);
    expect(stableHash(r1)).toBe(stableHash(r2));
    // 450 LOW/GRAY successes climb past qualification (200) into T1.
    expect(r1.recomputedScore).toBeGreaterThan(200);
    expect(r1.recomputedTier).toBe('T1');
    // The score is a fixed-precision decimal (NOT an integer) — relabel check.
    expect(Number.isInteger(r1.recomputedScore)).toBe(false);
  });
});
