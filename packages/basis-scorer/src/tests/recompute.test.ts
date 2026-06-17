// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Recompute-not-trust tests — the property the scorer exists to provide.
 *
 * A claimed `trust_delta` (or `decision_made.trustScore`) is the runtime's
 * ASSERTION. The scorer NEVER sums it; it re-derives the value from the
 * execution outcome and uses the recomputed value, flagging the divergence
 * as advisory evidence. The actual defence against over-claim is the
 * `effectiveTier = min(...)` at the API boundary — NOT the divergence flag
 * (a sophisticated runtime can make claimed == recomputed and still assert a
 * high claimedTier; the min() catches that, the flag does not).
 */

import { describe, it, expect } from 'vitest';
import { scoreChain } from '../scorer.js';
import { hashPolicy } from '../policy-hash.js';
import type { ScoringPolicy } from '../types.js';
import { actionCycle, makeEvent, resetCycleSeq } from './helpers.js';

describe('recompute: a claimed trust_delta that DISAGREES is not trusted', () => {
  it('the scorer keeps the recomputed value and flags the divergence', () => {
    resetCycleSeq();
    // One LOW/GRAY success => recomputed gain 0.477486.
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    // The runtime ASSERTS it jumped to 500 (T3). This is a lie.
    events.push(
      makeEvent(
        'trust_delta',
        {
          type: 'trust_delta',
          deltaId: 'td-lie',
          previousScore: 0,
          newScore: 500,
          previousBand: 'T0',
          newBand: 'T3',
          reason: 'inflated',
        },
        '2026-01-01T00:00:10Z',
        'td-lie-evt',
      ),
    );

    const policy: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } };
    const r = scoreChain(events, policy);

    // The recomputed score is the small real gain, NOT the claimed 500.
    expect(r.recomputedScore).toBe(0.477486);
    expect(r.recomputedTier).toBe('T0');

    // The divergence is recorded with the claimed vs recomputed values.
    const div = r.divergences.find((d) => d.eventId === 'td-lie-evt');
    expect(div).toBeDefined();
    expect(div?.kind).toBe('trust_delta');
    expect(div?.claimed).toBe(500);
    expect(div?.recomputed).toBe(0.477486);
    expect(r.overClaim).toBe(true);
  });
});

describe('recompute: a HONEST trust_delta (claimed == recomputed) raises NO divergence', () => {
  it('a delta matching the recomputed gain is not flagged', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    // Honest claim: previousScore 0, newScore equal to the real recomputed gain.
    events.push(
      makeEvent(
        'trust_delta',
        {
          type: 'trust_delta',
          deltaId: 'td-honest',
          previousScore: 0,
          newScore: 0.477486,
          previousBand: 'T0',
          newBand: 'T0',
          reason: 'honest',
        },
        '2026-01-01T00:00:10Z',
        'td-honest-evt',
      ),
    );
    const r = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } });
    expect(r.divergences.find((d) => d.eventId === 'td-honest-evt')).toBeUndefined();
    expect(r.overClaim).toBe(false);
  });
});

describe('recompute: effectiveTier = min(claimed, recomputed) is the real defence', () => {
  it('a high claimedTier cannot raise the result above the recomputed/observation cap', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    // The client asserts T7. The recomputed score is ~0 (T0). min() wins.
    const r = scoreChain(events, {
      observationTier: 'VERIFIED_BOX', // even the highest obs (downgraded to WHITE)
      assertVerifiedObservation: false,
      riskByActionType: { 'db.read': 'LOW' },
      claimedTier: 'T7',
    });
    expect(r.effectiveTier).toBe('T0'); // not T7
  });
});

describe('policyHash: the untrusted policy is hashed for reproducibility/attribution', () => {
  it('the same policy yields the same hash; a different policy yields a different hash', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    const p1: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } };
    const p2: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'HIGH' } };
    const r1 = scoreChain(events, p1);
    const r1b = scoreChain(events, p1);
    const r2 = scoreChain(events, p2);
    expect(r1.policyHash).toBe(r1b.policyHash);
    expect(r1.policyHash).not.toBe(r2.policyHash);
    // Hash is order-independent over the policy object (canonical JSON).
    expect(hashPolicy(p1)).toBe(hashPolicy({ riskByActionType: { 'db.read': 'LOW' }, observationTier: 'GRAY_BOX' }));
  });
});

describe('recompute: trust_delta is NEVER summed into the score', () => {
  it('two large trust_delta claims do not move the recomputed score at all', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    const baseline = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } });

    const withDeltas = [
      ...events,
      makeEvent('trust_delta', { type: 'trust_delta', deltaId: 'a', previousScore: 0, newScore: 900, previousBand: 'T0', newBand: 'T6', reason: 'x' }, '2026-01-01T00:00:10Z', 'tdA'),
      makeEvent('trust_delta', { type: 'trust_delta', deltaId: 'b', previousScore: 900, newScore: 999, previousBand: 'T6', newBand: 'T7', reason: 'y' }, '2026-01-01T00:00:20Z', 'tdB'),
    ];
    const r = scoreChain(withDeltas, { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } });
    // The recomputed score is identical to the baseline — deltas added nothing.
    expect(r.recomputedScore).toBe(baseline.recomputedScore);
  });
});
