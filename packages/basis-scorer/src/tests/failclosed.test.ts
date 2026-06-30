// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Fail-closed tests — every malformed, unverifiable, unknown, or
 * non-deterministic input must degrade toward least privilege (T0 /
 * FAIL_CLOSED), never toward the higher value.
 *
 *   FAIL-01  garbage / GenericPayload event => no gain, flag, score not raised.
 *   FAIL-02  unknown actionType => defaultRisk = LIFE_CRITICAL applied.
 *   FAIL-03  unknown observation tier => BLACK_BOX / T3 floor + flag.
 *   FAIL-04  execution_completed with no matching execution_started =>
 *            broken-link flag, risk fails closed to max.
 *   plus: unparseable occurredAt, missing eventId, out-of-range/NaN guards,
 *   missing claim must NOT raise, and the empty-chain least-privilege case.
 */

import { describe, it, expect } from 'vitest';
import type { ProofEvent } from '@vorionsys/basis-spec';
import { scoreChain } from '../scorer.js';
import type { ScoringPolicy } from '../types.js';
import { actionCycle, makeEvent, resetCycleSeq } from './helpers.js';

const POLICY: ScoringPolicy = {
  observationTier: 'GRAY_BOX',
  riskByActionType: { 'db.read': 'LOW' },
};

describe('FAIL-01: garbage / unknown event types are unscorable', () => {
  it('a GenericPayload / unknown eventType applies no gain and is flagged', () => {
    const garbage = makeEvent(
      'wat_is_this' as ProofEvent['eventType'],
      { type: 'wat_is_this', foo: 'bar' },
      '2026-01-01T00:00:00Z',
      'g-1',
    );
    const r = scoreChain([garbage], POLICY);
    expect(r.recomputedScore).toBe(0);
    expect(r.effectiveTier).toBe('T0');
    expect(r.flags.some((f) => f.startsWith('unscorable_event_type'))).toBe(true);
  });

  it('a generic payload whose type mismatches the eventType is flagged but never raises score', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    // Corrupt the completed event's payload type to a generic value.
    const corrupted = events.map((e) =>
      e.eventType === 'execution_completed'
        ? makeEvent(e.eventType, { type: 'GenericPayload', executionId: 'x-000001', actionId: 'a' }, e.occurredAt, e.eventId)
        : e,
    );
    const r = scoreChain(corrupted, POLICY);
    // status is not 'success' => no gain.
    expect(r.recomputedScore).toBe(0);
    expect(r.flags.some((f) => f.startsWith('payload_type_mismatch'))).toBe(true);
  });
});

describe('FAIL-02: unknown actionType => defaultRisk LIFE_CRITICAL', () => {
  it('an unmapped action earns the LIFE_CRITICAL gain (more than LOW, by design of fail-closed-to-max)', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'mystery.action', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    // Policy maps nothing => defaultRisk LIFE_CRITICAL (multiplier 30).
    const r = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: {} });
    // calculateGain(0, 750, 30) = 0.05*ln(751)*cbrt(30), quantized.
    const expected =
      Math.round(0.05 * Math.log(1 + 750) * Math.cbrt(30) * 1e6) / 1e6;
    expect(r.recomputedScore).toBe(expected);

    // And it is strictly larger than the same action mapped LOW (cheap gain
    // impossible for an unrecognised action).
    const low = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: { 'mystery.action': 'LOW' } });
    expect(r.recomputedScore).toBeGreaterThan(low.recomputedScore);
  });

  it('an unmapped action is maximally penalised on failure', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'mystery.action', baseIso: '2026-01-01T00:00:00Z', outcome: 'fail' });
    const r = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: {} });
    // The accumulator weight is P(T0)*R = 3*30 = 90 (deepest single-failure
    // contribution at the floor tier).
    expect(r.riskAccumulator24h).toBe(90);
  });
});

describe('FAIL-03: unknown observation tier => BLACK_BOX / T3 floor + flag', () => {
  it('an unknown observation tier resolves to the most restrictive BLACK_BOX', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    const r = scoreChain(events, {
      observationTier: 'PLATINUM_BOX' as ScoringPolicy['observationTier'],
      riskByActionType: { 'db.read': 'LOW' },
    });
    expect(r.flags.some((f) => f.startsWith('unknown_observation_tier'))).toBe(true);
    // observationCappedTier can never exceed BLACK_BOX maxTier (T3).
    const order = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7'];
    expect(order.indexOf(r.observationCappedTier)).toBeLessThanOrEqual(order.indexOf('T3'));
  });
});

describe('FAIL-04: execution outcome with no matching execution_started', () => {
  it('a broken risk link fails closed to max risk and is flagged', () => {
    // A completed event whose executionId resolves no started/decision/intent.
    const orphan = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'orphan-x', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00Z',
      'orphan-1',
    );
    const r = scoreChain([orphan], { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } });
    expect(r.flags.some((f) => f.startsWith('broken_link_risk_maxed'))).toBe(true);
    // Risk fell closed to LIFE_CRITICAL => the gain equals the max-risk gain.
    const expected = Math.round(0.05 * Math.log(1 + 750) * Math.cbrt(30) * 1e6) / 1e6;
    expect(r.recomputedScore).toBe(expected);
  });
});

describe('Fail-closed: unparseable / missing structural fields', () => {
  it('an unparseable occurredAt => FAIL_CLOSED T0', () => {
    const bad = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'x', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      'yesterday-ish',
      'bad-ts',
    );
    const r = scoreChain([bad], POLICY);
    expect(r.status).toBe('FAIL_CLOSED');
    expect(r.effectiveTier).toBe('T0');
    expect(r.error).toContain('unparseable_occurredAt');
  });

  it('a missing/empty eventId => FAIL_CLOSED T0', () => {
    const bad = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'x', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00Z',
      '',
    );
    const r = scoreChain([bad], POLICY);
    expect(r.status).toBe('FAIL_CLOSED');
    expect(r.error).toContain('missing_or_empty_eventId');
  });

  it('a timestamp with >9 fractional digits (sub-nanosecond) => FAIL_CLOSED (lossless-or-reject)', () => {
    const bad = makeEvent(
      'execution_completed',
      { type: 'execution_completed', executionId: 'x', actionId: 'a', status: 'success', durationMs: 1, outputHash: 'o' },
      '2026-01-01T00:00:00.1234567890Z',
      'too-precise',
    );
    const r = scoreChain([bad], POLICY);
    expect(r.status).toBe('FAIL_CLOSED');
    expect(r.error).toContain('unparseable_occurredAt');
  });

  it('an invalid precision => FAIL_CLOSED T0', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    const r = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' }, precision: -5 });
    expect(r.status).toBe('FAIL_CLOSED');
    expect(r.error).toContain('invalid_precision');
  });
});

describe('Fail-closed: empty chain is least privilege, not an error', () => {
  it('empty chain => OK, score 0, T0 (no evidence => least privilege)', () => {
    const r = scoreChain([], POLICY);
    expect(r.status).toBe('OK');
    expect(r.recomputedScore).toBe(0);
    expect(r.effectiveTier).toBe('T0');
  });
});

describe('Fail-closed: a missing client claim must NOT raise the result', () => {
  it('omitting claimedTier leaves the observation/policy caps intact (no T7 default)', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    const withClaim = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' }, claimedTier: 'T0' });
    const noClaim = scoreChain(events, { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } });
    // Without a claim the effective tier is the (low) recomputed/observation
    // result — a missing claim cannot push it ABOVE that. With an explicit T0
    // claim it is still T0. Neither path raises the result.
    expect(noClaim.effectiveTier).toBe('T0');
    expect(withClaim.effectiveTier).toBe('T0');
  });

  it('a malformed claimedTier => FAIL_CLOSED rather than a silent high default', () => {
    resetCycleSeq();
    const events = actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' });
    const r = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.read': 'LOW' },
      claimedTier: 'T99' as ScoringPolicy['claimedTier'],
    });
    expect(r.status).toBe('FAIL_CLOSED');
    expect(r.error).toContain('invalid_claimedTier');
  });
});
