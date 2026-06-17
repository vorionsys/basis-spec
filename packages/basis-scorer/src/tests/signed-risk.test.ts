// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0002.1 — SIGNED, in-chain risk tests.
 *
 * Risk used to be injected purely by the caller's `ScoringPolicy`
 * (`riskByActionType`), an out-of-chain trust dependency the SAME party that
 * asserts the tier also controlled. RFC-0002.1 lets an `intent_received` event
 * carry a SIGNED `riskLevel` so risk becomes part of the evidence.
 *
 * Resolution precedence (and the `riskSource` we surface for attribution):
 *   1. CHAIN      — intent_received.riskLevel (signed) OVERRIDES policy.
 *   2. POLICY     — fall back to policy.riskByActionType (RFC-0002.0 chains).
 *   3. FAILCLOSED — neither resolves => policy.defaultRisk (LIFE_CRITICAL).
 *
 * Golden gain values (single success @ score 0, GRAY_BOX ceiling 750), locked
 * to bytes via the canonical formula gain = 0.05*ln(1+750)*cbrt(R):
 *   LOW (R=3)            => 0.477486
 *   HIGH (R=10)          => 0.713269
 *   LIFE_CRITICAL (R=30) => 1.028712
 */

import { describe, it, expect } from 'vitest';
import { scoreChain } from '../scorer.js';
import type { ScoringPolicy } from '../types.js';
import { actionCycle, resetCycleSeq } from './helpers.js';

// Locked golden gains (verified independently via the canonical formula).
const GAIN_LOW = 0.477486; // R=3
const GAIN_HIGH = 0.713269; // R=10
const GAIN_LIFE_CRITICAL = 1.028712; // R=30

describe('RFC-0002.1 (a): in-chain riskLevel drives gain and OVERRIDES policy', () => {
  it('signed HIGH wins over a conflicting policy mapping of LOW; riskSource=chain', () => {
    resetCycleSeq();
    // Chain signs the action as HIGH...
    const events = actionCycle({
      actionType: 'db.write',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'success',
      riskLevel: 'HIGH',
    });
    // ...while the (untrusted) policy tries to under-classify it as LOW.
    const policy: ScoringPolicy = {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.write': 'LOW' },
    };
    const r = scoreChain(events, policy);

    // The SIGNED HIGH risk drives the gain, NOT the policy's LOW.
    expect(r.recomputedScore).toBe(GAIN_HIGH);
    expect(r.recomputedScore).not.toBe(GAIN_LOW);
    expect(r.scoredEventCount).toBe(1);

    // Attribution: the risk came from the chain (signed evidence).
    expect(r.riskResolutions).toHaveLength(1);
    const rr = r.riskResolutions[0]!;
    expect(rr.source).toBe('chain');
    expect(rr.risk).toBe('HIGH');
    expect(rr.eventId).toBe(events.find((e) => e.eventType === 'execution_completed')!.eventId);
  });

  it('in-chain risk also drives LOSS magnitude on failure (overrides policy)', () => {
    resetCycleSeq();
    // Signed HIGH failure vs a policy that claims LOW. The loss + accumulator
    // weight must reflect HIGH (R=10), not LOW (R=3).
    const events = actionCycle({
      actionType: 'db.write',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'fail',
      riskLevel: 'HIGH',
    });
    const signedHigh = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.write': 'LOW' },
    });

    // Compare to a chain with NO signed risk but the SAME policy (LOW).
    resetCycleSeq();
    const policyLowEvents = actionCycle({
      actionType: 'db.write',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'fail',
    });
    const policyLow = scoreChain(policyLowEvents, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.write': 'LOW' },
    });

    // A fresh agent's score is floored at 0 (MIN_TRUST_SCORE), so the loss
    // magnitude is observed via the risk accumulator weight P(T)*R instead.
    // At tier 0, P(0)=3, so signed HIGH contributes 3*10=30 vs policy LOW 3*3=9.
    // That the two differ proves the in-chain HIGH risk drove the loss side.
    expect(signedHigh.riskAccumulator24h).toBe(30);
    expect(policyLow.riskAccumulator24h).toBe(9);
    expect(signedHigh.riskResolutions[0]!.source).toBe('chain');
    expect(policyLow.riskResolutions[0]!.source).toBe('policy');
  });
});

describe('RFC-0002.1 (b): back-compat — chain WITHOUT riskLevel uses policy fallback', () => {
  it('an RFC-0002.0 chain (no riskLevel) resolves via policy exactly as before; riskSource=policy', () => {
    resetCycleSeq();
    const events = actionCycle({
      actionType: 'db.read',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'success',
      // no riskLevel — this is a legacy RFC-0002.0 chain
    });
    const policy: ScoringPolicy = {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.read': 'LOW' },
    };
    const r = scoreChain(events, policy);

    // Identical to the pre-RFC-0002.1 behaviour: the LOW policy mapping is used.
    expect(r.recomputedScore).toBe(GAIN_LOW);
    expect(r.scoredEventCount).toBe(1);
    expect(r.riskResolutions).toHaveLength(1);
    expect(r.riskResolutions[0]!.source).toBe('policy');
    expect(r.riskResolutions[0]!.risk).toBe('LOW');
  });
});

describe('RFC-0002.1 (c): fail-closed — neither in-chain risk nor a policy mapping', () => {
  it('no riskLevel + unmapped action => LIFE_CRITICAL max risk; riskSource=failclosed', () => {
    resetCycleSeq();
    const events = actionCycle({
      actionType: 'unknown.action',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'success',
      // no riskLevel
    });
    const policy: ScoringPolicy = {
      observationTier: 'GRAY_BOX',
      riskByActionType: {}, // action is NOT mapped
    };
    const r = scoreChain(events, policy);

    // Fail closed to the max-configured default risk (LIFE_CRITICAL, R=30).
    expect(r.recomputedScore).toBe(GAIN_LIFE_CRITICAL);
    expect(r.riskResolutions).toHaveLength(1);
    expect(r.riskResolutions[0]!.source).toBe('failclosed');
    expect(r.riskResolutions[0]!.risk).toBe('LIFE_CRITICAL');
  });
});

describe('RFC-0002.1: an INVALID in-chain riskLevel is ignored (fail-closed to policy/default)', () => {
  it('a garbage riskLevel string is not honoured; resolution falls through to policy', () => {
    resetCycleSeq();
    const events = actionCycle({
      actionType: 'db.read',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'success',
    });
    // Inject a non-canonical riskLevel directly onto the intent_received payload.
    const intent = events.find((e) => e.eventType === 'intent_received')!;
    (intent.payload as Record<string, unknown>)['riskLevel'] = 'SUPER_DUPER_CRITICAL';

    const r = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.read': 'LOW' },
    });
    // The invalid value is ignored; the policy LOW mapping is used instead.
    expect(r.recomputedScore).toBe(GAIN_LOW);
    expect(r.riskResolutions[0]!.source).toBe('policy');
  });
});

describe('RFC-0002.1: deterministic — same signed chain + same policy => identical result', () => {
  it('two scorings of an in-chain-risk chain are byte-identical', () => {
    resetCycleSeq();
    const events = actionCycle({
      actionType: 'db.write',
      baseIso: '2026-01-01T00:00:00Z',
      outcome: 'success',
      riskLevel: 'HIGH',
    });
    const policy: ScoringPolicy = {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'db.write': 'LOW' },
    };
    const a = scoreChain(events, policy);
    const b = scoreChain(events, policy);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(a.recomputedScore).toBe(GAIN_HIGH);
  });
});
