// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Golden vectors — input chain -> expected score + tier. These LOCK the
 * scorer's behaviour to byte values so any drift in the formulas, the
 * quantization, or the cap logic breaks a test.
 *
 * The small, precise-byte vectors are read from JSON fixtures. The vectors
 * that require a long qualification climb (the log-gain curve is the
 * throttle, so reaching T2/T4 needs hundreds of successes) are generated
 * programmatically; their expectations are still locked to verified numbers.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { ProofEvent } from '@vorionsys/basis-spec';
import { scoreChain } from '../scorer.js';
import type { ScoringPolicy } from '../types.js';
import { actionCycle, makeEvent, resetCycleSeq, isoOffset } from './helpers.js';

const here = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): {
  policy: ScoringPolicy;
  expected: Record<string, unknown>;
  events: ProofEvent[];
} {
  const raw = JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf8'));
  return raw;
}

const RISK_MULT: Record<string, number> = {
  READ: 1, LOW: 3, MEDIUM: 5, HIGH: 10, CRITICAL: 15, LIFE_CRITICAL: 30,
};
const CEILING_OF: Record<string, number> = {
  BLACK_BOX: 600, GRAY_BOX: 750, WHITE_BOX: 900, ATTESTED_BOX: 950, VERIFIED_BOX: 1000,
};

/** Round-half-even at 1e6 — mirrors the scorer's quantization for prediction. */
function rhe(x: number): number {
  const v = x * 1e6;
  const f = Math.floor(v);
  const d = v - f;
  let n: number;
  if (d < 0.5) n = f;
  else if (d > 0.5) n = f + 1;
  else n = f % 2 === 0 ? f : f + 1;
  return n / 1e6;
}

/**
 * Predict the number of success cycles needed to climb to `target`, using the
 * same canonical gain formula + quantization the scorer uses. This is an
 * INDEPENDENT cross-check (the test predicts the count; the scorer is then
 * asserted to land in the expected tier) and is O(n) instead of O(n^2).
 */
function climbTo(opts: {
  actionType: string;
  observationTier: ScoringPolicy['observationTier'];
  risk: 'READ' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'LIFE_CRITICAL';
  target: number;
  baseIso: string;
}): ProofEvent[] {
  const ceiling = CEILING_OF[opts.observationTier] ?? 600;
  const r = RISK_MULT[opts.risk] ?? 1;
  let score = 0;
  let count = 0;
  while (score < opts.target && count < 5000) {
    const gain = 0.05 * Math.log(1 + Math.max(0, ceiling - score)) * Math.cbrt(r);
    score = rhe(score + gain);
    count += 1;
  }

  resetCycleSeq();
  const events: ProofEvent[] = [];
  let t = Date.parse(opts.baseIso);
  for (let k = 0; k < count; k++) {
    events.push(
      ...actionCycle({ actionType: opts.actionType, baseIso: new Date(t).toISOString(), outcome: 'success' }),
    );
    t += 60_000;
  }
  return events;
}

describe('GV-01: empty chain => least privilege (T0, INITIAL_TRUST_SCORE)', () => {
  it('empty chain returns score 0, tier T0, status OK', () => {
    const r = scoreChain([], { observationTier: 'GRAY_BOX', riskByActionType: {} });
    expect(r.recomputedScore).toBe(0);
    expect(r.recomputedTier).toBe('T0');
    expect(r.effectiveTier).toBe('T0');
    expect(r.status).toBe('OK');
    expect(r.scoredEventCount).toBe(0);
    expect(r.circuitBreaker).toBe('NONE');
  });
});

describe('GV-02: single success at LOW under GRAY_BOX => exact quantized gain', () => {
  const fx = loadFixture('gv02-single-success-low-gray.json');
  it('matches the locked golden byte value', () => {
    const r = scoreChain(fx.events, fx.policy);
    expect(r.recomputedScore).toBe(fx.expected.recomputedScore); // 0.477486
    expect(r.recomputedTier).toBe(fx.expected.recomputedTier);
    expect(r.observationCappedTier).toBe(fx.expected.observationCappedTier);
    expect(r.effectiveTier).toBe(fx.expected.effectiveTier);
    expect(r.status).toBe(fx.expected.status);
    expect(r.scoredEventCount).toBe(fx.expected.scoredEventCount);
  });
});

describe('GV-03: mixed chain — successes then a failure (loss uses tier-at-failure)', () => {
  it('locks final score, tier, and accumulator; loss applies at the failure-time tier', () => {
    // Climb to ~520 (T3) under GRAY_BOX MEDIUM, then ONE MEDIUM failure.
    resetCycleSeq();
    const events = climbTo({
      actionType: 'op.write',
      observationTier: 'GRAY_BOX',
      risk: 'MEDIUM',
      target: 520,
      baseIso: '2026-02-01T00:00:00Z',
    });
    const beforeFail = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'op.write': 'MEDIUM' },
    });
    expect(beforeFail.recomputedTier).toBe('T3'); // at the failure the tier index is 3

    // Append the failure one hour after the last success.
    const failBase = new Date(Date.parse('2026-02-01T00:00:00Z') + (events.length + 10) * 60_000).toISOString();
    events.push(...actionCycle({ actionType: 'op.write', baseIso: failBase, outcome: 'fail' }));

    const r = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { 'op.write': 'MEDIUM' },
    });
    // The score drops by the T3/MEDIUM loss; assert it is strictly lower and
    // the accumulator recorded the failure weight P(3)*5 = 30.
    expect(r.recomputedScore).toBeLessThan(beforeFail.recomputedScore);
    expect(r.riskAccumulator24h).toBe(30);
    expect(r.scoredEventCount).toBe(beforeFail.scoredEventCount + 1);
    // A T3/MEDIUM/GRAY loss is calculateLoss({tierIndex:3, ceiling:750, R:5}).
    // -penaltyRatio(3)*5*0.05*ln(1+375) = verified below.
    const expectedLoss = -(3 + 3) * 5 * 0.05 * Math.log(1 + 750 / 2);
    const expectedScore =
      Math.round((beforeFail.recomputedScore + expectedLoss) * 1e6) / 1e6;
    expect(r.recomputedScore).toBeCloseTo(expectedScore, 4);
  });
});

describe('GV-04: observation cap — T4-worth score under BLACK_BOX floored to T3', () => {
  it('a chain that recomputes to T4 under WHITE is capped to T3 by BLACK_BOX maxTier', () => {
    // Climb to T4 (>=650) under WHITE_BOX (ceiling 900) with MEDIUM successes.
    const events = climbTo({
      actionType: 'hi',
      observationTier: 'WHITE_BOX',
      risk: 'MEDIUM',
      target: 655,
      baseIso: '2026-04-01T00:00:00Z',
    });
    const underWhite = scoreChain(events, {
      observationTier: 'WHITE_BOX',
      riskByActionType: { hi: 'MEDIUM' },
    });
    expect(underWhite.recomputedTier).toBe('T4');
    expect(underWhite.observationCappedTier).toBe('T4'); // WHITE maxTier is T6
    expect(underWhite.effectiveTier).toBe('T4');

    // Same evidence under BLACK_BOX: ceiling 600 caps the score AND maxTier
    // is T3, so the effective tier can never exceed T3.
    const underBlack = scoreChain(events, {
      observationTier: 'BLACK_BOX',
      riskByActionType: { hi: 'MEDIUM' },
    });
    expect(underBlack.observationCappedTier).toBe('T3');
    expect(underBlack.effectiveTier).toBe('T3');
  });
});

describe('GV-05: honest TEE cap — ATTESTED_BOX downgraded to WHITE_BOX unless asserted', () => {
  const fx = loadFixture('gv02-single-success-low-gray.json');
  it('ATTESTED_BOX WITHOUT assertVerifiedObservation => WHITE_BOX cap (T6) + flag', () => {
    const r = scoreChain(fx.events, {
      observationTier: 'ATTESTED_BOX',
      riskByActionType: { 'db.read': 'LOW' },
    });
    expect(r.flags).toContain('tee_stub_downgrade:ATTESTED_BOX=>WHITE_BOX');
  });

  it('ATTESTED_BOX WITH assertVerifiedObservation => honored (no downgrade flag)', () => {
    const r = scoreChain(fx.events, {
      observationTier: 'ATTESTED_BOX',
      assertVerifiedObservation: true,
      riskByActionType: { 'db.read': 'LOW' },
    });
    expect(r.flags).not.toContain('tee_stub_downgrade:ATTESTED_BOX=>WHITE_BOX');
  });

  it('VERIFIED_BOX WITHOUT assertion => WHITE_BOX cap + flag (cannot reach T7)', () => {
    const r = scoreChain(fx.events, {
      observationTier: 'VERIFIED_BOX',
      riskByActionType: { 'db.read': 'LOW' },
    });
    expect(r.flags).toContain('tee_stub_downgrade:VERIFIED_BOX=>WHITE_BOX');
  });
});

describe('GV-06: over-claim — claimed T5 but recomputed T2 => effective T2', () => {
  it('effectiveTier = min(claimed T5, recomputed T2) = T2; overClaim flagged', () => {
    // Climb to ~420 (T2) under GRAY_BOX MEDIUM. The decision_made events carry
    // a realistic running trustScore so only the fabricated trust_delta
    // diverges (keeps the assertion clean).
    const events = climbTo({
      actionType: 'mw',
      observationTier: 'GRAY_BOX',
      risk: 'MEDIUM',
      target: 410,
      baseIso: '2026-05-01T00:00:00Z',
    });
    const recBefore = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { mw: 'MEDIUM' },
    });
    expect(recBefore.recomputedTier).toBe('T2');

    // Append a fabricated trust_delta claiming newScore=850 (T5 territory).
    const tdBase = new Date(
      Date.parse('2026-05-01T00:00:00Z') + (events.length + 10) * 60_000,
    ).toISOString();
    events.push(
      makeEvent(
        'trust_delta',
        {
          type: 'trust_delta',
          deltaId: 'td-fab',
          previousScore: 0,
          newScore: 850,
          previousBand: 'T0',
          newBand: 'T5',
          reason: 'fabricated over-claim',
        },
        tdBase,
        'td-fab-evt',
      ),
    );

    const r = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { mw: 'MEDIUM' },
      claimedTier: 'T5',
    });
    expect(r.recomputedTier).toBe('T2');
    expect(r.effectiveTier).toBe('T2'); // min(T5 claimed, T2 recomputed)
    expect(r.overClaim).toBe(true);
    const fabDiv = r.divergences.find((d) => d.eventId === 'td-fab-evt');
    expect(fabDiv).toBeDefined();
    expect(fabDiv?.kind).toBe('trust_delta');
    expect(fabDiv?.claimed).toBe(850);
  });
});

describe('GV-07: circuit-breaker trip — qualified agent driven below 100 => TRIPPED, T0', () => {
  it('after qualifying, high-risk failures trip the CB and floor the tier to T0', () => {
    // Qualify (cross 200) with LOW/GRAY successes, then HIGH failures to crash.
    resetCycleSeq();
    const events = climbTo({
      actionType: 'q',
      observationTier: 'GRAY_BOX',
      risk: 'LOW',
      target: 205,
      baseIso: '2026-06-01T00:00:00Z',
    });
    let t = Date.parse('2026-06-01T00:00:00Z') + (events.length + 10) * 60_000;
    for (let k = 0; k < 40; k++) {
      events.push(...actionCycle({ actionType: 'crash', baseIso: new Date(t).toISOString(), outcome: 'fail' }));
      t += 60_000;
    }
    const r = scoreChain(events, {
      observationTier: 'GRAY_BOX',
      riskByActionType: { q: 'LOW', crash: 'HIGH' },
    });
    expect(r.circuitBreaker).toBe('TRIPPED');
    expect(r.status).toBe('TRIPPED');
    expect(r.effectiveTier).toBe('T0');
    expect(r.recomputedScore).toBeLessThan(100);
  });
});

describe('GV-08: risk accumulator trips via the 24h occurredAt window, not the score path', () => {
  it('failures clustered within 24h trip the accumulator (>=240) while score stays >=200', () => {
    // Climb high under WHITE_BOX, then a small number of HIGH failures whose
    // P(T)*R sum crosses cbThreshold(240) but whose total loss keeps the score
    // qualified (>=200) — proving the accumulator path is independent.
    const events = climbTo({
      actionType: 'work',
      observationTier: 'WHITE_BOX',
      risk: 'HIGH',
      target: 600,
      baseIso: '2026-07-01T00:00:00Z',
    });
    const base = Date.parse('2026-07-01T00:00:00Z') + (events.length + 10) * 60_000;
    // 4 HIGH failures, ~1h apart, all within a 24h window.
    let t = base;
    for (let k = 0; k < 4; k++) {
      events.push(...actionCycle({ actionType: 'work', baseIso: new Date(t).toISOString(), outcome: 'fail' }));
      t += 3_600_000; // 1h
    }
    const clustered = scoreChain(events, {
      observationTier: 'WHITE_BOX',
      riskByActionType: { work: 'HIGH' },
    });
    expect(clustered.riskAccumulator24h).toBeGreaterThanOrEqual(240);
    expect(clustered.circuitBreaker).toBe('TRIPPED');
    // The score itself stayed well above the score-path CB threshold (100),
    // so the trip came from the accumulator, not the score path.
    expect(clustered.recomputedScore).toBeGreaterThan(100);

    // Same failures spread >24h apart do NOT trip the accumulator.
    resetCycleSeq();
    const spreadEvents = climbTo({
      actionType: 'work',
      observationTier: 'WHITE_BOX',
      risk: 'HIGH',
      target: 600,
      baseIso: '2026-08-01T00:00:00Z',
    });
    let st = Date.parse('2026-08-01T00:00:00Z') + (spreadEvents.length + 10) * 60_000;
    for (let k = 0; k < 4; k++) {
      spreadEvents.push(...actionCycle({ actionType: 'work', baseIso: new Date(st).toISOString(), outcome: 'fail' }));
      st += 25 * 3_600_000; // 25h apart => at most 1 in any 24h window
    }
    const spread = scoreChain(spreadEvents, {
      observationTier: 'WHITE_BOX',
      riskByActionType: { work: 'HIGH' },
    });
    expect(spread.riskAccumulator24h).toBeLessThan(240);
  });
});

describe('GV-09: shadow-mode exclusion — shadow/testnet events do not move the score', () => {
  it('interleaved shadow/testnet events yield the same score as the production-only chain', () => {
    resetCycleSeq();
    const withShadow = [
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' }),
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:30:00Z', outcome: 'success', shadowMode: 'shadow' }),
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T01:00:00Z', outcome: 'success', shadowMode: 'testnet' }),
    ];
    resetCycleSeq();
    const prodOnly = [
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' }),
    ];
    const policy: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } };
    const a = scoreChain(withShadow, policy);
    const b = scoreChain(prodOnly, policy);
    expect(a.recomputedScore).toBe(b.recomputedScore);
    expect(a.scoredEventCount).toBe(b.scoredEventCount);
  });
});

describe('GV-10: partial success => zero gain (score unchanged vs the event removed)', () => {
  it('a partial-success cycle leaves the score identical to omitting it', () => {
    resetCycleSeq();
    const withPartial = [
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' }),
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T01:00:00Z', outcome: 'partial' }),
    ];
    resetCycleSeq();
    const successOnly = [
      ...actionCycle({ actionType: 'db.read', baseIso: '2026-01-01T00:00:00Z', outcome: 'success' }),
    ];
    const policy: ScoringPolicy = { observationTier: 'GRAY_BOX', riskByActionType: { 'db.read': 'LOW' } };
    const a = scoreChain(withPartial, policy);
    const b = scoreChain(successOnly, policy);
    expect(a.recomputedScore).toBe(b.recomputedScore);
    expect(a.flags.some((f) => f.startsWith('partial_zero_gain'))).toBe(true);
  });
});
