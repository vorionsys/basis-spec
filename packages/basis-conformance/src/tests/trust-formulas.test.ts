// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Trust formulas test — verifies the gain and loss math the canonical
 * impl exposes matches the spec formulas:
 *
 *   gain  =  GAIN_RATE × ln(1 + (C - S)) × ∛R(action)
 *   loss  = -P(T) × R(action) × GAIN_RATE × ln(1 + C/2)
 *   P(T)  =  PENALTY_RATIO_MIN + tierIndex   (linear 3→10 across T0-T7)
 *
 * Spec reference: ATSF whitepaper §5 (gain/loss equations)
 */

import { describe, it, expect } from 'vitest';
import {
  calculateGain,
  calculateLoss,
  penaltyRatio,
  PENALTY_RATIO_MIN,
  PENALTY_RATIO_MAX,
  GAIN_RATE,
  MAX_TRUST_SCORE,
  RISK_LEVELS,
} from '@basis-spec/basis';

const CEILING = MAX_TRUST_SCORE;
const riskMul = (name: 'READ' | 'LOW' | 'MEDIUM' | 'HIGH'): number =>
  (RISK_LEVELS as Record<string, { multiplier: number }>)[name].multiplier;

describe('trust/penaltyRatio: P(T) = 3 + T', () => {
  it('penaltyRatio(0) = PENALTY_RATIO_MIN (= 3)', () => {
    expect(penaltyRatio(0)).toBe(PENALTY_RATIO_MIN);
  });

  it('penaltyRatio(7) = PENALTY_RATIO_MAX (= 10)', () => {
    expect(penaltyRatio(7)).toBe(PENALTY_RATIO_MAX);
  });

  it('penaltyRatio is strictly increasing across all 8 tiers', () => {
    let prev = -Infinity;
    for (let t = 0; t <= 7; t++) {
      const p = penaltyRatio(t);
      expect(p).toBeGreaterThan(prev);
      prev = p;
    }
  });

  it('penaltyRatio increments by 1 per tier (linear)', () => {
    for (let t = 1; t <= 7; t++) {
      expect(penaltyRatio(t) - penaltyRatio(t - 1)).toBeCloseTo(1, 9);
    }
  });

  it('penaltyRatio out of range throws', () => {
    expect(() => penaltyRatio(-1)).toThrow();
    expect(() => penaltyRatio(8)).toThrow();
  });
});

describe('trust/calculateGain: monotonic + sign-correct', () => {
  it('gain is positive for valid inputs', () => {
    const g = calculateGain({
      currentScore: 0,
      ceiling: CEILING,
      riskMultiplier: riskMul('LOW'),
    });
    expect(g).toBeGreaterThan(0);
  });

  it('gain matches spec formula exactly at (currentScore=0, ceiling=MAX, READ)', () => {
    const r = riskMul('READ');
    const expected = GAIN_RATE * Math.log(1 + CEILING) * Math.cbrt(r);
    const actual = calculateGain({
      currentScore: 0,
      ceiling: CEILING,
      riskMultiplier: r,
    });
    expect(actual).toBeCloseTo(expected, 6);
  });

  it('gain decreases as currentScore approaches ceiling (headroom shrinks)', () => {
    const r = riskMul('MEDIUM');
    const low = calculateGain({
      currentScore: 100,
      ceiling: CEILING,
      riskMultiplier: r,
    });
    const high = calculateGain({
      currentScore: 900,
      ceiling: CEILING,
      riskMultiplier: r,
    });
    expect(low).toBeGreaterThan(high);
  });

  it('gain is zero when currentScore equals ceiling', () => {
    const g = calculateGain({
      currentScore: CEILING,
      ceiling: CEILING,
      riskMultiplier: riskMul('MEDIUM'),
    });
    expect(g).toBe(0);
  });

  it('higher risk action earns more (cube-root scaling)', () => {
    const lowGain = calculateGain({
      currentScore: 500,
      ceiling: CEILING,
      riskMultiplier: riskMul('READ'),
    });
    const highGain = calculateGain({
      currentScore: 500,
      ceiling: CEILING,
      riskMultiplier: riskMul('HIGH'),
    });
    expect(highGain).toBeGreaterThan(lowGain);
  });
});

describe('trust/calculateLoss: negative + tier-amplified', () => {
  it('loss is negative for valid inputs', () => {
    const l = calculateLoss({
      tierIndex: 3,
      ceiling: CEILING,
      riskMultiplier: riskMul('MEDIUM'),
    });
    expect(l).toBeLessThan(0);
  });

  it('higher tier => deeper loss (P(T) scales 3× → 10×)', () => {
    const r = riskMul('HIGH');
    const t0Loss = calculateLoss({
      tierIndex: 0,
      ceiling: CEILING,
      riskMultiplier: r,
    });
    const t7Loss = calculateLoss({
      tierIndex: 7,
      ceiling: CEILING,
      riskMultiplier: r,
    });
    expect(t7Loss).toBeLessThan(t0Loss);
  });

  it('|loss| at T7 / |loss| at T0 = 10/3 (penalty-ratio shape)', () => {
    const r = riskMul('MEDIUM');
    const t0 = Math.abs(
      calculateLoss({ tierIndex: 0, ceiling: CEILING, riskMultiplier: r }),
    );
    const t7 = Math.abs(
      calculateLoss({ tierIndex: 7, ceiling: CEILING, riskMultiplier: r }),
    );
    expect(t7 / t0).toBeCloseTo(10 / 3, 6);
  });

  it('loss matches spec formula exactly at (T3, MEDIUM, MAX ceiling)', () => {
    const r = riskMul('MEDIUM');
    const expected =
      -penaltyRatio(3) * r * GAIN_RATE * Math.log(1 + CEILING / 2);
    const actual = calculateLoss({
      tierIndex: 3,
      ceiling: CEILING,
      riskMultiplier: r,
    });
    expect(actual).toBeCloseTo(expected, 6);
  });
});
