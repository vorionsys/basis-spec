// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS reference-scorer conformance — encodes the 11 tier-reconcile checks
 * (no-drift, CAR projection, fail-closed effectiveTier) plus the composite
 * pipeline, the golden vectors, and determinism.
 *
 * Mirrors SAM APP/tier-reconcile-verify.mjs and TIER_RECONCILIATION §6.
 */

import { describe, it, expect } from 'vitest';
import { TRUST_TIERS, MIN_TRUST_SCORE, MAX_TRUST_SCORE } from '@vorionsys/basis-spec';
import {
  CAR_TO_T, T_TO_CAR, OBS_MAXTIER, toT, projectCarToT, projectTToCar, effectiveTier,
  computeCompositeScore, scoreTrust, CANONICAL_FACTOR_IDS, TOTAL_FACTORS,
  CAR_PROJECTION_VECTORS, EFFECTIVE_TIER_VECTORS, COMPOSITE_VECTORS,
} from './index.js';

// --- Group 1: no-drift vs @vorionsys/basis-spec -----------------------------
describe('no-drift: tier lattice is byte-identical to @vorionsys/basis-spec', () => {
  const tiers = Object.entries(TRUST_TIERS).map(([k, v]) => ({ k, ...(v as { min: number; max: number }) }));

  it('exactly 8 tiers T0..T7', () => {
    expect(tiers.map((t) => t.k)).toEqual(['T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7']);
  });

  it('the partition is contiguous and exhaustive over [0,1000]', () => {
    expect(tiers[0]!.min).toBe(MIN_TRUST_SCORE);
    expect(tiers[tiers.length - 1]!.max).toBe(MAX_TRUST_SCORE);
    for (let i = 1; i < tiers.length; i++) {
      expect(tiers[i]!.min).toBe(tiers[i - 1]!.max + 1); // no gaps, no overlaps
    }
  });

  it('OBS_MAXTIER derives from canonical OBSERVATION_TIERS (TEE-stubbed → WHITE_BOX caps at T6)', () => {
    expect(OBS_MAXTIER).toEqual({ BLACK_BOX: 3, GRAY_BOX: 4, WHITE_BOX: 6, ATTESTED_BOX: 6, VERIFIED_BOX: 7 });
  });

  it('there are exactly 16 canonical factors', () => {
    expect(TOTAL_FACTORS).toBe(16);
    expect(CANONICAL_FACTOR_IDS.length).toBe(16);
  });
});

// --- Group 2: CAR-5 ⇄ T0–T7 projection --------------------------------------
describe('CAR-5 ⇄ T0–T7 projection (frozen)', () => {
  it('monotonic CAR→T: [0,1,3,5,6]', () => {
    expect(Object.values(CAR_TO_T)).toEqual([0, 1, 3, 5, 6]);
    const ts = CAR_PROJECTION_VECTORS.map((v) => projectCarToT(v.car));
    for (let i = 1; i < ts.length; i++) expect(ts[i]!).toBeGreaterThan(ts[i - 1]!);
  });

  it('round-trip CAR→T→CAR is identity (stable)', () => {
    for (const { car } of CAR_PROJECTION_VECTORS) {
      expect(projectTToCar(projectCarToT(car))).toBe(car);
    }
  });

  it('coarsening T→CAR→T always rounds DOWN (no over-grant)', () => {
    for (let t = 0; t <= 7; t++) {
      const round = projectCarToT(projectTToCar(t as 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7));
      expect(round).toBeLessThanOrEqual(t);
    }
  });

  it('golden CAR vectors match', () => {
    for (const v of CAR_PROJECTION_VECTORS) expect(projectCarToT(v.car)).toBe(v.t);
  });
});

// --- Group 3: effectiveTier = min(...) fail-closed --------------------------
describe('effectiveTier = min(...) fails closed', () => {
  for (const v of EFFECTIVE_TIER_VECTORS) {
    it(v.name, () => {
      const r = effectiveTier(v.input);
      expect(r.effectiveIndex).toBe(v.expect.effectiveIndex);
      expect(r.failClosed).toBe(v.expect.failClosed);
    });
  }

  it('toT never inflates: garbage / null / out-of-range → 0', () => {
    expect(toT(null)).toBe(0);
    expect(toT(undefined)).toBe(0);
    expect(toT('SUPER_ADMIN')).toBe(0);
    expect(toT(9)).toBe(0);
    expect(toT(-1)).toBe(0);
    expect(toT(3.5)).toBe(0);
    expect(toT('T5')).toBe(5);
    expect(toT('TRUSTED')).toBe(5);
    expect(toT(2)).toBe(2);
  });
});

// --- Group 4: composite / observation-ceiling pipeline + golden vectors -----
describe('reference scorer: evidence → score → tier', () => {
  for (const v of COMPOSITE_VECTORS) {
    it(v.name, () => {
      expect(computeCompositeScore(v.factorScores)).toBe(v.expect.composite);
      const r = scoreTrust({ factorScores: v.factorScores, observation: v.observation, verified: true });
      expect(r.compositeScore).toBe(v.expect.composite);
      expect(r.adjustedScore).toBe(v.expect.adjusted);
      expect(r.recomputedTier).toBe(v.expect.recomputedTier);
    });
  }

  it('end-to-end: a claimed tier above the recomputed/ceiling is pulled DOWN', () => {
    // claim T7, but only 0.5 evidence under BLACK_BOX (ceiling 600 → T3)
    const r = scoreTrust({
      factorScores: COMPOSITE_VECTORS[2]!.factorScores, // uniform 0.5 → composite 500
      observation: 'BLACK_BOX', claimedTier: 'T7', verified: true,
    });
    expect(r.recomputedTier).toBe('T3');          // 500 under BLACK_BOX is still T3
    expect(r.effective.effectiveIndex).toBe(3);   // min(7, 3, BLACK_BOX→3) = 3
    expect(r.effective.binding).not.toBe('claimed');
  });

  it('unverified evidence fails the whole score closed to T0', () => {
    const r = scoreTrust({ factorScores: COMPOSITE_VECTORS[0]!.factorScores, observation: 'VERIFIED_BOX', verified: false });
    expect(r.recomputedTier).toBe('T7');        // recomputation still T7
    expect(r.effective.effectiveIndex).toBe(0); // but unverified → effective T0
    expect(r.effective.binding).toBe('unverified');
  });
});

// --- Group 5: determinism (RP-recomputable, byte-identical) ------------------
describe('determinism', () => {
  it('scoreTrust is a pure function of its input (run twice → deep-equal)', () => {
    const input = { factorScores: COMPOSITE_VECTORS[0]!.factorScores, observation: 'WHITE_BOX' as const, claimedTier: 'T5', verified: true };
    expect(scoreTrust(input)).toEqual(scoreTrust(input));
  });

  it('computeCompositeScore is order-independent and stable', () => {
    const a = computeCompositeScore({ 'CT-COMP': 1, 'CT-REL': 0.5 });
    const b = computeCompositeScore({ 'CT-REL': 0.5, 'CT-COMP': 1 });
    expect(a).toBe(b);
  });
});
