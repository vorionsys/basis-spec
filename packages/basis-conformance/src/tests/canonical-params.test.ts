// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Canonical parameters test — every published BASIS constant has the
 * exact value the spec text and ATSF whitepapers cite. If any of these
 * fail, the canonical TypeScript impl has drifted from the spec it
 * claims to encode.
 *
 * Spec reference: ATSF whitepaper §4 (parameters), RFC-0001 (manifest)
 */

import { describe, it, expect } from 'vitest';
import {
  MIN_TRUST_SCORE,
  MAX_TRUST_SCORE,
  INITIAL_TRUST_SCORE,
  QUALIFICATION_PASS_SCORE,
  GAIN_RATE,
  PENALTY_RATIO_MIN,
  PENALTY_RATIO_MAX,
  HYSTERESIS,
  PROMOTION_DELAYS,
  TRUST_TIERS,
  RISK_LEVELS,
  TRUST_INHERITANCE,
  BASIS_SPEC_VERSION,
} from '@basis-spec/basis';

describe('canonical/params: trust-score range', () => {
  it('MIN_TRUST_SCORE = 0', () => {
    expect(MIN_TRUST_SCORE).toBe(0);
  });

  it('MAX_TRUST_SCORE = 1000', () => {
    expect(MAX_TRUST_SCORE).toBe(1000);
  });

  it('INITIAL_TRUST_SCORE = 0 (PROVISIONING starts at zero)', () => {
    expect(INITIAL_TRUST_SCORE).toBe(0);
  });

  it('QUALIFICATION_PASS_SCORE = 200 (training course earns T1)', () => {
    expect(QUALIFICATION_PASS_SCORE).toBe(200);
  });

  it('TRUST_INHERITANCE = "NONE" (every agent starts fresh)', () => {
    expect(TRUST_INHERITANCE).toBe('NONE');
  });
});

describe('canonical/params: gain & penalty constants', () => {
  it('GAIN_RATE = 0.05', () => {
    expect(GAIN_RATE).toBe(0.05);
  });

  it('PENALTY_RATIO_MIN = 3 (T0 P-factor)', () => {
    expect(PENALTY_RATIO_MIN).toBe(3);
  });

  it('PENALTY_RATIO_MAX = 10 (T7 P-factor)', () => {
    expect(PENALTY_RATIO_MAX).toBe(10);
  });

  it('PENALTY_RATIO_MAX - PENALTY_RATIO_MIN = number of tiers - 1 (linear scaling 3→10 across T0-T7)', () => {
    const tierCount = Object.keys(TRUST_TIERS).length;
    expect(PENALTY_RATIO_MAX - PENALTY_RATIO_MIN).toBe(tierCount - 1);
  });
});

describe('canonical/params: tier system', () => {
  it('exactly 8 tiers (T0-T7)', () => {
    expect(Object.keys(TRUST_TIERS)).toHaveLength(8);
  });

  it('tier ids are T0..T7', () => {
    const ids = Object.keys(TRUST_TIERS).sort();
    expect(ids[0]).toBe('T0');
    expect(ids[7]).toBe('T7');
  });

  it('tier ranges (min, max) are strictly increasing and non-overlapping', () => {
    type Range = { min: number; max: number };
    const tiers = Object.values(TRUST_TIERS) as Array<Range>;
    const sorted = [...tiers].sort((a, b) => a.min - b.min);
    for (let i = 1; i < sorted.length; i++) {
      expect(sorted[i].min).toBeGreaterThan(sorted[i - 1].max);
    }
  });

  it('T0 starts at 0 and T7 reaches 1000 (full score range covered)', () => {
    const t = TRUST_TIERS as Record<string, { min: number; max: number }>;
    expect(t.T0.min).toBe(0);
    expect(t.T7.max).toBe(1000);
  });
});

describe('canonical/params: risk levels', () => {
  it('exactly 6 risk levels', () => {
    expect(Object.keys(RISK_LEVELS)).toHaveLength(6);
  });

  it('contains READ, LOW, MEDIUM, HIGH, CRITICAL, LIFE_CRITICAL', () => {
    const names = Object.keys(RISK_LEVELS);
    for (const expected of [
      'READ',
      'LOW',
      'MEDIUM',
      'HIGH',
      'CRITICAL',
      'LIFE_CRITICAL',
    ]) {
      expect(names).toContain(expected);
    }
  });

  it('risk multipliers are strictly increasing in canonical order', () => {
    // Canonical order from ATSF whitepaper.
    const order: ReadonlyArray<string> = [
      'READ',
      'LOW',
      'MEDIUM',
      'HIGH',
      'CRITICAL',
      'LIFE_CRITICAL',
    ];
    const muls = order.map(
      (name) =>
        (RISK_LEVELS as Record<string, { multiplier: number }>)[name].multiplier,
    );
    for (let i = 1; i < muls.length; i++) {
      expect(muls[i]).toBeGreaterThan(muls[i - 1]);
    }
  });

  it('READ multiplier = 1, LIFE_CRITICAL multiplier = 30 (canonical anchors)', () => {
    expect(
      (RISK_LEVELS as Record<string, { multiplier: number }>).READ.multiplier,
    ).toBe(1);
    expect(
      (RISK_LEVELS as Record<string, { multiplier: number }>).LIFE_CRITICAL
        .multiplier,
    ).toBe(30);
  });
});

describe('canonical/params: hysteresis & promotion delays', () => {
  it('HYSTERESIS = [25, 25, 20, 20, 15, 10, 10, 10] (one entry per tier)', () => {
    expect([...HYSTERESIS]).toEqual([25, 25, 20, 20, 15, 10, 10, 10]);
  });

  it('PROMOTION_DELAYS = [0, 0, 0, 0, 0, 7, 10, 14] days (T5/T6/T7 are time-gated)', () => {
    expect([...PROMOTION_DELAYS]).toEqual([0, 0, 0, 0, 0, 7, 10, 14]);
  });

  it('hysteresis count matches tier count', () => {
    expect(HYSTERESIS.length).toBe(Object.keys(TRUST_TIERS).length);
  });

  it('promotion-delay count matches tier count', () => {
    expect(PROMOTION_DELAYS.length).toBe(Object.keys(TRUST_TIERS).length);
  });
});

describe('canonical/params: spec version', () => {
  it('BASIS_SPEC_VERSION is a semver string', () => {
    expect(BASIS_SPEC_VERSION).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z-.]+)?$/);
  });
});
