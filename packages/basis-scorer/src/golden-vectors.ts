// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS — golden test vectors for the reference scorer.
 *
 * These are the canonical, frozen input→output pairs a relying party recomputes
 * locally to prove its scorer build matches the spec byte-for-byte. They cover:
 *   - the CAR-5 ⇄ T0–T7 projection (monotonic, round-trip, down-safe),
 *   - the 5 fail-closed effectiveTier cases (mirrors tier-reconcile-verify.mjs),
 *   - the composite/observation-ceiling pipeline.
 * Importable so downstream conformance suites can assert against the same data.
 */

import type { ObservationTier } from '@vorionsys/basis-spec';
import { CANONICAL_FACTOR_IDS, type FactorScores } from './composite.js';
import type { TierIndex, CarTier, EffectiveTierInput } from './reconciliation.js';

// --- helpers to build full / partial factor maps deterministically ----------
function uniform(v: number): FactorScores {
  const o: FactorScores = {};
  for (const id of CANONICAL_FACTOR_IDS) o[id] = v;
  return o;
}
function firstN(n: number, v: number): FactorScores {
  const o: FactorScores = {};
  CANONICAL_FACTOR_IDS.slice(0, n).forEach((id) => { o[id] = v; });
  return o;
}

// --- CAR-5 projection -------------------------------------------------------
export const CAR_PROJECTION_VECTORS: ReadonlyArray<{ car: CarTier; t: TierIndex }> = [
  { car: 'UNKNOWN', t: 0 },
  { car: 'BASIC', t: 1 },
  { car: 'VERIFIED', t: 3 },
  { car: 'TRUSTED', t: 5 },
  { car: 'PRIVILEGED', t: 6 },
];

// --- effectiveTier (the 5 fail-closed cases) --------------------------------
export interface EffectiveTierVector {
  name: string;
  input: EffectiveTierInput;
  expect: { effectiveIndex: TierIndex; failClosed: boolean };
}
export const EFFECTIVE_TIER_VECTORS: ReadonlyArray<EffectiveTierVector> = [
  { name: 'min(T5 claim, T4 recomp, BLACK_BOX→T3) = T3',
    input: { claimed: 5, recomputed: 4, observation: 'BLACK_BOX', verified: true },
    expect: { effectiveIndex: 3, failClosed: false } },
  { name: 'happy path min(T6, T7, WHITE_BOX→T6) = T6',
    input: { claimed: 6, recomputed: 7, observation: 'WHITE_BOX', verified: true },
    expect: { effectiveIndex: 6, failClosed: false } },
  { name: 'unverified fails closed to T0',
    input: { claimed: 7, recomputed: 7, observation: 'VERIFIED_BOX', verified: false },
    expect: { effectiveIndex: 0, failClosed: true } },
  { name: 'unknown observation tier fails closed to T0',
    input: { claimed: 5, recomputed: 5, observation: 'NONSENSE', verified: true },
    expect: { effectiveIndex: 0, failClosed: true } },
  { name: 'unmappable claim string does not inflate (→ T0)',
    input: { claimed: 'SUPER_ADMIN', recomputed: 5, observation: 'WHITE_BOX', verified: true },
    expect: { effectiveIndex: 0, failClosed: true } },
];

// --- composite / observation-ceiling pipeline -------------------------------
export interface CompositeVector {
  name: string;
  factorScores: FactorScores;
  observation: ObservationTier;
  expect: { composite: number; adjusted: number; recomputedTier: string };
}
export const COMPOSITE_VECTORS: ReadonlyArray<CompositeVector> = [
  { name: 'all 16 factors max, VERIFIED_BOX → 1000 → T7',
    factorScores: uniform(1.0), observation: 'VERIFIED_BOX',
    expect: { composite: 1000, adjusted: 1000, recomputedTier: 'T7' } },
  { name: 'all 16 factors max but BLACK_BOX caps the score at 600 → T3',
    factorScores: uniform(1.0), observation: 'BLACK_BOX',
    expect: { composite: 1000, adjusted: 600, recomputedTier: 'T3' } },
  { name: 'all 16 factors at 0.5, WHITE_BOX → 500 → T3',
    factorScores: uniform(0.5), observation: 'WHITE_BOX',
    expect: { composite: 500, adjusted: 500, recomputedTier: 'T3' } },
  { name: 'only 8 of 16 factors maxed (no-inflation) → 500 → T3',
    factorScores: firstN(8, 1.0), observation: 'WHITE_BOX',
    expect: { composite: 500, adjusted: 500, recomputedTier: 'T3' } },
];
