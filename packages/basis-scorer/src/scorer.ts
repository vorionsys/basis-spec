// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS — reference scorer: deterministic `evidence → score → tier`.
 *
 *   compositeScore = mean over ALL 16 canonical factors (missing → 0) × 1000
 *   adjustedScore  = min(compositeScore, OBSERVATION_TIERS[observation].ceiling)
 *   recomputedTier = tierFromScore(adjustedScore)
 *   effectiveTier  = min(claimed, recomputed, observationCap, localCeiling)  [fail-closed]
 *
 * Everything is pure integer/rational arithmetic over canonical constants, so a
 * relying party recomputes a byte-identical result. This is the Stage-3
 * reference function the architecture calls for, so the tier can stop being a
 * bare client input: `effectiveTier = min(claimed, recomputed, …)` binds the
 * LOWER of the claim and the independent recomputation.
 */

import {
  TRUST_FACTORS, OBSERVATION_TIERS, MIN_TRUST_SCORE, MAX_TRUST_SCORE, BASIS_SPEC_VERSION, tierFromScore,
} from '@vorionsys/basis-spec';
import type { TrustTier, ObservationTier, TrustFactorId } from '@vorionsys/basis-spec';
import { effectiveTier, toT, type EffectiveTierResult, type TierIndex } from './reconciliation.js';

/** This package's own version (bump with package.json). */
export const BASIS_SCORER_VERSION = '0.1.0';

/** The 16 canonical factor ids, in canonical order. */
export const CANONICAL_FACTOR_IDS = Object.keys(TRUST_FACTORS) as TrustFactorId[];
export const TOTAL_FACTORS = CANONICAL_FACTOR_IDS.length;

/** Per-factor evidence scores in [0,1]. Missing factors count as 0 (no inflation). */
export type FactorScores = Partial<Record<TrustFactorId, number>>;

const clamp01 = (v: number): number => (v < 0 ? 0 : v > 1 ? 1 : v);
const clampScore = (v: number): number => Math.max(MIN_TRUST_SCORE, Math.min(MAX_TRUST_SCORE, v));

/**
 * Composite score = mean over ALL 16 canonical factors (missing → 0) × 1000.
 * Averaging over the FULL factor set is the no-inflation reference choice: you
 * cannot raise your tier by omitting a weak factor.
 *
 * Note: @vorionsys/contracts `calculateCompositeScore` currently averages over
 * the PROVIDED factors only — a known inflation gap this reference scorer
 * deliberately closes (see TIER_RECONCILIATION; the reference function must not
 * over-grant).
 */
export function computeCompositeScore(factorScores: FactorScores): number {
  let sum = 0;
  for (const id of CANONICAL_FACTOR_IDS) sum += clamp01(factorScores[id] ?? 0);
  return Math.round((sum / TOTAL_FACTORS) * 1000);
}

/** Observation ceiling (a score cap) from canonical OBSERVATION_TIERS. */
export function observationCeiling(observation: ObservationTier): number {
  return OBSERVATION_TIERS[observation].ceiling;
}

export interface ScoreTrustInput {
  factorScores: FactorScores;
  observation: ObservationTier;
  /** Optional client-claimed tier; coerced + min'd in. Absent → uses recomputed. */
  claimedTier?: unknown;
  /** RP local policy ceiling (default T7 = no extra cap). */
  localCeilingTier?: unknown;
  /** Proof chain log-verified + re-derived? Default false → fail closed to T0. */
  verified?: boolean;
}

export interface ScoreTrustResult {
  compositeScore: number;     // 0..1000 pre-ceiling
  observationCeiling: number; // score cap for the observation tier
  adjustedScore: number;      // min(composite, ceiling)
  recomputedTier: TrustTier;  // tierFromScore(adjustedScore)
  recomputedIndex: TierIndex;
  effective: EffectiveTierResult; // fail-closed min(...) authority binding
  spec: { scorer: string; basisSpec: string };
}

/** Full pipeline: factor evidence → composite → ceiling → recomputed tier → effectiveTier. */
export function scoreTrust(input: ScoreTrustInput): ScoreTrustResult {
  const compositeScore = computeCompositeScore(input.factorScores);
  const ceiling = observationCeiling(input.observation);
  const adjustedScore = clampScore(Math.min(compositeScore, ceiling));
  const recomputedTier = tierFromScore(adjustedScore);
  const recomputedIndex = toT(recomputedTier);

  const effective = effectiveTier({
    claimed: input.claimedTier == null ? recomputedTier : input.claimedTier,
    recomputed: recomputedTier,
    observation: input.observation,
    localCeiling: input.localCeilingTier,
    verified: input.verified ?? false,
  });

  return {
    compositeScore,
    observationCeiling: ceiling,
    adjustedScore,
    recomputedTier,
    recomputedIndex,
    effective,
    spec: { scorer: BASIS_SCORER_VERSION, basisSpec: BASIS_SPEC_VERSION },
  };
}
