// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import {
  TRUST_FACTORS,
  TOTAL_CORE_FACTORS,
  MAX_TRUST_SCORE,
  MIN_TRUST_SCORE,
  OBSERVATION_TIERS,
  tierFromScore,
  type TrustFactorId,
  type ObservationTier,
} from '@vorionsys/basis-spec';
import { effectiveTier, type EffectiveTierResult } from './reconciliation.js';

/** Canonical factor IDs in definition order (16 factors). */
export const CANONICAL_FACTOR_IDS = Object.keys(TRUST_FACTORS) as TrustFactorId[];

/** Total canonical trust factors. */
export const TOTAL_FACTORS = TOTAL_CORE_FACTORS;

/** Per-factor evidence score in [0, 1]. Missing entries count as 0 (no-inflation). */
export type FactorScores = Partial<Record<TrustFactorId, number>>;

/**
 * Composite trust score from factor evidence, 0–1000.
 * Missing factors count as 0 so partial evidence never inflates the score.
 */
export function computeCompositeScore(fs: FactorScores): number {
  const sum = CANONICAL_FACTOR_IDS.reduce((acc, id) => acc + (fs[id] ?? 0), 0);
  const raw = (sum / TOTAL_FACTORS) * MAX_TRUST_SCORE;
  return Math.min(MAX_TRUST_SCORE, Math.max(MIN_TRUST_SCORE, raw));
}

export interface ScoreTrustInput {
  factorScores: FactorScores;
  observation: ObservationTier;
  verified?: boolean;
  claimedTier?: string;
}

export interface ScoreTrustResult {
  compositeScore: number;
  adjustedScore: number;
  recomputedTier: string;
  effective: EffectiveTierResult;
}

/**
 * Full factor→score→tier pipeline with observation ceiling and effective-tier binding.
 * verified=false forces effective to T0 (fail-closed); recomputedTier is still derived.
 */
export function scoreTrust(input: ScoreTrustInput): ScoreTrustResult {
  const { factorScores, observation, verified = true, claimedTier } = input;
  const compositeScore = computeCompositeScore(factorScores);

  const obsTierSpec = (OBSERVATION_TIERS as Record<string, { ceiling: number; maxTier: string } | undefined>)[observation as string];
  const ceiling = obsTierSpec ? obsTierSpec.ceiling : MIN_TRUST_SCORE;

  const adjustedScore = Math.min(compositeScore, ceiling);
  const recomputedTier = tierFromScore(
    Math.min(MAX_TRUST_SCORE, Math.max(MIN_TRUST_SCORE, adjustedScore)),
  );

  const recomputedIndex = parseInt(recomputedTier.slice(1), 10);
  const effective = effectiveTier({
    claimed: claimedTier,
    recomputed: recomputedIndex,
    observation,
    verified,
  });

  return { compositeScore, adjustedScore, recomputedTier, effective };
}
