// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * @vorionsys/basis-scorer — the BASIS reference scorer.
 *
 * A pure, deterministic, fail-closed function that RE-COMPUTES an agent's
 * trust score and tier from a structurally + signature/linkage validated
 * proof-event chain (RFC-0002), reusing the canonical formulas from
 * @vorionsys/basis-spec. It treats the client's claimed tier and any
 * asserted trust_delta as an UPPER BOUND and a cross-check only — so the
 * effective tier is min(claimed, recomputed, caps) and can only be lowered.
 *
 * See the package README for the explicit v0.1 scope and deferred items.
 *
 * Usage:
 *   import { scoreChain } from '@vorionsys/basis-scorer';
 *   const result = scoreChain(events, {
 *     observationTier: 'GRAY_BOX',
 *     riskByActionType: { 'db.write': 'MEDIUM' },
 *     claimedTier: 'T5',
 *   });
 *   // result.effectiveTier is min(recomputed, observation, policy, claimed)
 */

export { scoreChain, effectiveTier } from './scorer.js';
export { parseOccurredAtNanos } from './time.js';
export { hashPolicy } from './policy-hash.js';
export {
  DEFAULT_PRECISION,
  quantize,
  unscale,
  clampScaled,
} from './fixed.js';
export type {
  ScoringPolicy,
  ScoreResult,
  ScoreStatus,
  CircuitBreakerState,
  Divergence,
  RiskKey,
} from './types.js';
