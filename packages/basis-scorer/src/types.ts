// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import type {
  ObservationTier,
  RiskLevel,
  TrustTier,
} from '@vorionsys/basis-spec';

/** A risk key from the canonical RISK_LEVELS table. */
export type RiskKey = RiskLevel;

/**
 * Provenance of a resolved per-outcome risk multiplier (RFC-0002.1).
 *
 * Surfaced for honesty/attribution: a consumer can tell whether an action's
 * risk came from SIGNED in-chain evidence or from an out-of-chain policy.
 *
 *   - `'chain'`      — the signed `intent_received.riskLevel` was used
 *                      (RFC-0002.1 in-chain evidence — preferred).
 *   - `'policy'`     — fell back to `policy.riskByActionType` because the
 *                      chain carried no signed risk (deprecated path).
 *   - `'failclosed'` — neither resolved (broken link, unmapped action, or no
 *                      signed risk + no mapping); pinned to the max-configured
 *                      `defaultRisk` (LIFE_CRITICAL by default).
 */
export type RiskSource = 'chain' | 'policy' | 'failclosed';

/**
 * The scoring policy. This is UNTRUSTED, caller-supplied input (see
 * `policy-hash.ts`). It is hashed into the result (`policyHash`) for
 * reproducibility and attribution.
 *
 * RFC-0002.1: when an action's `intent_received` event carries a SIGNED,
 * in-chain `riskLevel`, that value is PREFERRED and the policy's
 * `riskByActionType` mapping is NOT consulted for that action. The policy
 * mapping is now a FALLBACK for RFC-0002.0 chains (and unmapped actions). The
 * caller therefore no longer controls the risk multiplier for any action whose
 * chain carries signed risk — that integrity moved into the signed evidence.
 */
export interface ScoringPolicy {
  /** Observation tier — governs the score ceiling and the max tier cap. */
  readonly observationTier: ObservationTier;

  /**
   * Explicit map from a free-form `intent_received.actionType` to a canonical
   * risk key. Anything not present here resolves to `defaultRisk`.
   *
   * RFC-0002.1: this is now a FALLBACK only. It is consulted for an action
   * exactly when that action's `intent_received` event does NOT carry a signed
   * in-chain `riskLevel`. In-chain risk takes precedence (see `RiskSource`).
   */
  readonly riskByActionType: Readonly<Record<string, RiskKey>>;

  /**
   * Risk applied when an actionType is absent, unknown, unmapped, or the
   * linkage to it is broken. Defaults to `'LIFE_CRITICAL'` (the maximum
   * configured risk) so an unrecognised action can never earn cheap gain and
   * is maximally penalised on failure. Fail closed.
   */
  readonly defaultRisk?: RiskKey;

  /** Optional hard policy tier cap applied on top of the observation cap. */
  readonly ceilingTier?: TrustTier;

  /**
   * Gates ATTESTED_BOX / VERIFIED_BOX. TEE/attestation verifiers are stubs
   * ecosystem-wide, so absent an explicit, verifiable assertion the scorer
   * downgrades ATTESTED/VERIFIED to WHITE_BOX (the honest cap). Default false.
   */
  readonly assertVerifiedObservation?: boolean;

  /** Pinned quantization scale for deterministic arithmetic. Default 1e6. */
  readonly precision?: number;

  /**
   * The client's asserted tier — an UPPER BOUND only. The recomputation can
   * lower it but never raise it. Missing means the client imposes no upper
   * bound (the observation/policy caps still apply). It is explicitly NOT
   * treated as T7-if-missing (that would let a missing claim raise the
   * result — the opposite of fail-closed).
   */
  readonly claimedTier?: TrustTier;
}

/** A single recompute-vs-claimed divergence (advisory evidence, not enforcement). */
export interface Divergence {
  /** The eventId that carried the claim. */
  readonly eventId: string;
  /** Which claim diverged. */
  readonly kind: 'trust_delta' | 'decision_score';
  /** The runtime's claimed value. */
  readonly claimed: number;
  /** The scorer's independently recomputed value. */
  readonly recomputed: number;
}

/**
 * Per-outcome risk-resolution record (RFC-0002.1). One entry per
 * execution outcome (`execution_completed` / `execution_failed`) that the
 * scorer resolved a risk multiplier for. Surfaced for honesty/attribution:
 * a consumer can audit, per action, whether risk came from signed in-chain
 * evidence (`'chain'`), the out-of-chain policy fallback (`'policy'`), or a
 * fail-closed default (`'failclosed'`).
 */
export interface RiskResolutionRecord {
  /** The execution-outcome eventId the risk was resolved for. */
  readonly eventId: string;
  /** The resolved canonical risk key. */
  readonly risk: RiskKey;
  /** Where the risk came from. */
  readonly source: RiskSource;
}

/** Circuit-breaker state derived from the recomputed score + risk accumulator. */
export type CircuitBreakerState = 'NONE' | 'DEGRADED' | 'TRIPPED';

/** Overall scorer status. */
export type ScoreStatus = 'OK' | 'DEGRADED' | 'TRIPPED' | 'FAIL_CLOSED';

/**
 * The result of scoring a chain. Deterministic: the same chain + same policy
 * produces a byte-identical `ScoreResult` on any platform.
 */
export interface ScoreResult {
  /**
   * The recomputed trust score. A quantized FIXED-PRECISION DECIMAL in
   * [0, 1000] (NOT an integer — real scores are fractional, e.g. 200.265).
   * Quantized via round-half-even at `policy.precision`.
   */
  readonly recomputedScore: number;

  /** `tierFromScore(recomputedScore)` — the score-derived tier, uncapped. */
  readonly recomputedTier: TrustTier;

  /** The tier after the observation-tier cap (and honest TEE downgrade). */
  readonly observationCappedTier: TrustTier;

  /**
   * The effective tier: `min(recomputedTier, observationCappedTier,
   * policy.ceilingTier, claimedTier)`, with a T0 floor when the circuit
   * breaker is tripped. THIS min() — not the divergence flag — is the
   * mechanism that makes `effectiveTier = min(claimed, recomputed)` real.
   */
  readonly effectiveTier: TrustTier;

  /** Overall status. `FAIL_CLOSED` sets `error`. */
  readonly status: ScoreStatus;

  /** Circuit-breaker state. */
  readonly circuitBreaker: CircuitBreakerState;

  /** Peak rolling 24h risk-accumulator value observed (over occurredAt). */
  readonly riskAccumulator24h: number;

  /** Recompute-vs-claimed divergences (advisory). */
  readonly divergences: ReadonlyArray<Divergence>;

  /**
   * Per-outcome risk-resolution records (RFC-0002.1), in scored order. Lets a
   * consumer attribute every gain/loss to whether its risk came from signed
   * in-chain evidence (`source:'chain'`), the policy fallback
   * (`source:'policy'`), or a fail-closed default (`source:'failclosed'`).
   */
  readonly riskResolutions: ReadonlyArray<RiskResolutionRecord>;

  /**
   * True if any divergence where the claim exceeded the recomputed value was
   * seen. ADVISORY only: a sophisticated runtime controls its own claimed
   * numbers and can make `claimed == recomputed` to evade this flag. The real
   * defence is `effectiveTier = min(...)`, not this flag. Do not over-state.
   */
  readonly overClaim: boolean;

  /** Diagnostic flags: unscorable events, broken links, obs downgrades, etc. */
  readonly flags: ReadonlyArray<string>;

  /** Count of execution-outcome events that actually moved the score. */
  readonly scoredEventCount: number;

  /**
   * SHA-256 (hex) of the canonical-JSON policy used. The policy is untrusted
   * input controlling risk; this makes the recomputation reproducible and
   * attributable. Risk integrity depends on policy integrity (out of chain).
   */
  readonly policyHash: string;

  /** Set only when `status === 'FAIL_CLOSED'`. */
  readonly error?: string;
}
