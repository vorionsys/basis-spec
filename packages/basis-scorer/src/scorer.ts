// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS reference scorer — the pure, deterministic, fail-closed function
 * that RE-COMPUTES an agent's trust score and tier from a validated
 * proof-event chain.
 *
 * "Invert the artifact, not the trust." The client's claimed tier and any
 * `trust_delta.newScore` it asserts are treated as an UPPER BOUND and a
 * cross-check, never as the source of truth. The scorer re-derives gain and
 * loss from execution outcomes through the canonical `@vorionsys/basis-spec`
 * formulas, so `effectiveTier = min(claimed, recomputed, caps)` is real.
 *
 * Determinism, recompute-not-trust, and fail-closed posture are documented
 * inline at each decision point and in the package README. See README for
 * the explicit v0.1 scope and the deferred items.
 */

import {
  CIRCUIT_BREAKER,
  INITIAL_TRUST_SCORE,
  MAX_TRUST_SCORE,
  MIN_TRUST_SCORE,
  OBSERVATION_TIERS,
  QUALIFICATION_PASS_SCORE,
  RISK_ACCUMULATOR,
  RISK_LEVELS,
  TRUST_TIERS,
  calculateGain,
  calculateLoss,
  penaltyRatio,
  tierFromScore,
  type ObservationTier,
  type ProofEvent,
  type RiskLevel,
  type TrustTier,
} from '@vorionsys/basis-spec';

import { parseOccurredAtNanos } from './time.js';
import {
  DEFAULT_PRECISION,
  clampScaled,
  quantize,
  unscale,
} from './fixed.js';
import { hashPolicy } from './policy-hash.js';
import type {
  CircuitBreakerState,
  Divergence,
  RiskKey,
  RiskResolutionRecord,
  RiskSource,
  ScoreResult,
  ScoringPolicy,
} from './types.js';

// ---------------------------------------------------------------------------
// Tier index helpers (ordered T0..T7)
// ---------------------------------------------------------------------------

const TIER_ORDER: readonly TrustTier[] = Object.keys(TRUST_TIERS) as TrustTier[];

function tierIndex(tier: TrustTier): number {
  return TIER_ORDER.indexOf(tier);
}

/** The lower (more conservative) of two tiers. */
function minTier(a: TrustTier, b: TrustTier): TrustTier {
  return tierIndex(a) <= tierIndex(b) ? a : b;
}

// ---------------------------------------------------------------------------
// Intra-instant causal ordering (must-fix #4)
//
// A runtime commonly stamps a trust_delta and the execution outcome it
// summarises at the SAME occurredAt. A naive (occurredAt, eventId) tiebreak
// can order the delta BEFORE its own outcome, producing a false divergence
// flag. We impose a deterministic causal precedence within an instant so a
// delta is always evaluated AFTER the outcome it claims to summarise.
// ---------------------------------------------------------------------------

const EVENT_TYPE_PRECEDENCE: Record<string, number> = {
  intent_received: 0,
  decision_made: 1,
  execution_started: 2,
  execution_completed: 3,
  execution_failed: 3,
  incident_detected: 4,
  rollback_initiated: 4,
  component_registered: 5,
  component_updated: 5,
  trust_delta: 6, // always last within an instant — summarises the outcome
};

function precedence(eventType: string): number {
  return eventType in EVENT_TYPE_PRECEDENCE
    ? (EVENT_TYPE_PRECEDENCE[eventType] as number)
    : 5; // unknown/generic types sort with the neutral middle band
}

// ---------------------------------------------------------------------------
// Observation tier resolution (fail-closed)
// ---------------------------------------------------------------------------

interface ResolvedObservation {
  readonly tier: ObservationTier;
  readonly ceiling: number;
  readonly maxTier: TrustTier;
  readonly flag?: string;
}

/**
 * Resolve the observation tier to a (ceiling, maxTier), applying the honest
 * fail-closed rules:
 *   - unknown tier string => most restrictive (BLACK_BOX: ceiling 600 / T3).
 *   - ATTESTED_BOX / VERIFIED_BOX without policy.assertVerifiedObservation
 *     => downgraded to WHITE_BOX (ceiling 900 / T6), because TEE verifiers
 *     are stubs ecosystem-wide and we never assume a higher tier on trust.
 */
function resolveObservation(policy: ScoringPolicy): ResolvedObservation {
  const raw = policy.observationTier;
  const spec = (OBSERVATION_TIERS as Record<string, { ceiling: number; maxTier: TrustTier } | undefined>)[
    raw as string
  ];
  if (!spec) {
    const bb = OBSERVATION_TIERS.BLACK_BOX;
    return {
      tier: 'BLACK_BOX',
      ceiling: bb.ceiling,
      maxTier: bb.maxTier,
      flag: `unknown_observation_tier:${String(raw)}=>BLACK_BOX`,
    };
  }
  const isAttested = raw === 'ATTESTED_BOX' || raw === 'VERIFIED_BOX';
  if (isAttested && policy.assertVerifiedObservation !== true) {
    const wb = OBSERVATION_TIERS.WHITE_BOX;
    return {
      tier: 'WHITE_BOX',
      ceiling: wb.ceiling,
      maxTier: wb.maxTier,
      flag: `tee_stub_downgrade:${String(raw)}=>WHITE_BOX`,
    };
  }
  return { tier: raw as ObservationTier, ceiling: spec.ceiling, maxTier: spec.maxTier };
}

// ---------------------------------------------------------------------------
// Linkage index: executionId -> (in-chain riskLevel | actionType)
//
// RFC-0002.1: risk MAY now be SIGNED, in-chain evidence carried on
// `intent_received.riskLevel`. We resolve risk for an outcome by walking
//   executionId -> execution_started.decisionId
//             -> decision_made.intentId
//             -> intent_received
// and then, in PRECEDENCE ORDER:
//   1. CHAIN     — intent_received.riskLevel (signed evidence) if present;
//   2. POLICY    — else map intent_received.actionType through
//                  policy.riskByActionType (deprecated, out-of-chain path);
//   3. FAILCLOSED — else policy.defaultRisk (default LIFE_CRITICAL).
// Any broken link also fails closed to the max (LIFE_CRITICAL) default.
// ---------------------------------------------------------------------------

interface LinkageIndex {
  /** decisionId -> intentId (from decision_made) */
  readonly decisionToIntent: Map<string, string>;
  /** intentId -> actionType (from intent_received) */
  readonly intentToActionType: Map<string, string>;
  /**
   * intentId -> in-chain signed riskLevel (RFC-0002.1), when the
   * intent_received payload carries a valid `riskLevel`. Absent for
   * RFC-0002.0 chains, which fall back to the policy mapping.
   */
  readonly intentToRiskLevel: Map<string, RiskLevel>;
  /** executionId -> decisionId (from execution_started) */
  readonly executionToDecision: Map<string, string>;
}

function buildLinkageIndex(events: readonly ProofEvent[]): LinkageIndex {
  const decisionToIntent = new Map<string, string>();
  const intentToActionType = new Map<string, string>();
  const intentToRiskLevel = new Map<string, RiskLevel>();
  const executionToDecision = new Map<string, string>();

  for (const ev of events) {
    const p = ev.payload as Record<string, unknown>;
    switch (ev.eventType) {
      case 'intent_received': {
        const intentId = p['intentId'];
        const actionType = p['actionType'];
        if (typeof intentId === 'string' && typeof actionType === 'string') {
          intentToActionType.set(intentId, actionType);
        }
        // RFC-0002.1: capture the SIGNED, in-chain riskLevel when present and
        // a valid canonical key. An unknown/garbage value is ignored here
        // (fail-closed): resolveRisk then falls through to policy/default.
        const riskLevel = p['riskLevel'];
        if (
          typeof intentId === 'string' &&
          typeof riskLevel === 'string' &&
          riskLevel in RISK_LEVELS
        ) {
          intentToRiskLevel.set(intentId, riskLevel as RiskLevel);
        }
        break;
      }
      case 'decision_made': {
        const decisionId = p['decisionId'];
        const intentId = p['intentId'];
        if (typeof decisionId === 'string' && typeof intentId === 'string') {
          decisionToIntent.set(decisionId, intentId);
        }
        break;
      }
      case 'execution_started': {
        const executionId = p['executionId'];
        const decisionId = p['decisionId'];
        if (typeof executionId === 'string' && typeof decisionId === 'string') {
          executionToDecision.set(executionId, decisionId);
        }
        break;
      }
      default:
        break;
    }
  }
  return { decisionToIntent, intentToActionType, intentToRiskLevel, executionToDecision };
}

interface RiskResolution {
  readonly key: RiskKey;
  readonly multiplier: number;
  /**
   * Provenance of the resolved risk (RFC-0002.1):
   *   - 'chain'      — signed in-chain intent_received.riskLevel was used;
   *   - 'policy'     — fell back to policy.riskByActionType (out-of-chain);
   *   - 'failclosed' — neither resolved; pinned to policy.defaultRisk (max).
   */
  readonly source: RiskSource;
  /** True only when the linkage walk to intent_received itself broke. */
  readonly brokenLink: boolean;
}

function resolveRisk(
  executionId: string | undefined,
  index: LinkageIndex,
  policy: ScoringPolicy,
): RiskResolution {
  const defaultRisk: RiskKey = policy.defaultRisk ?? 'LIFE_CRITICAL';
  // Fail-closed to the max-configured risk. `brokenLink` is true only when the
  // linkage chain to intent_received could not be walked; an intent that
  // resolves but carries neither a signed riskLevel nor a policy mapping is
  // ALSO failclosed, but with brokenLink=false (the link was intact).
  const maxResolution = (brokenLink: boolean): RiskResolution => ({
    key: defaultRisk,
    multiplier: RISK_LEVELS[defaultRisk].multiplier,
    source: 'failclosed',
    brokenLink,
  });

  if (typeof executionId !== 'string') return maxResolution(true);
  const decisionId = index.executionToDecision.get(executionId);
  if (decisionId === undefined) return maxResolution(true);
  const intentId = index.decisionToIntent.get(decisionId);
  if (intentId === undefined) return maxResolution(true);

  // (1) PREFER signed, in-chain risk (RFC-0002.1). When the intent_received
  // event carries a valid `riskLevel`, it is the evidence and OVERRIDES any
  // policy mapping — the operator/runtime signed the risk at intent time.
  const inChain = index.intentToRiskLevel.get(intentId);
  if (inChain !== undefined) {
    return { key: inChain, multiplier: RISK_LEVELS[inChain].multiplier, source: 'chain', brokenLink: false };
  }

  // (2) FALL BACK to the policy mapping (deprecated, out-of-chain path) only
  // when the chain carries no signed risk for this action.
  const actionType = index.intentToActionType.get(intentId);
  if (actionType === undefined) return maxResolution(false);

  const mapped = policy.riskByActionType[actionType];
  if (mapped === undefined || !(mapped in RISK_LEVELS)) {
    // actionType resolved but not mapped by policy => fail closed to default.
    return maxResolution(false);
  }
  return { key: mapped, multiplier: RISK_LEVELS[mapped].multiplier, source: 'policy', brokenLink: false };
}

// ---------------------------------------------------------------------------
// Shadow-mode production filter (RFC-0002)
// ---------------------------------------------------------------------------

/** Only production/verified (and absent => production) events move the score. */
function movesProductionScore(ev: ProofEvent): boolean {
  const m = ev.shadowMode;
  return m === undefined || m === 'production' || m === 'verified';
}

// ---------------------------------------------------------------------------
// Risk accumulator over a sliding 24h occurredAt window.
//
// Each failure contributes P(T) * R, where T is the tier index at the moment
// of failure and R is the resolved risk multiplier. The window slides over
// occurredAt nanoseconds (never wall-clock). incident_detected (high|critical)
// and rollback_initiated also contribute a conservative safety weight equal to
// the resolved/default risk multiplier so they can only push toward degraded,
// never raise the score (no canonical severity->delta formula exists — see
// the deferred items; this is a safety signal, not a score delta).
// ---------------------------------------------------------------------------

const WINDOW_NANOS = BigInt(RISK_ACCUMULATOR.windowHours) * 3_600_000_000_000n;

interface AccumulatorEntry {
  readonly atNanos: bigint;
  readonly weight: number;
}

function peakWindowedAccumulator(entries: readonly AccumulatorEntry[]): number {
  // entries are already in ascending occurredAt order. Slide a 24h window and
  // track the maximum sum within any window ending at an entry.
  let peak = 0;
  let start = 0;
  let runningSum = 0;
  for (let end = 0; end < entries.length; end++) {
    runningSum += (entries[end] as AccumulatorEntry).weight;
    const endAt = (entries[end] as AccumulatorEntry).atNanos;
    while (
      start <= end &&
      endAt - (entries[start] as AccumulatorEntry).atNanos >= WINDOW_NANOS
    ) {
      runningSum -= (entries[start] as AccumulatorEntry).weight;
      start++;
    }
    if (runningSum > peak) peak = runningSum;
  }
  return peak;
}

// ---------------------------------------------------------------------------
// Fail-closed result builder
// ---------------------------------------------------------------------------

function failClosed(error: string, policyHash: string, flags: string[] = []): ScoreResult {
  return {
    recomputedScore: INITIAL_TRUST_SCORE,
    recomputedTier: 'T0',
    observationCappedTier: 'T0',
    effectiveTier: 'T0',
    status: 'FAIL_CLOSED',
    circuitBreaker: 'NONE',
    riskAccumulator24h: 0,
    divergences: [],
    riskResolutions: [],
    overClaim: false,
    flags,
    scoredEventCount: 0,
    policyHash,
    error,
  };
}

// ---------------------------------------------------------------------------
// scoreChain — the keystone
// ---------------------------------------------------------------------------

/**
 * Pure, deterministic. The input chain MUST already be structurally +
 * signature/linkage validated upstream; this is a pure function over a
 * validated chain. It still fails closed on anything it cannot compute.
 */
export function scoreChain(
  events: ReadonlyArray<ProofEvent>,
  policy: ScoringPolicy,
): ScoreResult {
  // Hash the (untrusted) policy first so even a fail-closed result is
  // attributable to the exact policy that produced it.
  let policyHash: string;
  try {
    policyHash = hashPolicy(policy);
  } catch (e) {
    // A policy we cannot even canonicalise is unusable — fail closed with a
    // sentinel hash so the result still carries a stable, attributable value.
    return failClosed(
      `policy_uncanonicalisable: ${e instanceof Error ? e.message : String(e)}`,
      'unhashable',
    );
  }

  const flags: string[] = [];
  const scale = policy.precision ?? DEFAULT_PRECISION;
  if (!Number.isInteger(scale) || scale <= 0) {
    return failClosed(`invalid_precision:${String(scale)}`, policyHash);
  }

  // --- Resolve observation tier (fail-closed downgrades) -------------------
  const obs = resolveObservation(policy);
  if (obs.flag) flags.push(obs.flag);

  // Ceiling C drives gain headroom; clamp into [MIN, MAX].
  const ceiling = Math.min(MAX_TRUST_SCORE, Math.max(MIN_TRUST_SCORE, obs.ceiling));

  // --- Deterministic ordering (must-fix #2 + #4) ---------------------------
  // Parse occurredAt to exact nanoseconds; fail closed on anything not
  // losslessly representable. Sort by (instant, causal-precedence, eventId).
  type Keyed = { ev: ProofEvent; nanos: bigint; prec: number };
  const keyed: Keyed[] = [];
  for (const ev of events) {
    if (typeof ev.eventId !== 'string' || ev.eventId.length === 0) {
      return failClosed('missing_or_empty_eventId', policyHash, flags);
    }
    const nanos = parseOccurredAtNanos(ev.occurredAt);
    if (nanos === null) {
      return failClosed(`unparseable_occurredAt:${ev.eventId}`, policyHash, flags);
    }
    if (typeof ev.eventType !== 'string') {
      return failClosed(`missing_eventType:${ev.eventId}`, policyHash, flags);
    }
    keyed.push({ ev, nanos, prec: precedence(ev.eventType) });
  }

  keyed.sort((a, b) => {
    if (a.nanos < b.nanos) return -1;
    if (a.nanos > b.nanos) return 1;
    if (a.prec !== b.prec) return a.prec - b.prec;
    if (a.ev.eventId < b.ev.eventId) return -1;
    if (a.ev.eventId > b.ev.eventId) return 1;
    return 0;
  });

  // Reject a true non-deterministic tie: identical (instant, eventId).
  for (let i = 1; i < keyed.length; i++) {
    const prev = keyed[i - 1] as Keyed;
    const cur = keyed[i] as Keyed;
    if (cur.nanos === prev.nanos && cur.ev.eventId === prev.ev.eventId) {
      return failClosed(
        `nondeterministic_duplicate_key:${cur.ev.eventId}`,
        policyHash,
        flags,
      );
    }
  }

  const sorted = keyed.map((k) => k.ev);
  const nanosOf = new Map<string, bigint>();
  for (const k of keyed) nanosOf.set(k.ev.eventId, k.nanos);

  // --- Linkage index for risk resolution -----------------------------------
  const linkage = buildLinkageIndex(sorted);

  // --- Replay -------------------------------------------------------------
  const minScaled = BigInt(MIN_TRUST_SCORE) * BigInt(scale);
  const maxScaled = BigInt(MAX_TRUST_SCORE) * BigInt(scale);
  let scoredScaled = quantize(INITIAL_TRUST_SCORE, scale); // exact accumulator

  let hasQualified = false; // must-fix #1: CB engages only after qualifying
  let scoredEventCount = 0;
  const divergences: Divergence[] = [];
  const riskResolutions: RiskResolutionRecord[] = [];
  let overClaim = false;
  const accumulatorEntries: AccumulatorEntry[] = [];

  // Record a per-outcome risk resolution (RFC-0002.1) for honesty/attribution.
  const recordRisk = (
    eventId: string,
    risk: { key: RiskKey; source: RiskSource },
  ): void => {
    riskResolutions.push({ eventId, risk: risk.key, source: risk.source });
  };

  // Current float score reconstructed from the scaled accumulator via one
  // pinned division (must-fix #5: ln/cbrt input is the quantized score).
  const currentScore = (): number => unscale(scoredScaled, scale);

  // Current tier index, with a fail-closed clamp + try/catch around the
  // throwing canonical tierFromScore (must-fix: clamp must be PROVEN).
  const currentTierIndex = (): number => {
    const s = currentScore();
    const clamped = Math.min(MAX_TRUST_SCORE, Math.max(MIN_TRUST_SCORE, s));
    return tierIndex(tierFromScore(clamped));
  };

  // Degraded-freeze latch: once the agent has qualified AND fallen below the
  // degraded threshold, gains are frozen until the chain ends (losses still
  // apply). Tracked as we go so subsequent successes apply zero gain.
  const isDegradedNow = (): boolean => {
    if (!hasQualified) return false;
    return currentScore() < CIRCUIT_BREAKER.degradedThreshold;
  };

  try {
    for (const ev of sorted) {
      const p = ev.payload as Record<string, unknown> | undefined;
      const payloadType = typeof p?.['type'] === 'string' ? (p?.['type'] as string) : undefined;

      // Generic / unknown payload type that does not match the eventType is
      // unscorable: no gain, flag, never raises the score (fail closed).
      const isProd = movesProductionScore(ev);

      switch (ev.eventType) {
        case 'execution_completed': {
          if (!isProd) {
            flags.push(`shadow_excluded:${ev.eventId}`);
            break;
          }
          const status = p?.['status'];
          const executionId = typeof p?.['executionId'] === 'string'
            ? (p['executionId'] as string)
            : undefined;
          const risk = resolveRisk(executionId, linkage, policy);
          if (risk.brokenLink) flags.push(`broken_link_risk_maxed:${ev.eventId}`);
          recordRisk(ev.eventId, risk);

          if (status === 'success') {
            // Gain is frozen if the agent is in degraded mode (must-fix #1).
            if (isDegradedNow()) {
              flags.push(`gain_frozen_degraded:${ev.eventId}`);
              break;
            }
            const gain = calculateGain({
              currentScore: currentScore(),
              ceiling,
              riskMultiplier: risk.multiplier,
            });
            scoredScaled = clampScaled(
              scoredScaled + quantize(gain, scale),
              minScaled,
              maxScaled,
            );
            scoredEventCount++;
            if (currentScore() >= QUALIFICATION_PASS_SCORE) hasQualified = true;
          } else if (status === 'partial') {
            // Fail closed: partial is NOT success. Zero gain (documented).
            flags.push(`partial_zero_gain:${ev.eventId}`);
          } else {
            // Unknown status string => unscorable, no gain.
            flags.push(`unknown_execution_status:${ev.eventId}`);
          }
          break;
        }

        case 'execution_failed': {
          if (!isProd) {
            flags.push(`shadow_excluded:${ev.eventId}`);
            break;
          }
          const executionId = typeof p?.['executionId'] === 'string'
            ? (p['executionId'] as string)
            : undefined;
          const risk = resolveRisk(executionId, linkage, policy);
          if (risk.brokenLink) flags.push(`broken_link_risk_maxed:${ev.eventId}`);
          recordRisk(ev.eventId, risk);

          const ti = currentTierIndex();
          const loss = calculateLoss({
            tierIndex: ti,
            ceiling,
            riskMultiplier: risk.multiplier,
          });
          scoredScaled = clampScaled(
            scoredScaled + quantize(loss, scale), // loss is negative
            minScaled,
            maxScaled,
          );
          scoredEventCount++;

          // Risk accumulator: P(T) * R at the moment of failure.
          const weight = penaltyRatio(ti) * risk.multiplier;
          const at = nanosOf.get(ev.eventId);
          if (at !== undefined) accumulatorEntries.push({ atNanos: at, weight });
          break;
        }

        case 'trust_delta': {
          // NEVER summed. Cross-check only: compare the claimed delta against
          // the running recomputed score (advisory). The recomputed value
          // always wins; the divergence is evidence, not enforcement.
          if (!isProd) break;
          const prev = p?.['previousScore'];
          const next = p?.['newScore'];
          if (typeof prev === 'number' && typeof next === 'number') {
            const claimedNewScore = next;
            const recomputed = currentScore();
            if (Math.abs(claimedNewScore - recomputed) > 0.5) {
              divergences.push({
                eventId: ev.eventId,
                kind: 'trust_delta',
                claimed: claimedNewScore,
                recomputed,
              });
              if (claimedNewScore > recomputed) overClaim = true;
            }
          }
          break;
        }

        case 'decision_made': {
          if (!isProd) break;
          const claimed = p?.['trustScore'];
          if (typeof claimed === 'number') {
            const recomputed = currentScore();
            if (Math.abs(claimed - recomputed) > 0.5) {
              divergences.push({
                eventId: ev.eventId,
                kind: 'decision_score',
                claimed,
                recomputed,
              });
              if (claimed > recomputed) overClaim = true;
            }
          }
          break;
        }

        case 'incident_detected': {
          if (!isProd) break;
          // Safety signal only. high|critical contribute a conservative weight
          // to the risk accumulator; no canonical score delta exists.
          const sev = p?.['severity'];
          flags.push(`incident:${String(sev)}:${ev.eventId}`);
          if (sev === 'high' || sev === 'critical') {
            const ti = currentTierIndex();
            const weight = penaltyRatio(ti) * RISK_LEVELS[policy.defaultRisk ?? 'LIFE_CRITICAL'].multiplier;
            const at = nanosOf.get(ev.eventId);
            if (at !== undefined) accumulatorEntries.push({ atNanos: at, weight });
          }
          break;
        }

        case 'rollback_initiated': {
          if (!isProd) break;
          flags.push(`rollback:${ev.eventId}`);
          break;
        }

        case 'intent_received':
        case 'execution_started':
        case 'component_registered':
        case 'component_updated':
          // No score effect (audit/linkage/provenance only). TRUST_INHERITANCE
          // is NONE so component_registered grants nothing.
          break;

        default: {
          // Unknown eventType => unscorable, flag, never raises score.
          flags.push(`unscorable_event_type:${String(ev.eventType)}:${ev.eventId}`);
          break;
        }
      }

      // Flag a generic/unknown payload-type that does not match a typed event.
      if (
        payloadType !== undefined &&
        payloadType !== ev.eventType &&
        !flags.includes(`payload_type_mismatch:${ev.eventId}`)
      ) {
        flags.push(`payload_type_mismatch:${ev.eventId}`);
      }
    }
  } catch (e) {
    // Any residual throw (e.g. a corrupted ceiling driving NaN/Infinity into
    // quantize, or tierFromScore on an out-of-range value) => fail closed.
    return failClosed(
      `replay_threw: ${e instanceof Error ? e.message : String(e)}`,
      policyHash,
      flags,
    );
  }

  // --- Final score + quantization -----------------------------------------
  const recomputedScore = unscale(scoredScaled, scale);

  // tierFromScore is clamped+guarded; fail closed to T0 on any residual throw.
  let recomputedTier: TrustTier;
  try {
    const clamped = Math.min(MAX_TRUST_SCORE, Math.max(MIN_TRUST_SCORE, recomputedScore));
    recomputedTier = tierFromScore(clamped);
  } catch (e) {
    return failClosed(
      `tier_from_score_threw: ${e instanceof Error ? e.message : String(e)}`,
      policyHash,
      flags,
    );
  }

  // --- Circuit breaker + risk accumulator ----------------------------------
  // must-fix #1: the score-path CB only engages AFTER the agent has crossed
  // QUALIFICATION_PASS_SCORE at least once in this chain. A fresh agent
  // climbing from 0 is PROVISIONING, not a fallen agent — it is not tripped.
  let circuitBreaker: CircuitBreakerState = 'NONE';
  if (hasQualified) {
    if (recomputedScore < CIRCUIT_BREAKER.trippedThreshold) {
      circuitBreaker = 'TRIPPED';
    } else if (recomputedScore < CIRCUIT_BREAKER.degradedThreshold) {
      circuitBreaker = 'DEGRADED';
    }
  }

  const riskAccumulator24h = peakWindowedAccumulator(accumulatorEntries);
  // The accumulator path can also trip/degrade — even pre-qualification a
  // burst of failures is a safety signal (it can only lower, never raise).
  if (riskAccumulator24h >= RISK_ACCUMULATOR.cbThreshold) {
    circuitBreaker = 'TRIPPED';
  } else if (
    riskAccumulator24h >= RISK_ACCUMULATOR.degradedThreshold &&
    circuitBreaker !== 'TRIPPED'
  ) {
    if (circuitBreaker === 'NONE') circuitBreaker = 'DEGRADED';
  } else if (riskAccumulator24h >= RISK_ACCUMULATOR.warningThreshold) {
    flags.push(`risk_accumulator_warning:${riskAccumulator24h}`);
  }

  // --- Tier caps (observation, policy ceiling, claimed) --------------------
  let observationCappedTier = minTier(recomputedTier, obs.maxTier);

  let effectiveTier = observationCappedTier;
  if (policy.ceilingTier !== undefined) {
    if (!(policy.ceilingTier in TRUST_TIERS)) {
      return failClosed(`invalid_ceilingTier:${String(policy.ceilingTier)}`, policyHash, flags);
    }
    effectiveTier = minTier(effectiveTier, policy.ceilingTier);
  }
  // Caller's claimedTier is an UPPER BOUND only. Missing => no client cap.
  if (policy.claimedTier !== undefined) {
    if (!(policy.claimedTier in TRUST_TIERS)) {
      return failClosed(`invalid_claimedTier:${String(policy.claimedTier)}`, policyHash, flags);
    }
    effectiveTier = minTier(effectiveTier, policy.claimedTier);
  }

  // Circuit-breaker TRIPPED floors the effective tier to T0.
  if (circuitBreaker === 'TRIPPED') {
    effectiveTier = 'T0';
  }

  const status =
    circuitBreaker === 'TRIPPED'
      ? 'TRIPPED'
      : circuitBreaker === 'DEGRADED'
        ? 'DEGRADED'
        : 'OK';

  return {
    recomputedScore,
    recomputedTier,
    observationCappedTier,
    effectiveTier,
    status,
    circuitBreaker,
    riskAccumulator24h,
    divergences,
    riskResolutions,
    overClaim,
    flags,
    scoredEventCount,
    policyHash,
  };
}

/**
 * Convenience: recompute then min against a claimed tier. Never raises above
 * the recomputed / observation / policy caps already in `result`.
 */
export function effectiveTier(result: ScoreResult, claimed?: TrustTier): TrustTier {
  if (result.status === 'FAIL_CLOSED') return 'T0';
  let t = result.effectiveTier;
  if (claimed !== undefined && claimed in TRUST_TIERS) {
    t = minTier(t, claimed);
  }
  return t;
}
