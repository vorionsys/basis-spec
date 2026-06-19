// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS — tier reconciliation: the FROZEN legacy CAR-5 ⇄ canonical T0–T7
 * projection, and the canonical, fail-closed `effectiveTier` aggregation.
 *
 *   effectiveTier = verified
 *     ? min( toT(claimed), toT(recomputed), OBS_MAXTIER[observation], localPolicyCeiling )
 *     : T0
 *
 * Any unverified, unmappable, or unknown-observation input fails CLOSED to T0
 * (least privilege) — never fail-open to a claimed tier. The projection table is
 * frozen; coarsening (T→CAR→T) always rounds DOWN, the safe direction for min().
 *
 * Source of truth: TIER_RECONCILIATION §3–§4; mirrors tier-reconcile-verify.mjs.
 * OBS_MAXTIER is DERIVED from @vorionsys/basis-spec OBSERVATION_TIERS so it can
 * never drift from the canonical spec.
 */

import { OBSERVATION_TIERS } from '@vorionsys/basis-spec';
import type { ObservationTier } from '@vorionsys/basis-spec';

// ---------------------------------------------------------------------------
// Tier index
// ---------------------------------------------------------------------------

/** Canonical tier index 0..7 (T0..T7). */
export type TierIndex = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;
export const MIN_TIER_INDEX: TierIndex = 0;
export const MAX_TIER_INDEX: TierIndex = 7;

/** 'T3' | 3 | 't3' → 3; anything else → 0 (fail closed). */
function tIndexFromTierName(name: string): TierIndex {
  const m = /^T?([0-7])$/.exec(String(name).toUpperCase().trim());
  return (m ? (Number(m[1]) as TierIndex) : 0);
}

/** Canonical tier label for an index, e.g. 3 → 'T3'. */
export function tierLabel(t: TierIndex): string {
  return `T${t}`;
}

// ---------------------------------------------------------------------------
// Frozen CAR-5 ⇄ T0–T7 projection
// ---------------------------------------------------------------------------

/** Frozen legacy CAR-5 → canonical T-index projection (TIER_RECONCILIATION §3). */
export const CAR_TO_T = {
  UNKNOWN: 0,
  BASIC: 1,
  VERIFIED: 3,
  TRUSTED: 5,
  PRIVILEGED: 6,
} as const satisfies Record<string, TierIndex>;
export type CarTier = keyof typeof CAR_TO_T;

/** Inverse: T-index → coarsest CAR band. Coarsening rounds DOWN (lossy-safe). */
export const T_TO_CAR = [
  'UNKNOWN', 'BASIC', 'BASIC', 'VERIFIED', 'VERIFIED', 'TRUSTED', 'PRIVILEGED', 'PRIVILEGED',
] as const satisfies readonly CarTier[];

export function projectCarToT(car: CarTier): TierIndex {
  return CAR_TO_T[car];
}
export function projectTToCar(t: TierIndex): CarTier {
  return T_TO_CAR[t] ?? 'UNKNOWN';
}

// ---------------------------------------------------------------------------
// Observation ceiling (derived from canonical OBSERVATION_TIERS — no drift)
// ---------------------------------------------------------------------------

/**
 * Observation tier → maximum reachable canonical tier index. Derived from
 * OBSERVATION_TIERS[*].maxTier in @vorionsys/basis-spec. TEE verifiers are
 * stubs today, so anything resting on attested execution honestly caps at
 * WHITE_BOX (T6) until a real TPM/quote verifier lands.
 */
export const OBS_MAXTIER = Object.freeze(
  Object.fromEntries(
    Object.entries(OBSERVATION_TIERS).map(([k, v]) => [k, tIndexFromTierName((v as { maxTier: string }).maxTier)]),
  ),
) as Readonly<Record<ObservationTier, TierIndex>>;

// ---------------------------------------------------------------------------
// toT coercion — every external claim funnels through this, fail closed
// ---------------------------------------------------------------------------

/**
 * Coerce any external tier claim to a canonical index, fail-closed.
 * Accepts an integer 0..7, a 'T0'..'T7' string, or a legacy CAR band name.
 * Anything else (null, garbage, out of range) → 0. Never inflates.
 */
export function toT(claim: unknown): TierIndex {
  if (claim == null) return 0;
  if (typeof claim === 'number') {
    return Number.isInteger(claim) && claim >= 0 && claim <= 7 ? (claim as TierIndex) : 0;
  }
  if (typeof claim === 'string') {
    const up = claim.toUpperCase().trim();
    if (up in CAR_TO_T) return CAR_TO_T[up as CarTier];
    const m = /^T?([0-7])$/.exec(up);
    if (m) return Number(m[1]) as TierIndex;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// effectiveTier = min(...) — fail-closed authority binding
// ---------------------------------------------------------------------------

export type TierBinding =
  | 'claimed' | 'recomputed' | 'observation' | 'localCeiling'
  | 'unverified' | 'unknown-observation';

export interface EffectiveTierInput {
  /** Claimed tier (int 0-7, 'T5', or a CAR band). Absent/garbage → 0 (fail closed). */
  claimed?: unknown;
  /** Independently recomputed tier (the RP's own derivation). */
  recomputed?: unknown;
  /** Observation tier name; unknown/missing → fail closed to T0. */
  observation?: string;
  /** RP's local policy ceiling (int 0-7 / 'T5' / CAR). Default T7 (no extra cap). */
  localCeiling?: unknown;
  /** Was the proof chain log-verified and re-derived by the RP? false → T0. */
  verified: boolean;
}

export interface EffectiveTierResult {
  effectiveIndex: TierIndex;
  effectiveTier: string; // 'T0'..'T7'
  binding: TierBinding;
  failClosed: boolean;
  inputs: { claimed: TierIndex; recomputed: TierIndex; observationCap: TierIndex; localCeiling: TierIndex };
}

/**
 * The canonical effective-tier binding. Fail-toward-least-privilege:
 *   - not verified                  → T0
 *   - unknown/absent observation    → T0
 *   - else  min(claimed, recomputed, observationCap, localCeiling)
 * The hosted score becomes one cached opinion; a divergence between claimed and
 * recomputed makes the LOWER value bind.
 */
export function effectiveTier(input: EffectiveTierInput): EffectiveTierResult {
  const claimed = toT(input.claimed);
  const recomputed = toT(input.recomputed);
  const localCeiling = input.localCeiling == null ? 7 : toT(input.localCeiling);

  if (!input.verified) {
    return {
      effectiveIndex: 0, effectiveTier: 'T0', binding: 'unverified', failClosed: true,
      inputs: { claimed, recomputed, observationCap: 0, localCeiling },
    };
  }

  const obsName = String(input.observation ?? '').toUpperCase().trim();
  if (!(obsName in OBS_MAXTIER)) {
    return {
      effectiveIndex: 0, effectiveTier: 'T0', binding: 'unknown-observation', failClosed: true,
      inputs: { claimed, recomputed, observationCap: 0, localCeiling },
    };
  }
  const observationCap = OBS_MAXTIER[obsName as ObservationTier];

  let bestIdx: TierIndex = claimed;
  let binding: TierBinding = 'claimed';
  const consider = (v: TierIndex, b: TierBinding) => { if (v < bestIdx) { bestIdx = v; binding = b; } };
  consider(recomputed, 'recomputed');
  consider(observationCap, 'observation');
  consider(localCeiling as TierIndex, 'localCeiling');

  return {
    effectiveIndex: bestIdx, effectiveTier: `T${bestIdx}`, binding, failClosed: bestIdx === 0,
    inputs: { claimed, recomputed, observationCap, localCeiling: localCeiling as TierIndex },
  };
}
