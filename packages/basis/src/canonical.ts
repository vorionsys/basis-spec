/**
 * BASIS — Canonical Parameters
 *
 * Single source of truth for the BASIS standard's tier definitions,
 * risk levels, formulas, and constants. Conforming implementations
 * SHOULD import from this module rather than re-declaring values.
 *
 * Spec version: 1.0.0
 */

// ---------------------------------------------------------------------------
// Trust score space
// ---------------------------------------------------------------------------

/** Minimum trust score in the standard scale. */
export const MIN_TRUST_SCORE = 0;

/** Maximum trust score in the standard scale. */
export const MAX_TRUST_SCORE = 1000;

/** Initial trust score for a newly registered agent. */
export const INITIAL_TRUST_SCORE = 0;

/** Score required to exit qualification and reach T1 (Observed). */
export const QUALIFICATION_PASS_SCORE = 200;

// ---------------------------------------------------------------------------
// Trust tiers (T0 - T7)
// ---------------------------------------------------------------------------

export interface TrustTierSpec {
  readonly name: string;
  readonly min: number;
  readonly max: number;
  readonly description: string;
}

export const TRUST_TIERS = {
  T0: { name: 'Sandbox',     min: 0,   max: 199,  description: 'No external effects' },
  T1: { name: 'Observed',    min: 200, max: 349,  description: 'Read-only, monitored' },
  T2: { name: 'Provisional', min: 350, max: 499,  description: 'Limited write, scoped tools' },
  T3: { name: 'Monitored',   min: 500, max: 649,  description: 'Standard operations, audit' },
  T4: { name: 'Standard',    min: 650, max: 799,  description: 'Full operational capability' },
  T5: { name: 'Trusted',     min: 800, max: 875,  description: 'Cross-system operations' },
  T6: { name: 'Certified',   min: 876, max: 950,  description: 'Multi-agent coordination' },
  T7: { name: 'Autonomous',  min: 951, max: 1000, description: 'Full autonomous operation' },
} as const satisfies Record<string, TrustTierSpec>;

export type TrustTier = keyof typeof TRUST_TIERS;

/** Map a numeric trust score to its tier identifier. */
export function tierFromScore(score: number): TrustTier {
  if (score < 0 || score > MAX_TRUST_SCORE) {
    throw new RangeError(`Score ${score} outside [0, ${MAX_TRUST_SCORE}]`);
  }
  for (const [tier, spec] of Object.entries(TRUST_TIERS)) {
    if (score >= spec.min && score <= spec.max) return tier as TrustTier;
  }
  // Unreachable given the partition is exhaustive over [0, 1000].
  throw new Error(`No tier covers score ${score}`);
}

// ---------------------------------------------------------------------------
// Risk levels
// ---------------------------------------------------------------------------

export interface RiskLevelSpec {
  readonly multiplier: number;
  readonly description: string;
}

export const RISK_LEVELS = {
  READ:          { multiplier: 1,  description: 'Observation only' },
  LOW:           { multiplier: 3,  description: 'Minor, reversible' },
  MEDIUM:        { multiplier: 5,  description: 'Operational impact' },
  HIGH:          { multiplier: 10, description: 'Significant damage' },
  CRITICAL:      { multiplier: 15, description: 'Severe, hard to reverse' },
  LIFE_CRITICAL: { multiplier: 30, description: 'Human safety at stake' },
} as const satisfies Record<string, RiskLevelSpec>;

export type RiskLevel = keyof typeof RISK_LEVELS;

/** Minimum trust score required to attempt an action at the given risk. */
export const TRUST_THRESHOLDS_BY_RISK: Record<RiskLevel, number> = {
  READ: 0,
  LOW: 200,
  MEDIUM: 400,
  HIGH: 600,
  CRITICAL: 800,
  LIFE_CRITICAL: 951,
};

// ---------------------------------------------------------------------------
// Gain formula
//
//   gain = GAIN_RATE * ln(1 + C - S) * cubeRoot(R)
//
//   GAIN_RATE: standard rate constant
//   C:         observation tier ceiling (max achievable score)
//   S:         current trust score
//   R:         risk multiplier from RISK_LEVELS
//
// Cube-root scaling on R yields a sub-linear bonus for higher-risk
// successes, preventing risk-seeking behaviour as a path to faster gain.
// ---------------------------------------------------------------------------

export const GAIN_RATE = 0.05;

/** Compute trust gain for a successful action. */
export function calculateGain(args: {
  currentScore: number;
  ceiling: number;
  riskMultiplier: number;
}): number {
  const { currentScore, ceiling, riskMultiplier } = args;
  const headroom = Math.max(0, ceiling - currentScore);
  return GAIN_RATE * Math.log(1 + headroom) * Math.cbrt(riskMultiplier);
}

// ---------------------------------------------------------------------------
// Loss formula
//
//   loss = -P(T) * R * GAIN_RATE * ln(1 + C/2)
//
//   P(T) = PENALTY_RATIO_MIN + (T/7) * (PENALTY_RATIO_MAX - PENALTY_RATIO_MIN)
//        = 3 + T  (with the standard 3..10 range)
//
// The fixed midpoint reference ln(1 + C/2) prevents agents from positioning
// near the ceiling to reduce loss exposure: loss magnitude depends on the
// ceiling, not on current score.
// ---------------------------------------------------------------------------

export const PENALTY_RATIO_MIN = 3;
export const PENALTY_RATIO_MAX = 10;

/** Penalty multiplier P(T) for a given tier index (0..7). */
export function penaltyRatio(tierIndex: number): number {
  if (tierIndex < 0 || tierIndex > 7) {
    throw new RangeError(`Tier index ${tierIndex} out of range [0, 7]`);
  }
  return PENALTY_RATIO_MIN + tierIndex * ((PENALTY_RATIO_MAX - PENALTY_RATIO_MIN) / 7);
}

/** Compute trust loss for a failed action. Returns a negative number. */
export function calculateLoss(args: {
  tierIndex: number;
  ceiling: number;
  riskMultiplier: number;
}): number {
  const { tierIndex, ceiling, riskMultiplier } = args;
  return -penaltyRatio(tierIndex) * riskMultiplier * GAIN_RATE * Math.log(1 + ceiling / 2);
}

// ---------------------------------------------------------------------------
// Observation tiers
//
// Each observation tier caps the maximum achievable trust score for an
// agent based on the degree of internal-state visibility available to
// the operator. An agent under BLACK_BOX observation cannot exceed T3
// regardless of behavioral evidence.
// ---------------------------------------------------------------------------

export interface ObservationTierSpec {
  readonly ceiling: number;
  readonly maxTier: TrustTier;
  readonly description: string;
}

export const OBSERVATION_TIERS = {
  BLACK_BOX:    { ceiling: 600,  maxTier: 'T3', description: 'I/O only' },
  GRAY_BOX:     { ceiling: 750,  maxTier: 'T4', description: 'I/O + logs' },
  WHITE_BOX:    { ceiling: 900,  maxTier: 'T6', description: 'Full code access' },
  ATTESTED_BOX: { ceiling: 950,  maxTier: 'T6', description: 'TEE-verified execution' },
  VERIFIED_BOX: { ceiling: 1000, maxTier: 'T7', description: 'TEE + interpretability stack' },
} as const satisfies Record<string, ObservationTierSpec>;

export type ObservationTier = keyof typeof OBSERVATION_TIERS;

// ---------------------------------------------------------------------------
// Hysteresis (per-tier demotion buffers)
//
// Wider at low tiers (new agents fluctuate), tighter at high tiers
// (established agents should be stable). Indexed by source tier 0..7.
// Demotion only — promotion crosses tier boundaries immediately.
// ---------------------------------------------------------------------------

export const HYSTERESIS = [25, 25, 20, 20, 15, 10, 10, 10] as const;

// ---------------------------------------------------------------------------
// Promotion delays (days before promotion takes effect)
//
// T0..T4: zero — the logarithmic gain curve is the throttle.
// T5..T7: time-gated — sustained behaviour required for high autonomy.
// ---------------------------------------------------------------------------

export const PROMOTION_DELAYS = [0, 0, 0, 0, 0, 7, 10, 14] as const;

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

export const CIRCUIT_BREAKER = {
  /** Trust below this trips the circuit breaker (hard stop). */
  trippedThreshold: 100,
  /** Trust below this enters degraded mode (gains frozen). */
  degradedThreshold: 200,
} as const;

// ---------------------------------------------------------------------------
// Risk accumulator (rolling 24h window)
//
// Each failure adds P(T) * R to the accumulator. Thresholds escalate
// monitoring and eventually trip the circuit breaker.
// ---------------------------------------------------------------------------

export const RISK_ACCUMULATOR = {
  windowHours: 24,
  warningThreshold: 60,
  degradedThreshold: 120,
  cbThreshold: 240,
} as const;

// ---------------------------------------------------------------------------
// Dormancy schedule
//
// Stepped per-milestone deductions for agents that go idle. Resets on
// any trust-relevant activity. Floor prevents inactivity alone from
// driving an agent below half its pre-dormancy score.
// ---------------------------------------------------------------------------

export interface DormancyMilestone {
  readonly days: number;
  readonly deduction: number;
}

export const DORMANCY = {
  milestones: [
    { days: 7,   deduction: 0.06 },
    { days: 14,  deduction: 0.06 },
    { days: 28,  deduction: 0.06 },
    { days: 42,  deduction: 0.06 },
    { days: 56,  deduction: 0.06 },
    { days: 84,  deduction: 0.05 },
    { days: 112, deduction: 0.05 },
    { days: 140, deduction: 0.05 },
    { days: 182, deduction: 0.05 },
  ] as readonly DormancyMilestone[],
  /** Floor as a fraction of pre-dormancy score (0.50 = never below 50%). */
  floor: 0.50,
  halfLifeDays: 182,
} as const;

// ---------------------------------------------------------------------------
// Lifecycle states
//
// Every agent traverses these states. State transitions are governed
// by trust signals and operator decisions.
// ---------------------------------------------------------------------------

export interface LifecycleStateSpec {
  readonly description: string;
  readonly canOperate: boolean;
  readonly canGain: boolean;
  readonly canLose: boolean;
}

export const LIFECYCLE_STATES = {
  PROVISIONING: { description: 'Qualification course in progress', canOperate: false, canGain: false, canLose: false },
  ACTIVE:       { description: 'Normal operation',                 canOperate: true,  canGain: true,  canLose: true },
  AUDITED:      { description: 'Enhanced monitoring',              canOperate: true,  canGain: true,  canLose: true },
  DEGRADED:     { description: 'Gains frozen, losses apply',       canOperate: true,  canGain: false, canLose: true },
  SUSPENDED:    { description: 'Read-only, writes queued',         canOperate: false, canGain: false, canLose: true },
  TRIPPED:      { description: 'Fully blocked',                    canOperate: false, canGain: false, canLose: false },
  RETIRED:      { description: 'Deactivated, data preserved',      canOperate: false, canGain: false, canLose: false },
  VANQUISHED:   { description: 'Permanent, irreversible',          canOperate: false, canGain: false, canLose: false },
} as const satisfies Record<string, LifecycleStateSpec>;

export type LifecycleState = keyof typeof LIFECYCLE_STATES;

// ---------------------------------------------------------------------------
// Trust inheritance
//
// The standard does NOT support positive trust inheritance from a parent
// agent or model. A derived agent starts at INITIAL_TRUST_SCORE and must
// pass qualification regardless of parent trust. Provenance modifiers
// MAY apply additional negative pressure.
// ---------------------------------------------------------------------------

export const TRUST_INHERITANCE = 'NONE' as const;
export const MAX_PROVENANCE_MODIFIER = 0;

// ---------------------------------------------------------------------------
// Spec version
// ---------------------------------------------------------------------------

export const BASIS_SPEC_VERSION = '1.0.0' as const;
