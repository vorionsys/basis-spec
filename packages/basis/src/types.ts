/**
 * BASIS — Public type surface.
 *
 * Re-exports the spec types from canonical for ergonomic imports.
 */

export type {
  TrustTier,
  TrustTierSpec,
  RiskLevel,
  RiskLevelSpec,
  ObservationTier,
  ObservationTierSpec,
  LifecycleState,
  LifecycleStateSpec,
  DormancyMilestone,
} from './canonical.js';

/**
 * Conforming implementations represent an agent's trust state with at
 * minimum these fields. Implementations MAY add fields for their own
 * runtime needs, but MUST NOT change the meaning or constraints below.
 */
export interface AgentTrustState {
  readonly agentId: string;
  /** Current trust score in [0, 1000]. */
  readonly score: number;
  /** Current tier identifier derived from `score`. */
  readonly tier: import('./canonical.js').TrustTier;
  /** Observation tier governing the score ceiling. */
  readonly observationTier: import('./canonical.js').ObservationTier;
  /** Current lifecycle state. */
  readonly lifecycleState: import('./canonical.js').LifecycleState;
  /** ISO 8601 timestamp of the last trust-relevant event. */
  readonly lastActivity: string;
}

/**
 * The result of evaluating a proposed action against an agent's trust
 * state. Implementations gating actions SHOULD return a value of this
 * shape so consumers can interoperate.
 */
export interface GateDecision {
  readonly allowed: boolean;
  readonly reason: 'ALLOWED' | 'INSUFFICIENT_TRUST' | 'CIRCUIT_BREAKER' | 'LIFECYCLE_BLOCKED' | 'OBSERVATION_CEILING';
  readonly requiredScore: number;
  readonly currentScore: number;
}
