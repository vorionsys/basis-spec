/**
 * BASIS — Zod validators for runtime conformance checks.
 *
 * Importing from `@basis-spec/basis/zod` is optional. Implementations that
 * already have their own validation layer can use the canonical constants
 * and types directly without pulling in the Zod dependency at runtime.
 */

import { z } from 'zod';
import {
  MIN_TRUST_SCORE,
  MAX_TRUST_SCORE,
  TRUST_TIERS,
  RISK_LEVELS,
  OBSERVATION_TIERS,
  LIFECYCLE_STATES,
} from './canonical.js';

const tierKeys = Object.keys(TRUST_TIERS) as [keyof typeof TRUST_TIERS, ...Array<keyof typeof TRUST_TIERS>];
const riskKeys = Object.keys(RISK_LEVELS) as [keyof typeof RISK_LEVELS, ...Array<keyof typeof RISK_LEVELS>];
const observationKeys = Object.keys(OBSERVATION_TIERS) as [keyof typeof OBSERVATION_TIERS, ...Array<keyof typeof OBSERVATION_TIERS>];
const lifecycleKeys = Object.keys(LIFECYCLE_STATES) as [keyof typeof LIFECYCLE_STATES, ...Array<keyof typeof LIFECYCLE_STATES>];

export const TrustScoreSchema = z
  .number()
  .min(MIN_TRUST_SCORE)
  .max(MAX_TRUST_SCORE);

export const TrustTierSchema = z.enum(tierKeys);
export const RiskLevelSchema = z.enum(riskKeys);
export const ObservationTierSchema = z.enum(observationKeys);
export const LifecycleStateSchema = z.enum(lifecycleKeys);

export const AgentTrustStateSchema = z.object({
  agentId: z.string().min(1),
  score: TrustScoreSchema,
  tier: TrustTierSchema,
  observationTier: ObservationTierSchema,
  lifecycleState: LifecycleStateSchema,
  lastActivity: z.string().datetime(),
});

export const GateDecisionSchema = z.object({
  allowed: z.boolean(),
  reason: z.enum([
    'ALLOWED',
    'INSUFFICIENT_TRUST',
    'CIRCUIT_BREAKER',
    'LIFECYCLE_BLOCKED',
    'OBSERVATION_CEILING',
  ]),
  requiredScore: TrustScoreSchema,
  currentScore: TrustScoreSchema,
});

export type AgentTrustState = z.infer<typeof AgentTrustStateSchema>;
export type GateDecision = z.infer<typeof GateDecisionSchema>;

// Proof-chain validators (RFC-0002). Re-exported here so consumers
// can import everything Zod-related from a single entry point:
//   `import { ProofEventSchema } from '@basis-spec/basis/zod';`
export {
  ProofEventSchema,
  ProofEventPayloadSchema,
  ProofEventFilterSchema,
  ChainVerificationResultSchema,
  LogProofEventRequestSchema,
  ProofEventSummarySchema,
} from './proof-chain-schema.js';
