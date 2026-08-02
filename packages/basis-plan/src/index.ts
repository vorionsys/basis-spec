// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * `@vorionsys/basis-plan` — public reference implementation of BASIS RFC-0006,
 * symbolic verification of multi-step agent execution plans.
 *
 * An agent declares a DAG of steps with their effects, plus the invariants the
 * plan must not violate. A solver is asked to find any path that reaches a
 * violating state. If none exists, the plan is proved safe OVER ALL PATHS —
 * not merely over the path that happened to be sampled.
 *
 * WHY THIS IS WORTH STANDARDISING: the result is REPRODUCIBLE. The exact
 * SMT-LIB2 program and the solver identity are published, so a buyer, auditor
 * or regulator re-runs the solve and obtains the same answer without trusting
 * the runtime that produced it. Unlike a classifier score, this is not a
 * vendor assertion — it is a claim anyone can check.
 *
 * WHAT `proved_safe` MEANS, precisely: no path through the DECLARED graph,
 * under the DECLARED effect semantics, reaches a state violating the DECLARED
 * invariants. Every qualifier is load-bearing:
 *
 *   - It is a proof about the plan, not about the agent's code.
 *   - It does not establish that declared effects are truthful. If a step says
 *     it writes 100 and it writes 10,000, the proof is sound about a fiction.
 *     Effects are a TRUST INPUT. Per-step gating at execution time is what
 *     converts that from a hole into an enforceable commitment.
 *   - It does not guarantee the agent follows the plan.
 *   - A plan can be provably safe and commercially catastrophic.
 *
 * THIS DOES NOT REPLACE PRE-ACTION GATING, and must not be presented as an
 * evolution beyond it. Plan verification covers composition and sequencing
 * across a whole plan but is blind to anything undeclared and to the agent
 * deviating. A per-action gate covers the actual call but is blind to
 * composition. The useful guarantee comes from running both: verify the plan,
 * then gate each action AGAINST the approved plan.
 *
 * Spec: rfcs/0006-plan-verification.md
 */

export {
  PLAN_EVENT_TYPES,
  type Condition,
  type Effect,
  type Invariant,
  type PlanStep,
  type PlanEdge,
  type PlanSymbol,
  type ExecutionPlan,
  type PlanOutcome,
  type SolverResult,
  type SolverIdentity,
  type VerificationRecord,
  type PlanVerification,
  type PlanEventType,
  type PlanSubmittedPayload,
  type PlanVerifiedPayload,
  type PlanPayload,
} from './types.js';

export { encodePlan, PlanEncodingError, type EncodedPlan } from './encode.js';

export { verifyPlan, verifyEncoded, type VerifyOptions } from './verify.js';
