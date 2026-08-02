// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0006 types — execution plan verification.
 *
 * A plan is a DAG of steps with declared effects, plus the invariants it must
 * not violate. Acyclicity is not a convenience: it is what keeps the
 * verification obligation decidable.
 *
 * Spec reference: rfcs/0006-plan-verification.md
 */

import type { RiskLevel } from '@vorionsys/basis-spec';

/** Boolean condition over the plan's variable vocabulary. Stays within QF_LIA. */
export type Condition =
  /** A free boolean — the solver explores both values, giving branch coverage. */
  | { readonly kind: 'var'; readonly name: string }
  | { readonly kind: 'not'; readonly operand: Condition }
  | { readonly kind: 'and'; readonly operands: ReadonlyArray<Condition> }
  | { readonly kind: 'or'; readonly operands: ReadonlyArray<Condition> }
  /** Compare an integer symbol or accumulator against a constant. */
  | {
      readonly kind: 'compare';
      readonly left: string;
      readonly op: '<' | '<=' | '=' | '>=' | '>';
      readonly right: number;
    };

/**
 * A declared state change.
 *
 * ⚠️ Effects are a TRUST INPUT, not a verified output. If a step declares it
 * writes 100 and it actually writes 10,000, verification is sound about a
 * fiction. See RFC-0006 §"What this verifies — and what it does not".
 */
export type Effect =
  /** `counter += amount`. A string amount names a symbol (see `symbols`). */
  | {
      readonly kind: 'accumulate';
      readonly counter: string;
      readonly amount: number | string;
    }
  /** Resource access, for reachability and taint reasoning. */
  | {
      readonly kind: 'access';
      readonly mode: 'read' | 'write' | 'delete';
      readonly resource: string;
    }
  /** Explicit assignment to an integer variable. */
  | { readonly kind: 'assign'; readonly variable: string; readonly value: number };

export type Invariant =
  /** Linear bound over an accumulator. */
  | {
      readonly kind: 'bound';
      readonly id: string;
      readonly counter: string;
      readonly op: '<=' | '<' | '>=' | '>';
      readonly limit: number;
    }
  /** A resource that must not be touched in this mode on ANY path. */
  | {
      readonly kind: 'forbid';
      readonly id: string;
      readonly mode: 'read' | 'write' | 'delete';
      readonly resource: string;
    }
  /**
   * Ordering / taint. Violated when `after` executes on a path where `before`
   * also executed — the shape that catches read-restricted-then-write-external.
   */
  | {
      readonly kind: 'never_after';
      readonly id: string;
      readonly before: string;
      readonly after: string;
    }
  /** Arbitrary predicate that must hold. */
  | { readonly kind: 'predicate'; readonly id: string; readonly expression: Condition };

export interface PlanStep {
  readonly stepId: string;
  readonly actionType: string;
  readonly resourceScope: ReadonlyArray<string>;
  readonly riskLevel?: RiskLevel;
  readonly effects: ReadonlyArray<Effect>;
  /** Guard under which this step runs at all. Absent means unconditional. */
  readonly guard?: Condition;
}

export interface PlanEdge {
  readonly from: string;
  readonly to: string;
  /** Additional condition on taking this edge. */
  readonly condition?: Condition;
}

/**
 * A symbolic quantity whose exact value is not known at plan time.
 *
 * Bounds matter more than they look. An UNBOUNDED symbol cannot satisfy any
 * accumulator bound — the solver will correctly return a counterexample where
 * it is arbitrarily large. That is not a tool defect; you genuinely cannot
 * prove a limit over a quantity you have not constrained. Declare bounds, or
 * expect (and read) the counterexample.
 */
export interface PlanSymbol {
  readonly name: string;
  readonly min?: number;
  readonly max?: number;
}

export interface ExecutionPlan {
  readonly planId: string;
  readonly steps: ReadonlyArray<PlanStep>;
  readonly edges: ReadonlyArray<PlanEdge>;
  readonly invariants: ReadonlyArray<Invariant>;
  readonly symbols?: ReadonlyArray<PlanSymbol>;
  /** Set when iteration was flattened. Records exactly what can execute. */
  readonly unrollBound?: number;
}

// ---------------------------------------------------------------------------
// Verification results
// ---------------------------------------------------------------------------

export type PlanOutcome = 'proved_safe' | 'counterexample' | 'inconclusive';

export type SolverResult = 'unsat' | 'sat' | 'unknown';

export interface SolverIdentity {
  readonly name: string;
  readonly version: string;
  readonly seed?: string;
}

export interface VerificationRecord {
  readonly logic: string;
  readonly result: SolverResult;
  readonly solver: SolverIdentity;
  /** The exact program solved. Publishing this is what makes the result checkable. */
  readonly smtlib2: string;
  readonly smtlib2Hash: string;
  /** For `sat`: the violating assignment — the counterexample IS the artefact. */
  readonly model?: string;
  readonly durationMs?: number;
  /** Present when the solve could not be trusted. Forces `inconclusive`. */
  readonly diagnostic?: string;
}

export interface PlanVerification {
  readonly planId: string;
  readonly outcome: PlanOutcome;
  /** Invariant ids checked. A verdict without this is unfalsifiable. */
  readonly invariantsChecked: ReadonlyArray<string>;
  readonly verification: VerificationRecord;
  /** Invariants the counterexample violates, when determinable. */
  readonly violated?: ReadonlyArray<string>;
}

// ---------------------------------------------------------------------------
// RFC-0006 event payloads
// ---------------------------------------------------------------------------

export const PLAN_EVENT_TYPES = ['plan_submitted', 'plan_verified'] as const;
export type PlanEventType = (typeof PLAN_EVENT_TYPES)[number];

export interface PlanSubmittedPayload {
  readonly type: 'plan_submitted';
  readonly planId: string;
  readonly intentId?: string;
  readonly plan: ExecutionPlan;
  readonly submittedAt: string;
}

export interface PlanVerifiedPayload {
  readonly type: 'plan_verified';
  readonly planId: string;
  /** eventHash of the `plan_submitted` this verdict applies to. */
  readonly planEventHash: string;
  readonly outcome: PlanOutcome;
  readonly invariantsChecked: ReadonlyArray<string>;
  readonly verification: VerificationRecord;
  readonly violated?: ReadonlyArray<string>;
  readonly verifiedAt: string;
}

export type PlanPayload = PlanSubmittedPayload | PlanVerifiedPayload;
