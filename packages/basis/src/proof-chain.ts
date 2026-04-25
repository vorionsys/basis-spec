// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS — Proof Chain types.
 *
 * Source of truth for the public-facing shape of every audit event a
 * BASIS-compliant runtime emits. Auditors, compliance officers, and
 * customer SOC teams consume this shape to verify what their governance
 * gateway is recording on their behalf.
 *
 * Implementation independence: any conforming runtime — open or
 * proprietary — MUST emit events that validate against the Zod schema in
 * `./proof-chain-schema.ts`. The cryptographic operations that produce
 * `eventHash`, `previousHash`, and `signature` are described in
 * `rfcs/0002-proof-event-chain.md`. This file fixes the *contract*; the
 * impl is the runtime's business.
 *
 * Timestamps are ISO 8601 strings (not Date) so the contract serializes
 * losslessly across language boundaries (Python, Go, Rust, JSON-only
 * pipelines). Implementations MAY parse to native Date types internally.
 */

/**
 * Event types in a BASIS proof chain. Stable string values — implementations
 * MUST emit exactly these strings (lowercase, snake_case) so consumers can
 * dispatch by `eventType` without per-impl translation tables.
 *
 * New event types added to this enum require an RFC amendment.
 */
export const PROOF_EVENT_TYPES = [
  'intent_received',
  'decision_made',
  'trust_delta',
  'execution_started',
  'execution_completed',
  'execution_failed',
  'incident_detected',
  'rollback_initiated',
  'component_registered',
  'component_updated',
] as const;

export type ProofEventType = (typeof PROOF_EVENT_TYPES)[number];

/**
 * Shadow-mode status for events emitted from sandbox / testnet contexts.
 *
 * Events from T0_SANDBOX agents (or any agent in `lifecycleState`
 * `PROVISIONING`) are tagged `shadow` and recorded but excluded from
 * production trust scores until verified by a HITL review. This solves
 * the chicken-and-egg problem of validating sandbox behavior without
 * letting unproven agents move the production score.
 */
export type ShadowModeStatus =
  | 'production'
  | 'shadow'
  | 'testnet'
  | 'verified'
  | 'rejected';

/**
 * The canonical proof event — one immutable entry in a BASIS audit chain.
 *
 * Hash chain: `previousHash` is the `eventHash` of the immediately prior
 * event for the same chain (per-tenant, or per-agent depending on impl
 * scope). The first event in a chain has `previousHash: null`.
 *
 * `eventHash` is sha256 over the canonical-JSON serialization of
 * (`previousHash || eventType || agentId || occurredAt || payload`).
 * The exact serialization rules are in RFC-0002 §"Hash semantics".
 *
 * `eventHash3` is an optional SHA3-256 dual-anchor over the same
 * serialization. Recommended for chains intended to outlive the SHA-256
 * security horizon. Verifiers SHOULD check both when present.
 *
 * Implementations MAY add additional fields for their internal needs
 * (e.g., a database row id, a tenant id) but MUST NOT change the
 * meaning or constraints of the fields below. Conformance suites verify
 * the public shape; private fields are out of scope.
 */
export interface ProofEvent {
  /** Implementation-assigned unique identifier (UUID recommended). */
  readonly eventId: string;

  /** One of `PROOF_EVENT_TYPES`. */
  readonly eventType: ProofEventType;

  /** Correlation id linking related events end-to-end across components. */
  readonly correlationId: string;

  /** Agent involved (omitted for non-agent events such as platform updates). */
  readonly agentId?: string;

  /** Typed payload; structure varies by `eventType`. See payload interfaces. */
  readonly payload: ProofEventPayload;

  /**
   * Hash of the previous event in this chain, or `null` for the first
   * event. Verifiers walking the chain compare the previous event's
   * `eventHash` to the next event's `previousHash`.
   */
  readonly previousHash: string | null;

  /** SHA-256 of the canonical serialization. Hex-encoded, lowercase. */
  readonly eventHash: string;

  /** Optional SHA3-256 dual anchor. Hex-encoded, lowercase when present. */
  readonly eventHash3?: string;

  /** ISO 8601 timestamp of when the event happened in the world. */
  readonly occurredAt: string;

  /**
   * ISO 8601 timestamp of when the event was committed to the chain.
   * MAY differ from `occurredAt` if the runtime buffers writes.
   */
  readonly recordedAt: string;

  /** Identity of the signer (key fingerprint, runtime id, or DID). */
  readonly signedBy?: string;

  /**
   * Detached signature over `eventHash` (and `eventHash3` when present).
   * Algorithm and encoding are described in the runtime's signing key
   * advertisement; verifiers fetch the key by `signedBy`.
   */
  readonly signature?: string;

  /**
   * Shadow-mode status. Events from sandbox or testnet contexts MUST be
   * tagged `shadow` or `testnet` so production analysis pipelines can
   * exclude them from trust accounting.
   *
   * @default 'production'
   */
  readonly shadowMode?: ShadowModeStatus;

  /**
   * Identifier of the HITL review that transitioned this event from
   * `shadow` to `verified` or `rejected`. Required when `shadowMode`
   * is `verified` or `rejected`.
   */
  readonly verificationId?: string;

  /** ISO 8601 timestamp of the HITL transition (when applicable). */
  readonly verifiedAt?: string;
}

// =====================================================================
// Payload variants (one per event type)
// =====================================================================

export type ProofEventPayload =
  | IntentReceivedPayload
  | DecisionMadePayload
  | TrustDeltaPayload
  | ExecutionStartedPayload
  | ExecutionCompletedPayload
  | ExecutionFailedPayload
  | IncidentDetectedPayload
  | RollbackInitiatedPayload
  | ComponentRegisteredPayload
  | ComponentUpdatedPayload
  | GenericPayload;

export interface IntentReceivedPayload {
  readonly type: 'intent_received';
  readonly intentId: string;
  readonly action: string;
  readonly actionType: string;
  readonly resourceScope: ReadonlyArray<string>;
}

export interface DecisionMadePayload {
  readonly type: 'decision_made';
  readonly decisionId: string;
  readonly intentId: string;
  readonly permitted: boolean;
  readonly trustBand: string;
  readonly trustScore: number;
  readonly reasoning: ReadonlyArray<string>;
}

export interface TrustDeltaPayload {
  readonly type: 'trust_delta';
  readonly deltaId: string;
  readonly previousScore: number;
  readonly newScore: number;
  readonly previousBand: string;
  readonly newBand: string;
  readonly reason: string;
}

export interface ExecutionStartedPayload {
  readonly type: 'execution_started';
  readonly executionId: string;
  readonly actionId: string;
  readonly decisionId: string;
  readonly adapterId: string;
}

export interface ExecutionCompletedPayload {
  readonly type: 'execution_completed';
  readonly executionId: string;
  readonly actionId: string;
  readonly status: 'success' | 'partial';
  readonly durationMs: number;
  /** Hex-encoded SHA-256 of the action output (or canonical equivalent). */
  readonly outputHash: string;
}

export interface ExecutionFailedPayload {
  readonly type: 'execution_failed';
  readonly executionId: string;
  readonly actionId: string;
  readonly error: string;
  readonly durationMs: number;
  readonly retryable: boolean;
}

export interface IncidentDetectedPayload {
  readonly type: 'incident_detected';
  readonly incidentId: string;
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
  readonly description: string;
  readonly affectedResources: ReadonlyArray<string>;
}

export interface RollbackInitiatedPayload {
  readonly type: 'rollback_initiated';
  readonly rollbackId: string;
  readonly executionId: string;
  readonly reason: string;
  readonly initiatedBy: string;
}

export interface ComponentRegisteredPayload {
  readonly type: 'component_registered';
  readonly componentId: string;
  readonly componentType: string;
  readonly name: string;
  readonly version: string;
}

export interface ComponentUpdatedPayload {
  readonly type: 'component_updated';
  readonly componentId: string;
  readonly changes: ReadonlyArray<string>;
  readonly previousVersion?: string;
  readonly newVersion?: string;
}

/**
 * Escape hatch for impls that need to record event types not yet covered
 * by a typed variant. New event types SHOULD migrate to a typed payload
 * via RFC amendment; the generic form is only for forward-compatibility
 * during transition windows.
 */
export interface GenericPayload {
  readonly type: string;
  readonly [key: string]: unknown;
}

// =====================================================================
// Query and verification surfaces
// =====================================================================

/**
 * Filter for chain-query operations. All fields optional. Implementations
 * MAY support additional vendor-specific filters but MUST honor these.
 */
export interface ProofEventFilter {
  readonly correlationId?: string;
  readonly agentId?: string;
  readonly eventTypes?: ReadonlyArray<ProofEventType>;
  /** ISO 8601 inclusive lower bound on `occurredAt`. */
  readonly from?: string;
  /** ISO 8601 inclusive upper bound on `occurredAt`. */
  readonly to?: string;
  readonly limit?: number;
  readonly offset?: number;
}

/**
 * Result of an end-to-end chain verification pass. A conforming
 * verifier walks every event, recomputes `eventHash` from the canonical
 * serialization, and confirms each `previousHash` matches the prior
 * event's `eventHash`. `valid: false` MUST set `brokenAt` to the first
 * event id where the chain failed.
 */
export interface ChainVerificationResult {
  readonly valid: boolean;
  readonly verifiedEvents: number;
  readonly firstEventId: string;
  readonly lastEventId: string;
  readonly brokenAt?: string;
  readonly error?: string;
}

/**
 * Request shape for logging a new event. Runtimes derive `eventId`,
 * `eventHash`, `previousHash`, `recordedAt`, and `signature` themselves
 * — clients SHOULD NOT supply these fields.
 */
export interface LogProofEventRequest {
  readonly eventType: ProofEventType;
  readonly correlationId: string;
  readonly agentId?: string;
  readonly payload: ProofEventPayload;
  /** Defaults to current time if omitted. */
  readonly occurredAt?: string;
  readonly signedBy?: string;
}

/** Lightweight summary for pagination / listing. */
export interface ProofEventSummary {
  readonly eventId: string;
  readonly eventType: ProofEventType;
  readonly correlationId: string;
  readonly agentId?: string;
  readonly occurredAt: string;
  readonly recordedAt: string;
}
