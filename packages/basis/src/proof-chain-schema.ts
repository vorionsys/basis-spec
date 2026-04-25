// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * BASIS — Zod validators for proof-chain events.
 *
 * Optional runtime companion to `./proof-chain.ts`. Implementations that
 * already have their own validation layer can use the TypeScript types
 * directly. Auditors and conformance harnesses use these schemas to
 * verify any vendor's exported audit log against the public contract.
 *
 * Usage:
 *   import { ProofEventSchema } from '@basis-spec/basis/zod';
 *   const ev = ProofEventSchema.parse(jsonFromVendor);
 *   // ev is statically typed as ProofEvent
 *
 * The schemas MUST stay in sync with the TypeScript shapes in
 * `proof-chain.ts`. RFC-0002 amendments update both files together.
 */

import { z } from 'zod';
import { PROOF_EVENT_TYPES } from './proof-chain.js';

// =====================================================================
// Primitives
// =====================================================================

/** Hex-encoded hash, lowercase, allows sha-256 (64 chars) or sha3-256 (64 chars). */
const HashHexSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, 'expected 64-char lowercase hex (sha-256 or sha3-256)');

/** Loose ISO 8601 — full date-time, optional fractional seconds, Z or offset. */
const Iso8601Schema = z.string().datetime({ offset: true });

const ProofEventTypeSchema = z.enum(
  PROOF_EVENT_TYPES as unknown as [string, ...Array<string>],
);

const ShadowModeStatusSchema = z.enum([
  'production',
  'shadow',
  'testnet',
  'verified',
  'rejected',
]);

// =====================================================================
// Payload variants
// =====================================================================

const IntentReceivedPayloadSchema = z.object({
  type: z.literal('intent_received'),
  intentId: z.string().min(1),
  action: z.string().min(1),
  actionType: z.string().min(1),
  resourceScope: z.array(z.string()),
});

const DecisionMadePayloadSchema = z.object({
  type: z.literal('decision_made'),
  decisionId: z.string().min(1),
  intentId: z.string().min(1),
  permitted: z.boolean(),
  trustBand: z.string().min(1),
  trustScore: z.number(),
  reasoning: z.array(z.string()),
});

const TrustDeltaPayloadSchema = z.object({
  type: z.literal('trust_delta'),
  deltaId: z.string().min(1),
  previousScore: z.number(),
  newScore: z.number(),
  previousBand: z.string().min(1),
  newBand: z.string().min(1),
  reason: z.string(),
});

const ExecutionStartedPayloadSchema = z.object({
  type: z.literal('execution_started'),
  executionId: z.string().min(1),
  actionId: z.string().min(1),
  decisionId: z.string().min(1),
  adapterId: z.string().min(1),
});

const ExecutionCompletedPayloadSchema = z.object({
  type: z.literal('execution_completed'),
  executionId: z.string().min(1),
  actionId: z.string().min(1),
  status: z.enum(['success', 'partial']),
  durationMs: z.number().nonnegative(),
  outputHash: HashHexSchema,
});

const ExecutionFailedPayloadSchema = z.object({
  type: z.literal('execution_failed'),
  executionId: z.string().min(1),
  actionId: z.string().min(1),
  error: z.string(),
  durationMs: z.number().nonnegative(),
  retryable: z.boolean(),
});

const IncidentDetectedPayloadSchema = z.object({
  type: z.literal('incident_detected'),
  incidentId: z.string().min(1),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  description: z.string(),
  affectedResources: z.array(z.string()),
});

const RollbackInitiatedPayloadSchema = z.object({
  type: z.literal('rollback_initiated'),
  rollbackId: z.string().min(1),
  executionId: z.string().min(1),
  reason: z.string(),
  initiatedBy: z.string().min(1),
});

const ComponentRegisteredPayloadSchema = z.object({
  type: z.literal('component_registered'),
  componentId: z.string().min(1),
  componentType: z.string().min(1),
  name: z.string().min(1),
  version: z.string().min(1),
});

const ComponentUpdatedPayloadSchema = z.object({
  type: z.literal('component_updated'),
  componentId: z.string().min(1),
  changes: z.array(z.string()),
  previousVersion: z.string().optional(),
  newVersion: z.string().optional(),
});

/**
 * Generic payload for forward-compatibility. New event types should
 * earn a typed schema via RFC amendment; this only exists to keep
 * the chain valid through transitions.
 */
const GenericPayloadSchema = z
  .object({ type: z.string().min(1) })
  .catchall(z.unknown());

export const ProofEventPayloadSchema = z.union([
  IntentReceivedPayloadSchema,
  DecisionMadePayloadSchema,
  TrustDeltaPayloadSchema,
  ExecutionStartedPayloadSchema,
  ExecutionCompletedPayloadSchema,
  ExecutionFailedPayloadSchema,
  IncidentDetectedPayloadSchema,
  RollbackInitiatedPayloadSchema,
  ComponentRegisteredPayloadSchema,
  ComponentUpdatedPayloadSchema,
  GenericPayloadSchema,
]);

// =====================================================================
// ProofEvent
// =====================================================================

export const ProofEventSchema = z
  .object({
    eventId: z.string().min(1),
    eventType: ProofEventTypeSchema,
    correlationId: z.string().min(1),
    agentId: z.string().min(1).optional(),
    payload: ProofEventPayloadSchema,
    previousHash: z.union([HashHexSchema, z.null()]),
    eventHash: HashHexSchema,
    eventHash3: HashHexSchema.optional(),
    occurredAt: Iso8601Schema,
    recordedAt: Iso8601Schema,
    signedBy: z.string().min(1).optional(),
    signature: z.string().min(1).optional(),
    shadowMode: ShadowModeStatusSchema.optional(),
    verificationId: z.string().min(1).optional(),
    verifiedAt: Iso8601Schema.optional(),
  })
  .refine(
    (ev) => {
      // payload.type MUST match top-level eventType
      return ev.payload.type === ev.eventType || ev.payload.type === 'generic';
    },
    {
      message:
        'payload.type must match eventType (or be a generic payload during a transition window)',
      path: ['payload', 'type'],
    },
  )
  .refine(
    (ev) => {
      // verificationId + verifiedAt required when shadowMode is a HITL outcome
      if (ev.shadowMode === 'verified' || ev.shadowMode === 'rejected') {
        return ev.verificationId !== undefined && ev.verifiedAt !== undefined;
      }
      return true;
    },
    {
      message:
        'verificationId and verifiedAt are required when shadowMode is "verified" or "rejected"',
      path: ['verificationId'],
    },
  );

export const ProofEventFilterSchema = z.object({
  correlationId: z.string().min(1).optional(),
  agentId: z.string().min(1).optional(),
  eventTypes: z.array(ProofEventTypeSchema).optional(),
  from: Iso8601Schema.optional(),
  to: Iso8601Schema.optional(),
  limit: z.number().int().positive().optional(),
  offset: z.number().int().nonnegative().optional(),
});

export const ChainVerificationResultSchema = z.object({
  valid: z.boolean(),
  verifiedEvents: z.number().int().nonnegative(),
  firstEventId: z.string().min(1),
  lastEventId: z.string().min(1),
  brokenAt: z.string().min(1).optional(),
  error: z.string().optional(),
});

export const LogProofEventRequestSchema = z.object({
  eventType: ProofEventTypeSchema,
  correlationId: z.string().min(1),
  agentId: z.string().min(1).optional(),
  payload: ProofEventPayloadSchema,
  occurredAt: Iso8601Schema.optional(),
  signedBy: z.string().min(1).optional(),
});

export const ProofEventSummarySchema = z.object({
  eventId: z.string().min(1),
  eventType: ProofEventTypeSchema,
  correlationId: z.string().min(1),
  agentId: z.string().min(1).optional(),
  occurredAt: Iso8601Schema,
  recordedAt: Iso8601Schema,
});
