// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Truth-only structural validator for an EXTERNAL proof-chain manifest.
 *
 * Given a manifest (a JSON array of proof-chain events emitted by ANY
 * runtime — not just the reference impl), this checks required-field
 * PRESENCE and basic per-field shape against RFC-0002 §"Schema". It is
 * deliberately narrow:
 *
 *   - It reports ONLY structural facts (missing field, wrong type, wrong
 *     format). It does NOT emit any trust, compliance, or conformance
 *     verdict — "structurally well-formed" is not "trusted".
 *   - It does NOT verify signatures, recompute eventHash, or walk the
 *     hash chain's cryptographic linkage. Those are the runtime's /
 *     verifier's job (RFC-0002 §"Verification procedure"), not a
 *     structural pre-check's.
 *   - A `valid: true` result means every event carries the required
 *     fields in a plausible shape — nothing more.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

export interface ManifestError {
  /** Index of the offending event in the manifest array (-1 = whole manifest). */
  readonly index: number;
  /** Dotted field path that failed, or '(manifest)' for top-level problems. */
  readonly field: string;
  /** Human-readable description of the structural problem. */
  readonly problem: string;
}

export interface ManifestValidationResult {
  readonly valid: boolean;
  readonly errors: ReadonlyArray<ManifestError>;
}

const HASH_HEX = /^[0-9a-f]{64}$/;
const PROOF_EVENT_TYPES = [
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
const SHADOW_MODES = ['production', 'shadow', 'testnet', 'verified', 'rejected'];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

/** Loose ISO-8601 check: parseable date AND a date-time-shaped string. */
function isIsoDateTime(v: unknown): boolean {
  return (
    typeof v === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(v) &&
    !Number.isNaN(Date.parse(v))
  );
}

/**
 * Validate a single event's structure, pushing errors into `out`.
 * Checks ONLY presence + shape of the public RFC-0002 fields.
 */
function checkEvent(
  ev: unknown,
  index: number,
  out: ManifestError[],
): void {
  const push = (field: string, problem: string): void => {
    out.push({ index, field, problem });
  };

  if (!isObject(ev)) {
    push('(event)', 'event must be a JSON object');
    return;
  }

  // Required strings.
  if (!isNonEmptyString(ev.eventId)) push('eventId', 'missing or empty (required non-empty string)');
  if (!isNonEmptyString(ev.correlationId)) push('correlationId', 'missing or empty (required non-empty string)');

  // eventType must be one of the canonical values.
  if (!isNonEmptyString(ev.eventType)) {
    push('eventType', 'missing or empty (required non-empty string)');
  } else if (!(PROOF_EVENT_TYPES as readonly string[]).includes(ev.eventType)) {
    push('eventType', `not a canonical proof event type: "${ev.eventType}"`);
  }

  // payload must be an object carrying a non-empty `type` discriminator.
  if (!isObject(ev.payload)) {
    push('payload', 'missing (required object)');
  } else if (!isNonEmptyString(ev.payload.type)) {
    push('payload.type', 'missing or empty (required payload discriminator)');
  }

  // previousHash: null (chain head) or 64-char lowercase hex.
  if (!('previousHash' in ev)) {
    push('previousHash', 'missing (required: null for chain head, else 64-char lowercase hex)');
  } else if (ev.previousHash !== null && !(typeof ev.previousHash === 'string' && HASH_HEX.test(ev.previousHash))) {
    push('previousHash', 'must be null or 64-char lowercase hex');
  }

  // eventHash: required 64-char lowercase hex (presence/shape only — not recomputed).
  if (!('eventHash' in ev)) {
    push('eventHash', 'missing (required 64-char lowercase hex)');
  } else if (!(typeof ev.eventHash === 'string' && HASH_HEX.test(ev.eventHash))) {
    push('eventHash', 'must be 64-char lowercase hex');
  }

  // Required ISO-8601 timestamps.
  if (!isIsoDateTime(ev.occurredAt)) push('occurredAt', 'missing or not ISO-8601 date-time');
  if (!isIsoDateTime(ev.recordedAt)) push('recordedAt', 'missing or not ISO-8601 date-time');

  // Optional fields — only checked for shape WHEN present.
  if ('eventHash3' in ev && !(typeof ev.eventHash3 === 'string' && HASH_HEX.test(ev.eventHash3))) {
    push('eventHash3', 'when present, must be 64-char lowercase hex');
  }
  if ('agentId' in ev && ev.agentId !== undefined && !isNonEmptyString(ev.agentId)) {
    push('agentId', 'when present, must be a non-empty string');
  }
  if ('shadowMode' in ev && ev.shadowMode !== undefined && !SHADOW_MODES.includes(ev.shadowMode as string)) {
    push('shadowMode', `when present, must be one of: ${SHADOW_MODES.join(', ')}`);
  }
  // RFC-0002: verified/rejected require verificationId + verifiedAt.
  if (ev.shadowMode === 'verified' || ev.shadowMode === 'rejected') {
    if (!isNonEmptyString(ev.verificationId)) {
      push('verificationId', `required when shadowMode is "${ev.shadowMode}"`);
    }
    if (!isIsoDateTime(ev.verifiedAt)) {
      push('verifiedAt', `required (ISO-8601) when shadowMode is "${ev.shadowMode}"`);
    }
  }
}

/**
 * Validate a proof-chain manifest's structure.
 *
 * @param manifest An array of proof-chain events (already JSON-parsed).
 * @returns `{ valid, errors }`. Purely structural — NOT a trust verdict.
 */
export function validateManifest(manifest: unknown): ManifestValidationResult {
  const errors: ManifestError[] = [];

  if (!Array.isArray(manifest)) {
    errors.push({
      index: -1,
      field: '(manifest)',
      problem: 'manifest must be a JSON array of proof-chain events',
    });
    return { valid: false, errors };
  }

  manifest.forEach((ev, i) => checkEvent(ev, i, errors));

  return { valid: errors.length === 0, errors };
}
