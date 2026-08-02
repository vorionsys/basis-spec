/**
 * BASIS — Canonical JSON serialization (RFC-0002 §"Canonical serialization")
 *
 * This is the NORMATIVE serializer. Every hash and every signature in a BASIS
 * proof chain is computed over bytes produced here. If two implementations
 * disagree about these bytes, their chains cannot verify against each other —
 * which is the one failure this whole standard exists to prevent.
 *
 * It lives in the spec package rather than in any tool so that every
 * consumer — the reference verifier, the quorum reference implementation,
 * and any vendor runtime — hashes identical bytes by construction rather
 * than by careful re-implementation.
 *
 * Rules, per RFC-0002:
 *   1. Object keys sorted in ASCII-byte order.
 *   2. Strings UTF-8, no escape variants beyond what JSON requires.
 *   3. Numbers as the shortest decimal that round-trips exactly.
 *   4. No whitespace.
 *   5. `null` is serialized; `undefined` keys are omitted.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

/**
 * Serialize a value to canonical JSON per RFC-0002.
 *
 * @throws if the value contains a non-finite number or an unsupported type —
 *   a value that cannot be canonicalized must never be hashed as something
 *   else, so this fails loudly rather than coercing.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonical JSON requires finite numbers');
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const v = value as Record<string, unknown>;
    const keys = Object.keys(v)
      .filter((k) => v[k] !== undefined)
      .sort();
    const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalize(v[k]));
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonical JSON does not support type ${typeof value}`);
}

/** The subset of a proof event that the hash and signature cover. */
export interface HashableEventFields {
  readonly previousHash: string | null;
  readonly eventType: string;
  /** Omitted or null becomes the empty string, per RFC-0002. */
  readonly agentId?: string | null;
  readonly occurredAt: string;
  readonly payload: unknown;
}

/**
 * Build the canonical JSON string for a proof event's hashable fields.
 *
 * Only `previousHash`, `eventType`, `agentId`, `occurredAt` and `payload` are
 * covered. `eventId`, `recordedAt`, `signedBy`, `signature`, the hashes
 * themselves and the shadow-mode trio are attached AFTER the hash is sealed
 * and are therefore excluded by design.
 */
export function canonicalEventString(event: HashableEventFields): string {
  return canonicalize({
    agentId: event.agentId ?? '',
    eventType: event.eventType,
    occurredAt: event.occurredAt,
    payload: event.payload,
    previousHash: event.previousHash,
  });
}

/**
 * UTF-8 bytes of the canonical event string — the exact input to sha256,
 * sha3-256, and (per RFC-0002 Erratum E-1) the detached signature.
 *
 * Returns a platform-neutral `Uint8Array`; `node:crypto` accepts it directly.
 */
export function canonicalEventBytes(event: HashableEventFields): Uint8Array {
  return new TextEncoder().encode(canonicalEventString(event));
}
