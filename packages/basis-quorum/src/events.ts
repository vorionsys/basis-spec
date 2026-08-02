// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Event sealing for RFC-0005 quorum events.
 *
 * "Sealing" is the RFC-0002 operation: build the canonical byte string over
 * the hashable fields, derive `eventHash` (sha256) and `eventHash3`
 * (sha3-256) from those exact bytes, and link `previousHash` to the prior
 * event. The bytes are returned alongside the event because they are also
 * what a detached signature covers (RFC-0002 Erratum E-1).
 *
 * The canonicalizer is imported from `@vorionsys/basis-spec` rather than
 * reimplemented. That is deliberate: byte-identity with the verifier is the
 * property every other guarantee rests on, and a second implementation is a
 * second chance to diverge.
 */

import { createHash } from 'node:crypto';
import { canonicalEventBytes } from '@vorionsys/basis-spec';
import type {
  QuorumEventType,
  QuorumPayload,
  QuorumProofEvent,
} from './types.js';
import type { ShadowModeStatus } from '@vorionsys/basis-spec';

/** Everything needed to seal an event except the chain link and hashes. */
export interface EventDraft {
  readonly eventId: string;
  readonly eventType: QuorumEventType;
  readonly correlationId: string;
  readonly agentId?: string;
  readonly payload: QuorumPayload;
  readonly occurredAt: string;
  readonly recordedAt: string;
  readonly shadowMode?: ShadowModeStatus;
}

export interface SealedEvent {
  /** The event, hashed and linked but not yet signed. */
  readonly event: QuorumProofEvent;
  /**
   * Canonical bytes the hashes were computed over. Sign THESE — not the
   * hex `eventHash` string (RFC-0002 Erratum E-1).
   */
  readonly bytes: Uint8Array;
}

/** sha3-256 requires an OpenSSL 3 build; report absence rather than skipping silently. */
function sha3_256HexOrNull(bytes: Uint8Array): string | null {
  try {
    return createHash('sha3-256').update(bytes).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Seal a draft event against a previous hash.
 *
 * @param draft         The event content.
 * @param previousHash  Prior event's `eventHash`, or `null` for a chain head.
 */
export function sealEvent(
  draft: EventDraft,
  previousHash: string | null,
): SealedEvent {
  const bytes = canonicalEventBytes({
    previousHash,
    eventType: draft.eventType,
    agentId: draft.agentId,
    occurredAt: draft.occurredAt,
    payload: draft.payload,
  });

  const eventHash = createHash('sha256').update(bytes).digest('hex');
  const eventHash3 = sha3_256HexOrNull(bytes);

  const event: QuorumProofEvent = {
    eventId: draft.eventId,
    eventType: draft.eventType,
    correlationId: draft.correlationId,
    ...(draft.agentId !== undefined ? { agentId: draft.agentId } : {}),
    payload: draft.payload,
    previousHash,
    eventHash,
    ...(eventHash3 !== null ? { eventHash3 } : {}),
    occurredAt: draft.occurredAt,
    recordedAt: draft.recordedAt,
    ...(draft.shadowMode !== undefined ? { shadowMode: draft.shadowMode } : {}),
  };

  return { event, bytes };
}

/**
 * Attach a detached signature to a sealed event.
 *
 * Returns a new event; the sealed input is not mutated. Attaching a signature
 * never changes `eventHash`, because signature fields are excluded from the
 * hash input by design.
 */
export function attachSignature(
  sealed: SealedEvent,
  signedBy: string,
  signature: string,
): QuorumProofEvent {
  return { ...sealed.event, signedBy, signature };
}

/**
 * Accumulates a linear hash chain, tracking `previousHash` across events.
 *
 * A chain built here starts at `null` and links strictly linearly, which is
 * what RFC-0002 §"Chain linkage" requires within whatever boundary the runtime
 * chooses.
 */
export class ChainBuilder {
  #previousHash: string | null;
  readonly #events: QuorumProofEvent[] = [];

  /**
   * @param previousHash Tail hash of an existing chain to append to, or `null`
   *   to start a new one. Passing an existing tail is how a quorum round is
   *   appended to a runtime's ongoing chain rather than forming its own.
   */
  constructor(previousHash: string | null = null) {
    this.#previousHash = previousHash;
  }

  /** Seal a draft against the current tail. Does NOT append — call `append`. */
  seal(draft: EventDraft): SealedEvent {
    return sealEvent(draft, this.#previousHash);
  }

  /** Append a (possibly signed) event and advance the tail. */
  append(event: QuorumProofEvent): QuorumProofEvent {
    this.#events.push(event);
    this.#previousHash = event.eventHash;
    return event;
  }

  /** Seal and append in one step, for events that carry no signature. */
  add(draft: EventDraft): QuorumProofEvent {
    return this.append(this.seal(draft).event);
  }

  get previousHash(): string | null {
    return this.#previousHash;
  }

  /** The chain accumulated so far, in order. */
  get events(): ReadonlyArray<QuorumProofEvent> {
    return this.#events;
  }
}
