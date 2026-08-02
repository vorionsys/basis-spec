// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0007 types — chain compaction and selective disclosure.
 *
 * Spec reference: rfcs/0007-compaction-selective-disclosure.md
 */

import type { PathStep } from './proof.js';

export const COMPACTION_EVENT_TYPES = ['chain_compacted', 'disclosure_issued'] as const;
export type CompactionEventType = (typeof COMPACTION_EVENT_TYPES)[number];

/**
 * How much a verifier was actually able to establish.
 *
 * This MUST be reported. Two verifiers holding different data can both be
 * correct and reach different conclusions, so a bare `valid: true` without the
 * level is misleading and is non-conforming.
 */
export type VerificationLevel =
  /** Holder has every event: hashes, linkage and signatures, undiminished. */
  | 'full'
  /**
   * Holder has the compaction event plus disclosed leaves and paths. The root
   * is validly signed and the disclosed events sit under it. Says NOTHING
   * about undisclosed events beyond their count.
   */
  | 'attested'
  /** Insufficient data. Not a pass. */
  | 'none';

export interface ChainCompactedPayload {
  readonly type: 'chain_compacted';
  readonly compactionId: string;
  readonly merkleRoot: string;
  readonly firstEventId: string;
  readonly lastEventId: string;
  /** Required — a root without a count is unauditable. */
  readonly leafCount: number;
  /** Anchors letting a holder of the underlying data re-attach the segment. */
  readonly rangePreviousHash: string | null;
  readonly rangeEventHash: string;
  readonly archiveUri?: string;
  readonly salted: boolean;
  readonly compactedAt: string;
}

export interface DisclosureIssuedPayload {
  readonly type: 'disclosure_issued';
  readonly disclosureId: string;
  readonly compactionId: string;
  readonly disclosedEventIds: ReadonlyArray<string>;
  readonly recipient?: string;
  readonly purpose?: string;
  readonly issuedAt: string;
}

/** Minimal RFC-0002 event shape this package needs. */
export interface ChainEvent {
  readonly eventId: string;
  readonly eventType: string;
  readonly agentId?: string;
  readonly payload: unknown;
  readonly previousHash: string | null;
  readonly eventHash: string;
  readonly occurredAt: string;
  readonly recordedAt?: string;
  readonly signedBy?: string;
  readonly signature?: string;
  readonly [k: string]: unknown;
}

export interface DisclosedLeaf {
  readonly event: ChainEvent;
  readonly leafIndex: number;
  /** Required when the compaction was salted, or the leaf can never be proved. */
  readonly salt?: string;
  readonly path: ReadonlyArray<PathStep>;
}

/**
 * The artefact handed to an auditor. Self-contained: verifiable with this
 * plus nothing else.
 */
export interface DisclosurePackage {
  readonly disclosureVersion: 1;
  /** The compaction event verbatim, including its signature. */
  readonly compaction: ChainEvent;
  readonly disclosed: ReadonlyArray<DisclosedLeaf>;
  /** signedBy identity → Ed25519 public key. */
  readonly keys: Readonly<Record<string, string>>;
}

export interface DisclosureIssue {
  readonly code: string;
  readonly message: string;
  readonly eventId?: string;
}

export interface DisclosureVerification {
  readonly valid: boolean;
  readonly level: VerificationLevel;
  readonly issues: ReadonlyArray<DisclosureIssue>;
  readonly merkleRoot: string | null;
  /** How many leaves were shown. */
  readonly disclosedCount: number;
  /**
   * How many leaves the range held. Reported so a recipient can see how much
   * they were NOT shown — 3-of-4 and 3-of-40,000 are very different artefacts.
   */
  readonly leafCount: number | null;
}
