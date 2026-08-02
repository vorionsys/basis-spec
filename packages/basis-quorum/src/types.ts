// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0005 types — quorum authorization events.
 *
 * These extend the RFC-0002 proof event set with three new event types. They
 * are declared here rather than in `@vorionsys/basis-spec` because RFC-0005 is
 * still Draft; they fold into the canonical `PROOF_EVENT_TYPES` union when the
 * RFC is accepted.
 *
 * Practical consequence today: `basis-conformance verify` (hashes, linkage,
 * signatures) works on quorum chains unchanged, because it does not inspect
 * event types. `basis-conformance validate` (structural, truth-only) WILL
 * report these as non-canonical event types — correctly, since a draft RFC has
 * not amended the canonical set yet.
 *
 * Spec reference: rfcs/0005-quorum-authorization.md
 */

import type { RiskLevel, TrustTier, ShadowModeStatus } from '@vorionsys/basis-spec';

/** The three event types RFC-0005 adds. */
export const QUORUM_EVENT_TYPES = [
  'quorum_requested',
  'validator_vote',
  'quorum_resolved',
] as const;

export type QuorumEventType = (typeof QUORUM_EVENT_TYPES)[number];

/** How a validator voted on the proposed action. */
export type VoteDecision = 'approve' | 'reject' | 'abstain';

/** How the round closed. */
export type QuorumOutcome =
  | 'approved'
  | 'rejected'
  | 'timeout'
  | 'insufficient_quorum';

export interface QuorumThreshold {
  /** Signatures required to authorize. MUST satisfy 1 < m <= n. */
  readonly m: number;
  /** Size of the declared validator set. */
  readonly n: number;
}

/**
 * A validator in the declared set.
 *
 * `attributes` records the CLAIMED basis for this validator's independence
 * (e.g. `{ independence: 'distinct-model-family' }`) so an auditor can assess
 * it. Recording a claim is not the same as establishing it — RFC-0005 requires
 * independence to be measured, not asserted.
 */
export interface ValidatorDescriptor {
  readonly validatorId: string;
  /** Ed25519 key this validator signs its own votes with. */
  readonly publicKey?: string;
  readonly attributes?: Readonly<Record<string, string>>;
}

/** Why policy escalated this action to a quorum. */
export interface EscalationReason {
  readonly riskLevel?: RiskLevel;
  readonly proposerTier?: TrustTier;
  readonly actionType?: string;
}

export interface QuorumRequestedPayload {
  readonly type: 'quorum_requested';
  readonly quorumId: string;
  /** Links to the `intent_received` event being authorized. */
  readonly intentId: string;
  readonly policyId: string;
  readonly threshold: QuorumThreshold;
  /**
   * Every validator ASKED. Declaring the full set up front is what makes a
   * suppressed vote detectable — `quorum_resolved` must account for all of them.
   */
  readonly validatorSet: ReadonlyArray<ValidatorDescriptor>;
  readonly escalationReason: EscalationReason;
  /** ISO 8601. After this the round MUST resolve as `timeout`. */
  readonly deadline: string;
}

/**
 * A supporting signal behind a vote.
 *
 * RECORDED CLAIM, NOT VERIFIABLE FACT. A verifier can confirm that this entry
 * was chained under signature; it cannot confirm the signal was correct.
 * Reproducing a classifier score would require the model weights, the exact
 * runtime, and the exact input state.
 *
 * `version` is required. Evidence whose producing component cannot be
 * identified and versioned is not evidence, it is an assertion.
 */
export interface VoteEvidence {
  readonly kind: string;
  readonly source: string;
  readonly version: string;
  readonly score?: number;
  readonly threshold?: number;
  readonly fired?: boolean;
}

export interface ValidatorVotePayload {
  readonly type: 'validator_vote';
  readonly quorumId: string;
  readonly validatorId: string;
  readonly vote: VoteDecision;
  /** Human-readable. Never machine-authoritative. */
  readonly rationale?: string;
  readonly evidence?: ReadonlyArray<VoteEvidence>;
  /** sha256 hex published before any vote was revealed, when using commit-reveal. */
  readonly commitment?: string;
  readonly votedAt: string;
}

export interface QuorumTally {
  readonly approve: number;
  readonly reject: number;
  readonly abstain: number;
  readonly noResponse: number;
}

export interface QuorumResolvedPayload {
  readonly type: 'quorum_resolved';
  readonly quorumId: string;
  readonly outcome: QuorumOutcome;
  readonly threshold: QuorumThreshold;
  readonly tally: QuorumTally;
  /** eventIds of EVERY chained `validator_vote` for this quorumId. */
  readonly votesRecorded: ReadonlyArray<string>;
  /** Declared validators that never responded. */
  readonly noResponders?: ReadonlyArray<string>;
  readonly signatureScheme: string;
  readonly groupPublicKey: string;
  readonly resolvedAt: string;
}

export type QuorumPayload =
  | QuorumRequestedPayload
  | ValidatorVotePayload
  | QuorumResolvedPayload;

/**
 * An RFC-0002-shaped proof event carrying a quorum payload.
 *
 * Field semantics are exactly RFC-0002's — this is deliberately NOT a new
 * envelope. The whole design depends on quorum events being ordinary proof
 * events so the stock verifier handles them unchanged.
 */
export interface QuorumProofEvent {
  readonly eventId: string;
  readonly eventType: QuorumEventType;
  readonly correlationId: string;
  readonly agentId?: string;
  readonly payload: QuorumPayload;
  readonly previousHash: string | null;
  readonly eventHash: string;
  readonly eventHash3?: string;
  readonly occurredAt: string;
  readonly recordedAt: string;
  /**
   * For `validator_vote`, the validator's OWN identity.
   * For `quorum_resolved`, the quorum GROUP key identity.
   */
  readonly signedBy?: string;
  readonly signature?: string;
  readonly shadowMode?: ShadowModeStatus;
}

/** The FROST ciphersuite RFC-0005 requires by default. */
export const FROST_ED25519_SUITE = 'FROST-ED25519-SHA512-v1';
