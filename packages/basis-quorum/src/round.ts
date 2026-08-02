// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Quorum round orchestration — RFC-0005 §"The execution sequence".
 *
 * Runs one authorization round: declare the validator set, collect votes
 * blindly, chain every vote under its own validator's key, aggregate an
 * attestation over the outcome, and emit `quorum_resolved`.
 *
 * BLIND VOTING is structural here: `evaluate()` receives only the proposal,
 * and the orchestrator never passes one validator's result to another. In a
 * distributed deployment where the coordinator cannot be trusted to enforce
 * this, use commit-reveal via `ValidatorVotePayload.commitment`.
 *
 * The coordinator is UNTRUSTED by design. What keeps it honest is not this
 * code but the record it is forced to produce: the full validator set is
 * declared up front, every declared member must be accounted for at
 * resolution, and each vote is signed by the validator rather than by the
 * coordinator. A coordinator that drops a dissent produces a chain that
 * `verifyQuorumRound()` rejects.
 */

import type { RiskLevel, TrustTier } from '@vorionsys/basis-spec';
import { ChainBuilder, attachSignature } from './events.js';
import { aggregateAttestation, type QuorumGroup, type Rng } from './group.js';
import {
  FROST_ED25519_SUITE,
  type QuorumOutcome,
  type QuorumProofEvent,
  type QuorumRequestedPayload,
  type QuorumResolvedPayload,
  type QuorumTally,
  type ValidatorVotePayload,
  type VoteDecision,
  type VoteEvidence,
} from './types.js';

/** The action a quorum is being asked to authorize. */
export interface Proposal {
  readonly quorumId: string;
  readonly intentId: string;
  readonly proposerAgentId: string;
  readonly action: string;
  readonly actionType: string;
  readonly resourceScope: ReadonlyArray<string>;
  readonly riskLevel?: RiskLevel;
  readonly proposerTier?: TrustTier;
}

/** What a validator returns from evaluating a proposal. */
export interface VoteResult {
  readonly vote: VoteDecision;
  readonly rationale?: string;
  readonly evidence?: ReadonlyArray<VoteEvidence>;
}

/**
 * A quorum validator.
 *
 * Implementations wrap whatever does the judging — a policy engine, a model,
 * a human queue. Two rules matter:
 *
 *   - `evaluate` MUST NOT be given other validators' votes.
 *   - `sign` MUST use the validator's OWN key, not the group key. That is what
 *     makes attribution possible, since the aggregate cannot provide it.
 *
 * Correlated validators are ONE validator for threshold purposes. Two
 * instances of the same policy engine must not both count toward `m`, or the
 * threshold is theatre.
 */
export interface Validator {
  readonly validatorId: string;
  /** Ed25519 public key (hex, base64, or PEM SPKI) used to verify its votes. */
  readonly publicKey: string;
  /** Claimed basis for independence, recorded for auditors. A claim, not proof. */
  readonly attributes?: Readonly<Record<string, string>>;
  evaluate(proposal: Proposal): Promise<VoteResult>;
  /** Detached Ed25519 signature over canonical bytes, base64. */
  sign(bytes: Uint8Array): Promise<string>;
}

export interface RunRoundOptions {
  readonly group: QuorumGroup;
  readonly validators: ReadonlyArray<Validator>;
  readonly proposal: Proposal;
  readonly policyId: string;
  readonly correlationId: string;
  /** ISO 8601. Past this the round resolves as `timeout`. */
  readonly deadline: string;
  /**
   * Monotonic ISO-8601 clock. Injected rather than read from `Date` so rounds
   * are reproducible and golden vectors are byte-stable.
   */
  readonly now: () => string;
  /** Event id generator. Injected for the same reason. */
  readonly nextEventId: () => string;
  /** Append to an existing chain; omit to start a fresh one. */
  readonly chain?: ChainBuilder;
  /** Per-validator wall-clock budget. A validator that exceeds it is a non-responder. */
  readonly timeoutMs?: number;
  /** Which members attest the resolution. Defaults to the responders. */
  readonly attesterIds?: ReadonlyArray<string>;
  /**
   * ⚠️ Fixtures only. Deterministic randomness for byte-stable golden vectors.
   * Leave undefined in production — FROST nonce reuse leaks key material.
   */
  readonly rng?: Rng;
}

export interface RoundResult {
  readonly outcome: QuorumOutcome;
  readonly tally: QuorumTally;
  readonly events: ReadonlyArray<QuorumProofEvent>;
  /** Validators that did not return a usable vote. */
  readonly noResponders: ReadonlyArray<string>;
  /** True when an aggregate attestation could be produced. */
  readonly attested: boolean;
}

interface Collected {
  readonly validator: Validator;
  readonly result: VoteResult | null;
}

function withTimeout<T>(p: Promise<T>, ms: number | undefined): Promise<T | null> {
  if (ms === undefined) return p.catch(() => null);
  return new Promise<T | null>((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      () => {
        clearTimeout(timer);
        resolve(null);
      },
    );
  });
}

/**
 * Run one quorum authorization round.
 *
 * Events are chained in DECLARED VALIDATOR ORDER, not completion order, so a
 * round is reproducible regardless of how the async races resolve.
 */
export async function runQuorumRound(opts: RunRoundOptions): Promise<RoundResult> {
  const { group, validators, proposal, now, nextEventId } = opts;
  const chain = opts.chain ?? new ChainBuilder();

  if (validators.length !== group.threshold.n) {
    throw new Error(
      `validator count (${validators.length}) does not match the group's n (${group.threshold.n})`,
    );
  }

  // --- 1. Declare the round, including the FULL validator set. -------------
  const requestedAt = now();
  const requestedPayload: QuorumRequestedPayload = {
    type: 'quorum_requested',
    quorumId: proposal.quorumId,
    intentId: proposal.intentId,
    policyId: opts.policyId,
    threshold: group.threshold,
    validatorSet: validators.map((v) => ({
      validatorId: v.validatorId,
      publicKey: v.publicKey,
      ...(v.attributes ? { attributes: v.attributes } : {}),
    })),
    escalationReason: {
      ...(proposal.riskLevel ? { riskLevel: proposal.riskLevel } : {}),
      ...(proposal.proposerTier ? { proposerTier: proposal.proposerTier } : {}),
      actionType: proposal.actionType,
    },
    deadline: opts.deadline,
  };
  chain.add({
    eventId: nextEventId(),
    eventType: 'quorum_requested',
    correlationId: opts.correlationId,
    agentId: proposal.proposerAgentId,
    payload: requestedPayload,
    occurredAt: requestedAt,
    recordedAt: requestedAt,
    shadowMode: 'production',
  });

  // --- 2. Collect votes concurrently and blindly. --------------------------
  // No validator is given another's result; each sees only the proposal.
  const collected: Collected[] = await Promise.all(
    validators.map(async (validator) => ({
      validator,
      result: await withTimeout(validator.evaluate(proposal), opts.timeoutMs),
    })),
  );

  // --- 3. Chain one signed vote per responder, in declared order. ----------
  const tally: { approve: number; reject: number; abstain: number } = {
    approve: 0,
    reject: 0,
    abstain: 0,
  };
  const votesRecorded: string[] = [];
  const noResponders: string[] = [];
  const responders: string[] = [];

  for (const { validator, result } of collected) {
    if (result === null) {
      noResponders.push(validator.validatorId);
      continue;
    }

    const votedAt = now();
    const payload: ValidatorVotePayload = {
      type: 'validator_vote',
      quorumId: proposal.quorumId,
      validatorId: validator.validatorId,
      vote: result.vote,
      ...(result.rationale ? { rationale: result.rationale } : {}),
      ...(result.evidence ? { evidence: result.evidence } : {}),
      votedAt,
    };

    const eventId = nextEventId();
    const sealed = chain.seal({
      eventId,
      eventType: 'validator_vote',
      correlationId: opts.correlationId,
      agentId: proposal.proposerAgentId,
      payload,
      occurredAt: votedAt,
      recordedAt: votedAt,
      shadowMode: 'production',
    });

    // Signed by the VALIDATOR'S own key — this is what the aggregate cannot do.
    const signature = await validator.sign(sealed.bytes);
    chain.append(attachSignature(sealed, validator.validatorId, signature));

    tally[result.vote]++;
    votesRecorded.push(eventId);
    responders.push(validator.validatorId);
  }

  // --- 4. Resolve. ---------------------------------------------------------
  const resolvedAt = now();
  const fullTally: QuorumTally = { ...tally, noResponse: noResponders.length };

  // Fewer than m responders means no aggregate can be produced at all.
  const attesterIds = opts.attesterIds ?? responders;
  const canAttest = attesterIds.length >= group.threshold.m;

  let outcome: QuorumOutcome;
  if (!canAttest) {
    outcome = 'insufficient_quorum';
  } else if (resolvedAt > opts.deadline) {
    outcome = 'timeout';
  } else if (tally.approve >= group.threshold.m) {
    outcome = 'approved';
  } else {
    outcome = 'rejected';
  }

  const resolvedPayload: QuorumResolvedPayload = {
    type: 'quorum_resolved',
    quorumId: proposal.quorumId,
    outcome,
    threshold: group.threshold,
    tally: fullTally,
    votesRecorded,
    ...(noResponders.length > 0 ? { noResponders } : {}),
    signatureScheme: FROST_ED25519_SUITE,
    groupPublicKey: group.groupPublicKey,
    resolvedAt,
  };

  const sealedResolution = chain.seal({
    eventId: nextEventId(),
    eventType: 'quorum_resolved',
    correlationId: opts.correlationId,
    agentId: proposal.proposerAgentId,
    payload: resolvedPayload,
    occurredAt: resolvedAt,
    recordedAt: resolvedAt,
    shadowMode: 'production',
  });

  if (canAttest) {
    // The aggregate attests the ACCURACY OF THE RECORD, not approval of the
    // action — rejecting validators sign it too (RFC-0005).
    const aggregate = aggregateAttestation(
      group,
      attesterIds,
      sealedResolution.bytes,
      opts.rng,
    );
    chain.append(
      attachSignature(
        sealedResolution,
        group.groupId,
        Buffer.from(aggregate).toString('base64'),
      ),
    );
  } else {
    // No quorum attestation obtainable. The event is still chained — the
    // record of a failed round matters — but it MUST NOT be presented as
    // quorum-attested.
    chain.append(sealedResolution.event);
  }

  return {
    outcome,
    tally: fullTally,
    events: chain.events,
    noResponders,
    attested: canAttest,
  };
}
