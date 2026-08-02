// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Quorum round verification — RFC-0005 §"Verification procedure" steps 5–8,
 * plus the attribution check the chain verifier structurally cannot perform.
 *
 * TWO LAYERS, NO OVERLAP. Verification of a quorum chain is done in two
 * passes, and both are required:
 *
 *   1. `verifyChain()` from `@vorionsys/basis-spec-conformance` — hashes,
 *      linkage, and signature validity (RFC-0002 §"Verification procedure"
 *      steps 1–4). Proves the record was not altered.
 *
 *   2. `verifyQuorumRound()` — this module. Proves the record is a COHERENT
 *      QUORUM: the tally reconciles against the chained votes, every declared
 *      validator is accounted for, the outcome follows from the threshold, and
 *      each vote was signed by the validator it claims to come from.
 *
 * Passing (1) alone is not enough. A cryptographically perfect chain can still
 * describe an impossible quorum — an approved outcome with too few approvals,
 * a tally that does not match the votes present, or a declared validator whose
 * vote silently vanished. Those are exactly the manipulations a hostile
 * coordinator would attempt, and they are what this pass catches.
 *
 * THE ATTRIBUTION CHECK. `verifyChain()` verifies each signature against a
 * supplied keyring, but it has no way to know that a given vote was supposed
 * to come from a given validator. If validator A's vote were signed with
 * validator B's key, and both keys were in the ring, the chain verifier would
 * report a valid signature. This module checks `signedBy` against the
 * `validatorId` inside the payload, which is what actually binds a vote to its
 * author.
 *
 * Spec reference: rfcs/0005-quorum-authorization.md
 */

import type {
  QuorumProofEvent,
  QuorumRequestedPayload,
  QuorumResolvedPayload,
  QuorumTally,
  ValidatorVotePayload,
} from './types.js';

export interface QuorumVerificationIssue {
  /** Stable machine-readable code. */
  readonly code: string;
  readonly message: string;
  readonly eventId?: string;
}

export interface QuorumRoundVerification {
  readonly valid: boolean;
  readonly quorumId: string;
  readonly issues: ReadonlyArray<QuorumVerificationIssue>;
  /** Tally recomputed from the chained votes. */
  readonly recomputedTally: QuorumTally | null;
  /** Tally the resolution claims. */
  readonly declaredTally: QuorumTally | null;
  readonly outcome: string | null;
  /** Whether the resolution carries a quorum attestation. */
  readonly attested: boolean;
}

const EMPTY_TALLY: QuorumTally = { approve: 0, reject: 0, abstain: 0, noResponse: 0 };

function tallyEquals(a: QuorumTally, b: QuorumTally): boolean {
  return (
    a.approve === b.approve &&
    a.reject === b.reject &&
    a.abstain === b.abstain &&
    a.noResponse === b.noResponse
  );
}

/**
 * Verify the quorum semantics of a round within a chain.
 *
 * @param chain     Events in chain order. May contain unrelated events;
 *                  only those matching `quorumId` are considered.
 * @param quorumId  The round to verify.
 *
 * @returns `valid: true` only when every check passes. This is a statement
 *   about the COHERENCE OF THE RECORD — that a quorum of the declared shape
 *   really did resolve this way. It is not a claim that the decision was
 *   correct. A verifiably coherent quorum can be unanimously wrong.
 */
export function verifyQuorumRound(
  chain: ReadonlyArray<QuorumProofEvent>,
  quorumId: string,
): QuorumRoundVerification {
  const issues: QuorumVerificationIssue[] = [];
  const fail = (code: string, message: string, eventId?: string): void => {
    issues.push({ code, message, ...(eventId ? { eventId } : {}) });
  };

  const bail = (): QuorumRoundVerification => ({
    valid: false,
    quorumId,
    issues,
    recomputedTally: null,
    declaredTally: null,
    outcome: null,
    attested: false,
  });

  // --- Locate the round's events -------------------------------------------
  const requests: QuorumProofEvent[] = [];
  const votes: QuorumProofEvent[] = [];
  const resolutions: QuorumProofEvent[] = [];

  chain.forEach((ev) => {
    const p = ev.payload as { type?: string; quorumId?: string };
    if (p?.quorumId !== quorumId) return;
    if (ev.eventType === 'quorum_requested') requests.push(ev);
    else if (ev.eventType === 'validator_vote') votes.push(ev);
    else if (ev.eventType === 'quorum_resolved') resolutions.push(ev);
  });

  if (requests.length !== 1) {
    fail(
      'request-count',
      `expected exactly one quorum_requested for "${quorumId}", found ${requests.length}`,
    );
    return bail();
  }
  if (resolutions.length !== 1) {
    fail(
      'resolution-count',
      `expected exactly one quorum_resolved for "${quorumId}", found ${resolutions.length}`,
    );
    return bail();
  }

  const requestEvent = requests[0]!;
  const resolutionEvent = resolutions[0]!;
  const request = requestEvent.payload as QuorumRequestedPayload;
  const resolution = resolutionEvent.payload as QuorumResolvedPayload;

  // --- Ordering: request precedes votes precede resolution ------------------
  const idx = (ev: QuorumProofEvent): number => chain.indexOf(ev);
  const requestIdx = idx(requestEvent);
  const resolutionIdx = idx(resolutionEvent);
  if (resolutionIdx < requestIdx) {
    fail('ordering', 'quorum_resolved is chained before quorum_requested');
  }
  votes.forEach((v) => {
    const i = idx(v);
    if (i < requestIdx) {
      fail('ordering', 'a validator_vote is chained before quorum_requested', v.eventId);
    }
    if (i > resolutionIdx) {
      fail('ordering', 'a validator_vote is chained after quorum_resolved', v.eventId);
    }
  });

  // --- Threshold sanity -----------------------------------------------------
  const { m, n } = request.threshold;
  if (!(m > 1)) {
    fail('threshold-degenerate', `threshold m must be > 1, got ${m} — a quorum of one is not a quorum`);
  }
  if (m > n) {
    fail('threshold-degenerate', `threshold m (${m}) exceeds validator count n (${n})`);
  }
  if (request.validatorSet.length !== n) {
    fail(
      'set-size',
      `validatorSet has ${request.validatorSet.length} members but threshold declares n=${n}`,
    );
  }
  if (
    resolution.threshold.m !== m ||
    resolution.threshold.n !== n
  ) {
    fail(
      'threshold-mismatch',
      `quorum_resolved declares ${resolution.threshold.m}-of-${resolution.threshold.n} but the round was requested as ${m}-of-${n}`,
      resolutionEvent.eventId,
    );
  }

  const declaredIds = new Set(request.validatorSet.map((v) => v.validatorId));
  if (declaredIds.size !== request.validatorSet.length) {
    fail('set-duplicates', 'validatorSet contains duplicate validatorIds');
  }

  // --- Votes: membership, uniqueness, attribution ---------------------------
  const recomputed = { approve: 0, reject: 0, abstain: 0 };
  const seenVoters = new Set<string>();
  const voteEventIds: string[] = [];

  for (const ev of votes) {
    const payload = ev.payload as ValidatorVotePayload;
    voteEventIds.push(ev.eventId);

    if (!declaredIds.has(payload.validatorId)) {
      fail(
        'undeclared-voter',
        `vote from "${payload.validatorId}", who is not in the declared validatorSet`,
        ev.eventId,
      );
    }
    if (seenVoters.has(payload.validatorId)) {
      fail(
        'duplicate-vote',
        `"${payload.validatorId}" voted more than once in this round`,
        ev.eventId,
      );
    }
    seenVoters.add(payload.validatorId);

    // ATTRIBUTION: the signer must be the validator the payload names.
    if (ev.signedBy === undefined) {
      fail(
        'vote-unsigned',
        `vote from "${payload.validatorId}" carries no signedBy — a vote nobody signed is not attributable`,
        ev.eventId,
      );
    } else if (ev.signedBy !== payload.validatorId) {
      fail(
        'vote-misattributed',
        `vote claims validatorId "${payload.validatorId}" but is signed by "${ev.signedBy}"`,
        ev.eventId,
      );
    }

    if (payload.vote === 'approve') recomputed.approve++;
    else if (payload.vote === 'reject') recomputed.reject++;
    else if (payload.vote === 'abstain') recomputed.abstain++;
    else {
      fail('vote-invalid', `unrecognised vote value "${String(payload.vote)}"`, ev.eventId);
    }

    // Temporal: a vote cannot be cast after the round resolved.
    if (payload.votedAt > resolution.resolvedAt) {
      fail(
        'vote-after-resolution',
        `votedAt ${payload.votedAt} is after resolvedAt ${resolution.resolvedAt}`,
        ev.eventId,
      );
    }
  }

  // --- votesRecorded must match the votes actually chained ------------------
  const recordedSet = new Set(resolution.votesRecorded);
  const actualSet = new Set(voteEventIds);
  for (const id of recordedSet) {
    if (!actualSet.has(id)) {
      fail(
        'phantom-vote',
        `votesRecorded references eventId "${id}", which is not a chained validator_vote for this round`,
        resolutionEvent.eventId,
      );
    }
  }
  for (const id of actualSet) {
    if (!recordedSet.has(id)) {
      fail(
        'unrecorded-vote',
        `chained vote "${id}" is missing from votesRecorded`,
        resolutionEvent.eventId,
      );
    }
  }

  // --- SUPPRESSION CHECK: every declared validator is accounted for ---------
  const noResponders = new Set(resolution.noResponders ?? []);
  for (const id of noResponders) {
    if (!declaredIds.has(id)) {
      fail('undeclared-nonresponder', `noResponders lists "${id}", who was never declared`, resolutionEvent.eventId);
    }
    if (seenVoters.has(id)) {
      fail(
        'contradictory-nonresponder',
        `"${id}" is listed as a non-responder but also cast a chained vote`,
        resolutionEvent.eventId,
      );
    }
  }
  for (const id of declaredIds) {
    if (!seenVoters.has(id) && !noResponders.has(id)) {
      fail(
        'unaccounted-validator',
        `declared validator "${id}" neither voted nor is listed as a non-responder — a dropped dissent looks exactly like this`,
        resolutionEvent.eventId,
      );
    }
  }

  // --- Tally reconciliation -------------------------------------------------
  const recomputedTally: QuorumTally = {
    ...recomputed,
    noResponse: noResponders.size,
  };
  const declaredTally = resolution.tally ?? EMPTY_TALLY;

  if (!tallyEquals(recomputedTally, declaredTally)) {
    fail(
      'tally-mismatch',
      `declared tally ${JSON.stringify(declaredTally)} does not match the chained votes ${JSON.stringify(recomputedTally)}`,
      resolutionEvent.eventId,
    );
  }

  const sum =
    declaredTally.approve + declaredTally.reject + declaredTally.abstain + declaredTally.noResponse;
  if (sum !== n) {
    fail(
      'tally-incomplete',
      `tally sums to ${sum} but the validator set has n=${n} members`,
      resolutionEvent.eventId,
    );
  }

  // --- Outcome consistency --------------------------------------------------
  const attested = typeof resolutionEvent.signature === 'string' && resolutionEvent.signature.length > 0;

  if (resolution.outcome === 'approved') {
    if (recomputedTally.approve < m) {
      fail(
        'approved-below-threshold',
        `outcome is "approved" with only ${recomputedTally.approve} approvals against m=${m}`,
        resolutionEvent.eventId,
      );
    }
    if (!attested) {
      fail(
        'approved-unattested',
        'outcome is "approved" but the resolution carries no quorum attestation',
        resolutionEvent.eventId,
      );
    }
  }

  if (resolution.outcome === 'rejected' && recomputedTally.approve >= m) {
    fail(
      'rejected-above-threshold',
      `outcome is "rejected" but ${recomputedTally.approve} approvals met m=${m}`,
      resolutionEvent.eventId,
    );
  }

  if (resolution.outcome === 'insufficient_quorum') {
    const responded = seenVoters.size;
    if (responded >= m) {
      fail(
        'insufficient-contradicted',
        `outcome is "insufficient_quorum" but ${responded} validators responded against m=${m}`,
        resolutionEvent.eventId,
      );
    }
  } else if (!attested) {
    fail(
      'unattested-resolution',
      `outcome "${resolution.outcome}" carries no quorum attestation — only insufficient_quorum may be unattested`,
      resolutionEvent.eventId,
    );
  }

  // The resolution must be signed by the group, never by an individual member.
  if (resolutionEvent.signedBy !== undefined && declaredIds.has(resolutionEvent.signedBy)) {
    fail(
      'resolution-individually-signed',
      `quorum_resolved is signed by member "${resolutionEvent.signedBy}" rather than the quorum group key`,
      resolutionEvent.eventId,
    );
  }

  // --- Deadline -------------------------------------------------------------
  if (resolution.resolvedAt > request.deadline && resolution.outcome !== 'timeout') {
    fail(
      'deadline-exceeded',
      `resolvedAt ${resolution.resolvedAt} is past the declared deadline ${request.deadline}, but outcome is "${resolution.outcome}" rather than "timeout"`,
      resolutionEvent.eventId,
    );
  }

  // --- Group key consistency ------------------------------------------------
  if (!resolution.groupPublicKey || resolution.groupPublicKey.length === 0) {
    fail(
      'missing-group-key',
      'quorum_resolved does not name the group public key its attestation verifies under',
      resolutionEvent.eventId,
    );
  }

  return {
    valid: issues.length === 0,
    quorumId,
    issues,
    recomputedTally,
    declaredTally,
    outcome: resolution.outcome,
    attested,
  };
}
