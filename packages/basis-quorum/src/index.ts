// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * `@vorionsys/basis-quorum` — public reference implementation of BASIS
 * RFC-0005, m-of-n threshold authorization for high-consequence agent actions.
 *
 * WHAT THIS IS
 *
 * A quorum round produces two kinds of record, and both are required:
 *
 *   - `quorum_resolved`, carrying a FROST(Ed25519) AGGREGATE signature. Proves
 *     quorum AUTHORITY. Because a FROST aggregate is a standard Ed25519
 *     signature, this verifies with the stock RFC-0002 verifier unchanged.
 *
 *   - one `validator_vote` per responder, each signed with that validator's
 *     OWN key. Provides ATTRIBUTION — which the aggregate structurally cannot,
 *     because it is subset-anonymous: every valid m-subset produces a
 *     different signature under the same group key.
 *
 * Emitting only the aggregate is non-conforming. It destroys exactly the
 * information needed to detect a suppressed dissent or to move a validator's
 * trust tier honestly.
 *
 * WHAT THIS IS NOT
 *
 * This is m-of-n threshold authorization with an ensemble judgment layer. It
 * is NOT Byzantine fault-tolerant consensus, and must not be described as
 * such. pBFT's safety argument assumes honest replicas are deterministic —
 * same input, same output — which is what makes "matching signatures"
 * meaningful. Validators that exercise judgment are stochastic and can
 * legitimately disagree. No liveness guarantee, no partition tolerance, and no
 * state-machine replication is claimed or provided.
 *
 * Threshold cryptography proves that m parties signed. It says nothing about
 * whether their judgment was right. A quorum can be unanimously, verifiably
 * wrong.
 *
 * VERIFYING A QUORUM CHAIN — both passes are required:
 *
 * ```ts
 * // 1. Integrity: hashes, linkage, signatures (RFC-0002)
 * import { verifyChain } from '@vorionsys/basis-spec-conformance';
 * const integrity = verifyChain(chain, { publicKeys: keyring, requireSignatures: true });
 *
 * // 2. Coherence: tally, accounting, attribution, outcome (RFC-0005)
 * import { verifyQuorumRound } from '@vorionsys/basis-quorum';
 * const round = verifyQuorumRound(chain, quorumId);
 * ```
 *
 * Passing (1) alone is not enough — a cryptographically perfect chain can
 * still describe an impossible quorum.
 *
 * NOTE ON EVENT TYPES: RFC-0005 is Draft, so its three event types are not yet
 * in the canonical `PROOF_EVENT_TYPES` union. `basis-conformance verify` is
 * unaffected (it does not inspect event types), but `basis-conformance
 * validate` will correctly report them as non-canonical until the RFC is
 * accepted.
 *
 * Spec: rfcs/0005-quorum-authorization.md
 */

export {
  QUORUM_EVENT_TYPES,
  FROST_ED25519_SUITE,
  type QuorumEventType,
  type VoteDecision,
  type QuorumOutcome,
  type QuorumThreshold,
  type ValidatorDescriptor,
  type EscalationReason,
  type QuorumRequestedPayload,
  type VoteEvidence,
  type ValidatorVotePayload,
  type QuorumTally,
  type QuorumResolvedPayload,
  type QuorumPayload,
  type QuorumProofEvent,
} from './types.js';

export {
  sealEvent,
  attachSignature,
  ChainBuilder,
  type EventDraft,
  type SealedEvent,
} from './events.js';

export {
  createGroupViaDkg,
  aggregateAttestation,
  type QuorumGroup,
  type GroupMember,
  type FrostKey,
  type CreateGroupOptions,
  type Rng,
} from './group.js';

export {
  runQuorumRound,
  type Proposal,
  type VoteResult,
  type Validator,
  type RunRoundOptions,
  type RoundResult,
} from './round.js';

export {
  verifyQuorumRound,
  type QuorumRoundVerification,
  type QuorumVerificationIssue,
} from './verify-round.js';

export {
  createLocalValidator,
  buildKeyring,
  type LocalValidatorOptions,
} from './validators.js';
