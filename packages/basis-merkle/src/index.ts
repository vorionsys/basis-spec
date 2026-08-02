// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * `@vorionsys/basis-merkle` — public reference implementation of BASIS
 * RFC-0007, chain compaction and selective disclosure.
 *
 * A long-running runtime accumulates millions of proof events. This collapses a
 * range into one signed Merkle root, then lets an operator prove a specific
 * decision sits under that root WITHOUT disclosing the rest of the range.
 *
 * Built from SHA-256 and the Ed25519 signatures RFC-0002 already carries. No
 * trusted setup, no pairing-friendly curves, no new cryptographic assumptions.
 *
 * COMPACTION IS APPEND-ONLY, and cannot be otherwise. `previousHash` is inside
 * the RFC-0002 canonical hash input, so re-pointing an event changes its own
 * `eventHash` and invalidates every event after it. The chain cannot be edited
 * — that is the tamper-evidence guarantee working, not a limitation to route
 * around.
 *
 * THE COST, STATED PLAINLY: compaction trades full-chain verification for
 * root-attested membership. A verifier holding the events verifies everything
 * as before. A verifier holding only the compacted form verifies the root
 * signature and membership, and CANNOT verify the linkage of events it does not
 * have. That is what "we no longer store these" means, said out loud.
 *
 * Hence every result carries a `level`:
 *
 *   full     — holder has the events; the RFC-0002 guarantee, undiminished
 *   attested — root validly signed, disclosed leaves sit under it, and nothing
 *              is established about undisclosed events beyond their count
 *   none     — insufficient data. Not a pass.
 *
 * Reporting `valid` without the level is misleading and non-conforming.
 *
 * THIS IS NOT ZERO-KNOWLEDGE and must not be described as such. A recipient
 * learns the path hashes (stable identifiers for sibling subtrees, so repeated
 * disclosures are correlatable), the range size, and the leaf position. It is
 * selective disclosure: a smaller, deliberate reveal — not the absence of one.
 *
 * Spec: rfcs/0007-compaction-selective-disclosure.md
 */

export {
  leafHash,
  nodeHash,
  buildLevels,
  merkleRoot,
  rootFromEvents,
  MerkleError,
  LEAF_PREFIX,
  NODE_PREFIX,
} from './tree.js';

export { auditPath, foldPath, verifyPath, type PathStep } from './proof.js';

export {
  buildCompaction,
  buildDisclosure,
  verifyDisclosure,
  verifyAgainstRange,
  type CompactOptions,
  type BuildDisclosureOptions,
} from './disclosure.js';

export {
  COMPACTION_EVENT_TYPES,
  type CompactionEventType,
  type VerificationLevel,
  type ChainCompactedPayload,
  type DisclosureIssuedPayload,
  type ChainEvent,
  type DisclosedLeaf,
  type DisclosurePackage,
  type DisclosureIssue,
  type DisclosureVerification,
} from './types.js';
