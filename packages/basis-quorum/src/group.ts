// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * FROST(Ed25519) quorum group lifecycle — RFC-0005 §"Signature semantics".
 *
 * Wraps `@noble/curves`' audited RFC 9591 implementation. Two properties make
 * this the right scheme for BASIS, and both are load-bearing:
 *
 *   1. A FROST aggregate is a STANDARD 64-byte Ed25519 signature over a
 *      32-byte group public key, so a quorum-authorized event verifies with
 *      the stock RFC-0002 verifier — no new signature type, no new code path.
 *
 *   2. Distributed key generation means no single party — including the
 *      coordinator — ever holds the group private key. That is the actual
 *      security claim; trusted-dealer generation does not provide it.
 *
 * A note on what the aggregate does NOT tell you: it is subset-anonymous.
 * Every valid m-subset produces a different signature verifying under the same
 * group key, so the aggregate proves a valid quorum signed and never which
 * members. Attribution comes from separately-chained `validator_vote` events.
 * See RFC-0005 §"The two-record structure".
 */

import { ed25519_FROST as FROST } from '@noble/curves/ed25519.js';
import type { QuorumThreshold } from './types.js';

/** A participant's FROST key material, as produced by DKG. */
export type FrostKey = ReturnType<typeof FROST.DKG.round3>;

export interface GroupMember {
  readonly validatorId: string;
  /** FROST participant identifier (canonical serialized form). */
  readonly frostIdentifier: string;
  /**
   * This member's key material, including its secret share.
   *
   * In the reference implementation shares are held in-process so a round can
   * be demonstrated end to end. In production each share belongs to a
   * separately isolated validator and never transits the coordinator.
   */
  readonly key: FrostKey;
}

export interface QuorumGroup {
  /** Identity written to `signedBy` on `quorum_resolved`. */
  readonly groupId: string;
  /** 32-byte group public key, lowercase hex. The aggregate verifies under this. */
  readonly groupPublicKey: string;
  readonly threshold: QuorumThreshold;
  readonly members: ReadonlyArray<GroupMember>;
}

const hex = (u8: Uint8Array): string => Buffer.from(u8).toString('hex');

/**
 * Randomness source, matching `@noble/curves`' RNG shape.
 *
 * ⚠️ FIXTURES ONLY. Overriding this makes key generation and signing
 * deterministic, which is required to produce byte-stable golden vectors and
 * catastrophic anywhere else: FROST nonce reuse leaks key material, and a
 * predictable DKG secret is not a secret. Every production path MUST leave
 * this undefined so the library's cryptographically secure default is used.
 */
export type Rng = (bytesLength?: number) => Uint8Array;

export interface CreateGroupOptions {
  /** Identity written to `signedBy`, e.g. `did:vorion:quorum:prod-destructive#frost-ed25519`. */
  readonly groupId: string;
  /** One entry per validator. Order fixes FROST identifier assignment. */
  readonly validatorIds: ReadonlyArray<string>;
  /** Signatures required to authorize. */
  readonly m: number;
  /** ⚠️ Fixtures only — see {@link Rng}. */
  readonly rng?: Rng;
}

/**
 * Create a quorum group by running a real distributed key generation.
 *
 * No dealer: every participant contributes, and the group private key exists
 * only as the (never-reconstructed) combination of shares.
 *
 * @throws if the threshold is degenerate. RFC-0005 requires `1 < m <= n`; a
 *   "quorum" of one is not a quorum and is rejected here rather than at
 *   runtime.
 */
export function createGroupViaDkg(opts: CreateGroupOptions): QuorumGroup {
  const n = opts.validatorIds.length;
  const m = opts.m;

  if (n < 2) {
    throw new RangeError(
      `a quorum needs at least 2 validators, got ${n} — an empty or single-member set is not a quorum`,
    );
  }
  if (m < 2) {
    throw new RangeError(
      `threshold m must be > 1, got ${m} — a quorum of one is not a quorum (RFC-0005)`,
    );
  }
  if (m > n) {
    throw new RangeError(`threshold m (${m}) cannot exceed validator count n (${n})`);
  }
  if (new Set(opts.validatorIds).size !== n) {
    throw new Error('validatorIds must be unique — duplicates would double-count toward the threshold');
  }

  const signers = { min: m, max: n };
  const identifiers = opts.validatorIds.map((_, i) => FROST.Identifier.fromNumber(i + 1));

  // Round 1: each participant broadcasts a commitment + proof of knowledge.
  const round1 = identifiers.map((id) =>
    FROST.DKG.round1(id, signers, undefined, opts.rng),
  );

  // Round 2: each participant produces per-peer secret packages.
  const round2 = round1.map((own, i) =>
    FROST.DKG.round2(
      own.secret,
      round1.filter((_, j) => j !== i).map((o) => o.public),
    ),
  );

  // Round 3: each participant finalizes using peers' round-1 and round-2 data.
  const keys = identifiers.map((id, i) =>
    FROST.DKG.round3(
      round1[i]!.secret,
      round1.filter((_, j) => j !== i).map((o) => o.public),
      round2
        .map((msgs, j) => (j === i ? null : msgs[id]))
        .filter((x): x is NonNullable<typeof x> => x != null),
    ),
  );

  // Every participant must have derived the same group key. If they have not,
  // the DKG did not converge and the group is unusable — fail loudly.
  const groupPublicKey = hex(keys[0]!.public.commitments[0]!);
  for (let i = 1; i < keys.length; i++) {
    if (hex(keys[i]!.public.commitments[0]!) !== groupPublicKey) {
      throw new Error(
        `DKG did not converge: participant ${i} derived a different group public key`,
      );
    }
  }

  return {
    groupId: opts.groupId,
    groupPublicKey,
    threshold: { m, n },
    members: opts.validatorIds.map((validatorId, i) => ({
      validatorId,
      frostIdentifier: keys[i]!.secret.identifier,
      key: keys[i]!,
    })),
  };
}

/**
 * Produce an aggregate threshold signature over `message`.
 *
 * @param group        The quorum group.
 * @param attesterIds  Validator ids attesting. Must number at least `m`.
 * @param message      Canonical bytes to sign (RFC-0002 Erratum E-1).
 *
 * Attesting is NOT the same as approving. Per RFC-0005, the aggregate on
 * `quorum_resolved` attests that the recorded outcome is accurate — so
 * validators that voted `reject` sign it too. A rejection is precisely the
 * record a hostile coordinator most wants to forge, and leaving it unsigned
 * would make the denial of a dangerous action the least protected event in
 * the chain.
 *
 * @throws if fewer than `m` attesters are supplied, or if any signature share
 *   fails its individual check. A bad share is never silently dropped.
 */
export function aggregateAttestation(
  group: QuorumGroup,
  attesterIds: ReadonlyArray<string>,
  message: Uint8Array,
  /** ⚠️ Fixtures only — see {@link Rng}. Nonce reuse leaks key material. */
  rng?: Rng,
): Uint8Array {
  if (attesterIds.length < group.threshold.m) {
    throw new RangeError(
      `need at least m=${group.threshold.m} attesters to aggregate, got ${attesterIds.length}`,
    );
  }

  const attesters = attesterIds.map((id) => {
    const member = group.members.find((mem) => mem.validatorId === id);
    if (!member) throw new Error(`"${id}" is not a member of group ${group.groupId}`);
    return member;
  });

  // Round 1: one-time nonce commitments. FROST nonces MUST NOT be reused
  // across signing sessions — reuse leaks key material. `commit()` is called
  // fresh here for every round, and noble zeroizes the nonce package on use.
  const noncePairs = attesters.map((mem) => FROST.commit(mem.key.secret, rng));
  const commitmentList = noncePairs.map((nc) => nc.commitments);

  // Round 2: signature shares, each verified before it is accepted.
  const shares: Record<string, Uint8Array> = {};
  attesters.forEach((mem, i) => {
    const share = FROST.signShare(
      mem.key.secret,
      mem.key.public,
      noncePairs[i]!.nonces,
      commitmentList,
      message,
    );
    const ok = FROST.verifyShare(
      mem.key.public,
      commitmentList,
      message,
      mem.key.secret.identifier,
      share,
    );
    if (!ok) {
      throw new Error(`signature share from "${mem.validatorId}" failed verification`);
    }
    shares[mem.key.secret.identifier] = share;
  });

  return FROST.aggregate(attesters[0]!.key.public, commitmentList, message, shares);
}
