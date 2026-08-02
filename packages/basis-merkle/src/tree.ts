// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Canonical Merkle construction — RFC-0007 §"Canonical Merkle construction".
 *
 * Two details here are SECURITY, not style. Getting either wrong produces
 * distinct leaf sequences that share a root, which destroys the only property
 * the tree provides.
 *
 * 1. DOMAIN SEPARATORS. Leaves are hashed with a `0x00` prefix, internal nodes
 *    with `0x01`. Without them, leaf hashes and node hashes are drawn from the
 *    same space, and an attacker can present an internal node as though it were
 *    a leaf — the classic Merkle second-preimage attack. RFC 6962 uses this
 *    construction for exactly this reason.
 *
 * 2. ODD NODES ARE PROMOTED, NEVER DUPLICATED. When a level has an odd count,
 *    the last node moves up unchanged. Duplicating it and pairing it with
 *    itself makes `[a,b,c]` and `[a,b,c,c]` produce an IDENTICAL root — the
 *    defect behind Bitcoin's CVE-2012-2459 — which would let a compactor swap
 *    a range's contents while keeping its attested root. There is a test that
 *    pins this.
 *
 * Leaves are in CHAIN ORDER, not sorted. Order carries meaning; sorting would
 * let a compactor present a different sequence under the same root.
 */

import { createHash } from 'node:crypto';
import { canonicalEventBytes, type HashableEventFields } from '@vorionsys/basis-spec';

/** Domain separator for leaf hashes. */
export const LEAF_PREFIX = 0x00;
/** Domain separator for internal-node hashes. */
export const NODE_PREFIX = 0x01;

const sha256 = (...parts: Uint8Array[]): string =>
  parts.reduce((h, p) => h.update(p), createHash('sha256')).digest('hex');

const hexToBytes = (hex: string): Uint8Array => {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`not a hex string: ${JSON.stringify(hex.slice(0, 32))}`);
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};

/**
 * Hash one leaf.
 *
 * The leaf covers exactly the RFC-0002 canonical event bytes — the same bytes
 * `eventHash` is computed over — so a leaf is derivable from the event alone,
 * with no additional state.
 *
 * @param salt Optional per-leaf salt, hex. Breaks cross-range linkability of
 *   identical events. Must be disclosed alongside any leaf it covers, or that
 *   leaf can never be proved again.
 */
export function leafHash(event: HashableEventFields, salt?: string): string {
  const bytes = canonicalEventBytes(event);
  const prefix = Uint8Array.of(LEAF_PREFIX);
  return salt === undefined
    ? sha256(prefix, bytes)
    : sha256(prefix, hexToBytes(salt), bytes);
}

/** Hash an internal node from its two children. */
export function nodeHash(left: string, right: string): string {
  return sha256(Uint8Array.of(NODE_PREFIX), hexToBytes(left), hexToBytes(right));
}

export class MerkleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MerkleError';
  }
}

/**
 * Build the tree levels, bottom-up. `levels[0]` is the leaves; the last level
 * holds the single root.
 *
 * Exposed because proof generation needs the intermediate levels, and because
 * an auditor rebuilding the tree by hand should be able to compare level by
 * level rather than only at the root.
 */
export function buildLevels(leaves: ReadonlyArray<string>): string[][] {
  if (leaves.length === 0) {
    // A zero-leaf range has no root, and an empty compaction is
    // indistinguishable from a suppressed one. Refuse rather than invent a
    // convention (some implementations use sha256("") — that silently makes
    // "nothing happened" and "I hid everything" identical).
    throw new MerkleError(
      'cannot build a Merkle tree over zero leaves — an empty compaction attests nothing and is indistinguishable from a suppressed range',
    );
  }

  const levels: string[][] = [[...leaves]];
  while (levels[levels.length - 1]!.length > 1) {
    const current = levels[levels.length - 1]!;
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(nodeHash(current[i]!, current[i + 1]!));
      } else {
        // PROMOTE. Not `nodeHash(current[i], current[i])` — see the module note.
        next.push(current[i]!);
      }
    }
    levels.push(next);
  }
  return levels;
}

/** Merkle root over leaves in chain order. */
export function merkleRoot(leaves: ReadonlyArray<string>): string {
  const levels = buildLevels(leaves);
  return levels[levels.length - 1]![0]!;
}

/** Convenience: hash events into leaves, then root them. */
export function rootFromEvents(
  events: ReadonlyArray<HashableEventFields>,
  salts?: ReadonlyArray<string | undefined>,
): string {
  return merkleRoot(events.map((e, i) => leafHash(e, salts?.[i])));
}
