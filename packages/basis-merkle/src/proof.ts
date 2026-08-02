// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Audit paths — RFC-0007 §"Disclosure package".
 *
 * An audit path is the set of sibling hashes needed to fold one leaf up to the
 * root. It is O(log n) per leaf, and it is the artefact that lets a recipient
 * confirm "this decision sits under that signed root" while seeing nothing else
 * from the range.
 *
 * What it does NOT hide is documented in RFC-0007 §"Residual disclosure":
 * the path hashes are stable identifiers for sibling subtrees, so two
 * disclosures from the same range are correlatable, and the path length bounds
 * the range size even without an explicit count.
 */

import { buildLevels, nodeHash, MerkleError } from './tree.js';

export interface PathStep {
  readonly hash: string;
  /** Which side the SIBLING sits on when recombining. */
  readonly side: 'left' | 'right';
}

/**
 * Generate the audit path for one leaf.
 *
 * @param leaves All leaves of the range, in chain order.
 * @param index  Position of the leaf being disclosed.
 */
export function auditPath(leaves: ReadonlyArray<string>, index: number): PathStep[] {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new MerkleError(
      `leaf index ${index} is outside the range [0, ${leaves.length})`,
    );
  }

  const levels = buildLevels(leaves);
  const path: PathStep[] = [];
  let i = index;

  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level]!;
    const isRight = i % 2 === 1;
    const siblingIdx = isRight ? i - 1 : i + 1;

    if (siblingIdx < nodes.length) {
      path.push({
        hash: nodes[siblingIdx]!,
        side: isRight ? 'left' : 'right',
      });
    }
    // No sibling means this node was PROMOTED unchanged, so no path step is
    // recorded for this level. Either way the parent index is floor(i/2):
    // pairs (2k, 2k+1) collapse to k, and a promoted last node at even index
    // i (with i = n-1, n odd) lands at (n-1)/2 = floor(i/2), because exactly
    // that many pairs precede it.
    i = Math.floor(i / 2);
  }

  return path;
}

/**
 * Fold a leaf up its audit path and return the resulting root.
 *
 * Pure and dependency-free by design: a third party should be able to
 * re-implement this from the RFC in any language and get the same answer.
 */
export function foldPath(leaf: string, path: ReadonlyArray<PathStep>): string {
  let acc = leaf;
  for (const step of path) {
    acc = step.side === 'left' ? nodeHash(step.hash, acc) : nodeHash(acc, step.hash);
  }
  return acc;
}

/** Does this leaf, folded up this path, reach the claimed root? */
export function verifyPath(
  leaf: string,
  path: ReadonlyArray<PathStep>,
  expectedRoot: string,
): boolean {
  try {
    return foldPath(leaf, path) === expectedRoot;
  } catch {
    // A malformed path (non-hex sibling, wrong length) is a failed proof, not
    // an exception the caller has to guess the meaning of.
    return false;
  }
}
