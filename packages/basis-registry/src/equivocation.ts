// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Split-view / equivocation DETECTORS over a SUPPLIED pair of STHs. The lib
 * provides the math; it does NOT run gossip / a witness network (out of scope).
 *
 * HONEST CEILING (also stated in the README): detection REQUIRES the relying
 * party to actually SEE >=2 STHs from independent vantage points. The lib
 * cannot MANUFACTURE the second head — that needs the gossip/witness network
 * which is deferred. In a single-operator/single-witness air-gap profile no
 * independent second head exists, so split-view detection STRUCTURALLY CANNOT
 * FIRE; the residual trust root is the honest enclave operator. The lib does
 * NOT claim "non-equivocation" for that profile.
 */

import { verifyConsistency, sameRootHash, type VerifyResult } from './verify.js';
import type { Sth } from './log.js';

export interface EquivocationResult {
  readonly equivocation: boolean;
  readonly kind?: 'same_size_divergent_root' | 'non_extending' | undefined;
  readonly reason?: string;
  /** Re-verifiable evidence: the two signed STHs that contradict. */
  readonly misbehaviorCertificate?: readonly [Sth, Sth];
}

function bad(reason: string): EquivocationResult {
  return { equivocation: false, reason };
}

/**
 * Detect equivocation between two STHs claiming the SAME logId.
 *
 * Rule 1 (same-size fork): equal treeSize but different rootHash => a single
 * honest tree has exactly one root per size, so two roots at one size is a
 * cryptographic contradiction => equivocation (same_size_divergent_root).
 *
 * Rule 2 (non-extending): for m < n, run verifyConsistency(smaller, larger,
 * proof). If a consistency proof is SUPPLIED and FAILS, the larger is not an
 * append-only extension of the smaller => equivocation (non_extending). If the
 * proof is ABSENT, the result is 'undetermined' (NOT 'consistent') — absence of
 * a proof is NEVER treated as proof of consistency (fail-closed).
 *
 * Comparing two different logIds is "two logs", not equivocation.
 *
 * NOTE: the caller is responsible for having verified BOTH STH signatures by
 * the same logId/signer BEFORE trusting a returned misbehaviorCertificate — a
 * forged unsigned STH is not a non-repudiable misbehavior proof. This function
 * detects the contradiction; signature attribution is the caller's step (it has
 * the trusted signer key; this pure function does not).
 */
export function detectEquivocation(
  sthA: Sth,
  sthB: Sth,
  consistencyProof?: readonly string[],
): EquivocationResult {
  if (sthA === null || typeof sthA !== 'object') return bad('sthA_invalid');
  if (sthB === null || typeof sthB !== 'object') return bad('sthB_invalid');
  if (typeof sthA.logId !== 'string' || typeof sthB.logId !== 'string') {
    return bad('logId_invalid');
  }
  if (sthA.logId !== sthB.logId) {
    return { equivocation: false, reason: 'different_logs' };
  }
  const a = sthA.treeSize;
  const b = sthB.treeSize;
  if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b < 0) {
    return bad('treeSize_invalid');
  }

  // Rule 1: same-size divergent root.
  if (a === b) {
    if (typeof sthA.rootHash !== 'string' || typeof sthB.rootHash !== 'string') {
      return bad('rootHash_invalid');
    }
    if (!sameRootHash(sthA.rootHash, sthB.rootHash)) {
      return {
        equivocation: true,
        kind: 'same_size_divergent_root',
        reason: 'two_distinct_roots_at_same_size',
        misbehaviorCertificate: [sthA, sthB],
      };
    }
    // identical heads — not equivocation
    return { equivocation: false, reason: 'identical_heads' };
  }

  // Rule 2: different sizes — check append-only extension.
  const [smaller, larger] = a < b ? [sthA, sthB] : [sthB, sthA];
  if (consistencyProof === undefined) {
    // Absence of a proof is UNDETERMINED, never "consistent".
    return { equivocation: false, reason: 'undetermined_no_consistency_proof' };
  }
  const cons: VerifyResult = verifyConsistency(smaller, larger, consistencyProof);
  if (!cons.valid) {
    return {
      equivocation: true,
      kind: 'non_extending',
      reason: `consistency_failed:${cons.reason ?? 'unknown'}`,
      misbehaviorCertificate: [smaller, larger],
    };
  }
  return { equivocation: false, reason: 'consistent_extension' };
}
