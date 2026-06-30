// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * OFFLINE, FAIL-CLOSED verifiers for the transparency log. Pure functions over
 * supplied {leafHash, auditPath/proof, STH, public keys} — ZERO network calls,
 * ZERO DID resolution. The caller verifies the STH signature/witness separately
 * (or passes a pre-trusted STH); these functions check a proof AGAINST that STH.
 *
 * Every verifier:
 *  - decodes every hash to EXACTLY 32 bytes before any comparison (a non-32B
 *    hash => false);
 *  - compares ALL bytes (constant-time) and only returns true after the FULL
 *    fold (never true on a partial check — the prior fail-open anti-pattern);
 *  - wraps decode+compare in try/catch and returns {valid:false} on any throw;
 *  - treats treeSize===0 / index>=treeSize / m>=n as no-membership/false.
 */

import { verify as edVerify } from 'node:crypto';
import { jcsBytes } from './jcs.js';
import {
  constantTimeEqual,
  fromHexExact,
} from './bytes.js';
import {
  hashInterior,
  type Sth,
  type SthBody,
} from './log.js';
import {
  ED25519_SIG_LEN,
  publicKeyObjectFrom,
  type PublicKeyLike,
} from './didkey.js';

export interface VerifyResult {
  readonly valid: boolean;
  readonly reason?: string;
}

const HASH_LEN = 32;

function fail(reason: string): VerifyResult {
  return { valid: false, reason };
}

/** Decode an array of hex hashes to 32-byte buffers; null if any is malformed. */
function decodePath(path: readonly string[]): Uint8Array[] | null {
  const out: Uint8Array[] = [];
  for (const h of path) {
    const b = fromHexExact(h, HASH_LEN);
    if (b === null) return null;
    out.push(b);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Inclusion proof verification (RFC-6962 §2.1.1)
// ---------------------------------------------------------------------------

/**
 * The exact RFC-6962 inclusion-path length for (leafIndex, treeSize). Used to
 * reject a path that is too short OR too long (both are fail-open footguns).
 */
function expectedInclusionPathLength(leafIndex: number, treeSize: number): number {
  let len = 0;
  let index = leafIndex;
  let size = treeSize;
  while (size > 1) {
    const k = largestPow2Below(size);
    if (index < k) {
      size = k;
    } else {
      index -= k;
      size -= k;
    }
    len++;
  }
  return len;
}

function largestPow2Below(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/**
 * Verify a leaf's inclusion against a trusted STH's root, recomputing the root
 * by folding leafHash up through the audit path using the RFC-6962 index-bit
 * rule. Returns true ONLY after the full fold matches all 32 bytes of the root.
 */
export function verifyInclusion(args: {
  leafHash: string;
  leafIndex: number;
  treeSize: number;
  auditPath: readonly string[];
  sth: Sth;
}): VerifyResult {
  try {
    const { leafHash, leafIndex, treeSize, auditPath, sth } = args;

    if (!Number.isInteger(treeSize) || treeSize <= 0) return fail('empty_or_bad_treeSize');
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
      return fail('index_out_of_range');
    }
    if (sth === null || typeof sth !== 'object') return fail('sth_invalid');
    if (sth.treeSize !== treeSize) return fail('treeSize_mismatch');

    const leaf = fromHexExact(leafHash, HASH_LEN);
    if (leaf === null) return fail('leafHash_malformed');
    const root = fromHexExact(sth.rootHash, HASH_LEN);
    if (root === null) return fail('sth_rootHash_malformed');

    const path = decodePath(auditPath);
    if (path === null) return fail('auditPath_malformed_hash');

    // Reject too-short AND too-long audit paths.
    const expectedLen = expectedInclusionPathLength(leafIndex, treeSize);
    if (path.length !== expectedLen) return fail('auditPath_wrong_length');

    // Canonical RFC-6962 §2.1.1 audit-path verification. The path is ordered
    // DEEPEST sibling first (as the generator emits it). fn/sn track the
    // collapsing (index, lastIndex) of the current node within its subtree:
    //   - if fn is the rightmost node of its level (fn === sn) OR fn is a left
    //     child with no right sibling captured yet, the sibling is to the
    //     LEFT only when fn is odd; otherwise it is to the RIGHT.
    let node = leaf;
    let fn = leafIndex;
    let sn = treeSize - 1;
    for (const sibling of path) {
      if (sn === 0) {
        // No more levels expected but a sibling remains => over-long path.
        return fail('auditPath_wrong_length');
      }
      if (fn % 2 === 1 || fn === sn) {
        // current node is a RIGHT child (or pushed up as a right edge): sibling
        // is on the LEFT.
        node = hashInterior(sibling, node);
        // collapse: walk fn/sn up until fn is even (a left child) or zero.
        if (fn % 2 === 0) {
          do {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          } while (fn % 2 === 0 && sn !== 0);
        }
      } else {
        // current node is a LEFT child: sibling is on the RIGHT.
        node = hashInterior(node, sibling);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }

    if (sn !== 0) return fail('auditPath_wrong_length');
    if (!constantTimeEqual(node, root)) return fail('root_mismatch');
    return { valid: true };
  } catch {
    return fail('malformed');
  }
}

// ---------------------------------------------------------------------------
// Consistency proof verification (RFC-6962 §2.1.2)
// ---------------------------------------------------------------------------

/**
 * Verify that newSth (size n) is an append-only extension of oldSth (size m),
 * m < n. Reconstructs BOTH the old root and the new root from the single proof
 * and requires BOTH to match (matching only one is a fail-open). FAIL-CLOSED on
 * m>=n, m<=0, malformed hashes, or a wrong proof length.
 *
 * Algorithm: the canonical RFC-6962 consistency-verification (as in RFC-6962
 * §2.1.2 / the CT reference). Handles the m===2^x boundary where the old tree
 * is a complete subtree (proof omits the first node).
 */
export function verifyConsistency(
  oldSth: Sth,
  newSth: Sth,
  proof: readonly string[],
): VerifyResult {
  try {
    if (oldSth === null || typeof oldSth !== 'object') return fail('oldSth_invalid');
    if (newSth === null || typeof newSth !== 'object') return fail('newSth_invalid');
    const m = oldSth.treeSize;
    const n = newSth.treeSize;
    if (!Number.isInteger(m) || !Number.isInteger(n)) return fail('bad_treeSize');
    if (m <= 0) return fail('m_nonpositive'); // m===0 has no first tree to extend
    if (m >= n) return fail('m_ge_n');

    const oldRoot = fromHexExact(oldSth.rootHash, HASH_LEN);
    if (oldRoot === null) return fail('oldSth_rootHash_malformed');
    const newRoot = fromHexExact(newSth.rootHash, HASH_LEN);
    if (newRoot === null) return fail('newSth_rootHash_malformed');

    const path = decodePath(proof);
    if (path === null) return fail('proof_malformed_hash');

    // Canonical RFC-6962 §2.1.2 consistency verification (the CT / Trillian
    // VerifyConsistencyProof recurrence). The proof is consumed in order
    // (deepest first). We reconstruct BOTH the old root (fr=hash) and the new
    // root (sr=hash1); BOTH must match or the larger tree is not an append-only
    // extension.
    //
    // Reference recurrence (RFC-6962):
    //   node = m - 1; last = n - 1
    //   while node is odd: node >>= 1; last >>= 1     (skip complete right edge)
    //   seed = (m is a power of two) ? oldRoot : proof[0]
    //   hash = hash1 = seed; consume remaining proof nodes:
    //     while last > 0:
    //       if node is odd OR node == last:
    //         hash  = H(0x01 || proof[i] || hash)
    //         hash1 = H(0x01 || proof[i] || hash1)
    //         while node is even AND node != 0: node >>= 1; last >>= 1
    //       else:
    //         hash1 = H(0x01 || hash1 || proof[i])
    //       node >>= 1; last >>= 1
    //   require hash == oldRoot AND hash1 == newRoot AND all proof consumed.
    const mIsPow2 = (m & (m - 1)) === 0;

    let node = m - 1;
    let last = n - 1;
    while (node % 2 === 1) {
      node = Math.floor(node / 2);
      last = Math.floor(last / 2);
    }

    let i = 0;
    let seed: Uint8Array;
    if (mIsPow2) {
      seed = oldRoot;
    } else {
      if (path.length === 0) return fail('proof_too_short');
      seed = path[i++] as Uint8Array;
    }

    let hash = seed; // toward old root
    let hash1 = seed; // toward new root
    while (last > 0) {
      if (i >= path.length) return fail('proof_exhausted');
      const p = path[i++] as Uint8Array;
      if (node % 2 === 1 || node === last) {
        hash = hashInterior(p, hash);
        hash1 = hashInterior(p, hash1);
        while (node % 2 === 0 && node !== 0) {
          node = Math.floor(node / 2);
          last = Math.floor(last / 2);
        }
      } else {
        hash1 = hashInterior(hash1, p);
      }
      node = Math.floor(node / 2);
      last = Math.floor(last / 2);
    }

    // The proof must be consumed exactly (over-long => fail-closed).
    if (i !== path.length) return fail('proof_too_long');

    if (!constantTimeEqual(hash, oldRoot)) return fail('old_root_mismatch');
    if (!constantTimeEqual(hash1, newRoot)) return fail('new_root_mismatch');
    return { valid: true };
  } catch {
    return fail('malformed');
  }
}

// ---------------------------------------------------------------------------
// STH signature + witness cosignature verification
// ---------------------------------------------------------------------------

/** Reconstruct the canonical signed body from an STH's own fields. */
function sthBodyOf(sth: Sth): SthBody {
  const body: SthBody = {
    sthVersion: sth.sthVersion,
    treeSize: sth.treeSize,
    rootHash: sth.rootHash,
    logId: sth.logId,
    ...(sth.treeHeadTime !== undefined ? { treeHeadTime: sth.treeHeadTime } : {}),
  };
  return body;
}

/**
 * Verify the STH's own signature with a relying-party-supplied signer public
 * key. FAIL-CLOSED: empty/absent signature => false (NOT "valid by omission");
 * a signature that is not 64 bytes => false; a crypto throw => false. The
 * signerKey is bound INSIDE the verified bytes via JCS(sthBody) reconstruction,
 * so a key/alg strip or downgrade fails the recompute.
 */
export function verifySthSignature(sth: Sth, signerPublicKey: PublicKeyLike): boolean {
  try {
    if (sth === null || typeof sth !== 'object') return false;
    if (sth.sthVersion !== 'v1') return false;
    if (typeof sth.signature !== 'string' || sth.signature.length === 0) return false;
    if (typeof sth.rootHash !== 'string') return false;
    if (!Number.isInteger(sth.treeSize) || sth.treeSize < 0) return false;

    const sig = Buffer.from(sth.signature, 'base64');
    if (sig.length !== ED25519_SIG_LEN) return false;

    const pub = publicKeyObjectFrom(signerPublicKey);
    if (pub === null) return false;

    const msg = jcsBytes(sthBodyOf(sth));
    return edVerify(null, msg, pub, sig);
  } catch {
    return false;
  }
}

/**
 * Verify ONE supplied witness cosignature over the SAME canonical sthBody.
 * The lib HOLDS+VERIFIES a witness sig if the caller supplies it; it never runs
 * or assumes a witness. Absence of a witness sig => false here (the caller
 * decides, per policy, whether absence is acceptable — the lib does not
 * fabricate a witness). FAIL-CLOSED on any malformed input or crypto throw.
 */
export function verifySthWitness(sth: Sth, witnessPublicKey: PublicKeyLike): boolean {
  try {
    if (sth === null || typeof sth !== 'object') return false;
    if (sth.sthVersion !== 'v1') return false;
    const cosigs = sth.witnessCosignatures;
    if (!Array.isArray(cosigs) || cosigs.length === 0) return false;

    const pub = publicKeyObjectFrom(witnessPublicKey);
    if (pub === null) return false;

    const msg = jcsBytes(sthBodyOf(sth));

    // The witness sig must match the SAME public key the RP chose. We find a
    // cosignature whose witnessKey normalizes to the supplied key, then verify.
    const wantMk = publicKeyObjectFrom(witnessPublicKey);
    if (wantMk === null) return false;
    const wantSpki = (wantMk.export({ type: 'spki', format: 'der' }) as Buffer);

    for (const c of cosigs) {
      if (typeof c?.witnessKey !== 'string' || typeof c?.signature !== 'string') continue;
      if (c.signature.length === 0) continue;
      const cKey = publicKeyObjectFrom(c.witnessKey);
      if (cKey === null) continue;
      const cSpki = cKey.export({ type: 'spki', format: 'der' }) as Buffer;
      if (!constantTimeEqual(new Uint8Array(cSpki), new Uint8Array(wantSpki))) continue;
      const sig = Buffer.from(c.signature, 'base64');
      if (sig.length !== ED25519_SIG_LEN) continue;
      if (edVerify(null, msg, pub, sig)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

// Internal export for the equivocation module (root-hash hex equality with
// length safety). Kept here so the 32-byte rule lives in one place.
export function sameRootHash(a: string, b: string): boolean {
  const ba = fromHexExact(a, HASH_LEN);
  const bb = fromHexExact(b, HASH_LEN);
  if (ba === null || bb === null) return false;
  return constantTimeEqual(ba, bb);
}
