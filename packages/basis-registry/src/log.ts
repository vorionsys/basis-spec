// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-6962 append-only Merkle transparency log (sha-256, 32-byte nodes).
 *
 * Domain separation (RFC-6962 §2.1 — the second-preimage defense):
 *   leaf hash:     H(0x00 || leafBytes)
 *   interior hash: H(0x01 || left || right)
 *   empty tree:    H()  = sha-256 of the empty string.
 * The 0x00/0x01 prefix bytes put leaf and interior hashes in disjoint domains,
 * so a forged leaf whose bytes equal 0x01||a||b CANNOT collide with interior(a,b).
 * There is NO un-prefixed hashing path in this API.
 *
 * The class is an IN-MEMORY reference (storage is the operator's; this lib is
 * the math). It generates proofs + signs STHs; the OFFLINE verifiers live in
 * verify.ts. No Date.now / Math.random anywhere.
 */

import { createHash, sign as edSign, type KeyObject } from 'node:crypto';
import { jcsBytes } from './jcs.js';
import { multibaseEncodeZ, toHex } from './bytes.js';
import { normalizeToMultikey, ED25519_RAW_LEN, ED25519_MULTIKEY_LEN } from './didkey.js';

export const LEAF_PREFIX = 0x00;
export const NODE_PREFIX = 0x01;

// ---------------------------------------------------------------------------
// Leaf records (tagged union). Raw evidence NEVER enters the log — only
// commitments (hashes / ids).
// ---------------------------------------------------------------------------

export type LeafRecord =
  | { readonly type: 'registration'; readonly carId: string; readonly genesisHash: string }
  | {
      readonly type: 'key_rotation';
      readonly carId: string;
      readonly fromKid: string;
      readonly toKid: string;
      readonly rotationSig: string;
    }
  | { readonly type: 'provenance_anchor'; readonly carId: string; readonly chainHead: string };

// ---------------------------------------------------------------------------
// STH + proof types
// ---------------------------------------------------------------------------

export interface WitnessCosignature {
  readonly witnessKey: string;
  readonly signature: string;
}

export interface Sth {
  readonly sthVersion: 'v1';
  readonly treeSize: number;
  /** lowercase hex sha-256 of the RFC-6962 MTH root. */
  readonly rootHash: string;
  /** Log namespace id (e.g. registryRootFp or the log signer fp). */
  readonly logId: string;
  /** OPTIONAL caller-supplied trusted time. NEVER read from Date.now here. */
  readonly treeHeadTime?: string;
  /** base64 detached Ed25519 signature over JCS(sthBody). */
  readonly signature: string;
  /** Multibase Multikey of the STH signer. */
  readonly signerKey: string;
  readonly witnessCosignatures?: readonly WitnessCosignature[];
}

/** The fields that are signed (everything except signature/signerKey/witness). */
export type SthBody = Pick<Sth, 'sthVersion' | 'treeSize' | 'rootHash' | 'logId'> &
  Partial<Pick<Sth, 'treeHeadTime'>>;

export interface InclusionProof {
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly auditPath: readonly string[]; // hex sibling hashes
}

// ---------------------------------------------------------------------------
// hashing primitives (the ONLY hashing paths; both domain-separated)
// ---------------------------------------------------------------------------

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** H() — RFC-6962 empty-tree hash = sha-256 of the empty string. */
export function emptyRootBytes(): Uint8Array {
  return sha256(new Uint8Array(0));
}

/** H(0x00 || leafBytes). */
export function hashLeafBytes(leafBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + leafBytes.length);
  buf[0] = LEAF_PREFIX;
  buf.set(leafBytes, 1);
  return sha256(buf);
}

/** H(0x01 || left || right) — left/right MUST each be 32 bytes. */
export function hashInterior(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== 32 || right.length !== 32) {
    throw new RangeError('hashInterior: children must be 32-byte hashes');
  }
  const buf = new Uint8Array(1 + 64);
  buf[0] = NODE_PREFIX;
  buf.set(left, 1);
  buf.set(right, 33);
  return sha256(buf);
}

/** Leaf bytes = JCS(leafRecord) UTF-8 (structured leaves, RFC-8785). */
export function leafBytes(leaf: LeafRecord): Uint8Array {
  return jcsBytes(leaf);
}

/** Public leaf-hash helper: H(0x00 || JCS(leaf)), lowercase hex. */
export function hashLeaf(leaf: LeafRecord): string {
  return toHex(hashLeafBytes(leafBytes(leaf)));
}

// ---------------------------------------------------------------------------
// RFC-6962 Merkle Tree Hash (MTH) over an ordered list of LEAF HASHES.
// ---------------------------------------------------------------------------

/** Largest power of two strictly less than n (n >= 2). */
function largestPow2Below(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/**
 * MTH over leaf-HASH bytes (each already H(0x00||leaf)):
 *   MTH([])    = H()
 *   MTH([d0])  = d0                              (the leaf hash itself)
 *   MTH(D[n])  = H(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest pow2 < n
 * NB: a single-leaf sub-list returns the LEAF hash (correct per RFC-6962); the
 * final root of a >1-leaf tree is therefore ALWAYS an interior hash.
 */
function mth(leafHashes: readonly Uint8Array[]): Uint8Array {
  const n = leafHashes.length;
  if (n === 0) return emptyRootBytes();
  if (n === 1) return leafHashes[0] as Uint8Array;
  const k = largestPow2Below(n);
  return hashInterior(mth(leafHashes.slice(0, k)), mth(leafHashes.slice(k)));
}

// ---------------------------------------------------------------------------
// RFC-6962 audit (inclusion) path: PATH(m, D[n]).
// ---------------------------------------------------------------------------

function inclusionPath(m: number, leafHashes: readonly Uint8Array[]): Uint8Array[] {
  const n = leafHashes.length;
  if (n === 1) return [];
  const k = largestPow2Below(n);
  if (m < k) {
    // path within the left subtree, plus the right subtree's root as a sibling
    return [...inclusionPath(m, leafHashes.slice(0, k)), mth(leafHashes.slice(k))];
  }
  // path within the right subtree, plus the left subtree's root as a sibling
  return [...inclusionPath(m - k, leafHashes.slice(k)), mth(leafHashes.slice(0, k))];
}

// ---------------------------------------------------------------------------
// RFC-6962 consistency proof: PROOF(m, D[n]) for 0 < m < n.
// ---------------------------------------------------------------------------

function subproof(
  m: number,
  leafHashes: readonly Uint8Array[],
  isComplete: boolean,
): Uint8Array[] {
  const n = leafHashes.length;
  if (m === n) {
    // If the subtree is complete (m === n and this is the original full tree
    // node), no node is needed; otherwise the subtree root is appended.
    return isComplete ? [] : [mth(leafHashes)];
  }
  // 0 < m < n
  const k = largestPow2Below(n);
  if (m <= k) {
    return [...subproof(m, leafHashes.slice(0, k), isComplete), mth(leafHashes.slice(k))];
  }
  return [...subproof(m - k, leafHashes.slice(k), false), mth(leafHashes.slice(0, k))];
}

function consistency(m: number, leafHashes: readonly Uint8Array[]): Uint8Array[] {
  const n = leafHashes.length;
  if (m === n) return []; // identical trees — empty proof
  return subproof(m, leafHashes, true);
}

// ---------------------------------------------------------------------------
// TransparencyLog — in-memory reference
// ---------------------------------------------------------------------------

export class TransparencyLog {
  private readonly leafHashes: Uint8Array[] = [];

  /** Append a leaf record; returns its index + lowercase-hex leaf hash. */
  append(leaf: LeafRecord): { leafIndex: number; leafHash: string } {
    const lh = hashLeafBytes(leafBytes(leaf));
    const leafIndex = this.leafHashes.length;
    this.leafHashes.push(lh);
    return { leafIndex, leafHash: toHex(lh) };
  }

  size(): number {
    return this.leafHashes.length;
  }

  /** RFC-6962 MTH root, lowercase hex. */
  rootHash(): string {
    return toHex(mth(this.leafHashes));
  }

  /** Inclusion (audit) proof for a leaf. null if index out of range. */
  inclusionProof(leafIndex: number): InclusionProof | null {
    const treeSize = this.leafHashes.length;
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
      return null;
    }
    const auditPath = inclusionPath(leafIndex, this.leafHashes).map(toHex);
    return { leafIndex, treeSize, auditPath };
  }

  /**
   * Consistency proof that the size-n tree extends the size-m tree (m < n).
   * null if (m, n) are out of range (m <= 0, m >= n, n > size).
   */
  consistencyProof(m: number, n: number): readonly string[] | null {
    if (!Number.isInteger(m) || !Number.isInteger(n)) return null;
    if (m <= 0 || m >= n || n > this.leafHashes.length) return null;
    return consistency(m, this.leafHashes.slice(0, n)).map(toHex);
  }

  /**
   * Sign an STH body with the log's Ed25519 private key. The signer public key
   * is recorded as a multibase Multikey so a verifier can recompute the bytes.
   * sthBody is canonicalized via JCS so the signerKey/alg are bound implicitly
   * by what re-canonicalizes on the verify side. THROWS on a bad key/body
   * (constructor semantics; verification never throws).
   */
  signSth(sthBody: SthBody, privateKey: KeyObject, signerPublicKey: KeyObject): Sth {
    const signerMk = normalizeToMultikey(signerPublicKey);
    if (signerMk === null) {
      throw new TypeError('signSth: signerPublicKey not a valid ed25519 key');
    }
    if (signerMk.length !== ED25519_MULTIKEY_LEN) {
      throw new RangeError('signSth: signer multikey length invalid');
    }
    // canonical signed body (only the body fields, no sig/signer/witness)
    const body: SthBody = {
      sthVersion: sthBody.sthVersion,
      treeSize: sthBody.treeSize,
      rootHash: sthBody.rootHash,
      logId: sthBody.logId,
      ...(sthBody.treeHeadTime !== undefined ? { treeHeadTime: sthBody.treeHeadTime } : {}),
    };
    const msg = jcsBytes(body);
    const sig = edSign(null, msg, privateKey);
    if (sig.length !== 64) throw new RangeError('signSth: unexpected signature length');
    return {
      ...body,
      signature: Buffer.from(sig).toString('base64'),
      signerKey: multibaseEncodeZ(signerMk),
    };
  }
}

// Re-export for tests / advanced callers that need the raw-32 path length.
export { ED25519_RAW_LEN };
