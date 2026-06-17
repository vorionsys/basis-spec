// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * @vorionsys/basis-registry — reference LIBRARY of verifiable primitives for
 * the BASIS trust substrate (arch-doc Stages 1-2).
 *
 * TWO primitives, BOTH verifiable fully OFFLINE (no server call, no DID
 * resolution), every verifier FAIL-CLOSED:
 *   1. Self-certifying CAR id — an id that is the hash of its own genesis
 *      object, so identity is forgery-resistant without an allocator.
 *   2. RFC-6962 append-only Merkle transparency log — inclusion + consistency
 *      proofs + Signed Tree Heads, with domain separation (0x00 leaf / 0x01
 *      interior) for second-preimage resistance, and split-view detection.
 *
 * SCOPE: this is a LIBRARY. It does NOT run a registry server, a witness
 * cosigning network, gossip, the AgentAnchor dual-write, or federation/
 * sovereign profiles — those are infra/operator follow-ons. See README.
 *
 * Usage:
 *   import { mint, verify } from '@vorionsys/basis-registry';
 *   import { TransparencyLog, verifyInclusion } from '@vorionsys/basis-registry';
 */

// --- Identity primitive ---
export {
  mint,
  verify,
  registryRootFp,
  CAR_CATEGORIES,
} from './identity.js';
export type { CarId, CarGenesis, CarCategory, VerifyResult } from './identity.js';

// --- Holder-of-key proof ---
export { verifyControl, MIN_CHALLENGE_BYTES } from './control.js';

// --- did:key + multikey helpers ---
export {
  encodeEd25519DidKey,
  decodeEd25519DidKey,
  isValidEd25519DidKey,
  ed25519Multikey,
  decodeEd25519Multikey,
  normalizeToMultikey,
  ED25519_RAW_LEN,
  ED25519_MULTIKEY_LEN,
  ED25519_SIG_LEN,
} from './didkey.js';
export type { PublicKeyLike } from './didkey.js';

// --- Canonicalization ---
export { jcsCanonicalize, jcsBytes, ASCII_KEY_INVARIANT } from './jcs.js';

// --- byte primitives (exported for advanced callers / tooling) ---
export {
  base58btcEncode,
  base58btcDecode,
  multibaseEncodeZ,
  multibaseDecodeZ,
  multihashEncode,
  multihashDecode,
  multihashDecodeExact,
  MH_SHA2_256,
  MH_SHA2_384,
  constantTimeEqual,
  toHex,
  fromHexExact,
} from './bytes.js';

// --- Transparency log primitive ---
export {
  TransparencyLog,
  hashLeaf,
  hashLeafBytes,
  hashInterior,
  leafBytes,
  emptyRootBytes,
  LEAF_PREFIX,
  NODE_PREFIX,
} from './log.js';
export type {
  LeafRecord,
  Sth,
  SthBody,
  WitnessCosignature,
  InclusionProof,
} from './log.js';

// --- Offline log verifiers (the load-bearing surface) ---
export {
  verifyInclusion,
  verifyConsistency,
  verifySthSignature,
  verifySthWitness,
} from './verify.js';

// --- Split-view / equivocation detection ---
export { detectEquivocation } from './equivocation.js';
export type { EquivocationResult } from './equivocation.js';
