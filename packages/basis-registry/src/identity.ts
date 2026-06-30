// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Self-certifying CAR identifier (arch-doc §2.A).
 *
 * A CAR id is the hash of its own genesis object, so identity is
 * forgery-resistant WITHOUT an allocator or a server:
 *
 *   car:<registryRootFp>:v1:<idHash>
 *
 *   registryRootFp = multibase('z', multihash(sha2-256, sha-256(rootMultikey)))
 *                    — full sha-256 multihash (NO truncation): prefix 0x12 0x20
 *                    then the 32-byte digest. Depends ONLY on the root public
 *                    key, so it is verifiable from rootPublicKey alone.
 *   "v1"           = id-construction version (also bound INTO the hashed bytes
 *                    via genesis.idSpec='car/v1').
 *   idHash         = multibase('z', multihash(sha2-384, sha-384(JCS(genesis))))
 *                    — full sha-384 multihash: prefix 0x20 0x30 then the
 *                    48-byte digest. (The garbled "0x97 0x01 0x30" from the
 *                    draft is WRONG and is not used; sha2-384 multihash code is
 *                    0x20, length 48 = 0x30.) The length is part of the
 *                    multihash so a truncated digest is structurally rejected.
 *
 * Two algorithms by deliberate design (defended in the README):
 *  - sha-384 for the PERMANENT identity preimage (the strongest, heaviest hash
 *    for the part where a 2nd-preimage break = identity forgery);
 *  - sha-256 for the registryRootFp namespace id (it lives in the log world,
 *    which is RFC-6962/sha-256).
 *
 * verify() is FAIL-CLOSED and NEVER throws to a trusted state. mint() is a
 * constructor and MAY throw on malformed CALLER input.
 */

import { createHash } from 'node:crypto';
import { jcsBytes } from './jcs.js';
import {
  MH_SHA2_256,
  MH_SHA2_384,
  multibaseDecodeZ,
  multibaseEncodeZ,
  multihashDecodeExact,
  multihashEncode,
  constantTimeEqual,
} from './bytes.js';
import {
  decodeEd25519DidKey,
  decodeEd25519Multikey,
  isValidEd25519DidKey,
  normalizeToMultikey,
  type PublicKeyLike,
} from './didkey.js';

// ---------------------------------------------------------------------------
// CARCategory — registry-owned (NOT in @vorionsys/basis-spec today, verified).
// Documented as RFC-amendable and re-export-ready if basis-spec adopts it.
// ---------------------------------------------------------------------------

export const CAR_CATEGORIES = {
  AGENT: 'AGENT',
  MODEL: 'MODEL',
  TOOL: 'TOOL',
  SERVICE: 'SERVICE',
  REGISTRY: 'REGISTRY',
} as const;

export type CarCategory = keyof typeof CAR_CATEGORIES;

const CATEGORY_SET: ReadonlySet<string> = new Set(Object.keys(CAR_CATEGORIES));

// ---------------------------------------------------------------------------
// Genesis + id types
// ---------------------------------------------------------------------------

export type CarId = `car:${string}:v1:${string}`;

export interface CarGenesis {
  /** Pins construction + hash rules. v1 is exactly 'car/v1'. */
  readonly idSpec: 'car/v1';
  /** Pinned TrustSpec version (opaque string, e.g. 'basis-spec@1.2.0+sha256:..'). */
  readonly specVersion: string;
  /** Declared CAR class. */
  readonly category: CarCategory;
  /** 1..n controller did:key(s); MUST be pre-sorted (ascending) and unique. */
  readonly controller: readonly string[];
  /** Issuing registry root PUBLIC key as a multibase Multikey ('z' || 34B). */
  readonly registryRoot: string;
}

export interface VerifyResult {
  readonly valid: boolean;
  readonly reason?: string;
}

const REQUIRED_GENESIS_KEYS = [
  'idSpec',
  'specVersion',
  'category',
  'controller',
  'registryRoot',
] as const;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}
function sha384(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha384').update(data).digest());
}

/** Are the strings strictly ascending (sorted AND unique) by UTF-16 code unit? */
function isStrictlySortedUnique(arr: readonly string[]): boolean {
  for (let i = 1; i < arr.length; i++) {
    if ((arr[i - 1] as string) >= (arr[i] as string)) return false;
  }
  return true;
}

/**
 * registryRootFp from a root public key: multibase('z', multihash(sha2-256,
 * sha256(rootMultikey))). Computable from the root key alone. Returns null
 * (fail-closed) if the key cannot be normalized.
 */
export function registryRootFp(rootPublicKey: PublicKeyLike): string | null {
  const mk = normalizeToMultikey(rootPublicKey);
  if (mk === null) return null;
  const digest = sha256(mk);
  return multibaseEncodeZ(multihashEncode(MH_SHA2_256, digest));
}

/** registryRootFp computed directly from canonical 34-byte multikey bytes. */
function fpFromMultikey(multikey: Uint8Array): string {
  return multibaseEncodeZ(multihashEncode(MH_SHA2_256, sha256(multikey)));
}

/** idHash from a genesis: multibase('z', multihash(sha2-384, sha384(JCS))). */
function computeIdHash(genesis: CarGenesis): string {
  const digest = sha384(jcsBytes(genesis));
  return multibaseEncodeZ(multihashEncode(MH_SHA2_384, digest));
}

/**
 * Structural genesis validation: object with EXACTLY the required keys, all
 * well-typed, idSpec === 'car/v1', a known category, a non-empty strictly
 * sorted+unique controller array of valid ed25519 did:keys, and a registryRoot
 * that decodes to a 34-byte ed25519 multikey. Returns a reason string on the
 * first failure, or null if structurally valid.
 */
function genesisStructureError(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'genesis_not_object';
  }
  const g = value as Record<string, unknown>;
  const keys = Object.keys(g);
  // EXACT keys: no missing, no extra (extra keys cannot change idHash but could
  // smuggle hash-irrelevant semantics).
  if (keys.length !== REQUIRED_GENESIS_KEYS.length) return 'genesis_extra_or_missing_keys';
  for (const k of REQUIRED_GENESIS_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(g, k)) return `genesis_missing_${k}`;
  }
  if (g['idSpec'] !== 'car/v1') return 'genesis_bad_idSpec';
  if (typeof g['specVersion'] !== 'string' || g['specVersion'].length === 0) {
    return 'genesis_bad_specVersion';
  }
  if (typeof g['category'] !== 'string' || !CATEGORY_SET.has(g['category'])) {
    return 'genesis_bad_category';
  }
  const controller = g['controller'];
  if (!Array.isArray(controller) || controller.length === 0) {
    return 'genesis_bad_controller';
  }
  for (const c of controller) {
    if (typeof c !== 'string') return 'genesis_controller_not_string';
    // Mixed-suite reject: every controller MUST be a valid ed25519 did:key
    // under idSpec 'car/v1'. A non-ed25519 (e.g. P-384) did:key => false, so
    // v1 cannot be tricked into "verifying" a controller it does not check.
    if (!isValidEd25519DidKey(c)) return 'genesis_controller_not_ed25519_didkey';
  }
  if (!isStrictlySortedUnique(controller as readonly string[])) {
    return 'genesis_controller_unsorted_or_dup';
  }
  const registryRoot = g['registryRoot'];
  if (typeof registryRoot !== 'string') return 'genesis_registryRoot_not_string';
  const mk = multibaseDecodeZ(registryRoot);
  if (mk === null) return 'genesis_registryRoot_bad_multibase';
  if (decodeEd25519Multikey(mk) === null) return 'genesis_registryRoot_not_ed25519_multikey';
  return null;
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

/**
 * Mint a CAR id from a genesis + the issuing registry root public key.
 * THROWS (constructor semantics) on malformed caller input. Binds the supplied
 * root key to genesis.registryRoot (they MUST be the same 34 bytes).
 */
export function mint(genesis: CarGenesis, rootPublicKey: PublicKeyLike): CarId {
  const err = genesisStructureError(genesis);
  if (err !== null) throw new TypeError(`mint: invalid genesis (${err})`);

  const rootMk = normalizeToMultikey(rootPublicKey);
  if (rootMk === null) throw new TypeError('mint: rootPublicKey not a valid ed25519 key');

  // Bind: genesis.registryRoot must decode to the SAME 34 bytes as the supplied
  // root key. (genesis structure already proved it decodes to a valid multikey.)
  const declaredMk = multibaseDecodeZ(genesis.registryRoot);
  if (declaredMk === null || !constantTimeEqual(declaredMk, rootMk)) {
    throw new TypeError('mint: genesis.registryRoot does not match rootPublicKey');
  }

  const fp = fpFromMultikey(rootMk);
  const idHash = computeIdHash(genesis);
  return `car:${fp}:v1:${idHash}`;
}

// ---------------------------------------------------------------------------
// verify (fail-closed, never throws)
// ---------------------------------------------------------------------------

/**
 * Verify that `id` is the correct self-certifying hash of `genesis` issued
 * under `rootPublicKey`. FAIL-CLOSED: returns {valid:false,reason} on the first
 * failure and NEVER throws to a trusted state. Proves the id binds to THIS
 * genesis and THIS root; it does NOT prove the controller currently holds the
 * key (use verifyControl) nor that the id was ever logged (use the log layer).
 */
export function verify(
  id: string,
  genesis: unknown,
  rootPublicKey: PublicKeyLike,
): VerifyResult {
  try {
    // (a) id parses into exactly 5 segments: car:<fp>:v1:<idHash>
    if (typeof id !== 'string') return { valid: false, reason: 'id_not_string' };
    const seg = id.split(':');
    if (seg.length !== 4) return { valid: false, reason: 'id_bad_segment_count' };
    const [scheme, idFp, ver, idHashSeg] = seg as [string, string, string, string];
    if (scheme !== 'car') return { valid: false, reason: 'id_bad_scheme' };
    if (ver !== 'v1') return { valid: false, reason: 'id_bad_version' };
    if (idFp.length === 0 || idHashSeg.length === 0) {
      return { valid: false, reason: 'id_empty_segment' };
    }

    // (b) genesis structurally exact + well-typed.
    const gErr = genesisStructureError(genesis);
    if (gErr !== null) return { valid: false, reason: gErr };
    const g = genesis as CarGenesis;

    // (c) registryRootFp agreement across THREE sources: supplied root key,
    // id segment, and genesis-declared root.
    const rootMk = normalizeToMultikey(rootPublicKey);
    if (rootMk === null) return { valid: false, reason: 'root_key_invalid' };
    const declaredMk = multibaseDecodeZ(g.registryRoot);
    if (declaredMk === null) return { valid: false, reason: 'genesis_root_bad_multibase' };
    if (!constantTimeEqual(declaredMk, rootMk)) {
      return { valid: false, reason: 'genesis_root_mismatch' };
    }
    const fpFromKey = fpFromMultikey(rootMk);
    if (fpFromKey !== idFp) return { valid: false, reason: 'id_fp_mismatch' };

    // (d) idHash recompute + constant-time compare on the decoded 48-byte
    // digest. Decode BOTH sides as a sha2-384 multihash so a truncated /
    // wrong-code multihash in the id is structurally rejected.
    const idMhBytes = multibaseDecodeZ(idHashSeg);
    if (idMhBytes === null) return { valid: false, reason: 'id_hash_bad_multibase' };
    const idDigest = multihashDecodeExact(idMhBytes, MH_SHA2_384, 48);
    if (idDigest === null) return { valid: false, reason: 'id_hash_bad_multihash' };
    const recomputed = sha384(jcsBytes(g));
    if (!constantTimeEqual(idDigest, recomputed)) {
      return { valid: false, reason: 'id_hash_mismatch' };
    }

    // (e) controller array sorted+unique & each a valid ed25519 did:key.
    // (genesisStructureError already enforced this, but assert again so the
    // invariant is local to the trusted-true path.)
    if (!isStrictlySortedUnique(g.controller)) {
      return { valid: false, reason: 'controller_unsorted_or_dup' };
    }
    for (const c of g.controller) {
      if (decodeEd25519DidKey(c) === null) {
        return { valid: false, reason: 'controller_not_ed25519_didkey' };
      }
    }

    return { valid: true };
  } catch {
    // Any decode/canonicalization throw (e.g. JCS on NaN/Infinity/cycle in a
    // genesis that somehow slipped the type check) => fail closed.
    return { valid: false, reason: 'noncanonical_genesis' };
  }
}
