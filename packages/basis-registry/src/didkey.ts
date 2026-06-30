// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * did:key + Ed25519 Multikey helpers. v1 supports Ed25519 ONLY (multicodec
 * 0xed01). A non-ed25519 multikey (X25519 0xec01, P-256 0x1200, P-384 0x1201,
 * secp256k1 0xe701, ...) is REJECTED — key-type confusion is the main did:key
 * footgun. P-256/P-384 are a documented FUTURE profile, a DISTINCT construction
 * pinned by genesis.idSpec ('car/v1'), never a silent downgrade.
 *
 * Byte mechanics (verified against Node crypto):
 *  - ed25519 SPKI DER export is 44 bytes; the raw 32-byte public key is the
 *    last 32 bytes.
 *  - Multikey = 0xed 0x01 (unsigned-varint of multicodec 0xed01) || raw32
 *    => 34 bytes.
 *  - did:key = "did:key:" + multibase('z', multikey).
 */

import { createPublicKey, type KeyObject } from 'node:crypto';
import { multibaseDecodeZ, multibaseEncodeZ } from './bytes.js';

/** Unsigned-varint encoding of multicodec ed25519-pub (0xed01) => [0xed, 0x01]. */
export const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

/** Raw Ed25519 public key length. */
export const ED25519_RAW_LEN = 32;
/** Ed25519 Multikey length (2-byte multicodec prefix + 32-byte key). */
export const ED25519_MULTIKEY_LEN = 34;
/** Ed25519 signature length. */
export const ED25519_SIG_LEN = 64;

/**
 * SPKI DER prefix for an Ed25519 public key. raw32 = SPKI[12..44]; conversely
 * a raw32 key can be re-wrapped as SPKI by prepending this prefix. (Verified:
 * createPublicKey on prefix||raw32 reconstructs a working verify key.)
 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Build the 34-byte Multikey from a raw 32-byte Ed25519 public key. */
export function ed25519Multikey(rawPubkey32: Uint8Array): Uint8Array {
  if (rawPubkey32.length !== ED25519_RAW_LEN) {
    throw new RangeError('ed25519Multikey: raw public key must be 32 bytes');
  }
  const out = new Uint8Array(ED25519_MULTIKEY_LEN);
  out.set(ED25519_MULTICODEC, 0);
  out.set(rawPubkey32, 2);
  return out;
}

/**
 * Decode a 34-byte Ed25519 Multikey to its raw 32-byte key. FAIL-CLOSED:
 * wrong length OR a multicodec prefix other than 0xed01 (key-type confusion)
 * => null.
 */
export function decodeEd25519Multikey(multikey: Uint8Array): Uint8Array | null {
  if (multikey.length !== ED25519_MULTIKEY_LEN) return null;
  if (multikey[0] !== 0xed || multikey[1] !== 0x01) return null;
  return new Uint8Array(multikey.subarray(2));
}

/** Encode a raw 32-byte Ed25519 public key as a did:key string. */
export function encodeEd25519DidKey(rawPubkey32: Uint8Array): string {
  const multikey = ed25519Multikey(rawPubkey32);
  return 'did:key:' + multibaseEncodeZ(multikey);
}

/**
 * Decode an Ed25519 did:key to its raw 32-byte public key. Returns null
 * (fail-closed) on ANY of:
 *  - missing "did:key:" prefix;
 *  - a multibase prefix other than 'z' (e.g. 'f' base16, 'm' base64);
 *  - a non-base58 character;
 *  - a multikey that is not exactly 34 bytes;
 *  - a multicodec prefix that is not ed25519-pub (0xed01).
 */
export function decodeEd25519DidKey(didKey: string): Uint8Array | null {
  if (typeof didKey !== 'string') return null;
  const PREFIX = 'did:key:';
  if (!didKey.startsWith(PREFIX)) return null;
  const mb = didKey.slice(PREFIX.length);
  const multikey = multibaseDecodeZ(mb); // rejects non-'z' multibase
  if (multikey === null) return null;
  return decodeEd25519Multikey(multikey);
}

/** A structurally valid Ed25519 did:key string (decodes to a 32-byte key). */
export function isValidEd25519DidKey(didKey: string): boolean {
  return decodeEd25519DidKey(didKey) !== null;
}

/**
 * A public key supplied to mint/verify in any of three forms:
 *  - a Node KeyObject (asymmetricKeyType 'ed25519');
 *  - a raw 32-byte Uint8Array;
 *  - a multibase Multikey string ('z' || 34-byte multikey).
 * Normalized internally to the canonical 34-byte Multikey, with a length
 * assert, so a 32-byte raw key can never be confused for a 34-byte multikey.
 */
export type PublicKeyLike = KeyObject | Uint8Array | string;

/**
 * Normalize a PublicKeyLike to its canonical 34-byte Ed25519 Multikey bytes.
 * Returns null (fail-closed) on any malformed / non-ed25519 input.
 */
export function normalizeToMultikey(key: PublicKeyLike): Uint8Array | null {
  try {
    if (typeof key === 'string') {
      // Accept a bare multibase Multikey OR a full did:key string.
      if (key.startsWith('did:key:')) {
        const raw = decodeEd25519DidKey(key);
        return raw === null ? null : ed25519Multikey(raw);
      }
      const mk = multibaseDecodeZ(key);
      if (mk === null) return null;
      // Must be a valid 34-byte ed25519 multikey.
      const raw = decodeEd25519Multikey(mk);
      return raw === null ? null : ed25519Multikey(raw);
    }
    if (key instanceof Uint8Array) {
      // A raw 34-byte multikey is accepted as-is (after validation); a raw
      // 32-byte key is promoted to a multikey. Any other length => null. This
      // is the length-disambiguation the reviewer mandated.
      if (key.length === ED25519_MULTIKEY_LEN) {
        const raw = decodeEd25519Multikey(key);
        return raw === null ? null : ed25519Multikey(raw);
      }
      if (key.length === ED25519_RAW_LEN) {
        return ed25519Multikey(key);
      }
      return null;
    }
    // KeyObject
    const ko = key as KeyObject;
    if (ko.type !== 'public') return null;
    if (ko.asymmetricKeyType !== 'ed25519') return null;
    const spki = ko.export({ type: 'spki', format: 'der' }) as Buffer;
    if (spki.length !== 44) return null;
    const raw = new Uint8Array(spki.subarray(spki.length - ED25519_RAW_LEN));
    return ed25519Multikey(raw);
  } catch {
    return null;
  }
}

/**
 * Build a Node KeyObject for crypto.verify from a raw 32-byte Ed25519 key.
 * Returns null (fail-closed) on any error (bad length, bad bytes).
 */
export function ed25519PublicKeyObject(rawPubkey32: Uint8Array): KeyObject | null {
  try {
    if (rawPubkey32.length !== ED25519_RAW_LEN) return null;
    const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawPubkey32)]);
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

/** KeyObject from a PublicKeyLike, via canonical multikey normalization. */
export function publicKeyObjectFrom(key: PublicKeyLike): KeyObject | null {
  const mk = normalizeToMultikey(key);
  if (mk === null) return null;
  const raw = decodeEd25519Multikey(mk);
  if (raw === null) return null;
  return ed25519PublicKeyObject(raw);
}
