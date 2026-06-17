// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Holder-of-key proof (proof of control). Separate from identity verify():
 * verify() proves an id IS the hash of a genesis; verifyControl proves the
 * presenter currently HOLDS the controller private key, via a signed
 * verifier-supplied challenge nonce.
 *
 * FAIL-CLOSED: a malformed did:key, a wrong-length signature, a too-short
 * challenge, or any crypto throw => false (NEVER true on an unchecked input).
 */

import { verify as edVerify } from 'node:crypto';
import { decodeEd25519DidKey, ed25519PublicKeyObject, ED25519_SIG_LEN } from './didkey.js';

/**
 * Minimum challenge length. The verifier MUST supply fresh, sufficiently long
 * randomness so a replay or an empty/trivial challenge cannot "verify". 16
 * bytes (128 bits) is the floor; the lib does not generate the nonce (no
 * Math.random in the library) — the relying party supplies it.
 */
export const MIN_CHALLENGE_BYTES = 16;

/**
 * Verify a holder-of-key signature: the controller did:key signed `challenge`.
 *  - decodeEd25519DidKey null (malformed / non-ed25519) => false BEFORE any
 *    crypto call;
 *  - signature not exactly 64 bytes => false;
 *  - challenge shorter than MIN_CHALLENGE_BYTES => false (anti-replay contract);
 *  - crypto.verify throw on a bad key object => caught => false.
 */
export function verifyControl(
  didKey: string,
  challenge: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (!(challenge instanceof Uint8Array) || challenge.length < MIN_CHALLENGE_BYTES) {
      return false;
    }
    if (!(signature instanceof Uint8Array) || signature.length !== ED25519_SIG_LEN) {
      return false;
    }
    const raw = decodeEd25519DidKey(didKey);
    if (raw === null) return false; // hard-false, never fall through
    const pub = ed25519PublicKeyObject(raw);
    if (pub === null) return false;
    return edVerify(null, challenge, pub, signature);
  } catch {
    return false;
  }
}
