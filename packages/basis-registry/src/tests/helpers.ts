// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Test-only helpers. Key generation is DETERMINISTIC where it matters (we seed
 * raw 32-byte keys from a counter) so tests are reproducible; crypto.sign over
 * those keys exercises the real Node Ed25519 path. The LIBRARY itself contains
 * no key generation, no Date.now, no Math.random.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from 'node:crypto';
import { encodeEd25519DidKey } from '../didkey.js';

/** PKCS#8 DER prefix for an Ed25519 private key; append the 32-byte seed. */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface TestKey {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly raw32: Uint8Array;
  readonly didKey: string;
}

/** Deterministic Ed25519 key from a 32-byte seed (fills from a byte value). */
export function keyFromSeedByte(seedByte: number): TestKey {
  const seed = Buffer.alloc(32, seedByte & 0xff);
  return keyFromSeed(seed);
}

export function keyFromSeed(seed: Buffer): TestKey {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const raw32 = new Uint8Array(spki.subarray(spki.length - 32));
  return { privateKey, publicKey, raw32, didKey: encodeEd25519DidKey(raw32) };
}

/** A fresh random key (used where determinism is not asserted). */
export function freshKey(): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const raw32 = new Uint8Array(spki.subarray(spki.length - 32));
  return { privateKey, publicKey, raw32, didKey: encodeEd25519DidKey(raw32) };
}

/** Sign arbitrary bytes with a test private key. */
export function signBytes(priv: KeyObject, msg: Uint8Array): Uint8Array {
  return new Uint8Array(edSign(null, msg, priv));
}
