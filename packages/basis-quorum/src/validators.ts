// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * A reference `Validator` that holds its signing key locally.
 *
 * Useful for tests, vectors, and single-process deployments. In a real
 * deployment each validator is a separately isolated service — the point of a
 * quorum is that the parties are independent, and independence is not achieved
 * by four objects in one process.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from 'node:crypto';
import type { Proposal, Validator, VoteResult } from './round.js';

/** DER PKCS8 prefix for a raw 32-byte Ed25519 seed (RFC 8410). */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface LocalValidatorOptions {
  readonly validatorId: string;
  /**
   * Judgment function. Receives ONLY the proposal — never another validator's
   * vote. Blindness is the caller's guarantee and this signature enforces it.
   */
  readonly evaluate: (proposal: Proposal) => Promise<VoteResult> | VoteResult;
  /** Claimed basis for independence, recorded for auditors. A claim, not proof. */
  readonly attributes?: Readonly<Record<string, string>>;
  /**
   * Ed25519 private key. Supply a fixed 32-byte seed (hex) for deterministic
   * fixtures; omit to generate a fresh key.
   */
  readonly privateKey?: KeyObject | string;
}

function resolvePrivateKey(key: KeyObject | string | undefined): KeyObject {
  if (key === undefined) return generateKeyPairSync('ed25519').privateKey;
  if (typeof key !== 'string') return key;

  const trimmed = key.trim();
  if (trimmed.includes('BEGIN PRIVATE KEY')) return createPrivateKey(trimmed);

  if (!/^[0-9a-f]{64}$/i.test(trimmed)) {
    throw new Error(
      'privateKey string must be a PEM PKCS8 block or a 64-char hex Ed25519 seed',
    );
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(trimmed, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * Build a `Validator` backed by a local Ed25519 key.
 *
 * The returned validator signs its votes with its OWN key, which is what makes
 * a vote attributable — the quorum aggregate cannot provide attribution,
 * because it is subset-anonymous.
 */
export function createLocalValidator(opts: LocalValidatorOptions): Validator & {
  readonly privateKey: KeyObject;
} {
  const privateKey = resolvePrivateKey(opts.privateKey);
  const publicKey = createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('hex');

  return {
    validatorId: opts.validatorId,
    publicKey,
    ...(opts.attributes ? { attributes: opts.attributes } : {}),
    privateKey,
    async evaluate(proposal: Proposal): Promise<VoteResult> {
      return opts.evaluate(proposal);
    },
    async sign(bytes: Uint8Array): Promise<string> {
      return nodeSign(null, bytes, privateKey).toString('base64');
    },
  };
}

/**
 * Build the `signedBy -> public key` map a chain verifier needs.
 *
 * Includes each validator's own key plus the quorum group key, because a
 * quorum chain carries both individually-signed votes and a group-signed
 * resolution.
 */
export function buildKeyring(
  validators: ReadonlyArray<Validator>,
  group?: { groupId: string; groupPublicKey: string },
): Record<string, string> {
  const keyring: Record<string, string> = {};
  for (const v of validators) keyring[v.validatorId] = v.publicKey;
  if (group) keyring[group.groupId] = group.groupPublicKey;
  return keyring;
}
