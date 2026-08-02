#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Generates the golden proof-chain test vectors in ../vectors/.
 *
 * IMPORTANT — this script deliberately does NOT import the canonicalizer
 * from src/chain-verifier.ts. It carries its own independent
 * implementation of RFC-0002 §"Canonical serialization", written from the
 * spec text rather than from the verifier's code. If the two ever
 * disagree, the vectors fail and we learn that one of them misread the
 * spec. Sharing the implementation would make the tests circular and
 * prove nothing.
 *
 * Everything here is deterministic — fixed key seed, fixed timestamps, no
 * randomness — so regenerating produces byte-identical vectors and the
 * diff is empty unless something genuinely changed.
 *
 * Usage: node scripts/generate-vectors.mjs
 */

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(HERE, '..', 'vectors');

// --- Independent canonical-JSON implementation (from the RFC text) ---------

function canon(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number');
    return String(v);
  }
  if (t === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (t === 'object') {
    const entries = [];
    // ASCII-byte order. Default Array#sort on strings is UTF-16 code-unit
    // order, which agrees with ASCII order for the ASCII range used by
    // these field names.
    for (const k of Object.keys(v).sort()) {
      if (v[k] === undefined) continue;
      entries.push(`${JSON.stringify(k)}:${canon(v[k])}`);
    }
    return `{${entries.join(',')}}`;
  }
  throw new Error(`unsupported type ${t}`);
}

/** RFC-0002 hashable fields, in canonical form. */
function hashInput({ agentId, eventType, occurredAt, payload, previousHash }) {
  return canon({
    agentId: agentId ?? '',
    eventType,
    occurredAt,
    payload,
    previousHash: previousHash ?? null,
  });
}

// --- Deterministic Ed25519 key from a fixed seed ---------------------------

const SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(SEED_HEX, 'hex')]),
  format: 'der',
  type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey);
const publicRawHex = publicKey
  .export({ format: 'der', type: 'spki' })
  .subarray(-32)
  .toString('hex');

const SIGNER = 'did:vorion:reference-runtime#ed25519-1';

// --- Chain construction ----------------------------------------------------

const AGENT = 'agent:reference-01';
const CORRELATION = '5f2b0c7a-1d3e-4a89-9c11-8e6b2a4d7f30';

/** Fixed skeletons — occurredAt/recordedAt are frozen for determinism. */
const SKELETONS = [
  {
    eventId: '0f8c2d41-6b57-4e29-a3f1-2c9d5e7a1b04',
    eventType: 'intent_received',
    occurredAt: '2026-08-01T12:00:00.000Z',
    recordedAt: '2026-08-01T12:00:00.014Z',
    payload: {
      type: 'intent_received',
      intentId: 'b71e4c90-52a8-4d63-91f7-0e3a8c6d25f1',
      action: 'Write the quarterly summary row to the reporting table',
      actionType: 'db.write',
      resourceScope: ['db:reporting.quarterly_summary'],
      riskLevel: 'MEDIUM',
    },
  },
  {
    eventId: '1a9e3f52-7c68-4f3a-b402-3da6f8b09c15',
    eventType: 'decision_made',
    occurredAt: '2026-08-01T12:00:00.021Z',
    recordedAt: '2026-08-01T12:00:00.029Z',
    payload: {
      type: 'decision_made',
      decision: 'allow',
      policyId: 'basis_core_security',
      rationale: 'actionType db.write is within T3 scoped-write authority',
    },
  },
  {
    eventId: '2b7d4a63-8e79-4a4b-c513-4eb7a9c1ad26',
    eventType: 'execution_started',
    occurredAt: '2026-08-01T12:00:00.033Z',
    recordedAt: '2026-08-01T12:00:00.037Z',
    payload: { type: 'execution_started', executionId: 'exec-7741' },
  },
  {
    eventId: '3c8e5b74-9f8a-4b5c-d624-5fc8bad2be37',
    eventType: 'execution_completed',
    occurredAt: '2026-08-01T12:00:00.198Z',
    recordedAt: '2026-08-01T12:00:00.203Z',
    payload: {
      type: 'execution_completed',
      executionId: 'exec-7741',
      durationMs: 161,
      outcome: 'success',
    },
  },
];

/** Seal a chain: compute hashes, link, and sign over the canonical bytes. */
function buildChain(skeletons, { signed }) {
  const out = [];
  let previousHash = null;

  for (const s of skeletons) {
    const input = hashInput({
      agentId: AGENT,
      eventType: s.eventType,
      occurredAt: s.occurredAt,
      payload: s.payload,
      previousHash,
    });
    const bytes = Buffer.from(input, 'utf-8');
    const eventHash = createHash('sha256').update(bytes).digest('hex');
    const eventHash3 = createHash('sha3-256').update(bytes).digest('hex');

    const ev = {
      eventId: s.eventId,
      eventType: s.eventType,
      correlationId: CORRELATION,
      agentId: AGENT,
      payload: s.payload,
      previousHash,
      eventHash,
      eventHash3,
      occurredAt: s.occurredAt,
      recordedAt: s.recordedAt,
      shadowMode: 'production',
    };

    if (signed) {
      // RFC-0002 §"Verification procedure" step 5: the detached signature
      // covers the CANONICAL BYTES (not the hex hash string).
      ev.signedBy = SIGNER;
      ev.signature = sign(null, bytes, privateKey).toString('base64');
    }

    out.push(ev);
    previousHash = eventHash;
  }
  return out;
}

const clone = (x) => JSON.parse(JSON.stringify(x));

const validSigned = buildChain(SKELETONS, { signed: true });
const validUnsigned = buildChain(SKELETONS, { signed: false });

// Tamper 1: payload edited after sealing — stored eventHash is now stale.
const tamperedPayload = clone(validSigned);
tamperedPayload[1].payload.decision = 'deny';

// Tamper 2: linkage cut — event 2 points at a hash that isn't event 1's.
const brokenLinkage = clone(validSigned);
brokenLinkage[2].previousHash = 'f'.repeat(64);

// Tamper 3: signature corrupted (flip the first base64 char to a different
// valid one) while leaving hashes and linkage intact — isolates the
// signature check from the hash check.
const badSignature = clone(validSigned);
{
  const sig = Buffer.from(badSignature[0].signature, 'base64');
  sig[0] ^= 0xff;
  badSignature[0].signature = sig.toString('base64');
}

// Tamper 4: signature computed over the eventHash string instead of the
// canonical bytes — the RFC-0002 ambiguity, as a real vector.
const domainMismatch = clone(validSigned);
for (const ev of domainMismatch) {
  ev.signature = sign(null, Buffer.from(ev.eventHash, 'utf-8'), privateKey).toString('base64');
}

// Tamper 5: head does not start at null.
const badHead = clone(validSigned);
badHead[0].previousHash = 'a'.repeat(64);

mkdirSync(VECTORS_DIR, { recursive: true });

const write = (name, data) =>
  writeFileSync(join(VECTORS_DIR, name), JSON.stringify(data, null, 2) + '\n', 'utf-8');

write('chain-valid-signed.json', validSigned);
write('chain-valid-unsigned.json', validUnsigned);
write('chain-tampered-payload.json', tamperedPayload);
write('chain-broken-linkage.json', brokenLinkage);
write('chain-bad-signature.json', badSignature);
write('chain-signature-domain-mismatch.json', domainMismatch);
write('chain-bad-head.json', badHead);
write('keys.json', {
  note: 'Ed25519 public key for the reference test vectors. Derived from a FIXED seed — these vectors are deterministic and this key protects nothing real.',
  signer: SIGNER,
  publicKeyHex: publicRawHex,
  seedHex: SEED_HEX,
  signatureDomain: 'canonical',
});

process.stdout.write(
  `wrote 8 vector files to ${VECTORS_DIR}\n` +
    `  signer:    ${SIGNER}\n` +
    `  publicKey: ${publicRawHex}\n` +
    `  head hash: ${validSigned[0].eventHash}\n`,
);
