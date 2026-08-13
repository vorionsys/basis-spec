// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Chain-verification tests — RFC-0002 §"Verification procedure".
 *
 * These run the public reference verifier against the shipped golden
 * vectors in ../../vectors/. The vectors are produced by
 * scripts/generate-vectors.mjs, which carries its OWN independent
 * canonicalizer written from the spec text — so a passing run here means
 * two separate implementations of RFC-0002 §"Canonical serialization"
 * agree on the exact bytes, which is the property the whole chain depends
 * on.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  verifyChain,
  canonicalize,
  canonicalEventString,
  toEd25519PublicKey,
} from '../chain-verifier.js';

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'vectors');

function vector(name: string): unknown {
  return JSON.parse(readFileSync(join(VECTORS, `${name}.json`), 'utf-8'));
}

const keys = vector('keys') as {
  signer: string;
  publicKeyHex: string;
};
const KEYRING = { [keys.signer]: keys.publicKeyHex };

// ---------------------------------------------------------------------------

describe('chain-verify: valid chains', () => {
  it('a well-formed signed chain verifies end to end', () => {
    const r = verifyChain(vector('chain-valid-signed'), { publicKeys: KEYRING });
    expect(r.valid).toBe(true);
    expect(r.verifiedEvents).toBe(4);
    expect(r.brokenAt).toBeUndefined();
    expect(r.signaturesValid).toBe(4);
    expect(r.signaturesInvalid).toBe(0);
    expect(r.signaturesUnverified).toBe(0);
  });

  it('recomputes the optional sha3-256 anchor when present', () => {
    const r = verifyChain(vector('chain-valid-signed'), { publicKeys: KEYRING });
    expect(r.hash3Checked).toBe(4);
    expect(r.events.every((e) => e.hash3Valid === true)).toBe(true);
  });

  it('an unsigned chain still verifies its hashes and linkage', () => {
    const r = verifyChain(vector('chain-valid-unsigned'));
    expect(r.valid).toBe(true);
    expect(r.verifiedEvents).toBe(4);
    expect(r.events.every((e) => e.signature === 'absent')).toBe(true);
  });

  it('reports first and last event ids per the spec result shape', () => {
    const chain = vector('chain-valid-signed') as Array<{ eventId: string }>;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.firstEventId).toBe(chain[0].eventId);
    expect(r.lastEventId).toBe(chain[chain.length - 1].eventId);
  });
});

describe('chain-verify: tamper detection', () => {
  it('detects a payload edited after the hash was sealed', () => {
    const chain = vector('chain-tampered-payload') as Array<{ eventId: string }>;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.valid).toBe(false);
    // Event 0 is untouched and verifies; the break is at event 1.
    expect(r.verifiedEvents).toBe(1);
    expect(r.brokenAt).toBe(chain[1].eventId);
    expect(r.events[1].hashValid).toBe(false);
    expect(r.events[1].problem).toMatch(/eventHash mismatch/);
  });

  it('detects cut linkage, and re-linking cannot be hidden', () => {
    const chain = vector('chain-broken-linkage') as Array<{ eventId: string }>;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(chain[2].eventId);
    expect(r.events[2].linkageValid).toBe(false);
    // `previousHash` is itself inside the hash input, so an attacker who
    // re-points an event at a different parent ALSO invalidates that
    // event's own eventHash. There is no way to splice a chain and leave
    // the per-event hashes intact — the two checks are not independent,
    // and that is the property that makes the chain tamper-evident.
    expect(r.events[2].hashValid).toBe(false);
  });

  it('rejects a chain head whose previousHash is not null', () => {
    const chain = vector('chain-bad-head') as Array<{ eventId: string }>;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.valid).toBe(false);
    expect(r.verifiedEvents).toBe(0);
    expect(r.brokenAt).toBe(chain[0].eventId);
    expect(r.events[0].problem).toMatch(/chain head must have previousHash null/);
  });

  it('detects a corrupted signature while hashes still verify', () => {
    const chain = vector('chain-bad-signature') as Array<{ eventId: string }>;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(chain[0].eventId);
    expect(r.events[0].signature).toBe('invalid');
    expect(r.events[0].hashValid).toBe(true);
    expect(r.events[0].linkageValid).toBe(true);
    expect(r.signaturesInvalid).toBe(1);
  });
});

describe('chain-verify: signature stripping', () => {
  // Regression guard. Before 0.3.0 the verifier only inspected `signature`
  // when it was present, so deleting the field left the event in the same
  // 'absent' state as a legitimately unsigned one — and a stripped chain
  // verified clean, including under --require-signatures. Removing a field
  // is the cheapest attack there is; it has to be the loudest failure.
  it('rejects a chain whose signatures were deleted but signedBy left behind', () => {
    const chain = vector('chain-stripped-signature') as Array<{ eventId: string }>;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(chain[0].eventId);
    expect(r.events[0].signature).toBe('stripped');
    expect(r.signaturesStripped).toBe(1);
    expect(r.events[0].problem).toMatch(/signature stripped/);
  });

  it('rejects it with no keyring supplied either — stripping is not a key problem', () => {
    const r = verifyChain(vector('chain-stripped-signature'));
    expect(r.valid).toBe(false);
    expect(r.events[0].signature).toBe('stripped');
  });

  it('still rejects it under requireSignatures', () => {
    const r = verifyChain(vector('chain-stripped-signature'), {
      publicKeys: KEYRING,
      requireSignatures: true,
    });
    expect(r.valid).toBe(false);
  });

  it('hashes and linkage are untouched — only the proof of authorship is gone', () => {
    const r = verifyChain(vector('chain-stripped-signature'), { publicKeys: KEYRING });
    expect(r.events[0].hashValid).toBe(true);
    expect(r.events[0].linkageValid).toBe(true);
    // Which is exactly why the hash chain alone cannot carry this claim: a
    // stripped chain is internally consistent and still unattributable.
  });

  it('does not confuse a legitimately unsigned chain with a stripped one', () => {
    const r = verifyChain(vector('chain-valid-unsigned'), { publicKeys: KEYRING });
    expect(r.valid).toBe(true);
    expect(r.signaturesStripped).toBe(0);
    expect(r.events.every((e) => e.signature === 'absent')).toBe(true);
  });
});

describe('chain-verify: signature domain (RFC-0002 erratum)', () => {
  it('flags a signature made over eventHash instead of the canonical bytes', () => {
    const r = verifyChain(vector('chain-signature-domain-mismatch'), {
      publicKeys: KEYRING,
    });
    expect(r.valid).toBe(false);
    expect(r.events[0].signature).toBe('domain-mismatch');
    expect(r.events[0].problem).toMatch(/signer and verifier disagree/);
  });

  it('accepts that same chain when told the signature covers eventHash', () => {
    const r = verifyChain(vector('chain-signature-domain-mismatch'), {
      publicKeys: KEYRING,
      signatureDomain: 'eventHash',
    });
    expect(r.valid).toBe(true);
    expect(r.signaturesValid).toBe(4);
  });
});

describe('chain-verify: fail-closed posture', () => {
  it('an empty chain is never a valid verification', () => {
    const r = verifyChain([]);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/empty/);
  });

  it('a non-array input is rejected rather than coerced', () => {
    const r = verifyChain({ events: [] });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/must be a JSON array/);
  });

  it('a present signature with no supplied key is counted, never assumed good', () => {
    const r = verifyChain(vector('chain-valid-signed'));
    expect(r.signaturesUnverified).toBe(4);
    expect(r.signaturesValid).toBe(0);
    expect(r.events[0].signature).toBe('unverified');
  });

  it('requireSignatures turns an unverifiable signature into an invalid chain', () => {
    const r = verifyChain(vector('chain-valid-signed'), { requireSignatures: true });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/verified signature/);
  });

  it('requireSignatures rejects an unsigned chain instead of vacuously passing it', () => {
    // The flag says "require signatures". A chain with none must fail it,
    // even though that same chain is legitimately valid without the flag.
    const r = verifyChain(vector('chain-valid-unsigned'), { requireSignatures: true });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/only 0 of 4/);
    expect(verifyChain(vector('chain-valid-unsigned')).valid).toBe(true);
  });

  it('a malformed public key is a hard error, not a skipped check', () => {
    const r = verifyChain(vector('chain-valid-signed'), {
      publicKeys: { [keys.signer]: 'not-a-key' },
    });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/unusable/);
  });

  it('an event missing a hashable field breaks the chain rather than hashing around it', () => {
    const chain = vector('chain-valid-signed') as Array<Record<string, unknown>>;
    delete chain[1].occurredAt;
    const r = verifyChain(chain, { publicKeys: KEYRING });
    expect(r.valid).toBe(false);
    expect(r.events[1].problem).toMatch(/missing one of the hashable fields/);
  });
});

describe('chain-verify: canonical serialization agreement', () => {
  it('builds the exact field set RFC-0002 specifies, in sorted order', () => {
    const s = canonicalEventString({
      previousHash: null,
      eventType: 'intent_received',
      agentId: 'agent:x',
      occurredAt: '2026-08-01T12:00:00.000Z',
      payload: { type: 'intent_received' },
    });
    expect(s).toBe(
      '{"agentId":"agent:x","eventType":"intent_received","occurredAt":"2026-08-01T12:00:00.000Z","payload":{"type":"intent_received"},"previousHash":null}',
    );
  });

  it('substitutes the empty string for an absent agentId', () => {
    const s = canonicalEventString({
      previousHash: null,
      eventType: 'component_registered',
      occurredAt: '2026-08-01T12:00:00.000Z',
      payload: { type: 'component_registered' },
    });
    expect(s).toContain('"agentId":""');
  });

  it('is insensitive to input key order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });

  it('accepts a raw hex Ed25519 key and a PEM SPKI key as the same key', () => {
    const fromHex = toEd25519PublicKey(keys.publicKeyHex);
    const pem = fromHex.export({ format: 'pem', type: 'spki' }) as string;
    const fromPem = toEd25519PublicKey(pem);
    expect(fromPem.export({ format: 'der', type: 'spki' })).toEqual(
      fromHex.export({ format: 'der', type: 'spki' }),
    );
  });
});
