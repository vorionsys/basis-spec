// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * The two-sided vector contract — vectors/expected.json.
 *
 * Every other test in this suite asserts behaviour we wrote in TypeScript.
 * This one asserts the DECLARED contract that ships next to the vectors, so
 * an independent implementation can hold itself to the same bar without ever
 * opening our source.
 *
 * The point is the reject REASON, not the reject. Two verifiers can agree a
 * chain is bad while disagreeing entirely about what is wrong with it, and
 * that agreement is worth nothing. `failureCode` is what makes "reject"
 * testable against a stated reason rather than a bare boolean.
 *
 * If this file and vectors/expected.json ever disagree, expected.json is the
 * published artifact and wins.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyChain } from '../chain-verifier.js';

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'vectors');

interface Outcome {
  valid: boolean;
  exitCode: number;
  failureCode?: string;
  signature?: string;
  hashValid?: boolean;
  linkageValid?: boolean;
}

interface Declared {
  file: string;
  intent: string;
  default: Outcome;
  requireSignatures: Outcome;
}

const contract = JSON.parse(readFileSync(join(VECTORS, 'expected.json'), 'utf-8')) as {
  vectors: Declared[];
};

const keys = JSON.parse(readFileSync(join(VECTORS, 'keys.json'), 'utf-8')) as {
  signer: string;
  publicKeyHex: string;
};
const KEYRING = { [keys.signer]: keys.publicKeyHex };

const load = (file: string): unknown => JSON.parse(readFileSync(join(VECTORS, file), 'utf-8'));

describe('vectors/expected.json is the compared contract', () => {
  it('declares every chain vector that ships, and no phantom ones', () => {
    const onDisk = readdirSync(VECTORS)
      .filter((f) => f.startsWith('chain-') && f.endsWith('.json'))
      .sort();
    const declared = contract.vectors.map((v) => v.file).sort();
    // A vector shipping without a declared outcome is exactly the hole this
    // file exists to close, so it is a failure, not a warning.
    expect(declared).toEqual(onDisk);
  });

  for (const v of contract.vectors) {
    describe(`${v.file} — ${v.intent}`, () => {
      it('matches its declared default outcome', () => {
        const r = verifyChain(load(v.file), { publicKeys: KEYRING });
        expect(r.valid).toBe(v.default.valid);
        if (v.default.failureCode) {
          expect(r.failureCode).toBe(v.default.failureCode);
        } else {
          expect(r.failureCode).toBeUndefined();
        }
        // Where the contract pins per-event detail, hold it to that too: this
        // is how "integrity intact, attribution broken" stays inspectable.
        const broken = r.brokenAt ? r.events.find((e) => e.eventId === r.brokenAt) : r.events[0];
        if (v.default.signature) expect(broken?.signature).toBe(v.default.signature);
        if (v.default.hashValid !== undefined) expect(broken?.hashValid).toBe(v.default.hashValid);
        if (v.default.linkageValid !== undefined) {
          expect(broken?.linkageValid).toBe(v.default.linkageValid);
        }
      });

      it('matches its declared outcome under --require-signatures', () => {
        const r = verifyChain(load(v.file), { publicKeys: KEYRING, requireSignatures: true });
        expect(r.valid).toBe(v.requireSignatures.valid);
        if (v.requireSignatures.failureCode) {
          expect(r.failureCode).toBe(v.requireSignatures.failureCode);
        } else {
          expect(r.failureCode).toBeUndefined();
        }
      });

      it('declares an exit code consistent with validity', () => {
        // The CLI contract: 0 verified, 1 failed, 2 could not run.
        expect(v.default.exitCode).toBe(v.default.valid ? 0 : 1);
        expect(v.requireSignatures.exitCode).toBe(v.requireSignatures.valid ? 0 : 1);
      });
    });
  }
});

describe('failure codes are machine-readable, not prose', () => {
  it('never reports a code on a chain it accepted', () => {
    const r = verifyChain(load('chain-valid-signed.json'), { publicKeys: KEYRING });
    expect(r.valid).toBe(true);
    expect(r.failureCode).toBeUndefined();
  });

  it('pairs every event problem with a code', () => {
    // Prose without a code would be a reason a consumer cannot compare on.
    for (const v of contract.vectors) {
      const r = verifyChain(load(v.file), { publicKeys: KEYRING });
      for (const e of r.events) {
        if (e.problem !== undefined) {
          expect(e.failureCode, `${v.file} event ${e.index} has prose but no code`).toBeDefined();
        }
      }
    }
  });

  it('says where AND why together when a chain breaks at an event', () => {
    const r = verifyChain(load('chain-stripped-signature.json'), { publicKeys: KEYRING });
    expect(r.brokenAt).toBeDefined();
    expect(r.failureCode).toBe('SIGNATURE_STRIPPED');
    const broken = r.events.find((e) => e.eventId === r.brokenAt);
    expect(broken?.failureCode).toBe(r.failureCode);
  });

  it('distinguishes a strict-mode shortfall from any single event fault', () => {
    // Nothing is wrong with any event in an unsigned chain. The refusal is the
    // chain's, so it must not be attributed to an event.
    const r = verifyChain(load('chain-valid-unsigned.json'), {
      publicKeys: KEYRING,
      requireSignatures: true,
    });
    expect(r.valid).toBe(false);
    expect(r.failureCode).toBe('SIGNATURES_REQUIRED_SHORTFALL');
    expect(r.brokenAt).toBeUndefined();
    expect(r.events.every((e) => e.failureCode === undefined)).toBe(true);
  });
});
