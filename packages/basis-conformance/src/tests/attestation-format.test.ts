// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Attestation format tests — RFC-0003 §"The attestation document".
 * Validates the strict JSON Schema in schemas/attestation-v1.json
 * against canonical valid + invalid samples.
 *
 * Spec reference: rfcs/0003-conformance-attestation.md
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = resolve(
  here,
  '..',
  '..',
  '..',
  '..',
  'schemas',
  'attestation-v1.json',
);
const schema = JSON.parse(readFileSync(schemaPath, 'utf-8'));

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(schema);

const validAttestation = {
  attestationVersion: 1,
  product: 'Cognigate',
  version: '0.1.0',
  releasedAt: '2026-04-25T14:30:00Z',
  conformanceSuite: {
    name: '@vorionsys/basis-conformance',
    version: '0.1.0',
    revision: '1a2b3c4d5e6f78',
  },
  results: {
    passed: 50,
    failed: 0,
    skipped: 2,
    total: 52,
  },
  signature: 'a'.repeat(86),
  signedBy: 'did:web:vorion.org#release-2026',
  signedAt: '2026-04-25T14:35:00Z',
};

describe('attestation/schema: valid documents pass', () => {
  it('canonical valid attestation passes', () => {
    const ok = validate(validAttestation);
    expect(ok).toBe(true);
  });

  it('attestation with optional details passes', () => {
    const ok = validate({
      ...validAttestation,
      results: {
        ...validAttestation.results,
        details: [
          { id: 'tier-transition.t0-t1', status: 'passed', durationMs: 12 },
          {
            id: 'shadow-mode.hitl-required',
            status: 'skipped',
            reason: 'feature flag off',
          },
        ],
      },
    });
    expect(ok).toBe(true);
  });

  it('third-party attestation with vendorAttestation passes', () => {
    const ok = validate({
      ...validAttestation,
      thirdParty: true,
      vendorAttestation: 'https://cognigate.dev/attestations/cognigate-0.1.0.json',
    });
    expect(ok).toBe(true);
  });

  it('revocation with required fields passes', () => {
    const ok = validate({
      ...validAttestation,
      revoked: true,
      revokedAt: '2026-05-12T09:00:00Z',
      revokedReason: 'CVE-2026-12345',
    });
    expect(ok).toBe(true);
  });
});

describe('attestation/schema: malformed documents fail', () => {
  it('missing required field fails', () => {
    const { signature: _drop, ...without } = validAttestation;
    expect(validate(without)).toBe(false);
  });

  it('attestationVersion not equal to 1 fails', () => {
    expect(
      validate({ ...validAttestation, attestationVersion: 2 }),
    ).toBe(false);
  });

  it('non-semver version fails', () => {
    expect(validate({ ...validAttestation, version: 'one' })).toBe(false);
  });

  it('non-ISO releasedAt fails', () => {
    expect(
      validate({ ...validAttestation, releasedAt: '2026-04-25 14:30' }),
    ).toBe(false);
  });

  it('signature with non-base64url chars fails', () => {
    expect(
      validate({ ...validAttestation, signature: 'not!base64url!' }),
    ).toBe(false);
  });

  it('thirdParty=true WITHOUT vendorAttestation fails', () => {
    expect(
      validate({ ...validAttestation, thirdParty: true }),
    ).toBe(false);
  });

  it('revoked=true WITHOUT revokedAt+revokedReason fails', () => {
    expect(validate({ ...validAttestation, revoked: true })).toBe(false);
  });

  it('extra unknown field fails (additionalProperties=false)', () => {
    expect(
      validate({ ...validAttestation, vendorSecretSauce: 'no' }),
    ).toBe(false);
  });
});
