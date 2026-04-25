// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Proof-event shape test — RFC-0002 §"Schema". Every well-formed event
 * MUST validate; every malformed event MUST fail with a clear path.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

import { describe, it, expect } from 'vitest';
import { ProofEventSchema } from '@basis-spec/basis/zod';

const validEvent = {
  eventId: '11111111-2222-3333-4444-555555555555',
  eventType: 'decision_made',
  correlationId: 'corr-001',
  agentId: 'agt-abc',
  payload: {
    type: 'decision_made',
    decisionId: 'dec-001',
    intentId: 'int-001',
    permitted: true,
    trustBand: 'T4',
    trustScore: 612,
    reasoning: ['within tier'],
  },
  previousHash: null as string | null,
  eventHash:
    'a'.repeat(64),
  occurredAt: '2026-04-25T12:00:00Z',
  recordedAt: '2026-04-25T12:00:01Z',
};

describe('proof-event/shape: well-formed events validate', () => {
  it('canonical decision_made event passes', () => {
    const r = ProofEventSchema.safeParse(validEvent);
    expect(r.success).toBe(true);
  });

  it('chain head with previousHash: null is valid', () => {
    const r = ProofEventSchema.safeParse({ ...validEvent, previousHash: null });
    expect(r.success).toBe(true);
  });

  it('non-head event with valid previousHash is valid', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      previousHash: 'b'.repeat(64),
    });
    expect(r.success).toBe(true);
  });

  it('optional eventHash3 (sha3-256 dual anchor) accepted', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      eventHash3: 'c'.repeat(64),
    });
    expect(r.success).toBe(true);
  });

  it('shadowMode=production explicit value is valid', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      shadowMode: 'production',
    });
    expect(r.success).toBe(true);
  });
});

describe('proof-event/shape: malformed events fail', () => {
  it('missing eventId fails', () => {
    const { eventId: _drop, ...without } = validEvent;
    const r = ProofEventSchema.safeParse(without);
    expect(r.success).toBe(false);
  });

  it('eventHash with wrong length fails', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      eventHash: 'short',
    });
    expect(r.success).toBe(false);
  });

  it('eventHash with uppercase hex fails (canonical = lowercase)', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      eventHash: 'A'.repeat(64),
    });
    expect(r.success).toBe(false);
  });

  it('unknown eventType fails', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      eventType: 'made_up_event',
    });
    expect(r.success).toBe(false);
  });

  it('payload.type mismatch with eventType fails refine', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      eventType: 'intent_received',
      // payload still says decision_made → mismatch
    });
    expect(r.success).toBe(false);
  });

  it('non-ISO occurredAt fails', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      occurredAt: '2026-04-25 12:00:00',
    });
    expect(r.success).toBe(false);
  });
});

describe('proof-event/shape: shadow-mode HITL refine', () => {
  it('shadowMode=verified WITHOUT verificationId fails', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      shadowMode: 'verified',
    });
    expect(r.success).toBe(false);
  });

  it('shadowMode=rejected WITHOUT verificationId fails', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      shadowMode: 'rejected',
    });
    expect(r.success).toBe(false);
  });

  it('shadowMode=verified WITH verificationId + verifiedAt passes', () => {
    const r = ProofEventSchema.safeParse({
      ...validEvent,
      shadowMode: 'verified',
      verificationId: 'hitl-001',
      verifiedAt: '2026-04-25T13:00:00Z',
    });
    expect(r.success).toBe(true);
  });
});
