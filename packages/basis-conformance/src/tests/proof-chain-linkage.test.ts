// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Proof-chain linkage tests — RFC-0002 §"Chain linkage". The hash
 * chain's load-bearing property is that previousHash[i] = eventHash[i-1]
 * across the whole chain. Verifiers walk the chain and assert this; if
 * any link breaks, the entire downstream chain is suspect.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md §"Verification
 * procedure"
 */

import { describe, it, expect } from 'vitest';

interface ChainEvent {
  eventId: string;
  eventHash: string;
  previousHash: string | null;
}

function verifyChain(events: ReadonlyArray<ChainEvent>): {
  valid: boolean;
  brokenAt?: string;
} {
  if (events.length === 0) return { valid: true };
  if (events[0].previousHash !== null) {
    return { valid: false, brokenAt: events[0].eventId };
  }
  for (let i = 1; i < events.length; i++) {
    if (events[i].previousHash !== events[i - 1].eventHash) {
      return { valid: false, brokenAt: events[i].eventId };
    }
  }
  return { valid: true };
}

describe('proof-chain/linkage: well-formed chains validate', () => {
  it('empty chain is trivially valid', () => {
    const r = verifyChain([]);
    expect(r.valid).toBe(true);
  });

  it('single-event chain with previousHash=null is valid', () => {
    const r = verifyChain([
      { eventId: 'e1', eventHash: 'h1', previousHash: null },
    ]);
    expect(r.valid).toBe(true);
  });

  it('two-event chain with proper linkage is valid', () => {
    const r = verifyChain([
      { eventId: 'e1', eventHash: 'h1', previousHash: null },
      { eventId: 'e2', eventHash: 'h2', previousHash: 'h1' },
    ]);
    expect(r.valid).toBe(true);
  });

  it('long chain (100 events) with proper linkage is valid', () => {
    const events: ChainEvent[] = [];
    for (let i = 0; i < 100; i++) {
      events.push({
        eventId: `e${i}`,
        eventHash: `h${i}`,
        previousHash: i === 0 ? null : `h${i - 1}`,
      });
    }
    const r = verifyChain(events);
    expect(r.valid).toBe(true);
  });
});

describe('proof-chain/linkage: broken chains are detected', () => {
  it('chain head with non-null previousHash fails at head', () => {
    const r = verifyChain([
      { eventId: 'e1', eventHash: 'h1', previousHash: 'h0' },
    ]);
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe('e1');
  });

  it('mid-chain link mismatch fails at first broken event', () => {
    const r = verifyChain([
      { eventId: 'e1', eventHash: 'h1', previousHash: null },
      { eventId: 'e2', eventHash: 'h2', previousHash: 'h1' },
      { eventId: 'e3', eventHash: 'h3', previousHash: 'WRONG' },
      { eventId: 'e4', eventHash: 'h4', previousHash: 'h3' },
    ]);
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe('e3');
  });

  it('out-of-order events (swapped 2 and 3) detected', () => {
    const r = verifyChain([
      { eventId: 'e1', eventHash: 'h1', previousHash: null },
      { eventId: 'e3', eventHash: 'h3', previousHash: 'h2' },
      { eventId: 'e2', eventHash: 'h2', previousHash: 'h1' },
    ]);
    expect(r.valid).toBe(false);
    // First broken position is e3 (its previousHash 'h2' != prior event's 'h1')
    expect(r.brokenAt).toBe('e3');
  });

  it('duplicated event (same hash twice in a row) detected', () => {
    const r = verifyChain([
      { eventId: 'e1', eventHash: 'h1', previousHash: null },
      { eventId: 'e2', eventHash: 'h2', previousHash: 'h1' },
      // Duplicate of e2 — its previousHash 'h1' should be 'h2'
      { eventId: 'e2-dup', eventHash: 'h2', previousHash: 'h1' },
    ]);
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe('e2-dup');
  });
});
