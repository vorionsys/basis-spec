// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Test helpers — small builders for proof-event chains.
 *
 * These construct events with the EXACT field shapes from
 * @vorionsys/basis-spec proof-chain.ts. Timestamps are passed explicitly so
 * tests are deterministic and never touch wall-clock.
 *
 * NOTE: timestamp arithmetic here uses `Date` purely to GENERATE fixture
 * `occurredAt` strings for the test inputs. The SCORER never uses `Date`;
 * it parses these strings with its own deterministic nanosecond parser.
 */

import type { ProofEvent, ProofEventType } from '@vorionsys/basis-spec';

let seq = 0;
/** Stable, monotonic eventId generator for fixtures. */
export function nextId(prefix = 'e'): string {
  seq += 1;
  return `${prefix}-${String(seq).padStart(6, '0')}`;
}

export function resetSeq(): void {
  seq = 0;
}

export function makeEvent(
  eventType: ProofEventType,
  payload: Record<string, unknown>,
  occurredAt: string,
  eventId: string,
  extra: Partial<ProofEvent> = {},
): ProofEvent {
  return {
    eventId,
    eventType,
    correlationId: 'corr-1',
    agentId: 'agent-1',
    payload: payload as ProofEvent['payload'],
    previousHash: null,
    eventHash: `hash-${eventId}`,
    occurredAt,
    recordedAt: occurredAt,
    ...extra,
  };
}

/** ISO string `offsetMs` after `baseIso`, using Date ONLY for fixture gen. */
export function isoOffset(baseIso: string, offsetMs: number): string {
  return new Date(Date.parse(baseIso) + offsetMs).toISOString();
}

let cycleSeq = 0;
export function resetCycleSeq(): void {
  cycleSeq = 0;
}

/**
 * A full intent->decision->started->(completed|failed) cycle for one action.
 * Returns the four events with monotonically increasing occurredAt offsets
 * from `baseIso`.
 */
export function actionCycle(opts: {
  actionType: string;
  baseIso: string;
  outcome: 'success' | 'partial' | 'fail';
  shadowMode?: ProofEvent['shadowMode'];
}): ProofEvent[] {
  cycleSeq += 1;
  const tag = String(cycleSeq).padStart(6, '0');
  const intentId = `i-${tag}`;
  const decisionId = `d-${tag}`;
  const executionId = `x-${tag}`;
  const sm = opts.shadowMode ? { shadowMode: opts.shadowMode } : {};

  const events: ProofEvent[] = [
    makeEvent(
      'intent_received',
      { type: 'intent_received', intentId, action: 'act', actionType: opts.actionType, resourceScope: [] },
      isoOffset(opts.baseIso, 0),
      `${intentId}-evt`,
      sm,
    ),
    makeEvent(
      'decision_made',
      { type: 'decision_made', decisionId, intentId, permitted: true, trustBand: 'T0', trustScore: 0, reasoning: [] },
      isoOffset(opts.baseIso, 1000),
      `${decisionId}-evt`,
      sm,
    ),
    makeEvent(
      'execution_started',
      { type: 'execution_started', executionId, actionId: 'act-id', decisionId, adapterId: 'adapter-1' },
      isoOffset(opts.baseIso, 2000),
      `${executionId}-start`,
      sm,
    ),
  ];

  if (opts.outcome === 'fail') {
    events.push(
      makeEvent(
        'execution_failed',
        { type: 'execution_failed', executionId, actionId: 'act-id', error: 'boom', durationMs: 1, retryable: false },
        isoOffset(opts.baseIso, 3000),
        `${executionId}-fail`,
        sm,
      ),
    );
  } else {
    events.push(
      makeEvent(
        'execution_completed',
        { type: 'execution_completed', executionId, actionId: 'act-id', status: opts.outcome, durationMs: 1, outputHash: 'out' },
        isoOffset(opts.baseIso, 3000),
        `${executionId}-complete`,
        sm,
      ),
    );
  }
  return events;
}
