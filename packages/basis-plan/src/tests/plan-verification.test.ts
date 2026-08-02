// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-0006 plan verification tests.
 *
 * The tests that matter most are the ones no amount of per-action gating or
 * sampled testing would pass: composition, sequencing, and branch coverage.
 * Plus two regressions for solver behaviours that produce a FALSE SAFE, which
 * is the only direction this tool must never fail in.
 */

import { describe, it, expect } from 'vitest';
import { encodePlan, PlanEncodingError } from '../encode.js';
import { verifyPlan, verifyEncoded } from '../verify.js';
import type { ExecutionPlan } from '../types.js';

// Z3 is a WASM module and cold start is slow.
const TIMEOUT = 60_000;

const transferStep = (id: string, amount: number, guard?: ExecutionPlan['steps'][number]['guard']) => ({
  stepId: id,
  actionType: 'payment.transfer',
  resourceScope: ['acct:treasury'],
  riskLevel: 'HIGH' as const,
  effects: [{ kind: 'accumulate' as const, counter: 'daily_transferred', amount }],
  ...(guard ? { guard } : {}),
});

const DAILY_LIMIT = {
  kind: 'bound' as const,
  id: 'daily-transfer-limit',
  counter: 'daily_transferred',
  op: '<=' as const,
  limit: 100,
};

// ---------------------------------------------------------------------------

describe('plan verification: composition', () => {
  it(
    'catches transfers that are individually legal but collectively over the limit',
    async () => {
      // This is the attack a per-action gate cannot see: every step passes its
      // own check; only the sum violates.
      const plan: ExecutionPlan = {
        planId: 'p-composition',
        steps: [
          transferStep('t1', 30),
          transferStep('t2', 30),
          transferStep('t3', 30),
          transferStep('t4', 30),
        ],
        edges: [
          { from: 't1', to: 't2' },
          { from: 't2', to: 't3' },
          { from: 't3', to: 't4' },
        ],
        invariants: [DAILY_LIMIT],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('counterexample');
      expect(r.verification.result).toBe('sat');
      expect(r.violated).toContain('daily-transfer-limit');
      expect(r.verification.model).toBeTypeOf('string');
    },
    TIMEOUT,
  );

  it(
    'proves a plan safe when the sum stays within the limit',
    async () => {
      const plan: ExecutionPlan = {
        planId: 'p-safe',
        steps: [transferStep('t1', 30), transferStep('t2', 40)],
        edges: [{ from: 't1', to: 't2' }],
        invariants: [DAILY_LIMIT],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('proved_safe');
      expect(r.verification.result).toBe('unsat');
      expect(r.invariantsChecked).toEqual(['daily-transfer-limit']);
    },
    TIMEOUT,
  );
});

describe('plan verification: branch coverage', () => {
  it(
    'finds a violation that only occurs on a conditional branch',
    async () => {
      // The common path is safe; the violation hides behind a guard. Sampled
      // testing that never took the branch would report this plan as fine.
      // Symbolic verification covers both branches at once.
      const plan: ExecutionPlan = {
        planId: 'p-branch',
        steps: [
          transferStep('base', 50),
          transferStep('escalated', 60, { kind: 'var', name: 'retry_path' }),
        ],
        edges: [{ from: 'base', to: 'escalated' }],
        invariants: [DAILY_LIMIT],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('counterexample');
      expect(r.violated).toContain('daily-transfer-limit');
      // The counterexample must name the branch it took.
      expect(r.verification.model).toContain('retry_path');
    },
    TIMEOUT,
  );

  it(
    'proves safety when every branch stays within bounds',
    async () => {
      const plan: ExecutionPlan = {
        planId: 'p-branch-safe',
        steps: [
          transferStep('base', 30),
          transferStep('escalated', 40, { kind: 'var', name: 'retry_path' }),
        ],
        edges: [{ from: 'base', to: 'escalated' }],
        invariants: [DAILY_LIMIT],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('proved_safe');
    },
    TIMEOUT,
  );
});

describe('plan verification: sequencing and taint', () => {
  it(
    'catches read-restricted-then-write-external',
    async () => {
      // Each step is individually permitted. The COMBINATION is exfiltration.
      const plan: ExecutionPlan = {
        planId: 'p-exfil',
        steps: [
          {
            stepId: 'read-pii',
            actionType: 'db.read',
            resourceScope: ['db:restricted.customers'],
            effects: [
              { kind: 'access', mode: 'read', resource: 'db:restricted.customers' },
            ],
          },
          {
            stepId: 'post-external',
            actionType: 'http.post',
            resourceScope: ['https://external.example/ingest'],
            effects: [
              { kind: 'access', mode: 'write', resource: 'net:external' },
            ],
          },
        ],
        edges: [{ from: 'read-pii', to: 'post-external' }],
        invariants: [
          {
            kind: 'never_after',
            id: 'no-external-write-after-restricted-read',
            before: 'read-pii',
            after: 'post-external',
          },
        ],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('counterexample');
      expect(r.violated).toContain('no-external-write-after-restricted-read');
    },
    TIMEOUT,
  );

  it(
    'catches a forbidden resource touched on any path',
    async () => {
      const plan: ExecutionPlan = {
        planId: 'p-forbid',
        steps: [
          {
            stepId: 'cleanup',
            actionType: 'db.schema.destructive',
            resourceScope: ['db:production.customer_ledger'],
            riskLevel: 'LIFE_CRITICAL',
            effects: [
              { kind: 'access', mode: 'delete', resource: 'db:production.customer_ledger' },
            ],
            guard: { kind: 'var', name: 'cleanup_enabled' },
          },
        ],
        edges: [],
        invariants: [
          {
            kind: 'forbid',
            id: 'never-delete-the-ledger',
            mode: 'delete',
            resource: 'db:production.customer_ledger',
          },
        ],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('counterexample');
      expect(r.violated).toContain('never-delete-the-ledger');
    },
    TIMEOUT,
  );
});

describe('plan verification: symbolic amounts', () => {
  it(
    'cannot prove a bound over an UNBOUNDED symbol, and says so',
    async () => {
      // This is correct behaviour, not a defect: you genuinely cannot prove a
      // limit over a quantity you never constrained.
      const plan: ExecutionPlan = {
        planId: 'p-unbounded',
        steps: [
          {
            stepId: 't1',
            actionType: 'payment.transfer',
            resourceScope: ['acct:treasury'],
            effects: [
              { kind: 'accumulate', counter: 'daily_transferred', amount: 'invoice_total' },
            ],
          },
        ],
        edges: [],
        invariants: [DAILY_LIMIT],
        symbols: [{ name: 'invoice_total' }],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('counterexample');
    },
    TIMEOUT,
  );

  it(
    'proves safety once the symbol is bounded',
    async () => {
      const plan: ExecutionPlan = {
        planId: 'p-bounded',
        steps: [
          {
            stepId: 't1',
            actionType: 'payment.transfer',
            resourceScope: ['acct:treasury'],
            effects: [
              { kind: 'accumulate', counter: 'daily_transferred', amount: 'invoice_total' },
            ],
          },
        ],
        edges: [],
        invariants: [DAILY_LIMIT],
        symbols: [{ name: 'invoice_total', min: 0, max: 80 }],
      };

      const r = await verifyPlan(plan);
      expect(r.outcome).toBe('proved_safe');
    },
    TIMEOUT,
  );
});

describe('plan verification: fail-closed and encoder guards', () => {
  it('rejects a cyclic plan rather than approximating it', () => {
    const plan: ExecutionPlan = {
      planId: 'p-cycle',
      steps: [transferStep('a', 1), transferStep('b', 1)],
      edges: [
        { from: 'a', to: 'b' },
        { from: 'b', to: 'a' },
      ],
      invariants: [DAILY_LIMIT],
    };
    expect(() => encodePlan(plan)).toThrow(PlanEncodingError);
    expect(() => encodePlan(plan)).toThrow(/cycle/);
  });

  it('refuses a plan with no invariants — a verdict with nothing checked is unfalsifiable', () => {
    const plan: ExecutionPlan = {
      planId: 'p-empty',
      steps: [transferStep('a', 1)],
      edges: [],
      invariants: [],
    };
    expect(() => encodePlan(plan)).toThrow(/unfalsifiable/);
  });

  it('rejects duplicate step ids', () => {
    const plan: ExecutionPlan = {
      planId: 'p-dup',
      steps: [transferStep('a', 1), transferStep('a', 2)],
      edges: [],
      invariants: [DAILY_LIMIT],
    };
    expect(() => encodePlan(plan)).toThrow(/duplicate stepIds/);
  });

  it('rejects an effect referencing an undeclared symbol', () => {
    const plan: ExecutionPlan = {
      planId: 'p-undeclared',
      steps: [
        {
          stepId: 'a',
          actionType: 'x',
          resourceScope: [],
          effects: [{ kind: 'accumulate', counter: 'c', amount: 'ghost' }],
        },
      ],
      edges: [],
      invariants: [{ kind: 'bound', id: 'b', counter: 'c', op: '<=', limit: 1 }],
    };
    expect(() => encodePlan(plan)).toThrow(/not declared in plan.symbols/);
  });

  it(
    'TRAP 2 REGRESSION: a malformed program is inconclusive, never a result',
    async () => {
      // z3 emits `(error ...)` and then CONTINUES, printing a result derived
      // from whatever it parsed — observed printing `sat` after erroring. Any
      // error must force inconclusive, which denies.
      const broken = {
        smtlib2: '(set-logic QF_LIA)\n(assert (bogus))\n(check-sat)\n',
        logic: 'QF_LIA',
        invariantIds: ['x'],
        violationClauses: [{ id: 'x', clause: 'true' }],
      };

      const r = await verifyEncoded('p-broken', broken);
      expect(r.outcome).toBe('inconclusive');
      expect(r.verification.result).toBe('unknown');
      expect(r.verification.diagnostic).toMatch(/error/i);
    },
    TIMEOUT,
  );
});

describe('plan verification: reproducibility', () => {
  const plan: ExecutionPlan = {
    planId: 'p-repro',
    steps: [transferStep('t1', 30), transferStep('t2', 40)],
    edges: [{ from: 't1', to: 't2' }],
    invariants: [DAILY_LIMIT],
  };

  it('encodes deterministically — same plan, byte-identical program', () => {
    const a = encodePlan(plan);
    const b = encodePlan(plan);
    expect(a.smtlib2).toBe(b.smtlib2);
  });

  it('is insensitive to declaration order in the input', () => {
    const reordered: ExecutionPlan = {
      ...plan,
      steps: [plan.steps[1]!, plan.steps[0]!],
    };
    expect(encodePlan(reordered).smtlib2).toBe(encodePlan(plan).smtlib2);
  });

  it(
    'publishes a re-runnable artifact and records the solver identity',
    async () => {
      const r = await verifyPlan(plan);
      expect(r.verification.smtlib2).toContain('(check-sat)');
      expect(r.verification.smtlib2).toContain('(set-option :random-seed 0)');
      expect(r.verification.smtlib2Hash).toMatch(/^[0-9a-f]{64}$/);
      expect(r.verification.solver.name).toBe('z3');
      expect(r.verification.solver.version).toBeTruthy();
      expect(r.verification.solver.seed).toBe('0');
    },
    TIMEOUT,
  );

  it(
    'TRAP 1 REGRESSION: alternating plans stay correct across solves',
    async () => {
      // The Z3 context leaks declarations and set-logic between programs. With
      // a shared context, a genuinely VIOLATING plan was observed reporting
      // `unsat` — a false safe — purely from the previous solve's state. Each
      // solve therefore runs in a fresh context. This alternation is the
      // regression: interleaving is what surfaces the leak.
      const violating: ExecutionPlan = {
        planId: 'p-violating',
        steps: [transferStep('t1', 60), transferStep('t2', 70)],
        edges: [{ from: 't1', to: 't2' }],
        invariants: [DAILY_LIMIT],
      };

      const outcomes: string[] = [];
      for (const p of [plan, violating, plan, violating]) {
        outcomes.push((await verifyPlan(p)).outcome);
      }
      expect(outcomes).toEqual([
        'proved_safe',
        'counterexample',
        'proved_safe',
        'counterexample',
      ]);
    },
    TIMEOUT,
  );
});
