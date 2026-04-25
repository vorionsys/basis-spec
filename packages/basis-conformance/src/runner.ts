// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Programmatic runner — exposes the conformance suite as a function.
 *
 * Most consumers use the CLI (`npx basis-conformance run`) or vitest
 * directly. This entry exists for callers that want to run the suite
 * inline (e.g., a release pipeline that wraps the results into an
 * RFC-0003 attestation document and signs it).
 *
 * v0.1 self-test scope: the function shells out to vitest's programmatic
 * API and returns the parsed JSON output reshaped to the
 * `results` field of an RFC-0003 attestation.
 */

import {
  SUITE_NAME,
  SUITE_VERSION,
  SUITE_REVISION,
  SUITE_SOURCE,
} from './suite-meta.js';

export interface ConformanceTestResult {
  readonly id: string;
  readonly status: 'passed' | 'failed' | 'skipped';
  readonly durationMs?: number;
  readonly reason?: string;
  readonly specRef?: string;
}

export interface ConformanceResults {
  readonly suite: {
    readonly name: typeof SUITE_NAME;
    readonly version: typeof SUITE_VERSION;
    readonly revision: string;
    readonly source: typeof SUITE_SOURCE;
  };
  readonly passed: number;
  readonly failed: number;
  readonly skipped: number;
  readonly total: number;
  readonly details: ReadonlyArray<ConformanceTestResult>;
  readonly startedAt: string;
  readonly finishedAt: string;
}

/**
 * Run the conformance suite programmatically.
 *
 * v0.1 implementation note: vitest's programmatic API requires running
 * inside a vitest context. The simplest cross-environment approach is
 * to spawn `vitest run --reporter=json` as a child process, capture
 * the output, and parse it. That's what `runConformance` does.
 *
 * For inline use (where spawning is awkward), call `runConformanceFromVitestJson`
 * with a pre-collected vitest JSON output.
 */
export async function runConformance(options: {
  readonly cwd?: string;
} = {}): Promise<ConformanceResults> {
  const { spawn } = await import('node:child_process');
  const cwd = options.cwd ?? process.cwd();
  const startedAt = new Date().toISOString();

  return new Promise<ConformanceResults>((resolve, reject) => {
    const child = spawn(
      'npx',
      ['vitest', 'run', '--reporter=json'],
      { cwd, shell: true },
    );
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => {
      stdout += String(d);
    });
    child.stderr?.on('data', (d) => {
      stderr += String(d);
    });
    child.on('close', () => {
      try {
        // vitest's JSON reporter prints a single document. There may be
        // ANSI noise before/after; locate the last `{...}` block.
        const start = stdout.indexOf('{');
        const end = stdout.lastIndexOf('}');
        if (start < 0 || end < 0 || end <= start) {
          reject(
            new Error(
              `could not locate vitest JSON in stdout (stderr: ${stderr.slice(0, 500)})`,
            ),
          );
          return;
        }
        const parsed = JSON.parse(stdout.slice(start, end + 1)) as VitestJson;
        resolve(reshape(parsed, startedAt));
      } catch (err) {
        reject(err);
      }
    });
    child.on('error', reject);
  });
}

interface VitestJson {
  readonly numTotalTests: number;
  readonly numPassedTests: number;
  readonly numFailedTests: number;
  readonly numPendingTests: number;
  readonly testResults: ReadonlyArray<{
    readonly name?: string;
    readonly assertionResults?: ReadonlyArray<{
      readonly fullName?: string;
      readonly title?: string;
      readonly status: string;
      readonly duration?: number;
      readonly failureMessages?: ReadonlyArray<string>;
    }>;
  }>;
}

export function runConformanceFromVitestJson(
  vitestJson: VitestJson,
  startedAt: string = new Date().toISOString(),
): ConformanceResults {
  return reshape(vitestJson, startedAt);
}

function reshape(vitestJson: VitestJson, startedAt: string): ConformanceResults {
  const details: ConformanceTestResult[] = [];
  for (const file of vitestJson.testResults ?? []) {
    for (const t of file.assertionResults ?? []) {
      const id = (t.fullName ?? t.title ?? 'unknown').trim();
      const status = mapStatus(t.status);
      const detail: ConformanceTestResult = {
        id,
        status,
        ...(typeof t.duration === 'number'
          ? { durationMs: t.duration }
          : {}),
        ...(status === 'failed' && t.failureMessages?.length
          ? { reason: t.failureMessages[0].slice(0, 500) }
          : {}),
      };
      details.push(detail);
    }
  }

  return {
    suite: {
      name: SUITE_NAME,
      version: SUITE_VERSION,
      revision: SUITE_REVISION,
      source: SUITE_SOURCE,
    },
    passed: vitestJson.numPassedTests ?? 0,
    failed: vitestJson.numFailedTests ?? 0,
    skipped: vitestJson.numPendingTests ?? 0,
    total: vitestJson.numTotalTests ?? 0,
    details,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

function mapStatus(s: string): 'passed' | 'failed' | 'skipped' {
  switch (s) {
    case 'passed':
      return 'passed';
    case 'failed':
      return 'failed';
    case 'pending':
    case 'skipped':
    case 'todo':
      return 'skipped';
    default:
      return 'failed';
  }
}
