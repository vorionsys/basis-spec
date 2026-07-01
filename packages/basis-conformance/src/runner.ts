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

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SUITE_NAME,
  SUITE_VERSION,
  SUITE_REVISION,
  SUITE_SOURCE,
} from './suite-meta.js';

/**
 * Root of the installed conformance package (one level up from the
 * compiled dist/ this module lives in) — where the shipped test vectors
 * (src/tests) and vitest.config.ts live. This is the default vitest cwd
 * so `npx basis-conformance run` works from anywhere.
 */
const SUITE_PACKAGE_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '..',
);

/**
 * Locate the vitest CLI entry point by resolving the `vitest` package
 * from THIS module (vitest is a runtime dependency of this package), so
 * the suite runs offline with the exact vitest version we installed.
 * Falls back to `npx vitest` only if resolution fails.
 */
function resolveVitestCommand(): {
  readonly command: string;
  readonly args: ReadonlyArray<string>;
  readonly shell: boolean;
} {
  try {
    const require = createRequire(import.meta.url);
    const pkgJsonPath = require.resolve('vitest/package.json');
    const pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf-8')) as {
      bin?: string | Record<string, string>;
    };
    const binRel = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.['vitest'];
    if (binRel) {
      return {
        command: process.execPath,
        args: [join(dirname(pkgJsonPath), binRel)],
        shell: false,
      };
    }
  } catch {
    // fall through to npx
  }
  return { command: 'npx', args: ['vitest'], shell: true };
}

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
 * `options.cwd` defaults to this package's own install directory, where
 * the shipped test vectors and vitest.config.ts live.
 *
 * FAIL-CLOSED: if the run discovers zero tests, the returned promise
 * REJECTS — zero discovered tests is never a passing result.
 *
 * For inline use (where spawning is awkward), call `runConformanceFromVitestJson`
 * with a pre-collected vitest JSON output.
 */
export async function runConformance(options: {
  readonly cwd?: string;
} = {}): Promise<ConformanceResults> {
  const { spawn } = await import('node:child_process');
  const cwd = options.cwd ?? SUITE_PACKAGE_ROOT;
  const startedAt = new Date().toISOString();
  const vitest = resolveVitestCommand();

  return new Promise<ConformanceResults>((resolvePromise, reject) => {
    const child = spawn(
      vitest.command,
      [...vitest.args, 'run', '--reporter=json'],
      { cwd, shell: vitest.shell },
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
        const results = reshape(parsed, startedAt);
        if (results.total === 0) {
          // FAIL CLOSED: zero discovered tests must never look like a
          // passing run (e.g. vectors missing from an installation, or
          // a --cwd that does not contain the suite).
          reject(
            new Error(
              'conformance suite discovered 0 tests — refusing to report success (fail-closed). ' +
                `The test vectors are missing from this installation or the working directory (${cwd}) does not contain the suite.`,
            ),
          );
          return;
        }
        resolvePromise(results);
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
