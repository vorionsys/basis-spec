#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * CLI for @vorionsys/basis-spec-conformance.
 *
 * Subcommands:
 *
 *   basis-conformance run [--out PATH] [--cwd DIR]
 *     Runs the suite via vitest, reshapes results into RFC-0003
 *     `results` shape, prints to stdout (and optionally writes to file).
 *
 *   basis-conformance validate <manifest.json> [--pretty]
 *     Truth-only structural check of an external proof-chain manifest
 *     against RFC-0002 (required-field presence + basic shape). Prints
 *     { valid, errors } JSON. Emits NO trust/compliance verdict and does
 *     NOT verify signatures or hash linkage.
 *
 *   basis-conformance --help
 *     Shows usage.
 *
 *   basis-conformance --version
 *     Prints suite version.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { runConformance } from './runner.js';
import { validateManifest } from './manifest-validator.js';
import { SUITE_VERSION } from './suite-meta.js';

const HELP = `basis-conformance — BASIS conformance test suite

Usage:
  basis-conformance run [options]            Run the suite, print results JSON to stdout
  basis-conformance validate <manifest.json> Structurally validate an external proof-chain manifest
  basis-conformance --version                Print suite version
  basis-conformance --help                   This message

Options for 'run':
  --out PATH        Write the results JSON to PATH instead of stdout
  --cwd DIR         Run vitest in DIR (default: current directory)
  --pretty          Pretty-print the JSON output (default: compact)

Options for 'validate':
  --pretty          Pretty-print the JSON output (default: compact)

'validate' is TRUTH-ONLY: it reports structural facts (missing/malformed
RFC-0002 fields) and does NOT emit any trust, compliance, or conformance
verdict, nor verify signatures or recompute the hash chain.

Exit codes:
  0  All tests passed / manifest structurally well-formed
  1  One or more tests failed / manifest has structural errors
  2  Runner error (could not invoke vitest, read/parse the manifest, etc.)
`;

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(HELP);
    process.exit(0);
  }
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write(`${SUITE_VERSION}\n`);
    process.exit(0);
  }

  const cmd = argv[0];

  if (cmd === 'validate') {
    const pretty = argv.includes('--pretty');
    const path = argv.slice(1).find((a) => !a.startsWith('--'));
    if (!path) {
      process.stderr.write(`validate: missing <manifest.json> path\n\n${HELP}`);
      process.exit(2);
    }
    let manifest: unknown;
    try {
      manifest = JSON.parse(readFileSync(path, 'utf-8'));
    } catch (err) {
      process.stderr.write(
        `validate: could not read/parse ${path}: ${(err as Error).message}\n`,
      );
      process.exit(2);
    }
    const result = validateManifest(manifest);
    process.stdout.write(
      (pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)) + '\n',
    );
    process.exit(result.valid ? 0 : 1);
  }

  if (cmd !== 'run') {
    process.stderr.write(`unknown subcommand: ${cmd}\n\n${HELP}`);
    process.exit(2);
  }

  const outIdx = argv.indexOf('--out');
  const cwdIdx = argv.indexOf('--cwd');
  const out = outIdx >= 0 ? argv[outIdx + 1] : null;
  const cwd = cwdIdx >= 0 ? argv[cwdIdx + 1] : process.cwd();
  const pretty = argv.includes('--pretty');

  let results;
  try {
    results = await runConformance({ cwd });
  } catch (err) {
    process.stderr.write(`runner error: ${(err as Error).message}\n`);
    process.exit(2);
  }

  const json = pretty
    ? JSON.stringify(results, null, 2)
    : JSON.stringify(results);

  if (out) {
    writeFileSync(out, json + '\n', 'utf-8');
    process.stderr.write(
      `wrote ${results.total} test results to ${out}\n` +
        `  passed: ${results.passed}\n` +
        `  failed: ${results.failed}\n` +
        `  skipped: ${results.skipped}\n`,
    );
  } else {
    process.stdout.write(json + '\n');
  }

  process.exit(results.failed > 0 ? 1 : 0);
}

void main();
