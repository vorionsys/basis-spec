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
import { verifyChain, type VerifyChainOptions } from './chain-verifier.js';
import { SUITE_VERSION } from './suite-meta.js';

const HELP = `basis-conformance — BASIS conformance test suite

Usage:
  basis-conformance run [options]            Run the suite, print results JSON to stdout
  basis-conformance validate <manifest.json> Structurally validate an external proof-chain manifest
  basis-conformance verify <chain.json>      Cryptographically verify a proof chain (RFC-0002)
  basis-conformance --version                Print suite version
  basis-conformance --help                   This message

Options for 'run':
  --out PATH        Write the results JSON to PATH instead of stdout
  --cwd DIR         Run vitest in DIR (default: this package's own install
                    directory, where the shipped test vectors live)
  --pretty          Pretty-print the JSON output (default: compact)

Options for 'validate':
  --pretty          Pretty-print the JSON output (default: compact)

Options for 'verify':
  --keys PATH       JSON map of signedBy identity -> Ed25519 public key
                    (PEM SPKI, 64-char hex, or base64 of the raw 32 bytes).
                    A { "signer": ..., "publicKeyHex": ... } object is also
                    accepted for single-signer chains.
  --require-signatures  Require that EVERY event carry a signature that
                    verified. Unverifiable, stripped and absent signatures
                    all fail. (Before 0.3.0 this covered only the
                    unverifiable case, so a chain with no signatures at
                    all passed it.)
  --signature-domain canonical|eventHash
                    Which message the detached signature covers.
                    Default: canonical (RFC-0002 §"Verification procedure").
  --pretty          Pretty-print the JSON output (default: compact)

'validate' is TRUTH-ONLY: it reports structural facts (missing/malformed
RFC-0002 fields) and does NOT emit any trust, compliance, or conformance
verdict, nor verify signatures or recompute the hash chain.

'verify' DOES do the cryptography: it recomputes each event's canonical
bytes and sha256 (plus sha3-256 when present), walks previousHash linkage
from a null head, and checks detached Ed25519 signatures. It reports on the
INTEGRITY OF THE RECORD only — a chain that verifies has not been altered,
which is not a claim that the agent behaved well.

An event that names a signer in signedBy but carries no signature is
reported as STRIPPED and always fails, with or without
--require-signatures: deleting a field must not downgrade a signed chain
into an "unsigned" one. A chain carrying neither field is a legitimately
unsigned chain and still verifies on hashes and linkage alone.

Exit codes:
  0  All tests passed (at least one test ran) / manifest structurally well-formed
     / chain verified
  1  One or more tests failed / manifest has structural errors / chain did
     not verify
  2  Runner error (could not invoke vitest, ZERO tests discovered,
     could not read/parse the manifest or keys, etc.)

FAIL-CLOSED: a run that discovers zero tests is never a pass — it exits 2.
An empty chain is never a valid verification. A signature that is present
but could not be checked is never silently counted as good.
`;

/**
 * Accepts either a flat { identity: key } map or the single-signer
 * { signer, publicKeyHex } shape the shipped vectors use.
 */
function parseKeyring(raw: unknown): Record<string, string> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('keys file must be a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.signer === 'string' && typeof obj.publicKeyHex === 'string') {
    return { [obj.signer]: obj.publicKeyHex };
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') out[k] = v;
  }
  if (Object.keys(out).length === 0) {
    throw new Error('keys file contained no identity -> key entries');
  }
  return out;
}

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

  if (cmd === 'verify') {
    const pretty = argv.includes('--pretty');
    const positional = argv.slice(1).filter((a, i, all) => {
      if (a.startsWith('--')) return false;
      // Skip values consumed by --keys / --signature-domain.
      const prev = all[i - 1];
      return prev !== '--keys' && prev !== '--signature-domain';
    });
    const path = positional[0];
    if (!path) {
      process.stderr.write(`verify: missing <chain.json> path\n\n${HELP}`);
      process.exit(2);
    }

    let chain: unknown;
    try {
      chain = JSON.parse(readFileSync(path, 'utf-8'));
    } catch (err) {
      process.stderr.write(
        `verify: could not read/parse ${path}: ${(err as Error).message}\n`,
      );
      process.exit(2);
    }

    const opts: { -readonly [K in keyof VerifyChainOptions]: VerifyChainOptions[K] } = {};

    const keysIdx = argv.indexOf('--keys');
    if (keysIdx >= 0) {
      const keysPath = argv[keysIdx + 1];
      if (!keysPath || keysPath.startsWith('--')) {
        process.stderr.write('verify: --keys requires a PATH\n');
        process.exit(2);
      }
      try {
        opts.publicKeys = parseKeyring(JSON.parse(readFileSync(keysPath, 'utf-8')));
      } catch (err) {
        process.stderr.write(
          `verify: could not read/parse keys ${keysPath}: ${(err as Error).message}\n`,
        );
        process.exit(2);
      }
    }

    const domIdx = argv.indexOf('--signature-domain');
    if (domIdx >= 0) {
      const dom = argv[domIdx + 1];
      if (dom !== 'canonical' && dom !== 'eventHash') {
        process.stderr.write(
          "verify: --signature-domain must be 'canonical' or 'eventHash'\n",
        );
        process.exit(2);
      }
      opts.signatureDomain = dom;
    }

    if (argv.includes('--require-signatures')) opts.requireSignatures = true;

    const report = verifyChain(chain, opts);
    process.stdout.write(
      (pretty ? JSON.stringify(report, null, 2) : JSON.stringify(report)) + '\n',
    );

    // A stripped signature is the finding, not a footnote — say so in plain
    // words on stderr, because a caller scanning output for "valid":false
    // still deserves to know WHY without parsing the per-event array.
    if (report.signaturesStripped > 0) {
      process.stderr.write(
        `WARNING: ${report.signaturesStripped} event(s) name a signer in signedBy but carry no signature. ` +
          'This is a stripped chain, not an unsigned one — the hashes still ' +
          'agree, so the record is internally consistent and entirely ' +
          'unattributable. Treat it as tampering.\n',
      );
    }

    // Never let a present-but-unchecked signature pass by unremarked, even
    // when the caller did not ask for strict mode.
    if (report.signaturesUnverified > 0 && !opts.requireSignatures) {
      process.stderr.write(
        `note: ${report.signaturesUnverified} event(s) carry a signature that was NOT verified ` +
          '(no public key supplied). Hash and linkage integrity were checked; signer provenance was not. ' +
          'Pass --keys to check it, or --require-signatures to make this a failure.\n',
      );
    }

    process.exit(report.valid ? 0 : 1);
  }

  if (cmd !== 'run') {
    process.stderr.write(`unknown subcommand: ${cmd}\n\n${HELP}`);
    process.exit(2);
  }

  const outIdx = argv.indexOf('--out');
  const cwdIdx = argv.indexOf('--cwd');
  const out = outIdx >= 0 ? argv[outIdx + 1] : null;
  // No --cwd -> let the runner default to the package's own install
  // directory (where the shipped test vectors live).
  const cwd = cwdIdx >= 0 ? argv[cwdIdx + 1] : undefined;
  const pretty = argv.includes('--pretty');

  let results;
  try {
    results = await runConformance(cwd ? { cwd } : {});
  } catch (err) {
    process.stderr.write(`runner error: ${(err as Error).message}\n`);
    process.exit(2);
  }

  // Defense in depth: the runner already rejects on zero discovered
  // tests, but never let an empty run masquerade as a pass here either.
  if (results.total === 0) {
    process.stderr.write(
      'runner error: conformance suite discovered 0 tests — refusing to report success (fail-closed)\n',
    );
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
