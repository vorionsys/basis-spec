#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC
//
// Post-compile step, wired into `npm run build` (and therefore into
// `prepublishOnly` and the release workflow's build gate):
//
//   1. Stamps dist/revision.json with the git sha the build was cut from
//      (GITHUB_SHA in CI, `git rev-parse HEAD` locally). If no sha can be
//      determined, any stale stamp is REMOVED so the runtime falls back to
//      'dev-build' instead of reporting somebody else's revision.
//   2. Copies the repo-root schemas/ directory into dist/schemas so the
//      published tarball is self-sufficient — the attestation-format tests
//      load schemas/attestation-v1.json from there when the repo root is
//      not present (i.e., when running from an installed package).
//
// This script is not shipped in the tarball (not in "files"); it only runs
// from a repo checkout, where ../../schemas always exists.

import { execSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = resolve(pkgRoot, 'dist');
mkdirSync(distDir, { recursive: true });

// 1. Revision stamp
let revision = process.env.GITHUB_SHA || null;
if (!revision) {
  try {
    revision =
      execSync('git rev-parse HEAD', {
        cwd: pkgRoot,
        stdio: ['ignore', 'pipe', 'ignore'],
      })
        .toString()
        .trim() || null;
  } catch {
    revision = null;
  }
}

const stampPath = resolve(distDir, 'revision.json');
if (revision) {
  writeFileSync(stampPath, JSON.stringify({ revision }) + '\n', 'utf-8');
  console.log(`prepare-dist: stamped revision ${revision}`);
} else {
  rmSync(stampPath, { force: true });
  console.warn(
    'prepare-dist: no GITHUB_SHA and no git sha available — removed stamp; runtime will report "dev-build"',
  );
}

// 2. Schemas copy (repo root -> dist/schemas)
const schemasSrc = resolve(pkgRoot, '..', '..', 'schemas');
const schemasDest = resolve(distDir, 'schemas');
if (!existsSync(schemasSrc)) {
  console.error(`prepare-dist: schemas directory not found at ${schemasSrc}`);
  process.exit(1);
}
rmSync(schemasDest, { recursive: true, force: true });
cpSync(schemasSrc, schemasDest, { recursive: true });
console.log('prepare-dist: copied schemas/ into dist/schemas');
