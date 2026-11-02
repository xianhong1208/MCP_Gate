#!/usr/bin/env node
/**
 * Copy the project version from pyproject.toml into frontend/package.json.
 *
 * pyproject.toml's [project].version is the only place a release bumps the
 * version. This script runs as `prebuild` (and by hand via `npm run
 * sync-version`) so package.json never drifts from it. The console itself
 * shows the version it gets from the backend at runtime; this only keeps the
 * package metadata honest.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const TAG = '[sync-version]'
const frontendDir = join(dirname(fileURLToPath(import.meta.url)), '..')
const files = {
  pyproject: join(frontendDir, '..', 'pyproject.toml'),
  packageJson: join(frontendDir, 'package.json'),
}

/**
 * Return the `version = "..."` value from the [project] table, or null.
 * A full TOML parser is overkill for one key: walk the lines, track which
 * table we are in, and stop at the first version key inside [project].
 */
function projectVersion(toml) {
  let table = null
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.trim()
    const header = line.match(/^\[([^\]]+)\]$/)
    if (header) {
      table = header[1].trim()
      continue
    }
    if (table !== 'project') continue
    const kv = line.match(/^version\s*=\s*(["'])(.+?)\1/)
    if (kv) return kv[2]
  }
  return null
}

const version = projectVersion(readFileSync(files.pyproject, 'utf-8'))
if (version === null) {
  // Not fatal: leave package.json alone rather than break the build.
  console.warn(`${TAG} no [project].version in pyproject.toml; package.json left unchanged`)
  process.exit(0)
}

const pkg = JSON.parse(readFileSync(files.packageJson, 'utf-8'))
if (pkg.version === version) {
  console.log(`${TAG} package.json already at ${version}`)
} else {
  const previous = pkg.version
  pkg.version = version
  writeFileSync(files.packageJson, `${JSON.stringify(pkg, null, 2)}\n`, 'utf-8')
  console.log(`${TAG} package.json ${previous} -> ${version} (from pyproject.toml)`)
}
