/**
 * Frontend i18n key coverage: every t('a.b.c') called with a literal key must exist in both zh-TW and en.
 * A missing key makes i18next render the raw key on screen (e.g. "services.common.refresh");
 * the build does not catch that, only users would -- so we catch it here.
 * Dynamically built keys (t(`x.${y}`)) are out of scope.
 */
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
const zh = JSON.parse(readFileSync(join(root, 'i18n/locales/zh-TW.json'), 'utf8'))
const en = JSON.parse(readFileSync(join(root, 'i18n/locales/en.json'), 'utf8'))

function lookup(dict, key) {
  let node = dict
  for (const part of key.split('.')) {
    if (node === null || typeof node !== 'object' || !(part in node)) return undefined
    node = node[part]
  }
  return node
}

// i18next plurals: t('x.count', { count }) resolves to x.count_one / x.count_other
function has(dict, key) {
  if (lookup(dict, key) !== undefined) return true
  return lookup(dict, `${key}_one`) !== undefined || lookup(dict, `${key}_other`) !== undefined
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) yield* walk(p)
    else if (/\.(jsx?|tsx?)$/.test(name)) yield p
  }
}

const missing = []
let total = 0
for (const file of walk(root)) {
  const src = readFileSync(file, 'utf8')
  for (const m of src.matchAll(/\bt\(\s*'([a-zA-Z0-9_.]+)'/g)) {
    total++
    const key = m[1]
    if (!has(zh, key)) missing.push(`${key} (zh-TW) ← ${file.slice(root.length + 1)}`)
    if (!has(en, key)) missing.push(`${key} (en) ← ${file.slice(root.length + 1)}`)
  }
}
assert.ok(total > 500, `expected to find many t() calls, found ${total}`)
assert.deepEqual(missing, [], `missing i18n keys:\n  ${missing.join('\n  ')}`)
console.log(`i18nKeys.test.mjs ALL PASS (${total} static keys checked)`)
