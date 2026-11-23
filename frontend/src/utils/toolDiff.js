/**
 * Tool pinning (#32): what changed between the approved version of a tool and the pending one.
 * Both sides are the canonical definitions the hashes cover (MCP field names).
 */

const FIELDS = ['title', 'description', 'inputSchema', 'outputSchema', 'annotations']

/** Line diff (LCS). Returns [{ op: 'same' | 'add' | 'del', text }]. Inputs are capped to keep it cheap. */
export function diffLines(oldText, newText, maxLines = 2000) {
  const a = String(oldText ?? '').split('\n').slice(0, maxLines)
  const b = String(newText ?? '').split('\n').slice(0, maxLines)
  if (oldText == null || oldText === '') a.length = 0
  if (newText == null || newText === '') b.length = 0
  const n = a.length
  const m = b.length
  const lcs = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1])
    }
  }
  const out = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ op: 'same', text: a[i] }); i++; j++ }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ op: 'del', text: a[i] }); i++ }
    else { out.push({ op: 'add', text: b[j] }); j++ }
  }
  while (i < n) out.push({ op: 'del', text: a[i++] })
  while (j < m) out.push({ op: 'add', text: b[j++] })
  return out
}

/** Stable, readable text of one field: strings as they are, objects as sorted, indented JSON. */
export function fieldText(value) {
  if (value == null) return ''
  if (typeof value === 'string') return value
  return JSON.stringify(sortKeys(value), null, 2)
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]))
  }
  return value
}

/** The fields that differ between two definitions, each with its line diff. `before` may be null (a new tool). */
export function toolChanges(before, after) {
  const changes = []
  for (const field of FIELDS) {
    const oldText = fieldText(before?.[field])
    const newText = fieldText(after?.[field])
    if (oldText !== newText) changes.push({ field, lines: diffLines(oldText, newText) })
  }
  return changes
}
