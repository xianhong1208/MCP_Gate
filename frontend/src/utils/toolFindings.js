/**
 * Tool poisoning scan (#34): helpers to show what the server-side scan flagged in a tool definition.
 * The findings come from the API (src/tool_pinning/scan.py); these only order, count and highlight them.
 */

export const SEVERITIES = ['high', 'warning', 'info']

/** Findings ordered most severe first (stable within a severity). */
export function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
}

/** { high, warning, info } counts. */
export function countBySeverity(findings) {
  const counts = { high: 0, warning: 0, info: 0 }
  for (const f of findings || []) if (f.severity in counts) counts[f.severity]++
  return counts
}

export function hasHigh(findings) {
  return (findings || []).some((f) => f.severity === 'high')
}

/** The tools an approval must confirm first: those whose current definition has a high finding. */
export function toolsNeedingConfirm(tools) {
  return (tools || []).filter((tool) => hasHigh(tool.findings))
}

/** The findings grouped by rule, most severe rule first: [{ rule, severity, findings }]. */
export function groupByRule(findings) {
  const groups = new Map()
  for (const f of sortFindings(findings)) {
    if (!groups.has(f.rule)) groups.set(f.rule, { rule: f.rule, severity: f.severity, findings: [] })
    groups.get(f.rule).findings.push(f)
  }
  return [...groups.values()]
}

/** The top-level field a finding's path points into ("inputSchema.properties.x" -> "inputSchema"). */
export function fieldOf(path) {
  return String(path || '').split(/[.[]/)[0]
}

// The characters the scan calls invisible (same set as scan.py): zero-width, bidi controls, tags, fillers
// U+034F (combining grapheme joiner) is matched on its own: inside a character class eslint reads it as a combining mark
const INVISIBLE = /\u034f|[\u00ad\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u3164\ufeff\uffa0]|\uDB40[\uDC00-\uDDEF]/

export function isInvisible(ch) {
  return INVISIBLE.test(ch)
}

/** Text with every invisible character dropped and whitespace collapsed (for one-line summaries). */
export function plainText(text) {
  return Array.from(String(text ?? '')).filter((ch) => !isInvisible(ch)).join('').replace(/\s+/g, ' ').trim()
}

/** "U+200B" for a character (code point, not UTF-16 unit). */
export function codePointLabel(ch) {
  return `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`
}

/**
 * The strings to highlight in a field's diff for its findings: each match (per line, since the diff is per line),
 * and for schema fields also as JSON writes it (quotes and backslashes escaped).
 */
export function needlesFor(findings, field) {
  const out = new Set()
  for (const f of findings || []) {
    if (fieldOf(f.path) !== field || !f.match) continue
    for (const piece of f.match.split('\n')) {
      const p = piece.trim()
      if (p.length < 2) continue
      out.add(p)
      const json = JSON.stringify(p).slice(1, -1)
      if (json !== p) out.add(json)
    }
  }
  return [...out]
}

/**
 * Split text into segments for rendering: { text, mark } where mark = inside one of the needles, and every invisible
 * character as its own segment { text, invisible: 'U+XXXX', mark }. Needles are matched case-sensitively, as given.
 */
export function highlightSegments(text, needles = []) {
  const s = String(text ?? '')
  const marks = new Uint8Array(s.length)
  for (const n of needles) {
    if (!n) continue
    let at = s.indexOf(n)
    while (at !== -1) {
      marks.fill(1, at, at + n.length)
      at = s.indexOf(n, at + n.length)
    }
  }
  const out = []
  let buf = ''
  let bufMark = 0
  const flush = () => {
    if (buf) out.push({ text: buf, mark: bufMark === 1 })
    buf = ''
  }
  for (let i = 0; i < s.length;) {
    const cp = s.codePointAt(i)
    const ch = String.fromCodePoint(cp)
    if (isInvisible(ch)) {
      flush()
      out.push({ text: ch, invisible: codePointLabel(ch), mark: marks[i] === 1 })
    } else {
      if (buf && marks[i] !== bufMark) flush()
      bufMark = marks[i]
      buf += ch
    }
    i += ch.length
  }
  flush()
  return out
}

/** An excerpt from the API, where invisible characters are already written "<U+200B>": split those out. */
export function excerptSegments(excerpt) {
  const out = []
  const re = /<U\+([0-9A-F]{4,6})>/g
  let last = 0
  let m
  const s = String(excerpt ?? '')
  while ((m = re.exec(s)) !== null) {
    if (m.index > last) out.push({ text: s.slice(last, m.index) })
    out.push({ text: '', invisible: `U+${m[1]}` })
    last = m.index + m[0].length
  }
  if (last < s.length) out.push({ text: s.slice(last) })
  return out
}
