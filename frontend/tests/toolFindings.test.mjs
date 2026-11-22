/**
 * Tool poisoning scan (#34): ordering, counting and highlighting the findings on the approval card.
 */
import assert from 'node:assert/strict'
import {
  countBySeverity, excerptSegments, fieldOf, groupByRule, hasHigh, highlightSegments, needlesFor, sortFindings,
  plainText, toolsNeedingConfirm,
} from '../src/utils/toolFindings.js'

const F = (rule, severity, path, match, excerpt = match) => ({ rule, severity, path, match, excerpt })
const findings = [
  F('url', 'info', 'description', 'https://example.com'),
  F('instruction-phrase', 'high', 'description', 'Ignore previous instructions'),
  F('url', 'high', 'inputSchema.properties.to.default', 'http://198.51.100.4/c'),
  F('tool-mention', 'warning', 'description', 'send_message'),
]

assert.deepEqual(sortFindings(findings).map((f) => f.severity), ['high', 'high', 'warning', 'info'])
assert.deepEqual(countBySeverity(findings), { high: 2, warning: 1, info: 1 })
assert.equal(hasHigh(findings), true)
assert.equal(hasHigh([findings[0]]), false)
assert.deepEqual(groupByRule(findings).map((g) => [g.rule, g.severity, g.findings.length]),
  [['instruction-phrase', 'high', 1], ['url', 'high', 2], ['tool-mention', 'warning', 1]])
assert.equal(fieldOf('inputSchema.properties.to.default'), 'inputSchema')
assert.equal(fieldOf('annotations[0]'), 'annotations')

// needles are per field; schema needles also come JSON-escaped (the diff shows schemas as JSON)
assert.deepEqual(needlesFor(findings, 'inputSchema'), ['http://198.51.100.4/c'])
assert.deepEqual(needlesFor([F('x', 'high', 'inputSchema.a', 'say "hi"')], 'inputSchema'), ['say "hi"', 'say \\"hi\\"'])
assert.deepEqual(needlesFor([F('x', 'high', 'description', 'line one\nline two')], 'description'), ['line one', 'line two'])

// highlighting marks the needle and makes every invisible character its own visible segment
const segs = highlightSegments('a\u200bIgnore previous instructions!', ['Ignore previous instructions'])
assert.deepEqual(segs.map((s) => [s.text, !!s.mark, s.invisible || null]), [
  ['a', false, null], ['\u200b', false, 'U+200B'], ['Ignore previous instructions', true, null], ['!', false, null],
])
const tag = String.fromCodePoint(0xE0041)
assert.deepEqual(highlightSegments(`x${tag}y`).map((s) => s.invisible || s.text), ['x', 'U+E0041', 'y'])
// an emoji is not invisible
assert.deepEqual(highlightSegments('ok 👍').map((s) => s.text), ['ok 👍'])

// API excerpts carry <U+XXXX> already
assert.deepEqual(excerptSegments('a<U+200B><U+E0041>b'), [
  { text: 'a' }, { text: '', invisible: 'U+200B' }, { text: '', invisible: 'U+E0041' }, { text: 'b' },
])

// approving asks first only for a definition with a high finding; warning and info stay one click
const tools = [
  { name: 'a', findings: [findings[0]] },
  { name: 'b', findings: [findings[3]] },
  { name: 'c', findings: [findings[1], findings[0]] },
  { name: 'd' },
]
assert.deepEqual(toolsNeedingConfirm(tools).map((t) => t.name), ['c'])
assert.deepEqual(toolsNeedingConfirm([]), [])
assert.equal(plainText('I\u200bg\u200bn  o\nre'), 'Ign o re')
console.log('ok   toolFindings: order, counts, highlighting, confirm')
