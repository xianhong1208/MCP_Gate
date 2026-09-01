import assert from 'node:assert/strict'
import { formatMs, parseServerDate, relativeTimeParts } from '../src/utils/format.js'

// parseServerDate: the backend 'YYYY-MM-DD HH:MM:SS' must parse; garbage input returns null
assert.ok(parseServerDate('2026-08-31 10:00:00') instanceof Date)
assert.equal(parseServerDate(''), null)
assert.equal(parseServerDate(null), null)
assert.equal(parseServerDate('not-a-date'), null)

// relativeTimeParts: verify each bucket boundary with a fixed now (feed Date objects to avoid time zone effects)
const now = new Date('2026-08-31T10:00:00').getTime()
const ago = (seconds) => new Date(now - seconds * 1000)

assert.deepEqual(relativeTimeParts(ago(10), now), { key: 'justNow', n: 10 })
assert.deepEqual(relativeTimeParts(ago(44), now), { key: 'justNow', n: 44 })
assert.deepEqual(relativeTimeParts(ago(45), now), { key: 'minutesAgo', n: 1 })
assert.deepEqual(relativeTimeParts(ago(5 * 60), now), { key: 'minutesAgo', n: 5 })
assert.deepEqual(relativeTimeParts(ago(59 * 60), now), { key: 'minutesAgo', n: 59 })
assert.deepEqual(relativeTimeParts(ago(60 * 60), now), { key: 'hoursAgo', n: 1 })
assert.deepEqual(relativeTimeParts(ago(23 * 3600), now), { key: 'hoursAgo', n: 23 })
assert.deepEqual(relativeTimeParts(ago(24 * 3600), now), { key: 'daysAgo', n: 1 })
assert.deepEqual(relativeTimeParts(ago(3 * 86400), now), { key: 'daysAgo', n: 3 })
// Future times (clock drift) must never yield negatives
assert.deepEqual(relativeTimeParts(new Date(now + 30_000), now), { key: 'justNow', n: 0 })
assert.equal(relativeTimeParts(null, now), null)

// formatMs existing behavior is unchanged
assert.equal(formatMs(842), '842 ms')
assert.equal(formatMs(1500), '1.5 s')

console.log('format.test.mjs ALL PASS')
