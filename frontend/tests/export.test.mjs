import assert from 'node:assert/strict'
import { csvCell, toCSV } from '../src/utils/export.js'

// Formula triggers (OWASP CSV injection) are neutralised with a leading apostrophe
for (const payload of ['=HYPERLINK("http://evil.example","x")', '+1+1', '-2+3', '@SUM(A1:A2)', '\t=1', '\r=1']) {
  const cell = csvCell(payload)
  assert.ok(cell.startsWith(`"'`), `not neutralised: ${JSON.stringify(payload)} -> ${cell}`)
}
assert.equal(csvCell('=1+1'), `"'=1+1"`)

// Quoting still works, including on neutralised cells
assert.equal(csvCell('say "hi"'), '"say ""hi"""')
assert.equal(csvCell('=A1&"x"'), `"'=A1&""x"""`)
assert.equal(csvCell('line1\nline2'), '"line1\nline2"')

// Ordinary values are untouched; numbers stay numeric (a negative count is not a formula)
assert.equal(csvCell('alice@example.com'), '"alice@example.com"')
assert.equal(csvCell('a-b'), '"a-b"')
assert.equal(csvCell(-1), '"-1"')
assert.equal(csvCell(0), '"0"')
assert.equal(csvCell(null), '""')
assert.equal(csvCell(undefined), '""')

// toCSV: header + rows, every cell goes through csvCell
const csv = toCSV(
  [{ actor: '=cmd|"/c calc"!A1', n: 3 }, { actor: 'owner', n: -2 }],
  [{ label: 'Actor', accessor: (r) => r.actor }, { label: 'Count', accessor: (r) => r.n }],
)
assert.equal(csv, `"Actor","Count"\n"'=cmd|""/c calc""!A1","3"\n"owner","-2"`)
assert.equal(toCSV([], []), '')

console.log('export.test.mjs ALL PASS')
