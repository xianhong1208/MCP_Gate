import { Fragment } from 'react'
import clsx from 'clsx'

/**
 * Renders the small markdown subset that MCP tool descriptions use (headings, paragraphs, bullet lists,
 * **bold**, `code`) as React elements. No HTML pass-through, so server-supplied text can never inject markup.
 */

function inline(text, keyPrefix) {
  // split on `code` and **bold**, keeping the delimiters' contents
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean)
  return parts.map((part, i) => {
    const key = `${keyPrefix}-${i}`
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={key} className="rounded bg-muted px-1 py-px font-mono text-[11px] text-foreground">{part.slice(1, -1)}</code>
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={key} className="font-semibold text-foreground">{part.slice(2, -2)}</strong>
    }
    return <Fragment key={key}>{part}</Fragment>
  })
}

function parseBlocks(text) {
  const blocks = []
  let paragraph = []
  let list = null
  const flushParagraph = () => {
    if (paragraph.length) blocks.push({ type: 'p', text: paragraph.join(' ') })
    paragraph = []
  }
  const flushList = () => {
    if (list) blocks.push(list)
    list = null
  }
  for (const raw of (text || '').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) { flushParagraph(); flushList(); continue }
    const heading = line.match(/^(#{1,6})\s+(.*)$/)
    if (heading) {
      flushParagraph(); flushList()
      blocks.push({ type: 'h', level: heading[1].length, text: heading[2] })
      continue
    }
    const item = line.match(/^(?:[-*•]|\d+[.)])\s+(.*)$/)
    if (item) {
      flushParagraph()
      if (!list) list = { type: 'ul', items: [] }
      list.items.push(item[1])
      continue
    }
    flushList()
    paragraph.push(line)
  }
  flushParagraph(); flushList()
  return blocks
}

export default function MarkdownLite({ text, className }) {
  const blocks = parseBlocks(text)
  return (
    <div className={clsx('space-y-2 text-xs leading-relaxed text-muted-foreground', className)}>
      {blocks.map((b, i) => {
        if (b.type === 'h') {
          const top = b.level <= 2
          return (
            <p key={i} className={clsx('text-foreground', top ? 'mt-3 text-[13px] font-semibold first:mt-0' : 'mt-2 text-xs font-semibold first:mt-0')}>
              {inline(b.text, `h${i}`)}
            </p>
          )
        }
        if (b.type === 'ul') {
          return (
            <ul key={i} className="space-y-1 pl-4">
              {b.items.map((it, j) => <li key={j} className="list-disc marker:text-subtle-foreground">{inline(it, `li${i}-${j}`)}</li>)}
            </ul>
          )
        }
        return <p key={i}>{inline(b.text, `p${i}`)}</p>
      })}
    </div>
  )
}
