// Layer 1: Structured vendor patterns (API keys, tokens, credentials)

import type { Match, RedactionContext, LayerResult } from "../types.js"
import { buildMarker, buildMarkerCache, isInsideMarker, isInsidePathContext } from "./shared.js"

interface Pattern {
  name: string
  prefix: string
  tail: RegExp
  wordBoundary: boolean
}

const PATTERNS: Pattern[] = [
  { name: "AWS Access Key", prefix: "AKIA", tail: /^AKIA[A-Z0-9]{16}\b/, wordBoundary: true },
  { name: "AWS Temp Access Key", prefix: "ASIA", tail: /^ASIA[A-Z0-9]{16}\b/, wordBoundary: true },
  {
    name: "AWS Secret Key",
    prefix: "secret_access_key",
    tail: /^(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret_access_key|SecretAccessKey)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40,}["']?/,
    wordBoundary: true,
  },
  { name: "Bearer Token", prefix: "Bearer", tail: /^Bearer\s+[a-zA-Z0-9._\-]{20,}\b/, wordBoundary: true },
  { name: "OpenAI/Anthropic API Key", prefix: "sk-", tail: /^sk-[a-zA-Z0-9._\-]{20,}\b/, wordBoundary: true },
  { name: "Stripe Live Key", prefix: "sk_live_", tail: /^sk_live_[a-zA-Z0-9]{20,}\b/, wordBoundary: true },
  { name: "Stripe Test Key", prefix: "sk_test_", tail: /^sk_test_[a-zA-Z0-9]{20,}\b/, wordBoundary: true },
  {
    name: "Hetzner Token",
    prefix: "TOKEN",
    tail: /^(?:HCLOUD_TOKEN|hcloud_token|token)\s*[:=]\s*["']?[a-f0-9]{64}\b/i,
    wordBoundary: false,
  },
  { name: "GitHub Token", prefix: "gh", tail: /^gh[pousr]_[a-zA-Z0-9]{36,}\b/, wordBoundary: true },
  { name: "GitHub Fine-grained PAT", prefix: "github_pat_", tail: /^github_pat_[a-zA-Z0-9_]{20,}\b/, wordBoundary: true },
  { name: "JWT", prefix: "eyJ", tail: /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, wordBoundary: true },
  { name: "Slack Token", prefix: "xoxb-", tail: /^xox[baprs]-[A-Za-z0-9-]{20,}\b/, wordBoundary: true },
  { name: "GitLab Token", prefix: "glpat-", tail: /^glpat-[A-Za-z0-9_\-]{20,}\b/, wordBoundary: true },
  { name: "Google API Key", prefix: "AIza", tail: /^AIza[A-Za-z0-9_\-]{35}\b/, wordBoundary: true },
  { name: "npm Token", prefix: "npm_", tail: /^npm_[A-Za-z0-9]{36,}\b/, wordBoundary: true },
  { name: "SendGrid API Key", prefix: "SG.", tail: /^SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{32,}\b/, wordBoundary: true },
  { name: "Tavily API Key", prefix: "tvly-", tail: /^tvly-[a-zA-Z0-9_\-]{20,}\b/, wordBoundary: true },
  { name: "Brave API Key", prefix: "BSA", tail: /^BSA[A-Z0-9]{20,}\b/, wordBoundary: true },
  { name: "Firecrawl API Key", prefix: "fc-", tail: /^fc-[a-f0-9]{32}\b/, wordBoundary: true },
]

const TELEGRAM_BOT_TOKEN_RE = /\b\d{5,20}:[A-Za-z0-9_-]{35}\b/g
const IONOS_API_TOKEN_RE = /\b[a-f0-9]{32}\.[A-Za-z0-9_-]{32,100}\b/g

function isWordChar(c: string): boolean {
  const code = c.charCodeAt(0)
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f
  )
}

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = []
  const allowlist = compileAllowlist(ctx.config.allowlistRegex)
  const markerCache = buildMarkerCache(text)

  for (const { name, prefix, tail, wordBoundary } of PATTERNS) {
    let idx = 0
    while (idx < text.length) {
      const found = text.indexOf(prefix, idx)
      if (found === -1) break

      if (wordBoundary) {
        const prev = found > 0 ? text.charCodeAt(found - 1) : -1
        if (prev !== -1 && isWordChar(String.fromCharCode(prev))) {
          idx = found + 1
          continue
        }
      }

      const window = text.slice(found, Math.min(text.length, found + 96))
      const m = tail.exec(window)
      if (!m) {
        idx = found + 1
        continue
      }

      const start = found
      const end = found + m[0].length
      if (isInsideMarker(markerCache, start, end)) { idx = end; continue }
      if (matchesOverlapExisting(matches, start, end)) { idx = end; continue }
      if (allowlist.test(m[0])) { idx = end; continue }
      if (isInsidePathContext(text, start, end)) { idx = end; continue }

      matches.push({
        start,
        end,
        type: name,
        replacement: buildMarker(m[0], name, ctx.config.preservePrefixChars, ctx.config.asterisksMax),
      })
      idx = end
    }
  }

  // Telegram Bot Token — no fixed literal prefix, dedicated scan.
  TELEGRAM_BOT_TOKEN_RE.lastIndex = 0
  let tm: RegExpExecArray | null
  while ((tm = TELEGRAM_BOT_TOKEN_RE.exec(text)) !== null) {
    const start = tm.index
    const end = start + tm[0].length
    if (isInsideMarker(markerCache, start, end)) continue
    if (matchesOverlapExisting(matches, start, end)) continue
    if (isInsidePathContext(text, start, end)) continue
    matches.push({
      start,
      end,
      type: "Telegram Bot Token",
      replacement: buildMarker(tm[0], "Telegram Bot Token", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
    })
  }

  // IONOS API Token — no fixed literal prefix, dedicated scan.
  IONOS_API_TOKEN_RE.lastIndex = 0
  let im: RegExpExecArray | null
  while ((im = IONOS_API_TOKEN_RE.exec(text)) !== null) {
    const start = im.index
    const end = start + im[0].length
    if (isInsideMarker(markerCache, start, end)) continue
    if (matchesOverlapExisting(matches, start, end)) continue
    if (isInsidePathContext(text, start, end)) continue
    matches.push({
      start,
      end,
      type: "IONOS API Token",
      replacement: buildMarker(im[0], "IONOS API Token", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
    })
  }

  return { matches }
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true
  }
  return false
}

function compileAllowlist(patterns: string[]): RegExp {
  if (patterns.length === 0) return /(?!)/
  try {
    return new RegExp(patterns.join("|"), "g")
  } catch {
    return /(?!)/
  }
}
