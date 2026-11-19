// Layer 8: PII detection (opt-in via config.layers.pii)

import type { Match, RedactionContext, LayerResult } from "../types.js"
import { buildMarkerCache, isInsideMarker } from "./shared.js"

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g
const PHONE_DE_RE = /\b(?:\+49|0)\s?[\d\s\-/()]{8,}\d\b/g
const PHONE_E164_RE = /\+[1-9]\d{1,14}\b/g
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g
const CREDIT_CARD_RE = /\b(?:\d[ -]?){13,19}\b/g
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g
const IBAN_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g

function isLuhnValid(digits: string): boolean {
  const d = digits.replace(/\D/g, "")
  if (d.length < 13 || d.length > 19) return false
  let sum = 0
  let alt = false
  for (let i = d.length - 1; i >= 0; i--) {
    let n = parseInt(d[i], 10)
    if (alt) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alt = !alt
  }
  return sum % 10 === 0
}

function textContainsAny(text: string, needles: string[]): boolean {
  for (let i = 0; i < needles.length; i++) {
    if (text.indexOf(needles[i]) !== -1) return true
  }
  return false
}

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = []
  const markerCache = buildMarkerCache(text)

  if (text.indexOf("@") !== -1) pushAll(text, EMAIL_RE, matches, "Email", markerCache)
  if (text.indexOf("+") !== -1) pushAll(text, PHONE_E164_RE, matches, "Phone", markerCache)
  pushAll(text, PHONE_DE_RE, matches, "Phone", markerCache)
  pushAll(text, IPV4_RE, matches, "IPv4", markerCache)

  if (
    textContainsAny(text, ["000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999"]) ||
    /[\d]{6,}/.test(text)
  ) {
    pushAll(text, CREDIT_CARD_RE, matches, "Credit Card", markerCache, (value) => {
      const digits = value.replace(/\D/g, "")
      return digits.length >= 13 && isLuhnValid(digits)
    })
  }

  if (
    textContainsAny(text, ["000-00-", "111-11-", "222-22-", "333-33-", "444-44-", "555-55-", "666-66-", "777-77-", "888-88-", "999-99-"]) ||
    /[\d]{3}-\d{2}-/.test(text)
  ) {
    pushAll(text, SSN_RE, matches, "SSN", markerCache)
  }

  if (/[A-Z]{2}\d{2}[A-Z0-9]{4,}/.test(text)) {
    pushAll(text, IBAN_RE, matches, "IBAN", markerCache)
  }

  void ctx
  return { matches }
}

function pushAll(
  text: string,
  pattern: RegExp,
  matches: Match[],
  type: string,
  markerCache: ReturnType<typeof buildMarkerCache>,
  validator?: (value: string) => boolean,
) {
  pattern.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = pattern.exec(text)) !== null) {
    const start = m.index
    const end = start + m[0].length
    if (isInsideMarker(markerCache, start, end)) continue
    if (matchesOverlapExisting(matches, start, end)) continue
    if (validator && !validator(m[0])) continue
    matches.push({
      start,
      end,
      type,
      replacement: `[REDACTED:${type}]`,
    })
  }
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true
  }
  return false
}
