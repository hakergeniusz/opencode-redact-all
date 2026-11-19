// Layer 4: Shannon-entropy heuristic for high-entropy tokens

import type { Match, RedactionContext, LayerResult } from "../types.js"
import { buildMarker, buildMarkerCache, isInsideMarker, isInsidePathContext } from "./shared.js"

export function shannonEntropy(str: string): number {
  const n = str.length
  if (n === 0) return 0
  const freq = new Int32Array(128)
  for (let i = 0; i < n; i++) {
    const c = str.charCodeAt(i)
    if (c < 128) freq[c]++
  }
  let h = 0
  for (let i = 0; i < 128; i++) {
    const count = freq[i]
    if (count === 0) continue
    const p = count / n
    h -= p * Math.log2(p)
  }
  return h
}

function classifyChars(value: string): { hex: boolean; base64: boolean } {
  let hex = true
  let base64 = true
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    if (c >= 0x30 && c <= 0x39) continue
    if (c >= 0x41 && c <= 0x46) continue
    if (c >= 0x61 && c <= 0x66) continue
    if (c >= 0x47 && c <= 0x5a) { hex = false; continue }
    if (c >= 0x67 && c <= 0x7a) { hex = false; continue }
    if (c === 0x2b || c === 0x2f || c === 0x3d) { hex = false; continue }
    return { hex: false, base64: false }
  }
  return { hex, base64 }
}

const TOKEN_RE = /\b[A-Za-z0-9+/\-_]{20,}\b/g

const ALLOWLIST_DEFAULT_PATTERNS = [
  /\b[0-9a-f]{7,40}\b.*?(?:commit|sha)/i,
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i,
  /\bv?\d+\.\d+\.\d+(?:-[\w.]+)?\b/,
]

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = []
  const minEntropy = ctx.config.minEntropy
  const minLength = ctx.config.minLength

  const userPatterns = ctx.config.allowlistRegex
    .map((p) => { try { return new RegExp(p) } catch { return null } })
    .filter((p): p is RegExp => p !== null)
  const allowlistPatterns = [...ALLOWLIST_DEFAULT_PATTERNS, ...userPatterns]

  const markerCache = buildMarkerCache(text)

  TOKEN_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = TOKEN_RE.exec(text)) !== null) {
    const value = m[0]
    const start = m.index
    const end = start + value.length

    if (value.length < minLength) continue
    if (isInsideMarker(markerCache, start, end)) continue

    const cls = classifyChars(value)
    if (!cls.hex && !cls.base64) continue

    let allowed = false
    for (let p = 0; p < allowlistPatterns.length; p++) {
      if (allowlistPatterns[p].test(value)) { allowed = true; break }
    }
    if (allowed) continue

    const entropy = shannonEntropy(value)
    if (entropy < minEntropy) continue
    if (isInsidePathContext(text, start, end)) continue

    matches.push({
      start,
      end,
      type: "High Entropy Token",
      replacement: buildMarker(value, "High Entropy Token", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
    })
  }

  return { matches }
}
