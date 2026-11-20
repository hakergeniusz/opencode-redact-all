// Shared utilities for layer implementations

import type { Match } from "../types.js"

/**
 * Build a redaction marker like: `AKIA****************[REDACTED:AWS Access Key]`
 * Preserves a short prefix for context, fills middle with asterisks, appends marker.
 */
export function buildMarker(value: string, type: string, preservePrefixChars = 4, asterisksMax = 20): string {
  const trimmed = value.replace(/^[\s"']+|[\s"']+$/g, "")
  const prefix = trimmed.slice(0, preservePrefixChars)
  const stars = "*".repeat(Math.min(asterisksMax, Math.max(8, trimmed.length - preservePrefixChars)))
  return `${prefix}${stars}[REDACTED:${type}]`
}

const FILE_EXT_RE = /\.[a-z0-9]{1,6}(?=[^a-z0-9]|$)/i

/**
 * Detects whether the [start, end) span in `text` is sitting inside a path-like
 * context. Loose on purpose: better to skip a suspicious token in a filename
 * than to corrupt a legitimate path.
 */
export function isInsidePathContext(text: string, start: number, end: number): boolean {
  const before = text.slice(Math.max(0, start - 60), start)
  const rawAfter = text.slice(end, Math.min(text.length, end + 80))
  const after = rawAfter.replace(/\[REDACTED[^\]]*\]/g, " ").trimStart()

  const lastChar = start > 0 ? text[start - 1] : ""
  if (lastChar === "/" || lastChar === "\\") return true

  if (after.length > 0 && /[\\/]/.test(after.slice(0, 20))) return true

  if (after.length > 0 && FILE_EXT_RE.test(after)) return true
  const tailWithinMatch = text.slice(Math.max(0, end - 7), end)
  if (/\.[a-z0-9]{1,6}$/i.test(tailWithinMatch)) return true

  if (/(?:path|file|filename|filepath|dir|loc|tgt|target)\s*:\s*$/i.test(before)) return true
  if (/\b(?:to|from|save|write|create|store|in|at|via|using)\s+$/i.test(before)) return true
  if (/<\s*\/?\s*(?:path|file|filename|filepath)\s*>\s*$/i.test(before)) return true
  if (/data:[a-z0-9.\/+-]+;base64,?$/i.test(before)) return true

  return false
}

export interface MarkerCache {
  spans: [number, number][]
  markerSpans: [number, number][]
}

export function buildMarkerCache(text: string): MarkerCache {
  const spans: [number, number][] = []
  const markerSpans: [number, number][] = []
  const re = /\[REDACTED[^\]]*\]/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const markerStart = m.index
    const markerEnd = m.index + m[0].length
    markerSpans.push([markerStart, markerEnd])
    spans.push([markerStart, markerEnd])
  }
  return { spans, markerSpans }
}

/** O(log n) check: is the [start, end) span inside any cached marker? */
export function isInsideMarker(cache: MarkerCache, start: number, end: number): boolean {
  const spans = cache.spans
  let lo = 0
  let hi = spans.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (spans[mid][1] <= start) lo = mid + 1
    else hi = mid
  }
  if (lo < spans.length && spans[lo][0] < end && spans[lo][1] > start) return true
  if (lo > 0 && spans[lo - 1][0] < end && spans[lo - 1][1] > start) return true
  return false
}

/**
 * Apply matches to text. All other whitespace, newlines and structure stay
 * 1:1 — only matched spans are replaced. O(n + m) via array parts + join.
 */
export function applyMatches(text: string, matches: Match[]): string {
  if (matches.length === 0) return text
  matches.sort((a, b) => a.start - b.start)
  const filtered: Match[] = new Array(matches.length)
  let fLen = 0
  let lastEnd = -1
  for (let i = 0; i < matches.length; i++) {
    const m = matches[i]
    if (m.start >= lastEnd) {
      filtered[fLen++] = m
      lastEnd = m.end
    }
  }
  const parts: string[] = new Array(fLen * 2 + 1)
  let cursor = 0
  let p = 0
  for (let i = 0; i < fLen; i++) {
    const m = filtered[i]
    if (m.start > cursor) parts[p++] = text.slice(cursor, m.start)
    parts[p++] = m.replacement
    cursor = m.end
  }
  if (cursor < text.length) parts[p++] = text.slice(cursor)
  if (p < parts.length) parts.length = p
  return parts.join("")
}

/** Check whether the span overlaps any existing marker (slow, legacy helper). */
export function isInsideExistingMarker(text: string, start: number, end: number): boolean {
  let i = start - 1
  while (i >= 0) {
    const c = text[i]
    if (c === "[") {
      const ahead = text.slice(i, i + 9)
      return ahead.startsWith("[REDACTED")
    }
    if (c === "]") return false
    i--
  }
  return false
}

/** O(log n) overlap check against a sorted match list. */
export function hasOverlap(sortedMatches: Match[], start: number, end: number): boolean {
  let lo = 0
  let hi = sortedMatches.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (sortedMatches[mid].end <= start) lo = mid + 1
    else hi = mid
  }
  if (lo < sortedMatches.length) {
    const m = sortedMatches[lo]
    if (start < m.end && end > m.start) return true
  }
  if (lo > 0) {
    const m = sortedMatches[lo - 1]
    if (start < m.end && end > m.start) return true
  }
  return false
}
