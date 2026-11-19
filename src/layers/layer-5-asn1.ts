// Layer 5: ASN.1 SEQUENCE detection (DER base64 starting with MII...)

import type { Match, RedactionContext, LayerResult } from "../types.js"
import { buildMarkerCache, isInsideMarker } from "./shared.js"

const ASN1_RE = /(?:^|\s)(MI[A-Za-z0-9+/=]{100,}={0,2})(?=\s|$)/gm

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = []
  const markerCache = buildMarkerCache(text)

  ASN1_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = ASN1_RE.exec(text)) !== null) {
    const start = m.index + m[0].indexOf(m[1])
    const end = start + m[1].length
    if (isInsideMarker(markerCache, start, end)) continue
    if (matchesOverlapExisting(matches, start, end)) continue

    // Skip if already wrapped in a PEM block (layer 2 catches those).
    const before = text.slice(Math.max(0, start - 200), start)
    if (/-----BEGIN [A-Z ]+-----/.test(before)) continue

    matches.push({
      start,
      end,
      type: "ASN.1 SEQUENCE",
      replacement: "[REDACTED:ASN.1 SEQUENCE]",
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
