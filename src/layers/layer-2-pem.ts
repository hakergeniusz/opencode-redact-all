// Layer 2: PEM / X.509 / PGP / SSH block detection

import type { Match, RedactionContext, LayerResult } from "../types.js"
import { buildMarkerCache, isInsideMarker } from "./shared.js"

// The label group is broad on purpose; any uppercase-word label is accepted.
const PEM_BLOCK_REGEX = new RegExp(
  `-----BEGIN ([A-Z ]+)-----\\r?\\n([\\s\\S]*?)(?:\\r?\\n-----END \\1-----|$)`,
  "g",
)

/**
 * Track which paths are mid-private-key-block (multi-chunk reads).
 * Used in the tool-result redactor via ctx.partialPrivateKeyPaths.
 */
export function detectPartialKey(text: string, ctx: RedactionContext): Match[] {
  if (ctx.inputPath && ctx.partialPrivateKeyPaths.has(ctx.inputPath)) {
    const beginMatch = /-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.exec(text)
    const endMatch = /-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.exec(text)
    if (!endMatch) {
      return [{
        start: 0,
        end: text.length,
        type: "Private Key Continuation",
        replacement: "[REDACTED:Private Key Continuation]",
      }]
    } else if (beginMatch) {
      return [{
        start: beginMatch.index,
        end: endMatch.index + endMatch[0].length,
        type: "Private Key",
        replacement: "[REDACTED:Private Key]",
      }]
    }
  }
  return []
}

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = []
  matches.push(...detectPartialKey(text, ctx))

  const markerCache = buildMarkerCache(text)

  PEM_BLOCK_REGEX.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = PEM_BLOCK_REGEX.exec(text)) !== null) {
    const label = m[1]
    const start = m.index
    const end = start + m[0].length
    if (isInsideMarker(markerCache, start, end)) continue
    if (matchesOverlapExisting(matches, start, end)) continue
    matches.push({
      start,
      end,
      type: `PEM ${label.trim()}`,
      replacement: `[REDACTED:PEM ${label.trim()}]`,
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
