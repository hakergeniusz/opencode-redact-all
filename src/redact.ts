// OpenCode-facing redaction helpers.
// Redaction helpers used by session and tool hooks.

import { redactText } from "./layers/index.js"
import { commandReadsSensitive, shouldBlockPath } from "./layers/layer-7-path.js"
import type { Config, Match, RedactionContext } from "./types.js"

/** Model-generated output: never filter or block. */
export const WRITE_TOOLS = new Set(["write", "edit", "ssh_write", "ssh_edit", "multi_edit"])

export function isWriteTool(name: string | undefined): boolean {
  if (!name) return false
  if (WRITE_TOOLS.has(name)) return true
  if (name.startsWith("mcp__") && /__write/i.test(name)) return true
  // OpenCode built-in mutation tools.
  if (name === "apply_patch" || name === "patch") return true
  return false
}

export function makeContext(
  config: Config,
  partialPrivateKeyPaths: Set<string>,
  enabled: boolean,
  toolName?: string,
  input?: Record<string, unknown>,
): RedactionContext {
  return {
    config,
    partialPrivateKeyPaths,
    enabled,
    toolName,
    inputPath: input ? extractPath(input) : undefined,
    command: input ? extractCommand(input) : undefined,
  }
}

export function extractPath(input: Record<string, unknown> | undefined): string | undefined {
  if (!input) return undefined
  const path = input.path ?? input.file_path ?? input.file
  return typeof path === "string" ? path : undefined
}

export function extractCommand(input: Record<string, unknown> | undefined): string | undefined {
  if (!input) return undefined
  const cmd = input.command ?? input.cmd
  return typeof cmd === "string" ? cmd : undefined
}

/**
 * Redact a single text span (tool output). Returns the matches so callers can
 * feed session stats. Whitelisted tools and write tools are skipped.
 */
export function redactToolText(text: string, ctx: RedactionContext): { text: string; matches: Match[] } {
  if (ctx.enabled === false) return { text, matches: [] }
  if (ctx.config.mode === "off") return { text, matches: [] }
  if (ctx.toolName && ctx.config.toolPolicy.whitelist.includes(ctx.toolName)) return { text, matches: [] }
  return redactText(text, ctx)
}

/**
 * Redact user input before it reaches the model. Slash commands are left
 * untouched so the command dispatcher still sees them.
 */
export function transformUserInput(text: string, ctx: RedactionContext): { text: string; matches: Match[] } {
  if (ctx.enabled === false) return { text, matches: [] }
  if (ctx.config.mode === "off") return { text, matches: [] }
  if (text.startsWith("/")) return { text, matches: [] }
  return redactText(text, { ...ctx, toolName: "user_input" })
}

/**
 * Track partial private-key reads across chunks.
 * A `read` of a PEM private key without an END marker marks the path so
 * subsequent chunks are fully redacted until an END marker is seen.
 */
export function updatePartialPrivateKeyPaths(
  output: string,
  toolName: string | undefined,
  inputPath: string | undefined,
  partialPrivateKeyPaths: Set<string>,
): void {
  if (toolName !== "read" || !inputPath) return
  if (/-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(output) &&
      !/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(output)) {
    partialPrivateKeyPaths.add(inputPath)
  } else if (/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(output)) {
    partialPrivateKeyPaths.delete(inputPath)
  }
}

/**
 * Recursively redact a JSON-like tool result value. Strings are replaced with
 * markers; objects and arrays are mutated in place so the caller's message
 * object is updated. Depth is capped to avoid runaway recursion.
 */
export function redactValue(
  value: unknown,
  ctx: RedactionContext,
  toolName: string,
  note: (matches: Match[], tool: string) => void,
  depth = 0,
): unknown {
  if (depth > 8) return value
  if (typeof value === "string") {
    const result = redactToolText(value, ctx)
    if (result.matches.length === 0) return value
    note(result.matches, toolName)
    return result.text
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const next = redactValue(value[i], ctx, toolName, note, depth + 1)
      if (next !== value[i]) value[i] = next
    }
    return value
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>
    for (const key of Object.keys(record)) {
      const next = redactValue(record[key], ctx, toolName, note, depth + 1)
      if (next !== record[key]) record[key] = next
    }
  }
  return value
}

export interface BlockResult {
  block: true
  reason: string
}

/**
 * blockMode check for tool calls (helper; not wired as a hard execution gate
 * in OpenCode). Prompt/context hooks cannot block tool execution.
 */
export function shouldBlock(
  toolName: string,
  input: Record<string, unknown>,
  config: Config,
  enabled: boolean,
): BlockResult | undefined {
  if (!enabled) return undefined
  if (isWriteTool(toolName)) return undefined
  if (!config.blockMode) return undefined

  if (toolName === "bash") {
    const cmd = (input.command ?? input.cmd) as string | undefined
    if (cmd && commandReadsSensitive(cmd)) {
      return {
        block: true,
        reason: "opencode-redact-all: bash command likely reads sensitive files.",
      }
    }
  }
  if (toolName === "read") {
    const path = (input.path ?? input.file_path ?? input.file) as string | undefined
    if (path && shouldBlockPath(path)) {
      return {
        block: true,
        reason: `opencode-redact-all: access to sensitive path "${path}" is blocked.`,
      }
    }
  }
  return undefined
}

/** blockMode check for secrets embedded in tool input. */
export function inputContainsSensitiveSecrets(
  toolName: string,
  input: Record<string, unknown>,
  config: Config,
  enabled: boolean,
): BlockResult | undefined {
  if (!enabled) return undefined
  if (isWriteTool(toolName)) return undefined
  if (!config.blockMode) return undefined
  const result = redactText(JSON.stringify(input), {
    config,
    partialPrivateKeyPaths: new Set(),
  })
  if (result.matches.length > 0) {
    return {
      block: true,
      reason: `opencode-redact-all: tool input contains ${result.matches.length} potential secret(s).`,
    }
  }
  return undefined
}
