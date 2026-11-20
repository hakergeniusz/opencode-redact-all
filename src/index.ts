// opencode-redact-all — native OpenCode V2 plugin.
//
//   * user input filter      -> ctx.session.hook("prompt", ...)
//   * post-tool redaction    -> ctx.session.hook("context"|"compaction"|"generate"|"title", ...)
//   * session toggle + info  -> ctx.command.transform(...)
//
// Write-like tools (write/edit/patch and mcp__*__write*) are never filtered —
// their output is model-generated code.

import { Plugin } from "@opencode/plugin"
import { loadConfig } from "./config.js"
import { createSessionStats, formatStats, recordMatches, type SessionStats } from "./stats.js"
import {
  isWriteTool,
  makeContext,
  redactToolText,
  redactValue,
  transformUserInput,
  updatePartialPrivateKeyPaths,
} from "./redact.js"
import type { Match } from "./types.js"

type MutableRecord = Record<string, any>

interface Disposable {
  dispose(): Promise<void>
}

export default Plugin.define({
  id: "opencode-redact-all",
  async setup(ctx) {
    const config = loadConfig(ctx.options)
    const stats: SessionStats = createSessionStats()
    const partialPrivateKeyPaths = new Set<string>()
    let enabled = true

    const registrations: Disposable[] = []
    const keep = async (promise: Promise<Disposable>) => {
      registrations.push(await promise)
    }

    const note = (matches: Match[], toolName: string) => {
      if (matches.length > 0) recordMatches(stats, matches, toolName)
    }

    // ──────────────────────────────────────────────────────────────
    // USER INPUT: redact the prompt before attachments/skills expand it.
    // ──────────────────────────────────────────────────────────────
    await keep(ctx.session.hook("prompt", (event) => {
      if (!enabled || config.mode === "off") return
      const draft = (event as unknown as { prompt: MutableRecord }).prompt
      if (!draft || typeof draft.text !== "string") return
      if (!draft.text || draft.text.startsWith("/")) return

      const result = transformUserInput(
        draft.text,
        makeContext(config, partialPrivateKeyPaths, enabled, "user_input"),
      )
      if (result.matches.length === 0) return
      draft.text = result.text
      note(result.matches, "user_input")
      // NOTE: attachment mention offsets may shift because markers are longer
      // than the original tokens. We deliberately leave them untouched —
      // redaction is rare and a stale offset only affects that attachment.
    }))

    // ──────────────────────────────────────────────────────────────
    // TOOL OUTPUT: redact tool result parts in the messages sent to the
    // model. Registered for every model-request kind so secrets never leak
    // through a summary or a transient generation either.
    // ──────────────────────────────────────────────────────────────
    const redactMessages = (messages: unknown) => {
      if (!enabled || config.mode === "off" || !Array.isArray(messages)) return

      const allMessages = messages as MutableRecord[]
      // Tool-call parts carry the input for the matching tool-result part;
      // remember it so path-based rules and partial-key tracking still work.
      const inputsById = new Map<string, Record<string, unknown>>()
      for (const message of allMessages) {
        const parts = message?.content ?? message?.parts
        if (!Array.isArray(parts)) continue
        for (const part of parts as MutableRecord[]) {
          if ((part?.type === "tool-call" || part?.type === "tool") && typeof part.id === "string" &&
              part.input && typeof part.input === "object") {
            inputsById.set(part.id, part.input as Record<string, unknown>)
          }
        }
      }

      for (const message of allMessages) {
        const parts = message?.content ?? message?.parts
        if (!Array.isArray(parts)) continue
        for (const part of parts as MutableRecord[]) {
          // AI message shape: { type: "tool-result", name, result: { type, value } }
          // Session message shape (defensive fallback): { type: "tool", tool, state: { output } }
          const isResult = part?.type === "tool-result" || part?.type === "tool"
          if (!isResult) continue

          const toolName: string | undefined =
            typeof part.name === "string" ? part.name
            : typeof part.tool === "string" ? part.tool
            : undefined
          if (isWriteTool(toolName)) continue

          const input = (typeof part.id === "string" ? inputsById.get(part.id) : undefined)
            ?? (part.state?.input && typeof part.state.input === "object"
              ? part.state.input as Record<string, unknown>
              : undefined)
          const ctx = makeContext(config, partialPrivateKeyPaths, enabled, toolName, input)
          const tool = toolName ?? "tool"

          const result = part.result
          if (result && typeof result === "object") {
            if (result.type === "content" && Array.isArray(result.value)) {
              for (const item of result.value as MutableRecord[]) {
                if (item && item.type === "text" && typeof item.text === "string") {
                  const redacted = redactToolText(item.text, ctx)
                  if (redacted.matches.length > 0) {
                    item.text = redacted.text
                    note(redacted.matches, tool)
                  }
                }
              }
            } else if ("value" in result) {
              if (result.type === "text" && typeof result.value === "string") {
                updatePartialPrivateKeyPaths(result.value, toolName, ctx.inputPath, partialPrivateKeyPaths)
              }
              result.value = redactValue(result.value, ctx, tool, note)
            }
          }

          const state = part.state
          if (state && typeof state === "object") {
            const output: unknown = state.output
            if (typeof output === "string") {
              updatePartialPrivateKeyPaths(output, toolName, ctx.inputPath, partialPrivateKeyPaths)
              const redacted = redactToolText(output, ctx)
              if (redacted.matches.length > 0) {
                state.output = redacted.text
                note(redacted.matches, tool)
              }
            } else if (output && typeof output === "object") {
              state.output = redactValue(output, ctx, tool, note)
            }
          }
        }
      }
    }

    for (const hookName of ["context", "compaction", "generate", "title"] as const) {
      await keep(ctx.session.hook(hookName, (event) => {
        redactMessages((event as unknown as { messages?: unknown }).messages)
      }))
    }

    // ──────────────────────────────────────────────────────────────
    // COMMANDS: /redact on|off|status|stats|config
    // Results are shown with session.synthetic (synthetic messages do not
    // re-run the prompt hook, so command output is never redacted).
    // ──────────────────────────────────────────────────────────────
    const setEnabled = (next: boolean) => {
      const changed = enabled !== next
      enabled = next
      partialPrivateKeyPaths.clear()
      return changed
    }

    const handleRedact = (rawInput: string): string => {
      let raw = (rawInput ?? "").trim()
      raw = raw.replace(/^\/?redact\b/i, "").trim()
      const sub = raw.toLowerCase().split(/\s+/)[0] ?? ""
      switch (sub) {
        case "on":
          return setEnabled(true)
            ? "opencode-redact-all: redaction ENABLED. Tool output and user input will be redacted."
            : "opencode-redact-all: redaction already enabled."
        case "off":
          return setEnabled(false)
            ? "opencode-redact-all: redaction DISABLED. Tool output and user input pass through unmodified. Use `/redact on` to re-enable."
            : "opencode-redact-all: redaction already disabled."
        case "status":
          return `opencode-redact-all: redaction is ${enabled ? "ENABLED" : "DISABLED"}.`
        case "stats":
          return formatStats(stats)
        case "config":
          return "```json\n" + JSON.stringify(config, null, 2) + "\n```"
        default:
          return "opencode-redact-all: unknown argument. Usage: /redact <on|off|status|stats|config>"
      }
    }

    const show = async (sessionID: string, text: string) => {
      await ctx.session.synthetic({ sessionID, text })
    }

    await keep(ctx.command.transform((editor) => {
      editor.add({
        name: "redact",
        description: "Toggle opencode-redact-all redaction (on|off|status|stats|config)",
        execute: async ({ sessionID, prompt }) => {
          const text = (prompt as MutableRecord | undefined)?.text ?? ""
          await show(sessionID, handleRedact(String(text)))
        },
      })

    }))

    return () => {
      for (const registration of registrations) {
        void registration.dispose().catch(() => undefined)
      }
    }
  },
})
