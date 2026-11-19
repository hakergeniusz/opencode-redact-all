import { describe, expect, it } from "bun:test"
import { redactText } from "../src/layers/index.js"
import { DEFAULT_CONFIG, loadConfig } from "../src/config.js"
import { transformUserInput, makeContext, redactToolText, redactValue } from "../src/redact.js"
import { createSessionStats, recordMatches, formatStats } from "../src/stats.js"
import type { Config, RedactionContext } from "../src/types.js"

function ctx(overrides: Partial<Config> = {}): RedactionContext {
  const config: Config = { ...DEFAULT_CONFIG, ...overrides }
  return {
    config,
    partialPrivateKeyPaths: new Set<string>(),
    enabled: true,
  }
}

describe("opencode-redact-all", () => {
  it("redacts vendor API keys while preserving structure", () => {
    const text = "The key is ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST end"
    const result = redactText(text, ctx())
    expect(result.matches.length).toBeGreaterThan(0)
    expect(result.text).toContain("[REDACTED:")
    expect(result.text).not.toContain("ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST")
    expect(result.text).toContain("The key is ")
    expect(result.text).toContain(" end")
  })

  it("redacts PEM private key blocks", () => {
    const text = "-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----"
    const result = redactText(text, ctx())
    expect(result.text).not.toContain("QUJDREVGRw==")
    expect(result.text).toContain("[REDACTED:PEM PRIVATE KEY]")
  })

  it("masks connection-string passwords", () => {
    const text = "postgres://admin:supersecret@db.internal:5432/app"
    const result = redactText(text, ctx())
    expect(result.text).toContain("[REDACTED:Password]")
    expect(result.text).not.toContain("supersecret")
    expect(result.text).toContain("postgres://admin:")
    expect(result.text).toContain("@db.internal:5432/app")
  })

  it("does not corrupt a legitimate file path that looks like a token", () => {
    const text = "path: zed-task-sk-abcdefghij0123456789.md"
    const result = redactText(text, ctx())
    expect(result.text).toContain(".md")
  })

  it("does not double-redact existing markers", () => {
    const once = redactText("ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST", ctx())
    const twice = redactText(once.text, ctx())
    expect(twice.matches.length).toBe(0)
    expect(twice.text).toBe(once.text)
  })

  it("leaves slash commands untouched in user input", () => {
    const c = ctx()
    expect(transformUserInput("/redact on", c).text).toBe("/redact on")
    expect(transformUserInput("my ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST", c).text).toContain("[REDACTED:")
  })

  it("respects whitelisted tools and disabled mode", () => {
    const text = "ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST"
    const whitelisted = makeContext(DEFAULT_CONFIG, new Set(), true, "edit")
    expect(redactToolText(text, whitelisted).matches.length).toBe(0)
    const disabled = makeContext(DEFAULT_CONFIG, new Set(), false, "bash")
    expect(redactToolText(text, disabled).matches.length).toBe(0)
  })

  it("redacts nested structured tool results in place", () => {
    const c = ctx()
    const value = { nested: { key: "ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST" }, keep: "public" }
    const hits: number[] = []
    redactValue(value, c, "bash", (m) => hits.push(m.length))
    expect(hits.length).toBeGreaterThan(0)
    expect(JSON.stringify(value)).not.toContain("ghp_abcdefghij0123456789ABCDEFGHIJKLMNOPQRST")
    expect(value.keep).toBe("public")
  })

  it("records stats and formats them", () => {
    const stats = createSessionStats()
    recordMatches(stats, [{ start: 0, end: 1, type: "GitHub Token", replacement: "" }], "bash")
    const formatted = formatStats(stats)
    expect(formatted).toContain("**Total redactions:** 1")
    expect(formatted).toContain("GitHub Token: 1")
    expect(formatted).toContain("bash: 1")
  })

  it("merges plugin config options over defaults", () => {
    const loaded = loadConfig({ layers: { pii: true }, minLength: 10 })
    expect(loaded.layers.pii).toBe(true)
    expect(loaded.layers.vendor).toBe(true)
    expect(loaded.minLength).toBe(10)
  })
})
