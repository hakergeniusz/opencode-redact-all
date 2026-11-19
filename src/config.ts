// Config loader for opencode-redact-all.
// Ported from pi-redact-all. In OpenCode, options come from the plugin's
// `options` object in opencode.json(c); the legacy pi config file is still
// read as a fallback for backwards compatibility.

import { readFileSync, existsSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"
import type { Config } from "./types.js"

export const DEFAULT_CONFIG: Config = {
  mode: "mask",
  blockMode: false,
  streamingRedaction: false,
  toolPolicy: {
    whitelist: ["write", "edit", "ssh_write", "ssh_edit", "multi_edit"],
    blacklist: [],
  },
  layers: {
    vendor: true,
    pem: true,
    prefix: true,
    entropy: true,
    asn1: true,
    context: true,
    path: true,
    pii: false,
    connection: true,
  },
  allowlistRegex: [
    "\\b[a-f0-9]{40}\\b",
    "\\b[0-9a-f]{7,40}\\b",
  ],
  blocklistRegex: [],
  minEntropy: 4.5,
  minLength: 32,
  preservePrefixChars: 4,
  asterisksMax: 20,
}

/** Legacy pi config location, kept so existing pi-redact-all.json files keep working. */
const LEGACY_CONFIG_PATH = join(homedir(), ".pi", "agent", "pi-redact-all.json")

function mergeConfig(base: Config, user: Partial<Config> | undefined | null): Config {
  if (!user || typeof user !== "object") return { ...base }
  return {
    mode: user.mode ?? base.mode,
    blockMode: user.blockMode ?? base.blockMode,
    streamingRedaction: user.streamingRedaction ?? base.streamingRedaction,
    toolPolicy: {
      whitelist: user.toolPolicy?.whitelist ?? base.toolPolicy.whitelist,
      blacklist: user.toolPolicy?.blacklist ?? base.toolPolicy.blacklist,
    },
    layers: {
      vendor: user.layers?.vendor ?? base.layers.vendor,
      pem: user.layers?.pem ?? base.layers.pem,
      prefix: user.layers?.prefix ?? base.layers.prefix,
      entropy: user.layers?.entropy ?? base.layers.entropy,
      asn1: user.layers?.asn1 ?? base.layers.asn1,
      context: user.layers?.context ?? base.layers.context,
      path: user.layers?.path ?? base.layers.path,
      pii: user.layers?.pii ?? base.layers.pii,
      connection: user.layers?.connection ?? base.layers.connection,
    },
    allowlistRegex: user.allowlistRegex ?? base.allowlistRegex,
    blocklistRegex: user.blocklistRegex ?? base.blocklistRegex,
    minEntropy: user.minEntropy ?? base.minEntropy,
    minLength: user.minLength ?? base.minLength,
    preservePrefixChars: user.preservePrefixChars ?? base.preservePrefixChars,
    asterisksMax: user.asterisksMax ?? base.asterisksMax,
  }
}

function readJson(path: string): Partial<Config> | undefined {
  if (!existsSync(path)) return undefined
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as Partial<Config>
  } catch (err) {
    console.error(`[opencode-redact-all] Failed to load config at ${path}:`, err)
    return undefined
  }
}

/**
 * Load configuration with precedence: OpenCode plugin options > legacy pi
 * config file > defaults.
 */
export function loadConfig(options?: unknown): Config {
  let config = { ...DEFAULT_CONFIG }
  const legacy = readJson(LEGACY_CONFIG_PATH)
  if (legacy) config = mergeConfig(config, legacy)
  if (options && typeof options === "object") {
    // Support both a flat options object and a nested `config` object.
    const opts = options as Record<string, unknown>
    const flat = (opts.config && typeof opts.config === "object" ? opts.config : opts) as Partial<Config>
    config = mergeConfig(config, flat)
  }
  // Nested objects from JSON are shallow-merged by mergeConfig; ensure the
  // nested defaults survive if only some subkeys were provided.
  config.toolPolicy = {
    whitelist: config.toolPolicy?.whitelist ?? DEFAULT_CONFIG.toolPolicy.whitelist,
    blacklist: config.toolPolicy?.blacklist ?? DEFAULT_CONFIG.toolPolicy.blacklist,
  }
  config.layers = { ...DEFAULT_CONFIG.layers, ...config.layers }
  return config
}
