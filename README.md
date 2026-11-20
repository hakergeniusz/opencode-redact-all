# opencode-redact-all

A native **OpenCode V2** plugin that redacts secrets, certificates (X.509), PII, and connection strings from tool output and user prompts **before they reach the model**.

It implements a 10-layer detection engine (pure TypeScript) integrated with OpenCode session hooks and commands.

## What it does

- **User prompts** are redacted at admission via `ctx.session.hook("prompt", ...)` — before skill/template expansion, matching the original `input` hook. Slash commands are left untouched.
- **Tool output** is redacted in the model request via `ctx.session.hook("context", ...)` (and `compaction`, `generate`, `title`). Only `tool-result` parts are touched (their `result.value`, recursively); plain assistant text and write-tool output are never modified. The matching `tool-call` input is used for path/partial-key rules.
- **`/redact on|off|status|stats|config`** controls and inspects the plugin per session, via `ctx.command.transform(...)`. Command replies are delivered with `ctx.session.synthetic(...)`.
- **Write tools** (`write`, `edit`, `ssh_write`, `ssh_edit`, `multi_edit`, `mcp__*__write*`, `apply_patch`, `patch`) are skipped — their output is model-generated code, never a secret to protect.

### Detection layers (same order as the original)

`path` → `vendor` → `prefix` → `pem` (with partial-key continuation tracking) → `asn1` → `connection` → `context` → `pii` (opt-in) → `entropy`.

- Vendor patterns: AWS, Bearer, OpenAI/Anthropic `sk-`, Stripe, Hetzner, GitHub, GitLab, JWT, Slack, Google, npm, SendGrid, Tavily, Brave, Firecrawl, Telegram bot tokens, IONOS tokens.
- PEM/X.509/PGP/SSH blocks, multi-chunk private-key reads, DER/ASN.1 (`MII…`) blobs.
- Context-anchored secrets: JSON, ENV, INI, YAML `password`/`token`/`api_key`/… fields and certificate metadata (`subject=`, `issuer=`, `verify return:`).
- Connection strings and URL credentials (`postgres://user:pass@host`, `https://user:pass@host`).
- Shannon-entropy heuristic (≥ 4.5 bits/char, ≥ 32 chars) with allowlist.
- Optional PII: e-mail, phone, IPv4, Luhn-valid credit cards, SSN, IBAN.

Markers use the original format, e.g. `[REDACTED:GitHub Token]`, `[REDACTED:PEM PRIVATE KEY]`, `[REDACTED:Password]`. Existing markers are detected so spans are never double-redacted, and whitespace/JSON structure is preserved 1:1.

## Install / load

Place the package in `.opencode/plugins/`, or reference it from `opencode.json(c)`:

```jsonc
{
  "plugins": [
    "opencode-redact-all",
    {
      "package": "opencode-redact-all",
      "options": {
        "layers": { "pii": true },
        "minLength": 24
      }
    }
  ]
}
```

Options are read from `ctx.options` and merged over the defaults.

### Options

All keys from the original config are supported:

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"mask"` | `"mask"` replaces matches; `"off"` disables redaction. |
| `blockMode` | `false` | Original block-mode flag (see gaps). |
| `streamingRedaction` | `false` | Unused by the original too. |
| `toolPolicy.whitelist` | write tools | Tools whose output is never redacted. |
| `toolPolicy.blacklist` | `[]` | Reserved (redaction already applies to all non-whitelisted tools). |
| `layers.*` | all on except `pii` | Per-layer toggles. |
| `allowlistRegex` / `blocklistRegex` | git SHA patterns / `[]` | Regex allowlist. |
| `minEntropy` / `minLength` | `4.5` / `32` | Entropy and minimum-length thresholds. |
| `preservePrefixChars` / `asterisksMax` | `4` / `20` | Marker formatting. |

## Known gaps / differences

- **No hard tool-call blocking.** OpenCode prompt/context hooks are model-request transforms, not tool-execution gates, so `blockMode` and `inputContainsSensitiveSecrets` remain helper functions (`src/redact.ts`) but are not wired as a hard execution block. Use OpenCode permission rules if you need hard blocking.
- **Presentation.** The `context` hook redacts the outgoing model call; persisted history and the TUI may keep the original output.
- **Structured tool output** (`result.type === "json"`) is traversed recursively up to a depth of 8; deeper nesting is not redacted.
- **Attachment mention offsets** in rewrites prompts are not recomputed (markers are longer than tokens). This only affects attachments whose mention sits after a redacted span.
- `blocklistRegex` and `streamingRedaction` are retained for config compatibility but were effectively unused in the original.

## Tests

`bun test` runs `test/redact.test.ts` (vendor keys, PEM, connection strings, path-context preservation, no double-redaction, user-input skip, whitelist/disabled mode, stats, config merge).

## License

MIT © 2026 hakergeniusz.
