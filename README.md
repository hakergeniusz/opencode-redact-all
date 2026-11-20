# opencode-redact-all

A native **OpenCode V2** plugin that redacts secrets, certificates (X.509),
PII and connection strings from tool output and user prompts **before they
reach the model**.

## What it does

- **User prompts** are redacted at admission via `ctx.session.hook("prompt", ...)`
  before skill/template expansion. Slash commands are left untouched.
- **Tool output** is redacted in model requests via `ctx.session.hook("context", ...)`
  (and `compaction`, `generate`, `title`). Only tool-result parts are touched
  (their values, recursively); plain assistant text and write-tool output are
  never modified. Matching tool-call input is used for path/partial-key rules.
- **`/redact on|off|status|stats|config`** (plus `/redact-all-stats` and
  `/redact-all-config`) controls and inspects the plugin per session via
  `ctx.command.transform(...)`. Command replies are delivered with
  `ctx.session.synthetic(...)`.
- **Write tools** (`write`, `edit`, `ssh_write`, `ssh_edit`, `multi_edit`,
  `mcp__*__write*`, `apply_patch`, `patch`) are skipped — their output is
  model-generated code, never a secret to protect.

### Detection layers

Detection runs in this order:

`path` → `vendor` → `prefix` → `pem` (with partial-key continuation tracking) → `asn1` → `connection` → `context` → `pii` (opt-in) → `entropy`.

- Vendor patterns: AWS, Bearer, OpenAI/Anthropic `sk-`, Stripe, Hetzner, GitHub,
  GitLab, JWT, Slack, Google, npm, SendGrid, Tavily, Brave, Firecrawl, Telegram
  bot tokens, IONOS tokens.
- PEM/X.509/PGP/SSH blocks, multi-chunk private-key reads, DER/ASN.1 (`MII…`)
  blobs.
- Context-anchored secrets: JSON, ENV, INI, YAML `password`/`token`/`api_key`/…
  fields and certificate metadata (`subject=`, `issuer=[REDACTED:Certificate Metadata]
- Connection strings and URL credentials (`postgres://user:[REDACTED:Password]@host`,
  `https://user:[REDACTED:Password]@host`).
- Shannon-entropy heuristic (≥ 4.5 bits/char, ≥ 32 chars) with allowlist.
- Optional PII: e-mail, phone, IPv4, Luhn-valid credit cards, SSN, IBAN.

Markers use formats like `[REDACTED:GitHub Token]`,
`[REDACTED:PEM PRIVATE KEY]`, `[REDACTED:Password]`. Existing markers are
detected so spans are never double-redacted, and whitespace/JSON structure is
preserved.

## Install / load

Place the package in `.opencode/plugins/`, or reference it from
`opencode.json(c)`:

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

Options are read from `ctx.options` and merged over defaults.

### Options

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"mask"` | `"mask"` replaces matches; `"off"` disables redaction. |
| `blockMode` | `false` | Block-mode flag (see gaps). |
| `streamingRedaction` | `false` | Reserved/unused. |
| `toolPolicy.whitelist` | write tools | Tools whose output is never redacted. |
| `toolPolicy.blacklist` | `[]` | Reserved (redaction applies to all non-whitelisted tools). |
| `layers.*` | all on except `pii` | Per-layer toggles. |
| `allowlistRegex` / `blocklistRegex` | git SHA patterns / `[]` | Regex allowlist/blocklist patterns. |
| `minEntropy` / `minLength` | `4.5` / `32` | Entropy and minimum-length thresholds. |
| `preservePrefixChars` / `asterisksMax` | `4` / `20` | Marker formatting. |

## How it works in OpenCode

| Integration point | OpenCode V2 hook/entrypoint |
|---|---|
| User input redaction | `ctx.session.hook("prompt", ...)` mutating `event.prompt.text` |
| Tool output redaction | `ctx.session.hook("context"/"compaction"/"generate"/"title", ...)` mutating tool-part output in `event.messages` |
| Commands | `ctx.command.transform(...)` |
| Command feedback | `ctx.session.synthetic({ sessionID, text })` |
| Configuration | `ctx.options` merged over defaults |

## Known gaps / differences

- **No hard tool-call blocking.** Prompt/context hooks are model-request
  transforms, not tool-execution gates, so `blockMode` and
  `inputContainsSensitiveSecrets` remain available as helper functions in
  `src/redact.ts` but are not wired to a blocking hook. Use OpenCode permission
  rules if you need hard blocking.
- **Presentation.** `context` hooks affect the outgoing model call; persisted
  history and the TUI keep the original output.
- **Structured tool output** (`result.type === "json"`) is traversed recursively
  up to a depth of 8; deeper nesting is not redacted.
- **Attachment mention offsets** in rewritten prompts are not recomputed (markers
  are longer than tokens). This only affects attachments whose mention sits
  after a redacted span.

## Tests

`bun test` runs `test/redact.test.ts`, covering core detection and redaction
behavior (vendor keys, PEM, connection strings, path-context preservation, no
double-redaction, user-input handling, whitelist/disabled mode, stats, and
config merge).

## License

MIT © 2026 hakergeniusz.
