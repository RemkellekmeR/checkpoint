# Checkpoint

**An MCP firewall for IT service-desk agents.** Built for the Clocked Build Challenge (building period Oct 21 to Nov 10, 2026).

Checkpoint is an MCP server that sits between an MCP client (Claude Desktop, VS Code, Cursor, MCP Inspector, or a scripted client) and the tools an IT service-desk agent uses: reading inbox messages and tickets, proposing remediation scripts, sending replies. Every tool call passes through Clocked before the agent sees the result or the action happens:

| Clocked endpoint | Product | What Checkpoint screens | What the verdict changes |
| --- | --- | --- | --- |
| `/injection` | Guard | Untrusted tool results (emails, tickets, KB pages) and the user's own request | **allow** clean content, **cut** the evidence spans of a high/critical injection, **hold** uncertain results for a human |
| `/pii` | Protect | Tool results and outbound replies | the agent only sees the anonymized text; originals never reach the model |
| `/script` | Inspect | Remediation scripts the agent proposes | **allow** (simulated run, never executed), **hold** suspicious scripts for approval, **deny** malicious ones with evidence |

Guard and Inspect are detectors, not enforcement boundaries, and a benign verdict is not execution authorization. Checkpoint keeps least-privilege tool design and human approval in place; Clocked reduces risk, it does not replace those controls.

> Status: early skeleton (Oct 21, 2026). Guard gates one tool today; Protect and Inspect are next. See the commit history.

## What works today

- **MCP Streamable HTTP server** on a single endpoint, `POST/GET/DELETE /mcp`, protocol revision `2025-11-25`.
  - `Origin` allowlist: a request whose `Origin` is not on `CHECKPOINT_ALLOWED_ORIGINS` gets `403` before any MCP handling. `Host` is checked against loopback names too (DNS rebinding).
  - Stateful sessions: `initialize` returns an `MCP-Session-Id`; other requests without it get `400`, unknown or terminated sessions get `404`; an unsupported `MCP-Protocol-Version` gets `400`.
- **One tool, `read_inbox_message`**, over a synthetic service-desk inbox (`fixtures/inbox.json`; fictional people, `example.com`). Every result is screened by Guard (`source: "content"`) and the verdict decides what the agent gets:
  - **allow**: benign, outside the uncertain band.
  - **cut**: `verdict = injection`, severity high/critical, with evidence: the evidence spans are removed using Clocked's offsets and the rest is wrapped in a quarantine notice.
  - **hold**: injection probability inside the review band (0.35 to 0.65 to start), a lower-severity injection, or a high-severity verdict with no evidence to cut. The content is withheld and a hold id is returned (in-memory queue for now).
  - **unscreened**: Guard failed (timeout, 5xx after the SDK's retries, 402). Read tools fail open with a visible banner; write/execute tools will fail closed.
- **Offsets are Unicode code points.** Clocked counts characters, not UTF-16 units, so spans are cut with `src/unicode.ts` (`Array.from`), never `String.slice`. Tests cover emoji and astral characters.

## Real vs. stub

Guard is an interface (`src/guard/types.ts`) with two implementations:

| Implementation | When | What it is |
| --- | --- | --- |
| `ClockedGuard` (`src/guard/clocked.ts`) | `CLOCKED_API_KEY` is set | The real Clocked `/injection` endpoint via `clocked-sdk` |
| `OfflineStubGuard` (`src/guard/offline-stub.ts`) | `CHECKPOINT_GUARD=offline-stub` and no key | **A keyword heuristic for local tests only. Not Clocked, not real screening.** Every result it touches is labeled `UNSCREENED` / `engine: "offline-stub"`. |

With neither set, the server refuses to start rather than run unscreened.

## Quick start

Requires Node.js 20+ (developed on 26) and gitleaks for commits.

```sh
git config core.hooksPath .githooks   # secret scan on every commit (see below)
npm ci
npm run check                          # typecheck + unit tests + smoke test (offline stub, no network)

# Run the server locally without Clocked (offline stub, for development only):
CHECKPOINT_GUARD=offline-stub npm start

# With Clocked (once you have a key): copy .env.example to .env, set CLOCKED_API_KEY, then
node --env-file=.env --import tsx src/main.ts
```

The server listens on `http://127.0.0.1:3333/mcp`. Point any Streamable HTTP MCP client (for example MCP Inspector) at it.

| Script | What it does |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Unit tests (`node --test`): code point spans, Guard mapping and policy, the tool |
| `npm run smoke` | Starts the server process and checks Origin 403, initialize, sessions, `tools/list`, `read_inbox_message` |
| `npm run record:clocked` | Records raw `/injection`, `/pii`, `/script` responses for the docs examples into `fixtures/recorded/` (needs a key and `--yes`; spends credits) |

## Pinned dependencies

| Package | Version |
| --- | --- |
| `clocked-sdk` | 0.6.0 |
| `@modelcontextprotocol/server` | 2.3.1 |
| `@modelcontextprotocol/node` | 2.1.1 |
| `@modelcontextprotocol/client` (dev, smoke test) | 2.3.1 |
| `zod` | 4.6.7 |

All versions are exact (`save-exact`), and `package-lock.json` is committed.

## Fixtures

- `fixtures/docs/`: request bodies and recorded responses from Clocked's public docs (Guard, Protect, Inspect examples).
- `fixtures/recorded/`: our own raw responses, written by `scripts/record-clocked.mjs` (empty until a key exists).
- `fixtures/inbox.json`: synthetic inbox. One message carries an obvious prompt-injection payload surrounded by emoji and astral letters.

## Secret scanning (do this first)

Commits are scanned by [gitleaks](https://github.com/gitleaks/gitleaks) through a versioned hook in `.githooks/pre-commit`. After cloning:

```sh
# 1. Install gitleaks >= 8.19 (see the gitleaks README), then:
git config core.hooksPath .githooks
```

The hook refuses to commit if gitleaks is missing. `.gitleaks.toml` extends the default rules with one for Clocked keys (`clk_...`). Keep keys in `.env` (gitignored); `.env.example` lists the variable names only.

## License

MIT, see [LICENSE](LICENSE).
