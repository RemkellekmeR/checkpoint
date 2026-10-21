# Checkpoint

**An MCP firewall for IT service-desk agents.** Built for the Clocked Build Challenge (building period Oct 21 to Nov 10, 2026).

Checkpoint is an MCP server that sits between an MCP client (Claude Desktop, VS Code, Cursor, MCP Inspector, or a scripted client) and the tools an IT service-desk agent uses: reading inbox messages and tickets, proposing remediation scripts, sending replies. Every tool call passes through Clocked before the agent sees the result or the action happens:

| Clocked endpoint | Product | What Checkpoint screens | What the verdict changes |
| --- | --- | --- | --- |
| `/injection` | Guard | Untrusted tool results (emails, tickets, KB pages) and the user's own request | **allow** clean content, **cut** the evidence spans of a high/critical injection, **hold** uncertain results for a human |
| `/pii` | Protect | Tool results and outbound replies | the agent only sees the anonymized text; originals never reach the model |
| `/script` | Inspect | Remediation scripts the agent proposes | **allow** (simulated run, never executed), **hold** suspicious scripts for approval, **deny** malicious ones with evidence |

Guard and Inspect are detectors, not enforcement boundaries, and a benign verdict is not execution authorization. Checkpoint keeps least-privilege tool design and human approval in place; Clocked reduces risk, it does not replace those controls.

> Status (Oct 21, 2026): all three paths are wired, and four tools work end to end against **offline stubs only**. No call to Clocked has been made yet because there is no Clocked account or key. The real clients are written against `clocked-sdk` 0.6.0 and tested against Clocked's recorded docs responses with a fake client, but they have not run against the live API. The hold queue, outbox and simulated run log are in memory. Convex and the dashboard are not started.

## What works today

- **MCP Streamable HTTP server** on a single endpoint, `POST/GET/DELETE /mcp`, protocol revision `2025-11-25`.
  - `Origin` allowlist: a request whose `Origin` is not on `CHECKPOINT_ALLOWED_ORIGINS` gets `403` before any MCP handling. `Host` is checked against loopback names too (DNS rebinding).
  - Stateful sessions: `initialize` returns an `MCP-Session-Id`; other requests without it get `400`, unknown or terminated sessions get `404`; an unsupported `MCP-Protocol-Version` gets `400`.
- **Four tools**, over synthetic fixtures (`fixtures/inbox.json`, `fixtures/changes.json`; fictional people, `example.com`):

| Tool | Screening | Outcomes | If screening fails |
| --- | --- | --- | --- |
| `read_inbox_message` | Guard (`source: "content"`) on the raw message, then Protect on whatever would be shown | **allow**; **cut** high/critical injection evidence spans and quarantine the rest; **hold** uncertain results. Shown text is always Protect's anonymized copy (`<EMAIL>`, `<PHONE>`, ...) | Guard error: fail **open** with an `UNSCREENED` banner (Protect still runs). Protect error: fail **closed**, content withheld, since showing it would hand unscreened personal data to the model |
| `send_reply` | Protect on the draft, then Guard on the anonymized draft | **recorded** to an in-memory outbox (anonymized body only; **nothing is ever sent**); **hold** anything Guard does not clearly allow (outbound text is never cut and sent) | Fail **closed**: refused, nothing recorded |
| `run_remediation_script` | Inspect, with the change ticket's approved scope from `fixtures/changes.json` as `instructions` (never taken from the agent) | **allow** = simulated run recorded in memory (**the script is never executed**); **hold** = approval queue; **deny** = refusal with the flagged lines and line numbers | Fail **closed**: refused, nothing run or queued |
| `check_hold` | none (read-only) | Status of a hold: `pending`, `approved` or `denied`, plus tool, reason and timestamps. Never returns the withheld content | |

- **Holds are decided by people, not the agent.** There is no approve or deny tool. `HoldQueue.resolve()` exists for the reviewer side (planned: a dashboard) and a decided hold cannot be decided again. Approving a hold does not yet release or replay anything; that comes with the dashboard.
- **Inspect policy**: deny on verdict `malicious` or `malicious >= threshold`; hold on verdict `suspicious`, `suspicious >= 0.5`, or high/critical severity; allow only an explicit `benign` verdict. An unrecognized verdict label is held, never allowed.
- **No execution path.** Nothing under `src/` imports `child_process`, `worker_threads`, `cluster` or `vm`, or calls `eval`; a unit test enforces it.
- **Offsets are Unicode code points.** Clocked counts characters, not UTF-16 units, so Guard cuts, Protect placeholders and Inspect line numbers all go through `src/unicode.ts` (`Array.from`), never `String.slice` on a Clocked offset. Tests cover emoji and astral characters, and rebuilding Protect's replace-style copy from the recorded `/pii` offsets reproduces Clocked's `anonymized_text` exactly.

## Real vs. stub

Guard, Protect and Inspect are each an interface with two implementations:

| Component | Real (`CLOCKED_API_KEY` set) | Offline stub (explicit flag, no key) |
| --- | --- | --- |
| Guard (`src/guard/`) | `ClockedGuard`: `/injection` via `clocked-sdk` | `OfflineStubGuard`, `CHECKPOINT_GUARD=offline-stub`: a few keyword patterns |
| Protect (`src/protect/`) | `ClockedProtect`: `/pii` via `clocked-sdk`, `anonymize: "replace"`, the nine default kinds plus a described `employee_id` kind | `OfflineStubProtect`, `CHECKPOINT_PROTECT=offline-stub`: regexes for emails, phones, IPv4, SSNs, card-like numbers, `EMP-` ids. No names, addresses, dates of birth or medical data |
| Inspect (`src/inspect/`) | `ClockedInspect`: `/script` via `clocked-sdk` | `OfflineStubInspect`, `CHECKPOINT_INSPECT=offline-stub`: a few line patterns; ignores the change scope |

**The stubs are for local tests only. They are not Clocked and not real screening.** Every result a stub touches is labeled `engine: "offline-stub"` and the tool text starts with an `UNSCREENED ... OFFLINE STUB ...` banner. When a component has neither a key nor its flag, the server refuses to start rather than run unscreened.

Not built yet: Convex audit log, holds table and dashboard; Guard on the user's own request (`source: "user"`); `read_ticket` and `fetch_kb_page`; upstream proxy mode; the evaluation table against live Clocked.

## Quick start

Requires Node.js 20+ (developed on 26) and gitleaks for commits.

```sh
git config core.hooksPath .githooks   # secret scan on every commit (see below)
npm ci
npm run check                          # typecheck + unit tests + smoke test (offline stub, no network)

# Run the server locally without Clocked (offline stubs, for development only):
CHECKPOINT_GUARD=offline-stub CHECKPOINT_PROTECT=offline-stub CHECKPOINT_INSPECT=offline-stub npm start

# With Clocked (once you have a key): copy .env.example to .env, set CLOCKED_API_KEY, then
node --env-file=.env --import tsx src/main.ts
```

The server listens on `http://127.0.0.1:3333/mcp`. Point any Streamable HTTP MCP client (for example MCP Inspector) at it.

| Script | What it does |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Unit tests (`node --test`): code point spans; Guard, Protect and Inspect mapping (recorded docs responses, fake clients) and policy; each tool's outcomes and failure modes; no execution APIs under `src/` |
| `npm run smoke` | Starts the server process (offline stubs, no network) and checks Origin 403, initialize, sessions, `tools/list`, and every tool's main outcomes over a real MCP client |
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
- `fixtures/inbox.json`: synthetic inbox. One message carries an obvious prompt-injection payload surrounded by emoji and astral letters; one carries personal data (email, employee id, IP, phone) for Protect.
- `fixtures/changes.json`: synthetic approved change tickets whose scope Inspect assesses scripts against. `CHG-DEMO-204` reuses the scope from Clocked's `/script` docs example.

## Secret scanning (do this first)

Commits are scanned by [gitleaks](https://github.com/gitleaks/gitleaks) through a versioned hook in `.githooks/pre-commit`. After cloning:

```sh
# 1. Install gitleaks >= 8.19 (see the gitleaks README), then:
git config core.hooksPath .githooks
```

The hook refuses to commit if gitleaks is missing. `.gitleaks.toml` extends the default rules with one for Clocked keys (`clk_...`). Keep keys in `.env` (gitignored); `.env.example` lists the variable names only.

## License

MIT, see [LICENSE](LICENSE).
