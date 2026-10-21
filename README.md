# Checkpoint

**An MCP firewall for IT service-desk agents.** Built for the Clocked Build Challenge (building period Oct 21 to Nov 10, 2026).

Checkpoint is an MCP server that sits between an MCP client (Claude Desktop, VS Code, Cursor, MCP Inspector, or a scripted client) and the tools an IT service-desk agent uses: reading inbox messages and tickets, proposing remediation scripts, sending replies. Every tool call passes through Clocked before the agent sees the result or the action happens:

| Clocked endpoint | Product | What Checkpoint screens | What the verdict changes |
| --- | --- | --- | --- |
| `/injection` | Guard | Untrusted tool results (emails, tickets, KB pages) and the user's own request | **allow** clean content, **cut** the evidence spans of a high/critical injection, **hold** uncertain results for a human |
| `/pii` | Protect | Tool results and outbound replies | the agent only sees the anonymized text; originals never reach the model |
| `/script` | Inspect | Remediation scripts the agent proposes | **allow** (simulated run, never executed), **hold** suspicious scripts for approval, **deny** malicious ones with evidence |

Guard and Inspect are detectors, not enforcement boundaries, and a benign verdict is not execution authorization. Checkpoint keeps least-privilege tool design and human approval in place; Clocked reduces risk, it does not replace those controls.

> Status: early skeleton (Oct 21, 2026). See the commit history for what exists so far.

## Secret scanning (do this first)

Commits are scanned by [gitleaks](https://github.com/gitleaks/gitleaks) through a versioned hook in `.githooks/pre-commit`. After cloning:

```sh
# 1. Install gitleaks >= 8.19 (see the gitleaks README), then:
git config core.hooksPath .githooks
```

The hook refuses to commit if gitleaks is missing. `.gitleaks.toml` extends the default rules with one for Clocked keys (`clk_...`). Keep keys in `.env` (gitignored); `.env.example` lists the variable names only.

## License

MIT, see [LICENSE](LICENSE).
