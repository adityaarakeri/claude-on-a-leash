# claude-on-a-leash — MCP Server

> Deterministic security guardrails from [claude-on-a-leash](https://github.com/adityaarakeri/claude-on-a-leash), exposed as an MCP server.
> Any MCP-aware agent — not just Claude Code — can validate actions before executing them.

---

## Why MCP?

The original hooks system enforces guardrails *in-process* for Claude Code via `exit 2`.
This MCP server makes the same logic available as a **validation oracle** that any agent can call:

- Codex, GPT-4o, Gemini, or any agentic framework
- Multi-agent pipelines that want a shared security layer
- Custom agents that can't use Claude Code hooks directly

> **Important:** MCP is advisory. An agent *should* consult these tools before acting.
> For hard enforcement in Claude Code, keep the original bash hooks. Use this alongside them.

---

## Tools

| Tool | What it validates |
|---|---|
| `validate_bash_command(command)` | Destructive FS, RCE, exfiltration, reverse shells, fork bombs, privilege escalation, git force-push |
| `validate_file_write(path, content?)` | System paths, secret filenames, credential patterns in content |
| `validate_file_read(path)` | SSH keys, cloud credentials, `.env` files, sensitive system files |
| `validate_network_request(url)` | Plain HTTP, exfil domains, direct IPs, cloud metadata SSRF |
| `scan_prompt_injection(prompt)` | Jailbreak phrases, instruction overrides, social engineering |
| `get_audit_log(n, filter_tool, filter_blocked_only)` | Query the local audit log |
| `validate_all(...)` | Validate multiple actions in one call, returns per-field results + overall |

All tools return:
```json
{
  "allowed": true,
  "reason": "Command passed all security checks.",
  "category": null,
  "matched_pattern": null
}
```

---

## Quickstart

```bash
# Clone
git clone https://github.com/adityaarakeri/claude-on-a-leash
cd claude-on-a-leash

# Install
pip install mcp

# Run the MCP server (stdio transport — for Claude Desktop / Claude Code)
python src/server.py
```

### Register with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "claude-on-a-leash": {
      "command": "python",
      "args": ["/path/to/claude-on-a-leash-mcp/src/server.py"]
    }
  }
}
```

### Register with Claude Code

```json
// .claude/settings.json — add alongside your existing hooks
{
  "mcpServers": {
    "leash": {
      "command": "python",
      "args": ["./mcp/src/server.py"]
    }
  }
}
```

---

## Audit log

Every validation call (allow or block) is appended to `leash-audit.log` as newline-delimited JSON:

```json
{"ts":"2025-04-01T10:00:00Z","tool":"validate_bash_command","command":"rm -rf /","allowed":false,"category":"destructive_filesystem"}
{"ts":"2025-04-01T10:01:00Z","tool":"validate_network_request","url":"https://api.github.com","allowed":true}
```

Override the log path:
```bash
LEASH_AUDIT_LOG=/var/log/leash.log python src/server.py
```

---

## Architecture

```
Agent
  │
  ├─ validate_bash_command("npm install")  ──► MCP Server ──► allow ✓
  ├─ validate_bash_command("curl x | bash") ─► MCP Server ──► block ✗ + reason
  ├─ validate_file_read(".env")            ──► MCP Server ──► block ✗
  └─ validate_network_request("http://...") ► MCP Server ──► block ✗
```

The server is stateless — no daemon, no database. Just pattern matching + an append-only log.

---

## Extending

All rules live in `src/server.py` as plain Python lists of regex strings — the same patterns as the original bash hooks, just ported to Python.

```python
# Add a blocked domain
BLOCKED_DOMAINS.append(r"your-internal-metrics\.company\.com")

# Add a destructive command pattern
DESTRUCTIVE_FS_PATTERNS.append(r"\bdropdb\b")
```

---

## Relationship to the bash hooks

| | Bash hooks | This MCP server |
|---|---|---|
| Enforcement | Hard block (`exit 2`) | Advisory (agent must respect) |
| Works with | Claude Code only | Any MCP-aware agent |
| Bypass risk | Very hard | Agent could ignore response |
| Audit log | `.claude/command-audit.log` | `leash-audit.log` |

**Recommended:** run both. Hooks for Claude Code hard enforcement, MCP for everything else.

---

## License

MIT