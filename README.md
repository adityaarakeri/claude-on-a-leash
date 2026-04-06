<p align="center">
  <img src="assets/claude-on-a-leash.png" width="200"/>
</p>

<h1 align="center">Claude on a Leash</h1>
<!-- --- -->
<!-- # claude-on-a-leash -->

> Deterministic security guardrails that intercept Claude Code tool calls **before** they execute.

[![Install](https://img.shields.io/badge/install-one--liner-blue?style=flat-square)](#install)
[![Hooks](https://img.shields.io/badge/hooks-6-green?style=flat-square)](#what-gets-installed)
[![MCP](https://img.shields.io/badge/MCP-server-purple?style=flat-square)](#mcp-server)
[![License](https://img.shields.io/badge/license-MIT-grey?style=flat-square)](LICENSE)

Claude Code can execute real actions in your repo. These hooks sit between Claude and your system, blocking dangerous commands, protecting secrets, and logging what happens. Six shell scripts. Zero trust.

---

## Install

> **Why not `curl | bash`?**
> One of these hooks *blocks* `curl | bash` patterns. We practice what we preach.
> Download the script, read it, then run it.

```bash
# Download
curl -fsSL https://raw.githubusercontent.com/adityaarakeri/claude-on-a-leash/main/install.sh \
  -o /tmp/claude-hooks-install.sh

# Inspect (please do this)
cat /tmp/claude-hooks-install.sh

# Install into current project
bash /tmp/claude-hooks-install.sh

# OR: install globally for all repos
bash /tmp/claude-hooks-install.sh --global
```

### Other options

```bash
bash install.sh --dry-run               # preview what would be installed
bash install.sh --uninstall             # remove leash hooks (project-local)
bash install.sh --uninstall --global    # remove leash hooks (global install)
bash install.sh --no-color              # plain output (for CI)
```

---

## What gets installed

### Claude Code

Six hooks wired via `.claude/settings.json`:

| Hook file | Event | Matcher | What it stops |
|-----------|-------|---------|--------------|
| `bash-safety-guard.sh` | `PreToolUse` | `Bash` | Destructive commands, RCE, exfiltration, reverse shells, privilege escalation |
| `file-write-guard.sh` | `PreToolUse` | `Write\|Edit\|MultiEdit` | Writes to system paths, secret files, Claude's own hooks |
| `read-guard.sh` | `PreToolUse` | `Read` | Reads of secrets, private keys, credentials, and sensitive system files |
| `network-guard.sh` | `PreToolUse` | `WebFetch` | Plain HTTP, known exfil domains, direct IPs, cloud metadata SSRF |
| `prompt-injection-guard.sh` | `UserPromptSubmit` | `*` | Instruction overrides, jailbreak patterns, social engineering |
| `command-audit-logger.sh` | `PostToolUse` | `Bash\|Read\|Write\|Edit\|MultiEdit\|WebFetch` | Logs everything to `.claude/command-audit.log` (async, never blocks) |

---

## MCP Server

The same guardrails are also available as an **MCP server** — so any MCP-aware agent (Codex, GPT-4o, Gemini, custom frameworks) can validate actions before executing them.

> **Important:** MCP is advisory. An agent *should* consult these tools before acting.
> For hard enforcement in Claude Code, keep the original bash hooks. Use both together.

### Tools

| Tool | What it validates |
|---|---|
| `validate_bash_command(command)` | Destructive FS, RCE, exfiltration, reverse shells, fork bombs, privilege escalation, git force-push |
| `validate_file_write(path, content?)` | System paths, secret filenames, credential patterns in content |
| `validate_file_read(path)` | SSH keys, cloud credentials, `.env` files, sensitive system files |
| `validate_network_request(url)` | Plain HTTP, exfil domains, direct IPs, cloud metadata SSRF |
| `scan_prompt_injection(prompt)` | Jailbreak phrases, instruction overrides, social engineering |
| `get_audit_log(n, filter_tool, filter_blocked_only)` | Query the local audit log |
| `validate_all(...)` | Validate multiple actions in one call, returns per-field results + overall |

### Quickstart

```bash
pip install mcp
python mcp/server.py
```

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "claude-on-a-leash": {
      "command": "python",
      "args": ["/path/to/claude-on-a-leash/mcp/server.py"]
    }
  }
}
```

**Claude Code** — add to `.claude/settings.json` alongside your existing hooks:

```json
{
  "mcpServers": {
    "leash": {
      "command": "python",
      "args": ["./mcp/server.py"]
    }
  }
}
```

### Hooks vs MCP

| | Bash hooks | MCP server |
|---|---|---|
| Enforcement | Hard block (`exit 2`) | Advisory (agent must respect) |
| Works with | Claude Code only | Any MCP-aware agent |
| Bypass risk | Very hard | Agent could ignore response |
| Audit log | `.claude/command-audit.log` | `leash-audit.log` |

Full MCP docs: [mcp/README.md](mcp/README.md)

---

## How it works

Claude Code's [hooks system](https://docs.anthropic.com/en/docs/claude-code/hooks) fires shell scripts at lifecycle events. Each hook receives a JSON blob on stdin describing what Claude wants to do:

```bash
# What Claude Code sends your hook:
{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}

# Your hook decides:
exit 0   # allow
exit 2   # block -- stderr becomes feedback Claude reads and adapts to
```

The feedback loop is the key feature: Claude doesn't just get stopped. It reads *why*, then tries a safer approach. Blocked hooks are also a great debugging tool for understanding what Claude was actually trying to do.

---

## What `bash-safety-guard.sh` blocks

| Category | Examples |
|----------|---------|
| Destructive FS | `rm -rf /`, `rm -rf ~`, `dd if=/dev/urandom of=/dev/sda`, `mkfs`, `shred /etc` |
| Privilege escalation | `sudo rm`, `sudo dd`, `sudo chmod 777`, `su root`, writing to `/etc/sudoers` |
| System modification | Writing to `/etc/passwd`, `/etc/hosts`, `crontab -e`, adding `~/.ssh/authorized_keys` |
| Pipe-to-shell RCE | `curl https://... \| bash`, `wget ... \| sh`, `eval $(curl ...)` |
| Credential exfiltration | `env \| curl`, `cat .aws/credentials \| nc`, `curl -F file=@.env`, `scp ~/.ssh/id_rsa host:/tmp/`, `rsync .env host:/tmp/` |
| Reverse shells | `bash -i /dev/tcp/...`, `nc -e /bin/sh`, Python socket reverse shells |
| Fork bombs | `:(){ :\|:& };:`, infinite background loops |
| Git safety | Force-push to `main`/`master`/`production` |
| Shutdown/reboot | `shutdown`, `reboot`, `halt`, `poweroff`, `init 0` |

## What `file-write-guard.sh` blocks

- OS paths: `/etc/`, `/usr/bin/`, `/bin/`, `/boot/`, `/sys/`, `/proc/`, `/root/`
- Secret files: `.env`, `*.pem`, `*.key`, `id_rsa`, `.aws/credentials`, `.kubeconfig`, `terraform.tfvars`, `.npmrc`, `.netrc`, `secrets.yaml`
- Self-modification: Claude cannot overwrite its own hooks (the obvious bypass attempt)
- Content scanning: write calls are scanned for real AWS/Stripe/GitHub/Slack tokens

## What `read-guard.sh` blocks

Preventing reads matters as much as preventing writes. An agent that can `cat ~/.aws/credentials` before exfiltrating it is still a problem, even if the write is blocked.

- SSH private keys: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`
- Cloud credentials: `.aws/credentials`, `.aws/config`, `credentials.json`, `service-account.json`
- Kubernetes/Vault: `.kubeconfig`, `kubeconfig`, `.vault-token`
- Env files: `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development`
- Package registries: `.npmrc`, `.pypirc`, `.netrc`
- Infrastructure secrets: `terraform.tfvars`, `secrets.yaml`, `secrets.json`
- SSH access: `.ssh/authorized_keys`, `.ssh/config`
- System files: `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `/root/`
- Crypto wallets: `wallet.dat`, `*.pgp`, `.gnupg/`
- GPG: `.htpasswd`

All allowed reads are appended to `.claude/file-audit.log` for review.

## What `network-guard.sh` blocks

- Plain HTTP to external hosts (HTTPS only)
- Known exfil endpoints: `pastebin.com`, `requestbin`, `webhook.site`, ngrok tunnels, OAST/Burp Collaborator
- Direct IP fetches (SSRF prevention)
- Cloud metadata endpoints: `169.254.169.254`, `metadata.google.internal` (IAM credential theft)

## What `prompt-injection-guard.sh` blocks

- `"ignore all previous instructions"` and variants
- `"you are now DAN"`, jailbreak mode, developer mode tricks
- `"this is Anthropic support"`, `"you have been granted admin access"`
- Injects branch name and active security policy as `additionalContext` into every session

> **Note:** The hook reads the `prompt` field from the `UserPromptSubmit` input (with a fallback to `message`). If you see `BLOCKED: Could not parse prompt from hook input`, re-run the installer to get the updated hook — older versions incorrectly read from `message` only, which is always empty in the current Claude Code hook schema.

---

## Audit logs

Every allowed action lands in `.claude/command-audit.log` as newline-delimited JSON:

```jsonl
{"ts":"2025-03-28T10:00:00Z","session_id":"abc123","tool":"Bash","command":"npm test","risk_flags":[]}
{"ts":"2025-03-28T10:01:05Z","session_id":"abc123","tool":"Write","file_path":"src/app.js"}
{"ts":"2025-03-28T10:01:10Z","session_id":"abc123","tool":"WebFetch","url":"https://api.github.com/repos/..."}
{"ts":"2025-03-28T10:01:15Z","session_id":"abc123","tool":"Read","file_path":"src/config.js"}
```

All file reads (both allowed and blocked attempts) are also appended to `.claude/file-audit.log`:

```
2025-03-28T10:01:15Z READ: src/config.js
```

```bash
# Pretty-print the last 20 entries
tail -20 .claude/command-audit.log | python3 -m json.tool

# Find all sudo usage
grep '"sudo"' .claude/command-audit.log

# Find all network fetches
grep '"network-fetch"' .claude/command-audit.log

# See everything Claude read this session
cat .claude/file-audit.log
```

Both log files are added to `.gitignore` automatically.

---

## Sharing with your team

The `.claude/` directory is designed to be version-controlled:

```bash
# Add to your repo
git add .claude/settings.json .claude/hooks/
git commit -m "security: add Claude Code security hooks"
```

Then each developer runs the installer once after cloning:

```bash
bash /tmp/claude-hooks-install.sh
```

Or add to your `README.md` / `Makefile`:

```makefile
setup:
    curl -fsSL https://raw.githubusercontent.com/adityaarakeri/claude-on-a-leash/main/install.sh \
      -o /tmp/claude-hooks-install.sh && bash /tmp/claude-hooks-install.sh
```

---

## Verify inside Claude Code

```
/hooks
```

This shows all registered hooks. You should see 6 entries across `UserPromptSubmit`, `PreToolUse`, and `PostToolUse`.

## Customising

All rules are plain bash. Edit the hook files directly. Common adjustments:

```bash
# Allow force-push to staging (remove the line that blocks it)
# In bash-safety-guard.sh, remove or comment:
# if echo "$COMMAND" | grep -qE 'git push.*--force.*\b(main|master)'; then ...

# Block npm install entirely (not just log it)
# Change warn_log to block() for the package install pattern

# Add your own blocked domain
# In network-guard.sh, add to the BLOCKED_DOMAINS loop:
# 'internal-metrics\.mycompany\.com'
```

---

## Requirements

- **bash** 4+ (macOS ships bash 3 -- `brew install bash` or use zsh-compatible syntax)
- **python3** -- required for JSON parsing in hooks
- **Claude Code** 1.0+ with hooks support

---

## License

MIT -- use freely, contribute back.

---

## Contributing

PRs welcome. Especially interested in:
- Additional dangerous command patterns
- Windows / WSL2 compatibility improvements
- Test harness for hook scripts
- Integration with `gitleaks` / `trufflehog` for richer secret scanning
