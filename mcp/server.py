"""
claude-on-a-leash MCP Server
Deterministic security guardrails exposed as MCP tools.
Any MCP-aware agent can validate actions before executing them.
"""

import json
import re
import os
from datetime import datetime, timezone
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("claude-on-a-leash")

# ---------------------------------------------------------------------------
# Patterns (ported from bash-safety-guard.sh)
# ---------------------------------------------------------------------------

DESTRUCTIVE_FS_PATTERNS = [
    r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+[/~]",   # rm -rf /  or  rm -rf ~
    r"rm\s+-[a-zA-Z]*f[a-zA-Z]*r\s+[/~]",
    r"\bdd\b.*\bif=/dev/(urandom|zero|random)\b.*\bof=/dev/",
    r"\bmkfs\b",
    r"\bshred\b.*/etc",
    r">\s*/dev/sd[a-z]",
]

PRIVILEGE_ESCALATION_PATTERNS = [
    r"\bsudo\s+(rm|dd|chmod\s+777|mkfs|shred)\b",
    r"\bsu\s+root\b",
    r"chmod\s+[0-7]*7[0-7][0-7]\s+/etc",
    r"echo\s+.*>>\s*/etc/sudoers",
]

SYSTEM_MODIFICATION_PATTERNS = [
    r">\s*/etc/passwd",
    r">\s*/etc/hosts",
    r"\bcrontab\s+-[re]\b",
    r">>?\s*~?/\.ssh/authorized_keys",
    r"\badduser\b|\buseradd\b",
]

PIPE_TO_SHELL_PATTERNS = [
    r"(curl|wget)\s+[^\|]+\|\s*(bash|sh|zsh|fish)",
    r"eval\s*\$\s*\(\s*(curl|wget)",
    r"\bpython[23]?\b.*\bexec\b.*\b(requests|urllib)\b",
    r"(bash|sh|source)\s+<\(\s*(curl|wget)",
]

EXFIL_PATTERNS = [
    r"(env|printenv|set)\s*\|?\s*(curl|wget|nc|ncat)",
    r"cat\s+[^\s]*\.aws/credentials\s*\|",
    r"cat\s+[^\s]*(id_rsa|id_ed25519|\.pem|\.key)\s*\|",
    r"history\s*\|?\s*(curl|wget)",
]

REVERSE_SHELL_PATTERNS = [
    r"bash\s+-i\s+>&?\s*/dev/tcp/",
    r"\bnc\b.*-e\s+/bin/(sh|bash)",
    r"python[23]?\s+-c\s+.*socket.*connect",
    r"perl\s+-e\s+.*socket",
]

FORK_BOMB_PATTERNS = [
    r":\(\)\s*\{.*:\|:.*\}",
    r"while\s+true.*fork",
]

GIT_FORCE_PUSH_PATTERNS = [
    r"git\s+push.*--force.*\b(main|master|production|prod)\b",
    r"git\s+push.*\b(main|master|production|prod)\b.*--force",
    r"git\s+push\s+-f\s+.*\b(main|master|production|prod)\b",
]

SHUTDOWN_PATTERNS = [
    r"\b(shutdown|reboot|halt|poweroff)\b",
    r"\binit\s+0\b",
]

# ---------------------------------------------------------------------------
# Patterns (ported from file-write-guard.sh)
# ---------------------------------------------------------------------------

BLOCKED_WRITE_PATHS = [
    r"^/etc/",
    r"^/usr/bin/",
    r"^/bin/",
    r"^/boot/",
    r"^/sys/",
    r"^/proc/",
    r"^/root/",
    r"(^|/)\.claude/hooks/",
]

SECRET_FILE_PATTERNS = [
    r"(^|/)\.env(\.(local|production|staging|development))?$",
    r"\.(pem|key|p12|pfx|jks)$",
    r"(^|/)id_(rsa|ed25519|ecdsa|dsa)$",
    r"(^|/)\.aws/credentials$",
    r"(^|/)\.kubeconfig$",
    r"(^|/)terraform\.tfvars$",
    r"(^|/)secrets\.(yaml|json)$",
    r"(^|/)\.npmrc$",
    r"(^|/)\.netrc$",
]

REAL_SECRET_CONTENT_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                          # AWS access key
    r"sk-[a-zA-Z0-9]{32,}",                        # OpenAI / Stripe sk
    r"xox[baprs]-[0-9a-zA-Z-]+",                   # Slack token
    r"ghp_[a-zA-Z0-9]{30,}",                        # GitHub PAT
    r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
]

# ---------------------------------------------------------------------------
# Patterns (ported from read-guard.sh)
# ---------------------------------------------------------------------------

BLOCKED_READ_PATTERNS = [
    r"(^|/)id_(rsa|ed25519|ecdsa|dsa)$",
    r"\.(pem|key|p12|pfx|jks|pgp)$",
    r"(^|/)\.aws/(credentials|config)$",
    r"(^|/)credentials\.json$",
    r"(^|/)service-account\.json$",
    r"(^|/)\.kubeconfig$",
    r"(^|/)\.vault-token$",
    r"(^|/)\.env(\.(local|production|staging|development))?$",
    r"(^|/)\.npmrc$",
    r"(^|/)\.pypirc$",
    r"(^|/)\.netrc$",
    r"(^|/)terraform\.tfvars$",
    r"(^|/)secrets\.(yaml|json)$",
    r"(^|/)\.ssh/authorized_keys$",
    r"(^|/)\.ssh/config$",
    r"^/etc/(shadow|sudoers)$",
    r"^/etc/sudoers\.d/",
    r"^/root/",
    r"(^|/)wallet\.dat$",
    r"(^|/)\.gnupg/",
    r"(^|/)\.htpasswd$",
]

# ---------------------------------------------------------------------------
# Patterns (ported from network-guard.sh)
# ---------------------------------------------------------------------------

BLOCKED_DOMAINS = [
    r"pastebin\.com",
    r"requestbin\.",
    r"webhook\.site",
    r"ngrok\.(io|app|com)",
    r"burpcollaborator\.net",
    r"oastify\.com",
    r"interact\.sh",
    r"canarytokens\.",
]

CLOUD_METADATA_IPS = [
    "169.254.169.254",        # AWS / Azure
    "metadata.google.internal",
    "169.254.170.2",          # ECS
]

# ---------------------------------------------------------------------------
# Patterns (ported from prompt-injection-guard.sh)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"forget\s+(everything|all)\s+(you|i|we)\s+(were|have|told)",
    r"you\s+are\s+now\s+(DAN|jailbreak|unrestricted)",
    r"(jailbreak|developer|god)\s+mode\s+(enabled|activated|on)",
    r"this\s+is\s+(anthropic|openai)\s+support",
    r"you\s+have\s+been\s+granted\s+admin\s+access",
    r"act\s+as\s+(if\s+you\s+are\s+)?an?\s+AI\s+without\s+(restrictions|limits|filters)",
    r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(restrictions|limits)",
    r"sudo\s+(make|give|grant)\s+me",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match_any(text: str, patterns: list[str]) -> str | None:
    """Return first matching pattern string, or None."""
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return p
    return None

def _is_direct_ip(url: str) -> bool:
    ip_re = re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)"
    )
    return bool(ip_re.search(url))

def _audit(entry: dict):
    """Append a JSON audit entry to ./leash-audit.log (best-effort)."""
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    try:
        log_path = Path(os.environ.get("LEASH_AUDIT_LOG", "leash-audit.log"))
        with log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def _result(allowed: bool, reason: str, category: str | None = None, matched_pattern: str | None = None) -> dict:
    return {
        "allowed": allowed,
        "reason": reason,
        "category": category,
        "matched_pattern": matched_pattern,
    }

# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def validate_bash_command(command: str) -> dict:
    """
    Validate a bash command against security guardrails before execution.
    Returns {allowed, reason, category, matched_pattern}.
    Block if allowed=False.
    """
    checks = [
        (DESTRUCTIVE_FS_PATTERNS,       "destructive_filesystem"),
        (PRIVILEGE_ESCALATION_PATTERNS, "privilege_escalation"),
        (SYSTEM_MODIFICATION_PATTERNS,  "system_modification"),
        (PIPE_TO_SHELL_PATTERNS,        "pipe_to_shell_rce"),
        (EXFIL_PATTERNS,                "credential_exfiltration"),
        (REVERSE_SHELL_PATTERNS,        "reverse_shell"),
        (FORK_BOMB_PATTERNS,            "fork_bomb"),
        (GIT_FORCE_PUSH_PATTERNS,       "git_force_push_protected_branch"),
        (SHUTDOWN_PATTERNS,             "shutdown_reboot"),
    ]

    for patterns, category in checks:
        matched = _match_any(command, patterns)
        if matched:
            _audit({"tool": "validate_bash_command", "command": command,
                    "allowed": False, "category": category})
            return _result(
                False,
                f"Blocked: command matches '{category}' guardrail.",
                category,
                matched,
            )

    _audit({"tool": "validate_bash_command", "command": command, "allowed": True})
    return _result(True, "Command passed all security checks.")


@mcp.tool()
def validate_file_write(path: str, content: str = "") -> dict:
    """
    Validate a file write operation.
    Checks system path restrictions, secret file names, and secret content patterns.
    Returns {allowed, reason, category, matched_pattern}.
    """
    # Normalise
    norm = str(Path(path).resolve())

    # System path check
    matched = _match_any(norm, BLOCKED_WRITE_PATHS)
    if matched:
        _audit({"tool": "validate_file_write", "path": path, "allowed": False, "category": "system_path"})
        return _result(False, f"Blocked: write to protected system path '{norm}'.", "system_path", matched)

    # Secret file name check
    matched = _match_any(path, SECRET_FILE_PATTERNS)
    if matched:
        _audit({"tool": "validate_file_write", "path": path, "allowed": False, "category": "secret_file"})
        return _result(False, f"Blocked: '{path}' matches secret file pattern.", "secret_file", matched)

    # Secret content scan
    if content:
        matched = _match_any(content, REAL_SECRET_CONTENT_PATTERNS)
        if matched:
            _audit({"tool": "validate_file_write", "path": path, "allowed": False, "category": "secret_content"})
            return _result(False, "Blocked: content appears to contain real credentials or private keys.", "secret_content", matched)

    _audit({"tool": "validate_file_write", "path": path, "allowed": True})
    return _result(True, "File write passed all security checks.")


@mcp.tool()
def validate_file_read(path: str) -> dict:
    """
    Validate a file read operation against sensitive file guardrails.
    Returns {allowed, reason, category, matched_pattern}.
    """
    matched = _match_any(path, BLOCKED_READ_PATTERNS)
    if matched:
        _audit({"tool": "validate_file_read", "path": path, "allowed": False, "category": "sensitive_file"})
        return _result(False, f"Blocked: '{path}' matches sensitive file guardrail.", "sensitive_file", matched)

    _audit({"tool": "validate_file_read", "path": path, "allowed": True})
    return _result(True, "File read passed all security checks.")


@mcp.tool()
def validate_network_request(url: str) -> dict:
    """
    Validate a network/HTTP request before it is made.
    Blocks plain HTTP, known exfil endpoints, direct IPs, and cloud metadata endpoints.
    Returns {allowed, reason, category, matched_pattern}.
    """
    # file:// protocol
    if re.match(r"^file://", url, re.IGNORECASE):
        _audit({"tool": "validate_network_request", "url": url, "allowed": False, "category": "file_protocol"})
        return _result(False, "Blocked: file:// protocol can expose local sensitive files.", "file_protocol", r"^file://")

    # Plain HTTP
    if re.match(r"^http://", url, re.IGNORECASE):
        _audit({"tool": "validate_network_request", "url": url, "allowed": False, "category": "plain_http"})
        return _result(False, "Blocked: plain HTTP is not allowed. Use HTTPS.", "plain_http", r"^http://")

    # Cloud metadata
    for endpoint in CLOUD_METADATA_IPS:
        if endpoint in url:
            _audit({"tool": "validate_network_request", "url": url, "allowed": False, "category": "cloud_metadata_ssrf"})
            return _result(False, f"Blocked: request targets cloud metadata endpoint '{endpoint}'.", "cloud_metadata_ssrf", endpoint)

    # Direct IP fetch
    if _is_direct_ip(url):
        _audit({"tool": "validate_network_request", "url": url, "allowed": False, "category": "direct_ip_ssrf"})
        return _result(False, "Blocked: direct IP fetches are not allowed (SSRF prevention).", "direct_ip_ssrf")

    # Known exfil domains
    matched = _match_any(url, BLOCKED_DOMAINS)
    if matched:
        _audit({"tool": "validate_network_request", "url": url, "allowed": False, "category": "known_exfil_domain"})
        return _result(False, f"Blocked: URL matches known exfiltration domain.", "known_exfil_domain", matched)

    _audit({"tool": "validate_network_request", "url": url, "allowed": True})
    return _result(True, "Network request passed all security checks.")


@mcp.tool()
def scan_prompt_injection(prompt: str) -> dict:
    """
    Scan a user prompt for injection / jailbreak patterns.
    Returns {allowed, reason, category, matched_pattern}.
    """
    matched = _match_any(prompt, INJECTION_PATTERNS)
    if matched:
        _audit({"tool": "scan_prompt_injection", "allowed": False, "category": "prompt_injection"})
        return _result(False, "Blocked: prompt contains injection or jailbreak pattern.", "prompt_injection", matched)

    _audit({"tool": "scan_prompt_injection", "allowed": True})
    return _result(True, "Prompt passed injection scan.")


@mcp.tool()
def get_audit_log(n: int = 20, filter_tool: str = "", filter_blocked_only: bool = False) -> list[dict]:
    """
    Return the last N audit log entries (max 1000).
    Optionally filter by tool name (e.g. 'validate_bash_command') or show only blocked entries.
    """
    n = min(n, 1000)
    log_path = Path(os.environ.get("LEASH_AUDIT_LOG", "leash-audit.log"))
    if not log_path.exists():
        return []

    entries = []
    with log_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if filter_tool and entry.get("tool") != filter_tool:
                    continue
                if filter_blocked_only and entry.get("allowed", True):
                    continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue

    return entries[-n:]


@mcp.tool()
def validate_all(
    command: str = "",
    read_path: str = "",
    write_path: str = "",
    write_content: str = "",
    url: str = "",
    prompt: str = "",
) -> dict:
    """
    Convenience tool: validate multiple actions in one call.
    Pass whichever fields apply. Returns a dict of {field: result} for each provided field,
    plus an overall 'allowed' that is True only if ALL checks pass.
    """
    results = {}
    overall = True

    if command:
        r = validate_bash_command(command)
        results["command"] = r
        if not r["allowed"]:
            overall = False

    if read_path:
        r = validate_file_read(read_path)
        results["read_path"] = r
        if not r["allowed"]:
            overall = False

    if write_path:
        r = validate_file_write(write_path, write_content)
        results["write_path"] = r
        if not r["allowed"]:
            overall = False

    if url:
        r = validate_network_request(url)
        results["url"] = r
        if not r["allowed"]:
            overall = False

    if prompt:
        r = scan_prompt_injection(prompt)
        results["prompt"] = r
        if not r["allowed"]:
            overall = False

    results["overall_allowed"] = overall
    return results


if __name__ == "__main__":
    mcp.run()