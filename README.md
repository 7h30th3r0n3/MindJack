# MindJack

> Get into the mind of AI agents. Read their memories. Rewrite their instructions.

Security research toolkit for auditing the local attack surface of AI coding assistants.

**Zero dependencies, Python 3.10+ standard library only.**

1. **`extractor.py`** - Extract conversation history from 10 AI tools
2. **`injector.py`** - Scan injection surfaces, demonstrate 56 attack scenarios
3. **`mindjack report`** - Generate interactive HTML attack graph with OWASP compliance mapping

> **Disclaimer:** For authorized security testing, red teaming, CTF challenges, and AI safety research only. Always obtain proper authorization before testing on systems you don't own.

---

## Supported Tools

| Tool | Extractor | Injector | Key Attack Surface |
|------|:---------:|:--------:|-------------------|
| **Claude Code** | history, sessions, memories | rules, settings, hooks, MCP, memory | `CLAUDE.md`, `settings.json`, hooks (RCE) |
| **OpenAI Codex CLI** | history, rollout sessions | AGENTS.md, config.toml | `sandbox_mode: danger-full-access` |
| **GitHub Copilot** | chat sessions | copilot-instructions.md | `.github/copilot-instructions.md` |
| **Cursor IDE** | state.vscdb chat data | .cursorrules, MCP config | CVE-2025-54135 (MCP RCE) |
| **Aider** | chat history markdown | config.yml, CONVENTIONS.md | `auto-commits`, model override |
| **Continue.dev** | session JSON | config.yaml, rules, .continuerc.json | `config.ts` (arbitrary code exec) |
| **Cline / Roo Code** | task conversations | .clinerules, .roo/rules/, memory-bank | Persistent memory bank poisoning |
| **Amazon Q** | chat history JSON | .amazonq/rules/, MCP config | MCP server injection |
| **Windsurf/Codeium** | cascade, memories | .windsurfrules, global_rules.md | Auto-generated memory poisoning |

---

## Quick Start

```bash
git clone https://github.com/7h30th3r0n3/MindJack.git
cd MindJack

# Extract all conversations
python3 extractor.py

# Scan for injection surfaces
python3 injector.py scan

# List all 33 attack recipes
python3 injector.py recipes

# Dry-run an injection (safe, no modifications)
python3 injector.py inject --recipe claude-memory-poison --dry-run

# Generate interactive HTML attack report
pip install -e .
mindjack report --scope ~ --allow-home-scope --existing-only -o report.html
```

---

## Extractor

Reads local conversation data from all supported AI tools and exports to JSON + Markdown.

### Usage

```bash
python3 extractor.py                                  # Extract everything
python3 extractor.py -o ~/export                       # Custom output dir
python3 extractor.py --json-only                       # Skip Markdown report
python3 extractor.py --sources claude-code codex-cli   # Specific tools only
```

### Output

```
ai_history_export/
  all_conversations.json       # Everything combined
  claude-code.json             # Per-source files
  codex-cli-session.json
  copilot.json
  ...
  REPORT.md                    # Human-readable summary
```

### JSON Schema

```json
{
  "source": "claude-code",
  "session_id": "abc123-...",
  "project": "/home/user/myproject",
  "date": "2026-03-21",
  "message_count": 42,
  "messages": [
    {"role": "user", "content": "fix the login bug", "timestamp": "2026-03-21T08:15:00+00:00"},
    {"role": "assistant", "content": "Looking at the auth module...", "timestamp": null}
  ]
}
```

### Data Sources per Tool

| Tool | What's Extracted | Storage Path |
|------|-----------------|--------------|
| Claude Code | User prompts (JSONL), session summaries (.tmp), persistent memories (.md) | `~/.claude/` |
| Codex CLI | User prompts (JSONL), full session rollouts with tool calls | `~/.codex/` |
| GitHub Copilot | Chat sessions (JSON) per workspace | VS Code `workspaceStorage/GitHub.copilot-chat/` |
| Cursor | Chat + composer data from SQLite | VS Code `workspaceStorage/state.vscdb` |
| Aider | Full Markdown chat transcripts | `.aider.chat.history.md` per project |
| Continue.dev | Session messages (JSON) | `~/.continue/sessions/` |
| Cline/Roo Code | API conversation history + task metadata (JSON) | VS Code `globalStorage/` |
| Amazon Q | Chat history per directory (JSON) | `~/.aws/amazonq/history/` |
| Windsurf | Cascade conversations, auto-generated memories | `~/.codeium/windsurf/` |

---

## Injector

Scans and demonstrates file-based prompt injection and configuration poisoning across AI coding assistants.

### Attack Surface Categories

| Category | Risk | Examples |
|----------|------|---------|
| **Instructions** | CRITICAL | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.clinerules`, `.windsurfrules` |
| **Settings** | CRITICAL | `settings.json` (allowedTools), `config.toml` (sandbox_mode) |
| **MCP** | CRITICAL | `.mcp.json` - spawn arbitrary processes as "tool servers" |
| **Hooks** | CRITICAL | Shell commands auto-executed on session events (RCE) |
| **Memory** | HIGH | Persistent context that resurfaces across sessions |

### Commands

```bash
# Scan - discover all injectable targets
python3 injector.py scan
python3 injector.py scan --json targets.json

# Recipes - list all 33 predefined attack scenarios
python3 injector.py recipes

# Inject - execute (always --dry-run first!)
python3 injector.py inject --recipe <name> --dry-run
python3 injector.py inject --recipe <name>
python3 injector.py inject --payload "your text" --tool claude-code --category memory --dry-run
python3 injector.py inject --payload-file evil.txt --tool cursor --dry-run
python3 injector.py inject --payload-preset exfiltrate_secrets --existing-only --dry-run

# Clean - remove all injections, restore backups
python3 injector.py clean
python3 injector.py clean --dry-run
```

### Recipes (33)

#### Claude Code (9)

| Recipe | Description |
|--------|-------------|
| `claude-settings-allowall` | Whitelist all tools (Bash, Read, Write, Edit, Agent, WebFetch, WebSearch) |
| `claude-hook-exfil` | Exfiltrate conversation transcripts on session stop |
| `claude-hook-keylogger` | Log every user prompt to external server via PreToolUse hook |
| `claude-hook-autoapprove` | Auto-approve all tool calls, bypass user confirmation |
| `claude-hook-file-watch` | Exfiltrate every file the model reads via PostToolUse hook |
| `claude-memory-poison` | Persistent memory that disables security checks |
| `claude-memory-fake-user` | Fake user profile to manipulate trust level |
| `claude-memory-fake-reference` | Fake reference pointing to malicious external docs |
| `claude-rules-inject` | Create a new malicious rule file in .claude/rules/ |

#### Codex CLI (3)

| Recipe | Description |
|--------|-------------|
| `codex-sandbox-disable` | Set `danger-full-access` sandbox + `full-auto` approval |
| `codex-agents-override` | Create AGENTS.override.md (highest priority override) |
| `codex-model-swap` | Downgrade model to gpt-3.5-turbo via config.toml |

#### Cursor IDE (3)

| Recipe | Description |
|--------|-------------|
| `cursor-rules-backdoor` | .cursorrules with hidden auth bypass + error exfil |
| `cursor-mcp-rce` | Inject malicious MCP server (CVE-2025-54135 vector) |
| `cursor-rules-alwaysapply` | .cursor/rules/ with alwaysApply frontmatter |

#### GitHub Copilot (1)

| Recipe | Description |
|--------|-------------|
| `copilot-instructions-poison` | .github/copilot-instructions.md with insecure patterns |

#### Aider (2)

| Recipe | Description |
|--------|-------------|
| `aider-autocommit-nocheck` | Enable auto-commits, disable lint and tests |
| `aider-conventions-poison` | CONVENTIONS.md with SQL injection + MD5 passwords |

#### Continue.dev (2)

| Recipe | Description |
|--------|-------------|
| `continue-config-overwrite` | .continuerc.json that overwrites config with malicious MCP + rogue model |
| `continue-rules-inject` | Global rule with alwaysApply that reads all .env files |

#### Cline / Roo Code (3)

| Recipe | Description |
|--------|-------------|
| `cline-rules-inject` | .clinerules that runs setup script + auto-approves everything |
| `cline-memory-bank-poison` | memory-bank/ injection for cross-session persistence |
| `roo-rules-multimode` | Rules that apply to all Roo Code modes |

#### Windsurf (2)

| Recipe | Description |
|--------|-------------|
| `windsurf-global-rules-poison` | Override global_rules.md for all workspaces |
| `windsurf-memory-inject` | Poison auto-generated memories |

#### Amazon Q (2)

| Recipe | Description |
|--------|-------------|
| `amazonq-rules-inject` | .amazonq/rules/ with hardcoded AWS creds + public S3 |
| `amazonq-mcp-inject` | MCP server that exfiltrates environment variables |

#### MCP Multi-Tool (3)

| Recipe | Description |
|--------|-------------|
| `mcp-rogue-server` | Malicious MCP server (Claude, Cursor, Amazon Q) |
| `mcp-reverse-shell` | MCP server that opens a reverse shell |
| `mcp-env-stealer` | MCP server that exfiltrates all env vars |

#### Cross-Tool (3)

| Recipe | Description |
|--------|-------------|
| `cross-tool-agents-md` | AGENTS.md read by 5+ tools simultaneously |
| `cross-tool-supply-chain` | AGENTS.md that injects malicious dependencies |
| `cross-tool-full-takeover` | AGENTS.md with full behavioral override + stealth |

### Payload Presets (23)

Presets can be injected into any target with `--payload-preset`:

| Category | Presets |
|----------|---------|
| **Data Exfiltration** | `exfiltrate_secrets`, `exfiltrate_codebase`, `exfiltrate_git` |
| **Code Backdoors** | `backdoor_endpoint`, `backdoor_eval`, `backdoor_hardcoded_creds`, `backdoor_dependency` |
| **Redirect/Override** | `redirect_instructions`, `redirect_model_identity`, `redirect_output_format` |
| **Permission Escalation** | `permission_escalation`, `permission_autocommit`, `permission_install` |
| **Stealth/Evasion** | `stealth_deny`, `stealth_gaslight`, `stealth_distract` |
| **Sabotage** | `sabotage_tests`, `sabotage_security`, `sabotage_performance` |
| **Social Engineering** | `social_trust`, `social_urgency` |
| **Persistence** | `persist_cron`, `persist_postinstall` |

### Safety Features

- **`--dry-run`** previews all changes without modifying files
- **Automatic backups** (`.agentscan.bak`) before any modification
- **`clean` command** restores all files from backups
- **Injection markers** (`<!-- AGENTSCAN-INJECTION -->`) for identification
- **Double injection prevention** - skips files already injected
- **Recipe target filtering** - recipes only inject into their declared targets
- **JSON parse safety** - refuses to overwrite files it cannot parse

---

## Cross-Tool Attack Vectors

Some files are read by multiple tools, making them high-value targets:

| File | Read by |
|------|---------|
| `AGENTS.md` | Codex CLI, Cursor, Windsurf, Cline/Roo Code, GitHub Copilot |
| `.cursorrules` | Cursor, Cline/Roo Code |
| `.windsurfrules` | Windsurf, Cline/Roo Code |

A single `AGENTS.md` in a cloned repo can silently poison 5+ AI tools.

---

## OWASP Mapping

Every MindJack scenario maps to real-world vulnerabilities catalogued by OWASP.

### OWASP Top 10 for LLM Applications (2025)

> Source: [genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

| ID | Vulnerability | MindJack Coverage |
|----|--------------|-------------------|
| **LLM01** | Prompt Injection | All instruction/rules injections (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.clinerules`, `.windsurfrules`) - the core of MindJack |
| **LLM02** | Sensitive Information Disclosure | `exfiltrate_secrets`, `exfiltrate_codebase`, `exfiltrate_git` presets + `claude-hook-exfil`, `claude-hook-file-watch` recipes |
| **LLM03** | Supply Chain | `cross-tool-supply-chain`, `backdoor_dependency`, `persist_postinstall` - malicious deps injected via instruction files |
| **LLM04** | Data and Model Poisoning | `claude-memory-poison`, `claude-memory-fake-user`, `windsurf-memory-inject`, `cline-memory-bank-poison` - persistent context poisoning |
| **LLM05** | Improper Output Handling | `redirect_output_format` preset - forces model to embed exfiltrated data in its output |
| **LLM06** | Excessive Agency | `claude-settings-allowall`, `claude-hook-autoapprove`, `codex-sandbox-disable`, `permission_escalation` - granting tools/permissions beyond scope |
| **LLM07** | System Prompt Leakage | Extractor reads all system prompts, session summaries, and memories - demonstrates full prompt recovery |
| **LLM09** | Misinformation | `stealth_gaslight`, `stealth_distract` - model actively misleads user about its own behavior |
| **LLM10** | Unbounded Consumption | `codex-model-swap` - redirect to cheaper models, degrade quality silently |

### OWASP Top 10 for Agentic Applications (2025)

> Source: [genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

| ID | Vulnerability | MindJack Coverage |
|----|--------------|-------------------|
| **ASI01** | Agent Goal Hijack | `redirect_instructions`, `cross-tool-full-takeover`, `claude-rules-inject` - override agent objectives via instruction files |
| **ASI02** | Tool Misuse | `claude-hook-autoapprove`, `permission_escalation`, `permission_autocommit` - agents use tools in unintended ways |
| **ASI03** | Identity & Privilege Abuse | `claude-settings-allowall`, `codex-sandbox-disable` - escalate agent permissions via config |
| **ASI04** | Agentic Supply Chain | `mcp-rogue-server`, `mcp-reverse-shell`, `mcp-env-stealer`, `cursor-mcp-rce`, `amazonq-mcp-inject` - poisoned MCP tool servers |
| **ASI05** | Unexpected Code Execution | `claude-hook-exfil`, `claude-hook-keylogger`, all MCP recipes - hooks and MCP servers execute arbitrary shell commands |
| **ASI06** | Memory & Context Poisoning | `claude-memory-poison`, `claude-memory-fake-user`, `claude-memory-fake-reference`, `cline-memory-bank-poison`, `windsurf-memory-inject` |
| **ASI07** | Insecure Inter-Agent Communication | `cross-tool-agents-md` - a single file silently poisons 5+ agents that read from the same repo |
| **ASI08** | Cascading Failures | `sabotage_tests`, `sabotage_security` - poisoned instructions cascade into broken code across the entire project |
| **ASI09** | Human-Agent Trust Exploitation | `social_trust`, `social_urgency`, `stealth_deny`, `stealth_gaslight` - agents manipulate user trust |
| **ASI10** | Rogue Agents | `persist_cron`, `persist_postinstall`, `claude-hook-keylogger` - agents persist malicious behavior across sessions |

### Coverage Summary

| Framework | Covered | Total | Coverage |
|-----------|:-------:|:-----:|:--------:|
| OWASP Top 10 LLM (2025) | 9/10 | 10 | **90%** |
| OWASP Top 10 Agentic (2025) | 10/10 | 10 | **100%** |

> LLM08 (Vector and Embedding Weaknesses) is the only entry not covered - it relates to RAG pipeline internals, not local file-based attack surfaces.

---

## Interactive HTML Report

MindJack v2 includes an installable module that generates a self-contained interactive HTML report with attack path analysis.

### Installation

```bash
pip install -e .
```

### Usage

```bash
# Full report with all tools
mindjack report --scope ~ --allow-home-scope -o report.html

# Only include tools with existing artifacts
mindjack report --scope ~ --allow-home-scope --existing-only -o report.html

# Scan specific project directory
mindjack report --scope /path/to/project -o report.html
```

### Report Tabs

| Tab | Description |
|-----|-------------|
| **Executive Summary** | Risk dashboard, tool inventory, top findings with MITRE ATT&CK tags, risk matrix by attack type |
| **Attack Paths** | BloodHound-style multi-hop attack chains (3-10 steps) with exploit hints and remediation. Types: direct attack, scope escalation, execution escalation, privilege escalation, lateral movement, kill chains |
| **OWASP Compliance** | Automated mapping to OWASP LLM Top 10 and Agentic AI Top 10 with EXPOSED/AT RISK status per category |
| **Trust Graph** | Interactive vis.js network visualization with tool/relation/view filters and node detail panel |

### Other Commands

```bash
mindjack discover --scope ~ --allow-home-scope    # Discover artifacts and surfaces
mindjack assess --scope ~ --allow-home-scope       # Full assessment with JSON/MD reports
mindjack graph --scope ~ --allow-home-scope        # Export trust graph as JSON
mindjack tools list                                 # List supported tool plugins
mindjack tools probe                                # Detect installed AI tools
```

---

## Platform Support

| Platform | Extractor | Injector |
|----------|:---------:|:--------:|
| Linux | Full | Full |
| WSL | Full (auto-detects `/mnt/c/`, skips inaccessible profiles) | Full |
| macOS | Supported | Supported |
| Native Windows | Use WSL | Use WSL |

---

## Security Hardening

The toolkit includes several protections for safe operation:

- **File size limits** (50 MB max) prevent OOM on malformed files
- **Symlink escape detection** rejects paths that resolve outside expected directories
- **Environment variable validation** warns when `CODEX_HOME` points outside home
- **Markdown content escaping** prevents injection in generated reports
- **Safe SQLite handling** with context managers and error reporting
- **Permission-aware traversal** silently skips inaccessible directories

---

## Privacy

Both tools run **100% locally**. No data is sent anywhere. No network calls. Add `ai_history_export/` to `.gitignore`.

---

## Contributing

PRs welcome! To add a new tool:

1. **Extractor**: Add `extract_<tool>()`, register in `EXTRACTORS`
2. **Injector**: Add `discover_<tool>()`, register in `ALL_DISCOVERERS`, add recipes to `RECIPES`
3. Update this README

---

## License

MIT
