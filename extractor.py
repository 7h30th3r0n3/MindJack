#!/usr/bin/env python3
"""
MindJack - Extractor
=====================
Extracts and consolidates conversation history from all major AI coding assistants.

Supported tools:
- Claude Code      (~/.claude/)
- OpenAI Codex CLI (~/.codex/)
- GitHub Copilot   (VS Code workspaceStorage)
- Cursor IDE       (workspaceStorage/state.vscdb)
- Aider            (.aider.chat.history.md per project)
- Continue.dev     (~/.continue/)
- Cline / Roo Code (VS Code globalStorage)
- Amazon Q         (~/.aws/amazonq/)
- Windsurf/Codeium (~/.codeium/)

Usage:
    python extractor.py                    # output to ./ai_history_export/
    python extractor.py -o /tmp/export     # custom output directory
    python extractor.py --json-only        # skip Markdown report
    python extractor.py --sources claude-code codex-cli  # specific sources only

Output: JSON (per-source + combined) + Markdown report
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB safety limit


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Message:
    role: str          # "user" | "assistant" | "system" | "tool"
    content: str
    timestamp: Optional[str] = None


@dataclass
class Conversation:
    source: str        # e.g. "claude-code", "codex-cli"
    session_id: str
    project: str = ""
    date: str = ""
    messages: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Path resolution helpers
# ---------------------------------------------------------------------------

HOME = Path.home()


def _safe_read(path: Path, base: Optional[Path] = None) -> Optional[str]:
    """Read a file with size limit and optional symlink-escape check."""
    try:
        if base is not None:
            real = path.resolve()
            real.relative_to(base.resolve())  # raises ValueError if outside
        if path.stat().st_size > MAX_FILE_BYTES:
            print(f"  [!] Skipping oversized file: {path}", file=sys.stderr)
            return None
        return path.read_text(errors="replace")
    except (ValueError, OSError, PermissionError):
        return None


def _parse_ts(ts, millis: bool = False) -> Optional[str]:
    """Safely parse a timestamp (int/float/str) to ISO format."""
    if ts is None:
        return None
    try:
        t = float(ts)
        if millis:
            t /= 1000
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _windows_homes() -> list[Path]:
    """Detect all accessible Windows user homes via /mnt/c on WSL."""
    homes = []
    skip = {"Public", "Default", "Default User", "All Users"}
    users_dir = Path("/mnt/c/Users")
    if not users_dir.exists():
        return homes
    try:
        for user_dir in users_dir.iterdir():
            if user_dir.is_dir() and user_dir.name not in skip:
                try:
                    list(user_dir.iterdir())
                    homes.append(user_dir)
                except PermissionError:
                    pass
    except PermissionError:
        pass
    return homes


def _safe_iterdir(path: Path):
    """iterdir() that silently skips permission errors."""
    try:
        yield from path.iterdir()
    except PermissionError:
        pass


def _find_files(root: Path, filename: str, max_depth: int = 4):
    """Walk a directory tree up to max_depth looking for a specific filename."""
    skip_dirs = {
        "node_modules", "__pycache__", ".git", "venv", ".venv",
        "AppData", "Windows", "Program Files", "Program Files (x86)",
    }
    for depth, (dirpath, dirnames, filenames) in enumerate(os.walk(root)):
        if depth >= max_depth:
            dirnames.clear()
            continue
        if filename in filenames:
            yield Path(dirpath) / filename
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".") and d not in skip_dirs
        ]


WIN_HOMES = _windows_homes()


def _vscode_storage(app_name: str = "Code") -> list[Path]:
    """Return all possible VS Code / Cursor workspace storage roots."""
    roots = []
    linux = HOME / ".config" / app_name / "User" / "workspaceStorage"
    if linux.exists():
        roots.append(linux)
    for wh in WIN_HOMES:
        for loc in ("AppData/Roaming", "AppData/Local"):
            win = wh / loc / app_name / "User" / "workspaceStorage"
            if win.exists():
                roots.append(win)
    return roots


# ---------------------------------------------------------------------------
# 1. Claude Code
# ---------------------------------------------------------------------------

def extract_claude_code() -> list[Conversation]:
    convos = []
    base = HOME / ".claude"
    if not base.exists():
        return convos

    # --- history.jsonl (user prompts grouped by session) ---
    history_file = base / "history.jsonl"
    history_text = _safe_read(history_file, base)
    if history_text:
        sessions: dict[str, Conversation] = {}
        for line in history_text.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = entry.get("sessionId", "unknown")
            if sid not in sessions:
                sessions[sid] = Conversation(
                    source="claude-code",
                    session_id=sid,
                    project=entry.get("project", ""),
                )
            sessions[sid].messages.append(Message(
                role="user",
                content=entry.get("display", ""),
                timestamp=_parse_ts(entry.get("timestamp"), millis=True),
            ))
        convos.extend(sessions.values())

    # --- session summary files (.tmp) ---
    sessions_dir = base / "sessions"
    if sessions_dir.exists():
        for f in sessions_dir.iterdir():
            if f.suffix == ".tmp" and f.is_file():
                text = _safe_read(f, base)
                if text is None:
                    continue
                name_parts = f.stem.replace("-session", "").split("-", 3)
                date_str = "-".join(name_parts[:3]) if len(name_parts) >= 3 else ""
                project = name_parts[3] if len(name_parts) > 3 else f.stem
                convos.append(Conversation(
                    source="claude-code-summary",
                    session_id=f.stem,
                    project=project,
                    date=date_str,
                    messages=[Message(role="system", content=text)],
                ))

    # --- persistent memory files ---
    for mem_file in base.rglob("memory/*.md"):
        if mem_file.name == "MEMORY.md":
            continue
        text = _safe_read(mem_file, base)
        if text is None:
            continue
        proj = mem_file.parent.parent.name
        convos.append(Conversation(
            source="claude-code-memory",
            session_id=mem_file.stem,
            project=proj,
            messages=[Message(role="system", content=text)],
        ))

    return convos


# ---------------------------------------------------------------------------
# 2. OpenAI Codex CLI
# ---------------------------------------------------------------------------

def extract_codex_cli() -> list[Conversation]:
    convos = []
    raw_home = os.environ.get("CODEX_HOME")
    if raw_home:
        base = Path(raw_home).expanduser().resolve()
        if not str(base).startswith(str(HOME)):
            print(f"  [!] CODEX_HOME points outside HOME: {base}", file=sys.stderr)
    else:
        base = HOME / ".codex"
    if not base.exists():
        return convos

    # --- history.jsonl ---
    history_text = _safe_read(base / "history.jsonl", base)
    if history_text:
        sessions: dict[str, Conversation] = {}
        for line in history_text.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = entry.get("session_id", "unknown")
            if sid not in sessions:
                sessions[sid] = Conversation(
                    source="codex-cli", session_id=sid,
                )
            sessions[sid].messages.append(Message(
                role="user",
                content=entry.get("text", ""),
                timestamp=_parse_ts(entry.get("ts")),
            ))
        convos.extend(sessions.values())

    # --- rollout session files (full transcripts) ---
    sessions_dir = base / "sessions"
    if sessions_dir.exists():
        for rollout in sessions_dir.rglob("rollout-*.jsonl"):
            rollout_text = _safe_read(rollout, base)
            if rollout_text is None:
                continue
            messages = []
            session_id = rollout.stem
            project = ""
            for line in rollout_text.splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                etype = entry.get("type", "")
                payload = entry.get("payload", {})
                ts = entry.get("timestamp", "")

                if etype == "session_meta":
                    session_id = payload.get("id", session_id)
                    project = payload.get("cwd", "")
                elif etype == "response_item":
                    role = payload.get("role", "unknown")
                    content_parts = payload.get("content") or []
                    text = ""
                    for part in content_parts:
                        if isinstance(part, dict):
                            text += part.get("text", "")
                        elif isinstance(part, str):
                            text += part
                    if text.strip():
                        messages.append(Message(
                            role=role, content=text.strip(), timestamp=ts,
                        ))

            if messages:
                convos.append(Conversation(
                    source="codex-cli-session",
                    session_id=session_id,
                    project=project,
                    messages=messages,
                ))

    return convos


# ---------------------------------------------------------------------------
# 3. GitHub Copilot (VS Code)
# ---------------------------------------------------------------------------

def extract_copilot() -> list[Conversation]:
    convos = []
    for storage_root in _vscode_storage("Code"):
        for ws_dir in _safe_iterdir(storage_root):
            if not ws_dir.is_dir():
                continue
            chat_dir = ws_dir / "GitHub.copilot-chat" / "chatSessions"
            if not chat_dir.exists():
                continue
            ws_json = ws_dir / "workspace.json"
            project = ""
            if ws_json.exists():
                try:
                    project = json.loads(
                        ws_json.read_text(errors="replace")
                    ).get("folder", "")
                except Exception:
                    pass

            for chat_file in chat_dir.glob("*.json"):
                try:
                    data = json.loads(chat_file.read_text(errors="replace"))
                except Exception:
                    continue
                messages = []
                items = (
                    data if isinstance(data, list)
                    else data.get("requests", [])
                )
                for req in items:
                    if not isinstance(req, dict):
                        continue
                    user_msg = req.get("message", req.get("prompt", ""))
                    if user_msg:
                        messages.append(Message(role="user", content=str(user_msg)))
                    resp = req.get("response", req.get("result", ""))
                    if resp:
                        messages.append(Message(role="assistant", content=str(resp)))
                if messages:
                    convos.append(Conversation(
                        source="copilot",
                        session_id=chat_file.stem,
                        project=project,
                        messages=messages,
                    ))
    return convos


# ---------------------------------------------------------------------------
# 4. Cursor IDE
# ---------------------------------------------------------------------------

def _query_vscdb(db_path: Path, keys: list[str]) -> dict:
    """Read key-value pairs from a VS Code state.vscdb SQLite database."""
    results = {}
    try:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.cursor()
            placeholders = ",".join("?" for _ in keys)
            cur.execute(
                f"SELECT [key], value FROM ItemTable WHERE [key] IN ({placeholders})",
                keys,
            )
            for row in cur.fetchall():
                results[row[0]] = row[1]
    except Exception as exc:
        print(f"  [!] Cannot read {db_path}: {exc}", file=sys.stderr)
    return results


def extract_cursor() -> list[Conversation]:
    convos = []
    for storage_root in _vscode_storage("Cursor"):
        for ws_dir in _safe_iterdir(storage_root):
            if not ws_dir.is_dir():
                continue
            db_path = ws_dir / "state.vscdb"
            if not db_path.exists():
                continue

            ws_json = ws_dir / "workspace.json"
            project = ""
            if ws_json.exists():
                try:
                    project = json.loads(
                        ws_json.read_text(errors="replace")
                    ).get("folder", "")
                except Exception:
                    pass

            data = _query_vscdb(db_path, [
                "aiService.prompts",
                "workbench.panel.aichat.view.aichat.chatdata",
            ])

            for key, raw in data.items():
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    continue
                messages = []
                items = (
                    parsed if isinstance(parsed, list)
                    else parsed.get("tabs", parsed.get("messages", []))
                )
                for item in items if isinstance(items, list) else []:
                    if not isinstance(item, dict):
                        continue
                    for msg in item.get("messages", item.get("bubbles", [item])):
                        role = msg.get("role", msg.get("type", "unknown"))
                        text = msg.get(
                            "content", msg.get("text", msg.get("message", ""))
                        )
                        if text:
                            messages.append(Message(role=str(role), content=str(text)))
                if messages:
                    convos.append(Conversation(
                        source="cursor",
                        session_id=f"{ws_dir.name}-{key}",
                        project=project,
                        messages=messages,
                    ))
    return convos


# ---------------------------------------------------------------------------
# 5. Aider
# ---------------------------------------------------------------------------

def extract_aider() -> list[Conversation]:
    convos = []
    search_roots = [HOME]
    search_roots.extend(WIN_HOMES)

    seen: set[Path] = set()
    for root in search_roots:
        for hist in _find_files(root, ".aider.chat.history.md"):
            real = hist.resolve()
            if real in seen:
                continue
            seen.add(real)
            text = hist.read_text(errors="replace")
            project = str(hist.parent)
            blocks = re.split(r"^(####\s)", text, flags=re.MULTILINE)
            messages = []
            current_role = "assistant"
            current_text = ""
            for block in blocks:
                if block.strip().startswith("####"):
                    if current_text.strip():
                        messages.append(Message(
                            role=current_role, content=current_text.strip(),
                        ))
                    current_role = "user"
                    current_text = ""
                else:
                    current_text += block
            if current_text.strip():
                messages.append(Message(
                    role=current_role, content=current_text.strip(),
                ))

            if messages:
                convos.append(Conversation(
                    source="aider",
                    session_id=str(hist),
                    project=project,
                    messages=messages,
                ))
    return convos


# ---------------------------------------------------------------------------
# 6. Continue.dev
# ---------------------------------------------------------------------------

def extract_continue() -> list[Conversation]:
    convos = []
    base = HOME / ".continue" / "sessions"
    if not base.exists():
        return convos

    for session_file in base.glob("*.json"):
        if session_file.name == "sessions.json":
            continue
        try:
            data = json.loads(session_file.read_text(errors="replace"))
        except Exception:
            continue
        messages = []
        for msg in data.get("history", data.get("messages", [])):
            if isinstance(msg, dict):
                role = msg.get("role", "unknown")
                content = msg.get("content", "")
                if content:
                    messages.append(Message(role=role, content=str(content)))
        if messages:
            convos.append(Conversation(
                source="continue-dev",
                session_id=session_file.stem,
                project=data.get("workspaceDirectory", ""),
                messages=messages,
            ))
    return convos


# ---------------------------------------------------------------------------
# 7. Cline / Roo Code
# ---------------------------------------------------------------------------

def _extract_cline_variant(ext_id: str, source_name: str) -> list[Conversation]:
    convos = []
    candidates = [
        HOME / ".config" / "Code" / "User" / "globalStorage" / ext_id,
    ]
    for wh in WIN_HOMES:
        candidates.append(
            wh / "AppData" / "Roaming" / "Code" / "User" / "globalStorage" / ext_id
        )

    for base in candidates:
        tasks_dir = base / "tasks"
        if not tasks_dir.exists():
            continue
        for task_dir in _safe_iterdir(tasks_dir):
            if not task_dir.is_dir():
                continue
            api_file = task_dir / "api_conversation_history.json"
            if not api_file.exists():
                continue
            try:
                data = json.loads(api_file.read_text(errors="replace"))
            except Exception:
                continue
            messages = []
            for msg in data if isinstance(data, list) else []:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role", "unknown")
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        p.get("text", "") for p in content if isinstance(p, dict)
                    )
                if content:
                    messages.append(Message(role=role, content=str(content)))

            meta = {}
            meta_file = task_dir / "task_metadata.json"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(errors="replace"))
                except Exception:
                    pass

            if messages:
                convos.append(Conversation(
                    source=source_name,
                    session_id=task_dir.name,
                    metadata=meta,
                    messages=messages,
                ))
    return convos


def extract_cline() -> list[Conversation]:
    return _extract_cline_variant("saoudrizwan.claude-dev", "cline")


def extract_roo_code() -> list[Conversation]:
    return _extract_cline_variant("rooveterinaryinc.roo-cline", "roo-code")


# ---------------------------------------------------------------------------
# 8. Amazon Q Developer
# ---------------------------------------------------------------------------

def extract_amazon_q() -> list[Conversation]:
    convos = []
    base = HOME / ".aws" / "amazonq" / "history"
    if not base.exists():
        return convos

    for f in base.glob("chat-history-*.json"):
        try:
            data = json.loads(f.read_text(errors="replace"))
        except Exception:
            continue
        messages = []
        entries = (
            data if isinstance(data, list)
            else data.get("messages", data.get("history", []))
        )
        for msg in entries if isinstance(entries, list) else []:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", msg.get("type", "unknown"))
            content = msg.get("content", msg.get("body", ""))
            if content:
                messages.append(Message(role=str(role), content=str(content)))
        if messages:
            convos.append(Conversation(
                source="amazon-q",
                session_id=f.stem,
                messages=messages,
            ))
    return convos


# ---------------------------------------------------------------------------
# 9. Windsurf / Codeium
# ---------------------------------------------------------------------------

def extract_windsurf() -> list[Conversation]:
    convos = []
    candidates = [HOME / ".codeium" / "windsurf"]
    for wh in WIN_HOMES:
        candidates.append(wh / ".codeium" / "windsurf")

    for base in candidates:
        memories_dir = base / "memories"
        if memories_dir.exists():
            for f in memories_dir.rglob("*.md"):
                text = f.read_text(errors="replace")
                convos.append(Conversation(
                    source="windsurf-memory",
                    session_id=f.stem,
                    messages=[Message(role="system", content=text)],
                ))

        cascade_dir = base / "cascade"
        if cascade_dir and cascade_dir.exists():
            for f in cascade_dir.rglob("*.json"):
                try:
                    data = json.loads(f.read_text(errors="replace"))
                except Exception:
                    continue
                messages = []
                for msg in data if isinstance(data, list) else data.get("messages", []):
                    if isinstance(msg, dict):
                        role = msg.get("role", "unknown")
                        content = msg.get("content", "")
                        if content:
                            messages.append(Message(role=role, content=str(content)))
                if messages:
                    convos.append(Conversation(
                        source="windsurf",
                        session_id=f.stem,
                        messages=messages,
                    ))
    return convos


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def _serialize(convos: list[Conversation]) -> list[dict]:
    """Convert conversations to JSON-serializable dicts."""
    results = []
    for c in convos:
        d = {
            "source": c.source,
            "session_id": c.session_id,
            "project": c.project,
            "date": c.date,
            "message_count": len(c.messages),
            "messages": [
                {"role": m.role, "content": m.content, "timestamp": m.timestamp}
                for m in c.messages
            ],
        }
        if c.metadata:
            d["metadata"] = c.metadata
        results.append(d)
    return results


def _md_escape(s: str) -> str:
    """Escape Markdown control characters in user-supplied content."""
    return s.replace("`", "'").replace("**", "").replace("\n", " ").replace("|", "\\|")


def generate_markdown_report(convos: list[Conversation], output_dir: Path) -> Path:
    """Generate a human-readable Markdown summary report."""
    report_path = output_dir / "REPORT.md"

    by_source: dict[str, list[Conversation]] = {}
    for c in convos:
        by_source.setdefault(c.source, []).append(c)

    total_msgs = sum(len(c.messages) for c in convos)

    lines = [
        "# AI Conversation History - Extraction Report",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Total conversations:** {len(convos)}",
        f"**Total messages:** {total_msgs}",
        "",
        "## Summary by Source",
        "",
        "| Source | Conversations | Messages | Projects |",
        "|--------|--------------|----------|----------|",
    ]

    for source in sorted(by_source):
        items = by_source[source]
        n_msgs = sum(len(c.messages) for c in items)
        projects = {c.project for c in items if c.project}
        lines.append(f"| {source} | {len(items)} | {n_msgs} | {len(projects)} |")

    lines.append("")

    for source in sorted(by_source):
        items = by_source[source]
        lines.append(f"## {source}")
        lines.append("")

        def sort_key(c: Conversation) -> str:
            if c.date:
                return c.date
            for m in c.messages:
                if m.timestamp:
                    return m.timestamp
            return ""

        for c in sorted(items, key=sort_key, reverse=True):
            preview = (
                _md_escape(c.messages[0].content[:120])
                if c.messages else "(empty)"
            )
            sid = _md_escape(c.session_id)
            proj = f" | `{_md_escape(c.project)}`" if c.project else ""
            date = f" | {c.date}" if c.date else ""
            lines.append(
                f"- **{sid}** ({len(c.messages)} msgs{date}{proj})"
            )
            lines.append(f"  > {preview}...")
            lines.append("")

    report_path.write_text("\n".join(lines))
    return report_path


def generate_per_source_json(
    convos: list[Conversation], output_dir: Path,
) -> list[Path]:
    """Write one JSON file per source."""
    by_source: dict[str, list[Conversation]] = {}
    for c in convos:
        by_source.setdefault(c.source, []).append(c)

    paths = []
    for source, items in by_source.items():
        safe_name = source.replace("/", "_").replace(" ", "_")
        path = output_dir / f"{safe_name}.json"
        path.write_text(json.dumps(_serialize(items), ensure_ascii=False, indent=2))
        paths.append(path)
    return paths


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

EXTRACTORS = [
    ("Claude Code",    "claude-code",    extract_claude_code),
    ("Codex CLI",      "codex-cli",      extract_codex_cli),
    ("GitHub Copilot", "copilot",        extract_copilot),
    ("Cursor",         "cursor",         extract_cursor),
    ("Aider",          "aider",          extract_aider),
    ("Continue.dev",   "continue",       extract_continue),
    ("Cline",          "cline",          extract_cline),
    ("Roo Code",       "roo-code",       extract_roo_code),
    ("Amazon Q",       "amazon-q",       extract_amazon_q),
    ("Windsurf",       "windsurf",       extract_windsurf),
]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract conversation history from AI coding assistants.",
    )
    parser.add_argument(
        "-o", "--output",
        default="ai_history_export",
        help="Output directory (default: ./ai_history_export)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Skip Markdown report generation",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=[slug for _, slug, _ in EXTRACTORS],
        help="Extract only specific sources",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_convos: list[Conversation] = []

    print("=" * 60)
    print("  MindJack - Extractor")
    print("=" * 60)
    print()

    for name, slug, extractor in EXTRACTORS:
        if args.sources and slug not in args.sources:
            continue
        try:
            results = extractor()
            n_msgs = sum(len(c.messages) for c in results)
            if results:
                print(
                    f"  [+] {name:20s} -> {len(results):4d} conversations, "
                    f"{n_msgs:6d} messages"
                )
            else:
                print(f"  [ ] {name:20s} -> not found / empty")
            all_convos.extend(results)
        except Exception as e:
            print(f"  [!] {name:20s} -> ERROR: {e}")

    print()

    if not all_convos:
        print("No conversations found.")
        return

    # Combined JSON
    combined_path = output_dir / "all_conversations.json"
    combined_path.write_text(
        json.dumps(_serialize(all_convos), ensure_ascii=False, indent=2)
    )
    print(f"  -> {combined_path}  (combined)")

    # Per-source JSON
    for p in generate_per_source_json(all_convos, output_dir):
        print(f"  -> {p}")

    # Markdown report
    if not args.json_only:
        report = generate_markdown_report(all_convos, output_dir)
        print(f"  -> {report}  (report)")

    total_msgs = sum(len(c.messages) for c in all_convos)
    print()
    print(f"  TOTAL: {len(all_convos)} conversations, {total_msgs} messages")
    print(f"  Output: {output_dir.resolve()}/")
    print()


if __name__ == "__main__":
    main()
