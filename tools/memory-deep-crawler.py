#!/usr/bin/env python3
"""memory-deep-crawler.py — Deep-memory crawler for the Obsidian vault.

Crawls authorized external memory sources and emits new vault note categories:
  - obsidian-vault/external-memory/claude/   — mirrors of ~/.claude/.../memory/
  - obsidian-vault/external-memory/codex/    — Codex rules + session index
  - obsidian-vault/routines/                 — ~/.claude/scheduled-tasks/ SKILL.md files
  - obsidian-vault/commits/                  — git log last 30 days (cap 200)
  - obsidian-vault/prs/                      — GitHub PR list (limit 50)
  - obsidian-vault/tools-api/                — per-tool docstrings from tools/*.py
  - obsidian-vault/make-targets/INDEX.md     — Makefile target index
  - obsidian-vault/workspaces/<ws>/state.md  — per-workspace state expansion
  - obsidian-vault/errors/                   — /private/tmp/auditooor-inventory/ log errors

Idempotent and incremental: tracks per-source mtime in vault/.deep_sync.json.
Vault size hard cap: 30 MB total. Stops writing when cap is hit.
Secret redaction: filters private_key, mnemonic, seed_phrase, clob_creds patterns.

Usage:
    python3 tools/memory-deep-crawler.py [--vault-dir <path>] [--force] [--dry-run]
    python3 tools/memory-deep-crawler.py --section <name>  # run one section only
    python3 tools/memory-deep-crawler.py --status          # show staleness only

Sections: claude-memory, codex-memory, routines, commits, prs, tools-api,
          make-targets, workspaces, errors
"""
from __future__ import annotations

import argparse
import ast
import datetime as _dt
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
TOOLS_DIR = REPO_ROOT / "tools"
MAKEFILE = REPO_ROOT / "Makefile"
AUDITS_ROOT = Path.home() / "audits"
CLAUDE_MEMORY_DIR = (
    Path.home()
    / ".claude"
    / "projects"
    / "-Users-wolf-Downloads-GTO-WEBSITE-proper-installation-polymarket-clob2"
    / "memory"
)
CODEX_DIR = Path.home() / ".codex"
SCHEDULED_TASKS_DIR = Path.home() / ".claude" / "scheduled-tasks"
INVENTORY_DIR = Path("/private/tmp/auditooor-inventory")
GIT_LOG_CACHE_DIR = Path(os.environ.get("TMPDIR") or "/tmp")


def _git_log_cache_path(repo_root: Path) -> Path:
    repo_key = hashlib.sha256(str(repo_root.resolve()).encode("utf-8")).hexdigest()[:16]
    return GIT_LOG_CACHE_DIR / f"auditooor-git-log-30d-{repo_key}.txt"


GIT_LOG_CACHE = _git_log_cache_path(REPO_ROOT)

# 30 MB total vault cap
VAULT_BYTE_CAP = 30 * 1024 * 1024
VAULT_WRITES_ENABLED = True

# Secret patterns to redact (not expose in vault)
SECRET_PATTERNS = [
    re.compile(r'(?i)(private[_\s]?key|mnemonic|seed[_\s]?phrase|clob[_\s]?cred|api[_\s]?secret)[^\n]*'),
    re.compile(r'\b(?:sk|xai|ak)[_-][A-Za-z0-9_-]{20,}\b'),
    re.compile(r'0x[0-9a-fA-F]{40,}'),  # hex addresses/keys — redact long ones (>40 chars = likely key)
]
# But allow short ethereum addresses (40 hex chars) — only redact longer ones
SECRET_PATTERNS[2] = re.compile(r'0x[0-9a-fA-F]{64,}')  # Only 64+ hex = private key length

NOW_ISO = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, redaction_count)."""
    count = 0
    for pat in SECRET_PATTERNS:
        matches = pat.findall(text)
        if matches:
            count += len(matches)
            text = pat.sub("[REDACTED]", text)
    return text, count


def _safe_write(path: Path, content: str, byte_counter: list[int], cap: int) -> bool:
    """Write if under cap. Returns True on success."""
    encoded = content.encode("utf-8")
    if byte_counter[0] + len(encoded) > cap:
        return False
    if VAULT_WRITES_ENABLED:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    byte_counter[0] += len(encoded)
    return True


def _frontmatter(**kwargs) -> str:
    lines = ["---"]
    for k, v in kwargs.items():
        if isinstance(v, list):
            lines.append(f"{k}:")
            for item in v:
                lines.append(f"  - {item}")
        else:
            lines.append(f"{k}: {v!r}")
    lines.append("---")
    return "\n".join(lines) + "\n\n"


def _load_deep_sync(vault_dir: Path) -> dict:
    p = vault_dir / ".deep_sync.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _save_deep_sync(vault_dir: Path, state: dict) -> None:
    p = vault_dir / ".deep_sync.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2))


def _source_mtime(paths: list[Path]) -> float:
    """Max mtime across a list of paths (missing = 0)."""
    mtimes = []
    for p in paths:
        try:
            mtimes.append(p.stat().st_mtime)
        except FileNotFoundError:
            pass
    return max(mtimes, default=0.0)


# ---------------------------------------------------------------------------
# Section 1: Claude memory mirror
# ---------------------------------------------------------------------------

def crawl_claude_memory(vault_dir: Path, byte_counter: list[int], force: bool = False,
                         sync_state: dict = {}) -> tuple[int, int]:
    """Mirror all Claude memory files into external-memory/claude/."""
    out_dir = vault_dir / "external-memory" / "claude"
    written = 0
    redacted_total = 0

    if not CLAUDE_MEMORY_DIR.exists():
        print(f"  [claude-memory] Source missing: {CLAUDE_MEMORY_DIR}")
        return 0, 0

    source_mtime = _source_mtime(list(CLAUDE_MEMORY_DIR.iterdir()))
    last_sync = sync_state.get("claude-memory", 0.0)
    if not force and source_mtime <= last_sync:
        print(f"  [claude-memory] Up to date (mtime={source_mtime:.0f})")
        return 0, 0

    for src_path in sorted(CLAUDE_MEMORY_DIR.glob("*.md")):
        fname = src_path.name
        content_raw = src_path.read_text(encoding="utf-8", errors="replace")
        content, redact_count = _redact(content_raw)
        redacted_total += redact_count

        # Determine tag based on filename
        if fname.startswith("feedback_"):
            topic_tag = "#topic/" + fname.replace("feedback_", "").replace(".md", "").replace("_", "-")
            tags = ["memory/claude/feedback", topic_tag]
        elif fname.startswith("auditooor_"):
            tags = ["memory/claude/session", "#topic/auditooor-session"]
        elif fname == "MEMORY.md":
            tags = ["memory/claude/index"]
        elif fname.startswith("m14"):
            tags = ["memory/claude/discipline", "#topic/m14-trap"]
        elif fname.startswith("base_azul"):
            tags = ["memory/claude/engagement", "#topic/base-azul"]
        elif fname.startswith("morpho") or fname.startswith("solodit"):
            tags = ["memory/claude/engagement", "#topic/" + fname.replace(".md", "")]
        elif fname.startswith("session_"):
            tags = ["memory/claude/session-state", "#topic/session-pickup"]
        else:
            tags = ["memory/claude/misc"]

        fm = _frontmatter(
            source="claude-memory",
            last_synced=NOW_ISO,
            canonical_path=str(src_path),
            tags=tags,
        )
        note = fm + content
        if _safe_write(out_dir / fname, note, byte_counter, VAULT_BYTE_CAP):
            written += 1

    sync_state["claude-memory"] = source_mtime
    print(f"  [claude-memory] Wrote {written} notes, redacted {redacted_total} secrets")
    return written, redacted_total


# ---------------------------------------------------------------------------
# Section 2: Codex memory mirror
# ---------------------------------------------------------------------------

def crawl_codex_memory(vault_dir: Path, byte_counter: list[int], force: bool = False,
                        sync_state: dict = {}) -> tuple[int, int]:
    """Mirror Codex rules + session index into external-memory/codex/."""
    out_dir = vault_dir / "external-memory" / "codex"
    written = 0
    redacted_total = 0

    if not CODEX_DIR.exists():
        print(f"  [codex-memory] ~/.codex/ does not exist — skipping (honest: no Codex memory found)")
        return 0, 0

    # Source 1: default.rules (permission rules Codex has learned)
    rules_path = CODEX_DIR / "rules" / "default.rules"
    if rules_path.exists():
        raw = rules_path.read_text(encoding="utf-8", errors="replace")
        content, rc = _redact(raw)
        redacted_total += rc
        # Parse rules into readable lines
        rules_lines = [line.strip() for line in content.splitlines() if line.strip()]
        rules_summary = "\n".join(f"- `{line}`" for line in rules_lines[:80])
        if len(rules_lines) > 80:
            rules_summary += f"\n\n_(truncated — {len(rules_lines) - 80} more rules)_"

        fm = _frontmatter(
            source="codex-memory",
            last_synced=NOW_ISO,
            canonical_path=str(rules_path),
            rule_count=len(rules_lines),
            tags=["memory/codex/rules", "#topic/codex-permissions"],
        )
        note = fm + "# Codex Permission Rules\n\nThese are `prefix_rule` + `always_deny` entries Codex has learned from prior sessions.\n\n" + rules_summary
        if _safe_write(out_dir / "default-rules.md", note, byte_counter, VAULT_BYTE_CAP):
            written += 1

    # Source 2: session_index.jsonl — emit summary index
    session_index = CODEX_DIR / "session_index.jsonl"
    if session_index.exists():
        sessions = []
        raw = session_index.read_text(encoding="utf-8", errors="replace")
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                sessions.append(d)
            except Exception:
                pass

        # Emit an index note
        rows = []
        for s in sessions[-200:]:  # last 200 sessions
            sid = s.get("id", "?")[:8]
            name, rc = _redact(s.get("thread_name", "?"))
            redacted_total += rc
            updated = s.get("updated_at", "?")[:10]
            rows.append(f"| `{sid}` | {name[:80]} | {updated} |")

        table = "| Session ID | Thread Name | Updated |\n|---|---|---|\n" + "\n".join(rows)
        fm = _frontmatter(
            source="codex-memory",
            last_synced=NOW_ISO,
            total_sessions=len(sessions),
            canonical_path=str(session_index),
            tags=["memory/codex/sessions", "#topic/codex-history"],
        )
        note = fm + f"# Codex Session Index\n\nTotal sessions: **{len(sessions)}**. Showing last 200.\n\n" + table
        if _safe_write(out_dir / "session-index.md", note, byte_counter, VAULT_BYTE_CAP):
            written += 1

    # Source 3: individual session notes (last 400 sessions → one note each)
    if session_index.exists():
        sessions_dir = out_dir / "sessions"
        all_sessions: list[dict] = []
        raw2 = session_index.read_text(encoding="utf-8", errors="replace")
        for line in raw2.splitlines():
            if not line.strip():
                continue
            try:
                all_sessions.append(json.loads(line))
            except Exception:
                pass

        # emit last 400 sessions as individual notes
        for s in all_sessions[-400:]:
            sid = s.get("id", "unknown")
            short_id = sid[:8]
            name_raw = s.get("thread_name", "unknown session")
            name, rc2 = _redact(name_raw)
            redacted_total += rc2
            updated = s.get("updated_at", "")
            date_str = updated[:10] if updated else "unknown"

            fm2 = _frontmatter(
                source="codex-session",
                session_id=sid,
                thread_name=name,
                updated_at=updated,
                date=date_str,
                last_synced=NOW_ISO,
                tags=["memory/codex/session", f"#codex-session/{date_str[:7]}"],
            )
            note2 = fm2 + f"# Codex Session: {name}\n\n"
            note2 += f"**Session ID:** `{sid}`\n**Updated:** {updated}\n"

            if _safe_write(sessions_dir / f"{short_id}.md", note2, byte_counter, VAULT_BYTE_CAP):
                written += 1

    sync_state["codex-memory"] = _source_mtime([CODEX_DIR / "rules" / "default.rules",
                                                  CODEX_DIR / "session_index.jsonl"])
    print(f"  [codex-memory] Wrote {written} notes, redacted {redacted_total} secrets")
    return written, redacted_total


# ---------------------------------------------------------------------------
# Section 3: Scheduled tasks / routines
# ---------------------------------------------------------------------------

def crawl_routines(vault_dir: Path, byte_counter: list[int], force: bool = False,
                   sync_state: dict = {}) -> int:
    """Emit each scheduled-task SKILL.md into routines/<task-id>.md."""
    out_dir = vault_dir / "routines"
    written = 0

    if not SCHEDULED_TASKS_DIR.exists():
        print(f"  [routines] {SCHEDULED_TASKS_DIR} does not exist — skipping")
        return 0

    source_mtime = _source_mtime([SCHEDULED_TASKS_DIR])
    last_sync = sync_state.get("routines", 0.0)
    if not force and source_mtime <= last_sync:
        print(f"  [routines] Up to date")
        return 0

    for task_dir in sorted(SCHEDULED_TASKS_DIR.iterdir()):
        if not task_dir.is_dir():
            continue
        skill_path = task_dir / "SKILL.md"
        if not skill_path.exists():
            continue

        task_id = task_dir.name
        content = skill_path.read_text(encoding="utf-8", errors="replace")

        # Extract frontmatter fields from SKILL.md header
        name_match = re.search(r'^name:\s*(.+)$', content, re.MULTILINE)
        desc_match = re.search(r'^description:\s*(.+)$', content, re.MULTILINE)
        skill_name = name_match.group(1).strip() if name_match else task_id
        skill_desc = desc_match.group(1).strip() if desc_match else ""

        # Tag by content
        if "30" in skill_desc or "30 min" in content:
            cron_tag = "#routine/cron-30m"
        elif "2 min" in content or "2 MINUTES" in content:
            cron_tag = "#routine/cron-2m"
        elif "hourly" in task_id:
            cron_tag = "#routine/cron-hourly"
        else:
            cron_tag = "#routine/cron-misc"

        fm = _frontmatter(
            source="scheduled-task",
            task_id=task_id,
            skill_name=skill_name,
            description=skill_desc,
            last_synced=NOW_ISO,
            canonical_path=str(skill_path),
            tags=["routine/scheduled-task", cron_tag, "#routine/auditooor"],
        )
        note = fm + content
        if _safe_write(out_dir / f"{task_id}.md", note, byte_counter, VAULT_BYTE_CAP):
            written += 1

    sync_state["routines"] = source_mtime
    print(f"  [routines] Wrote {written} notes")
    return written


# ---------------------------------------------------------------------------
# Section 4: Git commit history
# ---------------------------------------------------------------------------

def crawl_commits(vault_dir: Path, byte_counter: list[int], force: bool = False,
                  sync_state: dict = {}, cap: int = 200, dry_run: bool = False) -> int:
    """Emit one note per commit (capped at 200) into commits/<short-sha>.md."""
    out_dir = vault_dir / "commits"
    written = 0

    # Regenerate log file if needed
    if not GIT_LOG_CACHE.exists() or force:
        result = subprocess.run(
            ["git", "log", "--all", "--since=30 days ago",
             "--pretty=format:%H|%aI|%an|%s"],
            capture_output=True, text=True, cwd=REPO_ROOT
        )
        if result.returncode != 0:
            print(f"  [commits] git log failed: {result.stderr[:200]}")
            return 0
        if dry_run:
            log_text = result.stdout
        else:
            GIT_LOG_CACHE.parent.mkdir(parents=True, exist_ok=True)
            GIT_LOG_CACHE.write_text(result.stdout)
            log_text = result.stdout
    else:
        log_text = GIT_LOG_CACHE.read_text()

    lines = log_text.splitlines()
    total = len(lines)
    capped = total > cap
    # Take newest `cap` commits (file is ordered newest-first)
    lines = lines[:cap]

    for line in lines:
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue
        sha, date, author, subject = parts
        short_sha = sha[:8]

        # Extract PR reference from subject
        pr_refs = re.findall(r'#(\d+)', subject)
        pr_wikilinks = " ".join(f"[[prs/{n}]]" for n in pr_refs) if pr_refs else ""

        fm = _frontmatter(
            sha=sha,
            short_sha=short_sha,
            author=author,
            date=date[:10],
            datetime=date,
            last_synced=NOW_ISO,
            tags=["commit/git", f"#commit/{date[:7]}"],
        )
        body = f"# {subject}\n\n"
        if pr_wikilinks:
            body += f"**Referenced PRs:** {pr_wikilinks}\n\n"
        body += f"```\nsha:    {sha}\ndate:   {date}\nauthor: {author}\n```\n"

        if _safe_write(out_dir / f"{short_sha}.md", body, byte_counter, VAULT_BYTE_CAP):
            written += 1

    cap_notice = f" (capped at {cap}; {total} total in 30d)" if capped else f" ({total} total)"
    if not dry_run:
        sync_state["commits"] = _dt.datetime.now().timestamp()
    action = "Would write" if dry_run else "Wrote"
    print(f"  [commits] {action} {written} notes{cap_notice}")
    return written


# ---------------------------------------------------------------------------
# Section 5: GitHub PRs
# ---------------------------------------------------------------------------

def crawl_prs(vault_dir: Path, byte_counter: list[int], force: bool = False,
              sync_state: dict = {}) -> int:
    """Emit one note per PR into prs/<number>.md."""
    out_dir = vault_dir / "prs"
    written = 0

    result = subprocess.run(
        ["gh", "pr", "list", "--state", "all", "--limit", "50",
         "--json", "number,title,state,mergedAt,headRefName,body,labels"],
        capture_output=True, text=True, cwd=REPO_ROOT
    )
    if result.returncode != 0:
        print(f"  [prs] gh pr list failed: {result.stderr[:200]}")
        return 0

    try:
        prs = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  [prs] JSON parse error")
        return 0

    for pr in prs:
        number = pr.get("number", 0)
        title = pr.get("title", "")
        state = pr.get("state", "")
        merged_at = pr.get("mergedAt") or ""
        branch = pr.get("headRefName", "")
        labels = [lbl.get("name", "") for lbl in pr.get("labels", [])]
        body_raw = pr.get("body") or ""
        body_text, _ = _redact(body_raw[:1000])  # first 1000 chars of PR body

        # Extract commit SHAs mentioned in body
        commit_refs = re.findall(r'\b([0-9a-f]{7,8})\b', body_text)
        commit_wikilinks = " ".join(f"[[commits/{c}]]" for c in commit_refs[:5]) if commit_refs else ""

        fm = _frontmatter(
            pr_number=number,
            title=title,
            state=state,
            merged_at=merged_at[:10] if merged_at else "",
            branch=branch,
            labels=labels if labels else ["none"],
            last_synced=NOW_ISO,
            tags=["pr/github", f"#pr/{state.lower()}"],
        )
        note = fm + f"# PR #{number}: {title}\n\n"
        note += f"**State:** {state}  **Branch:** `{branch}`"
        if merged_at:
            note += f"  **Merged:** {merged_at[:10]}"
        note += "\n\n"
        if commit_wikilinks:
            note += f"**Referenced commits:** {commit_wikilinks}\n\n"
        if body_text.strip():
            note += f"## Description\n\n{body_text}\n"
        if len(body_raw) > 1000:
            note += f"\n_(body truncated at 1000 chars; full text at GitHub PR #{number})_\n"

        if _safe_write(out_dir / f"{number}.md", note, byte_counter, VAULT_BYTE_CAP):
            written += 1

    sync_state["prs"] = _dt.datetime.now().timestamp()
    print(f"  [prs] Wrote {written} notes")
    return written


# ---------------------------------------------------------------------------
# Section 6: Tools API (docstrings)
# ---------------------------------------------------------------------------

def crawl_tools_api(vault_dir: Path, byte_counter: list[int], force: bool = False,
                    sync_state: dict = {}) -> tuple[int, int]:
    """Emit per-tool docstring notes into tools-api/<name>.md."""
    out_dir = vault_dir / "tools-api"
    written = 0
    skipped_no_docstring = 0

    py_files = sorted(TOOLS_DIR.glob("*.py"))
    source_mtime = _source_mtime(py_files)
    last_sync = sync_state.get("tools-api", 0.0)
    if not force and source_mtime <= last_sync:
        print(f"  [tools-api] Up to date")
        return 0, 0

    for py_path in py_files:
        try:
            src = py_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
            docstring = ast.get_docstring(tree)
        except SyntaxError:
            skipped_no_docstring += 1
            continue

        if not docstring:
            skipped_no_docstring += 1
            continue

        tool_name = py_path.stem
        has_main = "if __name__" in src or "def main(" in src
        has_argparse = "argparse" in src
        last_mod = _dt.datetime.fromtimestamp(py_path.stat().st_mtime,
                                               tz=_dt.timezone.utc).strftime("%Y-%m-%d")

        # Infer category from name
        if "vault" in tool_name:
            cat = "vault"
        elif "obsidian" in tool_name:
            cat = "vault"
        elif "wirer" in tool_name or "wire" in tool_name:
            cat = "wirer"
        elif "submission" in tool_name or "submit" in tool_name:
            cat = "submission"
        elif "detector" in tool_name or "slither" in tool_name:
            cat = "detector"
        elif "pattern" in tool_name:
            cat = "pattern"
        elif "workspace" in tool_name or "engage" in tool_name:
            cat = "workspace"
        elif "semantic" in tool_name:
            cat = "semantic"
        elif "invariant" in tool_name or "harness" in tool_name:
            cat = "harness"
        elif "agent" in tool_name or "dispatch" in tool_name:
            cat = "agent"
        elif "scan" in tool_name or "audit" in tool_name:
            cat = "scanner"
        elif "zkbugs" in tool_name or "cairo" in tool_name or "cosmos" in tool_name:
            cat = "polyglot"
        elif "obsidian" in tool_name or "calibration" in tool_name:
            cat = "calibration"
        else:
            cat = "misc"

        fm = _frontmatter(
            source="tools-api",
            tool_name=tool_name,
            tool_path=str(py_path.relative_to(REPO_ROOT)),
            has_main=has_main,
            has_argparse=has_argparse,
            last_modified=last_mod,
            last_synced=NOW_ISO,
            tags=[f"tool-api/{cat}", "#tool-api/python"],
        )
        note = fm + f"# `{tool_name}`\n\n```\n{docstring}\n```\n"
        if _safe_write(out_dir / f"{tool_name}.md", note, byte_counter, VAULT_BYTE_CAP):
            written += 1

    sync_state["tools-api"] = source_mtime
    print(f"  [tools-api] Wrote {written} notes, skipped {skipped_no_docstring} (no/unparseable docstring)")
    return written, skipped_no_docstring


# ---------------------------------------------------------------------------
# Section 7: Makefile targets index
# ---------------------------------------------------------------------------

def crawl_make_targets(vault_dir: Path, byte_counter: list[int], force: bool = False,
                        sync_state: dict = {}) -> int:
    """Parse Makefile and emit INDEX.md into make-targets/."""
    out_dir = vault_dir / "make-targets"
    written = 0

    if not MAKEFILE.exists():
        print(f"  [make-targets] Makefile not found")
        return 0

    source_mtime = _source_mtime([MAKEFILE])
    last_sync = sync_state.get("make-targets", 0.0)
    if not force and source_mtime <= last_sync:
        print(f"  [make-targets] Up to date")
        return 0

    mk_text = MAKEFILE.read_text(encoding="utf-8", errors="replace")

    # Extract .PHONY declarations
    phony_targets: set[str] = set()
    for m in re.finditer(r'^\.PHONY:\s*(.+)$', mk_text, re.MULTILINE):
        phony_targets.update(m.group(1).split())

    # Extract target → first command lines
    target_pat = re.compile(r'^([\w][\w\-\.]*)\s*:((?:[^=\n][^\n]*)?)\n((?:[\t][^\n]*\n)*)', re.MULTILINE)
    rows = []
    seen: set[str] = set()
    for m in target_pat.finditer(mk_text):
        name = m.group(1)
        deps = m.group(2).strip()
        cmds_raw = m.group(3).strip()
        cmds = [line.strip().lstrip("@") for line in cmds_raw.splitlines() if line.strip()]
        cmd_preview = cmds[0][:120] if cmds else ""
        if name not in seen:
            seen.add(name)
            rows.append((name, deps[:80], cmd_preview))

    # Sort alphabetically
    rows.sort(key=lambda r: r[0])

    table_lines = ["| Target | Dependencies | First Command |", "|---|---|---|"]
    for name, deps, cmd in rows:
        table_lines.append(f"| `{name}` | `{deps}` | `{cmd}` |")

    fm = _frontmatter(
        source="makefile",
        target_count=len(rows),
        phony_count=len(phony_targets),
        last_synced=NOW_ISO,
        tags=["make-targets/index", "#make-targets/makefile"],
    )
    content = fm + f"# Makefile Targets Index\n\n**{len(rows)} targets** ({len(phony_targets)} declared .PHONY).\n\n"
    content += "\n".join(table_lines) + "\n"

    if _safe_write(out_dir / "INDEX.md", content, byte_counter, VAULT_BYTE_CAP):
        written += 1

    sync_state["make-targets"] = source_mtime
    print(f"  [make-targets] Wrote INDEX.md ({len(rows)} targets)")
    return written


# ---------------------------------------------------------------------------
# Section 8: Workspace state ingestion
# ---------------------------------------------------------------------------

def crawl_workspaces(vault_dir: Path, byte_counter: list[int], force: bool = False,
                      sync_state: dict = {}) -> int:
    """Expand per-workspace vault notes with .auditooor-state.yaml + submissions."""
    written = 0

    if not AUDITS_ROOT.exists():
        print(f"  [workspaces] {AUDITS_ROOT} not found")
        return 0

    workspaces = [d for d in sorted(AUDITS_ROOT.iterdir())
                  if d.is_dir() and not d.name.startswith(".") and not d.name.startswith("_")]

    for ws_dir in workspaces:
        ws_name = ws_dir.name
        state_file = ws_dir / ".auditooor-state.yaml"
        submissions_md = ws_dir / ".auditooor" / "SUBMISSIONS.md"

        sources = [p for p in [state_file, submissions_md] if p.exists()]
        if not sources:
            continue

        source_mtime = _source_mtime(sources)
        last_sync = sync_state.get(f"workspaces/{ws_name}", 0.0)
        if not force and source_mtime <= last_sync:
            continue

        out_dir = vault_dir / "workspaces" / ws_name
        note_path = out_dir / "state.md"

        # Parse state YAML (simple key-value)
        state_data: dict[str, Any] = {}
        if state_file.exists():
            raw = state_file.read_text(encoding="utf-8", errors="replace")
            for line in raw.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    state_data[k.strip()] = v.strip()

        workspace_val = state_data.get("workspace", ws_name)
        initialized = state_data.get("initialized_at", "unknown")
        open_subs = state_data.get("open_submissions", "[]")
        closed_subs = state_data.get("closed_submissions", "[]")
        platform_val = state_data.get("platform", "unknown")
        status_val = state_data.get("status", "unknown")

        # Read submissions if available
        subs_inline = ""
        if submissions_md.exists():
            subs_raw = submissions_md.read_text(encoding="utf-8", errors="replace")
            subs_inline = subs_raw[:3000]  # cap at 3KB
            if len(subs_raw) > 3000:
                subs_inline += "\n\n_(truncated at 3000 chars)_"

        fm = _frontmatter(
            source="workspace-state",
            workspace=workspace_val,
            platform=platform_val,
            initialized_at=initialized,
            status=status_val,
            last_synced=NOW_ISO,
            tags=[f"workspace/{ws_name}", "#workspace/state"],
        )
        note = fm + f"# Workspace: {ws_name}\n\n"
        note += f"**Platform:** {platform_val}  **Status:** {status_val}\n"
        note += f"**Initialized:** {initialized}\n\n"
        if subs_inline:
            note += f"## Submissions\n\n{subs_inline}\n"

        if _safe_write(note_path, note, byte_counter, VAULT_BYTE_CAP):
            written += 1
            sync_state[f"workspaces/{ws_name}"] = source_mtime

    print(f"  [workspaces] Wrote {written} workspace state notes")
    return written


# ---------------------------------------------------------------------------
# Section 9: Error / smoke-fail aggregation
# ---------------------------------------------------------------------------

def crawl_errors(vault_dir: Path, byte_counter: list[int], force: bool = False,
                  sync_state: dict = {}) -> int:
    """Aggregate error lines from /private/tmp/auditooor-inventory/ logs."""
    out_dir = vault_dir / "errors"
    written = 0

    if not INVENTORY_DIR.exists():
        print(f"  [errors] {INVENTORY_DIR} not found")
        return 0

    error_pat = re.compile(r'\[err|FAIL|ERROR|smoke_fail|fp_repair|architectural_mismatch', re.IGNORECASE)
    today = _dt.date.today().isoformat()

    # Group log files by source (strip date suffix from filename)
    log_files = sorted(INVENTORY_DIR.glob("*.log"))

    for log_path in log_files:
        source = log_path.stem  # e.g. "fp_repair_queue"
        source_mtime = log_path.stat().st_mtime
        last_sync = sync_state.get(f"errors/{source}", 0.0)
        if not force and source_mtime <= last_sync:
            continue

        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        error_lines = [ln for ln in lines if error_pat.search(ln)]

        if not error_lines:
            sync_state[f"errors/{source}"] = source_mtime
            continue

        # Count frequency by error type
        freq: dict[str, int] = {}
        for ln in error_lines:
            # Extract rc=N pattern or error kind
            m = re.search(r'rc=(\d+)', ln)
            key = f"rc={m.group(1)}" if m else "unknown"
            freq[key] = freq.get(key, 0) + 1

        freq_table = "\n".join(f"| {k} | {v} |" for k, v in sorted(freq.items(), key=lambda x: -x[1]))

        fm = _frontmatter(
            source="log-errors",
            log_file=log_path.name,
            error_line_count=len(error_lines),
            total_line_count=len(lines),
            date=today,
            last_synced=NOW_ISO,
            tags=["error/smoke-fail", f"#error/{source.replace('_', '-')}"],
        )
        note = fm + f"# Error Log: {source} ({today})\n\n"
        note += f"**Total lines:** {len(lines)}  **Error lines:** {len(error_lines)}\n\n"
        note += f"## Frequency by Exit Code\n\n| Exit Code | Count |\n|---|---|\n{freq_table}\n\n"
        note += "## Sample Error Lines (first 20)\n\n"
        note += "```\n" + "\n".join(error_lines[:20]) + "\n```\n"
        if len(error_lines) > 20:
            note += f"\n_({len(error_lines) - 20} more error lines omitted)_\n"

        out_name = f"{source}-{today}.md"
        if _safe_write(out_dir / out_name, note, byte_counter, VAULT_BYTE_CAP):
            written += 1
            sync_state[f"errors/{source}"] = source_mtime

    print(f"  [errors] Wrote {written} error aggregation notes")
    return written


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

# All 9 crawlable sections. W6-3 / Gap G1: every one of these is now also
# registered in obsidian-vault-sync.py SECTION_SOURCES + DEEP_CRAWLER_SECTIONS,
# so `make docs-check` / `make vault-sync` proactively refresh them. The two
# git-backed sections (`commits`, `prs`) shell out to git / gh, so the sync
# orchestrator throttles them behind a staleness window (see
# obsidian-vault-sync.py GIT_BACKED_SECTIONS / --include-git-sections); the
# crawler itself is unchanged and still refreshes any section on demand.
ALL_SECTIONS = ["claude-memory", "codex-memory", "routines", "commits", "prs",
                "tools-api", "make-targets", "workspaces", "errors"]


def main() -> None:
    global VAULT_WRITES_ENABLED

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vault-dir", default=str(VAULT_DEFAULT))
    ap.add_argument("--force", action="store_true", help="Ignore mtime cache, regenerate all")
    ap.add_argument("--dry-run", action="store_true", help="Show stats only, no writes")
    ap.add_argument("--section", choices=ALL_SECTIONS, help="Run only one section")
    ap.add_argument("--status", action="store_true", help="Show staleness info only")
    args = ap.parse_args()

    vault_dir = Path(args.vault_dir)
    VAULT_WRITES_ENABLED = not args.dry_run
    if VAULT_WRITES_ENABLED and not args.status:
        vault_dir.mkdir(parents=True, exist_ok=True)

    if args.dry_run or args.status:
        sync_state = _load_deep_sync(vault_dir)
        print(f"Deep sync state: {vault_dir / '.deep_sync.json'}")
        for sec in ALL_SECTIONS:
            last = sync_state.get(sec, 0.0)
            age = (_dt.datetime.now().timestamp() - last) / 3600 if last else float("inf")
            print(f"  {sec:<25} last_sync={_dt.datetime.fromtimestamp(last).isoformat()[:16] if last else 'never':>16}  age={age:.1f}h")
        if args.status:
            return

    sync_state = _load_deep_sync(vault_dir)
    byte_counter = [0]
    total_written = 0
    total_redacted = 0

    sections_to_run = [args.section] if args.section else ALL_SECTIONS

    for section in sections_to_run:
        print(f"Running section: {section}")
        if section == "claude-memory":
            w, r = crawl_claude_memory(vault_dir, byte_counter, args.force, sync_state)
            total_written += w; total_redacted += r
        elif section == "codex-memory":
            w, r = crawl_codex_memory(vault_dir, byte_counter, args.force, sync_state)
            total_written += w; total_redacted += r
        elif section == "routines":
            total_written += crawl_routines(vault_dir, byte_counter, args.force, sync_state)
        elif section == "commits":
            total_written += crawl_commits(
                vault_dir, byte_counter, args.force, sync_state, cap=400, dry_run=args.dry_run
            )
        elif section == "prs":
            total_written += crawl_prs(vault_dir, byte_counter, args.force, sync_state)
        elif section == "tools-api":
            w, _ = crawl_tools_api(vault_dir, byte_counter, args.force, sync_state)
            total_written += w
        elif section == "make-targets":
            total_written += crawl_make_targets(vault_dir, byte_counter, args.force, sync_state)
        elif section == "workspaces":
            total_written += crawl_workspaces(vault_dir, byte_counter, args.force, sync_state)
        elif section == "errors":
            total_written += crawl_errors(vault_dir, byte_counter, args.force, sync_state)

    if not args.dry_run:
        _save_deep_sync(vault_dir, sync_state)
    else:
        print("Dry-run: skipped vault writes and sync-state save")

    print(f"\nDeep crawler complete:")
    notes_label = "Planned notes" if args.dry_run else "New/updated notes"
    bytes_label = "Bytes planned" if args.dry_run else "Bytes written"
    print(f"  {notes_label}: {total_written}")
    print(f"  Secrets redacted:  {total_redacted}")
    print(f"  {bytes_label}:     {byte_counter[0]:,} / {VAULT_BYTE_CAP:,}")
    if total_redacted > 0:
        print(f"  WARNING: {total_redacted} secret-pattern matches were redacted from vault output.")


if __name__ == "__main__":
    main()
