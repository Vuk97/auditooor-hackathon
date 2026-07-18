#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared 10 files in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at lane start
"""canonical-inventory.py - Live snapshot of the auditooor system surface.

Emits a single JSON snapshot at `.auditooor/canonical_inventory.json`
covering every callable surface an orchestrator can reference when
dispatching sub-agents (tools/, mcp callables, schemas, pre-submit
checks, R-rules, hooks, workspaces, finding-corpus sources). The
inventory exists so Rule R64 can mechanically verify orchestrator
prompt claims (file paths, record counts, callable names, Check #N,
R-rule IDs) against ground truth BEFORE dispatching, catching
hallucinated claims that L25/L26 trust-but-verify could only catch
AFTER the worker read the source files.

Empirical anchor (2026-05-26): orchestrator promised TOK-A would
"mine 10K Cantina rationales" without verifying the source corpus
existed. Reality at audit-pin: ~181 reference/findings_*.jsonl rows
+ ~221 prior_audits text files across 6 workspaces. The
"10K Cantina rationales" claim was fabricated.

Output schema (auditooor.canonical_inventory.v1):

    {
      "schema": "auditooor.canonical_inventory.v1",
      "generated_at_utc": "...",
      "ttl_hours": 24,
      "expires_at_utc": "...",
      "repo_root": "/Users/wolf/auditooor-mcp",
      "tools": {
        "<relative path>": {
          "exists": bool,
          "executable": bool,
          "lines": int|null
        },
        ...
      },
      "mcp_callables": [list of names parsed from vault-mcp-server --help],
      "schemas": [list of schema names extracted from JSON outputs],
      "record_counts_per_source": {
        "reference/findings_<name>.jsonl": int,
        "prior_audits/<workspace>": int,
        ...
      },
      "pre_submit_checks": [
        {"number": int, "name": str, "line": int},
        ...
      ],
      "r_rules": [list of R-rule IDs from reference/r_rules_inventory.jsonl],
      "hooks": {
        "pre_tool_use_matchers": [str, ...],
        "session_start_commands": [str, ...]
      },
      "makefile_targets": [str, ...],
      "workspaces": {
        "<name>": {
          "path": str,
          "submissions_count": int,
          "prior_audits_count": int
        }
      }
    }

CLI:

    # default: refresh if stale, write to .auditooor/canonical_inventory.json
    python3 tools/canonical-inventory.py

    # force regeneration
    python3 tools/canonical-inventory.py --refresh

    # filter to one field (tools | mcp_callables | r_rules | ...)
    python3 tools/canonical-inventory.py --field tools

    # check whether a claim is verifiable. CLAIM can be:
    #   - a tool path: "tools/foo.py"
    #   - a callable: "vault_some_callable"
    #   - a check number: "Check #42"
    #   - a rule ID: "R52"
    # Returns JSON with {"verified": bool, "kind": str, "evidence": ...}
    python3 tools/canonical-inventory.py --check "vault_resume_context"

    # raw JSON to stdout
    python3 tools/canonical-inventory.py --json

Exit codes:
    0 - success
    1 - fatal error (cannot locate repo root, cannot write snapshot)
    2 - --check returned not-found / unverified
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.canonical_inventory.v1"
DEFAULT_TTL_HOURS = 24
DEFAULT_AUDITS_ROOT = Path("/Users/wolf/audits")
DEFAULT_SETTINGS_JSON = Path.home() / ".claude" / "settings.json"


# ---------------------------------------------------------------------------
# Repo root discovery
# ---------------------------------------------------------------------------

def _find_repo_root(start: Path) -> Path:
    """Walk up from `start` until a directory containing `tools/` and
    `reference/` is found. Falls back to /Users/wolf/auditooor-mcp."""
    candidate = start.resolve()
    for parent in [candidate] + list(candidate.parents):
        if (parent / "tools").is_dir() and (parent / "reference").is_dir():
            return parent
    fallback = Path("/Users/wolf/auditooor-mcp")
    if (fallback / "tools").is_dir():
        return fallback
    raise FileNotFoundError(
        f"Could not locate auditooor-mcp repo root from {start}"
    )


# ---------------------------------------------------------------------------
# Field collectors
# ---------------------------------------------------------------------------

def _collect_tools(repo_root: Path) -> dict[str, dict[str, Any]]:
    """Enumerate tools/ top-level scripts (*.py, *.sh).

    Returns {relative_path: {exists, executable, lines}}. Top-level
    only to keep snapshot bounded.
    """
    tools_dir = repo_root / "tools"
    out: dict[str, dict[str, Any]] = {}
    if not tools_dir.is_dir():
        return out
    for entry in sorted(tools_dir.iterdir()):
        if not entry.is_file():
            continue
        suffix = entry.suffix.lower()
        if suffix not in {".py", ".sh"}:
            continue
        rel = f"tools/{entry.name}"
        st = entry.stat()
        executable = bool(st.st_mode & 0o111)
        try:
            with entry.open("r", encoding="utf-8", errors="replace") as fh:
                lines = sum(1 for _ in fh)
        except OSError:
            lines = None
        out[rel] = {
            "exists": True,
            "executable": executable,
            "lines": lines,
        }
    # r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION pathspec declared via tools/agent-pathspec-register.py
    # Also enumerate well-known subdirs: hooks, git-hooks, tests, lib, audit.
    for subdir in ("hooks", "git-hooks", "tests", "lib", "audit"):
        path = tools_dir / subdir
        if not path.is_dir():
            continue
        for entry in sorted(path.iterdir()):
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in {".py", ".sh"}:
                continue
            rel = f"tools/{subdir}/{entry.name}"
            st = entry.stat()
            executable = bool(st.st_mode & 0o111)
            try:
                with entry.open("r", encoding="utf-8", errors="replace") as fh:
                    lines = sum(1 for _ in fh)
            except OSError:
                lines = None
            out[rel] = {
                "exists": True,
                "executable": executable,
                "lines": lines,
            }
    return out


def _collect_mcp_callables(repo_root: Path) -> list[str]:
    """Parse `vault-mcp-server.py --help` for the --call enum.

    Falls back to reading `reference/mcp_callables_inventory.jsonl`
    if the server invocation fails (offline/test mode).
    """
    server = repo_root / "tools" / "vault-mcp-server.py"
    if server.is_file():
        try:
            import subprocess

            result = subprocess.run(
                ["python3", str(server), "--help"],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(repo_root),
            )
            text = result.stdout + result.stderr
            # Match the --call {a,b,c,...} block (may span multiple lines).
            m = re.search(r"--call\s+\{([^}]+)\}", text)
            if m:
                names = [n.strip() for n in m.group(1).split(",")]
                names = [n for n in names if n]
                if names:
                    return sorted(set(names))
        except Exception:
            pass
    # Fallback: parse reference/mcp_callables_inventory.jsonl
    jsonl = repo_root / "reference" / "mcp_callables_inventory.jsonl"
    if jsonl.is_file():
        names: set[str] = set()
        try:
            with jsonl.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    n = rec.get("name")
                    if isinstance(n, str) and n:
                        names.add(n)
        except OSError:
            pass
        if names:
            return sorted(names)
    return []


def _collect_schemas(repo_root: Path) -> list[str]:
    """Grep tools/ for `auditooor.<name>.v<N>` schema string literals."""
    tools_dir = repo_root / "tools"
    if not tools_dir.is_dir():
        return []
    schemas: set[str] = set()
    schema_re = re.compile(r"auditooor\.[a-z0-9_]+\.v\d+")
    # Scan only top-level *.py to bound cost.
    for entry in tools_dir.iterdir():
        if not entry.is_file() or entry.suffix != ".py":
            continue
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in schema_re.finditer(text):
            schemas.add(m.group(0))
    return sorted(schemas)


def _collect_record_counts(repo_root: Path) -> dict[str, int]:
    """Compute record counts for each known finding-corpus source.

    Sources (audit-pin truth, NOT orchestrator-promised quantities):

    - reference/findings_*.jsonl  -> row counts (one finding per line)
    - <audits>/<workspace>/prior_audits/   -> file counts (PDFs/text)
    - <audits>/<workspace>/submissions/    -> draft counts

    Returns flat key:int mapping for greppability.
    """
    out: dict[str, int] = {}
    # reference/findings_*.jsonl
    ref_dir = repo_root / "reference"
    if ref_dir.is_dir():
        for entry in sorted(ref_dir.iterdir()):
            if not entry.is_file() or not entry.name.startswith("findings_"):
                continue
            if entry.suffix != ".jsonl":
                continue
            try:
                with entry.open("rb") as fh:
                    cnt = sum(1 for _ in fh)
                out[f"reference/{entry.name}"] = cnt
            except OSError:
                continue
    # audits/<workspace>/prior_audits
    if DEFAULT_AUDITS_ROOT.is_dir():
        for ws_dir in sorted(DEFAULT_AUDITS_ROOT.iterdir()):
            if not ws_dir.is_dir():
                continue
            pa = ws_dir / "prior_audits"
            if pa.is_dir():
                try:
                    cnt = sum(1 for p in pa.rglob("*") if p.is_file())
                    out[f"prior_audits/{ws_dir.name}"] = cnt
                except OSError:
                    continue
    return out


# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared 10 files via tools/agent-pathspec-register.py at lane start
def _collect_pre_submit_checks(repo_root: Path) -> list[dict[str, Any]]:
    """Parse pre-submit checks from BOTH inventory JSONL and script header.

    Source-of-truth precedence:
    1. reference/pre_submit_checks_inventory.jsonl (curated, all 90+ rows)
    2. # Check #N: NAME headers from tools/pre-submit-check.sh (newer
       additions that may not be in JSONL yet)

    Returns a unified de-duplicated list ordered by check_number.
    """
    seen: dict[int, dict[str, Any]] = {}

    # Source 1: reference inventory
    jsonl_path = repo_root / "reference" / "pre_submit_checks_inventory.jsonl"
    if jsonl_path.is_file():
        try:
            with jsonl_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    num = rec.get("check_number")
                    name = rec.get("check_name")
                    if isinstance(num, int) and isinstance(name, str):
                        seen[num] = {
                            "number": num,
                            "name": name,
                            "source": "inventory_jsonl",
                        }
        except OSError:
            pass

    # Source 2: script headers
    script = repo_root / "tools" / "pre-submit-check.sh"
    if script.is_file():
        header_re = re.compile(r"^#\s*Check\s*#(\d+)\s*:\s*(.+?)\s*$")
        try:
            with script.open("r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    m = header_re.match(line)
                    if m:
                        num = int(m.group(1))
                        name = m.group(2).strip()
                        if num not in seen:
                            seen[num] = {
                                "number": num,
                                "name": name,
                                "line": lineno,
                                "source": "script_header",
                            }
                        else:
                            # Augment with line number when available
                            seen[num].setdefault("line", lineno)
        except OSError:
            pass

    return [seen[k] for k in sorted(seen.keys())]


# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION pathspec declared via tools/agent-pathspec-register.py
def _collect_r_rules(repo_root: Path) -> list[str]:
    """Parse R/L rule IDs from BOTH the canonical JSONL inventory AND
    CLAUDE.md heading scan (catches L-class rules and freshly-codified
    R-rules that haven't been backfilled into the inventory yet).
    """
    rule_ids: set[str] = set()

    # Source 1: reference inventory
    path = repo_root / "reference" / "r_rules_inventory.jsonl"
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    rid = rec.get("rule_id")
                    if isinstance(rid, str) and rid:
                        rule_ids.add(rid)
        except OSError:
            pass

    # Source 2: CLAUDE.md heading scan for "### Rule R64", "### L34", etc.
    # Also matches the in-rule references like "(Rule 34)" and "L29 -" forms.
    # The CLAUDE.md path can be either ~/.claude/CLAUDE.md or repo CLAUDE.md.
    rule_hdr_re = re.compile(
        r"(?:^|\n)#+\s+(?:Rule\s+|Hard rule:\s*)?([RL])[\s_-]?(\d+[A-Z]?)\b",
        re.IGNORECASE,
    )
    rule_inline_re = re.compile(
        r"\b([RL])[\s_-]?(\d+[A-Z]?)\s*[\(-]"
    )
    for candidate in (
        Path.home() / ".claude" / "CLAUDE.md",
        repo_root / "CLAUDE.md",
    ):
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in rule_hdr_re.finditer(text):
            prefix = m.group(1).upper()
            suffix = m.group(2)
            if len(suffix) <= 3:
                rule_ids.add(f"{prefix}{suffix}")
        for m in rule_inline_re.finditer(text):
            prefix = m.group(1).upper()
            suffix = m.group(2)
            if len(suffix) <= 3:
                rule_ids.add(f"{prefix}{suffix}")

    return sorted(rule_ids)


def _collect_hooks(settings_path: Path) -> dict[str, Any]:
    """Read ~/.claude/settings.json hooks section."""
    out: dict[str, Any] = {
        "pre_tool_use_matchers": [],
        "session_start_commands": [],
        "settings_path": str(settings_path),
        "settings_exists": settings_path.is_file(),
    }
    if not settings_path.is_file():
        return out
    try:
        text = settings_path.read_text(encoding="utf-8")
        cfg = json.loads(text)
    except Exception as exc:
        out["error"] = f"parse-error: {exc!r}"
        return out
    hooks = cfg.get("hooks", {}) or {}
    pre_tool_use = hooks.get("PreToolUse", []) or []
    matchers: list[str] = []
    for entry in pre_tool_use:
        if isinstance(entry, dict):
            m = entry.get("matcher")
            if isinstance(m, str):
                matchers.append(m)
    out["pre_tool_use_matchers"] = matchers
    session_start = hooks.get("SessionStart", []) or []
    commands: list[str] = []
    for entry in session_start:
        if isinstance(entry, dict):
            for h in entry.get("hooks", []) or []:
                if isinstance(h, dict):
                    c = h.get("command")
                    if isinstance(c, str):
                        commands.append(c)
    out["session_start_commands"] = commands
    return out


def _collect_makefile_targets(repo_root: Path) -> list[str]:
    """Parse top-level target names from Makefile (the `target:` heads)."""
    mf = repo_root / "Makefile"
    if not mf.is_file():
        return []
    target_re = re.compile(r"^([a-zA-Z][a-zA-Z0-9_.-]*?):(?:\s|$)")
    targets: set[str] = set()
    try:
        with mf.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("\t"):
                    continue
                m = target_re.match(line)
                if m:
                    name = m.group(1)
                    targets.add(name)
    except OSError:
        return []
    return sorted(targets)


def _collect_workspaces(audits_root: Path) -> dict[str, dict[str, Any]]:
    """Enumerate <audits_root>/<ws>/ with submissions + prior_audits counts."""
    out: dict[str, dict[str, Any]] = {}
    if not audits_root.is_dir():
        return out
    for entry in sorted(audits_root.iterdir()):
        if not entry.is_dir():
            continue
        sub_dir = entry / "submissions"
        pa_dir = entry / "prior_audits"
        if not (sub_dir.is_dir() or pa_dir.is_dir()):
            continue
        sub_count = 0
        if sub_dir.is_dir():
            try:
                sub_count = sum(
                    1 for p in sub_dir.rglob("*.md") if p.is_file()
                )
            except OSError:
                sub_count = 0
        pa_count = 0
        if pa_dir.is_dir():
            try:
                pa_count = sum(1 for p in pa_dir.rglob("*") if p.is_file())
            except OSError:
                pa_count = 0
        out[entry.name] = {
            "path": str(entry),
            "submissions_count": sub_count,
            "prior_audits_count": pa_count,
        }
    return out


# ---------------------------------------------------------------------------
# Snapshot orchestration
# ---------------------------------------------------------------------------

def build_snapshot(repo_root: Path,
                   settings_path: Path = DEFAULT_SETTINGS_JSON,
                   audits_root: Path = DEFAULT_AUDITS_ROOT,
                   ttl_hours: int = DEFAULT_TTL_HOURS) -> dict[str, Any]:
    """Build a fresh canonical inventory snapshot."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    snap: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ttl_hours": ttl_hours,
        "expires_at_utc": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "tools": _collect_tools(repo_root),
        "mcp_callables": _collect_mcp_callables(repo_root),
        "schemas": _collect_schemas(repo_root),
        "record_counts_per_source": _collect_record_counts(repo_root),
        "pre_submit_checks": _collect_pre_submit_checks(repo_root),
        "r_rules": _collect_r_rules(repo_root),
        "hooks": _collect_hooks(settings_path),
        "makefile_targets": _collect_makefile_targets(repo_root),
        "workspaces": _collect_workspaces(audits_root),
    }
    return snap


def _is_stale(snapshot_path: Path) -> bool:
    """True if snapshot is missing OR past its expires_at."""
    if not snapshot_path.is_file():
        return True
    try:
        text = snapshot_path.read_text(encoding="utf-8")
        snap = json.loads(text)
    except Exception:
        return True
    exp = snap.get("expires_at_utc")
    if not isinstance(exp, str):
        return True
    try:
        dt = datetime.strptime(exp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return True
    return datetime.now(timezone.utc) >= dt


def load_or_refresh(repo_root: Path, *,
                    refresh: bool = False,
                    snapshot_path: Path | None = None,
                    ttl_hours: int = DEFAULT_TTL_HOURS,
                    audits_root: Path = DEFAULT_AUDITS_ROOT,
                    settings_path: Path = DEFAULT_SETTINGS_JSON,
                    write: bool = True) -> dict[str, Any]:
    """Load existing snapshot if fresh; otherwise build a new one."""
    if snapshot_path is None:
        snapshot_path = repo_root / ".auditooor" / "canonical_inventory.json"
    if refresh or _is_stale(snapshot_path):
        snap = build_snapshot(
            repo_root,
            settings_path=settings_path,
            audits_root=audits_root,
            ttl_hours=ttl_hours,
        )
        if write:
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = snapshot_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(snap, indent=2, sort_keys=True))
            tmp.replace(snapshot_path)
        return snap
    return json.loads(snapshot_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Claim verification
# ---------------------------------------------------------------------------

_CHECK_RE = re.compile(r"^Check\s*#?\s*(\d+)$", re.IGNORECASE)
_R_RULE_RE = re.compile(r"^([RL])\s*[#-]?\s*(\d+[A-Z]?)$", re.IGNORECASE)


def verify_claim(snap: dict[str, Any], claim: str) -> dict[str, Any]:
    """Verify a single claim against the snapshot.

    Returns:
        {
          "claim": str,
          "kind": str,           # "tool-path" | "mcp-callable" | "check" |
                                 # "r-rule" | "schema" | "makefile-target" |
                                 # "workspace" | "unknown"
          "verified": bool,
          "evidence": ...        # extracted ground-truth row when verified,
                                 # else suggested alternative
        }
    """
    claim = claim.strip()
    out: dict[str, Any] = {
        "claim": claim,
        "kind": "unknown",
        "verified": False,
        "evidence": None,
    }
    if not claim:
        return out

    # 1. Tool path: starts with "tools/" or "./tools/"
    if claim.startswith("tools/") or claim.startswith("./tools/"):
        normalised = claim.lstrip("./")
        tools = snap.get("tools", {}) or {}
        if normalised in tools:
            out["kind"] = "tool-path"
            out["verified"] = True
            out["evidence"] = tools[normalised]
            return out
        out["kind"] = "tool-path"
        out["verified"] = False
        # Suggest closest match
        stem = normalised.split("/")[-1].split(".")[0]
        candidates = [t for t in tools.keys() if stem and stem in t][:5]
        out["evidence"] = {"not_found": normalised, "candidates": candidates}
        return out

    # 2. MCP callable: starts with vault_
    if claim.startswith("vault_"):
        callables = snap.get("mcp_callables", []) or []
        if claim in callables:
            out["kind"] = "mcp-callable"
            out["verified"] = True
            out["evidence"] = {"name": claim}
            return out
        out["kind"] = "mcp-callable"
        out["verified"] = False
        prefix = claim[:15] if len(claim) >= 15 else claim
        candidates = [c for c in callables if prefix in c][:5]
        out["evidence"] = {"not_found": claim, "candidates": candidates}
        return out

    # 3. Check #N
    m = _CHECK_RE.match(claim)
    if m:
        num = int(m.group(1))
        checks = snap.get("pre_submit_checks", []) or []
        match = next((c for c in checks if c.get("number") == num), None)
        out["kind"] = "check"
        if match:
            out["verified"] = True
            out["evidence"] = match
        else:
            out["verified"] = False
            max_check = max(
                (c.get("number", 0) for c in checks), default=0
            )
            out["evidence"] = {
                "not_found_check_number": num,
                "max_check_number": max_check,
            }
        return out

    # 4. R-rule / L-rule
    m = _R_RULE_RE.match(claim)
    if m:
        prefix_letter = m.group(1).upper()
        suffix = m.group(2)
        rid = f"{prefix_letter}{suffix}"
        rules = snap.get("r_rules", []) or []
        out["kind"] = "r-rule"
        if rid in rules:
            out["verified"] = True
            out["evidence"] = {"rule_id": rid}
        else:
            out["verified"] = False
            out["evidence"] = {
                "not_found_rule_id": rid,
                "known_rules_count": len(rules),
            }
        return out

    # 5. Schema name: starts with "auditooor."
    if claim.startswith("auditooor."):
        schemas = snap.get("schemas", []) or []
        out["kind"] = "schema"
        if claim in schemas:
            out["verified"] = True
            out["evidence"] = {"schema": claim}
        else:
            prefix_str = claim[:25] if len(claim) >= 25 else claim
            candidates = [s for s in schemas if prefix_str in s][:5]
            out["verified"] = False
            out["evidence"] = {"not_found": claim, "candidates": candidates}
        return out

    # 6. Makefile target: starts with "make "
    if claim.startswith("make "):
        target = claim[5:].split()[0]
        targets = snap.get("makefile_targets", []) or []
        out["kind"] = "makefile-target"
        if target in targets:
            out["verified"] = True
            out["evidence"] = {"target": target}
        else:
            out["verified"] = False
            prefix_t = target[:6] if len(target) >= 6 else target
            candidates = [t for t in targets if prefix_t in t][:5]
            out["evidence"] = {"not_found": target, "candidates": candidates}
        return out

    # Fallback - unknown shape
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=("Live canonical inventory of the auditooor system "
                     "surface (R64 enforcement source-of-truth).")
    )
    parser.add_argument("--refresh", action="store_true",
                        help="Force regeneration regardless of TTL.")
    parser.add_argument("--field", default=None,
                        help=("Print only the named top-level field "
                              "(tools | mcp_callables | r_rules | etc.)."))
    parser.add_argument("--json", action="store_true",
                        help="Emit the snapshot to stdout as JSON.")
    parser.add_argument("--check", default=None,
                        help=("Verify a single claim (tool path / mcp "
                              "callable / 'Check #N' / R-rule)."))
    parser.add_argument("--workspace", default=None,
                        help="Optional repo root override (for tests).")
    parser.add_argument("--snapshot-path", default=None,
                        help="Optional snapshot path override (for tests).")
    parser.add_argument("--audits-root", default=str(DEFAULT_AUDITS_ROOT),
                        help="Audits root override (for tests).")
    parser.add_argument("--settings-path", default=str(DEFAULT_SETTINGS_JSON),
                        help="Settings.json override (for tests).")
    parser.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS,
                        help="Snapshot TTL in hours (default 24).")
    parser.add_argument("--no-write", action="store_true",
                        help="Don't persist to .auditooor/canonical_inventory.json")
    args = parser.parse_args(argv)

    try:
        if args.workspace:
            repo_root = Path(args.workspace).resolve()
        else:
            repo_root = _find_repo_root(Path.cwd())
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    snapshot_path = (Path(args.snapshot_path)
                     if args.snapshot_path
                     else repo_root / ".auditooor" / "canonical_inventory.json")
    snap = load_or_refresh(
        repo_root,
        refresh=args.refresh,
        snapshot_path=snapshot_path,
        ttl_hours=args.ttl_hours,
        audits_root=Path(args.audits_root),
        settings_path=Path(args.settings_path),
        write=not args.no_write,
    )

    # --check short-circuit
    if args.check is not None:
        verdict = verify_claim(snap, args.check)
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0 if verdict.get("verified") else 2

    # --field filter
    if args.field is not None:
        if args.field in snap:
            print(json.dumps({args.field: snap[args.field]},
                             indent=2, sort_keys=True))
            return 0
        print(f"ERROR: unknown field '{args.field}'", file=sys.stderr)
        print(f"Known fields: {sorted(snap.keys())}", file=sys.stderr)
        return 1

    # --json full snapshot
    if args.json:
        print(json.dumps(snap, indent=2, sort_keys=True))
        return 0

    # Default: print a terse human-readable summary
    print(f"Canonical Inventory ({snap.get('schema', '?')})")
    print(f"  generated_at_utc:  {snap.get('generated_at_utc')}")
    print(f"  expires_at_utc:    {snap.get('expires_at_utc')}")
    print(f"  repo_root:         {snap.get('repo_root')}")
    print(f"  tools:             {len(snap.get('tools', {}))} entries")
    print(f"  mcp_callables:     {len(snap.get('mcp_callables', []))}")
    print(f"  schemas:           {len(snap.get('schemas', []))}")
    rc = snap.get("record_counts_per_source", {}) or {}
    rc_total = sum(v for v in rc.values() if isinstance(v, int))
    print(f"  record_sources:    {len(rc)} sources / {rc_total} records total")
    print(f"  pre_submit_checks: {len(snap.get('pre_submit_checks', []))}")
    print(f"  r_rules:           {len(snap.get('r_rules', []))}")
    print(f"  makefile_targets:  {len(snap.get('makefile_targets', []))}")
    print(f"  workspaces:        {len(snap.get('workspaces', {}))}")
    print(f"  snapshot_path:     {snapshot_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
