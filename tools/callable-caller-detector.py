#!/usr/bin/env python3
"""callable-caller-detector.py - hardened "dead-callable" criterion across 9 surfaces.

# Rule 36 + Rule 55: this tool emits no corpus record.
# Purpose-tier: active-gate (Phase 0 WF10-CALLABLE-COVERAGE-AUDIT lane,
# 2026-05-23).

Background:
  WF-10's "Adversarial Pruning" report flagged 53 of 94 MCP callables as
  "never called" against `.auditooor/mcp_call_log.jsonl` (60-day window,
  4,517 invocations). The recommendation was to delete 35-40 of the 53.
  But the NEG-E lesson - "rebuttal count / invocation log is the wrong
  proxy; real-activation count is what matters" - applies just as
  strongly to MCP callables as it did to L1-R rebuttal markers.

  Sibling tool `tools/tool-caller-detector.py` (WF10-CRITERION-FIX) proved
  the same point for Python tools: WF-10's 4-surface heuristic missed 5
  of the 9 actual invocation surfaces and produced a systematic FP rate
  of ~67% on its NEG-A delete batch. This tool brings the same 9-surface
  honesty audit to MCP callables.

CLI:
  python3 tools/callable-caller-detector.py <callable-name>
                                            [--scope local|workspace|all]
                                            [--root <repo-root>]
                                            [--scheduled-tasks-dir <path>]
                                            [--call-log <path>]
                                            [--json]
                                            [--include-self]
                                            [--include-test]
                                            [--exclude-archive]
                                            [--batch <file>]
                                            [--all]

  <callable-name> is the MCP callable name without quotes, e.g.
  `vault_resume_context`. Prefix `vault_` is not required (the tool
  accepts both `resume_context` and `vault_resume_context`).

Scopes:
  - local:     search only the repo root (default).
  - workspace: search the repo root + ~/audits/* workspace clones.
  - all:       search the repo root + ~/audits + ~/.claude/scheduled-tasks
               + ~/.claude/CLAUDE.md.

Verdicts (schema `auditooor.callable_caller_detector.v1`):
  - live-frequent        : >=10 invocations in --call-log
  - live-low-volume      : 1-9 invocations in --call-log
  - wired-not-yet-invoked: 0 invocations BUT >=1 non-doc-only surface wires it
  - unwired-but-cited    : 0 invocations + 0 non-doc wires + docs reference
  - dead-no-caller       : 0 across all 9 surfaces AND 0 invocations
  - error                : input / runtime error

Exit codes:
  0 - callable is live-frequent / live-low-volume / wired-not-yet-invoked
  1 - callable is unwired-but-cited / dead-no-caller
  2 - input / runtime error

Surface priority order (matches the tool-caller-detector surfaces, adapted
for MCP callables - the search term is `--call <callable>` not
`tools/<name>.py`):

  1.  Makefile + sibling Makefiles
  2.  pre-submit-check.sh + tools/*.sh shell wrappers
  3.  engage.py + stage_* references
  4.  pre-iter-check.sh
  5.  tools/audit-deep.sh + tools/audit-deep-*.sh
  6.  agent_briefs/*.md
  7.  docs/*.md (canonical anchors) + CLAUDE.md / AGENTS.md / SKILL.md
  8.  ~/.claude/scheduled-tasks/*/SKILL.md (cron callers) and
      ~/.claude/CLAUDE.md (global memory)
  9.  tools/*.py (subprocess.run / direct refs)
  10. registry_self_ref (always 1+ if the callable exists)

Output schema (per callable):
  {
    "schema": "auditooor.callable_caller_detector.v1",
    "callable": "<full vault_X name>",
    "verdict": "live-frequent | live-low-volume | wired-not-yet-invoked |
                unwired-but-cited | dead-no-caller | error",
    "invocation_count": <int from --call-log>,
    "surfaces_wired_in": [<list of surface names with hits>],
    "surface_count": <int - non-doc-only surface count>,
    "callers": [
      {"surface": "<surface-name>",
       "file": "<rel-path>",
       "line": <int>,
       "context_snippet": "<trimmed source line>",
       "is_self": <bool>,
       "is_test": <bool>}
    ],
    "caller_count_by_surface": {"<surface>": <int>, ...},
    "scope": "local | workspace | all",
    "root": "<absolute root path>",
    "surfaces_searched": [<10 surface names>],
    "registered_in_server": <bool>,
    "timestamp_utc": "<ISO-8601>"
  }

Empirical anchor:
  WF-10 (`reports/v3_iter_2026-05-23_iter17/workflow_giga_inspection/WF10_adversarial_pruning.md`)
  applied a 1-surface heuristic (count of invocations in
  `.auditooor/mcp_call_log.jsonl`) to call 53 callables "shelfware".
  But invocation-count != callability. A callable can be wired into
  CLAUDE.md Layer-1 sequence, the master plan documents, or worker
  brief templates without an actual cron-invocation having fired in the
  60-day window. This tool surfaces those wired-but-not-yet-invoked
  callables so the operator can decide whether to (a) genuinely delete
  them or (b) wire them into pillar workflows for real activation.

Environment hooks:
  AUDITOOOR_CALLABLE_CALLER_SCHEDULED_TASKS_DIR
    Override ~/.claude/scheduled-tasks for the SKILL.md surface.
  AUDITOOOR_CALLABLE_CALLER_AUDITS_DIR
    Override ~/audits/* glob for workspace/all scope.
  AUDITOOOR_CALLABLE_CALLER_CALL_LOG
    Override .auditooor/mcp_call_log.jsonl for invocation count.
  AUDITOOOR_CALLABLE_CALLER_EXTRA_DOC_DIRS
    Newline-separated extra doc roots to scan (joined to docs/).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.callable_caller_detector.v1"
GATE = "CALLABLE-CALLER-DETECTOR"

# Ordered list of surfaces.
SURFACES_ORDER = [
    "makefile",
    "pre_submit_check_and_sh_wrappers",
    "engage_py",
    "pre_iter_check_sh",
    "audit_deep_sh",
    "agent_briefs_md",
    "docs_md",
    "scheduled_tasks_skill_md",
    "tools_py_subprocess",
    "registry_self_ref",
]

# Surfaces classified as "doc-only" (cite but don't actually invoke).
# A callable wired only in these surfaces is `unwired-but-cited`, not
# `wired-not-yet-invoked`.
DOC_ONLY_SURFACES = {
    "docs_md",
    "agent_briefs_md",
    "scheduled_tasks_skill_md",  # SKILL.md cites count as wiring (cron path)
}

# Wiring surfaces (non-doc) - any of these = real wiring.
# scheduled_tasks_skill_md is actually a wiring surface (cron loops invoke)
# but cite-only mention in a SKILL.md without subprocess.run is doc-only.
# We treat it as wiring by default since cron loops fire them.
WIRING_SURFACES = {
    "makefile",
    "pre_submit_check_and_sh_wrappers",
    "engage_py",
    "pre_iter_check_sh",
    "audit_deep_sh",
    "scheduled_tasks_skill_md",
    "tools_py_subprocess",
}

_SNIPPET_MAX = 200

_DEFAULT_SCHEDULED_TASKS_DIR = Path.home() / ".claude" / "scheduled-tasks"
_DEFAULT_AUDITS_DIR = Path.home() / "audits"
_DEFAULT_CALL_LOG = ".auditooor/mcp_call_log.jsonl"
_DEFAULT_GLOBAL_CLAUDE_MD = Path.home() / ".claude" / "CLAUDE.md"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_root_from_cwd(start: Path) -> Path | None:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "Makefile").is_file() and (cur / "tools").is_dir():
            return cur
        cur = cur.parent
    return None


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_lines(path: Path) -> list[str] | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fp:
            return fp.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def _normalize_callable(name: str) -> str:
    """Normalize callable name to `vault_X` form."""
    name = name.strip()
    if name.startswith("vault_"):
        return name
    return f"vault_{name}"


def _candidate_search_terms(callable_name: str) -> list[str]:
    """Search terms to grep for per file.

    A callable invocation looks like one of these in real wiring:
      - `--call vault_X` (CLI flag, most common)
      - `--call=vault_X`
      - `"vault_X"` (string literal in Python wrapper)
      - `'vault_X'`
      - `vault_X` bare (Python registry reference, may produce FP)

    The bare form is used as a fall-back so callables with no surrounding
    quotes still match (e.g. in CLAUDE.md prose). The boundary check in
    `_line_matches` prevents `vault_X` from matching `vault_X_v2`.
    """
    name = _normalize_callable(callable_name)
    return [
        f"--call {name}",
        f"--call={name}",
        f'"{name}"',
        f"'{name}'",
        name,  # fallback bare form with boundary check
    ]


def _line_matches(line: str, terms: list[str]) -> str | None:
    """Return the longest matching term or ``None``.

    Boundary check: terms must not be embedded inside a larger identifier.
    """
    for term in terms:
        idx = line.find(term)
        while idx != -1:
            left_ok = idx == 0 or not (line[idx - 1].isalnum() or line[idx - 1] == "_")
            end = idx + len(term)
            right_ok = end >= len(line) or not (line[end].isalnum() or line[end] == "_")
            if left_ok and right_ok:
                return term
            idx = line.find(term, idx + 1)
    return None


def _snippet(line: str) -> str:
    s = line.strip()
    if len(s) > _SNIPPET_MAX:
        s = s[:_SNIPPET_MAX - 3] + "..."
    return s


def _iter_files(root: Path, rel_globs: list[str]) -> list[Path]:
    out: list[Path] = []
    for rel in rel_globs:
        if "*" in rel or "?" in rel:
            out.extend(p for p in root.glob(rel) if p.is_file())
        else:
            p = root / rel
            if p.is_file():
                out.append(p)
    return sorted(set(out))


def _scan_files(
    files: list[Path],
    terms: list[str],
    surface: str,
    root: Path,
    *,
    self_path_rel: str | None,
    test_file_basenames: set[str] | None,
    exclude_self: bool,
    exclude_test: bool,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in files:
        rel = _safe_rel(path, root)
        is_self = self_path_rel is not None and rel == self_path_rel
        is_test = test_file_basenames is not None and path.name in test_file_basenames
        if exclude_self and is_self:
            continue
        if exclude_test and is_test:
            continue
        lines = _read_lines(path)
        if lines is None:
            continue
        for lineno, line in enumerate(lines, start=1):
            if _line_matches(line, terms):
                out.append({
                    "surface": surface,
                    "file": rel,
                    "line": lineno,
                    "context_snippet": _snippet(line),
                    "is_self": is_self,
                    "is_test": is_test,
                })
    return out


def _surface_makefile(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, ["Makefile", "*.mk", "tools/*.mk", "tools/**/*.mk"])
    return _scan_files(files, terms, "makefile", root, **kwargs)


def _surface_presubmit_and_sh(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, [
        "tools/pre-submit-check.sh",
        "tools/*.sh",
        "tools/**/*.sh",
    ])
    excluded_names = {"pre-iter-check.sh", "audit-deep.sh"}
    files = [f for f in files if f.name not in excluded_names]
    return _scan_files(files, terms, "pre_submit_check_and_sh_wrappers", root, **kwargs)


def _surface_engage_py(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, ["tools/engage.py"])
    return _scan_files(files, terms, "engage_py", root, **kwargs)


def _surface_pre_iter_check_sh(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, ["tools/pre-iter-check.sh"])
    return _scan_files(files, terms, "pre_iter_check_sh", root, **kwargs)


def _surface_audit_deep_sh(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, [
        "tools/audit-deep.sh",
        "tools/audit-deep-*.sh",
    ])
    return _scan_files(files, terms, "audit_deep_sh", root, **kwargs)


def _surface_agent_briefs_md(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, [
        "agent_briefs/*.md",
        "agent_briefs/**/*.md",
    ])
    return _scan_files(files, terms, "agent_briefs_md", root, **kwargs)


def _surface_docs_md(root: Path, terms: list[str], *,
                    exclude_archive: bool = False,
                    extra_dirs: list[Path] | None = None,
                    include_global_claude_md: bool = False,
                    **kwargs) -> list[dict[str, Any]]:
    files = _iter_files(root, [
        "docs/*.md",
        "docs/**/*.md",
        "README.md",
        "CLAUDE.md",
        "AGENTS.md",
        "WORKFLOW.md",
        "SKILL.md",
        "SKILL_ISSUES.md",
        "INDEX.md",
        "INVARIANT_LEDGER.md",
        "reports/*.md",
        "reports/**/*.md",
    ])
    if exclude_archive:
        files = [f for f in files
                 if "/archive/" not in str(f) and "/_archive/" not in str(f)]
    if extra_dirs:
        for extra in extra_dirs:
            if extra.is_dir():
                for p in extra.rglob("*.md"):
                    if p.is_file():
                        files.append(p)
        files = sorted(set(files))
    if include_global_claude_md and _DEFAULT_GLOBAL_CLAUDE_MD.is_file():
        files.append(_DEFAULT_GLOBAL_CLAUDE_MD)
    return _scan_files(files, terms, "docs_md", root, **kwargs)


def _surface_scheduled_tasks_skill_md(scheduled_dir: Path, terms: list[str],
                                     root: Path, **kwargs) -> list[dict[str, Any]]:
    if not scheduled_dir.is_dir():
        return []
    files = []
    for d in sorted(scheduled_dir.iterdir()):
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.md")):
            if p.is_file():
                files.append(p)
    return _scan_files(files, terms, "scheduled_tasks_skill_md", root, **kwargs)


def _surface_tools_py_subprocess(root: Path, terms: list[str], **kwargs) -> list[dict[str, Any]]:
    """Surface 9: subprocess.run / direct refs in tools/*.py.

    Excludes engage.py (own surface) and vault-mcp-server.py (handled by
    registry_self_ref surface) so we don't double-count the registry
    references that every callable trivially produces.
    """
    files = _iter_files(root, [
        "tools/*.py",
        "tools/**/*.py",
    ])
    files = [f for f in files if f.name not in ("engage.py", "vault-mcp-server.py")]
    return _scan_files(files, terms, "tools_py_subprocess", root, **kwargs)


def _surface_registry_self_ref(root: Path, callable_name: str) -> list[dict[str, Any]]:
    """Surface 10: registry self-reference in vault-mcp-server.py.

    Always emits 1 hit if the callable is registered in TOOL_SCHEMAS.
    Use a strict quoted match to avoid double-counting bare refs already
    captured by surface 9.
    """
    server = root / "tools" / "vault-mcp-server.py"
    if not server.is_file():
        return []
    name = _normalize_callable(callable_name)
    lines = _read_lines(server)
    if lines is None:
        return []
    out = []
    quoted_terms = [f'"{name}"', f"'{name}'"]
    for lineno, line in enumerate(lines, start=1):
        if _line_matches(line, quoted_terms):
            out.append({
                "surface": "registry_self_ref",
                "file": "tools/vault-mcp-server.py",
                "line": lineno,
                "context_snippet": _snippet(line),
                "is_self": True,
                "is_test": False,
            })
            # Only need one registry hit to confirm registration.
            break
    return out


def _surface_audits_workspace_md(audits_dir: Path, terms: list[str],
                                root: Path, **kwargs) -> list[dict[str, Any]]:
    if not audits_dir.is_dir():
        return []
    files: list[Path] = []
    for ws in sorted(audits_dir.iterdir()):
        if not ws.is_dir():
            continue
        for pat in ("*.md", ".auditooor/*.md", "submissions/*.md",
                   "*.sh", ".auditooor/*.sh"):
            files.extend(ws.glob(pat))
    files = sorted(set(p for p in files if p.is_file()))
    return _scan_files(files, terms, "docs_md", root, **kwargs)


def _find_test_files(callable_name: str, root: Path) -> set[str]:
    """Test file basenames that exercise this callable.

    Convention: tests live at tools/tests/test_<callable>.py or
    tools/tests/test_vault_mcp_server*.py.
    """
    name = _normalize_callable(callable_name)
    stem = name.replace("vault_", "")
    candidates = {
        f"test_{name}.py",
        f"test_{stem}.py",
        f"test_vault_mcp_server.py",
        f"test_callable_caller_detector.py",
    }
    found = set()
    for c in candidates:
        p = root / "tools" / "tests" / c
        if p.is_file():
            found.add(c)
    return found


def _count_invocations(call_log_path: Path, callable_name: str) -> int:
    """Count occurrences of ``callable`` in the MCP call log JSONL."""
    if not call_log_path.is_file():
        return 0
    name = _normalize_callable(callable_name)
    count = 0
    try:
        with call_log_path.open("r", encoding="utf-8", errors="replace") as fp:
            for raw in fp:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if rec.get("callable") == name:
                    count += 1
    except OSError:
        return 0
    return count


def _list_all_callables(root: Path) -> list[str]:
    """Parse the vault-mcp-server.py TOOL_SCHEMAS registry to list all callables.

    Looks for the argparse `--call choices=[...]` line which is the
    authoritative gate: every callable that the server accepts is in
    that list, and only that list. Falls back to parsing TOOL_SCHEMAS
    dict-name fields if the choices line is not found.
    """
    server = root / "tools" / "vault-mcp-server.py"
    if not server.is_file():
        return []
    lines = _read_lines(server)
    if lines is None:
        return []
    names: set[str] = set()

    # Authoritative source: TOOL_SCHEMAS list of {"name": "vault_X", ...}.
    # The dispatcher uses `tool["name"] for tool in TOOL_SCHEMAS` to build
    # the --call argparse choices, so name="vault_X" entries are canonical.
    name_pat = re.compile(r'"name"\s*:\s*"(vault_[a-z0-9_]+)"')
    for line in lines:
        for m in name_pat.finditer(line):
            names.add(m.group(1))

    if names:
        return sorted(names)

    # Fallback: any "vault_X" string literal (looser; produces FPs).
    pat = re.compile(r'"(vault_[a-z0-9_]+)"')
    for line in lines:
        for m in pat.finditer(line):
            names.add(m.group(1))
    return sorted(names)


def _detect(
    callable_input: str,
    *,
    root: Path,
    scope: str,
    scheduled_tasks_dir: Path,
    audits_dir: Path,
    call_log_path: Path,
    include_self: bool,
    include_test: bool,
    exclude_archive: bool,
    extra_doc_dirs: list[Path] | None,
    include_global_claude_md: bool,
) -> dict[str, Any]:
    """Run all 10 surface scans + return a structured verdict dict."""
    callable_name = _normalize_callable(callable_input)
    terms = _candidate_search_terms(callable_name)
    test_basenames = _find_test_files(callable_name, root)

    exclude_self = not include_self
    exclude_test = not include_test

    self_path_rel = "tools/callable-caller-detector.py"

    common = {
        "self_path_rel": self_path_rel,
        "test_file_basenames": test_basenames or None,
        "exclude_self": exclude_self,
        "exclude_test": exclude_test,
    }

    callers: list[dict[str, Any]] = []

    callers.extend(_surface_makefile(root, terms, **common))
    callers.extend(_surface_presubmit_and_sh(root, terms, **common))
    callers.extend(_surface_engage_py(root, terms, **common))
    callers.extend(_surface_pre_iter_check_sh(root, terms, **common))
    callers.extend(_surface_audit_deep_sh(root, terms, **common))
    callers.extend(_surface_agent_briefs_md(root, terms, **common))
    callers.extend(_surface_docs_md(
        root, terms,
        exclude_archive=exclude_archive,
        extra_dirs=extra_doc_dirs,
        include_global_claude_md=include_global_claude_md,
        **common))
    callers.extend(_surface_scheduled_tasks_skill_md(
        scheduled_tasks_dir, terms, root, **common))
    callers.extend(_surface_tools_py_subprocess(root, terms, **common))
    callers.extend(_surface_registry_self_ref(root, callable_name))

    if scope in ("workspace", "all"):
        callers.extend(_surface_audits_workspace_md(
            audits_dir, terms, root, **common))

    invocation_count = _count_invocations(call_log_path, callable_name)
    registered = any(c["surface"] == "registry_self_ref" for c in callers)

    by_surface: dict[str, int] = {s: 0 for s in SURFACES_ORDER}
    for c in callers:
        by_surface[c["surface"]] = by_surface.get(c["surface"], 0) + 1

    surfaces_wired_in = sorted([s for s, n in by_surface.items() if n > 0])
    # surface_count counts only the wiring surfaces (excluding registry_self_ref
    # because that's auto-emitted for every registered callable, not a wire).
    non_self_wiring = [s for s in surfaces_wired_in
                       if s in WIRING_SURFACES and s != "registry_self_ref"]
    surface_count = len(non_self_wiring)

    has_doc_only = any(s in DOC_ONLY_SURFACES for s in surfaces_wired_in
                       if s != "registry_self_ref")

    if invocation_count >= 10:
        verdict = "live-frequent"
    elif invocation_count >= 1:
        verdict = "live-low-volume"
    elif surface_count >= 1:
        verdict = "wired-not-yet-invoked"
    elif has_doc_only:
        verdict = "unwired-but-cited"
    else:
        verdict = "dead-no-caller"

    return {
        "schema": SCHEMA_VERSION,
        "callable": callable_name,
        "verdict": verdict,
        "invocation_count": invocation_count,
        "surfaces_wired_in": surfaces_wired_in,
        "surface_count": surface_count,
        "callers": callers,
        "caller_count_by_surface": by_surface,
        "scope": scope,
        "root": str(root),
        "surfaces_searched": list(SURFACES_ORDER),
        "registered_in_server": registered,
        "test_file_basenames": sorted(test_basenames),
        "search_terms": terms,
        "timestamp_utc": _now_iso(),
    }


def _emit_text(result: dict[str, Any]) -> str:
    lines = []
    lines.append(f"callable: {result['callable']}")
    lines.append(f"verdict: {result['verdict']}")
    lines.append(f"invocation_count: {result['invocation_count']}")
    lines.append(f"surface_count: {result['surface_count']}")
    lines.append(f"surfaces_wired_in: {result['surfaces_wired_in']}")
    lines.append(f"registered_in_server: {result['registered_in_server']}")
    lines.append("caller_count_by_surface:")
    for s in SURFACES_ORDER:
        lines.append(f"  {s}: {result['caller_count_by_surface'].get(s, 0)}")
    if result["callers"]:
        lines.append("callers:")
        for c in result["callers"][:50]:
            flag = ""
            if c.get("is_self"):
                flag += " [self]"
            if c.get("is_test"):
                flag += " [test]"
            lines.append(
                f"  - [{c['surface']}] {c['file']}:{c['line']}{flag}: {c['context_snippet']}"
            )
        if len(result["callers"]) > 50:
            lines.append(f"  ... ({len(result['callers']) - 50} more)")
    return "\n".join(lines) + "\n"


def _exit_code_for(verdict: str) -> int:
    if verdict in ("live-frequent", "live-low-volume", "wired-not-yet-invoked"):
        return 0
    if verdict in ("unwired-but-cited", "dead-no-caller"):
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="callable-caller-detector",
        description=__doc__.splitlines()[0] if __doc__ else None,
    )
    parser.add_argument("callable", nargs="?",
                        help="MCP callable name (e.g. vault_resume_context).")
    parser.add_argument("--batch",
                        help="Path to file with one callable per line.")
    parser.add_argument("--all", action="store_true",
                        help="Run on every callable registered in the server.")
    parser.add_argument("--scope", choices=("local", "workspace", "all"),
                        default="local",
                        help="Search scope (default: local).")
    parser.add_argument("--root",
                        help="Repository root (default: walk up from cwd).")
    parser.add_argument("--scheduled-tasks-dir",
                        default=os.environ.get(
                            "AUDITOOOR_CALLABLE_CALLER_SCHEDULED_TASKS_DIR",
                            str(_DEFAULT_SCHEDULED_TASKS_DIR)),
                        help="Override scheduled-tasks dir for SKILL.md surface.")
    parser.add_argument("--audits-dir",
                        default=os.environ.get(
                            "AUDITOOOR_CALLABLE_CALLER_AUDITS_DIR",
                            str(_DEFAULT_AUDITS_DIR)),
                        help="Override audits dir for workspace/all scope.")
    parser.add_argument("--call-log",
                        default=os.environ.get(
                            "AUDITOOOR_CALLABLE_CALLER_CALL_LOG",
                            _DEFAULT_CALL_LOG),
                        help="Override mcp_call_log.jsonl path.")
    parser.add_argument("--include-global-claude-md", action="store_true",
                        help="Include ~/.claude/CLAUDE.md in docs surface.")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of human-readable text.")
    parser.add_argument("--ndjson", action="store_true",
                        help="With --all or --batch, emit one JSON per line.")
    parser.add_argument("--include-self", action="store_true",
                        help="Include the detector's own file as a caller.")
    parser.add_argument("--include-test", action="store_true",
                        help="Include the dedicated test file as a caller.")
    parser.add_argument("--exclude-archive", action="store_true",
                        help="Exclude docs/archive/* and docs/_archive/*.")
    parser.add_argument("--extra-doc-dirs",
                        help="Newline-separated extra doc dirs to scan.")
    args = parser.parse_args(argv)

    if not args.callable and not args.batch and not args.all:
        parser.error("either <callable>, --batch <file>, or --all is required")

    if sum(bool(x) for x in (args.callable, args.batch, args.all)) > 1:
        parser.error("--batch / --all / positional <callable> are mutually exclusive")

    # Resolve repo root.
    if args.root:
        root = Path(args.root).expanduser().resolve()
    else:
        root = _repo_root_from_cwd(Path.cwd())
        if root is None:
            root = Path(__file__).resolve().parents[1]

    if not (root / "tools").is_dir():
        print(f"[error] root {root} has no tools/ subdir", file=sys.stderr)
        return 2

    scheduled_tasks_dir = Path(args.scheduled_tasks_dir).expanduser().resolve()
    audits_dir = Path(args.audits_dir).expanduser().resolve()

    # Call log: if relative, resolve under root.
    call_log_path = Path(args.call_log).expanduser()
    if not call_log_path.is_absolute():
        call_log_path = root / call_log_path
    call_log_path = call_log_path.resolve()

    extra_doc_dirs: list[Path] = []
    env_extras = os.environ.get("AUDITOOOR_CALLABLE_CALLER_EXTRA_DOC_DIRS", "").strip()
    if env_extras:
        extra_doc_dirs.extend(Path(p).expanduser().resolve()
                              for p in env_extras.splitlines() if p.strip())
    if args.extra_doc_dirs:
        extra_doc_dirs.extend(Path(p).expanduser().resolve()
                              for p in args.extra_doc_dirs.splitlines() if p.strip())

    def _run_one(name: str) -> dict[str, Any]:
        try:
            return _detect(
                name,
                root=root,
                scope=args.scope,
                scheduled_tasks_dir=scheduled_tasks_dir,
                audits_dir=audits_dir,
                call_log_path=call_log_path,
                include_self=args.include_self,
                include_test=args.include_test,
                exclude_archive=args.exclude_archive,
                extra_doc_dirs=extra_doc_dirs or None,
                include_global_claude_md=args.include_global_claude_md,
            )
        except (OSError, RuntimeError) as exc:
            return {
                "schema": SCHEMA_VERSION,
                "callable": _normalize_callable(name),
                "verdict": "error",
                "error": str(exc),
                "timestamp_utc": _now_iso(),
            }

    # Batch / --all mode.
    if args.batch or args.all:
        if args.all:
            names = _list_all_callables(root)
        else:
            bpath = Path(args.batch).expanduser().resolve()
            if not bpath.is_file():
                print(f"[error] batch file not found: {bpath}", file=sys.stderr)
                return 2
            names = []
            with bpath.open("r", encoding="utf-8") as fp:
                for raw in fp:
                    n = raw.strip()
                    if not n or n.startswith("#"):
                        continue
                    names.append(n)
        results: list[dict[str, Any]] = []
        for name in names:
            results.append(_run_one(name))
        if args.ndjson:
            for r in results:
                sys.stdout.write(json.dumps(r, sort_keys=True) + "\n")
        elif args.json:
            json.dump({"schema": SCHEMA_VERSION + ".batch",
                       "results": results,
                       "count": len(results)},
                      sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            for r in results:
                sys.stdout.write(json.dumps(r, sort_keys=True) + "\n")
        if any(r.get("verdict") == "error" for r in results):
            return 2
        if any(r.get("verdict") in ("unwired-but-cited", "dead-no-caller")
               for r in results):
            return 1
        return 0

    result = _run_one(args.callable)
    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(_emit_text(result))
    return _exit_code_for(result.get("verdict", "error"))


if __name__ == "__main__":
    sys.exit(main())
