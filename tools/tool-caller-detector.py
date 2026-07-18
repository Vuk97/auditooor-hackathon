#!/usr/bin/env python3
"""tool-caller-detector.py - hardened "dead-tool" criterion across 9 caller surfaces.

# Rule 36 + Rule 55: this tool emits no corpus record.
# Purpose-tier: active-gate (Phase MINUS-1 WIRE-1 / WF-10 false-positive fix).

Background:
  WF-10's "Adversarial Pruning" report flagged 261 dead-candidate tools
  using grep against ONLY Makefile + pre-submit-check.sh. NEG-A then deleted
  33 of them. RESTORE-1 had to restore 13 hunt-relevant tools because
  WF-10's caller-surface check missed the rest:

    - engage.py (32-stage chain; auto-invokes many tools as stages)
    - pre-iter-check.sh (iter-bootstrap hook)
    - tools/audit-deep.sh (audit-deep recipe)
    - agent_briefs/*.md (canonical usage references)
    - docs/HACKERMAN_*.md / docs/MCP_*.md / etc. (canonical anchors)
    - ~/.claude/scheduled-tasks/*/SKILL.md (cron callers)
    - tools/*.py (subprocess.run / importlib.import_module references)

  This tool closes that gap: it searches all 9 caller surfaces and returns a
  structured verdict per tool. Designed to be re-run against the 24 NEG-A
  net deletes + 13 RESTORE-1 restores to confirm WF-10's call rates were
  systematically biased.

CLI:
  python3 tools/tool-caller-detector.py <tool-name>
                                       [--scope local|workspace|all]
                                       [--root <repo-root>]
                                       [--scheduled-tasks-dir <path>]
                                       [--json]
                                       [--include-self]
                                       [--include-test]
                                       [--exclude-archive]

  <tool-name> may be a basename (e.g. `pattern-migration-alert.py`),
  the path with the tools/ prefix, or omitted when using --batch.

  --batch <file>  read one tool name per line; emit one JSON object per
                  line (NDJSON) or a wrapped JSON list (with --json).

Scopes:
  - local:     search only the repo root (default).
  - workspace: search the repo root + ~/audits/* workspace clones.
  - all:       search the repo root + ~/audits + ~/.claude/scheduled-tasks.
               Distinguished from `workspace` because cron SKILL.md files
               live under ~/.claude, not under any audit workspace.

Verdicts (schema `auditooor.tool_caller_detector.v1`):
  - wired-in-N-surfaces       : >=1 caller in any surface (non-self, non-test).
  - dead-only-self-test-caller: callers only in own dedicated test file +/or self.
  - dead-no-caller            : zero callers across all surfaces.
  - error                     : input / runtime error.

Exit codes:
  0 - tool has callers (wired-in-*)
  1 - tool has no callers (dead-*)
  2 - input / runtime error

Surface priority order (matches the brief):
  1.  Makefile + sibling Makefiles
  2.  pre-submit-check.sh + tools/*.sh shell wrappers
  3.  engage.py + stage_* references
  4.  pre-iter-check.sh
  5.  tools/audit-deep.sh + tools/audit-deep-*.sh
  6.  agent_briefs/*.md
  7.  docs/*.md (canonical anchors)
  8.  ~/.claude/scheduled-tasks/*/SKILL.md (cron callers)
  9.  tools/*.py (subprocess.run / importlib.import_module / direct refs)

Output schema (per tool):
  {
    "schema": "auditooor.tool_caller_detector.v1",
    "tool": "<basename or rel path>",
    "tool_basename": "<basename only>",
    "verdict": "wired-in-N-surfaces | dead-only-self-test-caller | dead-no-caller | error",
    "callers": [
      {"surface": "<surface-name>",
       "file": "<rel-path>",
       "line": <int>,
       "context_snippet": "<trimmed source line>",
       "is_self": <bool>,
       "is_test": <bool>}
    ],
    "caller_count": <int>,
    "caller_count_by_surface": {"<surface>": <int>, ...},
    "scope": "local | workspace | all",
    "root": "<absolute root path>",
    "surfaces_searched": [<9 surface names>],
    "timestamp_utc": "<ISO-8601>"
  }

Empirical anchor:
  WF-10 (`reports/v3_iter_2026-05-23_iter17/workflow_giga_inspection/WF10_adversarial_pruning.md`)
  applied a 4-surface heuristic that missed all 5 non-Makefile invocation
  paths. NEG-A deleted 33 tools; RESTORE-1 had to restore 13. This tool
  rebuilds the criterion across the 9 actual invocation surfaces so a
  future pruning lane gets a true caller count, not a Makefile-only one.

Environment hooks:
  AUDITOOOR_TOOL_CALLER_SCHEDULED_TASKS_DIR
    Override ~/.claude/scheduled-tasks for the SKILL.md surface.
  AUDITOOOR_TOOL_CALLER_AUDITS_DIR
    Override ~/audits/* glob for workspace/all scope.
  AUDITOOOR_TOOL_CALLER_EXTRA_DOC_DIRS
    Newline-separated extra doc roots to scan (joined to docs/).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.tool_caller_detector.v1"
GATE = "TOOL-CALLER-DETECTOR"

# Ordered list of surfaces as the brief requires.
SURFACES_ORDER = [
    "makefile",
    "pre_submit_check_and_sh_wrappers",
    "engage_py",
    "pre_iter_check_sh",
    "audit_deep_sh",
    "agent_briefs_md",
    "docs_md",
    "scheduled_tasks_skill_md",
    "tools_py_subprocess_or_import",
]

# Snippet length cap for context column.
_SNIPPET_MAX = 200

# Default scheduled-tasks dir (cron SKILL.md surface).
_DEFAULT_SCHEDULED_TASKS_DIR = Path.home() / ".claude" / "scheduled-tasks"

# Default audits dir for workspace/all scope.
_DEFAULT_AUDITS_DIR = Path.home() / "audits"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_root_from_cwd(start: Path) -> Path | None:
    """Walk up from ``start`` looking for the repo root (Makefile + tools/)."""
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


def _basename_of(tool_name: str) -> str:
    name = tool_name.strip()
    if "/" in name:
        name = name.split("/")[-1]
    return name


def _candidate_search_terms(tool_name: str) -> list[str]:
    """The grep set we look for per file.

    Use both the bare basename (`new-detector-wizard.py`) and the
    `tools/`-prefixed form because some callers cite the latter
    (e.g. Makefile `@python3 tools/<name>.py`) and others the former
    (e.g. `subprocess.run([..., "new-detector-wizard.py"])`).
    """
    base = _basename_of(tool_name)
    forms = {base, f"tools/{base}"}
    # The bare module form (strip .py) is sometimes used by importlib calls
    # or by SKILL.md prose ("uses the new-detector-wizard helper").
    if base.endswith(".py"):
        forms.add(base[:-3])
        # Snake-case module form (importlib.import_module accepts dashes
        # only via importlib.util; the dot-style module form is the
        # common path for `from tools.X import Y` so add both.)
        snake = base[:-3].replace("-", "_")
        forms.add(snake)
        forms.add(f"tools.{snake}")
    return sorted(forms, key=len, reverse=True)


def _line_matches(line: str, terms: list[str]) -> str | None:
    """Return the longest matching term in ``line`` or ``None``.

    Boundary check: terms must not be embedded in a larger identifier
    (e.g. `mytool.py` should NOT match `not-mytool.py`). The boundary
    is the regex word boundary or path separators.
    """
    for term in terms:
        # Use a simple substring search first (fast), then a boundary
        # check to suppress false hits inside larger identifiers.
        idx = line.find(term)
        while idx != -1:
            left_ok = idx == 0 or not (line[idx - 1].isalnum() or line[idx - 1] in "_-")
            end = idx + len(term)
            right_ok = end >= len(line) or not (line[end].isalnum() or line[end] in "_-")
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
    """Resolve a list of glob patterns relative to ``root`` to file Paths."""
    out: list[Path] = []
    for rel in rel_globs:
        if "*" in rel or "?" in rel:
            out.extend(p for p in root.glob(rel) if p.is_file())
        else:
            p = root / rel
            if p.is_file():
                out.append(p)
    # Stable sorted output across runs.
    return sorted(set(out))


def _scan_files(
    files: list[Path],
    terms: list[str],
    surface: str,
    root: Path,
    *,
    tool_path_rel: str,
    test_file_basename: str | None,
    exclude_self: bool,
    exclude_test: bool,
) -> list[dict[str, Any]]:
    """Scan a list of files for any line containing one of ``terms``.

    Each hit is tagged with surface, file, line, snippet, and the
    self/test flags so the caller can later filter by those.
    """
    out: list[dict[str, Any]] = []
    for path in files:
        rel = _safe_rel(path, root)
        is_self = (rel == tool_path_rel)
        is_test = test_file_basename is not None and path.name == test_file_basename
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


def _surface_makefile(root: Path, terms: list[str], tool_path_rel: str,
                     test_basename: str | None, exclude_self: bool,
                     exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 1: Makefile + sibling makefiles."""
    files = _iter_files(root, ["Makefile", "*.mk", "tools/*.mk", "tools/**/*.mk"])
    return _scan_files(files, terms, "makefile", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_presubmit_and_sh(root: Path, terms: list[str], tool_path_rel: str,
                              test_basename: str | None, exclude_self: bool,
                              exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 2: pre-submit-check.sh + tools/*.sh shell wrappers.

    Excludes engage.py / pre-iter-check.sh / audit-deep.sh handled below.
    """
    files = _iter_files(root, [
        "tools/pre-submit-check.sh",
        "tools/*.sh",
        "tools/**/*.sh",
    ])
    # Drop the three .sh entrypoints that have their own surface.
    excluded_names = {"pre-iter-check.sh", "audit-deep.sh"}
    files = [f for f in files if f.name not in excluded_names]
    return _scan_files(files, terms, "pre_submit_check_and_sh_wrappers", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_engage_py(root: Path, terms: list[str], tool_path_rel: str,
                      test_basename: str | None, exclude_self: bool,
                      exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 3: engage.py (32-stage chain) + stage_* references."""
    files = _iter_files(root, ["tools/engage.py"])
    return _scan_files(files, terms, "engage_py", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_pre_iter_check_sh(root: Path, terms: list[str], tool_path_rel: str,
                              test_basename: str | None, exclude_self: bool,
                              exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 4: pre-iter-check.sh (iter-bootstrap hook)."""
    files = _iter_files(root, ["tools/pre-iter-check.sh"])
    return _scan_files(files, terms, "pre_iter_check_sh", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_audit_deep_sh(root: Path, terms: list[str], tool_path_rel: str,
                          test_basename: str | None, exclude_self: bool,
                          exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 5: tools/audit-deep.sh + sibling audit-deep-*.sh files."""
    files = _iter_files(root, [
        "tools/audit-deep.sh",
        "tools/audit-deep-*.sh",
    ])
    return _scan_files(files, terms, "audit_deep_sh", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_agent_briefs_md(root: Path, terms: list[str], tool_path_rel: str,
                            test_basename: str | None, exclude_self: bool,
                            exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 6: agent_briefs/*.md."""
    files = _iter_files(root, [
        "agent_briefs/*.md",
        "agent_briefs/**/*.md",
    ])
    return _scan_files(files, terms, "agent_briefs_md", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_docs_md(root: Path, terms: list[str], tool_path_rel: str,
                    test_basename: str | None, exclude_self: bool,
                    exclude_test: bool, *,
                    exclude_archive: bool = False,
                    extra_dirs: list[Path] | None = None) -> list[dict[str, Any]]:
    """Surface 7: docs/*.md (canonical anchors)."""
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
    ])
    if exclude_archive:
        files = [f for f in files if "/archive/" not in str(f) and "/_archive/" not in str(f)]
    if extra_dirs:
        for extra in extra_dirs:
            if extra.is_dir():
                for p in extra.rglob("*.md"):
                    if p.is_file():
                        files.append(p)
        files = sorted(set(files))
    return _scan_files(files, terms, "docs_md", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_scheduled_tasks_skill_md(scheduled_dir: Path, terms: list[str],
                                     root: Path, tool_path_rel: str,
                                     test_basename: str | None,
                                     exclude_self: bool,
                                     exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 8: ~/.claude/scheduled-tasks/*/SKILL.md (cron callers).

    These files live OUTSIDE the repo root; we still emit a relative path
    when possible (computed from the repo root parent), otherwise the
    absolute path is recorded.
    """
    if not scheduled_dir.is_dir():
        return []
    files = []
    for d in sorted(scheduled_dir.iterdir()):
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.md")):
            if p.is_file():
                files.append(p)
    return _scan_files(files, terms, "scheduled_tasks_skill_md", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_tools_py_subprocess(root: Path, terms: list[str], tool_path_rel: str,
                                test_basename: str | None,
                                exclude_self: bool,
                                exclude_test: bool) -> list[dict[str, Any]]:
    """Surface 9: tools/*.py + tools/**/*.py for cross-tool calls.

    Catches subprocess.run([..., 'tools/X.py']) and importlib.import_module
    and direct module-prefix imports.
    """
    files = _iter_files(root, [
        "tools/*.py",
        "tools/**/*.py",
    ])
    # Drop engage.py because surface 3 already handles it - avoid
    # double-counting hits.
    files = [f for f in files if f.name != "engage.py"]
    return _scan_files(files, terms, "tools_py_subprocess_or_import", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _surface_audits_workspace_md(audits_dir: Path, terms: list[str],
                                root: Path, tool_path_rel: str,
                                test_basename: str | None,
                                exclude_self: bool,
                                exclude_test: bool) -> list[dict[str, Any]]:
    """Optional extra surface (workspace + all scope): ~/audits/* .md/.sh files."""
    if not audits_dir.is_dir():
        return []
    files: list[Path] = []
    for ws in sorted(audits_dir.iterdir()):
        if not ws.is_dir():
            continue
        # Limit to .md and .sh inside each workspace - we don't recursively
        # walk every file (workspaces can be huge); the .auditooor/
        # subdir + briefs + scope + severity are the key surfaces.
        for pat in ("*.md", ".auditooor/*.md", "submissions/*.md",
                   "*.sh", ".auditooor/*.sh"):
            files.extend(ws.glob(pat))
    files = sorted(set(p for p in files if p.is_file()))
    # Re-use the "docs_md" surface name because workspace md is the same
    # category as canonical docs for the dead-or-alive verdict.
    return _scan_files(files, terms, "docs_md", root,
                       tool_path_rel=tool_path_rel,
                       test_file_basename=test_basename,
                       exclude_self=exclude_self,
                       exclude_test=exclude_test)


def _find_dedicated_test(tool_basename: str, root: Path) -> str | None:
    """Look up the conventional test file path for ``tool_basename``."""
    if not tool_basename.endswith(".py"):
        return None
    stem = tool_basename[:-3].replace("-", "_")
    candidates = [
        root / "tools" / "tests" / f"test_{stem}.py",
        root / "tests" / f"test_{stem}.py",
    ]
    for cand in candidates:
        if cand.is_file():
            return cand.name
    return None


def _resolve_tool_path_rel(tool_input: str, root: Path) -> str:
    """Return the canonical `tools/<basename>` relative path."""
    base = _basename_of(tool_input)
    return f"tools/{base}"


def _detect(
    tool_input: str,
    *,
    root: Path,
    scope: str,
    scheduled_tasks_dir: Path,
    audits_dir: Path,
    include_self: bool,
    include_test: bool,
    exclude_archive: bool,
    extra_doc_dirs: list[Path] | None,
) -> dict[str, Any]:
    """Run all 9 surface scans + return a structured verdict dict."""

    tool_basename = _basename_of(tool_input)
    tool_path_rel = _resolve_tool_path_rel(tool_input, root)
    test_basename = _find_dedicated_test(tool_basename, root)
    terms = _candidate_search_terms(tool_input)

    exclude_self = not include_self
    exclude_test = not include_test

    callers: list[dict[str, Any]] = []

    # Surfaces 1-9 in priority order.
    callers.extend(_surface_makefile(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))
    callers.extend(_surface_presubmit_and_sh(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))
    callers.extend(_surface_engage_py(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))
    callers.extend(_surface_pre_iter_check_sh(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))
    callers.extend(_surface_audit_deep_sh(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))
    callers.extend(_surface_agent_briefs_md(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))
    callers.extend(_surface_docs_md(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test,
        exclude_archive=exclude_archive,
        extra_dirs=extra_doc_dirs))
    callers.extend(_surface_scheduled_tasks_skill_md(
        scheduled_tasks_dir, terms, root, tool_path_rel, test_basename,
        exclude_self, exclude_test))
    callers.extend(_surface_tools_py_subprocess(
        root, terms, tool_path_rel, test_basename, exclude_self, exclude_test))

    # Optional workspace/all surface.
    if scope in ("workspace", "all"):
        callers.extend(_surface_audits_workspace_md(
            audits_dir, terms, root, tool_path_rel, test_basename,
            exclude_self, exclude_test))

    # Tally by surface (in declared order).
    by_surface: dict[str, int] = {s: 0 for s in SURFACES_ORDER}
    for c in callers:
        by_surface[c["surface"]] = by_surface.get(c["surface"], 0) + 1

    caller_count = len(callers)

    # Verdict.
    if caller_count == 0:
        verdict = "dead-no-caller"
    else:
        # Determine if all surviving callers are self or test only.
        # (With default flags `include_self=False, include_test=False`,
        # those are already excluded from callers, so non-empty means
        # `wired`. With `include_self=True` or `include_test=True` we
        # need to look at the flags to compute the variant verdict.)
        non_self_non_test = [c for c in callers
                             if not c.get("is_self") and not c.get("is_test")]
        if non_self_non_test:
            n_surfaces = sum(1 for s, n in by_surface.items() if n > 0)
            verdict = f"wired-in-{n_surfaces}-surfaces"
        else:
            verdict = "dead-only-self-test-caller"

    return {
        "schema": SCHEMA_VERSION,
        "tool": tool_path_rel,
        "tool_basename": tool_basename,
        "verdict": verdict,
        "callers": callers,
        "caller_count": caller_count,
        "caller_count_by_surface": by_surface,
        "scope": scope,
        "root": str(root),
        "surfaces_searched": list(SURFACES_ORDER),
        "test_file_basename": test_basename,
        "search_terms": terms,
        "timestamp_utc": _now_iso(),
    }


def _emit_text(result: dict[str, Any]) -> str:
    lines = []
    lines.append(f"tool: {result['tool']}")
    lines.append(f"verdict: {result['verdict']}")
    lines.append(f"caller_count: {result['caller_count']}")
    lines.append(f"scope: {result['scope']}")
    lines.append("caller_count_by_surface:")
    for s in SURFACES_ORDER:
        lines.append(f"  {s}: {result['caller_count_by_surface'].get(s, 0)}")
    if result["callers"]:
        lines.append("callers:")
        for c in result["callers"]:
            flag = ""
            if c.get("is_self"):
                flag += " [self]"
            if c.get("is_test"):
                flag += " [test]"
            lines.append(
                f"  - [{c['surface']}] {c['file']}:{c['line']}{flag}: {c['context_snippet']}"
            )
    return "\n".join(lines) + "\n"


def _exit_code_for(verdict: str) -> int:
    if verdict.startswith("wired-"):
        return 0
    if verdict.startswith("dead-"):
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tool-caller-detector",
        description=__doc__.splitlines()[0] if __doc__ else None,
    )
    parser.add_argument("tool", nargs="?",
                        help="Tool name to inspect (basename or tools/<name>.py).")
    parser.add_argument("--batch",
                        help="Path to file with one tool name per line.")
    parser.add_argument("--scope", choices=("local", "workspace", "all"),
                        default="local",
                        help="Search scope (default: local).")
    parser.add_argument("--root",
                        help="Repository root (default: walk up from cwd).")
    parser.add_argument("--scheduled-tasks-dir",
                        default=os.environ.get(
                            "AUDITOOOR_TOOL_CALLER_SCHEDULED_TASKS_DIR",
                            str(_DEFAULT_SCHEDULED_TASKS_DIR)),
                        help="Override scheduled-tasks dir for SKILL.md surface.")
    parser.add_argument("--audits-dir",
                        default=os.environ.get(
                            "AUDITOOOR_TOOL_CALLER_AUDITS_DIR",
                            str(_DEFAULT_AUDITS_DIR)),
                        help="Override audits dir for workspace/all scope.")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of human-readable text.")
    parser.add_argument("--include-self", action="store_true",
                        help="Include the tool's own file as a caller.")
    parser.add_argument("--include-test", action="store_true",
                        help="Include the dedicated test file as a caller.")
    parser.add_argument("--exclude-archive", action="store_true",
                        help="Exclude docs/archive/* and docs/_archive/*.")
    parser.add_argument("--extra-doc-dirs",
                        help="Newline-separated extra doc dirs to scan.")
    args = parser.parse_args(argv)

    if not args.tool and not args.batch:
        parser.error("either <tool> or --batch <file> is required")

    if args.tool and args.batch:
        parser.error("--batch is exclusive with positional <tool>")

    # Resolve repo root.
    if args.root:
        root = Path(args.root).expanduser().resolve()
    else:
        root = _repo_root_from_cwd(Path.cwd())
        if root is None:
            # Fall back to script location.
            root = Path(__file__).resolve().parents[1]

    if not (root / "tools").is_dir():
        print(f"[error] root {root} has no tools/ subdir", file=sys.stderr)
        return 2

    scheduled_tasks_dir = Path(args.scheduled_tasks_dir).expanduser().resolve()
    audits_dir = Path(args.audits_dir).expanduser().resolve()

    extra_doc_dirs: list[Path] = []
    env_extras = os.environ.get("AUDITOOOR_TOOL_CALLER_EXTRA_DOC_DIRS", "").strip()
    if env_extras:
        extra_doc_dirs.extend(Path(p).expanduser().resolve()
                              for p in env_extras.splitlines() if p.strip())
    if args.extra_doc_dirs:
        extra_doc_dirs.extend(Path(p).expanduser().resolve()
                              for p in args.extra_doc_dirs.splitlines() if p.strip())

    def _run_one(tool_input: str) -> dict[str, Any]:
        try:
            return _detect(
                tool_input,
                root=root,
                scope=args.scope,
                scheduled_tasks_dir=scheduled_tasks_dir,
                audits_dir=audits_dir,
                include_self=args.include_self,
                include_test=args.include_test,
                exclude_archive=args.exclude_archive,
                extra_doc_dirs=extra_doc_dirs or None,
            )
        except (OSError, RuntimeError) as exc:
            return {
                "schema": SCHEMA_VERSION,
                "tool": tool_input,
                "verdict": "error",
                "error": str(exc),
                "timestamp_utc": _now_iso(),
            }

    if args.batch:
        bpath = Path(args.batch).expanduser().resolve()
        if not bpath.is_file():
            print(f"[error] batch file not found: {bpath}", file=sys.stderr)
            return 2
        results: list[dict[str, Any]] = []
        with bpath.open("r", encoding="utf-8") as fp:
            for raw in fp:
                name = raw.strip()
                if not name or name.startswith("#"):
                    continue
                results.append(_run_one(name))
        if args.json:
            json.dump({"schema": SCHEMA_VERSION + ".batch",
                       "results": results,
                       "count": len(results)},
                      sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            for r in results:
                sys.stdout.write(json.dumps(r, sort_keys=True) + "\n")
        # Batch exit: 0 if every tool is wired; 1 if any dead; 2 on first error.
        if any(r.get("verdict") == "error" for r in results):
            return 2
        if any(r.get("verdict", "").startswith("dead-") for r in results):
            return 1
        return 0

    result = _run_one(args.tool)
    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(_emit_text(result))
    return _exit_code_for(result.get("verdict", "error"))


if __name__ == "__main__":
    sys.exit(main())
