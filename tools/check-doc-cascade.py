#!/usr/bin/env python3
"""check-doc-cascade.py — flag stale docs when tools/scripts change.

Background
----------
GPT-onboarding workflow scenario: an agent opens a PR that updates
``tools/<x>.py``. Today nothing enforces that ``README.md`` and any
``docs/*.md`` / ``reference/*.md`` that mention ``<x>.py`` are still
accurate — flag names, output paths, line citations, etc. drift silently.

Existing related guards:

* ``tools/check-stage-reference.py`` — narrow consistency between
  ``tools/engage.py`` STAGE_TABLE and ``docs/STAGE_REFERENCE.md``.
* ``tools/check-makefile-tool-refs.py`` — Makefile ↔ ``tools/`` filename
  existence.

Neither covers the general case "X.py changed AND X is referenced by
README/docs/Y.md, but Y.md wasn't updated". This tool fills that gap. It
is intentionally a *flagger*, not an editor — it never rewrites docs.

Algorithm
---------
1. Identify files changed in the current diff (vs. ``--base``, default
   ``origin/main``) that match ``tools/*.py`` or ``tools/*.sh`` (the
   canonical tool prefix). The ``--working-tree`` mode also includes
   uncommitted changes.
2. For each changed tool, scan ``README.md``, ``docs/*.md``, and
   ``reference/*.md`` for mentions of the tool's basename.
3. For each match, check the surrounding context:
   * Lists ``--flags`` or subcommands? Cross-check against the current
     tool's ``argparse`` definition (parsed via ``ast`` — no execution).
   * Lists output paths, JSONL, or ``docs/...`` artifact paths? Verify
     the path string still appears in the tool source.
   * Cites a specific line number (``tools/foo.py:L123`` or
     ``foo.py line 42``)? Verify the line still exists (file long
     enough). The line *content* is not pinned — too brittle.
4. Emit per-doc verdict:
     * ``OK``     — docs that are still consistent (or cross-checked).
     * ``STALE``  — docs that mention removed flags / changed paths /
                    invalid line numbers. Exit code 1 if any.
     * ``REVIEW`` — docs that mention the tool but consistency could
                    not be verified mechanically (just a reminder).

Output
------
* Stderr/stdout: a human-readable summary (``[OK]/[STALE]/[REVIEW]``).
* ``--json``: emit a structured JSON object on stdout instead.

Exit codes
----------
* 0 — no STALE doc references (REVIEW-only is still 0; review is
      advisory).
* 1 — at least one STALE reference detected.
* 2 — usage / I/O error.

Hard rules (project policy)
---------------------------
* Stdlib only.
* Never auto-update docs — only flag.
* Read-only on the working tree (no git mutations).

Usage
-----
::

    python3 tools/check-doc-cascade.py
    python3 tools/check-doc-cascade.py --base origin/main
    python3 tools/check-doc-cascade.py --working-tree
    python3 tools/check-doc-cascade.py --tool tools/engage.py --tool tools/poc-scaffold.py
    python3 tools/check-doc-cascade.py --json
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parent.parent

# Doc roots scanned for tool mentions. Add more here if/when new
# canonical doc directories appear. We deliberately do NOT scan
# ``_archive/`` or ``external/``.
DOC_ROOTS: tuple[tuple[str, str], ...] = (
    ("README.md", "file"),
    ("docs", "dir"),
    ("reference", "dir"),
)

# Files we never treat as a "tool change" even if they match the glob.
# Tests and __init__-style helpers do not have an external doc surface.
TOOL_EXCLUDE_PREFIXES: tuple[str, ...] = (
    "tools/tests/",
    "tools/_",  # private helpers like _analyzer_common.py
)

FLAG_RE = re.compile(r"(?<![A-Za-z0-9-])(--[a-z][a-z0-9-]+)(?![A-Za-z0-9_-])")
# Match any tool basename like ``foo.py`` / ``bar.sh`` so we can decide
# which tool a particular flag in a doc line is "closest" to. Used to
# avoid false-attributing one tool's flags to another tool when both
# basenames appear on the same line.
TOOL_BASENAME_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+\.(?:py|sh))(?![A-Za-z0-9_-])"
)
LINE_CITATION_RE = re.compile(
    r"(?P<base>[A-Za-z0-9_./-]+\.(?:py|sh))"
    r"(?:[:#]L?|\s+line\s+)"
    r"(?P<line>\d{1,6})\b",
    re.IGNORECASE,
)
PATH_CITATION_RE = re.compile(
    r"(?<![A-Za-z0-9_/.-])"
    r"(?P<path>(?:docs|reference|patterns|detectors|tools)/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+)"
    r"(?![A-Za-z0-9_/.-])"
)


def _git(args: list[str], repo: Path) -> str:
    """Run ``git`` and return stdout. Empty string on non-zero exit."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _changed_tools_from_git(repo: Path, base: str, working_tree: bool) -> list[str]:
    """List tool paths changed vs ``base``. Optionally include working tree."""
    out = _git(["diff", "--name-only", f"{base}...HEAD"], repo)
    paths = set(filter(None, out.splitlines()))
    if working_tree:
        paths.update(filter(None, _git(["diff", "--name-only", "HEAD"], repo).splitlines()))
        paths.update(filter(None, _git(["ls-files", "--others", "--exclude-standard"], repo).splitlines()))
    return sorted(p for p in paths if _is_tool_path(p))


def _is_tool_path(path: str) -> bool:
    if not (path.startswith("tools/") and (path.endswith(".py") or path.endswith(".sh"))):
        return False
    return not any(path.startswith(pref) for pref in TOOL_EXCLUDE_PREFIXES)


def _iter_doc_files(repo: Path) -> Iterable[Path]:
    for entry, kind in DOC_ROOTS:
        target = repo / entry
        if kind == "file":
            if target.is_file():
                yield target
        elif kind == "dir" and target.is_dir():
            for p in sorted(target.rglob("*.md")):
                # Skip archived sub-directories.
                rel = p.relative_to(repo).as_posix()
                if "/archive/" in rel or rel.startswith("docs/archive/"):
                    continue
                yield p


def _extract_argparse_flags(tool_path: Path) -> set[str] | None:
    """Parse a Python tool's argparse flags via AST. Return ``None`` if the
    tool is not Python or the flags can't be statically determined."""
    if tool_path.suffix != ".py" or not tool_path.is_file():
        return None
    try:
        tree = ast.parse(tool_path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None

    flags: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # match parser.add_argument(...) — attribute name only, not receiver.
        if not (isinstance(func, ast.Attribute) and func.attr == "add_argument"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith("--"):
                    flags.add(arg.value)
    return flags


def _extract_paths(tool_path: Path) -> set[str]:
    """String literals that look like in-repo artifact paths."""
    if not tool_path.is_file():
        return set()
    text = tool_path.read_text(encoding="utf-8", errors="replace")
    return {m.group("path") for m in PATH_CITATION_RE.finditer(text)}


def _file_line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return sum(1 for _ in fh)


def _doc_mentions_tool(doc_text: str, tool_basename: str, tool_path_rel: str) -> list[int]:
    """Return 1-indexed line numbers in ``doc_text`` that mention the tool.

    We match on either the basename (``foo.py``) or the full repo-relative
    path (``tools/foo.py``). Word boundary handled manually because
    Python's ``\b`` doesn't bracket ``.`` properly for filenames.
    """
    lines = doc_text.splitlines()
    matches: list[int] = []
    for i, line in enumerate(lines, start=1):
        if tool_path_rel in line:
            matches.append(i)
            continue
        # Conservative basename match — must be flanked by non-identifier chars.
        idx = 0
        while True:
            j = line.find(tool_basename, idx)
            if j < 0:
                break
            left_ok = j == 0 or not (line[j - 1].isalnum() or line[j - 1] in "_./-")
            end = j + len(tool_basename)
            right_ok = end == len(line) or not (line[end].isalnum() or line[end] in "_/-")
            if left_ok and right_ok:
                matches.append(i)
                break
            idx = j + 1
    return matches


def _classify_doc(
    *,
    doc_path: Path,
    doc_text: str,
    tool_path: Path,
    tool_basename: str,
    tool_path_rel: str,
    repo: Path,
) -> tuple[str, list[str]]:
    """Return ``(verdict, evidence_lines)`` for one (tool, doc) pair.

    ``verdict`` is one of ``"OK"``, ``"STALE"``, or ``"REVIEW"``.
    """
    mention_lines = _doc_mentions_tool(doc_text, tool_basename, tool_path_rel)
    if not mention_lines:
        return ("OK", [])

    evidence: list[str] = []

    # 1. Flag drift — flag attribution from natural-language prose is
    #    fundamentally ambiguous (e.g. ``engage.py --src src is
    #    hardcoded`` actually documents a flag passed downstream by
    #    engage.py to ``ccia.py``). To stay fail-closed *only* on
    #    high-confidence drift, we flag flags as STALE only when they
    #    appear on a line that:
    #
    #      a) looks like a runnable command invoking exactly THIS tool
    #         (``python3 tools/foo.py --bar``, ``./tools/foo.py --bar``,
    #         ``make some-target ... tools/foo.py --bar``, or
    #         ``tools/foo.py --bar`` directly), AND
    #      b) does not mention any *other* tool basename.
    #
    #    Lines that fail (a) or (b) are intentionally NOT flagged as
    #    STALE — at worst they surface as REVIEW via the
    #    basename-mention pass below.
    tool_flags = _extract_argparse_flags(tool_path)
    if tool_flags is not None:
        doc_lines = doc_text.splitlines()
        # Require an *unambiguous* invocation form: the tool basename
        # must be preceded by ``python3 ``, ``python ``, ``bash ``,
        # ``sh ``, or ``./`` (optionally with a path prefix). This
        # filters out prose mentions of other CLI tools whose flags
        # would otherwise be falsely attributed to ``tool_basename``
        # (e.g. ``codex-peer-poll.py ... git fetch --all`` on the same
        # line). Bare basename mentions still surface as REVIEW below.
        invocation_re = re.compile(
            r"(?:python3?|bash|sh)\s+"
            r"(?:[A-Za-z0-9_./-]*/)?"
            + re.escape(tool_basename)
            + r"\b"
            + r"|"
            + r"\./(?:[A-Za-z0-9_./-]*/)?"
            + re.escape(tool_basename)
            + r"\b"
        )
        for ln in mention_lines:
            line = doc_lines[ln - 1]
            stripped = line.lstrip()
            # Skip markdown headings — they are commentary, not commands.
            if stripped.startswith("#"):
                continue
            invocation_match = invocation_re.search(line)
            if not invocation_match:
                continue
            tool_hits_on_line = {m.group(1) for m in TOOL_BASENAME_RE.finditer(line)}
            if tool_hits_on_line != {tool_basename}:
                continue
            invocation_end = invocation_match.end()
            for fm in FLAG_RE.finditer(line):
                # The flag must appear AFTER the tool invocation on the
                # same line — otherwise it's most likely a flag for a
                # different tool the prose is describing.
                if fm.start() < invocation_end:
                    continue
                flag = fm.group(1)
                if flag in tool_flags or flag in {"--help", "--version"}:
                    continue
                evidence.append(
                    f"L{ln}: doc mentions flag {flag!r} not in {tool_path_rel} argparse"
                )

    # 2. Path-citation drift — every ``docs/...`` / ``reference/...`` /
    #    ``patterns/...`` / ``detectors/...`` / ``tools/...`` path that
    #    appears on the same line as the tool name and looks like a
    #    *tool output artifact* must still appear in the tool source.
    tool_paths = _extract_paths(tool_path)
    if tool_paths:
        doc_lines = doc_text.splitlines()
        for ln in mention_lines:
            line = doc_lines[ln - 1]
            for m in PATH_CITATION_RE.finditer(line):
                p = m.group("path")
                # Only suspect strings that look like generated artifacts:
                # the tool source itself doesn't count, and we don't want
                # to trigger on the fact that the doc cites the tool's
                # own path.
                if p == tool_path_rel:
                    continue
                if not p.startswith(("docs/", "reference/", "patterns/", "detectors/")):
                    continue
                # Only flag if the tool was clearly the producer in the
                # past — i.e. some same-prefix path appears in the
                # source — and *this specific* path is no longer there
                # *and* the file no longer exists on disk.
                same_prefix = any(
                    tp.split("/", 1)[0] == p.split("/", 1)[0] for tp in tool_paths
                )
                if not same_prefix:
                    continue
                if p in tool_paths:
                    continue
                if (repo / p).exists():
                    continue
                evidence.append(
                    f"L{ln}: doc cites artifact {p!r} not produced by {tool_path_rel} and missing on disk"
                )

    # 3. Line-citation drift — ``tools/foo.py:L42`` must still be a
    #    valid line.
    line_count = _file_line_count(tool_path)
    if line_count:
        for m in LINE_CITATION_RE.finditer(doc_text):
            base = m.group("base")
            if base != tool_basename and base != tool_path_rel:
                continue
            cited = int(m.group("line"))
            if cited > line_count:
                # Find which doc line the citation appears on for nicer evidence.
                upto = doc_text[: m.start()]
                doc_line_num = upto.count("\n") + 1
                evidence.append(
                    f"L{doc_line_num}: cites {base}:L{cited} but file only has {line_count} lines"
                )

    if evidence:
        return ("STALE", evidence)
    # Mention found, no mechanical breakage — surface for human review
    # so they don't forget to read the prose paragraph.
    review_evidence = [f"L{ln}: mentions {tool_basename}" for ln in mention_lines]
    return ("REVIEW", review_evidence)


def check(
    *,
    repo: Path,
    base: str,
    working_tree: bool,
    explicit_tools: list[str] | None,
) -> dict:
    """Run the cascade check. Pure function — caller decides how to render."""
    if explicit_tools:
        changed_tools = sorted(set(explicit_tools))
    else:
        changed_tools = _changed_tools_from_git(repo, base, working_tree)

    findings: list[dict] = []
    counts = {"OK": 0, "STALE": 0, "REVIEW": 0}

    if not changed_tools:
        return {
            "changed_tools": [],
            "findings": [],
            "counts": counts,
            "base": base,
            "working_tree": working_tree,
        }

    doc_paths = list(_iter_doc_files(repo))

    for tool_rel in changed_tools:
        tool_path = repo / tool_rel
        tool_basename = Path(tool_rel).name
        for doc_path in doc_paths:
            try:
                doc_text = doc_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            verdict, evidence = _classify_doc(
                doc_path=doc_path,
                doc_text=doc_text,
                tool_path=tool_path,
                tool_basename=tool_basename,
                tool_path_rel=tool_rel,
                repo=repo,
            )
            if verdict == "OK" and not evidence:
                # No mention at all — don't spam findings.
                continue
            counts[verdict] += 1
            findings.append(
                {
                    "tool": tool_rel,
                    "doc": doc_path.relative_to(repo).as_posix(),
                    "verdict": verdict,
                    "evidence": evidence,
                }
            )

    return {
        "changed_tools": changed_tools,
        "findings": findings,
        "counts": counts,
        "base": base,
        "working_tree": working_tree,
    }


def _render_human(result: dict) -> str:
    lines: list[str] = []
    lines.append("[doc-cascade] check")
    lines.append(f"  base         : {result['base']}")
    lines.append(f"  working_tree : {result['working_tree']}")
    if not result["changed_tools"]:
        lines.append("  changed_tools: <none> — nothing to check")
        lines.append("[doc-cascade] OK (no tool changes)")
        return "\n".join(lines)
    lines.append(f"  changed_tools: {len(result['changed_tools'])}")
    for t in result["changed_tools"]:
        lines.append(f"    - {t}")
    if not result["findings"]:
        lines.append("  findings     : <none> — no doc mentions any changed tool")
        lines.append("[doc-cascade] OK")
        return "\n".join(lines)
    lines.append(f"  findings     : {len(result['findings'])}")
    for f in result["findings"]:
        lines.append(f"  [{f['verdict']:<6}] {f['tool']} -> {f['doc']}")
        for ev in f["evidence"]:
            lines.append(f"          {ev}")
    counts = result["counts"]
    summary = (
        f"OK={counts['OK']} STALE={counts['STALE']} REVIEW={counts['REVIEW']}"
    )
    if counts["STALE"]:
        lines.append(f"[doc-cascade] FAIL — {summary}")
    else:
        lines.append(f"[doc-cascade] OK — {summary}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Flag stale docs when tools/scripts change. "
            "Read-only — never edits docs."
        ),
    )
    parser.add_argument(
        "--repo",
        default=str(REPO),
        help="Repository root (default: tool's parent of parent).",
    )
    parser.add_argument(
        "--base",
        default="origin/main",
        help="Git base ref to diff against (default: origin/main).",
    )
    parser.add_argument(
        "--working-tree",
        action="store_true",
        help="Also include uncommitted/untracked changes in the diff.",
    )
    parser.add_argument(
        "--tool",
        action="append",
        dest="tools",
        help=(
            "Explicit tool path(s) to check (repeatable). "
            "Bypasses git diff entirely."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human summary.",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists() and not args.tools:
        # ``.git`` may be a file in worktrees; fall through if --tool given.
        pass

    result = check(
        repo=repo,
        base=args.base,
        working_tree=args.working_tree,
        explicit_tools=args.tools,
    )

    if args.json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(_render_human(result) + "\n")

    return 1 if result["counts"]["STALE"] else 0


if __name__ == "__main__":
    sys.exit(main())
