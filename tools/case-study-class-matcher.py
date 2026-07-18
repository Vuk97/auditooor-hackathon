#!/usr/bin/env python3
"""
case-study-class-matcher.py — Phase E (commit E1) of the Corpus Mining + Case Study Logic
Extraction Plan (docs/CORPUS_MINING_AND_CASE_STUDY_LOGIC_EXTRACTION_PLAN_2026-05-08.md).

Reads YAML frontmatter from case_study/*.md files and emits class-match predicates for a
given workspace asset class.  The match score combines:
  - exact class match          (+3)
  - applicable_workspace_classes membership (+2)
  - severity_class multiplier  (CRIT=1.5, HIGH=1.2, MED=1.0, INFO=0.8)

Usage (CLI):
    python3 tools/case-study-class-matcher.py --class <workspace-class> [--top N] [--json]

API:
    from tools.case_study_class_matcher import match_workspace
    results = match_workspace("prediction-market", top_n=5)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Repo-root detection
# ---------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()
_TOOLS_DIR = _THIS_FILE.parent
_REPO_ROOT = _TOOLS_DIR.parent
_CASE_STUDY_DIR = _REPO_ROOT / "case_study"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {"CRIT": 1.5, "HIGH": 1.2, "MED": 1.0, "INFO": 0.8}


@dataclass
class CaseStudyMeta:
    """Parsed frontmatter from a case_study/*.md file."""

    case_id: str = ""
    mechanism: str = ""
    class_: str = ""          # 'class' is a Python keyword; stored as class_
    severity_class: str = "INFO"
    applicable_workspace_classes: list[str] = field(default_factory=list)
    grep_predicates: list[str] = field(default_factory=list)
    runtime_predicates: list[str] = field(default_factory=list)
    extracted_lesson: str = ""
    stop_criterion: str = ""
    workflow_signature: str = ""
    loop_back_phase: str = ""
    source_file: str = ""


@dataclass
class CaseMatch:
    """A case study that matched a workspace class query."""

    case_id: str
    mechanism: str
    class_: str
    severity_class: str
    score: float
    grep_predicates: list[str]
    runtime_predicates: list[str]
    extracted_lesson: str
    stop_criterion: str
    workflow_signature: str
    loop_back_phase: str
    source_file: str
    match_reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "mechanism": self.mechanism,
            "class": self.class_,
            "severity_class": self.severity_class,
            "score": round(self.score, 3),
            "match_reason": self.match_reason,
            "grep_predicates": self.grep_predicates,
            "runtime_predicates": self.runtime_predicates,
            "extracted_lesson": self.extracted_lesson,
            "stop_criterion": self.stop_criterion,
            "workflow_signature": self.workflow_signature,
            "loop_back_phase": self.loop_back_phase,
            "source_file": self.source_file,
        }


# ---------------------------------------------------------------------------
# YAML frontmatter parser (no external deps)
# ---------------------------------------------------------------------------

def _parse_yaml_frontmatter(text: str) -> dict[str, Any]:
    """
    Extract the YAML block between the first --- and the next --- delimiter.
    Returns {} if no frontmatter found.
    Only handles simple scalars, lists (- item), and block scalars (>).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    fm_lines: list[str] = []
    in_fm = False
    for i, line in enumerate(lines):
        if i == 0:
            in_fm = True
            continue
        if line.strip() == "---" and in_fm:
            break
        fm_lines.append(line)

    if not fm_lines:
        return {}

    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[str] | None = None
    block_scalar_key: str | None = None
    block_scalar_lines: list[str] = []
    block_scalar_indent = 0

    def _flush_block():
        nonlocal block_scalar_key, block_scalar_lines
        if block_scalar_key is not None:
            result[block_scalar_key] = " ".join(
                l.strip() for l in block_scalar_lines if l.strip()
            )
            block_scalar_key = None
            block_scalar_lines = []

    def _flush_list():
        nonlocal current_list, current_key
        if current_list is not None and current_key is not None:
            result[current_key] = current_list
            current_list = None
            current_key = None

    for line in fm_lines:
        # Inside a block scalar (>)
        if block_scalar_key is not None:
            stripped = line.rstrip()
            if stripped and not stripped.startswith(" "):
                # New top-level key — flush block first
                _flush_block()
            else:
                block_scalar_lines.append(stripped)
                continue

        # Key: value pattern
        kv = re.match(r"^(\w[\w_-]*):\s*(.*)", line)
        if kv:
            _flush_list()
            _flush_block()
            key = kv.group(1)
            val = kv.group(2).strip()

            if val == ">":
                block_scalar_key = key
                block_scalar_lines = []
                block_scalar_indent = len(line) - len(line.lstrip())
                current_key = None
                current_list = None
                continue

            if val == "[]":
                # Explicit empty list inline
                result[key] = []
                current_key = None
                current_list = None
                continue

            if val == "" or val is None:
                # Anticipating a list or block scalar
                current_key = key
                current_list = []
                continue

            # Inline value — strip optional quotes
            val = val.strip("\"'")
            result[key] = val
            current_key = None
            current_list = None
            continue

        # List item
        li = re.match(r"^\s+-\s+(.*)", line)
        if li and current_list is not None:
            current_list.append(li.group(1).strip().strip("\"'"))
            continue

    _flush_list()
    _flush_block()

    return result


def _load_case_study(path: Path) -> CaseStudyMeta | None:
    """Parse a case_study/*.md file and return its CaseStudyMeta, or None if no frontmatter."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    fm = _parse_yaml_frontmatter(text)
    if not fm:
        return None

    meta = CaseStudyMeta(
        case_id=fm.get("case_id", path.stem),
        mechanism=fm.get("mechanism", ""),
        class_=fm.get("class", ""),
        severity_class=fm.get("severity_class", "INFO").upper(),
        applicable_workspace_classes=fm.get("applicable_workspace_classes", []),
        grep_predicates=fm.get("grep_predicates", []),
        runtime_predicates=fm.get("runtime_predicates", []),
        extracted_lesson=fm.get("extracted_lesson", ""),
        stop_criterion=fm.get("stop_criterion", ""),
        workflow_signature=fm.get("workflow_signature", ""),
        loop_back_phase=fm.get("loop_back_phase", ""),
        source_file=str(path),
    )
    return meta


def load_all_case_studies(case_study_dir: Path | None = None) -> list[CaseStudyMeta]:
    """Load all case study files from the case_study/ directory."""
    d = case_study_dir or _CASE_STUDY_DIR
    if not d.exists():
        return []
    results: list[CaseStudyMeta] = []
    for p in sorted(d.glob("*.md")):
        m = _load_case_study(p)
        if m is not None:
            results.append(m)
    return results


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _score(meta: CaseStudyMeta, workspace_class: str) -> tuple[float, str]:
    """
    Return (score, reason) for a case study against the given workspace_class.
    Score > 0 means a match.
    """
    wc = workspace_class.lower().strip()
    score = 0.0
    reasons: list[str] = []

    # Exact class match
    if meta.class_.lower() == wc:
        score += 3.0
        reasons.append(f"exact class match ({meta.class_!r})")

    # In applicable_workspace_classes
    awc_lower = [c.lower() for c in meta.applicable_workspace_classes]
    if wc in awc_lower:
        score += 2.0
        reasons.append("listed in applicable_workspace_classes")

    # Partial / substring match in class or applicable list
    if score == 0:
        if wc in meta.class_.lower() or meta.class_.lower() in wc:
            score += 1.0
            reasons.append(f"partial class match ({meta.class_!r})")
        for awc in awc_lower:
            if wc in awc or awc in wc:
                score += 0.5
                reasons.append(f"partial applicable_workspace_class match ({awc!r})")
                break

    if score == 0:
        searchable = " ".join(
            [
                meta.mechanism,
                meta.extracted_lesson,
                meta.stop_criterion,
                meta.workflow_signature.replace("_", " "),
                meta.loop_back_phase.replace("-", " "),
                " ".join(meta.grep_predicates),
                " ".join(meta.runtime_predicates),
            ]
        ).lower()
        wc_terms = [term for term in re.split(r"[^a-z0-9]+", wc) if len(term) >= 4]
        if wc_terms and any(term in searchable for term in wc_terms):
            score += 0.75
            reasons.append("case-study lesson/predicate keyword match")

    if score == 0:
        return 0.0, ""

    # Severity multiplier
    sv_mul = SEVERITY_WEIGHT.get(meta.severity_class, 1.0)
    score *= sv_mul
    if sv_mul != 1.0:
        reasons.append(f"severity_class={meta.severity_class} (x{sv_mul})")

    return round(score, 3), "; ".join(reasons)


def match_workspace(
    workspace_class: str,
    top_n: int = 10,
    case_study_dir: Path | None = None,
) -> list[CaseMatch]:
    """
    Return up to top_n CaseMatch objects for the given workspace_class, sorted by score descending.

    Args:
        workspace_class: Primary asset class of the workspace being audited.
                         E.g. "prediction-market", "bridge", "lending".
        top_n: Maximum number of results to return.
        case_study_dir: Override directory (used in tests).

    Returns:
        List of CaseMatch objects sorted by score descending.
    """
    studies = load_all_case_studies(case_study_dir)
    matches: list[CaseMatch] = []

    for meta in studies:
        score, reason = _score(meta, workspace_class)
        if score > 0:
            matches.append(
                CaseMatch(
                    case_id=meta.case_id,
                    mechanism=meta.mechanism,
                    class_=meta.class_,
                    severity_class=meta.severity_class,
                    score=score,
                    grep_predicates=meta.grep_predicates,
                    runtime_predicates=meta.runtime_predicates,
                    extracted_lesson=meta.extracted_lesson,
                    stop_criterion=meta.stop_criterion,
                    workflow_signature=meta.workflow_signature,
                    loop_back_phase=meta.loop_back_phase,
                    source_file=meta.source_file,
                    match_reason=reason,
                )
            )

    matches.sort(key=lambda m: m.score, reverse=True)
    return matches[:top_n]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Match case studies to a workspace asset class."
    )
    parser.add_argument(
        "--class",
        dest="workspace_class",
        required=True,
        help="Workspace primary asset class (e.g. bridge, lending, prediction-market)",
    )
    parser.add_argument(
        "--top",
        dest="top_n",
        type=int,
        default=10,
        help="Maximum number of results (default: 10)",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output as JSON array",
    )
    parser.add_argument(
        "--case-study-dir",
        dest="case_study_dir",
        default=None,
        help="Override case_study/ directory path",
    )
    args = parser.parse_args()

    csd = Path(args.case_study_dir) if args.case_study_dir else None
    results = match_workspace(args.workspace_class, top_n=args.top_n, case_study_dir=csd)

    if not results:
        print(f"[case-study-class-matcher] No matches for class '{args.workspace_class}'")
        sys.exit(0)

    if args.as_json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
        return

    print(f"[case-study-class-matcher] {len(results)} match(es) for class '{args.workspace_class}':\n")
    for i, r in enumerate(results, 1):
        print(f"  {i}. {r.case_id}  (score={r.score}, severity={r.severity_class})")
        print(f"     class: {r.class_}")
        print(f"     match: {r.match_reason}")
        print(f"     mechanism: {r.mechanism}")
        if r.grep_predicates:
            print(f"     grep predicates ({len(r.grep_predicates)}):")
            for gp in r.grep_predicates:
                print(f"       - {gp}")
        if r.runtime_predicates:
            print(f"     runtime predicates ({len(r.runtime_predicates)}):")
            for rp in r.runtime_predicates:
                print(f"       - {rp}")
        if r.extracted_lesson:
            lesson_short = r.extracted_lesson[:200].replace("\n", " ")
            if len(r.extracted_lesson) > 200:
                lesson_short += "..."
            print(f"     lesson: {lesson_short}")
        print()


if __name__ == "__main__":
    _cli()
