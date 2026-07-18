#!/usr/bin/env python3
"""memory-gap-analyzer.py — L4 of the §M_ARCH memory architecture.

Reads the Obsidian vault read-only and surfaces gaps as next-loop candidates.

This is the "memory thinks for itself" piece. It does NOT auto-dispatch
agents — it identifies high-yield work and writes ranked candidates to
`obsidian-vault/NEXT_LOOP.md`. The companion `memory-next-loop-dispatcher.py`
emits prompt templates for operator review.

Heuristics (per category — each declares known FP/FN risk):

  G1  coverage-gap         — Solodit pattern classes with 0 Tier-S/E/A detector
                             (cross-ref docs/DETECTOR_GAP_REPORT_*.md).
                             FP risk: keyword-only mapping; FN risk: detector
                             named differently than pattern class.

  G2  routing-under-data   — task-types with decided n<5 calibration samples
                             (cross-ref obsidian-vault/calibration/INDEX.md).
                             FP risk: task-type may be intentionally rare;
                             FN risk: silent task-types not in calibration log.

  G3  stale-limitation     — P0/P1 burndown rows whose underlying note hasn't
                             been touched in >7 days (mtime heuristic; tells
                             us nothing about actual progress, only file
                             freshness — operator review mandatory).

  G4  untouched-workspace  — `~/audits/<ws>/` workspace mirror that hasn't
                             produced a finding-note in the last 30 days
                             (mtime under findings/<ws>/). FP risk: a
                             workspace can be in submission/quiet phase;
                             FN risk: dormant ws may be intentionally paused.

  G5  failed-twice-pattern — error/*.md notes containing the same detector
                             argument or pattern_id appearing in 2+ files.
                             FP risk: same arg flagged in multiple queues =
                             one root cause, not two; FN risk: error notes
                             may not include the detector arg as text.

  G6  m14-trap-recurrence  — prompt template files (templates/*.txt or
                             templates/*.md) modified in the last 7 days
                             that have not been linted via
                             agent-dispatch-prompt-lint.py --strict.
                             FP risk: not every template gets dispatched;
                             FN risk: prompts inlined in shell scripts.

  G7  memory-of-memory     — vault category dirs whose newest file mtime is
                             >24h old (ingester/L1-watcher gap).
                             FP risk: low-volume categories (incidents) may
                             legitimately go quiet; FN risk: an INDEX.md
                             refresh masks stale per-item notes.

  G8  knowledge-gap        — open canonical knowledge-gap rows in
                             reports/knowledge_gaps.jsonl. FP risk: a gap can
                             be stale after reality moved; FN risk: missing
                             truth not logged there is invisible.

  G9  completion-gap       — terminal dispatch manifest rows that lack a
                             canonical task-finalization ledger row.
                             FP risk: ledger may not have been backfilled yet;
                             FN risk: malformed ledger rows can hide closure
                             only if they pass the finalization validator.

  G10 harness-failure-recurrence
                           — repeated harness failure root causes in
                             reports/harness_failures.jsonl.
                             FP risk: backfilled counts can overstate current
                             recurrence after guard fixes; FN risk: failures
                             not logged in the canonical report are invisible.

Output:
  obsidian-vault/gap-analysis/<YYYY-MM-DD>.md   per-run report
  obsidian-vault/NEXT_LOOP.md                   always-current top-N

Exit codes:
  0 — analysis complete (gaps surfaced is informational, not error)
  2 — vault not found / read failure

This is HEURISTIC. False positives WILL happen. Operator review is the
final gate. NO LLM calls. $0 budget.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional


REPO = Path(__file__).resolve().parent.parent
DEFAULT_VAULT = REPO / "obsidian-vault"
DEFAULT_AUDITS_DIR = Path.home() / "audits"
SCHEMA = "auditooor.memory_gap_analyzer.v1"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class GapCandidate:
    gap_id: str                # e.g. G1-001
    category: str              # G1..G10
    title: str                 # one-line description
    description: str           # multi-line, describes the gap
    evidence: str              # data/heuristic supporting the call
    remediation: str           # concrete tool / agent-dispatch outline
    yield_estimate: str        # qualitative: low / med / high
    effort_estimate: str       # qualitative: low / med / high
    priority_score: float      # numeric, see PRIORITY_FORMULA
    source_paths: List[str] = field(default_factory=list)
    analyzer_target_paths: List[str] = field(default_factory=list)
    heuristic_fp_risk: str = ""
    heuristic_fn_risk: str = ""

    def to_md(self) -> str:
        lines = [f"### {self.gap_id} - {self.title}",
                 "",
                 f"- **Category:** `{self.category}`",
                 f"- **Priority score:** `{self.priority_score:.2f}`",
                 f"- **Yield × Effort:** {self.yield_estimate} × {self.effort_estimate}",
                 "",
                 "**Description**",
                 "",
                 self.description.strip(),
                 "",
                 "**Evidence**",
                 "",
                 self.evidence.strip(),
                 "",
                 "**Proposed remediation**",
                 "",
                 self.remediation.strip(),
                 ""]
        if self.source_paths:
            lines.append("**Source paths**")
            lines.append("")
            for p in self.source_paths:
                lines.append(f"- `{p}`")
            lines.append("")
        if self.analyzer_target_paths:
            lines.append("**Analyzer target paths**")
            lines.append("")
            for p in self.analyzer_target_paths:
                lines.append(f"- `{p}`")
            lines.append("")
        if self.heuristic_fp_risk or self.heuristic_fn_risk:
            lines.append("**Heuristic risks**")
            lines.append("")
            if self.heuristic_fp_risk:
                lines.append(f"- FP risk: {self.heuristic_fp_risk}")
            if self.heuristic_fn_risk:
                lines.append(f"- FN risk: {self.heuristic_fn_risk}")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Priority formula
# ---------------------------------------------------------------------------
# priority = yield_weight * (1 / effort_weight) * category_multiplier
# yield: high=3, med=2, low=1 ; effort: low=1, med=2, high=3
# category multiplier emphasizes user-visible wins; declared explicitly so
# downstream readers can audit the bias.
YIELD_WEIGHT = {"high": 3.0, "med": 2.0, "low": 1.0}
EFFORT_WEIGHT = {"low": 1.0, "med": 2.0, "high": 3.0}
CATEGORY_MULTIPLIER = {
    "G1": 1.4,   # detector coverage = direct finding yield
    "G2": 1.1,   # routing data = better future dispatches
    "G3": 0.8,   # limitation freshness = process hygiene
    "G4": 1.0,   # workspace pulse
    "G5": 1.2,   # repeat-failure root-causes
    "G6": 1.3,   # M14-trap is a known footgun
    "G7": 0.9,   # ingester pulse, mostly diagnostic
    "G8": 1.5,   # open knowledge gap that blocks downstream work
    "G9": 1.4,   # completion gaps block reliable loop closure
    "G10": 1.2,  # recurring harness failures block exploit proof lift
}


def priority_score(category: str, yield_est: str, effort_est: str) -> float:
    y = YIELD_WEIGHT.get(yield_est, 1.0)
    e = EFFORT_WEIGHT.get(effort_est, 2.0)
    m = CATEGORY_MULTIPLIER.get(category, 1.0)
    return round(m * y / e, 3)


# ---------------------------------------------------------------------------
# Vault readers
# ---------------------------------------------------------------------------

def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def strip_yaml_frontmatter(text: str) -> str:
    """Drop leading Obsidian-style YAML frontmatter before body heuristics."""
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---\n", 4)
    if end == -1:
        return text
    return text[end + len("\n---\n"):]


def file_age_days(path: Path, now_ts: Optional[float] = None) -> Optional[float]:
    try:
        st = path.stat()
    except Exception:
        return None
    now = now_ts if now_ts is not None else dt.datetime.now().timestamp()
    age_s = now - st.st_mtime
    return age_s / 86400.0


def newest_mtime(dir_path: Path) -> Optional[float]:
    # r36-rebuttal: bugfix-inventory-claude-20260610
    if not dir_path.is_dir():
        return None
    newest = None
    for p in dir_path.rglob("*"):
        # Skip symlink files: p.is_file() returns True for symlinks but
        # p.stat().st_mtime follows the target, returning external mtime.
        # A symlink to a fresh external file would mask stale real vault
        # files, producing false-green G7 staleness detection.
        if not p.is_file() or p.is_symlink():
            continue
        try:
            mt = p.stat().st_mtime
        except Exception:
            continue
        if newest is None or mt > newest:
            newest = mt
    return newest


# ---------------------------------------------------------------------------
# G1 — coverage gaps from detector blindspot report
# ---------------------------------------------------------------------------

DETECTOR_GAP_RE = re.compile(
    r"\|\s*\d+\s*\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*([\d.]+)\s*\|", re.MULTILINE)


def find_latest_detector_gap_report(repo: Path) -> Optional[Path]:
    docs = repo / "docs"
    if not docs.is_dir():
        return None
    cands = sorted(docs.glob("DETECTOR_GAP_REPORT_*.md"), reverse=True)
    return cands[0] if cands else None


def gather_g1(vault: Path, repo: Path) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    report = find_latest_detector_gap_report(repo)
    if not report:
        return out
    txt = read_text(report) or ""
    matches = DETECTOR_GAP_RE.findall(txt)
    if not matches:
        return out
    # Take top 3 missed pattern classes (highest weight)
    rows = [(cls, int(cnt), float(w)) for cls, cnt, w in matches]
    rows.sort(key=lambda x: x[2], reverse=True)
    for i, (cls, cnt, w) in enumerate(rows[:3], 1):
        yield_est = "high" if w >= 2.0 else "med"
        effort_est = "med"
        score = priority_score("G1", yield_est, effort_est)
        if cls == "uncategorized":
            title = "Uncategorized detector blindspots need taxonomy assignment"
            description = (
                f"The detector gap report has {cnt} missed Solodit "
                f"High/Critical finding(s) with severity-weight {w} still "
                "classified as `uncategorized`.\n\n"
                "Do not write a detector for `uncategorized`. First assign "
                "the linked findings to concrete bug classes, then decide "
                "whether an existing detector covers them or a targeted "
                "detector is needed.")
            remediation = (
                "Refine `BUG_CLASSES` in `tools/detector-blindspot-scan.py` "
                "or add a reviewed classification sidecar for the linked "
                "findings. Re-run `detector-blindspot-scan.py` after the "
                "taxonomy update; only dispatch detector-writing work for "
                "specific classes that remain missed.")
        else:
            title = f"No requested-tier detector coverage for `{cls}`"
            description = (
                f"Pattern class `{cls}` has {cnt} missed Solodit High/Critical "
                f"finding(s) and severity-weight {w} in the latest detector "
                f"gap report. The requested detector tier set did not cover "
                f"this class.\n\n"
                f"Closing this may mean promoting/calibrating an existing "
                f"lower-tier detector, fixing harness reach, refining "
                f"taxonomy, or writing a new targeted detector.")
            remediation = (
                f"Dispatch a detector-coverage agent for `{cls}`. First check "
                f"whether an existing lower-tier detector or adjacent fixture "
                f"already covers the linked findings; if yes, produce a "
                f"promotion/calibration packet and run focused smoke or "
                f"precision checks. Only draft a new detector when no suitable "
                f"existing detector exists. Re-run `detector-blindspot-scan.py` "
                f"after landing to confirm the class moves out of blindspot.")
        out.append(GapCandidate(
            gap_id=f"G1-{i:03d}",
            category="G1",
            title=title,
            description=description,
            evidence=(
                f"Source: `{report.relative_to(repo)}` (auto-generated by "
                f"`tools/detector-blindspot-scan.py`). The blindspot table "
                f"shows `{cls}` ranked among top missed classes "
                f"(count={cnt}, weight={w})."),
            remediation=remediation,
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[str(report.relative_to(repo))],
            heuristic_fp_risk=(
                "Keyword-only class mapping may misclassify a covered "
                "pattern as missed if our detector uses different naming."),
            heuristic_fn_risk=(
                "Solodit corpus is sampled (top 98 by quality); long-tail "
                "classes may not appear in the report."),
        ))
    return out


# ---------------------------------------------------------------------------
# G2 — routing under-data
# ---------------------------------------------------------------------------

CALIB_TASK_RE = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|",
    re.MULTILINE)
CALIB_TASK_NOTE_RE = re.compile(
    r"^\s*-\s*\[\[calibration/task-types/([^|\]]+)(?:\|[^\]]+)?\]\]\s+"
    r"[—-]\s+n=(\d+),\s+decided=(\d+)",
    re.MULTILINE)


def parse_int_value(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip().strip('"').strip("'"))
    except ValueError:
        return None


def parse_simple_frontmatter(text: str) -> Dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}
    fields: Dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def calibration_task_note_counts(vault: Path, task: str) -> Dict[str, Optional[int]]:
    note = vault / "calibration" / "task-types" / f"{task}.md"
    if not note.is_file():
        return {
            "total_dispatches": None,
            "decided": None,
            "note_exists": 0,
        }
    txt = read_text(note) or ""
    meta = parse_simple_frontmatter(txt)
    total_dispatches = parse_int_value(meta.get("total_dispatches"))
    decided = parse_int_value(meta.get("decided"))

    if total_dispatches is None:
        match = re.search(r"\*\*Total dispatches\*\*:\s*(\d+)", txt)
        total_dispatches = parse_int_value(match.group(1) if match else None)
    if decided is None:
        match = re.search(r"\*\*Decided\*\s*\(TRUE\+FALSE\):\s*(\d+)", txt)
        decided = parse_int_value(match.group(1) if match else None)

    return {
        "total_dispatches": total_dispatches,
        "decided": decided,
        "note_exists": 1,
    }


def gather_g2(vault: Path, min_n: int = 5) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    idx = vault / "calibration" / "INDEX.md"
    if not idx.is_file():
        return out
    txt = read_text(idx) or ""
    rows = CALIB_TASK_RE.findall(txt)
    index_task_totals: Dict[str, int] = {}
    for task, n_str, decided_str in CALIB_TASK_NOTE_RE.findall(txt):
        total_dispatches = parse_int_value(n_str)
        decided = parse_int_value(decided_str)
        if total_dispatches is not None and decided is not None:
            index_task_totals[task] = total_dispatches
    # Each quick-answer row: (task, provider, tp_rate, decided n, status)
    under = []
    for task, provider, tp, n_str, status in rows:
        index_decided = parse_int_value(n_str)
        if index_decided is None:
            continue
        note_counts = calibration_task_note_counts(vault, task)
        decided_n = note_counts["decided"]
        if decided_n is None:
            decided_n = index_decided
        total_dispatches = note_counts["total_dispatches"]
        if total_dispatches is None:
            total_dispatches = index_task_totals.get(task)
        if decided_n < min_n:
            under.append((
                task,
                provider,
                tp.strip(),
                index_decided,
                decided_n,
                total_dispatches,
                status.strip(),
                bool(note_counts["note_exists"]),
            ))
    # Take up to 3
    under.sort(key=lambda x: x[4])  # smallest decided n first
    for i, row in enumerate(under[:3], 1):
        (
            task,
            provider,
            tp,
            index_decided,
            decided_n,
            total_dispatches,
            status,
            note_exists,
        ) = row
        yield_est = "med"
        effort_est = "low"
        score = priority_score("G2", yield_est, effort_est)
        total_suffix = ""
        if total_dispatches is not None:
            total_suffix = f" (total dispatches={total_dispatches})"
        if total_dispatches is None:
            activity_sentence = (
                "Raw dispatch activity count is unavailable in the current "
                "calibration notes, so this candidate only asserts the "
                "decided-row deficit.")
        elif total_dispatches > decided_n:
            activity_sentence = (
                f"Raw activity is present: total dispatches={total_dispatches}, "
                f"decided TRUE/FALSE rows={decided_n}. This is an "
                "outcome-labeling/normalization gap, not a no-activity claim.")
        elif total_dispatches == 0:
            activity_sentence = (
                "No raw dispatch activity is recorded for this task-type in "
                "the current calibration notes.")
        else:
            activity_sentence = (
                f"Total dispatches={total_dispatches}; all recorded activity "
                "currently maps to the decided count.")
        if total_dispatches is not None and total_dispatches > decided_n:
            remediation = (
                f"Review existing `{task}` dispatches and log legitimate "
                "TRUE/FALSE outcomes where possible, then schedule additional "
                f"controlled `{task}` dispatches only for any remaining decided-row "
                "shortfall. Honest accounting required; don't backfill with "
                "synthetic samples.")
        else:
            remediation = (
                f"Add 3-5 real `{task}` dispatches over the next loop and ensure "
                "their outcomes become decided TRUE/FALSE rows. Sources: open PRs "
                "for `pr-review`, real findings for `gap-finding`/`scope-triage`, "
                "etc. Use `tools/agent-worktree-dispatch.py` and tag with "
                f"`--task-type {task}` so calibration logger picks it up.")
        source_paths = [
            str((vault / "calibration" / "INDEX.md").relative_to(vault.parent))
        ]
        if note_exists:
            task_note = vault / "calibration" / "task-types" / f"{task}.md"
            source_paths.append(str(task_note.relative_to(vault.parent)))
        out.append(GapCandidate(
            gap_id=f"G2-{i:03d}",
            category="G2",
            title=(
                f"Task-type `{task}` has decided n={decided_n} (<{min_n}); "
                f"routing decision under-powered{total_suffix}"),
            description=(
                f"Routing manifest can only recommend a provider for "
                f"`{task}` once we have ≥{min_n} decided TRUE/FALSE rows. "
                f"Currently decided n={decided_n} (INDEX quick-row n="
                f"{index_decided}, status={status!r}). The router falls "
                f"back to default until this stabilizes.\n\n"
                f"{activity_sentence}"),
            evidence=(
                f"`obsidian-vault/calibration/INDEX.md` row: "
                f"`{task}` decided n={index_decided} status=`{status}` "
                f"(best provider so far: `{provider}`). "
                f"Task note activity: total_dispatches="
                f"{total_dispatches if total_dispatches is not None else 'unknown'}, "
                f"decided={decided_n}."),
            remediation=remediation,
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=source_paths,
            heuristic_fp_risk=(
                "Some task-types are intentionally rare (e.g. "
                "severity-escalation); decided n<5 may be correct steady-state "
                "or an outcome-labeling backlog, not a dispatch shortage."),
            heuristic_fn_risk=(
                "Silent task-types that never reach the calibration logger "
                "won't appear here at all; schema drift between the INDEX and "
                "task-type notes can also hide raw activity."),
        ))
    return out


# ---------------------------------------------------------------------------
# G3 — stale limitations
# ---------------------------------------------------------------------------

STALE_LIMIT_DAYS = 7.0


def gather_g3(vault: Path, max_items: int = 3) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    lim_dir = vault / "limitations"
    if not lim_dir.is_dir():
        return out
    # Look at p0/p1 burndown queue files specifically; if not present fall
    # back to deep/ subdir.
    targets: List[Path] = []
    for name in ("p0-burn-down-queue.md", "p1-burn-down-queue.md"):
        p = lim_dir / name
        if p.is_file():
            targets.append(p)
    deep = lim_dir / "deep"
    if deep.is_dir():
        for p in sorted(deep.glob("*.md")):
            targets.append(p)
    stale = []
    for p in targets:
        age = file_age_days(p)
        if age is not None and age > STALE_LIMIT_DAYS:
            stale.append((p, age))
    stale.sort(key=lambda x: x[1], reverse=True)  # oldest first
    for i, (p, age) in enumerate(stale[:max_items], 1):
        yield_est = "low"
        effort_est = "low"
        score = priority_score("G3", yield_est, effort_est)
        rel = p.relative_to(vault.parent)
        out.append(GapCandidate(
            gap_id=f"G3-{i:03d}",
            category="G3",
            title=f"Stale limitation note (>{STALE_LIMIT_DAYS:.0f}d): `{p.stem}`",
            description=(
                f"`{rel}` was last modified {age:.1f} days ago. mtime is a "
                f"file-freshness proxy only - it tells us nothing about "
                f"actual P0/P1 burndown progress. Operator review is "
                f"mandatory; the gap may be resolved with the note simply "
                f"not updated."),
            evidence=f"mtime: {age:.1f} days; threshold: {STALE_LIMIT_DAYS:.0f}d.",
            remediation=(
                f"Either (a) update the note with current status if work "
                f"happened, (b) archive it under `limitations/_archive/` "
                f"if no longer relevant, or (c) escalate to next loop's "
                f"P0/P1 burndown queue. Don't rubber-stamp via touch."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[str(rel)],
            heuristic_fp_risk=(
                "mtime ≠ progress; a stable limitation may correctly go "
                "untouched while the underlying issue is being worked."),
            heuristic_fn_risk=(
                "A note can be touched (whitespace edit) without real "
                "progress; this rule misses cosmetic-update theatre."),
        ))
    return out


# ---------------------------------------------------------------------------
# G4 — untouched workspaces
# ---------------------------------------------------------------------------

UNTOUCHED_WS_DAYS = 30.0


def gather_g4(vault: Path, max_items: int = 3) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    ws_dir = vault / "workspaces"
    if not ws_dir.is_dir():
        return out
    findings_dir = vault / "findings"
    untouched = []
    for ws_md in sorted(ws_dir.glob("*.md")):
        if ws_md.name in ("INDEX.md", "INDEX_active.md"):
            continue
        ws_id = ws_md.stem
        # Check freshest finding under findings/<ws_id>/
        f_sub = findings_dir / ws_id
        newest = newest_mtime(f_sub) if f_sub.is_dir() else None
        if newest is None:
            # Use the workspace note's own mtime as fallback
            newest = ws_md.stat().st_mtime
        age = (dt.datetime.now().timestamp() - newest) / 86400.0
        if age > UNTOUCHED_WS_DAYS:
            untouched.append((ws_id, age, ws_md))
    untouched.sort(key=lambda x: x[1], reverse=True)
    for i, (ws_id, age, ws_md) in enumerate(untouched[:max_items], 1):
        yield_est = "med"
        effort_est = "med"
        score = priority_score("G4", yield_est, effort_est)
        out.append(GapCandidate(
            gap_id=f"G4-{i:03d}",
            category="G4",
            title=f"Workspace `{ws_id}` untouched >{UNTOUCHED_WS_DAYS:.0f}d",
            description=(
                f"Workspace `{ws_id}` has produced no new finding-note in "
                f"{age:.1f} days. Either the engagement is dormant (correct "
                f"and intentional) or we're leaving free yield on the "
                f"table.\n\n"
                f"Operator review: confirm the engagement status. If "
                f"closed, archive the workspace note. If still active, "
                f"queue a mining/triage pass."),
            evidence=(
                f"Newest finding under `obsidian-vault/findings/{ws_id}/` "
                f"is {age:.1f}d old; threshold {UNTOUCHED_WS_DAYS:.0f}d."),
            remediation=(
                f"Run `make audit WS=~/audits/{ws_id}` to refresh state, "
                f"or archive the workspace if closed. Tag the workspace "
                f"note with `status/dormant` or `status/closed`."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[str(ws_md.relative_to(vault.parent))],
            heuristic_fp_risk=(
                "A workspace can be in submission/quiet phase intentionally; "
                "untouched ≠ neglected."),
            heuristic_fn_risk=(
                "If findings/<ws>/ doesn't exist, we use the ws note "
                "mtime - which auto-refresh tools may bump artificially."),
        ))
    return out


# ---------------------------------------------------------------------------
# G5 — failed-twice patterns
# ---------------------------------------------------------------------------

DETECTOR_ARG_RE = re.compile(r"\b(?:pattern_id|detector|arg|failure)[\s:]+`?([A-Za-z0-9_\-]{4,})`?")
BARE_SNAKE_TOKEN_RE = re.compile(r"\b([a-z][a-z0-9_]{6,40})\b(?!\s*=)")


def gather_g5(vault: Path, max_items: int = 3) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    err_dir = vault / "errors"
    if not err_dir.is_dir():
        return out
    # Count how many error notes mention each token; require >=2 distinct
    # files for a hit (failed-twice).
    token_files: Dict[str, set] = defaultdict(set)
    for f in err_dir.glob("*.md"):
        txt = read_text(f) or ""
        body = strip_yaml_frontmatter(txt)
        # Heuristic 1: explicit detector/pattern markers
        for m in DETECTOR_ARG_RE.findall(body):
            token_files[m].add(f.name)
        # Heuristic 2: bare pattern_id-shaped tokens (snake_case 4+ chars)
        for m in BARE_SNAKE_TOKEN_RE.findall(body):
            if "_" in m:
                token_files[m].add(f.name)
    # Filter: appears in >=2 distinct files
    hits = [(tok, len(files), sorted(files)) for tok, files in token_files.items() if len(files) >= 2]
    # De-noise common tokens
    NOISY = {
        "fp_repair_v2", "fp_repair", "phase_b_prime", "phase_b", "no_yaml",
        "synthesis_loop", "synthesis_queue", "no_yaml_synthesis",
        "phase_b_prime_queue", "fp_repair_queue", "no_yaml_synthesis_queue",
        "fp_repair_queue_v2", "log_errors", "error_line_count",
        "total_line_count", "log_file", "wave12_synthesis_queue",
        "fp_repair_v2_full_queue", "phase_b_prime_full_queue",
        "no_yaml_synthesis_loop_queue", "phase_b_prime_queue_p1",
        "phase_b_prime_queue_p2", "phase_b_prime_queue_p3",
        "phase_b_prime_queue_p4", "phase_b_prime_queue_p5",
        "find_36_strict", "arch_mismatch_queue",
    }
    hits = [h for h in hits if h[0] not in NOISY]
    # Sort by file-count desc
    hits.sort(key=lambda x: x[1], reverse=True)
    for i, (tok, n, files) in enumerate(hits[:max_items], 1):
        yield_est = "med"
        effort_est = "med"
        score = priority_score("G5", yield_est, effort_est)
        out.append(GapCandidate(
            gap_id=f"G5-{i:03d}",
            category="G5",
            title=f"Repeat-error token `{tok}` in {n} error notes",
            description=(
                f"Token `{tok}` appears in {n} distinct error/queue notes "
                f"under `obsidian-vault/errors/`. A repeated failure across "
                f"≥2 runs suggests a fundamental issue (not a transient "
                f"flake). The token may be a detector/pattern_id, a queue "
                f"name, or a recurring failure-mode label.\n\n"
                f"Operator review: confirm whether this is one root cause "
                f"or distinct issues sharing a label."),
            evidence=(
                f"Error notes containing the token: {', '.join(files[:5])}"
                + (f" (+{len(files)-5} more)" if len(files) > 5 else "")),
            remediation=(
                f"Read the listed error notes; if they share a root cause, "
                f"open a P0/P1 burndown row for `{tok}` and dispatch a "
                f"targeted fix. If distinct, refine the heuristic by adding "
                f"`{tok}` to the NOISY filter in this analyzer."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[str((err_dir / f).relative_to(vault.parent)) for f in files[:3]],
            heuristic_fp_risk=(
                "Same arg flagged in multiple queues = one root cause "
                "split across notes; the rule double-counts."),
            heuristic_fn_risk=(
                "Tokens that don't match the snake_case + length filter "
                "won't surface (e.g. CamelCase pattern_ids)."),
        ))
    return out


# ---------------------------------------------------------------------------
# G6 — M14-trap recurrence-risk
# ---------------------------------------------------------------------------

PROMPT_TEMPLATE_GLOBS = ["templates/*.txt", "templates/*.md", "templates/**/*.txt", "templates/**/*.md"]
M14_RECENT_DAYS = 7.0
PROMPT_TEMPLATE_LINT_LEDGER = Path("reports/prompt_template_lint.jsonl")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def prompt_template_lint_confirmed(repo: Path, template_path: Path) -> bool:
    ledger_path = repo / PROMPT_TEMPLATE_LINT_LEDGER
    if not ledger_path.is_file():
        return False
    try:
        rel = template_path.resolve().relative_to(repo.resolve()).as_posix()
        digest = file_sha256(template_path)
    except (OSError, ValueError):
        return False
    try:
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for raw in lines:
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        if row.get("schema") != "auditooor.prompt_template_lint_confirmation.v1":
            continue
        if row.get("template_path") != rel:
            continue
        if row.get("template_sha256") != digest:
            continue
        if row.get("strict") is not True or row.get("fail_count") != 0:
            continue
        confirmed_at = row.get("confirmed_at")
        if not isinstance(confirmed_at, str):
            continue
        try:
            confirmed = dt.datetime.fromisoformat(confirmed_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if confirmed.tzinfo is None:
            continue
        return True
    return False


def gather_g6(repo: Path, max_items: int = 3) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    tpl_dir = repo / "templates"
    if not tpl_dir.is_dir():
        return out
    recent: List[Path] = []
    for pat in PROMPT_TEMPLATE_GLOBS:
        for p in tpl_dir.glob(pat.replace("templates/", "")):
            if p.is_file():
                age = file_age_days(p)
                if age is not None and age <= M14_RECENT_DAYS and not prompt_template_lint_confirmed(repo, p):
                    recent.append(p)
    recent = list({p.resolve(): p for p in recent}.values())
    recent.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for i, p in enumerate(recent[:max_items], 1):
        age = file_age_days(p) or 0.0
        yield_est = "med"
        effort_est = "low"
        score = priority_score("G6", yield_est, effort_est)
        out.append(GapCandidate(
            gap_id=f"G6-{i:03d}",
            category="G6",
            title=f"Recently touched prompt template not lint-confirmed: `{p.name}`",
            description=(
                f"Template `{p.relative_to(repo)}` was modified "
                f"{age:.1f}d ago. The fp_repair_v2 incident (PR #607) "
                f"showed that prompt-shape regressions ship 91/91 fakes "
                f"silently. This rule surfaces freshly-edited templates so "
                f"the operator can lint them before the next dispatch."),
            evidence=(
                f"mtime: {age:.1f}d; threshold: {M14_RECENT_DAYS:.0f}d. "
                f"This rule does NOT confirm the template has actually "
                f"failed lint - only that it has been touched recently."),
            remediation=(
                f"Run: `python3 tools/agent-dispatch-prompt-lint.py "
                f"{p.relative_to(repo)} --strict` and address any FAILs "
                f"before the next dispatch consumes this template."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[str(p.relative_to(repo))],
            heuristic_fp_risk=(
                "Not every template is dispatched; a touched-but-unused "
                "template is harmless."),
            heuristic_fn_risk=(
                "Prompts inlined in shell scripts or Python files don't "
                "live under templates/ and won't surface here."),
        ))
    return out


# ---------------------------------------------------------------------------
# G7 — memory-of-memory (vault category staleness)
# ---------------------------------------------------------------------------

VAULT_STALE_HOURS = 24.0
VAULT_CATEGORIES = [
    "calibration", "errors", "limitations", "patterns", "commits",
    "workspaces", "agent-memory", "external-memory", "tools-api",
    "make-targets", "routines",
]


def frontmatter_value(text: str, key: str) -> Optional[str]:
    """Return a simple scalar value from leading YAML frontmatter."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end == -1:
        return None
    prefix = f"{key}:"
    for raw_line in text[4:end].splitlines():
        line = raw_line.strip()
        if not line.startswith(prefix):
            continue
        value = line[len(prefix):].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            return value[1:-1]
        return value
    return None


def routines_source_mirror_current(vault: Path) -> bool:
    """True when routines notes are exact mirrors of their SKILL.md sources."""
    routines_dir = vault / "routines"
    if not routines_dir.is_dir():
        return False

    notes = sorted(p for p in routines_dir.glob("*.md") if p.is_file())
    if not notes:
        return False

    source_paths: List[Path] = []
    for note in notes:
        text = read_text(note)
        if text is None:
            return False
        canonical = frontmatter_value(text, "canonical_path")
        if not canonical:
            return False

        source_path = Path(os.path.expanduser(canonical))
        source_text = read_text(source_path)
        if source_text is None:
            return False
        note_body = strip_yaml_frontmatter(text)
        if note_body.startswith("\n"):
            note_body = note_body[1:]
        if note_body != source_text:
            return False
        source_paths.append(source_path)

    source_roots = {
        p.parent.parent for p in source_paths
        if p.name == "SKILL.md" and p.parent.parent.is_dir()
    }
    if len(source_roots) == 1:
        source_task_ids = {
            p.parent.name
            for p in next(iter(source_roots)).glob("*/SKILL.md")
            if p.is_file()
        }
        if source_task_ids != {p.stem for p in notes}:
            return False

    return True


def gather_g7(vault: Path, max_items: int = 3) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    stale = []
    for cat in VAULT_CATEGORIES:
        cdir = vault / cat
        if not cdir.is_dir():
            continue
        newest = newest_mtime(cdir)
        if newest is None:
            continue
        age_h = (dt.datetime.now().timestamp() - newest) / 3600.0
        if age_h > VAULT_STALE_HOURS:
            if cat == "routines" and routines_source_mirror_current(vault):
                continue
            stale.append((cat, age_h, cdir))
    stale.sort(key=lambda x: x[1], reverse=True)
    for i, (cat, age_h, cdir) in enumerate(stale[:max_items], 1):
        yield_est = "low"
        effort_est = "low"
        score = priority_score("G7", yield_est, effort_est)
        out.append(GapCandidate(
            gap_id=f"G7-{i:03d}",
            category="G7",
            title=f"Vault category `{cat}` stale (>{VAULT_STALE_HOURS:.0f}h)",
            description=(
                f"`obsidian-vault/{cat}/` newest file is {age_h:.1f}h old. "
                f"For an active loop this likely indicates an ingester gap "
                f"(L1 watcher not firing, cron drift, or category genuinely "
                f"quiet). Operator review confirms which."),
            evidence=f"newest mtime in `{cat}`: {age_h:.1f}h ago.",
            remediation=(
                f"Run `make vault-refresh` and re-check; if still stale, "
                f"the L1 watcher or per-category emitter is the regression. "
                f"Inspect `tools/obsidian-vault-emit.py` and "
                f"`tools/memory-deep-crawler.py` for the `{cat}` ingest "
                f"path."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[str(cdir.relative_to(vault.parent))],
            heuristic_fp_risk=(
                "Low-volume categories (incidents, tasks) may correctly "
                "go quiet for days."),
            heuristic_fn_risk=(
                "An INDEX.md auto-refresh masks staleness of per-item "
                "notes underneath."),
        ))
    return out


# ---------------------------------------------------------------------------
# G8 — open knowledge-gap ledger rows
# ---------------------------------------------------------------------------

_KNOWLEDGE_GAP_LOG = None


def knowledge_gap_log_module():
    global _KNOWLEDGE_GAP_LOG
    if _KNOWLEDGE_GAP_LOG is not None:
        return _KNOWLEDGE_GAP_LOG
    path = REPO / "tools" / "knowledge-gap-log.py"
    spec = importlib.util.spec_from_file_location("auditooor_knowledge_gap_log", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load knowledge gap log module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _KNOWLEDGE_GAP_LOG = module
    return module


def dedupe(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def knowledge_gap_evidence(row: Dict) -> str:
    parts = [str(row.get("evidence") or "").strip()]
    blocked = row.get("blocked_by_artifacts") or []
    tasks = row.get("downstream_blocked_tasks") or []
    if blocked:
        parts.append("Blocked by artifacts: " + ", ".join(f"`{item}`" for item in blocked))
    if tasks:
        parts.append("Downstream blocked tasks: " + ", ".join(f"`{item}`" for item in tasks))
    return "\n\n".join(part for part in parts if part)


def knowledge_gap_description(row: Dict) -> str:
    return (
        f"Question: {row.get('question')}\n\n"
        f"{row.get('description')}\n\n"
        f"Area: `{row.get('area')}`. Type: `{row.get('gap_type')}`. "
        f"Severity: `{row.get('severity')}`.")


SEVERITY_SORT = {"high": 0, "medium": 1, "low": 2}


def gather_g8(repo: Path, max_items: int = 5) -> List[GapCandidate]:
    ledger = repo / "reports" / "knowledge_gaps.jsonl"
    if not ledger.is_file():
        return []
    try:
        kg = knowledge_gap_log_module()
        states = kg.latest_states(ledger, repo=repo)
    except Exception as exc:
        yield_est = "high"
        effort_est = "low"
        return [GapCandidate(
            gap_id="G8-001",
            category="G8",
            title="Knowledge-gap ledger invalid",
            description=(
                "`reports/knowledge_gaps.jsonl` exists but failed strict "
                "validation, so L4 cannot trust missing-truth state."),
            evidence=str(exc),
            remediation=(
                "Run `python3 tools/knowledge-gap-log.py validate` and repair "
                "the canonical ledger before dispatching work that depends on "
                "knowledge-gap state."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=priority_score("G8", yield_est, effort_est),
            source_paths=["reports/knowledge_gaps.jsonl"],
            heuristic_fp_risk=(
                "The ledger may be repairable without changing the underlying "
                "work queue."),
            heuristic_fn_risk=(
                "While invalid, no individual open knowledge gaps can be ranked."),
        )]
    candidates: List[GapCandidate] = []
    for row in states.values():
        if row.get("status") != "open":
            continue
        yield_est = row.get("yield_estimate") or "med"
        effort_est = row.get("effort_estimate") or "med"
        candidates.append(GapCandidate(
            gap_id=row["candidate_gap_id"],
            category="G8",
            title=row["title"],
            description=knowledge_gap_description(row),
            evidence=knowledge_gap_evidence(row),
            remediation=row["remediation"],
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=priority_score("G8", yield_est, effort_est),
            source_paths=dedupe(
                ["reports/knowledge_gaps.jsonl"]
                + list(row.get("source_paths") or [])
                + list(row.get("blocked_by_artifacts") or [])),
            analyzer_target_paths=dedupe(row.get("analyzer_target_paths") or []),
            heuristic_fp_risk=row.get("heuristic_fp_risk") or (
                "The unknown may have been resolved outside the canonical ledger."),
            heuristic_fn_risk=row.get("heuristic_fn_risk") or (
                "Missing truth not logged in reports/knowledge_gaps.jsonl is invisible."),
        ))
    candidates.sort(key=lambda c: (
        -c.priority_score,
        SEVERITY_SORT.get(str(states.get(c.gap_id.removeprefix("G8-"), {}).get("severity")), 9),
        str(states.get(c.gap_id.removeprefix("G8-"), {}).get("occurred_at") or ""),
        c.gap_id,
    ))
    return candidates[:max_items]


# ---------------------------------------------------------------------------
# G9 — completion gaps from terminal dispatch rows without finalization memory
# ---------------------------------------------------------------------------

_TASK_FINALIZATION_LEDGER = None


def task_finalization_ledger_module():
    global _TASK_FINALIZATION_LEDGER
    if _TASK_FINALIZATION_LEDGER is not None:
        return _TASK_FINALIZATION_LEDGER
    path = REPO / "tools" / "task-finalization-ledger.py"
    spec = importlib.util.spec_from_file_location("auditooor_task_finalization_ledger", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load task finalization ledger module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _TASK_FINALIZATION_LEDGER = module
    return module


def gather_g9(vault: Path, repo: Path, max_items: int = 5) -> List[GapCandidate]:
    out: List[GapCandidate] = []
    manifest = vault / "dispatch" / "next_dispatch_manifest.json"
    if not manifest.is_file():
        return out
    validator = task_finalization_ledger_module()
    audit = getattr(validator, "manifest_completion_gaps", None)
    if audit is None:
        raise RuntimeError("task finalization ledger module missing manifest_completion_gaps()")
    missing = audit(manifest, repo / "reports" / "task_finalization.jsonl")
    for i, row in enumerate(missing[:max_items], 1):
        gap_id = row["gap_id"]
        slot_id = row["slot_id"]
        status = row["status"]
        artifact = str(row.get("terminal_artifact") or "").strip()
        proof_reason = str(row.get("proof_gap_reason") or "").strip()
        yield_est = "high"
        effort_est = "low"
        score = priority_score("G9", yield_est, effort_est)
        evidence = (
            f"`obsidian-vault/dispatch/next_dispatch_manifest.json` has "
            f"`gap_id={gap_id}`, `slot_id={slot_id}`, `status={status}`."
        )
        if proof_reason == "manifest_terminal_artifact_unproved":
            evidence += (
                " Its `terminal_artifact` is missing or not provable, so "
                "`reports/task_finalization.jsonl` cannot prove the exact terminal row."
            )
        else:
            evidence += (
                f" Its `terminal_artifact={artifact}` has no matching canonical "
                "finalization row in `reports/task_finalization.jsonl`."
            )
        out.append(GapCandidate(
            gap_id=f"G9-{i:03d}",
            category="G9",
            title=f"Finalize terminal dispatch `{gap_id}` / `{slot_id}` ({status})",
            description=(
                f"The active dispatch manifest contains terminal row `{gap_id}` "
                f"in `{slot_id}` with status `{status}`, but the canonical task "
                f"finalization ledger cannot prove that exact terminal row closed. "
                f"That means the loop cannot reliably learn what changed, what "
                f"was verified, or what followups remain."),
            evidence=evidence,
            remediation=(
                f"Run `python3 tools/task-finalization-ledger.py audit-manifest "
                f"--manifest obsidian-vault/dispatch/next_dispatch_manifest.json` "
                f"and then close `{gap_id}` with `add` or `from-commit`. The row "
                f"must include owner, source manifest, terminal artifact, changed "
                f"files when landed, verification commands with exit codes, "
                f"memory updates, and followups/blocker state."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=score,
            source_paths=[
                "obsidian-vault/dispatch/next_dispatch_manifest.json",
                "reports/task_finalization.jsonl",
            ],
            heuristic_fp_risk=(
                "Work may be complete but the finalization ledger has not been "
                "backfilled yet; the fix is to log proof, not redispatch work."),
            heuristic_fn_risk=(
                "A malformed or stale finalization row can still hide work if it "
                "is later accepted by the ledger validator; run "
                "`make task-finalization-validate`."),
        ))
    return out


# ---------------------------------------------------------------------------
# G10 — recurring harness failures from canonical harness-failure memory
# ---------------------------------------------------------------------------

_HARNESS_FAILURE_MEMORY = None


def harness_failure_memory_module():
    global _HARNESS_FAILURE_MEMORY
    if _HARNESS_FAILURE_MEMORY is not None:
        return _HARNESS_FAILURE_MEMORY
    path = REPO / "tools" / "harness-failure-memory.py"
    spec = importlib.util.spec_from_file_location("auditooor_harness_failure_memory", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load harness failure memory module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _HARNESS_FAILURE_MEMORY = module
    return module


def harness_target_paths(row: Dict) -> List[str]:
    targets: List[str] = []
    for value in row.get("tools_affected") or []:
        text = str(value or "").strip()
        if text == "Makefile" or text.startswith(("tools/", "docs/", "reference/", "detectors/")):
            targets.append(text)
    return dedupe(targets) or ["tools/harness-failure-memory.py"]


def harness_failure_candidate(row: Dict) -> GapCandidate:
    root = row["root_cause_id"]
    count = int(row.get("occurrence_count") or 0)
    tools = list(row.get("tools_affected") or [])
    multi_tool = len(tools) >= 2
    yield_est = "high" if count >= 3 or multi_tool else "med"
    effort_est = "low" if row.get("known_fix") and row.get("guard") else "med"
    note = f"obsidian-vault/harness-failures/{root}.md"
    source_paths = dedupe(
        ["reports/harness_failures.jsonl", note]
        + list(row.get("counter_example_links") or [])
        + list(row.get("source_paths") or []))
    return GapCandidate(
        gap_id=f"G10-{root}",
        category="G10",
        title=f"Harness failure recurrence: `{root}`",
        description=(
            f"The harness-failure memory reports `{root}` as a repeated active/watch root "
            f"cause with status `{row.get('status')}` and severity "
            f"`{row.get('severity')}`. Re-dispatching this through L4 gives "
            f"the next loop the known fix, guard, and counter-examples without "
            f"rediscovering the failure mode."),
        evidence=(
            f"Occurrence count: `{count}`. First seen: `{row.get('first_seen')}`. "
            f"Last seen: `{row.get('last_seen')}`. Tools affected: "
            f"{', '.join(f'`{tool}`' for tool in tools) or '`unknown`'}.\n\n"
            f"Symptom: {row.get('symptom')}\n\n"
            f"Guard: {row.get('guard')}"),
        remediation=(
            f"Use `reports/harness_failures.jsonl` and `{note}` as the memory "
            f"root. Apply or verify the known fix: {row.get('known_fix')}. "
            f"Keep the guard active: {row.get('guard')}. Then run "
            f"`make harness-failure-memory-test`, `make memory-next-loop-test`, "
            f"and the relevant harness guard before finalizing."),
        yield_estimate=yield_est,
        effort_estimate=effort_est,
        priority_score=priority_score("G10", yield_est, effort_est),
        source_paths=source_paths,
        analyzer_target_paths=harness_target_paths(row),
        heuristic_fp_risk=(
            "Backfilled recurrence counts can remain high after a guard fix; "
            "operator review must confirm the root cause still has current value."),
        heuristic_fn_risk=(
            "Harness failures that were not logged in reports/harness_failures.jsonl "
            "are invisible to this heuristic."),
    )


def gather_g10(repo: Path, max_items: int = 5) -> List[GapCandidate]:
    report = repo / "reports" / "harness_failures.jsonl"
    if not report.is_file():
        return []
    try:
        hfm = harness_failure_memory_module()
        errors = hfm.validate_report(report, repo=repo)
        if errors:
            raise ValueError("; ".join(errors[:5]))
        rows = [hfm.normalize_row(row) for row in hfm.read_jsonl(report)]
    except Exception as exc:
        yield_est = "high"
        effort_est = "low"
        return [GapCandidate(
            gap_id="G10-001",
            category="G10",
            title="Harness-failure report invalid",
            description=(
                "`reports/harness_failures.jsonl` exists but failed strict "
                "validation, so L4 cannot trust recurring harness-failure memory."),
            evidence=str(exc),
            remediation=(
                "Run `python3 tools/harness-failure-memory.py --validate` and "
                "repair or regenerate the canonical report before dispatching "
                "harness-failure recurrence work."),
            yield_estimate=yield_est,
            effort_estimate=effort_est,
            priority_score=priority_score("G10", yield_est, effort_est),
            source_paths=["reports/harness_failures.jsonl"],
            analyzer_target_paths=["tools/harness-failure-memory.py"],
            heuristic_fp_risk=(
                "The report may be repairable without changing any harness "
                "guard or detector tooling."),
            heuristic_fn_risk=(
                "While invalid, individual harness root causes cannot be ranked."),
        )]
    candidate_rows = [
        row for row in rows
        if int(row.get("occurrence_count") or 0) >= 2
        and str(row.get("status") or "") in {"active", "watch"}
    ]
    count_by_gap = {
        f"G10-{row['root_cause_id']}": int(row.get("occurrence_count") or 0)
        for row in candidate_rows
    }
    last_seen_by_gap = {
        f"G10-{row['root_cause_id']}": int(str(row.get("last_seen") or "0").replace("-", "") or 0)
        for row in candidate_rows
    }
    candidates = [
        harness_failure_candidate(row)
        for row in candidate_rows
    ]
    candidates.sort(key=lambda c: (
        -c.priority_score,
        -count_by_gap.get(c.gap_id, 0),
        -last_seen_by_gap.get(c.gap_id, 0),
        c.gap_id,
    ))
    return candidates[:max_items]


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------

def gather_all(vault: Path, repo: Path) -> List[GapCandidate]:
    candidates: List[GapCandidate] = []
    candidates.extend(gather_g1(vault, repo))
    candidates.extend(gather_g2(vault))
    candidates.extend(gather_g3(vault))
    candidates.extend(gather_g4(vault))
    candidates.extend(gather_g5(vault))
    candidates.extend(gather_g6(repo))
    candidates.extend(gather_g7(vault))
    candidates.extend(gather_g8(repo))
    candidates.extend(gather_g9(vault, repo))
    candidates.extend(gather_g10(repo))
    candidates.sort(key=lambda c: c.priority_score, reverse=True)
    return candidates


def write_run_report(out_dir: Path, run_date: str, candidates: List[GapCandidate]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{run_date}.md"
    lines = ["---",
             f'category: "memory-gap-analysis-run"',
             f'generated_at: "{dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}"',
             f'run_date: "{run_date}"',
             f'candidate_count: "{len(candidates)}"',
             f'schema: "{SCHEMA}"',
             "tags:",
             "  - memory-gap-analysis",
             "---",
             "",
             f"# Memory Gap Analysis - {run_date}",
             "",
             f"_Generated by `tools/memory-gap-analyzer.py`. "
             f"Read-only on the vault; output is heuristic._",
             "",
             "## Summary",
             "",
             f"- Total candidates surfaced: **{len(candidates)}**",
             f"- Categories: " + ", ".join(sorted({c.category for c in candidates})),
             "",
             "Priority formula:",
             "",
             "```",
             "priority = category_multiplier * yield_weight / effort_weight",
             "yield: high=3, med=2, low=1",
             "effort: low=1, med=2, high=3",
             "category multipliers: G1=1.4, G2=1.1, G3=0.8, G4=1.0,",
             "                      G5=1.2, G6=1.3, G7=0.9, G8=1.5, G9=1.4,",
             "                      G10=1.2",
             "```",
             "",
             "## Candidates",
             ""]
    if not candidates:
        lines.append("_No gaps surfaced this run._")
    else:
        for c in candidates:
            lines.append(c.to_md())
            lines.append("---")
            lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def write_next_loop(vault: Path, candidates: List[GapCandidate], top_n: int = 5) -> Path:
    out = vault / "NEXT_LOOP.md"
    top = candidates[:top_n]
    lines = ["---",
             f'category: "memory-next-loop"',
             f'generated_at: "{dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}"',
             f'top_n: "{len(top)}"',
             f'total_candidates: "{len(candidates)}"',
             f'schema: "{SCHEMA}"',
             "tags:",
             "  - memory/next-loop",
             "---",
             "",
             "# Next Loop - Top Candidates",
             "",
             f"_Top {len(top)} of {len(candidates)} surfaced by "
             f"`tools/memory-gap-analyzer.py`._",
             "",
             "**Operator action required.** This is a heuristic surface - "
             "every candidate carries declared FP/FN risks (see per-row "
             "block). NO auto-dispatch happens here; use "
             "`tools/memory-next-loop-dispatcher.py` to emit prompt "
             "templates for review.",
             ""]
    if not top:
        lines.append("_No top candidates this run._")
    else:
        lines.append("| Rank | Gap ID | Category | Priority | Title |")
        lines.append("|------|--------|----------|---------:|-------|")
        for i, c in enumerate(top, 1):
            lines.append(f"| {i} | `{c.gap_id}` | `{c.category}` | "
                         f"{c.priority_score:.2f} | {c.title} |")
        lines.append("")
        lines.append("## Details")
        lines.append("")
        for c in top:
            lines.append(c.to_md())
            lines.append("---")
            lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def write_jsonl_for_dispatcher(vault: Path, candidates: List[GapCandidate]) -> Path:
    """Emit a machine-readable form so the dispatcher doesn't have to parse MD."""
    out_dir = vault / "gap-analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "candidates.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps(asdict(c)) + "\n")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vault-dir", default=str(DEFAULT_VAULT),
                    help="path to obsidian-vault root")
    ap.add_argument("--repo", default=str(REPO),
                    help="path to auditooor repo (for docs/, templates/)")
    ap.add_argument("--top-n", type=int, default=5,
                    help="top-N candidates for NEXT_LOOP.md (default: 5)")
    ap.add_argument("--json-out", default=None,
                    help="optional path to emit a JSON summary")
    ap.add_argument("--dry-run", action="store_true",
                    help="print summary, don't write vault files")
    args = ap.parse_args(argv)

    vault = Path(args.vault_dir).resolve()
    repo = Path(args.repo).resolve()

    if not vault.is_dir():
        print(f"vault dir not found: {vault}", file=sys.stderr)
        return 2

    candidates = gather_all(vault, repo)

    print(f"[memory-gap-analyzer] vault={vault}")
    print(f"  candidates surfaced: {len(candidates)}")
    by_cat = Counter(c.category for c in candidates)
    for cat in sorted(by_cat):
        print(f"  {cat}: {by_cat[cat]}")

    summary = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "vault_dir": str(vault),
        "candidate_count": len(candidates),
        "by_category": dict(by_cat),
        "top_n": [
            {"gap_id": c.gap_id, "category": c.category,
             "priority_score": c.priority_score, "title": c.title}
            for c in candidates[:args.top_n]
        ],
    }

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(summary, indent=2),
                                       encoding="utf-8")
        print(f"  json summary: {args.json_out}")

    if args.dry_run:
        print("  (dry-run; no vault writes)")
        return 0

    run_date = dt.date.today().isoformat()
    run_dir = vault / "gap-analysis"
    run_md = write_run_report(run_dir, run_date, candidates)
    next_md = write_next_loop(vault, candidates, top_n=args.top_n)
    jsonl = write_jsonl_for_dispatcher(vault, candidates)

    print(f"  run report: {run_md}")
    print(f"  next-loop:  {next_md}")
    print(f"  jsonl:      {jsonl}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
