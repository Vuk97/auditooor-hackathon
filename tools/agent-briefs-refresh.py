#!/usr/bin/env python3
"""agent-briefs-refresh.py - freshness audit + selective regeneration for agent_briefs/

Background (iter14 RRRR META-1 dogfood):
  16/17 files under agent_briefs/ were frozen at 2026-05-10 (iter8/9). Only
  detector-reentrancy-guard.md was regenerated, by agent-recall-detector-loop.py.
  No brief-refresh step exists in the V3 iter loop.

Lane WWWW finding (iter15):
  agent_briefs/ contains TWO distinct categories of files which CANNOT be
  treated uniformly:

  Category A: hand-authored persona / category briefs
    - access_control.md, blue_team.md, deployment_state_enumeration.md,
      event_emission_parity.md, fee_logic.md, general_breadth_first.md,
      glider_query_integration.md, judge.md, multicall_safety.md,
      numerical_stability_solvers.md, red_team.md, reentrancy_deep.md,
      scope_review.md, stride_attack_tree.md, upgrade_security.md,
      AGENT_BOOTSTRAP_QUERY_2026-05-05.md
    - These are long-term prompt/knowledge templates curated by humans.
      They CANNOT be auto-regenerated without an LLM call + human review.
      "Freshness" here means "did a maintainer update this within window".

  Category B: auto-generated detector-authoring briefs
    - detector-<slug>.md
    - Templated by tools/agent-recall-detector-loop.py from the workspace's
      .auditooor/agent_recall_detector_tasks.json queue. Safe to regenerate
      mechanically when the queue task exists.

Behaviour:
  - Walks agent_briefs/*.md (excludes templates/ subdir).
  - Computes mtime-based age in days.
  - Skips briefs touched < FRESH_SKIP_DAYS (default 1) as "fresh".
  - For Category B briefs older than WARN_DAYS: attempts regeneration via
    agent-recall-detector-loop.py (Stages 3 only - re-render template) if a
    matching detector task is present in any workspace.
  - For Category A briefs:
      - >= WARN_DAYS  -> WARN (logged, non-zero in --strict only)
      - >= FAIL_DAYS  -> FAIL (always non-zero exit; surface in CI / iter loop)
    Honest verdict: this tool DOES NOT fabricate an offline regeneration path
    for Category A briefs. The remediation path is "maintainer updates the
    file" or "operator authorizes an LLM-call-based refresh".

Exit codes:
  0 - all briefs fresh, or stale briefs in WARN band only and not --strict
  1 - one or more briefs in FAIL band (>= FAIL_DAYS)
  2 - input error (briefs dir missing, etc.)
  3 - --strict was set and at least one brief was in WARN band

Usage:
  python3 tools/agent-briefs-refresh.py
  python3 tools/agent-briefs-refresh.py --strict
  python3 tools/agent-briefs-refresh.py --json
  python3 tools/agent-briefs-refresh.py --workspace ~/audits/spark
  python3 tools/agent-briefs-refresh.py --fresh-skip-days 2 --warn-days 10 --fail-days 21

Wired into the V3 iter loop via Makefile target `refresh-agent-briefs`.

L34 compliance: this tool NEVER writes to submissions/. It writes only to
agent_briefs/detector-*.md (Category B) and emits diagnostics to stdout/JSON.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Optional, Sequence

REPO = pathlib.Path(__file__).resolve().parents[1]
BRIEFS_DIR = REPO / "agent_briefs"
DETECTOR_LOOP_TOOL = REPO / "tools" / "agent-recall-detector-loop.py"

SCHEMA = "auditooor.agent_briefs_refresh.v1"

# Category A: hand-authored persona / category briefs. Maintainer-curated.
# Anything matching this set is classified as "static" and not regenerated.
STATIC_PERSONA_BRIEFS = frozenset(
    {
        "access_control.md",
        "AGENT_BOOTSTRAP_QUERY_2026-05-05.md",
        "blue_team.md",
        "deployment_state_enumeration.md",
        "event_emission_parity.md",
        "fee_logic.md",
        "general_breadth_first.md",
        "glider_query_integration.md",
        "judge.md",
        "multicall_safety.md",
        "numerical_stability_solvers.md",
        "red_team.md",
        "reentrancy_deep.md",
        "scope_review.md",
        "stride_attack_tree.md",
        "upgrade_security.md",
    }
)

# Category B: prefix marker for auto-regeneratable detector-authoring briefs.
DETECTOR_BRIEF_PREFIX = "detector-"

DEFAULT_FRESH_SKIP_DAYS = 1
DEFAULT_WARN_DAYS = 7
DEFAULT_FAIL_DAYS = 14


@dataclasses.dataclass
class BriefStatus:
    name: str
    path: pathlib.Path
    age_days: float
    category: str  # "static" | "detector" | "unknown"
    bucket: str    # "fresh" | "warn" | "fail"
    regenerated: bool = False
    regenerate_error: Optional[str] = None
    skipped_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "age_days": round(self.age_days, 2),
            "category": self.category,
            "bucket": self.bucket,
            "regenerated": self.regenerated,
            "regenerate_error": self.regenerate_error,
            "skipped_reason": self.skipped_reason,
        }


def _classify(name: str) -> str:
    if name in STATIC_PERSONA_BRIEFS:
        return "static"
    if name.startswith(DETECTOR_BRIEF_PREFIX):
        return "detector"
    return "unknown"


def _bucket(age_days: float, *, fresh_skip: int, warn: int, fail: int) -> str:
    if age_days < fresh_skip:
        return "fresh"
    if age_days >= fail:
        return "fail"
    if age_days >= warn:
        return "warn"
    return "fresh"


def _iter_briefs(briefs_dir: pathlib.Path) -> list[pathlib.Path]:
    """Return all *.md files directly under briefs_dir (excludes templates/)."""
    if not briefs_dir.is_dir():
        return []
    out: list[pathlib.Path] = []
    for entry in sorted(briefs_dir.iterdir()):
        if entry.is_file() and entry.suffix == ".md":
            out.append(entry)
    return out


def _age_days(path: pathlib.Path, now: dt.datetime) -> float:
    mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
    return (now - mtime).total_seconds() / 86400.0


def _regenerate_detector_brief(
    brief_path: pathlib.Path,
    *,
    workspace: Optional[pathlib.Path],
    log,
) -> tuple[bool, Optional[str]]:
    """Re-run agent-recall-detector-loop.py to refresh a detector-*.md brief.

    Returns (regenerated, error_message). regenerated=False with a non-None
    error_message means we attempted regeneration and failed honestly.
    """
    if not DETECTOR_LOOP_TOOL.is_file():
        return False, f"detector loop tool not found at {DETECTOR_LOOP_TOOL}"
    if workspace is None:
        return False, "no --workspace supplied; detector regeneration needs a workspace"
    tasks_path = workspace / ".auditooor" / "agent_recall_detector_tasks.json"
    if not tasks_path.is_file():
        return False, f"no detector task queue at {tasks_path}; cannot regenerate"
    # Sanity: only Stage 3 (brief materialisation). Don't run Stages 1/2/4/5
    # to keep the refresh path narrow.
    cmd = [
        sys.executable,
        str(DETECTOR_LOOP_TOOL),
        "--workspace",
        str(workspace),
        "--stage",
        "3",
    ]
    log(f"  [regenerate] invoking: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "detector loop tool timed out after 60s"
    except Exception as exc:  # noqa: BLE001 - surface any failure
        return False, f"detector loop tool raised: {exc!r}"
    if proc.returncode not in (0, 1):
        return False, (
            f"detector loop tool exited rc={proc.returncode}; "
            f"stderr head: {(proc.stderr or '').splitlines()[:1]}"
        )
    # rc=1 is nominal (no detector tasks) but means brief wasn't regenerated.
    if proc.returncode == 1:
        return False, "detector loop tool reported no detector tasks (rc=1)"
    return brief_path.is_file(), None


def audit_briefs(
    briefs_dir: pathlib.Path = BRIEFS_DIR,
    *,
    workspace: Optional[pathlib.Path] = None,
    fresh_skip_days: int = DEFAULT_FRESH_SKIP_DAYS,
    warn_days: int = DEFAULT_WARN_DAYS,
    fail_days: int = DEFAULT_FAIL_DAYS,
    attempt_regenerate: bool = True,
    now: Optional[dt.datetime] = None,
    log=None,
) -> list[BriefStatus]:
    """Audit briefs_dir and (optionally) regenerate detector-* briefs.

    Pure-functional: takes paths + thresholds, returns a list of BriefStatus.
    No global state, no side effects beyond optional regeneration writes.
    """
    if log is None:
        log = lambda *_a, **_k: None  # noqa: E731
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    statuses: list[BriefStatus] = []
    for brief in _iter_briefs(briefs_dir):
        name = brief.name
        category = _classify(name)
        age = _age_days(brief, now)
        bucket = _bucket(age, fresh_skip=fresh_skip_days, warn=warn_days, fail=fail_days)
        status = BriefStatus(
            name=name, path=brief, age_days=age, category=category, bucket=bucket
        )
        if bucket == "fresh":
            status.skipped_reason = f"fresh (<{fresh_skip_days}d)"
            log(f"[fresh] {name} ({age:.1f}d)")
            statuses.append(status)
            continue
        if category == "detector" and attempt_regenerate:
            log(f"[regen] {name} ({age:.1f}d, bucket={bucket})")
            regenerated, err = _regenerate_detector_brief(
                brief, workspace=workspace, log=log
            )
            status.regenerated = regenerated
            status.regenerate_error = err
            if regenerated:
                # Re-stat to update age post-regen
                status.age_days = _age_days(brief, dt.datetime.now(dt.timezone.utc))
                status.bucket = _bucket(
                    status.age_days,
                    fresh_skip=fresh_skip_days,
                    warn=warn_days,
                    fail=fail_days,
                )
                log(f"  [regen] OK ({status.age_days:.1f}d after regen)")
            else:
                log(f"  [regen] FAILED: {err}")
        elif category == "static":
            log(
                f"[{bucket}] {name} ({age:.1f}d) - hand-authored; "
                "needs maintainer update or operator-authorized LLM-refresh"
            )
            status.skipped_reason = "static-persona brief; no offline regenerator"
        else:
            log(
                f"[{bucket}] {name} ({age:.1f}d) - category=unknown; "
                "treated as advisory only"
            )
            status.skipped_reason = "unknown category; not regenerated"
        statuses.append(status)
    return statuses


def summarize(statuses: Sequence[BriefStatus]) -> dict[str, Any]:
    by_bucket = {"fresh": 0, "warn": 0, "fail": 0}
    by_category = {"static": 0, "detector": 0, "unknown": 0}
    regenerated = 0
    regen_failed = 0
    fail_briefs: list[str] = []
    warn_briefs: list[str] = []
    for s in statuses:
        by_bucket[s.bucket] = by_bucket.get(s.bucket, 0) + 1
        by_category[s.category] = by_category.get(s.category, 0) + 1
        if s.regenerated:
            regenerated += 1
        if s.regenerate_error:
            regen_failed += 1
        if s.bucket == "fail":
            fail_briefs.append(s.name)
        elif s.bucket == "warn":
            warn_briefs.append(s.name)
    return {
        "total_briefs": len(statuses),
        "by_bucket": by_bucket,
        "by_category": by_category,
        "regenerated_count": regenerated,
        "regenerate_failed_count": regen_failed,
        "fail_briefs": sorted(fail_briefs),
        "warn_briefs": sorted(warn_briefs),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freshness audit + selective regeneration for agent_briefs/. "
            "Walks the directory, skips fresh briefs, regenerates auto-generated "
            "detector-* briefs when stale, and emits WARN/FAIL diagnostics for "
            "hand-authored persona briefs that cannot be regenerated offline."
        ),
    )
    parser.add_argument(
        "--briefs-dir",
        type=pathlib.Path,
        default=BRIEFS_DIR,
        help=f"directory containing brief .md files (default: {BRIEFS_DIR})",
    )
    parser.add_argument(
        "--workspace",
        type=pathlib.Path,
        default=None,
        help="audit workspace path (required if detector-* briefs need regeneration)",
    )
    parser.add_argument(
        "--fresh-skip-days",
        type=int,
        default=DEFAULT_FRESH_SKIP_DAYS,
        help=f"skip briefs younger than N days (default: {DEFAULT_FRESH_SKIP_DAYS})",
    )
    parser.add_argument(
        "--warn-days",
        type=int,
        default=DEFAULT_WARN_DAYS,
        help=f"emit WARN at >= N days (default: {DEFAULT_WARN_DAYS})",
    )
    parser.add_argument(
        "--fail-days",
        type=int,
        default=DEFAULT_FAIL_DAYS,
        help=f"emit FAIL (rc=1) at >= N days (default: {DEFAULT_FAIL_DAYS})",
    )
    parser.add_argument(
        "--no-regenerate",
        action="store_true",
        help="audit-only mode; do not attempt to regenerate detector-* briefs",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit rc=3 if any brief is in WARN band (default: WARN does not fail)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON to stdout (diagnostics go to stderr)",
    )
    args = parser.parse_args(argv)

    briefs_dir: pathlib.Path = args.briefs_dir.expanduser().resolve()
    if not briefs_dir.is_dir():
        print(f"[error] briefs dir not found: {briefs_dir}", file=sys.stderr)
        return 2

    workspace: Optional[pathlib.Path] = None
    if args.workspace is not None:
        workspace = args.workspace.expanduser().resolve()
        if not workspace.is_dir():
            print(
                f"[warn] workspace {workspace} not found; detector regen will be skipped",
                file=sys.stderr,
            )
            workspace = None

    log_stream = sys.stderr if args.json else sys.stdout

    def log(*parts: object) -> None:
        print(*parts, file=log_stream)

    log(f"[agent-briefs-refresh] briefs_dir={briefs_dir}")
    log(
        f"[agent-briefs-refresh] thresholds: fresh<{args.fresh_skip_days}d, "
        f"warn>={args.warn_days}d, fail>={args.fail_days}d"
    )
    if workspace:
        log(f"[agent-briefs-refresh] workspace={workspace}")
    if args.no_regenerate:
        log("[agent-briefs-refresh] regeneration DISABLED (audit-only)")

    statuses = audit_briefs(
        briefs_dir,
        workspace=workspace,
        fresh_skip_days=args.fresh_skip_days,
        warn_days=args.warn_days,
        fail_days=args.fail_days,
        attempt_regenerate=not args.no_regenerate,
        log=log,
    )
    summary = summarize(statuses)

    log("")
    log(
        f"[summary] total={summary['total_briefs']} "
        f"fresh={summary['by_bucket']['fresh']} "
        f"warn={summary['by_bucket']['warn']} "
        f"fail={summary['by_bucket']['fail']} "
        f"regenerated={summary['regenerated_count']} "
        f"regen_failed={summary['regenerate_failed_count']}"
    )
    if summary["fail_briefs"]:
        log(f"[summary] FAIL briefs: {summary['fail_briefs']}")
    if summary["warn_briefs"]:
        log(f"[summary] WARN briefs: {summary['warn_briefs']}")

    if args.json:
        payload = {
            "schema": SCHEMA,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "briefs_dir": str(briefs_dir),
            "workspace": str(workspace) if workspace else None,
            "thresholds": {
                "fresh_skip_days": args.fresh_skip_days,
                "warn_days": args.warn_days,
                "fail_days": args.fail_days,
            },
            "regenerate_enabled": not args.no_regenerate,
            "summary": summary,
            "briefs": [s.to_dict() for s in statuses],
        }
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    if summary["by_bucket"]["fail"] > 0:
        return 1
    if args.strict and summary["by_bucket"]["warn"] > 0:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
