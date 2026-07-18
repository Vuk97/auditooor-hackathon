#!/usr/bin/env python3
"""stop-criterion-checker.py — Phase E2: workflow-predicate checker.

Formalizes R85's "6 consecutive FPs = surface exhausted" stop criterion as a
runnable check against a workspace's recent finding-attempt history. Also loads
workflow predicates from case_study/*.md frontmatter (stop_criterion,
workflow_signature, loop_back_phase) to emit actionable verdicts.

CLI:
    python3 tools/stop-criterion-checker.py --workspace <ws>
    python3 tools/stop-criterion-checker.py --workspace <ws> --json
    python3 tools/stop-criterion-checker.py --workspace <ws> --case-study-dir <dir>
    python3 tools/stop-criterion-checker.py --workspace <ws> --fp-window N

Exit codes:
    0 — CONTINUE  (no stop criterion fires)
    1 — STOP      (at least one stop criterion fires; surface exhausted or
                   workflow predicate matched)
    2 — UNKNOWN   (workspace missing required artifacts; cannot decide)
    3 — usage error

Summary line printed on stdout (always):
    [stop-criterion] verdict=CONTINUE|STOP|UNKNOWN  triggers=N  checked=M

----------------------------------------------------------------------
R85 stop criterion — "6 consecutive FP rule"
----------------------------------------------------------------------
The workspace's finding-attempt log records each scanner-flag attempt and
whether it resolved as TRUE_POSITIVE (TP) or FALSE_POSITIVE (FP).

When the most-recent N consecutive attempts on a given scanner surface are
all FP, the surface is declared exhausted (default N=6, per R85 case study).

Source of truth for the attempt log:
  <workspace>/.auditooor/finding_attempts.json  (canonical)
  <workspace>/.auditooor/finding_attempts.jsonl  (alternate, one JSON obj/line)

Schema (per row):
  {
    "timestamp": "2026-04-18T12:00:00Z",
    "surface": "v2-exchange",          // logical scanner surface name
    "tool": "slither",                 // slither|halmos|mythril|manual|...
    "candidate_id": "R85-C",           // internal label
    "verdict": "FP",                   // TP | FP
    "reason_class": "keccak-preimage"  // optional
  }

----------------------------------------------------------------------
Workflow predicates (case_study frontmatter)
----------------------------------------------------------------------
Each case_study/*.md YAML frontmatter may carry:

  stop_criterion:      # when to stop hunting on this surface/class
  workflow_signature:  # pattern that signals this case study is applicable
  loop_back_phase:     # which loop phase to return to after a stop event

The checker loads all case studies from the case_study/ dir adjacent to
tools/, matches the workspace's primary class against applicable_workspace_classes,
then reports which stop_criterion predicates apply and whether they fire.

----------------------------------------------------------------------
Workpack-validator extension (soft gate)
----------------------------------------------------------------------
When --check-paste is passed with a paste-ready markdown path, the checker
verifies that for every case study whose class matches the workspace's
primary class, the paste body cites the case study slug (case_id). Exits
rc=1 if any required citation is missing (soft gate — orchestrator decides
whether to block or warn).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Minimal YAML front-matter parser (no PyYAML dep required)
# ---------------------------------------------------------------------------

def _parse_frontmatter(text: str) -> dict[str, Any]:
    """Extract YAML front-matter block from a markdown file.

    Returns parsed dict or {} if no front-matter found.
    Only handles scalar values, simple lists, and block scalars (>).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = None
    for i, ln in enumerate(lines[1:], 1):
        if ln.strip() == "---":
            end = i
            break
    if end is None:
        return {}

    fm_lines = lines[1:end]
    result: dict[str, Any] = {}
    current_key: str | None = None
    list_items: list[str] | None = None
    block_scalar_key: str | None = None
    block_scalar_lines: list[str] = []

    def _flush_block() -> None:
        nonlocal block_scalar_key, block_scalar_lines
        if block_scalar_key and block_scalar_lines:
            result[block_scalar_key] = " ".join(
                ln.strip() for ln in block_scalar_lines if ln.strip()
            )
        block_scalar_key = None
        block_scalar_lines = []

    def _flush_list() -> None:
        nonlocal list_items, current_key
        if list_items is not None and current_key:
            result[current_key] = list_items
        list_items = None

    for raw in fm_lines:
        # Block scalar continuation
        if block_scalar_key is not None:
            if raw.startswith("  ") or not raw.strip():
                block_scalar_lines.append(raw.strip())
                continue
            _flush_block()

        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item under current key
        if stripped.startswith("- ") and list_items is not None:
            list_items.append(stripped[2:].strip().strip('"\''))
            continue

        # Key: value
        if ":" in stripped:
            _flush_list()
            _flush_block()
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip("\"'")
            current_key = key
            if val == ">":
                block_scalar_key = key
                block_scalar_lines = []
            elif val == "":
                # Possibly a list follows
                list_items = []
            else:
                result[key] = val
                list_items = None

    _flush_list()
    _flush_block()
    return result


# ---------------------------------------------------------------------------
# Load finding-attempt log
# ---------------------------------------------------------------------------

def _load_attempts(workspace: Path) -> list[dict]:
    """Load finding attempts from .auditooor/finding_attempts.{json,jsonl}."""
    auditooor_dir = workspace / ".auditooor"
    attempts: list[dict] = []

    json_path = auditooor_dir / "finding_attempts.json"
    jsonl_path = auditooor_dir / "finding_attempts.jsonl"

    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                attempts = data
        except (json.JSONDecodeError, OSError):
            pass

    if jsonl_path.exists():
        try:
            for line in jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        attempts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass

    return attempts


# ---------------------------------------------------------------------------
# R85 consecutive-FP check
# ---------------------------------------------------------------------------

def _check_r85_consecutive_fp(
    attempts: list[dict],
    fp_window: int = 6,
) -> list[dict]:
    """Return list of surfaces where the last fp_window attempts are all FP.

    Each returned dict: {surface, consecutive_fps, tool, last_attempt_ts}.
    """
    # Group by (surface, tool) — tool optional; fall back to "any"
    from collections import defaultdict

    by_surface: dict[str, list[dict]] = defaultdict(list)
    for a in attempts:
        surface = a.get("surface", "unknown")
        by_surface[surface].append(a)

    triggered: list[dict] = []
    for surface, rows in by_surface.items():
        # Sort by timestamp (ISO-8601 strings sort lexicographically)
        rows_sorted = sorted(rows, key=lambda r: r.get("timestamp", ""))
        recent = rows_sorted[-fp_window:]
        if len(recent) < fp_window:
            continue
        if all(r.get("verdict", "").upper() == "FP" for r in recent):
            triggered.append(
                {
                    "surface": surface,
                    "consecutive_fps": fp_window,
                    "tool": recent[-1].get("tool", "unknown"),
                    "last_attempt_ts": recent[-1].get("timestamp", ""),
                    "stop_criterion": "r85-consecutive-fp",
                    "verdict": "STOP",
                    "message": (
                        f"Surface '{surface}': {fp_window} consecutive FPs — "
                        "scanner surface exhausted (R85). "
                        "Pivot to specification-level or composition attack angle."
                    ),
                }
            )
    return triggered


# ---------------------------------------------------------------------------
# Workspace primary class detection
# ---------------------------------------------------------------------------

def _detect_workspace_class(workspace: Path) -> str | None:
    """Infer workspace primary class from INTAKE_BASELINE.md or engage_report.md."""
    class_keywords = {
        "lending": ["lending", "borrow", "morpho", "aave", "compound"],
        "AMM": ["amm", "swap", "uniswap", "balancer", "curve", "pool"],
        "bridge": ["bridge", "withdraw", "optimism", "arbitrum", "cross-chain"],
        "prediction-market": ["prediction", "polymarket", "ctf", "outcome"],
        "vault": ["vault", "erc4626", "share", "deposit"],
        "consensus-cross-version": ["consensus", "litecoin", "mweb", "validator"],
        "DLT": ["dlt", "spark", "lightning", "bitcoin", "statechain"],
        "workflow-methodology": ["workflow", "auditooor", "methodology"],
        "oracle": ["oracle", "chainlink", "price feed", "scale_factor"],
    }

    for candidate in ["INTAKE_BASELINE.md", "engage_report.md", "SUBMISSIONS.md"]:
        f = workspace / candidate
        if f.exists():
            text = f.read_text(encoding="utf-8", errors="replace").lower()
            for cls, keywords in class_keywords.items():
                if any(kw in text for kw in keywords):
                    return cls
    return None


# ---------------------------------------------------------------------------
# Case-study workflow predicate loader
# ---------------------------------------------------------------------------

def _load_case_studies(case_study_dir: Path) -> list[dict[str, Any]]:
    """Load all *.md files from case_study_dir and return parsed frontmatter rows."""
    studies: list[dict[str, Any]] = []
    if not case_study_dir.is_dir():
        return studies
    for md in sorted(case_study_dir.glob("*.md")):
        try:
            fm = _parse_frontmatter(md.read_text(encoding="utf-8"))
        except OSError:
            continue
        if fm:
            fm["_source_file"] = md.name
            studies.append(fm)
    return studies


def _match_case_studies(
    studies: list[dict[str, Any]],
    workspace_class: str | None,
) -> list[dict[str, Any]]:
    """Return case studies applicable to workspace_class."""
    if workspace_class is None:
        return []
    matched = []
    for s in studies:
        applicable = s.get("applicable_workspace_classes", [])
        if not isinstance(applicable, list):
            applicable = [applicable]
        if workspace_class in applicable or "workflow-methodology" in applicable:
            matched.append(s)
    return matched


def _check_workflow_predicates(
    studies: list[dict[str, Any]],
    workspace: Path,
) -> list[dict]:
    """Check stop_criterion / workflow_signature predicates from matched case studies.

    Returns list of fired predicate dicts.
    """
    triggers: list[dict] = []
    for s in studies:
        sc = s.get("stop_criterion")
        ws = s.get("workflow_signature")
        lb = s.get("loop_back_phase")
        if not sc:
            continue
        # The stop_criterion field is informational — we report it as applicable
        # context without executing arbitrary shell commands. The verdict is
        # APPLICABLE (operator should review) rather than a hard STOP unless it
        # encodes the R85 consecutive-FP rule, which is checked separately.
        triggers.append(
            {
                "source": s.get("case_id", s.get("_source_file", "?")),
                "stop_criterion": sc,
                "workflow_signature": ws or "(none)",
                "loop_back_phase": lb or "(none)",
                "verdict": "APPLICABLE",
                "message": (
                    f"Case study '{s.get('case_id', '?')}' stop criterion applies: {sc}"
                ),
            }
        )
    return triggers


# ---------------------------------------------------------------------------
# Paste-ready citation check (workpack-validator extension)
# ---------------------------------------------------------------------------

def _check_paste_citations(
    paste_path: Path,
    matched_studies: list[dict[str, Any]],
) -> list[dict]:
    """Return list of case study slugs not cited in the paste-ready body."""
    if not paste_path.exists():
        return [
            {
                "source": str(paste_path),
                "verdict": "UNKNOWN",
                "message": f"Paste-ready file not found: {paste_path}",
            }
        ]
    body = paste_path.read_text(encoding="utf-8", errors="replace").lower()
    missing: list[dict] = []
    for s in matched_studies:
        slug = s.get("case_id", "")
        if not slug:
            continue
        if slug.lower() not in body:
            missing.append(
                {
                    "source": slug,
                    "verdict": "MISSING-CITATION",
                    "message": (
                        f"Paste-ready body does not cite case study '{slug}'. "
                        "Add a reference or explicit override."
                    ),
                }
            )
    return missing


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Workspace stop-criterion checker (R85 + workflow predicates)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--workspace", "-w",
        metavar="PATH",
        required=True,
        help="Path to the audit workspace (must contain .auditooor/ for attempt log)",
    )
    p.add_argument(
        "--fp-window",
        type=int,
        default=6,
        metavar="N",
        help="Consecutive-FP window for R85 check (default: 6)",
    )
    p.add_argument(
        "--case-study-dir",
        metavar="PATH",
        default=None,
        help=(
            "Path to case_study directory. Defaults to <tools_dir>/../case_study/ "
            "(auto-resolved relative to this script)."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit full JSON report on stdout instead of human-readable summary",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable detail; only print summary line",
    )
    p.add_argument(
        "--check-paste",
        metavar="PATH",
        default=None,
        help=(
            "Path to a paste-ready markdown. Checks that every applicable case study "
            "slug is cited in the body."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"[stop-criterion] ERROR workspace not found: {workspace}", file=sys.stderr)
        return 3

    # Resolve case_study dir
    if args.case_study_dir:
        cs_dir = Path(args.case_study_dir).expanduser().resolve()
    else:
        # Auto-resolve: this script lives in tools/; case_study is at ../case_study
        tools_dir = Path(__file__).resolve().parent
        cs_dir = tools_dir.parent / "case_study"

    # --- Load attempts ---
    attempts = _load_attempts(workspace)

    # --- R85 consecutive-FP check ---
    r85_triggers = _check_r85_consecutive_fp(attempts, fp_window=args.fp_window)

    # --- Load case studies ---
    all_studies = _load_case_studies(cs_dir)
    workspace_class = _detect_workspace_class(workspace)
    matched_studies = _match_case_studies(all_studies, workspace_class)
    wp_triggers = _check_workflow_predicates(matched_studies, workspace)

    # --- Paste citation check ---
    paste_triggers: list[dict] = []
    if args.check_paste:
        paste_triggers = _check_paste_citations(
            Path(args.check_paste).expanduser().resolve(),
            matched_studies,
        )

    all_triggers = r85_triggers + wp_triggers + paste_triggers

    # Determine overall verdict
    has_stop = any(t.get("verdict") == "STOP" for t in all_triggers)
    has_unknown = any(t.get("verdict") == "UNKNOWN" for t in all_triggers)
    has_missing = any(t.get("verdict") == "MISSING-CITATION" for t in all_triggers)

    if has_stop or has_missing:
        overall = "STOP"
        rc = 1
    elif has_unknown and not all_triggers:
        overall = "UNKNOWN"
        rc = 2
    else:
        overall = "CONTINUE"
        rc = 0

    summary = (
        f"[stop-criterion] verdict={overall}  "
        f"triggers={len([t for t in all_triggers if t.get('verdict') in ('STOP','MISSING-CITATION')])}  "
        f"checked={len(attempts)} attempts  "
        f"case_studies_matched={len(matched_studies)}  "
        f"workspace_class={workspace_class or 'unknown'}"
    )

    if args.json:
        report = {
            "verdict": overall,
            "workspace": str(workspace),
            "workspace_class": workspace_class,
            "fp_window": args.fp_window,
            "attempts_loaded": len(attempts),
            "case_studies_total": len(all_studies),
            "case_studies_matched": len(matched_studies),
            "triggers": all_triggers,
            "summary": summary,
        }
        print(json.dumps(report, indent=2))
        return rc

    # Human-readable output
    print(summary)
    if not args.quiet and all_triggers:
        print()
        for t in all_triggers:
            icon = {"STOP": "STOP", "APPLICABLE": "INFO", "UNKNOWN": "???", "MISSING-CITATION": "WARN"}.get(
                t.get("verdict", ""), "---"
            )
            print(f"  [{icon}] {t.get('message', '')}")
            if t.get("workflow_signature") and t["workflow_signature"] != "(none)":
                print(f"         workflow_signature: {t['workflow_signature']}")
            if t.get("loop_back_phase") and t["loop_back_phase"] != "(none)":
                print(f"         loop_back_phase: {t['loop_back_phase']}")
        print()

    return rc


if __name__ == "__main__":
    sys.exit(main())
