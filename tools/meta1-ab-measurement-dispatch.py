#!/usr/bin/env python3
"""meta1-ab-measurement-dispatch.py - controlled A/B re-measurement harness
for META-1 (Section 15a/15b prebriefing wrapper) efficacy.

Background
----------

iter12 VVV measured "R42 fails 5 -> 15" but iter16 KKKKK proved that
measurement is unreliable for three reasons:

  1. The META-1 wrapper (tools/dispatch-agent-with-prebriefing.py) did
     not exist on disk during the iter12 measurement window.
  2. Cohort shift was severe (paste-ready rate 5.6% -> 75%).
  3. R42 itself became stricter mid-window (commit f6c86ac136 added
     field 5).

KKKKK proposed a matched-pair iter17 controlled re-measurement: each
trial dispatches the SAME lane spec twice - once with META-1
prebriefing invoked (cohort A) and once with raw prompt (cohort B).
Rule-version is pinned via a HEAD-SHA snapshot. The A/B harness
records both outputs and metadata to a JSONL log; a sibling analyzer
(``meta1-ab-measurement-analyze.py``) computes per-rule fail-rate
deltas with a binomial proportion confidence interval.

Status (2026-05-23 iter17)
--------------------------

PPPPP (the ``vault_dispatch_brief_skeleton`` MCP callable required for
cohort A to fire in REAL mode) has NOT landed at HEAD. This harness is
shipped in "ARMED BUT HOLSTERED" state. The dispatch path falls back
to "skeleton_unavailable" when PPPPP is absent, which would only
measure fallback-mode-vs-no-prebriefing (still meaningful as a sanity
check that the WRAPPER overhead alone does not cause regressions, but
NOT the headline A/B that KKKKK proposed).

The harness is opt-in: nothing fires until an operator (or sibling
lane) runs this tool against a real lane spec.

Usage
-----

Record a single dispatch (one half of a matched pair)::

    python3 tools/meta1-ab-measurement-dispatch.py \\
        --cohort A \\
        --trial-id trial-001 \\
        --lane-spec /path/to/lane-spec.md \\
        --lane-type hunt \\
        --severity HIGH \\
        --workspace /Users/wolf/audits/dydx \\
        --log .auditooor/meta1_ab_log.jsonl

Record a matched pair (both halves with seeded ordering)::

    python3 tools/meta1-ab-measurement-dispatch.py \\
        --matched-pair \\
        --trial-id trial-001 \\
        --lane-spec /path/to/lane-spec.md \\
        --lane-type hunt \\
        --severity HIGH \\
        --workspace /Users/wolf/audits/dydx \\
        --seed 42

The matched-pair mode randomizes which cohort runs first per --seed to
avoid first-mover bias.

Cohort A = META-1 invoked via ``tools/dispatch-agent-with-prebriefing.py``.
Cohort B = META-1 NOT invoked - raw prompt is emitted as-is.

The harness DOES NOT actually spawn a worker agent - it only records
the BRIEF that WOULD be dispatched. The dispatched brief is later
matched to the worker output (via brief-hash) by the analyzer when
the worker's draft lands. This separation means we can record the
A/B brief now and analyze the rule-fail-rates on the produced drafts
later, even across iter cycles.

Schema (one JSONL row per dispatch)
-----------------------------------

::

    {
      "schema": "auditooor.meta1_ab_dispatch_record.v1",
      "ts": "<ISO 8601 UTC>",
      "tool": "meta1-ab-measurement-dispatch.py",
      "tool_version": "0.1.0",
      "trial_id": "<operator-provided id, used to match A/B pair>",
      "cohort": "A" | "B",
      "lane_spec_path": "<abs path>",
      "lane_spec_sha256": "<64 hex chars>",
      "lane_type": "hunt" | "dispute" | "filing" | ...,
      "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "workspace_path": "<abs path>",
      "target_finding_class": "<optional>",
      "head_sha": "<git rev-parse HEAD>",
      "rules_pin_shas": {
        "R29": "<file sha256>",
        "R42": "<file sha256>",
        "R45": "<file sha256>",
        ...
      },
      "brief_chars": <int>,
      "brief_sha256": "<64 hex chars>",
      "meta1_invocation_status": "real" | "fallback" | "disabled",
      "skeleton_pack_id": "<from prebriefing wrapper>" | null,
      "skeleton_unavailable": true | false,
      "expected_draft_id": "<operator-provided slot for downstream analyzer>"
    }

Honest constraints
------------------

1. This tool records BRIEFS, not WORKER OUTPUTS. The analyzer matches
   briefs to drafts by lane-spec-hash + trial-id, and computes
   per-rule fail-rates on the produced drafts.

2. When PPPPP is unlanded, ``meta1_invocation_status`` is "fallback".
   The wrapper still emits a BEGIN/END block (warning the agent that
   skeleton was unavailable) - this is materially different from
   cohort B (no block at all). A "fallback vs no-block" measurement
   is a valid robustness check (does the WRAPPER ITSELF cause harm?)
   but is NOT the headline A/B that KKKKK proposed.

3. ``--matched-pair --seed N`` randomizes A-first vs B-first to avoid
   first-mover bias when an operator manually reads both briefs.

4. The recorded JSONL log lives under
   ``<workspace>/.auditooor/meta1_ab_log.jsonl`` by default; the path
   is overridable via ``--log``.

5. Tool emits NO corpus records; reporting-only. Rule 37 N/A.

6. NEVER modifies drafts. NEVER commits. L34 observed.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import random
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL_VERSION = "0.1.0"

PREBRIEFING_TOOL = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"

# Rule-tool files we pin SHAs for, to make rule-version-strictness
# changes between cohorts auditable. (Not exhaustive; the most-load-
# bearing R-rules per KKKKK's investigation.)
RULES_PIN_FILES = (
    ("R29", "tools/commitment-vs-validation-check.py"),
    ("R42", "tools/configured-impact-trace-check.py"),
    ("R43", "tools/load-bearing-bytes-attribution-check.py"),
    ("R45", "tools/designed-as-intended-precheck.py"),
    ("R46", "tools/trusted-infrastructure-compromise-check.py"),
    ("R52", "tools/rubric-row-coverage-check.py"),
)

VALID_COHORTS = ("A", "B")
VALID_LANE_TYPES = (
    "dispute",
    "mediation",
    "filing",
    "hunt",
    "opposed-trace-harness",
    "escalation",
)
VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_head_sha(repo_root: pathlib.Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def collect_rules_pin_shas(repo_root: pathlib.Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rid, rel in RULES_PIN_FILES:
        p = repo_root / rel
        if p.is_file():
            try:
                out[rid] = sha256_file(p)
            except OSError:
                out[rid] = "unreadable"
        else:
            out[rid] = "missing"
    return out


def utc_now_iso() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


# ---------------------------------------------------------------------------
# Brief generation
# ---------------------------------------------------------------------------

def generate_brief_cohort_a(
    lane_spec_text: str,
    *,
    lane_type: str,
    severity: str,
    workspace_path: Optional[pathlib.Path],
    target_finding_class: str = "",
    runner: Optional[Any] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Generate the cohort-A brief by invoking the META-1 prebriefing
    wrapper. Returns ``(brief_text, meta_dict)`` where ``meta_dict``
    has keys ``meta1_invocation_status`` (real | fallback | disabled),
    ``skeleton_pack_id``, and ``skeleton_unavailable``.

    ``runner`` is an injection seam for tests: a callable taking the
    argv list and returning a ``subprocess.CompletedProcess``-like
    object with ``returncode``, ``stdout``, ``stderr``. When None,
    we call subprocess.run on the real wrapper.
    """
    if not PREBRIEFING_TOOL.is_file():
        return (
            lane_spec_text,
            {
                "meta1_invocation_status": "disabled",
                "skeleton_pack_id": None,
                "skeleton_unavailable": True,
            },
        )

    argv = [
        sys.executable,
        str(PREBRIEFING_TOOL),
        "--prompt",
        lane_spec_text,
        "--lane-type",
        lane_type,
        "--severity",
        severity,
        "--no-infer",
        "--json-meta",
    ]
    if workspace_path is not None:
        argv.extend(["--workspace", str(workspace_path)])
    if target_finding_class:
        argv.extend(["--target-finding-class", target_finding_class])

    if runner is None:
        try:
            proc = subprocess.run(  # noqa: S603,S607
                argv,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return (
                lane_spec_text,
                {
                    "meta1_invocation_status": "disabled",
                    "skeleton_pack_id": None,
                    "skeleton_unavailable": True,
                    "error": "prebriefing timed out",
                },
            )
        except Exception as exc:  # noqa: BLE001
            return (
                lane_spec_text,
                {
                    "meta1_invocation_status": "disabled",
                    "skeleton_pack_id": None,
                    "skeleton_unavailable": True,
                    "error": f"prebriefing subprocess failed: {exc!r}",
                },
            )
    else:
        proc = runner(argv)

    brief_text = (proc.stdout or "").rstrip("\n") + "\n"
    if not brief_text.strip():
        brief_text = lane_spec_text

    meta_status = "real"
    skeleton_pack_id: Optional[str] = None
    skeleton_unavailable = False

    # The wrapper emits a JSON meta block on stderr (--json-meta).
    stderr_text = (proc.stderr or "").strip()
    json_line = None
    for line in reversed(stderr_text.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            json_line = line
            break
    if json_line is None:
        # Some Python versions or older wrapper builds put the JSON on
        # stdout - the wrapper currently emits both prompt + JSON to
        # stdout when --json-meta is passed; check both surfaces.
        for line in reversed(brief_text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                json_line = line
                break
    if json_line is not None:
        try:
            meta = json.loads(json_line)
            skeleton_pack_id = meta.get("skeleton_pack_id")
            skeleton_unavailable = bool(meta.get("skeleton_unavailable"))
            if skeleton_unavailable:
                meta_status = "fallback"
        except json.JSONDecodeError:
            pass
    if proc.returncode != 0:
        meta_status = "disabled"

    return brief_text, {
        "meta1_invocation_status": meta_status,
        "skeleton_pack_id": skeleton_pack_id,
        "skeleton_unavailable": skeleton_unavailable,
    }


def generate_brief_cohort_b(lane_spec_text: str) -> Tuple[str, Dict[str, Any]]:
    """Cohort B is the raw lane spec, no META-1 wrapper invocation.
    Returns ``(brief_text, meta_dict)`` for shape symmetry with cohort A.
    """
    return (
        lane_spec_text,
        {
            "meta1_invocation_status": "disabled",
            "skeleton_pack_id": None,
            "skeleton_unavailable": False,
        },
    )


# ---------------------------------------------------------------------------
# Record builder + log writer
# ---------------------------------------------------------------------------

def build_record(
    *,
    trial_id: str,
    cohort: str,
    lane_spec_path: pathlib.Path,
    lane_spec_text: str,
    lane_type: str,
    severity: str,
    workspace_path: pathlib.Path,
    target_finding_class: str,
    brief_text: str,
    brief_meta: Dict[str, Any],
    head_sha: str,
    rules_pin_shas: Dict[str, str],
    expected_draft_id: str,
) -> Dict[str, Any]:
    return {
        "schema": "auditooor.meta1_ab_dispatch_record.v1",
        "ts": utc_now_iso(),
        "tool": "meta1-ab-measurement-dispatch.py",
        "tool_version": TOOL_VERSION,
        "trial_id": trial_id,
        "cohort": cohort,
        "lane_spec_path": str(lane_spec_path),
        "lane_spec_sha256": sha256_text(lane_spec_text),
        "lane_type": lane_type,
        "severity": severity,
        "workspace_path": str(workspace_path),
        "target_finding_class": target_finding_class,
        "head_sha": head_sha,
        "rules_pin_shas": rules_pin_shas,
        "brief_chars": len(brief_text),
        "brief_sha256": sha256_text(brief_text),
        "meta1_invocation_status": brief_meta.get(
            "meta1_invocation_status", "unknown"
        ),
        "skeleton_pack_id": brief_meta.get("skeleton_pack_id"),
        "skeleton_unavailable": brief_meta.get("skeleton_unavailable", False),
        "expected_draft_id": expected_draft_id,
    }


def append_record(log_path: pathlib.Path, record: Dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Matched-pair runner
# ---------------------------------------------------------------------------

def run_single_cohort(
    cohort: str,
    *,
    trial_id: str,
    lane_spec_path: pathlib.Path,
    lane_spec_text: str,
    lane_type: str,
    severity: str,
    workspace_path: pathlib.Path,
    target_finding_class: str,
    expected_draft_id: str,
    head_sha: str,
    rules_pin_shas: Dict[str, str],
    runner: Optional[Any] = None,
) -> Dict[str, Any]:
    if cohort == "A":
        brief_text, brief_meta = generate_brief_cohort_a(
            lane_spec_text,
            lane_type=lane_type,
            severity=severity,
            workspace_path=workspace_path,
            target_finding_class=target_finding_class,
            runner=runner,
        )
    else:
        brief_text, brief_meta = generate_brief_cohort_b(lane_spec_text)
    return build_record(
        trial_id=trial_id,
        cohort=cohort,
        lane_spec_path=lane_spec_path,
        lane_spec_text=lane_spec_text,
        lane_type=lane_type,
        severity=severity,
        workspace_path=workspace_path,
        target_finding_class=target_finding_class,
        brief_text=brief_text,
        brief_meta=brief_meta,
        head_sha=head_sha,
        rules_pin_shas=rules_pin_shas,
        expected_draft_id=expected_draft_id,
    )


def run_matched_pair(
    *,
    trial_id: str,
    lane_spec_path: pathlib.Path,
    lane_spec_text: str,
    lane_type: str,
    severity: str,
    workspace_path: pathlib.Path,
    target_finding_class: str,
    expected_draft_id_a: str,
    expected_draft_id_b: str,
    head_sha: str,
    rules_pin_shas: Dict[str, str],
    seed: int,
    runner: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Run both cohorts for a single trial. ``seed`` controls the
    ordering (A-first vs B-first) deterministically per trial."""
    rng = random.Random(seed)
    order = ["A", "B"] if rng.random() < 0.5 else ["B", "A"]
    records: List[Dict[str, Any]] = []
    for cohort in order:
        draft_id = (
            expected_draft_id_a if cohort == "A" else expected_draft_id_b
        )
        records.append(
            run_single_cohort(
                cohort,
                trial_id=trial_id,
                lane_spec_path=lane_spec_path,
                lane_spec_text=lane_spec_text,
                lane_type=lane_type,
                severity=severity,
                workspace_path=workspace_path,
                target_finding_class=target_finding_class,
                expected_draft_id=draft_id,
                head_sha=head_sha,
                rules_pin_shas=rules_pin_shas,
                runner=runner,
            )
        )
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meta1-ab-measurement-dispatch.py",
        description=__doc__.splitlines()[0] if __doc__ else "",
    )
    p.add_argument(
        "--trial-id",
        required=True,
        help="Operator-chosen trial id (e.g. trial-001). Used to match A/B pair.",
    )
    p.add_argument(
        "--cohort",
        choices=VALID_COHORTS,
        default=None,
        help="Cohort A (META-1 invoked) or B (raw prompt). Omit when --matched-pair.",
    )
    p.add_argument(
        "--matched-pair",
        action="store_true",
        help="Run both cohorts for this trial; ordering randomized per --seed.",
    )
    p.add_argument(
        "--lane-spec",
        required=True,
        help="Path to the lane spec text file (UTF-8).",
    )
    p.add_argument(
        "--lane-type",
        choices=VALID_LANE_TYPES,
        required=True,
    )
    p.add_argument(
        "--severity",
        choices=VALID_SEVERITIES,
        required=True,
    )
    p.add_argument(
        "--workspace",
        required=True,
        help="Workspace absolute path (passed to META-1 wrapper + log root).",
    )
    p.add_argument(
        "--target-finding-class",
        default="",
        help="Optional finding-class hint for the skeleton filler.",
    )
    p.add_argument(
        "--expected-draft-id",
        default="",
        help="Slot for the downstream draft id (analyzer joins on this).",
    )
    p.add_argument(
        "--expected-draft-id-b",
        default="",
        help="Cohort B draft id when --matched-pair (defaults to --expected-draft-id + '-B').",
    )
    p.add_argument(
        "--log",
        default=None,
        help=(
            "JSONL log path. Default: <workspace>/.auditooor/meta1_ab_log.jsonl"
        ),
    )
    p.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Seed for --matched-pair ordering randomization.",
    )
    p.add_argument(
        "--print-brief",
        action="store_true",
        help="Print the generated brief text to stdout.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    lane_spec_path = pathlib.Path(args.lane_spec).expanduser().resolve()
    if not lane_spec_path.is_file():
        print(
            f"[meta1-ab-measurement-dispatch] ERROR: lane spec not found: "
            f"{lane_spec_path}",
            file=sys.stderr,
        )
        return 2
    lane_spec_text = lane_spec_path.read_text(encoding="utf-8")

    workspace_path = pathlib.Path(args.workspace).expanduser().resolve()
    if not workspace_path.is_dir():
        print(
            f"[meta1-ab-measurement-dispatch] WARN: workspace dir not found: "
            f"{workspace_path}; proceeding with the path as recorded value",
            file=sys.stderr,
        )

    if args.matched_pair and args.cohort:
        print(
            "[meta1-ab-measurement-dispatch] ERROR: cannot pass both "
            "--matched-pair and --cohort; pick one.",
            file=sys.stderr,
        )
        return 2
    if not args.matched_pair and not args.cohort:
        print(
            "[meta1-ab-measurement-dispatch] ERROR: must pass either "
            "--cohort A|B or --matched-pair.",
            file=sys.stderr,
        )
        return 2

    log_path = (
        pathlib.Path(args.log).expanduser().resolve()
        if args.log
        else workspace_path / ".auditooor" / "meta1_ab_log.jsonl"
    )

    head_sha = git_head_sha(REPO_ROOT)
    rules_pin_shas = collect_rules_pin_shas(REPO_ROOT)

    if args.matched_pair:
        draft_a = args.expected_draft_id or f"{args.trial_id}-A"
        draft_b = args.expected_draft_id_b or f"{args.trial_id}-B"
        records = run_matched_pair(
            trial_id=args.trial_id,
            lane_spec_path=lane_spec_path,
            lane_spec_text=lane_spec_text,
            lane_type=args.lane_type,
            severity=args.severity,
            workspace_path=workspace_path,
            target_finding_class=args.target_finding_class,
            expected_draft_id_a=draft_a,
            expected_draft_id_b=draft_b,
            head_sha=head_sha,
            rules_pin_shas=rules_pin_shas,
            seed=args.seed,
        )
    else:
        records = [
            run_single_cohort(
                args.cohort,
                trial_id=args.trial_id,
                lane_spec_path=lane_spec_path,
                lane_spec_text=lane_spec_text,
                lane_type=args.lane_type,
                severity=args.severity,
                workspace_path=workspace_path,
                target_finding_class=args.target_finding_class,
                expected_draft_id=args.expected_draft_id or args.trial_id,
                head_sha=head_sha,
                rules_pin_shas=rules_pin_shas,
            )
        ]

    for rec in records:
        append_record(log_path, rec)

    out = {
        "schema": "auditooor.meta1_ab_dispatch_response.v1",
        "log_path": str(log_path),
        "records_written": len(records),
        "trial_id": args.trial_id,
        "cohorts": [r["cohort"] for r in records],
        "head_sha": head_sha,
        "meta1_status_summary": [
            {
                "cohort": r["cohort"],
                "meta1_invocation_status": r["meta1_invocation_status"],
                "skeleton_unavailable": r["skeleton_unavailable"],
            }
            for r in records
        ],
    }
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
