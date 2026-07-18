#!/usr/bin/env python3
"""Compile mined agent artifacts into terminal learning-ledger rows.

The compiler is intentionally conservative. It creates exactly one terminal row
per mined artifact, keeps all rows advisory/quarantined, and records proposition
scope so secondary artifacts cannot be reused as proof/severity/chain truth.

Lane K K3/K3a/K4 (HACKERMAN_V3 capability plan):

* K3 - primary-signal promotion rules. Only a *primary* signal (a command
  transcript + source refs + a proof status) can produce a ``proof_artifact``
  terminal row. A provider-only / worker-only artifact can only become a
  ``hacker_question``, ``triager_objection``, ``kill_reason``, ``workflow_gap``
  or ``NO_ACTION``. The compiler hard-clamps provider-only rows away from
  ``proof_artifact`` regardless of upstream classification and records a
  ``promotion_class`` field the gate verifies (escape_count must stay 0).
* K3a - proposition-scoped evidence. Every row carries ``proposition``,
  ``evidence_polarity`` and ``primary_for``.
* K4 - artifact-derived hacker improvements. Every promotable row declares a
  ``reuse_action`` from the K4 enum so the next hunt converts the artifact into
  reusable behaviour (a detector, kill rubric, pre-submit gate, etc).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.agent_learning_compiler.v1"
LEDGER_SCHEMA = "auditooor.agent_learning_ledger.v1"

DEFAULT_REPORT = "agent_artifact_mining_report.json"
DEFAULT_LEDGER = ".auditooor/agent_artifacts/learning_ledger.jsonl"

# K3 - only a primary signal may promote to proof_artifact.  A primary signal
# carries all three: a reproduced command transcript, source refs, and a proof
# status.  Anything else can SUGGEST but not PROMOTE.
PRIMARY_PROMOTABLE_KIND = "proof_artifact"

# K4 - canonical reuse_action enum.  A promoted artifact must convert into one
# of these reusable hunting behaviours (or `none`).
K4_REUSE_ACTIONS = {
    "add_detector",
    "add_kill_rubric",
    "add_pre_submit_gate",
    "add_originality_check",
    "add_provider_prompt_constraint",
    "add_harness_template",
    "add_hacker_question",
    "none",
}

# Terminal kinds a provider-only or worker-only row is allowed to reach.  K3:
# a non-primary row may SUGGEST a question / objection / kill / gap, never
# PROMOTE to proof or severity evidence.
NON_PRIMARY_ALLOWED_KINDS = {
    "hacker_question",
    "triager_objection",
    "kill_reason",
    "workflow_gap",
    "proof_obligation",
    "detector_hypothesis",
    "typed_lesson",
    "NO_ACTION",
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _artifact_id(artifact: dict[str, Any], index: int) -> str:
    for key in ("artifact_id", "id", "candidate_id", "source_ref"):
        value = str(artifact.get(key) or "").strip()
        if value:
            return value
    return f"missing-artifact-id-{index}"


def _text(artifact: dict[str, Any]) -> str:
    return " ".join(
        str(artifact.get(key) or "")
        for key in ("artifact_type", "title", "content", "verdict", "provenance_ref")
    ).lower()


def _is_primary_signal(artifact: dict[str, Any]) -> bool:
    """K3 - a row may PROMOTE to proof_artifact only if it is a primary signal.

    A primary signal carries all three of:
      * a reproduced command transcript (``command_transcript`` / ``transcript``
        / ``proof_transcript`` non-empty, OR ``source_has_local_proof`` True);
      * source refs (``source_refs`` / ``source_ref`` / ``provenance_ref``);
      * a proof status (``proof_status`` / ``verification`` result).

    A provider-only or worker-only artifact is never a primary signal, even if
    it claims a transcript - its transcript was not locally reproduced.
    """
    if artifact.get("provider_only") is True:
        return False
    if str(artifact.get("origin") or "").strip().lower() in {"provider", "worker_only"}:
        return False
    has_transcript = (
        artifact.get("source_has_local_proof") is True
        or any(
            str(artifact.get(key) or "").strip()
            for key in ("command_transcript", "transcript", "proof_transcript")
        )
    )
    has_source_refs = bool(
        artifact.get("source_refs")
        or str(artifact.get("source_ref") or "").strip()
        or str(artifact.get("provenance_ref") or "").strip()
    )
    has_proof_status = bool(
        str(artifact.get("proof_status") or "").strip()
        or str(artifact.get("verification_result") or "").strip()
        or isinstance(artifact.get("verification"), dict)
    )
    return has_transcript and has_source_refs and has_proof_status


def _terminal_kind(artifact: dict[str, Any]) -> str:
    artifact_type = str(artifact.get("artifact_type") or "").strip()
    hay = _text(artifact)
    if artifact.get("provider_only") is True:
        return "NO_ACTION"
    if artifact_type in {"candidate_hacker_question", "hacker_question"}:
        return "hacker_question"
    if artifact_type in {"candidate_detector_pattern", "detector_hypothesis"}:
        return "detector_hypothesis"
    if artifact_type in {"kill_rubric_entry", "rejection_pattern"}:
        return "kill_reason"
    if artifact_type in {"triager_pattern", "triager_objection"}:
        return "triager_objection"
    if artifact_type in {"roadmap_gap", "harness_template_request"}:
        return "workflow_gap"
    if artifact_type == "proof_artifact_mapping_candidate":
        # K3 hard-clamp: proof_artifact requires a primary signal.  A
        # source_has_local_proof flag alone is necessary but not sufficient -
        # the artifact must also carry a transcript + source refs + proof
        # status.  A provider-only proof claim cannot reach proof_artifact.
        if artifact.get("source_has_local_proof") is True and _is_primary_signal(artifact):
            return "proof_artifact"
        return "proof_obligation"
    if "blocked" in hay or "missing" in hay or "needs-source" in hay or "gap" in hay:
        return "workflow_gap"
    return "typed_lesson"


def _clamp_kind_for_promotion(kind: str, artifact: dict[str, Any]) -> tuple[str, str]:
    """K3 - enforce: only a primary signal may stay ``proof_artifact``.

    Returns ``(clamped_kind, promotion_class)`` where promotion_class is one of
    ``primary_promoted`` (a real proof artifact), ``suggest_only`` (the row may
    seed a question/objection/gap but cannot promote), or
    ``provider_only_demoted`` (a provider-only row was demoted away from a
    promotable kind).  The gate keys ``provider_only_promotion_escape_count``
    off this field.
    """
    provider_only = artifact.get("provider_only") is True
    if kind == PRIMARY_PROMOTABLE_KIND:
        if _is_primary_signal(artifact):
            return kind, "primary_promoted"
        # Non-primary row reached proof_artifact upstream - demote it.
        return ("NO_ACTION" if provider_only else "proof_obligation"), (
            "provider_only_demoted" if provider_only else "suggest_only"
        )
    if provider_only and kind not in NON_PRIMARY_ALLOWED_KINDS:
        return "NO_ACTION", "provider_only_demoted"
    return kind, "suggest_only"


def _terminal_outcome(kind: str, artifact: dict[str, Any]) -> str:
    if kind == "NO_ACTION":
        return "verified_no_action"
    if kind == "proof_artifact" and artifact.get("source_has_local_proof") is True:
        return "needs_human_primary_review"
    if kind in {"workflow_gap", "proof_obligation", "hacker_question"}:
        return "needs_human_primary_review"
    return "curated_lesson"


def _primary_for(kind: str, artifact: dict[str, Any]) -> str:
    hay = _text(artifact)
    if kind == "NO_ACTION":
        return "methodology"
    if "duplicate" in hay or "dupe" in hay:
        return "dupe"
    if "oos" in hay or "out-of-scope" in hay or "scope" in hay:
        return "OOS"
    if "economic" in hay or "bond" in hay or "profit" in hay or "net-negative" in hay:
        return "economics"
    if "severity" in hay or "critical" in hay or "high" in hay or "medium" in hay:
        return "severity_cap"
    if kind == "proof_artifact":
        return "proof"
    if kind in {"proof_obligation", "hacker_question", "workflow_gap"}:
        if "harness" in hay or "poc" in hay or "execution" in hay:
            return "harness_gap"
        return "source_reachability"
    if kind == "kill_reason":
        return "source_reachability"
    if kind == "triager_objection":
        return "team_position"
    return "methodology"


def _evidence_polarity(kind: str, artifact: dict[str, Any]) -> str:
    hay = _text(artifact)
    if kind == "NO_ACTION":
        return "context_only"
    if "negative" in hay or "kill" in hay or "rejected" in hay or "blocked" in hay:
        return "contradicts" if kind in {"kill_reason", "triager_objection"} else "limits"
    if kind in {"workflow_gap", "proof_obligation", "hacker_question"}:
        return "limits"
    if kind == "proof_artifact":
        return "supports"
    return "context_only"


def _reuse_action(kind: str, primary_for: str, artifact: dict[str, Any]) -> str:
    """K4 - canonical reuse_action: convert the artifact into reusable behaviour.

    Returns one of ``K4_REUSE_ACTIONS``.  The mapping follows the K4 plan:
    killed lanes -> add_kill_rubric; detector hypotheses -> add_detector;
    triager objections -> add_pre_submit_gate; dupe/OOS -> add_originality_check;
    provider/tooling defects -> add_provider_prompt_constraint; harness gaps ->
    add_harness_template; open questions -> add_hacker_question; NO_ACTION ->
    none.
    """
    if kind == "NO_ACTION":
        return "none"
    if artifact.get("provider_only") is True:
        # Provider/tooling defect or constraint - only a dispatch constraint.
        return "add_provider_prompt_constraint"
    if kind == "kill_reason":
        return "add_kill_rubric"
    if kind == "detector_hypothesis":
        return "add_detector"
    if kind == "triager_objection":
        return "add_pre_submit_gate"
    if kind == "workflow_gap":
        if primary_for == "harness_gap":
            return "add_harness_template"
        return "add_pre_submit_gate"
    if kind == "proof_artifact":
        # A real proof artifact seeds a positive exploit template / detector.
        return "add_detector"
    if kind in {"hacker_question", "proof_obligation"}:
        return "add_hacker_question"
    if primary_for in {"OOS", "dupe"}:
        return "add_originality_check"
    if primary_for in {"economics", "severity_cap", "team_position"}:
        return "add_pre_submit_gate"
    return "none"


def _no_action_reason(artifact: dict[str, Any]) -> str:
    if artifact.get("provider_only") is True:
        return "provider_only"
    return "no_new_information"


def _compile_artifact(artifact: dict[str, Any], index: int, *, workspace: Path, report: Path, ts: str) -> dict[str, Any]:
    artifact_id = _artifact_id(artifact, index)
    raw_kind = _terminal_kind(artifact)
    # K3 - hard-clamp: a non-primary / provider-only row cannot stay on a
    # promotable kind.  promotion_class records the clamp decision; the gate
    # asserts no provider-only row reaches proof_artifact.
    kind, promotion_class = _clamp_kind_for_promotion(raw_kind, artifact)
    primary_for = _primary_for(kind, artifact)
    is_primary = _is_primary_signal(artifact)
    row: dict[str, Any] = {
        "schema": LEDGER_SCHEMA,
        "ts": ts,
        "source": "agent-artifact-miner",
        "workspace": str(workspace),
        "source_report": str(report),
        "artifact_id": artifact_id,
        "terminal_kind": kind,
        "terminal_outcome": _terminal_outcome(kind, artifact),
        "proposition": str(artifact.get("title") or artifact.get("content") or artifact_id)[:240],
        "evidence_polarity": _evidence_polarity(kind, artifact),
        "primary_for": primary_for,
        "reuse_action": _reuse_action(kind, primary_for, artifact),
        # K3 promotion-rule fields.
        "promotion_class": promotion_class,
        "is_primary_signal": is_primary,
        "can_promote_to_proof": bool(kind == PRIMARY_PROMOTABLE_KIND and is_primary),
        "evidence_tier": "secondary",
        "quarantine": True,
        "provider_only": bool(artifact.get("provider_only") is True),
        "source_has_local_proof": bool(artifact.get("source_has_local_proof") is True),
        "source_artifact_type": artifact.get("artifact_type"),
        "source_verdict": artifact.get("verdict"),
        "source_verification_tier": artifact.get("verification_tier"),
        "provenance_ref": artifact.get("provenance_ref"),
        "promotion_authority": False,
        "submit_ready": False,
        "severity": "none",
        "selected_impact": "",
    }
    if kind == "NO_ACTION":
        row["reason"] = _no_action_reason(artifact)
    return row


def _row_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("source") or ""),
        str(row.get("artifact_id") or ""),
        str(row.get("terminal_kind") or ""),
    )


def _existing_keys(ledger: Path) -> set[tuple[str, str, str]]:
    keys: set[tuple[str, str, str]] = set()
    if not ledger.is_file():
        return keys
    for raw in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            keys.add(_row_key(row))
    return keys


def _review_attribution():
    """Lazy-load review_attribution (the reverse-evolution admission gate)."""
    try:
        import importlib.util as _il
        p = Path(__file__).resolve().parent / "review_attribution.py"
        spec = _il.spec_from_file_location("review_attribution", p)
        m = _il.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:
        return None


def _annotate_global_eligibility(rows: list, workspace: Path, *, record: bool) -> None:
    """Wire the anti-inflation admission gate into the learning loop: a compiled
    lesson is GLOBAL-ELIGIBLE (safe to lift to CLAUDE.md / a global rule) only
    when the SAME lesson subject repeats across >= 3 DISTINCT workspaces. Each
    lesson's subject is recorded to the cross-workspace attribution ledger (so
    the signal accumulates), then admit() decides eligibility. Default is
    hold-fix-locally - a freshly-mined lesson is LOCAL until it recurs. This is
    the direct defense against reverse evolution (one miss -> one global rule)."""
    ra = _review_attribution()
    if ra is None:
        for row in rows:
            row["global_eligible"] = False
            row["global_admission_verdict"] = "tooling-absent"
        return
    led = getattr(ra, "LEDGER", None)
    for row in rows:
        subject = f"lesson:{row.get('primary_for','')}:{row.get('terminal_kind','')}"
        klass = "reasoning"  # a mined learning artifact is a reasoning-loop lesson
        if record:
            try:
                ra.record(str(workspace), subject, klass,
                          note="agent-learning-compiler lesson", ledger=led)
            except Exception:
                pass
        try:
            verdict = ra.admit(subject, klass, threshold=3, ledger=led)
            row["global_eligible"] = verdict["verdict"].startswith("pass-")
            row["global_admission_verdict"] = verdict["verdict"]
            row["global_admission_workspaces"] = verdict["distinct_workspaces"]
        except Exception:
            row["global_eligible"] = False
            row["global_admission_verdict"] = "error"


def compile_learning(workspace: Path, report: Path, ledger: Path, *, check: bool = False) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    report = report.expanduser().resolve()
    ledger = ledger.expanduser().resolve()
    payload = _read_json(report)
    artifacts_raw = payload.get("artifacts") or []
    if not isinstance(artifacts_raw, list):
        raise ValueError("report artifacts field is not a list")
    artifacts = [artifact for artifact in artifacts_raw if isinstance(artifact, dict)]
    ts = _utc_now()
    rows = [_compile_artifact(artifact, idx, workspace=workspace, report=report, ts=ts) for idx, artifact in enumerate(artifacts)]
    _annotate_global_eligibility(rows, workspace, record=not check)
    existing = _existing_keys(ledger)
    appendable = [row for row in rows if _row_key(row) not in existing]
    if not check:
        ledger.parent.mkdir(parents=True, exist_ok=True)
        with ledger.open("a", encoding="utf-8") as fh:
            for row in appendable:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    by_terminal_kind: dict[str, int] = {}
    by_primary_for: dict[str, int] = {}
    by_promotion_class: dict[str, int] = {}
    by_reuse_action: dict[str, int] = {}
    for row in rows:
        by_terminal_kind[row["terminal_kind"]] = by_terminal_kind.get(row["terminal_kind"], 0) + 1
        by_primary_for[row["primary_for"]] = by_primary_for.get(row["primary_for"], 0) + 1
        by_promotion_class[row["promotion_class"]] = by_promotion_class.get(row["promotion_class"], 0) + 1
        by_reuse_action[row["reuse_action"]] = by_reuse_action.get(row["reuse_action"], 0) + 1
    # K3 acceptance - count provider-only rows that nonetheless reached a
    # promotable proof_artifact kind.  The clamp guarantees this is 0; the
    # field makes the invariant auditable from compiler output.
    provider_only_promotion_escape_count = sum(
        1
        for row in rows
        if row.get("provider_only") is True and row.get("terminal_kind") == PRIMARY_PROMOTABLE_KIND
    )
    return {
        "schema": SCHEMA,
        "generated_at_utc": ts,
        "workspace": str(workspace),
        "source_report": str(report),
        "learning_ledger_path": str(ledger),
        "check": check,
        "artifacts_seen": len(artifacts),
        "terminal_rows_compiled": len(rows),
        "rows_appended": 0 if check else len(appendable),
        "rows_would_append": len(appendable) if check else 0,
        "rows_skipped_existing": len(rows) - len(appendable),
        "by_terminal_kind": dict(sorted(by_terminal_kind.items())),
        "by_primary_for": dict(sorted(by_primary_for.items())),
        "by_promotion_class": dict(sorted(by_promotion_class.items())),
        "by_reuse_action": dict(sorted(by_reuse_action.items())),
        "provider_only_promotion_escape_count": provider_only_promotion_escape_count,
        "advisory_only": True,
        "promotion_authority": False,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--check", action="store_true", help="Do not write; report rows that would be appended.")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if args.report:
        report = args.report.expanduser().resolve()
    else:
        # The artifact-mining report canonically lives in <ws>/.auditooor/; fall
        # back to the workspace root for older layouts. Generic path-resolution.
        _cand = workspace / ".auditooor" / DEFAULT_REPORT
        report = _cand if _cand.is_file() else workspace / DEFAULT_REPORT
    ledger = args.ledger.expanduser().resolve() if args.ledger else workspace / DEFAULT_LEDGER
    payload = compile_learning(workspace, report, ledger, check=args.check)
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif not args.out_json:
        print(
            f"agent-learning-compiler: compiled={payload['terminal_rows_compiled']} "
            f"appended={payload['rows_appended']} would_append={payload['rows_would_append']} "
            f"ledger={payload['learning_ledger_path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
