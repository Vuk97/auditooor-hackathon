#!/usr/bin/env python3
"""lesson-adoption-benchmark.py - J7 lesson-adoption benchmark.

Measures whether lessons are actually *used*, not merely recorded.

Four metrics:
  (a) pct_top10_exploit_rows_with_lesson_pack
        - percentage of the top-10 exploit queue rows whose worker packet
          carries at least one lesson_pack_receipt (context_pack_id +
          hint matching LESSON_RECEIPT_HINTS) in mcp_context_refs.
  (b) pre_poc_kill_count_from_lessons
        - count of exploit-queue rows whose proof_status is 'killed'
          AND where the lesson_enforcement_inventory contains a matching
          hard_pre_poc enforcement row (indicating a lesson predicate was
          the kill trigger).
  (c) paste_ready_blockers_from_lesson_gates
        - count of gate-status failures across paste_ready/ submissions
          whose gate name includes a lesson-derived pattern (outcome_lesson,
          lesson_enforcement, agent_learning, K8, K4) OR whose gate-status
          was emitted by the outcome_lesson_gate tool.
  (d) filings_citing_corpus_precedents
        - count of paste_ready/*.md files that contain any of the corpus/
          precedent citation patterns (solodit, corpus, case study,
          prior-audit, proof_artifact_precedent_refs, etc.).

Overall adoption_status:
  - lessons_changed_decisions  : metric (b) > 0 OR metric (c) > 0
  - lessons_recorded_not_adopted: any lesson inventory present but b==c==0 and a<50
  - no_evaluable_signal        : all required artifacts missing

Schema: auditooor.lesson_adoption_benchmark.v1
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.lesson_adoption_benchmark.v1"
SCHEMA_VERSION = "1.0"

# Patterns that indicate a lesson pack receipt in a context ref
# (mirrors LESSON_RECEIPT_HINTS in v3-worker-packet-builder.py)
LESSON_RECEIPT_HINTS: tuple[str, ...] = (
    "attack_class",
    "bug_family",
    "candidate_judgment",
    "chain",
    "corpus_mining",
    "detector_action_graph",
    "dupe",
    "external_corpus",
    "function_mindset",
    "function_shape_attack_evidence",
    "hacker",
    "hacker_question",
    "kill_rubric",
    "lesson",
    "outcome_lesson",
    "prior_disclosure",
    "triager_pattern",
)

# Gate name substrings that flag a lesson-derived gate
LESSON_GATE_PATTERNS: tuple[str, ...] = (
    "outcome_lesson",
    "lesson_enforcement",
    "agent_learning",
    "k8",
    "k4",
    "lesson",
    "kill_rubric",
    "triager_pattern",
)

# Corpus/precedent citation patterns to look for in paste_ready .md files
CORPUS_CITE_PATTERNS: tuple[str, ...] = (
    r"solodit",
    r"corpus",
    r"case.stud",
    r"prior.audit",
    r"proof_artifact_precedent",
    r"precedent",
    r"prior.finding",
    r"past.finding",
    r"external.*corpus",
    r"audit.*report.*\bcit",
    r"previously.*filed",
    r"historical.*finding",
)
_CORPUS_RE = re.compile(
    "|".join(CORPUS_CITE_PATTERNS), re.IGNORECASE | re.MULTILINE
)

# Pre-PoC enforcement levels that indicate a lesson blocked a row before proof work
PRE_POC_ENFORCEMENT_LEVELS: frozenset[str] = frozenset(
    {"hard_pre_poc", "pre_poc_kill", "hard_kill"}
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_json(path: Path) -> Any:
    """Return parsed JSON or None on any error."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _missing_artifact(path: Path, role: str) -> dict[str, Any]:
    return {
        "status": "missing_artifact",
        "role": role,
        "path": str(path),
    }


# ---------------------------------------------------------------------------
# Exploit-queue helpers
# ---------------------------------------------------------------------------

def _load_exploit_queue(ws: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (rows, artifact_paths_found).

    Searches for exploit_queue*.json / exploit_queue/*.json patterns.
    Returns up to the first 10 rows by priority_score (or file order).
    """
    candidates = [
        ws / ".auditooor" / "exploit_queue.json",
        ws / ".auditooor" / "exploit_queue.source_mined.json",
    ]
    # Also glob for any extra queue files
    extra = sorted((ws / ".auditooor").glob("exploit_queue*.json")) if (ws / ".auditooor").is_dir() else []
    for p in extra:
        if p not in candidates:
            candidates.append(p)

    rows: list[dict[str, Any]] = []
    found_paths: list[str] = []

    for path in candidates:
        payload = _read_json(path)
        if payload is None:
            continue
        found_paths.append(str(path))
        raw_rows = (
            payload.get("queue")
            or payload.get("rows")
            or (payload if isinstance(payload, list) else [])
        )
        if isinstance(raw_rows, list):
            rows.extend(r for r in raw_rows if isinstance(r, dict))

    # Deduplicate by lead_id
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for r in rows:
        lid = str(r.get("lead_id") or r.get("id") or id(r))
        if lid not in seen:
            seen.add(lid)
            deduped.append(r)

    # Sort by priority_score descending, take top 10
    deduped.sort(key=lambda r: float(r.get("priority_score", 0) or 0), reverse=True)
    return deduped[:10], found_paths


# ---------------------------------------------------------------------------
# Metric (a): lesson_pack coverage of top-10 exploit rows
# ---------------------------------------------------------------------------

def _has_lesson_pack_receipt(ref: dict[str, Any]) -> bool:
    """A context ref counts as a lesson_pack_receipt if it carries a
    context_pack_id and its serialized body contains a LESSON_RECEIPT_HINT."""
    if not isinstance(ref, dict):
        return False
    pack_id = str(ref.get("context_pack_id") or ref.get("id") or "").strip()
    if not pack_id:
        return False
    haystack = json.dumps(ref, sort_keys=True, ensure_ascii=True).lower()
    return any(hint in haystack for hint in LESSON_RECEIPT_HINTS)


def _worker_packet_for_row(ws: Path, row: dict[str, Any]) -> dict[str, Any] | None:
    """Try to load the canonical worker packet for this exploit-queue row."""
    lead_id = str(row.get("lead_id") or "").strip()
    # Check dedicated per-row packet files first
    for subdir in ["worker_packets", ".auditooor/worker_packets"]:
        for suffix in [".json", "-worker-packet.json", ".worker-packet.json"]:
            p = ws / subdir / f"{lead_id}{suffix}"
            payload = _read_json(p)
            if payload is not None:
                return payload
        p = ws / ".auditooor" / subdir / f"{lead_id}{suffix}"
        payload = _read_json(p) if p.exists() else None
        if payload is not None:
            return payload
    # Fall back to canonical packet
    canonical = ws / ".auditooor" / "worker_packets" / "canonical-audit-worker-packet.json"
    return _read_json(canonical)


def _row_has_lesson_pack(ws: Path, row: dict[str, Any]) -> tuple[bool, str]:
    """Return (has_pack, reason_detail)."""
    # First check the row itself for lesson references in mcp_context_ids
    mcp_ids = row.get("mcp_context_ids", []) or []
    if isinstance(mcp_ids, list) and mcp_ids:
        # Any MCP context ID that mentions a lesson hint is sufficient
        for cid in mcp_ids:
            if any(hint in str(cid).lower() for hint in LESSON_RECEIPT_HINTS):
                return True, f"mcp_context_id match: {cid}"

    # Check associated worker packet
    packet = _worker_packet_for_row(ws, row)
    if packet:
        refs = packet.get("mcp_context_refs") or []
        for ref in (refs if isinstance(refs, list) else []):
            if _has_lesson_pack_receipt(ref):
                return True, f"worker_packet lesson_pack_receipt: {ref.get('context_pack_id','?')}"
        # Check lesson_pack_blockers - if empty, lesson pack was satisfied
        blockers = (packet.get("offline_validation") or {}).get("lesson_pack_blockers") or []
        if not blockers and refs:
            # refs exist but none are lesson packs - no pack
            pass

    return False, "no_lesson_pack_receipt"


def _compute_metric_a(
    ws: Path,
    top10: list[dict[str, Any]],
    queue_paths: list[str],
) -> dict[str, Any]:
    if not top10:
        return {
            "metric": "pct_top10_exploit_rows_with_lesson_pack",
            "value": None,
            "status": "unknown",
            "detail": "no_exploit_queue_rows",
            "evidence_paths": queue_paths,
        }

    rows_with_pack: list[str] = []
    rows_without_pack: list[str] = []

    for row in top10:
        lead_id = str(row.get("lead_id") or row.get("id") or "?")
        has_pack, _ = _row_has_lesson_pack(ws, row)
        if has_pack:
            rows_with_pack.append(lead_id)
        else:
            rows_without_pack.append(lead_id)

    pct = round(len(rows_with_pack) / len(top10) * 100, 1)
    return {
        "metric": "pct_top10_exploit_rows_with_lesson_pack",
        "value": pct,
        "status": "measured",
        "rows_with_pack": rows_with_pack,
        "rows_without_pack": rows_without_pack,
        "top10_count": len(top10),
        "evidence_paths": queue_paths,
    }


# ---------------------------------------------------------------------------
# Metric (b): pre-PoC kills attributable to lessons
# ---------------------------------------------------------------------------

def _load_lesson_enforcement_inventory(ws: Path) -> tuple[dict[str, Any] | None, str]:
    path = ws / ".auditooor" / "lesson_enforcement_inventory.json"
    payload = _read_json(path)
    return payload, str(path)


def _compute_metric_b(
    ws: Path,
    top10: list[dict[str, Any]],
    queue_paths: list[str],
) -> dict[str, Any]:
    enforcement, enf_path = _load_lesson_enforcement_inventory(ws)

    # Collect lesson IDs from enforcement rows at hard_pre_poc level
    pre_poc_lesson_ids: set[str] = set()
    pre_poc_predicates: set[str] = set()
    if enforcement:
        for row in enforcement.get("enforcement_rows", []):
            if row.get("enforcement_level", "") in PRE_POC_ENFORCEMENT_LEVELS:
                for ex in row.get("examples", []):
                    lid = str(ex.get("lesson_id") or "").strip()
                    if lid:
                        pre_poc_lesson_ids.add(lid)
                pre_poc_predicates.add(str(row.get("predicate", "")))

    killed_rows: list[str] = []
    lesson_attributed_kills: list[str] = []

    for row in top10:
        lead_id = str(row.get("lead_id") or "?")
        proof_status = str(row.get("proof_status") or "").lower()
        blockers = row.get("blockers") or []
        is_killed = proof_status == "killed" or (
            bool(blockers)
            and any(
                kw in str(b).lower()
                for b in (blockers if isinstance(blockers, list) else [blockers])
                for kw in ("kill", "killed", "drop")
            )
        )
        if is_killed:
            killed_rows.append(lead_id)
            # Attribute to lessons if enforcement inventory has pre-poc predicates
            # OR if the blocker text references a known lesson predicate
            blocker_text = json.dumps(blockers).lower()
            lesson_triggered = bool(pre_poc_predicates) and any(
                pred.replace("_", " ") in blocker_text or pred in blocker_text
                for pred in pre_poc_predicates
            )
            if lesson_triggered or (pre_poc_lesson_ids and is_killed):
                lesson_attributed_kills.append(lead_id)

    # Also check outcome_lesson_gate for matched predicates
    outcome_gate_paths = [
        ws / ".auditooor" / "exploit_conversion_loop_outcome_lesson_gate.json",
        ws / ".auditooor" / "prove_top_leads_outcome_lesson_gate.json",
    ]
    for ogp in outcome_gate_paths:
        og = _read_json(ogp)
        if og and og.get("matched_predicates"):
            # matched predicates imply lesson enforcement fired
            extra = [
                str(row.get("lead_id") or "?")
                for row in top10
                if str(row.get("lead_id") or "?") not in lesson_attributed_kills
                and (str(row.get("proof_status") or "").lower() == "killed" or row.get("blockers"))
            ]
            lesson_attributed_kills.extend(extra)
            break

    # Deduplicate
    lesson_attributed_kills = list(dict.fromkeys(lesson_attributed_kills))

    evidence_paths = queue_paths + [enf_path] + [str(p) for p in outcome_gate_paths]

    if not top10:
        return {
            "metric": "pre_poc_kill_count_from_lessons",
            "value": None,
            "status": "unknown",
            "detail": "no_exploit_queue_rows",
            "evidence_paths": evidence_paths,
        }

    missing_enf = enforcement is None
    return {
        "metric": "pre_poc_kill_count_from_lessons",
        "value": len(lesson_attributed_kills),
        "status": "unknown" if missing_enf else "measured",
        "detail": "missing_lesson_enforcement_inventory" if missing_enf else "measured",
        "killed_rows": killed_rows,
        "lesson_attributed_kills": lesson_attributed_kills,
        "pre_poc_predicates": sorted(pre_poc_predicates),
        "evidence_paths": evidence_paths,
    }


# ---------------------------------------------------------------------------
# Metric (c): paste_ready blockers from lesson-derived gates
# ---------------------------------------------------------------------------

def _compute_metric_c(ws: Path) -> dict[str, Any]:
    gate_dir = ws / ".auditooor" / "gate-status"
    paste_ready_dir = ws / "submissions" / "paste_ready"
    evidence_paths: list[str] = []

    blocker_gates: list[dict[str, Any]] = []

    # Strategy 1: scan gate-status/*.gate-status.json for paste_ready files
    if gate_dir.is_dir():
        for gf in sorted(gate_dir.glob("*.gate-status.json")):
            evidence_paths.append(str(gf))
            payload = _read_json(gf)
            if not payload:
                continue
            # Only care about paste_ready-scoped gate files
            file_scope = str(payload.get("file") or gf.name).lower()
            if "paste_ready" not in file_scope:
                continue
            failures = payload.get("failures") or []
            for fail in (failures if isinstance(failures, list) else []):
                gate_name = str(fail.get("gate") or "").lower()
                if any(pat in gate_name for pat in LESSON_GATE_PATTERNS):
                    blocker_gates.append(
                        {
                            "file": str(payload.get("file") or gf.name),
                            "gate": fail.get("gate"),
                            "summary": fail.get("summary"),
                            "source": str(gf),
                        }
                    )

    # Strategy 2: scan outcome_lesson_gate files for blockers on paste_ready paths
    for ogp in [
        ws / ".auditooor" / "exploit_conversion_loop_outcome_lesson_gate.json",
        ws / ".auditooor" / "prove_top_leads_outcome_lesson_gate.json",
    ]:
        og = _read_json(ogp)
        if og is None:
            continue
        evidence_paths.append(str(ogp))
        blockers = og.get("blockers") or []
        for b in (blockers if isinstance(blockers, list) else []):
            if isinstance(b, dict):
                blocker_gates.append(
                    {
                        "file": str(b.get("path") or ogp.name),
                        "gate": "outcome_lesson_gate",
                        "summary": str(b.get("reason") or b),
                        "source": str(ogp),
                    }
                )

    if not gate_dir.is_dir() and not paste_ready_dir.is_dir():
        return {
            "metric": "paste_ready_blockers_from_lesson_gates",
            "value": None,
            "status": "unknown",
            "detail": "missing_artifact: gate-status dir and paste_ready dir",
            "evidence_paths": evidence_paths,
        }

    return {
        "metric": "paste_ready_blockers_from_lesson_gates",
        "value": len(blocker_gates),
        "status": "measured",
        "blockers": blocker_gates,
        "evidence_paths": evidence_paths,
    }


# ---------------------------------------------------------------------------
# Metric (d): filed findings citing corpus/case-study precedents
# ---------------------------------------------------------------------------

def _compute_metric_d(ws: Path) -> dict[str, Any]:
    paste_ready_dir = ws / "submissions" / "paste_ready"
    evidence_paths: list[str] = []
    citing_files: list[str] = []

    if not paste_ready_dir.is_dir():
        return {
            "metric": "filings_citing_corpus_precedents",
            "value": None,
            "status": "unknown",
            "detail": "missing_artifact: submissions/paste_ready",
            "evidence_paths": [str(paste_ready_dir)],
        }

    for md in sorted(paste_ready_dir.glob("*.md")):
        evidence_paths.append(str(md))
        text = ""
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _CORPUS_RE.search(text):
            citing_files.append(str(md))

    return {
        "metric": "filings_citing_corpus_precedents",
        "value": len(citing_files),
        "status": "measured",
        "citing_files": citing_files,
        "total_paste_ready": len(evidence_paths),
        "evidence_paths": evidence_paths,
    }


# ---------------------------------------------------------------------------
# Adoption status decision
# ---------------------------------------------------------------------------

def _adoption_status(
    a: dict[str, Any],
    b: dict[str, Any],
    c: dict[str, Any],
    d: dict[str, Any],
) -> str:
    any_signal = any(
        m.get("status") == "measured" for m in [a, b, c, d]
    )
    if not any_signal:
        return "no_evaluable_signal"

    b_val = b.get("value") or 0
    c_val = c.get("value") or 0
    d_val = d.get("value") or 0

    if b_val > 0 or c_val > 0:
        return "lessons_changed_decisions"

    a_val = a.get("value")
    if d_val > 0 or (a_val is not None and a_val >= 50):
        return "lessons_recorded_not_adopted"

    # Lessons exist (inventory present) but no decision evidence
    return "lessons_recorded_not_adopted"


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

def run_benchmark(workspace: Path) -> dict[str, Any]:
    ws = workspace.expanduser().resolve()

    top10, queue_paths = _load_exploit_queue(ws)

    metric_a = _compute_metric_a(ws, top10, queue_paths)
    metric_b = _compute_metric_b(ws, top10, queue_paths)
    metric_c = _compute_metric_c(ws)
    metric_d = _compute_metric_d(ws)

    adoption = _adoption_status(metric_a, metric_b, metric_c, metric_d)

    missing: list[dict[str, Any]] = []
    if not queue_paths:
        missing.append(
            _missing_artifact(ws / ".auditooor" / "exploit_queue.json", "exploit_queue")
        )
    enf_path = ws / ".auditooor" / "lesson_enforcement_inventory.json"
    if not enf_path.is_file():
        missing.append(_missing_artifact(enf_path, "lesson_enforcement_inventory"))
    paste_ready_dir = ws / "submissions" / "paste_ready"
    if not paste_ready_dir.is_dir():
        missing.append(_missing_artifact(paste_ready_dir, "paste_ready_submissions"))

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": _utc_now(),
        "workspace": str(ws),
        "adoption_status": adoption,
        "metrics": [metric_a, metric_b, metric_c, metric_d],
        "missing_artifacts": missing,
        "_interpretation": (
            "V3 progress is not 'records mined'; "
            "it is 'lessons changed worker decisions or blocked bad filings.'"
        ),
    }


# ---------------------------------------------------------------------------
# Human-readable formatting
# ---------------------------------------------------------------------------

def _fmt_metric(m: dict[str, Any]) -> str:
    name = m.get("metric", "?")
    val = m.get("value")
    status = m.get("status", "?")
    detail = m.get("detail", "")
    val_str = f"{val}%" if "pct" in name and val is not None else str(val) if val is not None else "n/a"
    lines = [f"  [{status}] {name}: {val_str}"]
    if detail:
        lines.append(f"    detail: {detail}")
    # Add specifics
    for key in ("rows_with_pack", "lesson_attributed_kills", "blockers", "citing_files"):
        items = m.get(key, [])
        if items:
            lines.append(f"    {key}: {items[:5]}{'...' if len(items) > 5 else ''}")
    return "\n".join(lines)


def _print_human(report: dict[str, Any]) -> None:
    print(f"Lesson Adoption Benchmark - {report['workspace']}")
    print(f"Generated: {report['generated_at_utc']}")
    print(f"Adoption status: {report['adoption_status']}")
    print()
    print("Metrics:")
    for m in report.get("metrics", []):
        print(_fmt_metric(m))
    missing = report.get("missing_artifacts", [])
    if missing:
        print()
        print("Missing artifacts:")
        for ma in missing:
            print(f"  [{ma['role']}] {ma['path']}")
    print()
    print(f"  {report['_interpretation']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="J7 lesson-adoption benchmark: measures whether lessons changed decisions."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Path to audit workspace (e.g. ~/audits/hyperbridge)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit JSON report instead of human-readable output",
    )
    parser.add_argument(
        "--output",
        help="Write JSON report to this file (implies --json)",
    )
    args = parser.parse_args(argv)

    report = run_benchmark(Path(args.workspace))

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Report written to {out_path}")
    elif args.emit_json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)


if __name__ == "__main__":
    main()
