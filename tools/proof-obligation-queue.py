#!/usr/bin/env python3
"""Build a bounded proof-obligation queue from local hacker/action artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.proof_obligation_queue.v1"
QUESTION_RE = re.compile(r"\b(Q-[A-Za-z0-9._-]+)\b")
FILE_HINT_RE = re.compile(
    r"[A-Za-z0-9_<>./-]+\.(?:sol|rs|go|ts|js|py|move|cairo|vy)(?::\d+)?"
)
PROOF_COMPLETE_STATUSES = {
    "complete",
    "completed",
    "proof_complete",
    "proofed",
    "proved",
    "proved_impact_evidence",
}
BLOCKED_STATUSES = {
    "blocked",
    "failed",
    "missing_evidence",
    "needs_source",
    "stale",
}


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _uniq_str(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _coerce_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return _uniq_str([str(item) for item in value])
    text = str(value or "").strip()
    return [text] if text else []


def _normalized_status(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument(
        "--hacker-brief-json",
        action="append",
        default=[],
        help="Optional explicit hacker brief JSON sidecar path(s)",
    )
    parser.add_argument(
        "--hacker-brief-md",
        action="append",
        default=[],
        help="Optional explicit hacker brief markdown path(s)",
    )
    parser.add_argument(
        "--chained-plans",
        default=None,
        help="Optional chained attack plans JSON path (default: <workspace>/swarm/chained_attack_plans.json)",
    )
    parser.add_argument(
        "--detector-action-graph",
        "--action-graph-json",
        dest="detector_action_graph",
        action="append",
        default=[],
        help=(
            "Optional detector action graph JSON path(s); when omitted, "
            "a bridge summary is authoritative when present; otherwise the per-hit graph dir is consumed before the "
            "legacy <workspace>/.auditooor/detector_action_graph.json fallback"
        ),
    )
    parser.add_argument(
        "--multi-tx-manifest",
        action="append",
        default=[],
        help=(
            "Optional multi-tx sequence manifest path(s). Defaults to "
            "<workspace>/.auditooor/multi-tx-sequences/manifest.json"
        ),
    )
    parser.add_argument(
        "--no-default-detector-action-graph",
        action="store_true",
        help="Do not auto-consume any default detector action graph when no explicit graph is passed",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output path (default: <workspace>/.auditooor/proof_obligation_queue.json)",
    )
    parser.add_argument("--max-tasks", type=int, default=200, help="Bounded task limit")
    parser.add_argument(
        "--generated-at",
        default="",
        help="Optional generated_at_utc override for deterministic tests",
    )
    parser.add_argument("--print-json", action="store_true", help="Print resulting queue JSON")
    return parser.parse_args(argv)


def _default_hacker_json_paths(workspace: Path, explicit_paths: list[str]) -> list[Path]:
    if explicit_paths:
        return [Path(p).expanduser().resolve() for p in explicit_paths if str(p or "").strip()]
    candidate = workspace / ".auditooor" / "hacker_brief.md.json"
    return [candidate]


def _default_hacker_md_paths(workspace: Path, explicit_paths: list[str]) -> list[Path]:
    if explicit_paths:
        return [Path(p).expanduser().resolve() for p in explicit_paths if str(p or "").strip()]
    candidate = workspace / ".auditooor" / "hacker_brief.md"
    return [candidate]


def _default_multi_tx_manifest_paths(workspace: Path, explicit_paths: list[str]) -> list[Path]:
    if explicit_paths:
        return [Path(p).expanduser().resolve() for p in explicit_paths if str(p or "").strip()]
    candidate = workspace / ".auditooor" / "multi-tx-sequences" / "manifest.json"
    return [candidate]


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _workspace_scoped_path(workspace: Path, raw_path: Any) -> Path | None:
    raw = str(raw_path or "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    resolved = candidate.resolve()
    if not _is_under(resolved, workspace):
        return None
    return resolved


def _uniq_paths(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _bridge_summary_graph_paths(workspace: Path) -> tuple[list[Path], list[str], bool]:
    summary_path = workspace / ".auditooor" / "audit_hacker_logic_bridge.json"
    if not summary_path.exists():
        return [], [], False
    try:
        payload = _load_json(summary_path)
    except (OSError, json.JSONDecodeError):
        return [], ["audit_hacker_logic_bridge.json exists but could not be parsed"], False
    warnings: list[str] = []
    if not isinstance(payload, dict):
        return [], ["audit_hacker_logic_bridge.json is not a JSON object"], False
    if isinstance(payload, dict):
        engage_scoped = _workspace_scoped_path(workspace, payload.get("engage_report"))
        if engage_scoped is not None and engage_scoped.exists():
            try:
                if engage_scoped.stat().st_mtime > summary_path.stat().st_mtime:
                    return [], [
                        "audit_hacker_logic_bridge.json is older than engage_report; regenerate audit-hacker-logic-bridge before consuming detector action graphs"
                    ], True
            except OSError:
                warnings.append("could not compare audit_hacker_logic_bridge.json freshness against engage_report")
    graphs = payload.get("graphs")
    if not isinstance(graphs, list):
        return [], [*warnings, "audit_hacker_logic_bridge.json graphs field is not a list"], False
    paths: list[Path] = []
    for graph in graphs:
        if not isinstance(graph, dict):
            continue
        scoped = _workspace_scoped_path(workspace, graph.get("graph_path"))
        if scoped is not None:
            paths.append(scoped)
    return paths, warnings, True


def _default_engage_report_path(workspace: Path) -> Path | None:
    for name in ("engage_report.json", "engage_report.md"):
        candidate = workspace / name
        if candidate.exists():
            return candidate
    return None


def _is_older_than(path: Path, reference: Path) -> bool:
    try:
        return path.stat().st_mtime < reference.stat().st_mtime
    except OSError:
        return False


def _default_detector_action_graph_paths(workspace: Path, explicit_paths: list[str]) -> tuple[list[Path], list[str]]:
    if explicit_paths:
        return [Path(p).expanduser().resolve() for p in explicit_paths if str(p or "").strip()], []
    graph_dir = workspace / ".auditooor" / "detector_action_graphs"
    summary_paths, warnings, summary_found = _bridge_summary_graph_paths(workspace)
    if summary_found:
        return _uniq_paths(summary_paths), warnings
    engage_report = _default_engage_report_path(workspace)
    if graph_dir.is_dir():
        discovered = []
        skipped_stale = 0
        for path in sorted(graph_dir.glob("*.json")):
            if engage_report is not None and _is_older_than(path, engage_report):
                skipped_stale += 1
                continue
            discovered.append(path)
        if skipped_stale:
            warnings.append(
                f"skipped {skipped_stale} detector action graph sidecar(s) older than engage_report; regenerate audit-hacker-logic-bridge"
            )
        discovered = _uniq_paths(discovered)
        if discovered:
            return discovered, warnings
    candidate = workspace / ".auditooor" / "detector_action_graph.json"
    if candidate.exists() and engage_report is not None and _is_older_than(candidate, engage_report):
        warnings.append(
            "skipped legacy detector_action_graph.json because it is older than engage_report; regenerate audit-hacker-logic-bridge"
        )
        return [], warnings
    return ([candidate] if candidate.exists() else []), warnings


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-").lower() or "unknown"


def _sanitize_context_text(text: str, workspace: Path) -> str:
    value = str(text or "")
    if not value:
        return ""
    variants = {str(workspace), str(workspace.resolve())}
    for raw in list(variants):
        if raw.startswith("/private/"):
            variants.add(raw.removeprefix("/private"))
        elif raw.startswith(("/var/", "/tmp/")):
            variants.add(f"/private{raw}")
    for raw in sorted(variants, key=len, reverse=True):
        if raw:
            value = value.replace(raw, "<workspace>")
    value = re.sub(
        r"(?<![A-Za-z0-9_.-])/(?:Users|home|private|tmp|var)/[^\s`'\"),;]+",
        "<external-path>",
        value,
    )
    return value.strip()


def _file_hints_from_fires(fires: list[str]) -> list[str]:
    hints: list[str] = []
    for fire in fires:
        hints.extend(FILE_HINT_RE.findall(fire))
    return _uniq_str(hints)


def _source_ref_file_hints(source_refs: list[str]) -> list[str]:
    hints: list[str] = []
    for ref in source_refs:
        normalized = re.sub(r"^(workspace:|<workspace>/)", "", str(ref or "").strip())
        hints.extend(FILE_HINT_RE.findall(normalized))
    return _uniq_str(hints)


def _declared_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for key in ("blocker", "blockers", "blocked_reason", "blocked_reasons"):
        blockers.extend(_coerce_str_list(row.get(key)))
    return _uniq_str(blockers)


def _completion_claimed(row: dict[str, Any]) -> bool:
    explicit = row.get("proof_complete")
    if isinstance(explicit, bool):
        return explicit
    for key in ("proof_status", "proof_readiness", "completion_status", "status", "source_status"):
        if _normalized_status(row.get(key)) in PROOF_COMPLETE_STATUSES:
            return True
    return False


def _strip_line_suffix(ref: str) -> str:
    return re.sub(r":\d+(?::\d+)?$", "", ref)


def _workspace_ref_to_path(workspace: Path, ref: str) -> Path | None:
    text = str(ref or "").strip()
    if not text or text.startswith(("http://", "https://", "solodit:", "repo:")):
        return None
    if text.startswith("<workspace>/"):
        text = text.removeprefix("<workspace>/")
    elif text.startswith("workspace:"):
        text = text.removeprefix("workspace:")
    text = _strip_line_suffix(text.strip())
    if not text or text == "<workspace>" or text.startswith("<"):
        return None
    candidate = Path(text).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        resolved = candidate
    return resolved if _is_under(resolved, workspace) else None


def _proof_source_refs(item: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("source_refs", "source_paths", "file_hints"):
        refs.extend(_coerce_str_list(item.get(key)))
    return _uniq_str(refs)


def _proof_completion_blockers(item: dict[str, Any], workspace: Path) -> list[str]:
    blockers: list[str] = []
    if bool(item.get("advisory_only")):
        blockers.append("advisory_only")
    if bool(item.get("blocked")):
        blockers.append("blocked_obligation")
    if _normalized_status(item.get("source_status")) in BLOCKED_STATUSES:
        blockers.append("blocked_obligation")
    declared_blockers = _coerce_str_list(item.get("blocker"))
    declared_blockers.extend(_coerce_str_list(item.get("blockers")))
    if declared_blockers:
        blockers.append("blocked_obligation")

    proof_refs = _proof_source_refs(item)
    if not proof_refs:
        blockers.append("missing_source_refs")
        return _uniq_str(blockers)

    source_ref_path = _workspace_ref_to_path(workspace, str(item.get("source_ref") or ""))
    source_ref_mtime: float | None = None
    if source_ref_path is not None:
        try:
            source_ref_mtime = source_ref_path.stat().st_mtime
        except OSError:
            source_ref_mtime = None
    for ref in proof_refs:
        workspace_ref = _workspace_ref_to_path(workspace, ref)
        if workspace_ref is None:
            continue
        try:
            ref_mtime = workspace_ref.stat().st_mtime
        except OSError:
            blockers.append("stale_workspace_ref")
            continue
        if source_ref_mtime is not None and ref_mtime > source_ref_mtime:
            blockers.append("stale_workspace_ref")
    return _uniq_str(blockers)


def _apply_proof_completion(item: dict[str, Any], workspace: Path) -> None:
    claimed = _completion_claimed(item)
    blockers = _proof_completion_blockers(item, workspace)
    complete = claimed and not blockers
    item["proof_completion_claimed"] = claimed
    item["proof_complete"] = complete
    item["proof_completion_status"] = "proof_complete" if complete else "not_proof_complete"
    item["proof_completion_blockers"] = blockers


def _proof_completion_blocker_counts(tasks: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for task in tasks:
        for reason in _coerce_str_list(task.get("proof_completion_blockers")):
            counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


def _action_graph_obligation_key(item: dict[str, Any]) -> str:
    obligation = str(item.get("detector_action_graph_obligation") or "").strip()
    kind = str(item.get("obligation_kind") or "").strip()
    detector = str(item.get("detector") or "").strip()
    if obligation:
        return f"{detector}:{obligation}"
    if kind:
        return f"{detector}:{kind}"
    return ""


def _detector_fire_context(sections: dict[str, Any], workspace: Path) -> dict[str, dict[str, Any]]:
    sec5 = sections.get("sec5_engage_report_fires") if isinstance(sections, dict) else {}
    raw_items = sec5.get("items") if isinstance(sec5, dict) else []
    if not isinstance(raw_items, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        detector = str(item.get("detector") or "").strip()
        if not detector:
            continue
        raw_fires = item.get("fires") if isinstance(item.get("fires"), list) else []
        fires = _uniq_str([
            _sanitize_context_text(str(fire), workspace)
            for fire in raw_fires
            if str(fire or "").strip()
        ])[:5]
        out[_slug(detector)] = {
            "detector": detector,
            "detector_fires": fires,
            "file_hints": _file_hints_from_fires(fires),
            "context_note": "detector fire context only; not exploit proof",
        }
    return out


def _extract_questions_from_json(payload: dict[str, Any], workspace: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    sections = payload.get("sections") if isinstance(payload.get("sections"), dict) else {}
    sec13 = sections.get("sec13_question_list") if isinstance(sections, dict) else {}
    detector_context = _detector_fire_context(sections, workspace)
    items = []
    if isinstance(sec13, dict):
        raw_items = sec13.get("items") or sec13.get("questions") or []
        if isinstance(raw_items, list):
            items = raw_items
    for item in items:
        if not isinstance(item, dict):
            continue
        qid = str(item.get("id") or "").strip()
        if not qid.startswith("Q-"):
            continue
        row: dict[str, Any] = {
            "source_question": qid,
            "proof_needed": str(item.get("text") or "").strip()
            or f"Answer {qid} with concrete file:line and PoC evidence",
            "blocker": str(item.get("evidence") or "").strip() or "question is unanswered",
        }
        if qid.startswith("Q-DET-"):
            ctx = detector_context.get(qid.removeprefix("Q-DET-"))
            if ctx:
                row.update(ctx)
        out.append(row)
    if out:
        return out
    raw = json.dumps(sec13, sort_keys=True) if sec13 else json.dumps(payload, sort_keys=True)
    found = _uniq_str([match.group(1) for match in QUESTION_RE.finditer(raw)])
    for qid in found:
        out.append(
            {
                "source_question": qid,
                "proof_needed": f"Answer {qid} with concrete file:line and PoC evidence",
                "blocker": "question is unanswered",
            }
        )
    return out


def _extract_questions_from_markdown(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        match = QUESTION_RE.search(line)
        if not match:
            continue
        qid = match.group(1)
        proof = line.strip().lstrip("-* ").strip() or f"Answer {qid} with concrete file:line and PoC evidence"
        out.append(
            {
                "source_question": qid,
                "proof_needed": proof,
                "blocker": "question is unanswered",
            }
        )
    deduped: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in out:
        key = row["source_question"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _extract_chain_blocker_tasks(payload: dict[str, Any]) -> list[dict[str, str]]:
    tasks: list[dict[str, str]] = []
    plans = payload.get("plans")
    if not isinstance(plans, list):
        return tasks
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        chain_id = str(plan.get("chain_id") or "").strip()
        if not chain_id:
            continue
        blockers = [str(item).strip() for item in (plan.get("blockers") or []) if str(item).strip()]
        proof_steps = [str(item).strip() for item in (plan.get("proof_steps") or []) if str(item).strip()]
        proof_needed = "; ".join(proof_steps) if proof_steps else "Collect local PoC/proof artifact that resolves blocker"
        for blocker in blockers:
            tasks.append(
                {
                    "chain_id": chain_id,
                    "proof_needed": proof_needed,
                    "blocker": blocker,
                }
            )
    return tasks


def _extract_detector_action_graph_tasks(payload: dict[str, Any], workspace: Path) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    obligations = payload.get("proof_obligations")
    if not isinstance(obligations, list):
        return []
    detector_hit = payload.get("detector_hit") if isinstance(payload.get("detector_hit"), dict) else {}
    detector = str(detector_hit.get("detector_slug") or "").strip()
    hit_file = _sanitize_context_text(str(detector_hit.get("file_path") or ""), workspace)
    tasks: list[dict[str, Any]] = []
    for row in obligations:
        if not isinstance(row, dict):
            continue
        obligation_id = str(row.get("id") or "").strip()
        kind = str(row.get("kind") or "detector_action_graph").strip()
        title = str(row.get("title") or "").strip()
        required_evidence = [
            _sanitize_context_text(str(item), workspace)
            for item in (row.get("required_evidence") if isinstance(row.get("required_evidence"), list) else [])
            if str(item or "").strip()
        ][:8]
        source_refs = [
            _sanitize_context_text(str(ref), workspace)
            for ref in (row.get("source_refs") if isinstance(row.get("source_refs"), list) else [])
            if str(ref or "").strip()
        ][:8]
        source_status = _normalized_status(row.get("status")) or "open"
        advisory_only = bool(row.get("advisory_only", True))
        declared_blockers = _declared_blockers(row)
        file_hints = _source_ref_file_hints(source_refs)
        if hit_file:
            file_hints = _uniq_str([hit_file, *file_hints])
        proof_needed_parts = [title] if title else [f"Resolve detector action graph obligation {obligation_id or kind}"]
        if required_evidence:
            proof_needed_parts.append("Required evidence: " + "; ".join(required_evidence))
        blocker = (
            declared_blockers[0]
            if declared_blockers
            else ""
            if source_status in PROOF_COMPLETE_STATUSES
            else f"open detector action graph obligation `{kind}`"
        )
        tasks.append(
            {
                "source_question": None,
                "chain_id": None,
                "detector_action_graph_obligation": obligation_id or None,
                "obligation_kind": kind,
                "detector": detector,
                "proof_needed": " | ".join(proof_needed_parts),
                "blocker": blocker,
                "blockers": declared_blockers,
                "source_status": source_status,
                "advisory_only": advisory_only,
                "required_evidence": required_evidence,
                "source_refs": _uniq_str(source_refs),
                "file_hints": file_hints,
                "context_note": "detector action graph obligation only; not exploit proof",
            }
        )
    return tasks


def _extract_multi_tx_tasks(payload: dict[str, Any], workspace: Path) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    lifted = payload.get("lifted")
    if not isinstance(lifted, list):
        return []

    tasks: list[dict[str, Any]] = []
    for row in lifted:
        if not isinstance(row, dict):
            continue
        slug = str(row.get("slug") or "").strip()
        if not slug:
            continue
        attack_shape = str(row.get("attack_shape") or "multi_step_chain").strip()
        step_count = int(row.get("minimized_step_count") or 0)
        engine = str(row.get("engine") or "fuzzer").strip()
        violated = str(row.get("violated_invariant") or "engine_counterexample").strip()
        record_path = _sanitize_context_text(str(row.get("record_path") or ""), workspace)
        poc_path = _sanitize_context_text(str(row.get("poc_path") or ""), workspace)
        source_refs = _uniq_str([record_path, poc_path])
        replay_hint = (
            f"forge test --match-path {poc_path}"
            if poc_path
            else f"forge test --match-test test_multi_tx_attack  # {slug}"
        )
        required_evidence = _uniq_str(
            [
                "Execution manifest with final_result=proved and impact_assertion=exploit_impact",
                f"Replay command and run log ({replay_hint})",
                f"Invariant trace proving `{violated}` is violated on non-self impact path",
            ]
        )
        proof_needed = (
            f"Replay multi-tx candidate `{slug}` from {engine} "
            f"({attack_shape}, {step_count} step{'s' if step_count != 1 else ''}) and "
            "capture exploit-impact execution evidence."
        )
        tasks.append(
            {
                "source_question": None,
                "chain_id": None,
                "multi_tx_candidate": slug,
                "proof_needed": proof_needed,
                "blocker": "multi-tx lift is scaffolded_unverified until replay execution proves impact",
                "next_action": (
                    "Run the replay on local harness/fork, then write poc_execution/"
                    "execution_manifest.json for closeout verification."
                ),
                "required_evidence": required_evidence,
                "source_refs": source_refs,
                "file_hints": _source_ref_file_hints(source_refs),
                "context_note": "multi-tx candidate routing only; not exploit proof",
            }
        )
    return tasks


def _sanitize_source_ref(path: Path, workspace: Path) -> str:
    try:
        rel = path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return "<external-input>"
    return f"<workspace>/{rel}" if rel else "<workspace>"


def _stable_payload_hash(payload: dict[str, Any]) -> str:
    stable = dict(payload)
    stable["generated_at_utc"] = "<generated_at_utc>"
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def run(argv: list[str] | None = None) -> dict[str, Any]:
    args = _parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    out_path = (
        Path(args.out).expanduser().resolve()
        if args.out
        else workspace / ".auditooor" / "proof_obligation_queue.json"
    )
    chained_path = (
        Path(args.chained_plans).expanduser().resolve()
        if args.chained_plans
        else workspace / "swarm" / "chained_attack_plans.json"
    )

    tasks: list[dict[str, Any]] = []
    source_files: list[str] = []
    missing_sources: list[str] = []
    hacker_source_found = False
    chained_source_found = False
    detector_graph_source_found = False
    multi_tx_source_found = False
    explicit_detector_graph_missing = False
    stale_source_warnings: list[str] = []

    for path in _default_hacker_json_paths(workspace, args.hacker_brief_json):
        if not path.exists():
            missing_sources.append(_sanitize_source_ref(path, workspace))
            continue
        hacker_source_found = True
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        for row in _extract_questions_from_json(payload, workspace):
            task = {
                "source_question": row["source_question"],
                "chain_id": None,
                "proof_needed": row["proof_needed"],
                "blocker": row["blocker"],
                "advisory_only": True,
                "source_ref": _sanitize_source_ref(path, workspace),
            }
            for key in ("detector", "detector_fires", "file_hints", "context_note"):
                if row.get(key):
                    task[key] = row[key]
            tasks.append(task)
        source_files.append(_sanitize_source_ref(path, workspace))

    for path in _default_hacker_md_paths(workspace, args.hacker_brief_md):
        if not path.exists():
            missing_sources.append(_sanitize_source_ref(path, workspace))
            continue
        hacker_source_found = True
        text = path.read_text(encoding="utf-8")
        for row in _extract_questions_from_markdown(text):
            tasks.append(
                {
                    "source_question": row["source_question"],
                    "chain_id": None,
                    "proof_needed": row["proof_needed"],
                    "blocker": row["blocker"],
                    "advisory_only": True,
                    "source_ref": _sanitize_source_ref(path, workspace),
                }
            )
        source_files.append(_sanitize_source_ref(path, workspace))

    if not chained_path.exists():
        missing_sources.append(_sanitize_source_ref(chained_path, workspace))
    else:
        chained_source_found = True
        payload = _load_json(chained_path)
        if isinstance(payload, dict):
            for row in _extract_chain_blocker_tasks(payload):
                tasks.append(
                    {
                        "source_question": None,
                        "chain_id": row["chain_id"],
                        "proof_needed": row["proof_needed"],
                        "blocker": row["blocker"],
                        "advisory_only": True,
                        "source_ref": _sanitize_source_ref(chained_path, workspace),
                    }
                )
            source_files.append(_sanitize_source_ref(chained_path, workspace))

    if args.no_default_detector_action_graph and not args.detector_action_graph:
        detector_graph_paths = []
    else:
        detector_graph_paths, stale_source_warnings = _default_detector_action_graph_paths(
            workspace,
            args.detector_action_graph,
        )
    for path in detector_graph_paths:
        if not path.exists():
            missing_sources.append(_sanitize_source_ref(path, workspace))
            explicit_detector_graph_missing = bool(args.detector_action_graph)
            continue
        detector_graph_source_found = True
        payload = _load_json(path)
        if isinstance(payload, dict):
            for row in _extract_detector_action_graph_tasks(payload, workspace):
                task = {
                    **row,
                    "advisory_only": bool(row.get("advisory_only", True)),
                    "source_ref": _sanitize_source_ref(path, workspace),
                }
                tasks.append(task)
            source_files.append(_sanitize_source_ref(path, workspace))

    for path in _default_multi_tx_manifest_paths(workspace, args.multi_tx_manifest):
        if not path.exists():
            missing_sources.append(_sanitize_source_ref(path, workspace))
            continue
        multi_tx_source_found = True
        payload = _load_json(path)
        if isinstance(payload, dict):
            for row in _extract_multi_tx_tasks(payload, workspace):
                task = {
                    **row,
                    "advisory_only": True,
                    "source_ref": _sanitize_source_ref(path, workspace),
                }
                tasks.append(task)
            source_files.append(_sanitize_source_ref(path, workspace))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in tasks:
        action_graph_key = _action_graph_obligation_key(item)
        multi_tx_key = str(item.get("multi_tx_candidate") or "").strip()
        if action_graph_key:
            key = (
                "action_graph",
                action_graph_key,
                str(item.get("source_ref") or ""),
                str(item.get("proof_needed") or ""),
            )
        elif multi_tx_key:
            key = (
                "multi_tx",
                multi_tx_key,
                str(item.get("source_ref") or ""),
                str(item.get("proof_needed") or ""),
            )
        else:
            key = (
                str(item.get("source_question") or item.get("chain_id") or ""),
                "",
                str(item.get("proof_needed") or ""),
                str(item.get("blocker") or ""),
            )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    bounded = deduped[: max(0, int(args.max_tasks))]
    for idx, item in enumerate(bounded, start=1):
        item["task_id"] = f"POQ-{idx:03d}"
        _apply_proof_completion(item, workspace)
    blocked = len(bounded) == 0
    partial_source_loss = not blocked and (not hacker_source_found or not chained_source_found)
    if not blocked and explicit_detector_graph_missing:
        partial_source_loss = True
    if not blocked and stale_source_warnings:
        partial_source_loss = True
    status = (
        "blocked_missing_proof_sources"
        if blocked and not source_files
        else "blocked_empty_proof_sources"
        if blocked
        else "ready_degraded_missing_proof_sources"
        if partial_source_loss
        else "ready"
    )

    payload = {
        "schema": SCHEMA,
        "workspace": "<workspace>",
        "advisory_only": True,
        "status": status,
        "blocked": blocked,
        "degraded": blocked or partial_source_loss,
        "generated_at_utc": args.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "task_count": len(bounded),
            "question_tasks": sum(1 for row in bounded if row.get("source_question")),
            "chain_blocker_tasks": sum(1 for row in bounded if row.get("chain_id")),
            "detector_action_graph_tasks": sum(
                1 for row in bounded if row.get("detector_action_graph_obligation")
            ),
            "multi_tx_candidate_tasks": sum(1 for row in bounded if row.get("multi_tx_candidate")),
            "max_tasks": int(args.max_tasks),
            "detector_action_graph_source_found": detector_graph_source_found,
            "multi_tx_source_found": multi_tx_source_found,
            "proof_complete_tasks": sum(1 for row in bounded if row.get("proof_complete") is True),
            "not_proof_complete_tasks": sum(1 for row in bounded if row.get("proof_complete") is not True),
            "proof_completion_blocker_counts": _proof_completion_blocker_counts(bounded),
            "stale_source_warning_count": len(stale_source_warnings),
        },
        "sources": _uniq_str(source_files),
        "missing_sources": _uniq_str(missing_sources),
        "stale_source_warnings": _uniq_str(stale_source_warnings),
        "tasks": bounded,
    }
    digest = _stable_payload_hash(payload)
    payload["context_pack_hash"] = digest
    payload["context_pack_id"] = f"{SCHEMA}:proof_obligation_queue:{digest[:16]}"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return payload


def main() -> int:
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
