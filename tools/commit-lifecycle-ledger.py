#!/usr/bin/env python3
"""Build an offline lifecycle ledger for mined GitHub commits and refs."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.commit_lifecycle_ledger.v1"
DEFAULT_DATE = "2026-05-05"
LIFECYCLE_STATES = [
    "wanted_untriaged",
    "ready_full_sha_needs_mirror",
    "blocked_short_or_named_ref",
    "context_only_scope_anchor",
    "review_packet_emitted",
    "detectorized_or_covered",
    "harnessable",
    "self_learning_only",
    "stale_or_nonsensical",
    "closed_no_action",
]
ALLOWED_LANES = [
    "detectorization",
    "harness_or_invariant_proof",
    "source_review_only",
    "self_learning_or_no_action",
]
DEFAULT_PROOF_BOUNDARY = (
    "A lifecycle row is routing memory only; it does not prove exploitability, "
    "scanner coverage, detector promotion readiness, or submission readiness."
)
DEFAULT_REPORTS = {
    "github_plan": "reports/github_commit_mining_exploit_plan_2026-05-05.json",
    "local_corpus": "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
    "prior_artifacts": "reports/prior_commit_mining_artifacts_2026-05-05.json",
    "base_patch": "reports/base_audit_patch_commit_inventory_2026-05-05.json",
    "source_ref_plan": "reports/source_ref_replay_manifest_plan_2026-05-05.json",
}
LIST_KEYS = (
    "rows",
    "results",
    "items",
    "review_packets",
    "scan_tasks",
    "packets",
    "tasks",
    "candidates",
)
ROW_PRIORITY = {state: idx for idx, state in enumerate(LIFECYCLE_STATES)}


def _read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)


def _normalize_ref(value: str | None) -> str | None:
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    if 7 <= len(value) <= 40 and value.isalnum() and all(ch in "0123456789abcdefABCDEF" for ch in value):
        return value.lower()
    return value


def _full_sha(value: str | None) -> str | None:
    value = _normalize_ref(value)
    if value and len(value) == 40 and all(ch in "0123456789abcdef" for ch in value):
        return value
    return None


def _best_ref(row: dict[str, Any]) -> str | None:
    for key in (
        "sha",
        "commit",
        "resolved_commit",
        "ref",
        "local_ref",
        "tree_ref",
        "blob_url",
        "source_url",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            if key == "local_ref" and "@" in value:
                return value.split("@", 1)[1].strip()
            return value.strip()
    return None


def _repo_from_fields(row: dict[str, Any]) -> str | None:
    repo = row.get("repo")
    if isinstance(repo, str) and repo.strip():
        return repo.strip()
    owner = row.get("repo_owner") or row.get("owner")
    name = row.get("repo_name") or row.get("name")
    if isinstance(owner, str) and isinstance(name, str) and owner.strip() and name.strip():
        return f"{owner.strip()}/{name.strip()}"
    local_ref = row.get("local_ref")
    if isinstance(local_ref, str) and "@" in local_ref and "/" in local_ref.split("@", 1)[0]:
        return local_ref.split("@", 1)[0]
    return None


def _row_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        ROW_PRIORITY.get(row["lifecycle_state"], 999),
        str(row.get("target") or ""),
        str(row.get("repo") or ""),
        str(row.get("ref") or ""),
        str(row.get("row_id") or ""),
    )


def _count_by(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"name": key, "count": counts[key]} for key in sorted(counts)]


def _project_posture(local_corpus: dict[str, Any] | None) -> dict[str, str]:
    posture: dict[str, str] = {}
    project_context = (local_corpus or {}).get("project_context")
    if not isinstance(project_context, dict):
        return posture

    for section_name in ("operator_snapshot", "continuation_plan_posture"):
        section = project_context.get(section_name)
        if not isinstance(section, dict):
            continue
        for key, value in section.items():
            if key == "source" or value is None:
                continue
            posture[key.lower().replace("_", " ")] = str(value)
    return posture


def _lookup_posture(target: str | None, posture: dict[str, str]) -> str:
    if not target:
        return ""
    name = target.lower()
    for key, value in posture.items():
        if key in name or name in key:
            return value
    return ""


def _posture_requires_reopen(posture: str) -> bool:
    lowered = posture.lower()
    return any(token in lowered for token in ("done", "declined", "closed", "rejection", "terminal"))


def _memory_priority(state: str, operator_reopen_required: bool) -> str:
    if operator_reopen_required:
        return "low"
    if state in {"wanted_untriaged", "ready_full_sha_needs_mirror", "review_packet_emitted", "harnessable"}:
        return "high"
    if state == "blocked_short_or_named_ref":
        return "medium"
    return "low"


def _wanted_state(state: str) -> str:
    mapping = {
        "blocked_short_or_named_ref": "ready_full_sha_needs_mirror",
        "wanted_untriaged": "review_packet_emitted",
        "ready_full_sha_needs_mirror": "review_packet_emitted",
        "review_packet_emitted": "harnessable",
        "harnessable": "harnessable",
        "context_only_scope_anchor": "context_only_scope_anchor",
        "detectorized_or_covered": "detectorized_or_covered",
        "self_learning_only": "self_learning_only",
        "stale_or_nonsensical": "closed_no_action",
        "closed_no_action": "closed_no_action",
    }
    return mapping[state]


def _artifact_candidates(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            yield from _artifact_candidates(item)
        return
    if not isinstance(payload, dict):
        return
    has_signal = any(key in payload for key in ("repo", "repo_owner", "repo_name", "commit", "sha", "ref"))
    if has_signal:
        yield payload
    for key in LIST_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            for item in value:
                yield from _artifact_candidates(item)


def _artifact_refs(root: Path, pattern: str) -> dict[tuple[str | None, str | None], list[dict[str, Any]]]:
    index: dict[tuple[str | None, str | None], list[dict[str, Any]]] = {}
    for path in sorted(root.glob(pattern)):
        payload = _read_json(path)
        if payload is None:
            continue
        for row in _artifact_candidates(payload):
            repo = _repo_from_fields(row)
            for candidate in (
                row.get("commit"),
                row.get("commit_sha"),
                row.get("sha"),
                row.get("resolved_commit"),
                row.get("ref"),
                row.get("original_ref"),
            ):
                ref = _normalize_ref(candidate if isinstance(candidate, str) else None)
                if repo and ref:
                    index.setdefault((repo, ref), []).append(
                        {
                            "path": str(path),
                            "bucket": row.get("bucket") or row.get("review_bucket"),
                            "poc_investment_allowed": bool(row.get("poc_investment_allowed")),
                            "proof_followon_slots": row.get("proof_followon_slots"),
                            "submit_ready": row.get("submit_ready"),
                        }
                    )
    return index


def _evidence_paths(row: dict[str, Any], source_report: str) -> list[str]:
    paths: list[str] = []
    value = row.get("evidence_paths")
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item not in paths:
                paths.append(item)
    elif isinstance(value, str):
        paths.append(value)
    source_path = row.get("path") or row.get("source_path")
    if isinstance(source_path, str) and source_path not in paths:
        paths.append(source_path)
    if source_report not in paths:
        paths.append(source_report)
    return paths


def _source_report_path(repo_root: Path, report_name: str) -> str:
    return str(repo_root / DEFAULT_REPORTS[report_name])


def _base_row_state(
    row: dict[str, Any],
    posture: str,
    review_signals: list[dict[str, Any]],
    scan_signals: list[dict[str, Any]],
) -> tuple[str, str, str]:
    kind = str(row.get("kind") or "")
    status = str(row.get("status") or "")
    local_posture = str(row.get("local_posture") or "")
    inventory_action = str(row.get("inventory_action") or "")

    if kind in {"context_only_scope_anchor", "context_only_blob_anchor", "source_root_pin", "historical_engagement_pin"}:
        return (
            "context_only_scope_anchor",
            "source_review_only",
            inventory_action or "Keep this as context only; do not treat it as a patch-commit work item.",
        )
    if review_signals:
        harnessable = False
        for signal in review_signals:
            if signal.get("poc_investment_allowed"):
                harnessable = True
                break
            bucket = str(signal.get("bucket") or "")
            slots = signal.get("proof_followon_slots")
            if bucket == "high_signal_exploit_seed":
                harnessable = True
                break
            if isinstance(slots, list) and slots:
                harnessable = True
                break
        if harnessable:
            return (
                "harnessable",
                "harness_or_invariant_proof",
                "A replayable review packet exists and already points at proof follow-on work; stay advisory until separate local reproduction exists.",
            )
        return (
            "review_packet_emitted",
            "source_review_only",
            "Use the emitted review packet before any deeper proof work; do not treat the patch itself as proof.",
        )
    if "historical_claimed_fix_unresolved" in kind or "blocked_short" in status or "pr_only" in status:
        return (
            "blocked_short_or_named_ref",
            "self_learning_or_no_action" if posture else "source_review_only",
            inventory_action or "Resolve the short SHA or mutable ref locally before any replay or review lane use.",
        )
    if "self_learning_only" in status or "self-learning" in local_posture or "self_learning" in posture:
        return (
            "self_learning_only",
            "self_learning_or_no_action",
            inventory_action or "Keep this as a self-learning review lead only unless the operator explicitly reopens the target.",
        )
    if scan_signals:
        return (
            "wanted_untriaged",
            "source_review_only",
            "A local scan task exists; run the review lane and keep the row advisory until separate proof exists.",
        )
    return (
        "ready_full_sha_needs_mirror",
        "source_review_only",
        inventory_action or "Find or prove the local mirror/source bytes before creating review packets or proof work.",
    )


def _named_ref_state(row: dict[str, Any], posture: str) -> tuple[str, str, str]:
    classification = str(row.get("classification") or "")
    inventory_action = str(row.get("inventory_action") or "")
    if classification == "source_root_pin_not_commit_mining_output":
        return (
            "context_only_scope_anchor",
            "source_review_only",
            inventory_action or "Keep as source-root context, not as a patch-commit work item.",
        )
    if classification == "legacy_fixdiff_pattern_ref":
        return (
            "detectorized_or_covered",
            "detectorization",
            inventory_action or "Treat this as already covered by pattern memory unless a detector gap reopens the lane.",
        )
    if classification == "legacy_mined_report_fixed_commit_token":
        lane = "self_learning_or_no_action" if _posture_requires_reopen(posture) else "source_review_only"
        return (
            "blocked_short_or_named_ref",
            lane,
            inventory_action or "Resolve the short token to repo/full-SHA locally before any replay, and only spend that work if the lane is reopened.",
        )
    if classification in {
        "pdf_or_report_finding_ref_without_commit_sha",
        "pdf_text_extraction_ref_without_commit_sha",
    }:
        return (
            "stale_or_nonsensical",
            "self_learning_or_no_action",
            inventory_action or "Do not treat this as a commit row; keep it only as corpus-search context.",
        )
    return (
        "wanted_untriaged",
        "source_review_only",
        inventory_action or "This ref needs manual triage before it enters any downstream lane.",
    )


def _make_row(
    *,
    source_report: str,
    source_name: str,
    row: dict[str, Any],
    lifecycle_state: str,
    downstream_lane: str,
    next_action: str,
    posture: str,
    proof_boundary: str,
) -> dict[str, Any]:
    target = str(row.get("target") or "")
    repo = _repo_from_fields(row)
    ref = _normalize_ref(_best_ref(row))
    commit = _full_sha(str(row.get("sha") or row.get("commit") or row.get("resolved_commit") or ""))
    operator_reopen_required = _posture_requires_reopen(posture) and lifecycle_state not in {
        "context_only_scope_anchor",
        "detectorized_or_covered",
        "stale_or_nonsensical",
        "closed_no_action",
    }
    return {
        "row_id": row.get("row_id") or row.get("local_ref") or ref or target or source_name,
        "source_report": source_report,
        "source_name": source_name,
        "target": target,
        "repo": repo,
        "ref": ref,
        "commit": commit,
        "ref_type": _ref_type(ref, commit),
        "evidence_kind": str(row.get("kind") or row.get("classification") or ""),
        "current_state": str(row.get("status") or row.get("classification") or ""),
        "wanted_state": _wanted_state(lifecycle_state),
        "lifecycle_state": lifecycle_state,
        "downstream_lane": downstream_lane,
        "next_action": next_action,
        "proof_boundary": proof_boundary,
        "operator_posture": posture,
        "operator_reopen_required": operator_reopen_required,
        "memory_priority": _memory_priority(lifecycle_state, operator_reopen_required),
        "evidence_paths": _evidence_paths(row, source_report),
    }


def _ref_type(ref: str | None, commit: str | None) -> str:
    if commit:
        return "commit"
    if not ref:
        return "unknown"
    if ref.startswith("http://") or ref.startswith("https://"):
        return "url"
    if 7 <= len(ref) <= 39 and all(ch in "0123456789abcdef" for ch in ref):
        return "short_sha"
    if "/" in ref and "@" in ref:
        return "repo_ref"
    return "named_ref"


def _expand_report_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    if str(row.get("kind") or "") != "historical_claimed_fix_unresolved":
        return [row]
    examples = row.get("examples")
    if not isinstance(examples, list):
        return [row]

    expanded: list[dict[str, Any]] = []
    for example_index, example in enumerate(examples, start=1):
        if not isinstance(example, dict):
            continue
        path = example.get("path")
        refs = example.get("refs")
        if not isinstance(refs, list):
            continue
        for ref_index, ref in enumerate(refs, start=1):
            if not isinstance(ref, str) or not ref.strip():
                continue
            clone = dict(row)
            clone["row_id"] = f"{row.get('row_id', 'claim')}-{example_index:02d}-{ref_index:02d}"
            clone["ref"] = ref.strip()
            clone["evidence_paths"] = [path] if isinstance(path, str) else []
            expanded.append(clone)
    return expanded or [row]


def _build_base_rows(
    repo_root: Path,
    base_report: dict[str, Any] | None,
    posture_map: dict[str, str],
    review_index: dict[tuple[str | None, str | None], list[dict[str, Any]]],
    scan_index: dict[tuple[str | None, str | None], list[dict[str, Any]]],
    proof_boundary: str,
) -> list[dict[str, Any]]:
    if not isinstance(base_report, dict):
        return []
    source_report = _source_report_path(repo_root, "base_patch")
    rows: list[dict[str, Any]] = []
    for raw in base_report.get("evidence_rows", []):
        if not isinstance(raw, dict):
            continue
        for expanded in _expand_report_row(raw):
            repo = _repo_from_fields(expanded)
            ref = _normalize_ref(_best_ref(expanded))
            review_paths = review_index.get((repo, ref), []) if repo and ref else []
            scan_paths = scan_index.get((repo, ref), []) if repo and ref else []
            posture = _lookup_posture(str(expanded.get("target") or ""), posture_map)
            state, lane, action = _base_row_state(expanded, posture, review_paths, scan_paths)
            rows.append(
                _make_row(
                    source_report=source_report,
                    source_name="base_patch",
                    row=expanded,
                    lifecycle_state=state,
                    downstream_lane=lane,
                    next_action=action,
                    posture=posture,
                    proof_boundary=proof_boundary,
                )
            )
    return rows


def _build_prior_rows(
    repo_root: Path,
    prior_report: dict[str, Any] | None,
    posture_map: dict[str, str],
    proof_boundary: str,
) -> list[dict[str, Any]]:
    if not isinstance(prior_report, dict):
        return []
    source_report = _source_report_path(repo_root, "prior_artifacts")
    rows: list[dict[str, Any]] = []
    for raw in prior_report.get("named_target_refs", []):
        if not isinstance(raw, dict):
            continue
        posture = _lookup_posture(str(raw.get("target") or ""), posture_map)
        state, lane, action = _named_ref_state(raw, posture)
        rows.append(
            _make_row(
                source_report=source_report,
                source_name="prior_artifacts",
                row=raw,
                lifecycle_state=state,
                downstream_lane=lane,
                next_action=action,
                posture=posture,
                proof_boundary=proof_boundary,
            )
        )
    return rows


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("repo") or ""),
            str(row.get("ref") or ""),
            str(row.get("lifecycle_state") or ""),
            str(row.get("source_name") or ""),
        )
        if key not in seen:
            seen[key] = row
            continue
        current = seen[key]
        combined = list(current["evidence_paths"])
        for path in row["evidence_paths"]:
            if path not in combined:
                combined.append(path)
        current["evidence_paths"] = combined
    return sorted(seen.values(), key=_row_sort_key)


def _coverage_limits(
    repo_root: Path,
    local_corpus: dict[str, Any] | None,
    prior_report: dict[str, Any] | None,
    review_index: dict[tuple[str | None, str | None], list[str]],
) -> list[str]:
    limits: list[str] = []
    source_report = _source_report_path(repo_root, "local_corpus")
    if isinstance(local_corpus, dict):
        returned = local_corpus.get("returned_inventory_capability")
        if isinstance(returned, dict):
            for text in returned.get("still_missing", []):
                if isinstance(text, str):
                    limits.append(f"{source_report}: {text}")
    if isinstance(prior_report, dict):
        for text in prior_report.get("stale_or_unknown", []):
            if isinstance(text, str):
                limits.append(f"{_source_report_path(repo_root, 'prior_artifacts')}: {text}")
    if not review_index:
        limits.append("No contest_fix_mines/**/review_packets.json rows were available to upgrade any ref to review_packet_emitted.")
    return limits


def _queue_item(
    *,
    item_id: str,
    priority: str,
    lane: str,
    title: str,
    detail: str,
    evidence_paths: list[str],
    depends_on: list[str] | None = None,
    row_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "item_id": item_id,
        "priority": priority,
        "lane": lane,
        "title": title,
        "detail": detail,
        "depends_on": depends_on or [],
        "row_ids": row_ids or [],
        "evidence_paths": evidence_paths,
    }


def _build_queue(
    repo_root: Path,
    rows: list[dict[str, Any]],
    local_corpus: dict[str, Any] | None,
    github_plan: dict[str, Any] | None,
    prior_report: dict[str, Any] | None,
    source_ref_plan: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    queue: list[dict[str, Any]] = []

    if isinstance(local_corpus, dict):
        source_report = _source_report_path(repo_root, "local_corpus")
        queue.append(
            _queue_item(
                item_id="Q1-corpus-row-artifact",
                priority="high",
                lane="source_review_only",
                title="Materialize the missing per-ref corpus artifact",
                detail=(
                    "The current local-corpus status packet has counts and examples but no one-row-per-reference export. "
                    "Emit that artifact before claiming full commit-lifecycle coverage."
                ),
                evidence_paths=[source_report],
            )
        )
        next_packet = local_corpus.get("recommended_next_packet")
        if isinstance(next_packet, list) and len(next_packet) > 1 and isinstance(next_packet[1], str):
            queue.append(
                _queue_item(
                    item_id="Q2-resolve-high-signal-corpus-refs",
                    priority="high",
                    lane="source_review_only",
                    title="Resolve the highest-signal unresolved corpus refs first",
                    detail=next_packet[1],
                    depends_on=["Q1-corpus-row-artifact"],
                    evidence_paths=[source_report],
                )
            )
        if isinstance(next_packet, list) and len(next_packet) > 3 and isinstance(next_packet[3], str):
            queue.append(
                _queue_item(
                    item_id="Q3-mirror-proven-scan-tasks",
                    priority="medium",
                    lane="source_review_only",
                    title="Convert mirror-proven full-SHA rows into scan tasks",
                    detail=next_packet[3],
                    depends_on=["Q1-corpus-row-artifact", "Q2-resolve-high-signal-corpus-refs"],
                    evidence_paths=[source_report],
                )
            )

    blocked_rows = [
        row for row in rows if row["lifecycle_state"] == "blocked_short_or_named_ref"
    ]
    if blocked_rows:
        queue.append(
            _queue_item(
                item_id="Q4-blocked-ref-triage",
                priority="medium",
                lane="source_review_only",
                title="Triage blocked short or mutable refs without reopening closed targets by accident",
                detail=(
                    "Resolve only rows that still support source-review or detectorization value. "
                    "Rows on done or declined targets stay low-priority unless the operator explicitly reopens them."
                ),
                evidence_paths=sorted({path for row in blocked_rows for path in row["evidence_paths"]}),
                row_ids=[str(row["row_id"]) for row in blocked_rows],
            )
        )

    self_learning_rows = [
        row for row in rows if row["lifecycle_state"] == "self_learning_only"
    ]
    if self_learning_rows:
        queue.append(
            _queue_item(
                item_id="Q5-keep-self-learning-closed",
                priority="medium",
                lane="self_learning_or_no_action",
                title="Keep self-learning rows out of active exploit-hunting spend",
                detail=(
                    "Base patch commits remain review leads for replay, detector calibration, or harness design only "
                    "until separate local reproduction exists and the operator explicitly reopens the target."
                ),
                evidence_paths=sorted({path for row in self_learning_rows for path in row["evidence_paths"]}),
                row_ids=[str(row["row_id"]) for row in self_learning_rows],
            )
        )

    if isinstance(source_ref_plan, dict):
        next_steps = source_ref_plan.get("next_steps")
        if isinstance(next_steps, list) and next_steps:
            detail = next_steps[0].get("detail") if isinstance(next_steps[0], dict) else ""
            if isinstance(detail, str) and detail:
                queue.append(
                    _queue_item(
                        item_id="Q6-wire-source-ref-manifest",
                        priority="low",
                        lane="source_review_only",
                        title="Wire source-ref persistence into the commit-mining loop",
                        detail=detail,
                        evidence_paths=[_source_report_path(repo_root, "source_ref_plan")],
                    )
                )

    if isinstance(github_plan, dict):
        upgrade = github_plan.get("commit_lifecycle_ledger_upgrade")
        if isinstance(upgrade, dict):
            roadmap = upgrade.get("roadmap_integration")
            if isinstance(roadmap, list) and roadmap:
                queue.append(
                    _queue_item(
                        item_id="Q7-refresh-roadmap-from-ledger",
                        priority="low",
                        lane="self_learning_or_no_action",
                        title="Refresh the roadmap from lifecycle counts instead of prose memory",
                        detail=str(roadmap[0]),
                        evidence_paths=[_source_report_path(repo_root, "github_plan")],
                    )
                )

    if isinstance(prior_report, dict):
        recs = prior_report.get("local_corpus_inventory_recommendations")
        if isinstance(recs, list):
            for item in recs:
                if not isinstance(item, dict):
                    continue
                if item.get("lane") == "contest_fix_mining.v0":
                    blockers = item.get("required_unblockers")
                    if isinstance(blockers, list) and blockers:
                        queue.append(
                            _queue_item(
                                item_id="Q8-unblock-contest-fix-lane",
                                priority="low",
                                lane="source_review_only",
                                title="Keep contest-fix mining blocked until its prerequisites are real",
                                detail="Required unblockers: " + ", ".join(str(part) for part in blockers),
                                evidence_paths=[_source_report_path(repo_root, "prior_artifacts")],
                            )
                        )
                    break

    priority_order = {"high": 0, "medium": 1, "low": 2}
    queue.sort(key=lambda item: (priority_order[item["priority"]], item["item_id"]))
    return queue


def build_ledger(repo_root: Path) -> dict[str, Any]:
    reports = {
        name: _read_json(repo_root / relpath)
        for name, relpath in DEFAULT_REPORTS.items()
    }
    review_index = _artifact_refs(repo_root, "contest_fix_mines/**/review_packets.json")
    scan_index = _artifact_refs(repo_root, "contest_fix_mines/**/scan_tasks.json")
    posture_map = _project_posture(reports["local_corpus"])
    proof_boundary = DEFAULT_PROOF_BOUNDARY
    github_upgrade = (reports["github_plan"] or {}).get("commit_lifecycle_ledger_upgrade")
    if isinstance(github_upgrade, dict):
        text = github_upgrade.get("proof_boundary")
        if isinstance(text, str) and text.strip():
            proof_boundary = text.strip()

    rows = _dedupe_rows(
        _build_base_rows(
            repo_root,
            reports["base_patch"],
            posture_map,
            review_index,
            scan_index,
            proof_boundary,
        )
        + _build_prior_rows(repo_root, reports["prior_artifacts"], posture_map, proof_boundary)
    )
    queue = _build_queue(
        repo_root,
        rows,
        reports["local_corpus"],
        reports["github_plan"],
        reports["prior_artifacts"],
        reports["source_ref_plan"],
    )
    found_reports = [name for name, payload in reports.items() if payload is not None]
    missing_reports = [str(repo_root / relpath) for name, relpath in DEFAULT_REPORTS.items() if reports[name] is None]
    date = DEFAULT_DATE
    for payload in reports.values():
        if isinstance(payload, dict) and isinstance(payload.get("date"), str):
            date = payload["date"]
            break
    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    branch = next(
        (
            str(payload.get("branch"))
            for payload in reports.values()
            if isinstance(payload, dict) and payload.get("branch")
        ),
        "",
    )

    return {
        "schema": SCHEMA,
        "date": date,
        "generated_at_utc": generated_at,
        "repo_root": str(repo_root),
        "branch": branch,
        "network_used": False,
        "lifecycle_states": LIFECYCLE_STATES,
        "allowed_downstream_lanes": ALLOWED_LANES,
        "proof_boundary": proof_boundary,
        "reports_found": found_reports,
        "reports_missing": missing_reports,
        "summary": {
            "row_count": len(rows),
            "queue_count": len(queue),
            "state_counts": _count_by(rows, "lifecycle_state"),
            "lane_counts": _count_by(rows, "downstream_lane"),
            "memory_priority_counts": _count_by(rows, "memory_priority"),
        },
        "coverage_limits": _coverage_limits(
            repo_root,
            reports["local_corpus"],
            reports["prior_artifacts"],
            review_index,
        ),
        "rows": rows,
        "concrete_queue": queue,
    }


def render_markdown(ledger: dict[str, Any]) -> str:
    lines = [
        "# Commit Lifecycle Ledger",
        "",
        f"- Date: `{ledger['date']}`",
        f"- Schema: `{ledger['schema']}`",
        f"- Network used: `{str(ledger['network_used']).lower()}`",
        f"- Row count: `{ledger['summary']['row_count']}`",
        f"- Queue count: `{ledger['summary']['queue_count']}`",
        "",
        "## Lifecycle Counts",
        "",
        "| State | Count |",
        "| --- | ---: |",
    ]
    for item in ledger["summary"]["state_counts"]:
        lines.append(f"| `{item['name']}` | {item['count']} |")

    lines.extend(
        [
            "",
            "## Concrete Queue",
            "",
        ]
    )
    for item in ledger["concrete_queue"]:
        lines.append(f"### {item['item_id']} - {item['title']}")
        lines.append("")
        lines.append(f"- Priority: `{item['priority']}`")
        lines.append(f"- Lane: `{item['lane']}`")
        lines.append(f"- Detail: {item['detail']}")
        if item["depends_on"]:
            lines.append(f"- Depends on: {', '.join(f'`{part}`' for part in item['depends_on'])}")
        if item["row_ids"]:
            lines.append(f"- Rows: {', '.join(f'`{part}`' for part in item['row_ids'])}")
        lines.append("")

    lines.extend(
        [
            "## Rows",
            "",
            "| Row | Lifecycle | Repo | Ref | Lane | Reopen? | Next action |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in ledger["rows"]:
        repo = row["repo"] or "-"
        ref = row["ref"] or "-"
        lines.append(
            "| `{row_id}` | `{state}` | `{repo}` | `{ref}` | `{lane}` | `{reopen}` | {action} |".format(
                row_id=row["row_id"],
                state=row["lifecycle_state"],
                repo=repo,
                ref=ref,
                lane=row["downstream_lane"],
                reopen=str(row["operator_reopen_required"]).lower(),
                action=row["next_action"].replace("|", "\\|"),
            )
        )

    if ledger["coverage_limits"]:
        lines.extend(["", "## Coverage Limits", ""])
        for item in ledger["coverage_limits"]:
            lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "## Proof Boundary",
            "",
            ledger["proof_boundary"],
            "",
            "Patch commits remain review leads only until separate local reproduction exists.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json-out", type=Path, help="Write the JSON ledger to this path.")
    parser.add_argument("--md-out", type=Path, help="Write a Markdown summary to this path.")
    parser.add_argument("--stdout", action="store_true", help="Print the JSON ledger to stdout.")
    args = parser.parse_args(argv)

    ledger = build_ledger(args.repo_root.resolve())
    rendered = json.dumps(ledger, indent=2, sort_keys=False) + "\n"

    wrote_any = False
    if args.json_out:
        args.json_out.write_text(rendered, encoding="utf-8")
        wrote_any = True
    if args.md_out:
        args.md_out.write_text(render_markdown(ledger), encoding="utf-8")
        wrote_any = True
    if args.stdout or not wrote_any:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
