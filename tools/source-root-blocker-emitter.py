#!/usr/bin/env python3
"""Emit blocked source-root knowledge-gap rows from a local locator report.

Bounded v0: this tool is offline-only and does not resolve repositories,
commits, tags, source roots, or replay readiness.  Cluster-inferred candidates
are carried forward strictly as non-replay-ready unblock hints.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.source_root_blocker_kg.v0"
KG_SCHEMA = "auditooor.knowledge_gap_event.v1"
PLAN_SCHEMA = "auditooor.source_root_acquisition_plan.v0"
DEFAULT_OCCURRED_AT = "2026-05-05T00:00:00+00:00"

STATUS_BLOCKED_CLUSTER = "blocked_cluster_inferred_candidate_no_local_root"
STATUS_BLOCKED_UNRESOLVED = "blocked_unresolved_no_candidate"
STATUS_SKIPPED_EXACT_ROOT = "skipped_exact_local_source_root_present"

SOURCE_REPLAY_BOUNDARY = (
    "Source replay readiness is not claimed. Exact reviewed source root, "
    "commit/tag, local checkout, and file/line anchors remain required."
)

ACTIONABILITY_SCHEMA = "auditooor.source_root_acquisition_plan.v0"
PLAN_SCHEMA = ACTIONABILITY_SCHEMA
FINDING_PLAN_HINTS: dict[str, dict[str, Any]] = {
    "38333": {
        "anchor_hints": [
            "SmartVaultV4.sol",
            "SmartVaultYieldManager.sol",
            "SmartVaultV4",
            "SmartVaultYieldManager",
            "USDsStabilityCanCompromised",
        ],
        "metadata_grep": (
            r'rg -n "Solodit\ \#38333|solodit_id|38333|The\ Standard\ Smart\ Vault|USDs|'
            r'stability|compromised|collateral|deposited|Gamma" <exact-source-report-or-local-metadata>'
        ),
        "source_grep": (
            r'rg -n "SmartVaultV4\.sol|SmartVaultYieldManager\.sol|SmartVaultV4|'
            r'SmartVaultYieldManager|USDsStabilityCanCompromised" <solodit-38333-source-root>'
        ),
        "candidate_confirmation_required": True,
    },
    "36418": {
        "anchor_hints": [
            "gainsnetwork",
            "gains-network",
            "DecreasePositionSize",
            "IncreasePositionSize",
            "TradingCallbacks",
            "Trading*.sol",
            "Trading*Utils*.sol",
            "Position*Utils*.sol",
            "GNS*.sol",
            "DecreasingPositionSizeVia",
        ],
        "metadata_grep": (
            r'rg -n "Solodit\ \#36418|solodit_id|36418|GainsNetwork\ May|Decreasing|position|'
            r'size|leverage|update|abused" <exact-source-report-or-local-metadata>'
        ),
        "source_grep": (
            r'rg -n "gainsnetwork|gains\-network|DecreasePositionSize|IncreasePositionSize|'
            r'TradingCallbacks|Trading\*\.sol|Trading\*Utils\*\.sol|Position\*Utils\*\.sol|'
            r'GNS\*\.sol|DecreasingPositionSizeVia" <solodit-36418-source-root>'
        ),
        "candidate_confirmation_required": False,
    },
    "33463": {
        "anchor_hints": [
            "VaultManagerV2.sol",
            "VaultManagerV2",
            "MissingEnoughExogenousCollateral",
        ],
        "metadata_grep": (
            r'rg -n "Solodit\ \#33463|solodit_id|33463|DYAD|Missing|exogenous|collateral|check|'
            r'VaultManagerV2|liquidate" <exact-source-report-or-local-metadata>'
        ),
        "source_grep": (
            r'rg -n "VaultManagerV2\.sol|VaultManagerV2|MissingEnoughExogenousCollateral" '
            r'<solodit-33463-source-root>'
        ),
        "candidate_confirmation_required": True,
    },
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[source-root-blocker-emitter] ERR missing input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[source-root-blocker-emitter] ERR invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("[source-root-blocker-emitter] ERR input must be a JSON object")
    return payload


def _clean_text(value: Any) -> str:
    text = str(value or "").strip()
    return "".join(" " if ord(ch) < 32 else ch for ch in text)


def _clean_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = _clean_text(item)
        if text and text not in out:
            out.append(text)
    return out


def _rel(path: Path | str | None, repo_root: Path | None) -> str:
    if path is None:
        return ""
    value = Path(path)
    if repo_root is None:
        return value.as_posix()
    try:
        return value.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return value.as_posix()


def _date_compact(occurred_at: str) -> str:
    match = re.match(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T", occurred_at)
    if match:
        return "".join(match.groups())
    return "20260505"


def event_id_for(gap_id: str, event_type: str, occurred_at: str) -> str:
    stamp = occurred_at.replace("+00:00", "Z").replace(":", "").replace("-", "")
    stamp = re.sub(r"[^A-Za-z0-9TZ.]", "", stamp)
    return f"{gap_id}:{event_type}:{stamp}"


def _source_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("findings")
    if not isinstance(rows, list):
        raise ValueError("locator report must contain findings[]")
    return [row for row in rows if isinstance(row, dict)]


def _has_exact_source_root(row: dict[str, Any]) -> bool:
    if row.get("local_source_checkout_found") is not True:
        return False
    if not _clean_text(row.get("local_source_root")):
        return False
    confirmation = _clean_text(row.get("confirmation_level")).lower()
    status = _clean_text(row.get("source_root_status")).lower()
    return "cluster_inferred" not in confirmation and "cluster_inferred" not in status


def _has_candidate(row: dict[str, Any]) -> bool:
    return any(
        _clean_text(row.get(key))
        for key in ("candidate_repo", "candidate_commit", "candidate_tag", "candidate_source_root")
    )


def _list_from_evidence(row: dict[str, Any], key: str) -> list[str]:
    values: list[str] = []
    evidence = row.get("evidence")
    if not isinstance(evidence, list):
        return values
    for item in evidence:
        if not isinstance(item, dict):
            continue
        value = item.get(key)
        if isinstance(value, list):
            for nested in value:
                text = _clean_text(nested)
                if text and text not in values:
                    values.append(text)
        else:
            text = _clean_text(value)
            if text and text not in values:
                values.append(text)
    return values


def _evidence_paths(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    evidence = row.get("evidence")
    if not isinstance(evidence, list):
        return paths
    for item in evidence:
        if not isinstance(item, dict):
            continue
        for key in ("path", "paths", "source_file"):
            value = item.get(key)
            if isinstance(value, list):
                values = value
            else:
                values = [value]
            for nested in values:
                text = _clean_text(nested)
                if text and text not in paths:
                    paths.append(text)
    return paths


def _anchor_hints(row: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    for source_file in _list_from_evidence(row, "source_file"):
        name = Path(source_file).name
        if name and name not in hints:
            hints.append(name)
    evidence = row.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            searched = item.get("searched")
            if isinstance(searched, list):
                for pattern in searched:
                    text = _clean_text(pattern).strip("*")
                    if text and text not in hints:
                        hints.append(text)
    for blocker in _clean_list(row.get("blockers")):
        for match in re.findall(r"[A-Za-z0-9_./-]+\.sol\b", blocker):
            name = Path(match).name
            if name and name not in hints:
                hints.append(name)
        for match in re.findall(r"\b[A-Za-z][A-Za-z0-9_]*(?:Position|Trading|Vault|Manager|Utils)[A-Za-z0-9_]*\b", blocker):
            if match and match not in hints:
                hints.append(match)
    title_words = re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", _clean_text(row.get("title")))
    if title_words:
        compact_title = "".join(word[:1].upper() + word[1:] for word in title_words[:4])
        if compact_title and compact_title not in hints:
            hints.append(compact_title)
    return hints[:12]


def _finding_search_terms(row: dict[str, Any]) -> str:
    finding_id = _clean_text(row.get("finding_id")) or "unknown"
    project = _clean_text(row.get("project"))
    title_words = [
        token
        for token in re.findall(r"[A-Za-z0-9_]{4,}", _clean_text(row.get("title")))
        if token.lower() not in {"with", "from", "this", "that", "enough"}
    ][:6]
    terms = [f"Solodit #{finding_id}", "solodit_id", finding_id]
    if project:
        terms.append(project)
    terms.extend(title_words)
    deduped: list[str] = []
    for term in terms:
        if term and term not in deduped:
            deduped.append(term)
    return "|".join(re.escape(term) for term in deduped)


def blocker_status(row: dict[str, Any]) -> str:
    if _has_exact_source_root(row):
        return STATUS_SKIPPED_EXACT_ROOT
    if _has_candidate(row):
        return STATUS_BLOCKED_CLUSTER
    return STATUS_BLOCKED_UNRESOLVED


def candidate_payload(row: dict[str, Any]) -> dict[str, Any]:
    has_candidate = _has_candidate(row)
    return {
        "repo": row.get("candidate_repo"),
        "commit": row.get("candidate_commit"),
        "tag": row.get("candidate_tag"),
        "source_root": row.get("candidate_source_root"),
        "confirmation_level": row.get("confirmation_level"),
        "confidence": row.get("confidence"),
        "status": "cluster_inferred_non_replay_ready" if has_candidate else "no_candidate",
        "replay_ready": False,
    }


def acquisition_plan(
    row: dict[str, Any],
    *,
    searched_roots: list[str] | None = None,
    commands_run: list[str] | None = None,
) -> dict[str, Any]:
    finding_id = _clean_text(row.get("finding_id")) or "unknown"
    hints = FINDING_PLAN_HINTS.get(finding_id, {})
    candidate = candidate_payload(row)
    has_candidate = candidate["status"] != "no_candidate"
    source_root_token = f"<solodit-{finding_id}-source-root>"
    dynamic_hints = _anchor_hints(row)
    configured_hints = [str(item) for item in hints.get("anchor_hints") or []]
    anchor_hints = list(dict.fromkeys([*configured_hints, *dynamic_hints]))[:12]
    anchor_query = "|".join(re.escape(hint) for hint in anchor_hints) if anchor_hints else "<finding-specific-symbols>"
    local_verification_commands = [
        hints.get("metadata_grep")
        or f'rg -n "Solodit\\ \\#{finding_id}|solodit_id|{finding_id}" <exact-source-report-or-local-metadata>',
        f"make project-source-root-declaration WS=<workspace> ENTRY=solodit-{finding_id}={source_root_token} JSON=1",
        "make project-source-root-readiness WS=<workspace> JSON=1",
        hints.get("source_grep") or f'rg -n "{anchor_query}" {source_root_token}',
    ]
    searched_paths = _clean_list(searched_roots or [])
    evidence_paths = _evidence_paths(row)
    next_commands = list(local_verification_commands)
    confirmation_criteria = [
        "reviewed row source metadata matches the Solodit finding id",
    ]
    if has_candidate or hints.get("candidate_confirmation_required"):
        confirmation_criteria.append(
            "cluster-inferred candidate is confirmed against exact-row source metadata before any replay"
        )
    confirmation_criteria.extend(
        [
            "local checkout HEAD or tag matches the reviewed row commit/tag",
            "declared source root exists under the local checkout and contains vulnerable source files",
            "project-source-root-readiness passes for the workspace",
            "file/line anchor grep resolves inside the declared source root",
        ]
    )
    missing_criteria = [
        "exact reviewed source report or metadata for this Solodit row",
        "exact reviewed repo URL",
        "exact reviewed commit or tag",
        "local checkout path containing the vulnerable source tree",
        "declared project source root passing project-source-root-readiness",
        "file/line anchors for the vulnerable code path",
    ]
    if has_candidate:
        missing_criteria.insert(1, "exact-row confirmation that the candidate tuple is the reviewed source")
    return {
        "schema": PLAN_SCHEMA,
        "finding_id": finding_id,
        "state": "blocked_pending_exact_source_acquisition",
        "candidate_confirmation_required": has_candidate or bool(hints.get("candidate_confirmation_required")),
        "candidate_is_replay_ready": False,
        "anchor_hints": anchor_hints,
        "candidate_hints": {
            "candidate": candidate,
            "anchor_hints": anchor_hints,
            "local_evidence_paths": evidence_paths,
        },
        "searched_paths": searched_paths,
        "searched_artifact_paths": evidence_paths,
        "commands_already_run": _clean_list(commands_run or []),
        "missing_inputs": [
            "exact_reviewed_source_report_or_metadata_for_this_solodit_row",
            "exact_repo_url_from_the_reviewed_row",
            "exact_commit_or_tag_from_the_reviewed_row",
            "local_checkout_path_containing_the_vulnerable_source_tree",
            "declared_project_source_root_passing_project_source_root_readiness",
            "file_line_anchors_for_the_vulnerable_code_path",
        ],
        "missing_criteria": missing_criteria,
        "confirmation_criteria": confirmation_criteria,
        "local_verification_commands": local_verification_commands,
        "next_commands": next_commands,
        "fail_closed_until": [
            "all missing_inputs are supplied",
            "all confirmation_criteria are satisfied",
            "source replay and detector promotion commands are rerun against the declared root",
        ],
    }


def _candidate_evidence(row: dict[str, Any]) -> str:
    candidate = candidate_payload(row)
    if candidate["status"] == "no_candidate":
        return "No candidate repo, commit/tag, or source root was found in local evidence."
    parts = [
        f"candidate_repo={candidate['repo'] or 'null'}",
        f"candidate_commit={candidate['commit'] or 'null'}",
        f"candidate_tag={candidate['tag'] or 'null'}",
        f"candidate_source_root={candidate['source_root'] or 'null'}",
        f"confirmation_level={candidate['confirmation_level'] or 'unknown'}",
        f"confidence={candidate['confidence'] or 'unknown'}",
        "candidate_replay_ready=false",
    ]
    return "; ".join(parts)


def build_kg_row(
    row: dict[str, Any],
    *,
    input_ref: str,
    source_refs: list[str],
    occurred_at: str,
    searched_roots: list[str] | None = None,
    commands_run: list[str] | None = None,
) -> dict[str, Any]:
    finding_id = _clean_text(row.get("finding_id")) or "unknown"
    title = _clean_text(row.get("title")) or f"Solodit {finding_id}"
    project = _clean_text(row.get("project")) or "unknown project"
    compact_date = _date_compact(occurred_at)
    gap_id = f"KG-{compact_date}-SRC-{finding_id}"
    input_blockers = _clean_list(row.get("blockers"))
    if not input_blockers:
        input_blockers = ["Exact local source root is absent from the locator report."]
    plan = acquisition_plan(row, searched_roots=searched_roots, commands_run=commands_run)

    description = (
        f"Solodit #{finding_id} ({project}) has no exact local source root in the "
        "source-root locator. " + SOURCE_REPLAY_BOUNDARY
    )
    evidence = (
        f"{input_ref} reports source_root_status={row.get('source_root_status') or 'unknown'}, "
        f"local_source_checkout_found={row.get('local_source_checkout_found') is True}, "
        f"local_source_root={row.get('local_source_root') or 'null'}. "
        f"{_candidate_evidence(row)} Blockers: {' | '.join(input_blockers)}"
    )
    remediation = (
        "Acquire the exact reviewed repo URL and commit/tag for this finding, place "
        "the vulnerable target source under a declared local project source root, "
        "run project-source-root-readiness, and capture file/line anchors before "
        "any replay, detector design, or promotion claim. Follow the paired "
        "source_root_acquisition_plan for concrete missing inputs and local "
        "verification commands."
    )
    plan = acquisition_plan(row, searched_roots=searched_roots, commands_run=commands_run)

    return {
        "schema": KG_SCHEMA,
        "event_id": event_id_for(gap_id, "opened", occurred_at),
        "event_type": "opened",
        "gap_id": gap_id,
        "candidate_gap_id": f"G8-{gap_id}",
        "status": "open",
        "occurred_at": occurred_at,
        "actor": "codex",
        "area": "source",
        "gap_type": "missing_source_root",
        "severity": "high",
        "title": f"Missing exact source root for Solodit #{finding_id}",
        "question": f"Which exact reviewed source root unlocks Solodit #{finding_id}?",
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "blocked_by_artifacts": [input_ref],
        "downstream_blocked_tasks": ["KLBQ-002", f"Solodit:{finding_id}"],
        "source_paths": source_refs,
        "analyzer_target_paths": ["tools/source-root-blocker-emitter.py"],
        "yield_estimate": "high",
        "effort_estimate": "med",
        "heuristic_fp_risk": "A valid checkout may exist outside the local roots inspected by the locator.",
        "heuristic_fn_risk": "Other source-absent Solodit rows are out of scope for this bounded G1 locator input.",
        "resolution_summary": "",
        "resolution_evidence_paths": [],
        "terminal_artifact": "",
        "verification": {"commands": plan["local_verification_commands"], "passed": False},
        "reopen_reason": "",
    }


def build_blocker_row(
    row: dict[str, Any],
    *,
    input_ref: str,
    source_refs: list[str],
    occurred_at: str,
    searched_roots: list[str] | None = None,
    commands_run: list[str] | None = None,
) -> dict[str, Any] | None:
    status = blocker_status(row)
    if status == STATUS_SKIPPED_EXACT_ROOT:
        return None
    blockers = _clean_list(row.get("blockers"))
    kg_row = build_kg_row(
        row,
        input_ref=input_ref,
        source_refs=source_refs,
        occurred_at=occurred_at,
        searched_roots=searched_roots,
        commands_run=commands_run,
    )
    plan = acquisition_plan(row, searched_roots=searched_roots, commands_run=commands_run)
    return {
        "finding_id": _clean_text(row.get("finding_id")) or "unknown",
        "title": _clean_text(row.get("title")),
        "project": _clean_text(row.get("project")),
        "source_root_status": _clean_text(row.get("source_root_status")),
        "confirmation_level": _clean_text(row.get("confirmation_level")),
        "local_source_checkout_found": row.get("local_source_checkout_found") is True,
        "local_source_root": row.get("local_source_root"),
        "exact_source_root_present": False,
        "blocker_status": status,
        "source_replay_ready": False,
        "promotion_claim_allowed": False,
        "candidate": candidate_payload(row),
        "exact_blockers": blockers,
        "evidence": row.get("evidence") if isinstance(row.get("evidence"), list) else [],
        "source_root_acquisition_plan": plan,
        "kg_row": kg_row,
    }


def build_payload(
    report: dict[str, Any],
    *,
    input_path: Path | None = None,
    repo_root: Path | None = None,
    occurred_at: str = DEFAULT_OCCURRED_AT,
    extra_source_paths: list[Path] | None = None,
    extra_searched_paths: list[str] | None = None,
    extra_commands_run: list[str] | None = None,
) -> dict[str, Any]:
    input_ref = _rel(input_path, repo_root) if input_path is not None else "reports/g1_source_root_locator_2026-05-05.json"
    source_refs = [input_ref]
    for path in extra_source_paths or []:
        ref = _rel(path, repo_root)
        if ref and ref not in source_refs:
            source_refs.append(ref)

    searched_roots = _clean_list(_clean_list(report.get("searched_roots")) + _clean_list(extra_searched_paths or []))
    commands_run = _clean_list(_clean_list(report.get("commands_run")) + _clean_list(extra_commands_run or []))
    rows: list[dict[str, Any]] = []
    skipped = 0
    for source_row in _source_rows(report):
        emitted = build_blocker_row(
            source_row,
            input_ref=input_ref,
            source_refs=source_refs,
            occurred_at=occurred_at,
            searched_roots=searched_roots,
            commands_run=commands_run,
        )
        if emitted is None:
            skipped += 1
        else:
            rows.append(emitted)

    rows.sort(key=lambda item: item["finding_id"])
    status_counts: dict[str, int] = {}
    for row in rows:
        status = row["blocker_status"]
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "schema": SCHEMA,
        "input_schema": report.get("schema"),
        "packet_id": report.get("packet_id"),
        "offline": True,
        "network_used": False,
        "llm_dispatch_ran": False,
        "source_replay_performed": False,
        "source_replay_ready_count": 0,
        "promotion_claim_allowed": False,
        "proof_boundary": SOURCE_REPLAY_BOUNDARY,
        "searched_paths": searched_roots,
        "commands_already_run": commands_run,
        "input_finding_count": len(_source_rows(report)),
        "skipped_exact_source_root_count": skipped,
        "row_count": len(rows),
        "summary": {
            "status_counts": dict(sorted(status_counts.items())),
            "cluster_inferred_candidate_count": status_counts.get(STATUS_BLOCKED_CLUSTER, 0),
            "unresolved_no_candidate_count": status_counts.get(STATUS_BLOCKED_UNRESOLVED, 0),
        },
        "rows": rows,
        "kg_rows": [row["kg_row"] for row in rows],
    }


def write_output(path: Path, payload: dict[str, Any], *, jsonl: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if jsonl:
        text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in payload["kg_rows"])
    else:
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit blocked source-root KG rows from a local G1 source-root locator report."
    )
    parser.add_argument("--input", required=True, type=Path, help="g1_source_root_locator-style JSON input.")
    parser.add_argument("--out", required=True, type=Path, help="Output JSON or JSONL path.")
    parser.add_argument("--jsonl", action="store_true", help="Write only canonical knowledge_gap_event rows as JSONL.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--occurred-at", default=DEFAULT_OCCURRED_AT, help="Deterministic ISO-8601 timestamp for opened KG events.")
    parser.add_argument(
        "--source-path",
        action="append",
        type=Path,
        default=[],
        help="Additional local source/report path to include in KG source_paths.",
    )
    parser.add_argument(
        "--searched-path",
        action="append",
        default=[],
        help="Additional local root/path searched while building the acquisition packet.",
    )
    parser.add_argument(
        "--command-run",
        action="append",
        default=[],
        help="Additional local-only command already run while building the acquisition packet.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = load_json(args.input)
    payload = build_payload(
        report,
        input_path=args.input,
        repo_root=args.repo_root,
        occurred_at=args.occurred_at,
        extra_source_paths=args.source_path,
        extra_searched_paths=args.searched_path,
        extra_commands_run=args.command_run,
    )
    write_output(args.out, payload, jsonl=args.jsonl)
    print(
        "[source-root-blocker-emitter] OK "
        f"rows={payload['row_count']} replay_ready={payload['source_replay_ready_count']} out={args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
