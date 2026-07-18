#!/usr/bin/env python3
"""Build zkBugs detector/invariant/replay task routing from repo-content rows.

The input is the local repo-content ingest produced by ``zkbugs-ingest.py`` and
the optional provider queue produced by ``zkbugs-brief-queue.py``. This tool is
offline-only: it does not read GitHub issues, does not call providers, and does
not promote any row beyond a task recommendation.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX = ROOT / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json"
DEFAULT_QUEUE = ROOT / ".audit_logs" / "zkbugs_farming" / "provider_queue" / "zkbugs_provider_queue.json"
DEFAULT_OUT_JSON = ROOT / ".audit_logs" / "zkbugs_farming" / "zkbugs_task_map.json"
DEFAULT_OUT_MD = ROOT / ".audit_logs" / "zkbugs_farming" / "zkbugs_task_map.md"
DEFAULT_QUEUE_DIR = ROOT / ".audit_logs" / "zkbugs_farming" / "task_queues"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:120] or "zkbug"


def _brief_name(record: dict[str, Any]) -> str:
    return (
        f"{_slug(str(record.get('dsl') or 'unknown'))}__"
        f"{_slug(str(record.get('vulnerability') or 'unknown'))}__"
        f"{_slug(str(record.get('title') or 'zkbug'))}.md"
    )


def _norm(value: object) -> str:
    return str(value or "").strip()


def _lower_text(record: dict[str, Any]) -> str:
    parts = [
        record.get("title"),
        record.get("dsl"),
        record.get("vulnerability"),
        record.get("impact"),
        record.get("root_cause"),
        record.get("location_path"),
        record.get("location_function"),
        record.get("short_vulnerability"),
        record.get("short_exploit"),
        record.get("proposed_mitigation"),
    ]
    return "\n".join(str(part or "") for part in parts).lower()


def _family_from_text(text: str, fallback: str) -> str:
    rules = [
        ("range_check_missing", ("range check", "byte range", "bit length", "num2bits", "less than", "greater")),
        ("booleanity_missing", ("boolean", "onehot", "is complete flag", "flag")),
        ("assignment_not_constrained", ("assigned but not constrained", "output is declared but never constrained", "not constrained")),
        ("hash_or_merkle_binding", ("merkle", "smt", "hash", "sha256", "mimc", "blake3", "path")),
        ("signature_or_curve_validation", ("signature", "ecdsa", "edwards", "montgomery", "babyjubjub", "pubkey", "g1")),
        ("rlp_or_evm_state_binding", ("rlp", "tx circuit", "mpt", "opcode", "calldata", "bytecode", "nonce")),
        ("fixed_point_arithmetic", ("fixed-point", "fixed point", "muladd", "mulmod", "addition", "multiplication")),
        ("field_or_bigint_aliasing", ("field", "alias", "overflow", "non-reduced", "bigint", "babybear")),
        ("fiat_shamir_transcript", ("fiat-shamir", "fri", "randomness", "observation", "degree check")),
        ("vk_or_verifier_binding", ("vk root", "verifier", "verification key", "stark verifier")),
        ("privacy_or_nullifier", ("nullifier", "kyc", "certificate", "ownership proof", "private information")),
        ("backend_or_zkvm_execution", ("backend", "zkvm", "register", "allocator", "chip ordering")),
    ]
    for family, needles in rules:
        if any(needle in text for needle in needles):
            return family
    return _slug(fallback).replace("-", "_") or "uncategorized"


def artifact_type(record: dict[str, Any]) -> str:
    dsl = _norm(record.get("dsl")).lower()
    path = _norm(record.get("location_path")).lower()
    text = _lower_text(record)
    if "verifier" in text or "vk root" in text or "fri" in text:
        return "verifier_or_backend"
    if dsl == "circom" or path.endswith(".circom"):
        return "circom_circuit"
    if dsl == "cairo" or path.endswith(".cairo"):
        return "cairo_circuit"
    if dsl == "pil":
        return "pil_constraints"
    if dsl == "gnark" or path.endswith(".go"):
        return "go_zk_library"
    if dsl == "risc0":
        return "zkvm_rust"
    if dsl in {"arkworks", "bellperson", "halo2", "plonky3"} or path.endswith(".rs"):
        return "rust_zk_library"
    return "mixed_or_report_only"


def proof_feasibility(record: dict[str, Any]) -> str:
    commands = record.get("commands") if isinstance(record.get("commands"), dict) else {}
    has_repro = bool(_norm(commands.get("Reproduce"))) if isinstance(commands, dict) else False
    if record.get("reproduced") or has_repro:
        return "direct_replay_available"
    if _norm(record.get("fix_commit")) and _norm(record.get("commit")) and _norm(record.get("location_path")):
        return "source_diff_replay_feasible"
    if record.get("report_text_files") and _norm(record.get("location_path")):
        return "report_guided_fixture_feasible"
    if record.get("source_links") or record.get("report_files"):
        return "provider_extraction_needed"
    return "blocked_missing_local_evidence"


def suitability(record: dict[str, Any]) -> list[str]:
    text = _lower_text(record)
    kind = artifact_type(record)
    lanes: list[str] = []
    if kind == "circom_circuit":
        lanes.append("circom_text_detector")
    if kind in {"rust_zk_library", "zkvm_rust", "verifier_or_backend"}:
        lanes.append("rust_semantic_detector")
    if kind in {"cairo_circuit", "pil_constraints", "go_zk_library"}:
        lanes.append("language_specific_detector")
    if any(word in text for word in ("range", "boolean", "nullifier", "root", "sum", "state", "hash", "signature", "comparator")):
        lanes.append("invariant_template")
    if proof_feasibility(record) in {"direct_replay_available", "source_diff_replay_feasible", "report_guided_fixture_feasible"}:
        lanes.append("replay_or_smoke_fixture")
    if not lanes:
        lanes.append("provider_advisory_only")
    return sorted(set(lanes))


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"[zkbugs-task-map] missing JSON input: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[zkbugs-task-map] invalid JSON at {path}: {exc}") from None
    if not isinstance(payload, dict):
        raise SystemExit(f"[zkbugs-task-map] expected object JSON at {path}")
    return payload


def _queue_by_brief(queue: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = queue.get("rows") if isinstance(queue.get("rows"), list) else []
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        brief = Path(_norm(row.get("brief"))).name
        if brief:
            by_name[brief] = row
    return by_name


def _provider_readiness(record: dict[str, Any], queue_row: dict[str, Any] | None) -> dict[str, Any]:
    kimi = Path(_norm(queue_row.get("kimi_prompt"))) if queue_row else Path()
    minimax = Path(_norm(queue_row.get("minimax_prompt_template"))) if queue_row else Path()
    ready = bool(queue_row and kimi.is_file() and minimax.is_file())
    return {
        "status": "prompt_ready" if ready else "missing_prompt_artifacts",
        "queue_index": queue_row.get("index") if queue_row else None,
        "brief": queue_row.get("brief") if queue_row else "",
        "kimi_prompt": str(kimi) if queue_row else "",
        "minimax_prompt_template": str(minimax) if queue_row else "",
    }


def build_task_map(index: dict[str, Any], queue: dict[str, Any]) -> dict[str, Any]:
    records = index.get("records")
    if not isinstance(records, list):
        raise SystemExit("[zkbugs-task-map] index has no records[]")
    queue_lookup = _queue_by_brief(queue)
    tasks: list[dict[str, Any]] = []
    counters: dict[str, Counter[str]] = {
        "by_bug_class": Counter(),
        "by_dsl": Counter(),
        "by_artifact_type": Counter(),
        "by_proof_feasibility": Counter(),
        "by_provider_prompt_readiness": Counter(),
        "by_detector_lane": Counter(),
    }
    group_rows: dict[str, list[str]] = defaultdict(list)
    for idx, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue
        text = _lower_text(record)
        family = _family_from_text(text, _norm(record.get("root_cause")) or _norm(record.get("vulnerability")))
        bug_class = f"{_slug(_norm(record.get('dsl')) or 'unknown')}::{_slug(_norm(record.get('vulnerability')) or 'unknown')}::{family}"
        kind = artifact_type(record)
        proof = proof_feasibility(record)
        lanes = suitability(record)
        queue_row = queue_lookup.get(_brief_name(record))
        provider = _provider_readiness(record, queue_row)
        task_id = f"ZKBUGS-{idx:03d}"
        task = {
            "task_id": task_id,
            "bug_id": record.get("bug_id") or "",
            "title": record.get("title") or "",
            "dsl": record.get("dsl") or "unknown",
            "vulnerability": record.get("vulnerability") or "unknown",
            "root_cause": record.get("root_cause") or "",
            "bug_class": bug_class,
            "artifact_type": kind,
            "proof_feasibility": proof,
            "detector_invariant_suitability": lanes,
            "provider_prompt_readiness": provider,
            "priority_score": int(record.get("priority_score") or 0),
            "location": {
                "project": record.get("project") or "",
                "commit": record.get("commit") or "",
                "fix_commit": record.get("fix_commit") or "",
                "path": record.get("location_path") or "",
                "function": record.get("location_function") or "",
                "line": record.get("location_line") or "",
            },
            "evidence": {
                "local_report_files": record.get("report_files") or [],
                "local_report_text_files": record.get("report_text_files") or [],
                "source_links": record.get("source_links") or [],
                "priority_reasons": record.get("priority_reasons") or [],
            },
            "next_action": _next_action(kind, proof, lanes, provider["status"]),
        }
        tasks.append(task)
        counters["by_bug_class"][bug_class] += 1
        counters["by_dsl"][_norm(record.get("dsl")) or "unknown"] += 1
        counters["by_artifact_type"][kind] += 1
        counters["by_proof_feasibility"][proof] += 1
        counters["by_provider_prompt_readiness"][str(provider["status"])] += 1
        for lane in lanes:
            counters["by_detector_lane"][lane] += 1
        group_rows[bug_class].append(task_id)
    groups = [
        {"bug_class": key, "count": len(ids), "task_ids": ids}
        for key, ids in sorted(group_rows.items(), key=lambda item: (-len(item[1]), item[0]))
    ]
    return {
        "schema": "auditooor.zkbugs_task_map.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": index.get("source") or "https://github.com/zksecurity/zkbugs",
        "corpus_boundary": "local zksecurity/zkbugs repo-content ingest only; GitHub issues are not used as corpus",
        "input_paths": {
            "index": str(DEFAULT_INDEX),
            "provider_queue": str(DEFAULT_QUEUE),
        },
        "summary": {
            "total_tasks": len(tasks),
            **{name: dict(counter.most_common()) for name, counter in counters.items()},
            "ready_for_provider_prompts": counters["by_provider_prompt_readiness"].get("prompt_ready", 0),
            "detector_or_invariant_candidates": sum(
                1
                for task in tasks
                if any(lane in task["detector_invariant_suitability"] for lane in ("circom_text_detector", "rust_semantic_detector", "language_specific_detector", "invariant_template"))
            ),
            "replay_or_fixture_candidates": sum(1 for task in tasks if "replay_or_smoke_fixture" in task["detector_invariant_suitability"]),
        },
        "groups": groups,
        "tasks": tasks,
    }


def _next_action(kind: str, proof: str, lanes: list[str], provider_status: str) -> str:
    if provider_status != "prompt_ready":
        return "regenerate provider queue before dispatch"
    if "replay_or_smoke_fixture" in lanes and proof == "source_diff_replay_feasible":
        return "build vulnerable/clean smoke fixture from vulnerable commit and fix diff"
    if "circom_text_detector" in lanes:
        return "extract Circom predicate, add positive/negative fixtures, then run circom detector tests"
    if "rust_semantic_detector" in lanes:
        return "extract Rust semantic predicate, add smoke fixture or replay scaffold"
    if kind in {"cairo_circuit", "pil_constraints", "go_zk_library"}:
        return "route to language-specific detector design after provider kill-pass"
    return "keep advisory until provider extraction produces a checkable predicate"


def build_route_queues(payload: dict[str, Any]) -> dict[str, Any]:
    tasks = payload["tasks"]
    detector_rows = [
        task
        for task in tasks
        if any(
            lane in task["detector_invariant_suitability"]
            for lane in ("circom_text_detector", "rust_semantic_detector", "language_specific_detector")
        )
    ]
    invariant_rows = [task for task in tasks if "invariant_template" in task["detector_invariant_suitability"]]
    replay_rows = [task for task in tasks if "replay_or_smoke_fixture" in task["detector_invariant_suitability"]]
    provider_rows = [task for task in tasks if task["provider_prompt_readiness"]["status"] == "prompt_ready"]
    covered = {
        task["task_id"]
        for task in [*detector_rows, *invariant_rows, *replay_rows, *provider_rows]
    }
    uncovered = [task for task in tasks if task["task_id"] not in covered]
    completeness = {
        "schema": "auditooor.zkbugs_route_completeness.v1",
        "generated_at": payload["generated_at"],
        "total_tasks": len(tasks),
        "detector_queue_rows": len(detector_rows),
        "invariant_queue_rows": len(invariant_rows),
        "replay_queue_rows": len(replay_rows),
        "provider_prompt_queue_rows": len(provider_rows),
        "covered_task_ids": sorted(covered),
        "uncovered_task_ids": [task["task_id"] for task in uncovered],
        "status": "complete" if not uncovered and len(provider_rows) == len(tasks) else "blocked",
        "blockers": [],
        "boundary": payload["corpus_boundary"],
    }
    if uncovered:
        completeness["blockers"].append("some_records_have_no_detector_invariant_replay_or_provider_route")
    if len(provider_rows) != len(tasks):
        completeness["blockers"].append("not_all_records_have_ready_provider_prompts")
    return {
        "detector_queue": _queue_payload("detector_queue", detector_rows),
        "invariant_queue": _queue_payload("invariant_queue", invariant_rows),
        "replay_queue": _queue_payload("replay_queue", replay_rows),
        "provider_prompt_queue": _queue_payload("provider_prompt_queue", provider_rows),
        "completeness": completeness,
    }


def _queue_payload(name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": f"auditooor.zkbugs_{name}.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "rows": rows,
    }


def render_queue_markdown(title: str, queue: dict[str, Any], *, top: int = 80) -> str:
    rows = queue["rows"]
    lines = [
        f"# zkBugs {title}",
        "",
        f"- Count: `{queue['count']}`",
        "",
        "| Task | DSL | Bug class | Artifact | Proof | Title | Next action |",
        "|---|---|---|---|---|---|---|",
    ]
    for task in rows[:top]:
        title_text = str(task["title"]).replace("|", "\\|")
        next_action = str(task["next_action"]).replace("|", "\\|")
        lines.append(
            f"| `{task['task_id']}` | `{task['dsl']}` | `{task['bug_class']}` | "
            f"`{task['artifact_type']}` | `{task['proof_feasibility']}` | {title_text} | {next_action} |"
        )
    if len(rows) > top:
        lines.append(f"| ... | ... | ... | ... | ... | `{len(rows) - top} additional rows in JSON` | ... |")
    lines.append("")
    return "\n".join(lines)


def render_completeness_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# zkBugs Route Completeness",
        "",
        f"- Status: `{payload['status']}`",
        f"- Total tasks: `{payload['total_tasks']}`",
        f"- Detector queue rows: `{payload['detector_queue_rows']}`",
        f"- Invariant queue rows: `{payload['invariant_queue_rows']}`",
        f"- Replay queue rows: `{payload['replay_queue_rows']}`",
        f"- Provider prompt queue rows: `{payload['provider_prompt_queue_rows']}`",
        f"- Uncovered task IDs: `{len(payload['uncovered_task_ids'])}`",
        "",
        "## Blockers",
        "",
    ]
    for blocker in payload["blockers"] or ["none"]:
        lines.append(f"- `{blocker}`")
    lines.extend(["", "## Boundary", "", payload["boundary"], ""])
    return "\n".join(lines)


def render_markdown(payload: dict[str, Any], *, top: int = 40) -> str:
    summary = payload["summary"]
    lines = [
        "# zkBugs Task Map",
        "",
        payload["corpus_boundary"],
        "",
        "## Summary",
        "",
        f"- Total tasks: `{summary['total_tasks']}`",
        f"- Provider-prompt ready: `{summary['ready_for_provider_prompts']}`",
        f"- Detector/invariant candidates: `{summary['detector_or_invariant_candidates']}`",
        f"- Replay/smoke-fixture candidates: `{summary['replay_or_fixture_candidates']}`",
        "",
        "## Artifact Types",
        "",
    ]
    for key, count in summary["by_artifact_type"].items():
        lines.append(f"- `{key}`: `{count}`")
    lines.extend(["", "## Proof / Replay Feasibility", ""])
    for key, count in summary["by_proof_feasibility"].items():
        lines.append(f"- `{key}`: `{count}`")
    lines.extend(["", "## Detector / Invariant Lanes", ""])
    for key, count in summary["by_detector_lane"].items():
        lines.append(f"- `{key}`: `{count}`")
    lines.extend(["", "## Largest Bug Classes", "", "| Count | Bug class | Task IDs |", "|---:|---|---|"])
    for group in payload["groups"][:top]:
        task_ids = ", ".join(group["task_ids"][:8])
        more = "" if len(group["task_ids"]) <= 8 else f" +{len(group['task_ids']) - 8} more"
        lines.append(f"| {group['count']} | `{group['bug_class']}` | `{task_ids}{more}` |")
    lines.extend(["", "## Top Routed Tasks", "", "| Task | DSL | Artifact | Proof | Lanes | Title | Next action |", "|---|---|---|---|---|---|---|"])
    tasks = sorted(payload["tasks"], key=lambda item: (-int(item["priority_score"]), item["task_id"]))
    for task in tasks[:top]:
        lanes = ", ".join(task["detector_invariant_suitability"])
        title = str(task["title"]).replace("|", "\\|")
        next_action = str(task["next_action"]).replace("|", "\\|")
        lines.append(
            f"| `{task['task_id']}` | `{task['dsl']}` | `{task['artifact_type']}` | "
            f"`{task['proof_feasibility']}` | `{lanes}` | {title} | {next_action} |"
        )
    lines.extend([
        "",
        "## Guardrails",
        "",
        "- This is a route map, not proof of exploitability or detector promotion.",
        "- Do not use GitHub issues as corpus for these rows.",
        "- Promote only after provider kill-pass plus vulnerable/clean smoke-fire or replayable counterexample.",
    ])
    return "\n".join(lines) + "\n"


def write_payload(payload: dict[str, Any], out_json: Path, out_md: Path, queue_dir: Path) -> dict[str, Any]:
    payload["input_paths"] = {
        "index": str(out_json.parent / "zkbugs_index.json"),
        "provider_queue": str(out_json.parent / "provider_queue" / "zkbugs_provider_queue.json"),
    }
    route_queues = build_route_queues(payload)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    queue_dir.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    for name, title in (
        ("detector_queue", "Detector Queue"),
        ("invariant_queue", "Invariant Queue"),
        ("replay_queue", "Replay / Smoke Fixture Queue"),
        ("provider_prompt_queue", "Provider Prompt Queue"),
    ):
        queue = route_queues[name]
        (queue_dir / f"zkbugs_{name}.json").write_text(
            json.dumps(queue, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (queue_dir / f"zkbugs_{name}.md").write_text(render_queue_markdown(title, queue), encoding="utf-8")
    completeness = route_queues["completeness"]
    (queue_dir / "zkbugs_route_completeness.json").write_text(
        json.dumps(completeness, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (queue_dir / "zkbugs_route_completeness.md").write_text(
        render_completeness_markdown(completeness),
        encoding="utf-8",
    )
    return route_queues


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--provider-queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--queue-dir", type=Path, default=DEFAULT_QUEUE_DIR)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    index = _load_json(args.index)
    queue = _load_json(args.provider_queue)
    payload = build_task_map(index, queue)
    route_queues = write_payload(payload, args.out_json, args.out_md, args.queue_dir)
    if args.print_json:
        print(json.dumps({**payload["summary"], "route_completeness": route_queues["completeness"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
