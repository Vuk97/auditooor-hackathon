#!/usr/bin/env python3
"""Build an execution queue from normalized deep counterexamples.

``deep_counterexample.v1`` records are useful only if they turn into replay
work. This tool converts the records into explicit next actions and model
handoffs so Kimi/Minimax/Claude can reduce Codex/Opus burn while Codex remains
the final verifier.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Local import: queue rows carry ``evidence_class`` (item #14) so closeout
# tooling can refuse to count generated counterexamples or skipped scaffolds
# as proof.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_class as _evidence_class  # noqa: E402


SCHEMA_VERSION = "auditooor.deep_counterexample_queue.v1"
RECORD_SCHEMA = "auditooor.deep_counterexample.v1"


def slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "counterexample"


def read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def iter_records(workspace: Path) -> list[Path]:
    root = workspace / "deep_counterexamples"
    return sorted(
        path
        for path in root.glob("*.deep_counterexample.v1.json")
        if path.name != "collection_manifest.json"
    )


def iter_execution_manifests(workspace: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(workspace.glob("poc_execution/**/execution_manifest.json")):
        data = read_json(path)
        if isinstance(data, dict):
            data = dict(data)
            data["path"] = str(path)
            rows.append(data)
    return rows


def record_id_for(path: Path) -> str:
    suffix = ".deep_counterexample.v1.json"
    return path.name[:-len(suffix)] if path.name.endswith(suffix) else path.stem


def execution_match(record_id: str, record: dict[str, Any], manifests: list[dict[str, Any]]) -> dict[str, Any] | None:
    target_slug = slug(str(record.get("target_function") or ""))
    forge_path = str(record.get("generated_forge_test_path") or "")
    forge_stem = slug(Path(forge_path).stem) if forge_path else ""
    candidates = {record_id, target_slug, forge_stem}
    candidates.discard("")
    for manifest in manifests:
        candidate_id = slug(str(manifest.get("candidate_id") or ""))
        brief = slug(str(manifest.get("brief_path") or ""))
        if candidate_id in candidates or any(c and c in brief for c in candidates):
            return manifest
    return None


def read_handoff_manifest(scaffold_path: Path) -> dict[str, Any] | None:
    handoff_path = scaffold_path.with_name(scaffold_path.name + ".handoff.json")
    data = read_json(handoff_path)
    if isinstance(data, dict) and data.get("schema_version") == "auditooor.deep_counterexample_replay_handoff.v1":
        return data
    return None


def _evidence_class_for_status(status: str, scaffold_exists: bool) -> str:
    """Map a deep-counterexample queue ``status`` onto an ``evidence_class``.

    Item #14: the queue itself is never proof. The strongest pre-execution
    state is ``scaffolded_unverified`` (a real Forge replay file exists but
    has not run end-to-end). Anything weaker is ``generated_hypothesis``.
    Once the queue has a matching execution manifest the row is upgraded
    to ``executed_with_manifest`` upstream by ``classify``.
    """
    if status == "executed":
        return _evidence_class.EXECUTED_WITH_MANIFEST
    if status == "needs_execution_manifest":
        # Real wired scaffold exists but has not run yet.
        return _evidence_class.SCAFFOLDED_UNVERIFIED
    if status == "needs_replay_wiring" and scaffold_exists:
        # Skipped scaffold is still a scaffold artifact, but it is not
        # wired. We grade it as ``scaffolded_unverified`` so closeout can
        # see how many scaffolds exist; it does NOT promote them above
        # that bar.
        return _evidence_class.SCAFFOLDED_UNVERIFIED
    return _evidence_class.GENERATED_HYPOTHESIS


def classify(workspace: Path, path: Path, manifests: list[dict[str, Any]]) -> dict[str, Any]:
    record_id = record_id_for(path)
    raw = read_json(path)
    if not isinstance(raw, dict) or raw.get("schema_version") != RECORD_SCHEMA:
        return {
            "record_id": record_id,
            "record_path": str(path),
            "status": "invalid_record",
            "assigned_model": "codex",
            "next_action": "Inspect and regenerate the malformed deep counterexample record.",
            "guardrails": ["Do not promote malformed records."],
            # Item #14: a malformed record cannot be proof and must not be
            # silently bucketed under ``generated_hypothesis`` either.
            "evidence_class": _evidence_class.GENERATED_HYPOTHESIS,
        }

    record = raw
    match = execution_match(record_id, record, manifests)
    if match:
        # Closeout can already check ``final_result`` / ``impact_assertion``;
        # we still default to ``executed_with_manifest`` because a manifest
        # exists. Reviewer/Codex sign-off would raise this further to
        # ``human_verified`` downstream.
        return {
            "record_id": record_id,
            "record_path": str(path),
            "engine": record.get("engine", ""),
            "target_function": record.get("target_function", ""),
            "status": "executed",
            "assigned_model": "codex",
            "execution_manifest": match.get("path", ""),
            "final_result": match.get("final_result", ""),
            "impact_assertion": match.get("impact_assertion", ""),
            "next_action": "Codex final-verifies the execution manifest before any submission use.",
            "guardrails": ["Only RESULT=proved with IMPACT=exploit_impact can support a finding."],
            "evidence_class": _evidence_class.EXECUTED_WITH_MANIFEST,
        }

    forge_path = str(record.get("generated_forge_test_path") or "")
    replay = str(record.get("replay_command") or "")
    impossible = str(record.get("replay_impossible_reason") or "")
    forge_abs = workspace / forge_path if forge_path and not Path(forge_path).is_absolute() else Path(forge_path)
    scaffold_exists = forge_path and forge_abs.exists()
    scaffold_text = forge_abs.read_text(encoding="utf-8", errors="replace") if scaffold_exists else ""

    if not replay or impossible:
        status = "needs_replay_path"
        assigned = "kimi+minimax"
        next_action = (
            "Kimi reads the bounded source packet to recover the missing production/replay path; "
            "Minimax tries to kill it as OOS, duplicate, mock-only, or impossible."
        )
    elif not scaffold_exists:
        status = "needs_replay_scaffold"
        assigned = "claude"
        next_action = "Run make deep-counterexample-replay-scaffold, then wire setup/calls/assertions."
    elif "vm.skip(true)" in scaffold_text:
        status = "needs_replay_wiring"
        assigned = "claude"
        next_action = "Replace the skipped scaffold with real setup, calls, and exploit-impact assertions."
    else:
        status = "needs_execution_manifest"
        assigned = "codex"
        next_action = (
            "Run the replay command and record the result with make poc-execution-record; "
            "Codex verifies impact before promotion."
        )

    item = {
        "record_id": record_id,
        "record_path": str(path),
        "engine": record.get("engine", ""),
        "target_function": record.get("target_function", ""),
        "status": status,
        "assigned_model": assigned,
        "generated_forge_test_path": forge_path,
        "replay_command": replay,
        "replay_impossible_reason": impossible,
        "next_action": next_action,
        "guardrails": [
            "No submission text from this queue alone.",
            "No Critical/High severity until production path and exploit-impact PoC are proven.",
            "Admin, guardian, compromised-prover, mock-only, and project-inaction paths are unsafe unless scope explicitly includes them.",
        ],
        # Item #14: never above ``scaffolded_unverified`` here. Closeout
        # demands an execution manifest to reach ``executed_with_manifest``.
        "evidence_class": _evidence_class_for_status(status, bool(scaffold_exists)),
    }
    if scaffold_exists:
        handoff = read_handoff_manifest(forge_abs)
        if handoff:
            item["replay_handoff_manifest"] = str(forge_abs.with_name(forge_abs.name + ".handoff.json"))
            item["synthesized_call_count"] = handoff.get("synthesized_call_count", 0)
            item["remaining_tasks"] = handoff.get("remaining_tasks", [])
    return item


def render_md(payload: dict[str, Any]) -> str:
    lines = [
        "# Deep Counterexample Execution Queue",
        "",
        f"- workspace: `{payload['workspace']}`",
        f"- records: {payload['record_count']}",
        f"- execution manifests: {payload['execution_manifest_count']}",
        "",
        "| record | status | model | target | next action |",
        "|---|---|---|---|---|",
    ]
    for item in payload["items"]:
        lines.append(
            "| `{record_id}` | `{status}` | `{assigned_model}` | `{target}` | {action} |".format(
                record_id=item.get("record_id", ""),
                status=item.get("status", ""),
                assigned_model=item.get("assigned_model", ""),
                target=item.get("target_function", ""),
                action=str(item.get("next_action", "")).replace("|", "\\|"),
            )
        )
    lines.extend([
        "",
        "## Guardrails",
        "",
        "- Queue entries are not proof.",
        "- Claude may wire replay scaffolds; Kimi may fill source/architecture gaps; Minimax should adversarially reject weak/OOS paths.",
        "- Codex remains the final verifier before any finding is promoted.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[deep-counterexample-queue] ERR workspace not found: {ws}")
        return 2

    manifests = iter_execution_manifests(ws)
    records = iter_records(ws)
    items = [classify(ws, path, manifests) for path in records]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(ws),
        "record_count": len(records),
        "execution_manifest_count": len(manifests),
        "status_counts": {
            status: sum(1 for item in items if item.get("status") == status)
            for status in sorted({str(item.get("status")) for item in items})
        },
        # Item #14: per-class counts so audit-closeout-check.py can refuse
        # to count rows below ``executed_with_manifest`` as proof.
        "evidence_class_counts": _evidence_class.count_records(items),
        "items": items,
    }

    out_json = args.out_json or ws / "deep_counterexamples" / "execution_queue.json"
    out_md = args.out_md or ws / "deep_counterexamples" / "execution_queue.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_md(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[deep-counterexample-queue] OK records={len(records)} json={out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
