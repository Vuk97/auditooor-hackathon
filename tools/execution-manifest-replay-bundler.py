#!/usr/bin/env python3
"""Reduce FI execution-manifest families into replayable blocked bundles.

This is deliberately conservative. It does not mark exploit impact proved; it
turns a terminal FI family into a narrower artifact that says which existing
``poc_execution`` manifests can be replayed as accepted blocked scaffolds, and
which rows still need a concrete project-specific harness.
"""
from __future__ import annotations

import argparse
import json
import shlex
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.execution_manifest_replay_bundle.v1"
PROOF_BOUNDARY = (
    "Replay bundles are blocked-evidence plumbing only. A row is not exploit "
    "proof unless a matching poc_execution/**/execution_manifest.json records "
    "final_result=proved, impact_assertion=exploit_impact, "
    "evidence_class=executed_with_manifest, and at least one structured "
    "command row with non-empty command, status=pass, and exit_code=0."
)

TASK_FAMILY_PREFIX = "task_"


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"[execution-replay-bundle] ERR missing input: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[execution-replay-bundle] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tail_text(path: Path, limit: int = 4000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return text[-limit:]


def command_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    commands = [row for row in manifest.get("commands_attempted") or [] if isinstance(row, dict)]
    if not commands:
        return {}
    return commands[-1]


def classify_blocked_reason(manifest: dict[str, Any], command_row: dict[str, Any], stdout: str, stderr: str) -> str:
    combined = "\n".join([stdout, stderr]).lower()
    if "blocked_missing_target_project" in combined:
        return "accepted_blocked_missing_target_project"
    if "replace neutral benchmark scaffold with project-specific harness" in combined:
        return "accepted_blocked_neutral_scaffold"
    if int(command_row.get("exit_code") or 0) != 0:
        return "accepted_blocked_command_exit_nonzero"
    if manifest.get("final_result") == "blocked_path":
        return "accepted_blocked_manifest_status"
    return "needs_manual_review"


def row_payload(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    manifest_path = Path(str(row.get("path") or ""))
    manifest = load_json(manifest_path)
    candidate_id = str(manifest.get("candidate_id") or row.get("candidate_id") or manifest_path.parent.name)
    command_row = command_from_manifest(manifest)
    command = str(command_row.get("command") or "")
    cwd = str(command_row.get("cwd") or workspace)
    stdout_path = Path(str(command_row.get("stdout_path") or ""))
    stderr_path = Path(str(command_row.get("stderr_path") or ""))
    stdout = tail_text(stdout_path)
    stderr = tail_text(stderr_path)
    replay_command = f"cd {shlex.quote(cwd)} && {shlex.quote(command)}" if command else ""
    accepted_status = classify_blocked_reason(manifest, command_row, stdout, stderr)
    required_next_commands = [
        replay_command,
        (
            "Replace the neutral benchmark scaffold with a project-specific harness "
            f"for {candidate_id}, then rerun the exact harness command and record via "
            "make poc-execution-record with RESULT=needs_human IMPACT=unknown until "
            "the exact listed impact is proven."
        ),
    ]
    return {
        "candidate_id": candidate_id,
        "manifest_path": str(manifest_path),
        "brief_path": manifest.get("brief_path") or "",
        "final_result": manifest.get("final_result") or "",
        "impact_assertion": manifest.get("impact_assertion") or "",
        "latest_command": command,
        "latest_exit_code": command_row.get("exit_code"),
        "latest_status": command_row.get("status") or "",
        "replay_command": replay_command,
        "stdout_path": str(stdout_path) if stdout_path != Path("") else "",
        "stderr_path": str(stderr_path) if stderr_path != Path("") else "",
        "stdout_tail": stdout,
        "stderr_tail": stderr,
        "accepted_blocked_status": accepted_status,
        "accepted_blocked": accepted_status.startswith("accepted_blocked_"),
        "required_next_commands": [cmd for cmd in required_next_commands if cmd],
        "submit_ready": False,
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
    }


def build_bundle(workspace: Path, family: str, limit: int = 0) -> dict[str, Any]:
    family_path = workspace / ".auditooor" / "execution_manifest_terminal_blockers_fi" / f"{family}.json"
    family_payload = load_json(family_path)
    rows = [row for row in family_payload.get("rows") or [] if isinstance(row, dict)]
    if limit > 0:
        rows = rows[:limit]
    bundle_rows = [row_payload(row, workspace) for row in rows]
    accepted = [row for row in bundle_rows if row["accepted_blocked"]]
    needs_review = [row for row in bundle_rows if not row["accepted_blocked"]]
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "source_family_path": str(family_path),
        "family": family,
        "row_count": len(bundle_rows),
        "accepted_blocked_count": len(accepted),
        "needs_manual_review_count": len(needs_review),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "rows": bundle_rows,
        "blockers_reduced": {
            "terminal_family_rows_reduced_to_replayable_blocked_evidence": len(accepted),
            "rows_still_needing_manual_review": len(needs_review),
        },
    }


def discover_replay_families(workspace: Path) -> list[str]:
    family_dir = workspace / ".auditooor" / "execution_manifest_terminal_blockers_fi"
    if not family_dir.exists():
        return []
    families: list[str] = []
    for path in sorted(family_dir.glob("*.json")):
        if path.stem.startswith(TASK_FAMILY_PREFIX):
            continue
        payload = load_json(path)
        rows = payload.get("rows") if isinstance(payload, dict) else []
        if any(isinstance(row, dict) and row.get("path") for row in rows or []):
            families.append(path.stem)
    return families


def write_bundle_outputs(workspace: Path, payload: dict[str, Any], out_dir: Path | None = None) -> tuple[Path, Path]:
    base = out_dir or (workspace / ".auditooor")
    out_json = base / f"execution_manifest_replay_bundle_{payload['family']}.json"
    out_md = base / f"execution_manifest_replay_bundle_{payload['family']}.md"
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    return out_json, out_md


def build_batch(workspace: Path, families: list[str], limit: int = 0, out_dir: Path | None = None) -> dict[str, Any]:
    family_payloads = []
    for family in families:
        payload = build_bundle(workspace, family, limit)
        out_json, out_md = write_bundle_outputs(workspace, payload, out_dir)
        family_payloads.append(
            {
                "family": family,
                "row_count": payload["row_count"],
                "accepted_blocked_count": payload["accepted_blocked_count"],
                "needs_manual_review_count": payload["needs_manual_review_count"],
                "out_json": str(out_json),
                "out_md": str(out_md),
            }
        )
    return {
        "schema": "auditooor.execution_manifest_replay_bundle_batch.v1",
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "family_count": len(family_payloads),
        "row_count": sum(row["row_count"] for row in family_payloads),
        "accepted_blocked_count": sum(row["accepted_blocked_count"] for row in family_payloads),
        "needs_manual_review_count": sum(row["needs_manual_review_count"] for row in family_payloads),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "families": family_payloads,
    }


def render_batch_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Execution Manifest Replay Bundle Batch",
        "",
        payload["proof_boundary"],
        "",
        "## Summary",
        "",
        f"- Families: `{payload['family_count']}`",
        f"- Rows: `{payload['row_count']}`",
        f"- Accepted blocked replay rows: `{payload['accepted_blocked_count']}`",
        f"- Manual review rows: `{payload['needs_manual_review_count']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        "",
        "## Families",
        "",
        "| Family | Rows | Accepted blocked | Manual review | Artifact |",
        "|---|---:|---:|---:|---|",
    ]
    for row in payload["families"]:
        lines.append(
            f"| `{row['family']}` | `{row['row_count']}` | `{row['accepted_blocked_count']}` | "
            f"`{row['needs_manual_review_count']}` | `{row['out_json']}` |"
        )
    if not payload["families"]:
        lines.append("| _none_ | 0 | 0 | 0 | _none_ |")
    return "\n".join(lines) + "\n"


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# Execution Manifest Replay Bundle: {payload['family']}",
        "",
        payload["proof_boundary"],
        "",
        "## Summary",
        "",
        f"- Rows: `{payload['row_count']}`",
        f"- Accepted blocked replay rows: `{payload['accepted_blocked_count']}`",
        f"- Manual review rows: `{payload['needs_manual_review_count']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        "",
        "## Rows",
        "",
        "| Candidate | Status | Exit | Replay command |",
        "|---|---|---:|---|",
    ]
    for row in payload["rows"]:
        replay = (row.get("replay_command") or "").replace("|", "\\|")
        lines.append(
            f"| `{row['candidate_id']}` | `{row['accepted_blocked_status']}` | "
            f"`{row.get('latest_exit_code')}` | `{replay}` |"
        )
    if not payload["rows"]:
        lines.append("| _none_ | _none_ | _none_ | _none_ |")
    lines.extend(
        [
            "",
            "## Next Step",
            "",
            "Rows here are accepted blocked evidence only. The next executable step is to replace the neutral scaffold named by each candidate with a project-specific harness, rerun the replay command, and record the result without `RESULT=proved` unless exact listed impact is demonstrated.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--family")
    parser.add_argument("--families", help="Comma-separated families to process.")
    parser.add_argument("--all-families", action="store_true", help="Process every non-task FI family with manifest paths.")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if args.all_families or args.families:
        families = discover_replay_families(workspace) if args.all_families else [
            family.strip() for family in (args.families or "").split(",") if family.strip()
        ]
        if not families:
            raise SystemExit("[execution-replay-bundle] ERR no families selected")
        out_dir = args.out_dir.expanduser().resolve() if args.out_dir else None
        payload = build_batch(workspace, families, args.limit, out_dir)
        out_json = args.out_json or workspace / ".auditooor" / "execution_manifest_replay_bundle_batch.json"
        out_md = args.out_md or workspace / ".auditooor" / "execution_manifest_replay_bundle_batch.md"
        write_json(out_json, payload)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_batch_markdown(payload), encoding="utf-8")
        if args.print_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        print(
            "[execution-replay-bundle] OK batch "
            f"families={payload['family_count']} rows={payload['row_count']} "
            f"accepted_blocked={payload['accepted_blocked_count']}"
        )
        return 0

    if not args.family:
        raise SystemExit("[execution-replay-bundle] ERR --family, --families, or --all-families is required")
    out_json = args.out_json or workspace / ".auditooor" / f"execution_manifest_replay_bundle_{args.family}.json"
    out_md = args.out_md or workspace / ".auditooor" / f"execution_manifest_replay_bundle_{args.family}.md"
    payload = build_bundle(workspace, args.family, args.limit)
    if args.out_json or args.out_md:
        write_json(out_json, payload)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")
    else:
        write_bundle_outputs(workspace, payload)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[execution-replay-bundle] OK "
        f"family={payload['family']} rows={payload['row_count']} "
        f"accepted_blocked={payload['accepted_blocked_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
