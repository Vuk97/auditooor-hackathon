#!/usr/bin/env python3
"""Validate the next proof inputs for impact-contract binding rows.

This sits one layer after ``impact-contract-binding-requirements.py``.  The
requirements file says which proof classes are missing; this tool splits those
classes into smaller executable/importable units and keeps the proof boundary
explicit.  It never promotes listed impact or severity.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_binding_next_input_validator.v1"
DEFAULT_INPUT = ".auditooor/impact_contract_binding_requirements.json"
DEFAULT_OUT = ".auditooor/impact_binding_next_input_validator.json"
DEFAULT_OUT_MD = ".auditooor/impact_binding_next_input_validator.md"
DEFAULT_UNIT_DIR = ".auditooor/impact_binding_next_input_units"
PROOF_BOUNDARY = (
    "Rows are next-input validation work units only. They do not prove listed "
    "impact, set severity, authorize submission, or replace source/live/OOS/"
    "pre-submit gates."
)


DEPENDENCY_ORDER = {
    "candidate_bound_project_source_citation": 10,
    "bounded_project_input_fixture": 20,
    "production_path_dossier": 30,
    "paired_live_or_fork_proof": 40,
    "project_specific_harness_execution": 50,
    "proved_exploit_impact_execution_manifest": 60,
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[impact-binding-next-input] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def path_exists(path_text: str) -> bool:
    return bool(path_text) and Path(path_text).exists()


def command_for(requirement: str, row: dict[str, Any], status: dict[str, Any], workspace: Path) -> str:
    candidate = str(row.get("candidate_id") or "")
    family = str(row.get("route_family") or "")
    if requirement == "candidate_bound_project_source_citation":
        return (
            f"rg -n \"{family}|impact|invariant|withdraw|settle|verify|signature|role\" <project-source-root> && "
            f"make source-proof-record WS={workspace} CANDIDATE={candidate} "
            "CITATION='<project-source-file:line>' OOS=in_scope VERDICT=proved_source_only"
        )
    if requirement == "bounded_project_input_fixture":
        return f"write project-bound JSON at test_fixtures/{candidate}/bounded_input_fixture.json"
    if requirement == "production_path_dossier":
        return f"python3 tools/production-path-dossier.py --workspace {workspace} <typed-candidate-for-{candidate}.json>"
    if requirement == "paired_live_or_fork_proof":
        return (
            f"capture/import same-block live proof or fork replay for {candidate}; "
            "then rerun live-topology proof/readiness gates"
        )
    if requirement == "project_specific_harness_execution":
        missing = ",".join(str(item) for item in status.get("missing_requirements") or [])
        return f"replace poc-tests/{candidate}/run_harness.sh neutral scaffold with project binding; missing={missing or 'unknown'}"
    if requirement == "proved_exploit_impact_execution_manifest":
        return (
            f"make poc-execution-record WS={workspace} CANDIDATE_ID={candidate} "
            "BRIEF=<brief.md> CMD='<project-specific harness command>' RESULT=proved IMPACT=exploit_impact"
        )
    return str(row.get("next_local_commands") or ["inspect missing requirement"])[0]


def classify_source(status: dict[str, Any]) -> tuple[str, list[str]]:
    if status.get("status") == "present":
        return "ready_present", []
    decision = str(status.get("review_decision") or "")
    paths = [path for path in status.get("source_proof_paths") or [] if path]
    if decision:
        return decision if decision.startswith("terminal_") else f"blocked_review_{decision}", ["candidate_bound_project_source_citation"]
    if paths:
        return "terminal_source_proof_exists_but_not_valid_project_citation", ["valid_project_source_citation"]
    return "missing_source_review_row", ["source_review_row", "candidate_bound_project_source_citation"]


def classify_requirement(requirement: str, status: dict[str, Any]) -> tuple[str, list[str]]:
    if status.get("status") == "present":
        return "ready_present", []
    if requirement == "candidate_bound_project_source_citation":
        return classify_source(status)
    if requirement == "project_specific_harness_execution":
        missing = [str(item) for item in status.get("missing_requirements") or []]
        return "blocked_project_harness_missing_inputs", missing or ["target_project_binding"]
    if requirement == "proved_exploit_impact_execution_manifest":
        paths = [path for path in status.get("manifest_paths") or [] if path]
        return ("terminal_execution_manifest_not_proved" if paths else "missing_execution_manifest"), ["proved_exploit_impact_execution_manifest"]
    if requirement == "production_path_dossier":
        path = str(status.get("path") or "")
        dossier_status = str(status.get("dossier_status") or "")
        if path_exists(path):
            return f"terminal_production_path_{dossier_status or 'not_proved'}", ["production_path_proof"]
        return "missing_production_path_dossier", ["typed_candidate", "production_path_dossier"]
    if requirement == "paired_live_or_fork_proof":
        path = str(status.get("path") or "")
        proof_status = str(status.get("proof_status") or "")
        if path_exists(path):
            return f"terminal_live_or_fork_{proof_status or 'not_proved'}", ["executed_same_block_or_fork_proof"]
        return "missing_live_or_fork_artifact", ["verified_address", "rpc", "shared_block", "expected_value", "manual_or_fork_proof"]
    if requirement == "bounded_project_input_fixture":
        path = str(status.get("path") or "")
        fixture_status = str(status.get("fixture_status") or "")
        if path_exists(path):
            return f"terminal_bounded_fixture_{fixture_status or 'not_project_bound'}", ["project_bound_fixture"]
        return "missing_bounded_project_input_fixture", ["bounded_input_fixture_json"]
    return "unknown_requirement_checker", [requirement]


def requirement_status_map(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("artifact") or ""): item
        for item in row.get("requirement_statuses") or []
        if isinstance(item, dict)
    }


def build_payload(workspace: Path, *, input_path: Path | None = None, unit_dir: Path | None = None) -> dict[str, Any]:
    source = load_json(input_path or workspace / DEFAULT_INPUT)
    rows = [row for row in source.get("rows") or [] if isinstance(row, dict)]
    units: list[dict[str, Any]] = []
    for row in rows:
        statuses = requirement_status_map(row)
        missing = [str(item) for item in row.get("missing_requirements") or []]
        for requirement in missing:
            status = statuses.get(requirement, {"artifact": requirement, "status": "missing"})
            blocker_class, missing_inputs = classify_requirement(requirement, status)
            units.append(
                {
                    "candidate_id": str(row.get("candidate_id") or ""),
                    "impact_contract_id": str(row.get("impact_contract_id") or ""),
                    "route_family": str(row.get("route_family") or ""),
                    "tier": str(row.get("tier") or ""),
                    "requirement": requirement,
                    "dependency_order": DEPENDENCY_ORDER.get(requirement, 100),
                    "blocker_class": blocker_class,
                    "missing_inputs": missing_inputs,
                    "local_artifact_status": status,
                    "next_command": command_for(requirement, row, status, workspace),
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "proof_boundary": PROOF_BOUNDARY,
                }
            )

    units.sort(key=lambda item: (item["dependency_order"], item["route_family"], item["candidate_id"], item["requirement"]))
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_requirement: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in units:
        by_family[str(unit["route_family"])].append(unit)
        by_requirement[str(unit["requirement"])].append(unit)

    ready_units = [unit for unit in units if unit["blocker_class"] == "ready_present"]
    actionable_units = [unit for unit in units if unit["blocker_class"] != "ready_present"]
    payload = {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "source_requirements_path": str(input_path or workspace / DEFAULT_INPUT),
        "contract_count": len(rows),
        "unit_count": len(units),
        "ready_unit_count": len(ready_units),
        "actionable_unit_count": len(actionable_units),
        "closure_candidate_count": 0,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "requirement_counts": dict(sorted(Counter(unit["requirement"] for unit in units).items())),
            "blocker_class_counts": dict(sorted(Counter(unit["blocker_class"] for unit in units).items())),
            "route_family_counts": dict(sorted(Counter(unit["route_family"] for unit in units).items())),
            "missing_input_counts": dict(sorted(Counter(item for unit in units for item in unit["missing_inputs"]).items())),
        },
        "requirement_manifests": {
            requirement: {
                "unit_count": len(items),
                "blocker_class_counts": dict(sorted(Counter(unit["blocker_class"] for unit in items).items())),
                "next_commands": [unit["next_command"] for unit in items[:20]],
            }
            for requirement, items in sorted(by_requirement.items())
        },
        "units": units,
    }

    if unit_dir:
        unit_dir.mkdir(parents=True, exist_ok=True)
        for family, family_units in sorted(by_family.items()):
            write_json(
                unit_dir / f"{family}.json",
                {
                    "schema": "auditooor.pr560.impact_binding_next_input_family.v1",
                    "workspace": str(workspace),
                    "route_family": family,
                    "unit_count": len(family_units),
                    "blocker_class_counts": dict(sorted(Counter(unit["blocker_class"] for unit in family_units).items())),
                    "missing_input_counts": dict(sorted(Counter(item for unit in family_units for item in unit["missing_inputs"]).items())),
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "proof_boundary": PROOF_BOUNDARY,
                    "units": family_units,
                },
            )
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Impact Binding Next Input Validator",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- Contracts inspected: `{payload['contract_count']}`",
        f"- Work units: `{payload['unit_count']}`",
        f"- Ready units: `{payload['ready_unit_count']}`",
        f"- Actionable/blocked units: `{payload['actionable_unit_count']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        "",
        "## Requirement Counts",
        "",
    ]
    for key, value in payload["summary"]["requirement_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Blocker Classes", ""])
    for key, value in payload["summary"]["blocker_class_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Missing Input Counts", ""])
    for key, value in payload["summary"]["missing_input_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## First Actionable Units", ""])
    for unit in payload["units"][:30]:
        lines.append(
            f"- `{unit['candidate_id']}` / `{unit['requirement']}`: "
            f"`{unit['blocker_class']}` -> `{unit['next_command']}`"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--unit-dir", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    input_path = (args.input_json or workspace / DEFAULT_INPUT).expanduser().resolve()
    unit_dir = (args.unit_dir or workspace / DEFAULT_UNIT_DIR).expanduser().resolve()
    payload = build_payload(workspace, input_path=input_path, unit_dir=unit_dir)
    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[impact-binding-next-input] OK "
        f"contracts={payload['contract_count']} units={payload['unit_count']} "
        f"ready={payload['ready_unit_count']} actionable={payload['actionable_unit_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
