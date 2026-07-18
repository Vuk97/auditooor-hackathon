#!/usr/bin/env python3
"""Emit a fail-closed KLBQ-010 impact-contract preflight status packet."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.impact_contract_preflight_status.v1"
DEFAULT_DATE = "2026-05-05"


ROUTE_EVIDENCE = (
    {
        "route": "shared-parser",
        "surface": "shared impact-contract parser",
        "strictness": "proof routes block; planning routes advisory-bypass only",
        "implementation": {
            "path": "tools/impact-contract-preflight.py",
            "needles": (
                "SCHEMA_VERSION",
                "impact-contract-missing",
                "planning-artifact-advisory-bypass",
                "impact-contract-explicit",
            ),
        },
        "test": {
            "path": "tools/tests/test_impact_contract_preflight.py",
            "needles": (
                "test_proof_grade_draft_without_explicit_contract_is_blocked",
                "test_explicit_markdown_contract_allows_filing",
                "test_planning_json_gets_advisory_bypass",
                "test_explicit_json_contract_allows_promotion",
            ),
        },
    },
    {
        "route": "source-proof",
        "surface": "source proof record",
        "strictness": "blocks source-proof records without an explicit impact contract",
        "implementation": {
            "path": "tools/source-proof-record.py",
            "needles": (
                "impact_contract_preflight",
                "build_source_proof_preflight",
                'route="source-proof"',
                "blocked_missing_impact_contract",
            ),
        },
        "test": {
            "path": "tools/tests/test_source_proof_record.py",
            "needles": (
                "impact_contract_preflight",
                "source-proof",
                "test_missing_impact_contract_blocks_even_if_proof_requested",
            ),
        },
    },
    {
        "route": "harness-scaffold",
        "surface": "harness scaffold attempt manifest",
        "strictness": "blocks runnable scaffold output when impact binding is missing",
        "implementation": {
            "path": "tools/harness-scaffold-emitter.py",
            "needles": (
                "impact_contract_preflight",
                "harness_impact_preflight",
                'route="harness-scaffold"',
                "blocked_missing_impact_contract",
            ),
        },
        "test": {
            "path": "tools/tests/test_harness_scaffold_emitter.py",
            "needles": (
                "impact_contract_preflight",
                "harness-scaffold",
                "test_missing_impact_contract_writes_only_blocked_manifest",
                "test_workspace_impact_contract_unlocks_scaffold_and_manifest_metadata",
            ),
        },
    },
    {
        "route": "exploit-memory",
        "surface": "exploit memory brief",
        "strictness": "advisory bypass only; never promotion or filing evidence",
        "implementation": {
            "path": "tools/exploit-memory-brief.py",
            "needles": (
                "impact_contract_preflight",
                "_exploit_memory_preflight",
                'route="exploit-memory"',
                "planning-artifact-advisory-bypass",
            ),
        },
        "test": {
            "path": "tools/tests/test_exploit_memory_brief.py",
            "needles": (
                "impact_contract_preflight",
                "exploit-memory",
                "planning-artifact-advisory-bypass",
            ),
        },
    },
    {
        "route": "filing",
        "surface": "pre-submit filing gate",
        "strictness": "blocks proof-grade filing drafts with missing impact contract",
        "implementation": {
            "path": "tools/pre-submit-check.sh",
            "needles": (
                "impact-contract-preflight",
                "--route filing",
                "impact-contract-missing",
            ),
        },
        "test": {
            "path": "tools/tests/test_pre_submit_impact_contract_check.py",
            "needles": (
                "test_missing_explicit_contract_is_reported",
                "test_explicit_contract_marks_check_green",
                "impact-contract-missing",
            ),
        },
    },
    {
        "route": "promotion",
        "surface": "agent-output synthesizer promotion",
        "strictness": "demotes candidate promotion when impact contract is missing",
        "implementation": {
            "path": "tools/agent-output-synthesizer.py",
            "needles": (
                "impact_contract_preflight",
                'route="promotion"',
                "candidate_finding",
            ),
        },
        "test": {
            "path": "tools/tests/test_agent_output_synthesizer_impact_contract.py",
            "needles": (
                "test_missing_contract_demotes_candidate_to_poc_plan",
                "test_explicit_contract_promotes_candidate_finding",
                "impact-contract-missing",
            ),
        },
    },
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_json_path(root: Path) -> Path:
    return root / "reports" / f"impact_contract_preflight_status_{DEFAULT_DATE}.json"


def default_md_path(root: Path) -> Path:
    return root / "docs" / f"IMPACT_CONTRACT_PREFLIGHT_STATUS_{DEFAULT_DATE}.md"


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _read_text(root: Path, rel_path: str) -> tuple[str, str | None]:
    path = root / rel_path
    if not path.is_file():
        return "", f"missing file: {rel_path}"
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return "", f"unreadable file: {rel_path}: {exc}"


def _check_file(root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    rel_path = _safe_text(spec.get("path"))
    text, issue = _read_text(root, rel_path)
    needles = tuple(_safe_text(item) for item in spec.get("needles", ()) if _safe_text(item))
    missing_needles = [needle for needle in needles if needle not in text]
    present = issue is None
    passed = present and not missing_needles
    return {
        "path": rel_path,
        "present": present,
        "status": "pass" if passed else "blocked",
        "required_needles": list(needles),
        "missing_needles": missing_needles,
        "issues": ([] if issue is None else [issue])
        + [f"missing required marker in {rel_path}: {needle}" for needle in missing_needles],
    }


def _build_route(root: Path, route: dict[str, Any]) -> dict[str, Any]:
    implementation = _check_file(root, route["implementation"])
    test = _check_file(root, route["test"])
    issues = implementation["issues"] + test["issues"]
    status = "pass" if not issues else "blocked"
    return {
        "route": route["route"],
        "surface": route["surface"],
        "strictness": route["strictness"],
        "status": status,
        "implementation": implementation,
        "test": test,
        "issues": issues,
    }


def build_report(root: Path) -> dict[str, Any]:
    routes = [_build_route(root, route) for route in ROUTE_EVIDENCE]
    blocked_routes = [route for route in routes if route["status"] != "pass"]
    evidence_paths = []
    for route in routes:
        for key in ("implementation", "test"):
            path = route[key]["path"]
            if path not in evidence_paths:
                evidence_paths.append(path)

    implemented = not blocked_routes and bool(routes)
    blockers = [
        f"{route['route']}: " + "; ".join(route["issues"])
        for route in blocked_routes
    ]
    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "limitation_id": "KLBQ-010",
        "worktree": str(root),
        "implementation_status": (
            "implemented_verified_local_evidence"
            if implemented
            else "blocked_missing_route_evidence"
        ),
        "open": not implemented,
        "dispatch_ready": not implemented,
        "expected_loop_cost": 0 if implemented else 1,
        "closed_benefit": (
            "Candidate, source-proof, harness-scaffold, filing, and exploit-memory planning routes now have "
            "one fail-closed local status packet proving impact-contract enforcement or advisory-only bypass."
        ),
        "not_submission_evidence": True,
        "routes": routes,
        "summary": {
            "route_count": len(routes),
            "passed_route_count": len(routes) - len(blocked_routes),
            "blocked_route_count": len(blocked_routes),
            "evidence_path_count": len(evidence_paths),
        },
        "blockers": blockers,
        "verification_commands": [
            "python3 -m unittest tools.tests.test_impact_contract_preflight_status -v",
            "python3 -m unittest tools.tests.test_impact_contract_preflight tools.tests.test_source_proof_record tools.tests.test_harness_scaffold_emitter tools.tests.test_exploit_memory_brief tools.tests.test_agent_output_synthesizer_impact_contract tools.tests.test_pre_submit_impact_contract_check -v",
            "python3 -m json.tool reports/impact_contract_preflight_status_2026-05-05.json",
        ],
        "evidence_paths": evidence_paths,
        "changed_paths": [
            "tools/impact-contract-preflight-status.py",
            "tools/tests/test_impact_contract_preflight_status.py",
            "docs/IMPACT_CONTRACT_PREFLIGHT_STATUS_2026-05-05.md",
            "reports/impact_contract_preflight_status_2026-05-05.json",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Impact Contract Preflight Status 2026-05-05",
        "",
        f"- Limitation: `{report['limitation_id']}`",
        f"- Status: `{report['implementation_status']}`",
        f"- Open: `{bool(report['open'])}`",
        f"- Dispatch ready: `{bool(report['dispatch_ready'])}`",
        f"- Expected loop cost: `{report['expected_loop_cost']}`",
        f"- Passed routes: `{summary['passed_route_count']}/{summary['route_count']}`",
        f"- Blocked routes: `{summary['blocked_route_count']}`",
        f"- Closed benefit: {report['closed_benefit']}",
        "",
        "## Route Evidence",
        "",
        "| Route | Surface | Status | Implementation | Test | Strictness |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for route in report["routes"]:
        lines.append(
            "| {route} | {surface} | {status} | `{implementation}` | `{test}` | {strictness} |".format(
                route=route["route"],
                surface=route["surface"],
                status=route["status"],
                implementation=route["implementation"]["path"],
                test=route["test"]["path"],
                strictness=route["strictness"].replace("|", "/"),
            )
        )

    lines.extend(["", "## Blockers", ""])
    if report["blockers"]:
        lines.extend(f"- {blocker}" for blocker in report["blockers"])
    else:
        lines.append("- None.")

    lines.extend(
        [
            "",
            "## Verification",
            "",
            "```sh",
            *report["verification_commands"],
            "```",
            "",
            "## Caveats",
            "",
            "- This is local route-coverage evidence only.",
            "- It is not exploit proof, source proof, or submission proof.",
            "- Exploit-memory route coverage is advisory-only and cannot promote a planning artifact.",
            "",
        ]
    )
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    report = build_report(root)
    json_out = args.json_out or default_json_path(root)
    md_out = args.md_out or default_md_path(root)

    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.write_text(render_markdown(report), encoding="utf-8")

    if args.print_json:
        print(json.dumps(report, indent=2))
    return 1 if report["open"] else 0


if __name__ == "__main__":
    raise SystemExit(_main())
