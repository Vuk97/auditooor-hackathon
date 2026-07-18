#!/usr/bin/env python3
"""Emit advisory scan-task packets from mirror-verified commit-mining jobs.

This is deliberately a routing tool. It converts rows whose local source mirror
and commit ref were already verified into bounded source-review tasks. It does
not run scanners, infer exploitability, or produce submission evidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.commit_mining_scan_tasks.v1"
TASK_SCHEMA = "auditooor.commit_mining_scan_task.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_NEXT_JOBS = Path("reports/commit_mining_next_jobs_2026-05-05.json")
DEFAULT_VERIFY = Path("reports/source_mirror_verify_2026-05-05.json")
DEFAULT_OUT = Path("reports/commit_mining_scan_tasks_2026-05-05.json")
DEFAULT_MD_OUT = Path("docs/COMMIT_MINING_SCAN_TASKS_2026-05-05.md")
SOURCE_REVIEW_PROOF_BOUNDARY = (
    "Mirror verification proves only that the local checkout matches the expected "
    "repo identity and that the referenced commit exists locally. These packets "
    "are source-review scan tasks, not exploit proof, detector promotion proof, "
    "impact proof, or submission readiness."
)
MIRROR_VERIFIED_LANE = "mirror_verified_scan_task_candidate"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _stable_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug or "task"


def _relpath(repo_root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path)


def _verify_by_id(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in _as_list(payload.get("results")):
        if isinstance(row, dict) and row.get("id"):
            out[str(row["id"])] = row
    return out


def _job_row_ids(job: dict[str, Any]) -> list[str]:
    return [str(row_id) for row_id in _as_list(job.get("row_ids")) if str(row_id).strip()]


def _verified_checks(row: dict[str, Any]) -> dict[str, Any]:
    checks = row.get("checks")
    return checks if isinstance(checks, dict) else {}


def _job_ref(job: dict[str, Any]) -> str:
    value = job.get("ref")
    return value.strip() if isinstance(value, str) else ""


def _resolved_ref(checks: dict[str, Any]) -> str:
    value = checks.get("resolved_ref")
    return value.strip() if isinstance(value, str) else ""


def _is_verified_job(job: dict[str, Any], verify_index: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    if job.get("job_class") != "ready_jobs":
        return False, "not_ready_job"
    if job.get("lane") != MIRROR_VERIFIED_LANE:
        return False, "not_mirror_verified_lane"

    embedded = job.get("source_mirror_verify")
    if not isinstance(embedded, dict):
        return False, "missing_embedded_source_mirror_verify"
    if embedded.get("status") != "verified" or embedded.get("ref_verified") is not True:
        return False, "embedded_verify_not_verified"

    row_ids = _job_row_ids(job)
    if len(row_ids) != 1:
        return False, "expected_exactly_one_source_row_id"
    verify_row = verify_index.get(row_ids[0])
    if not isinstance(verify_row, dict):
        return False, "missing_source_mirror_verify_result"
    if verify_row.get("status") != "verified":
        return False, "source_mirror_verify_status_not_verified"
    if verify_row.get("blockers"):
        return False, "source_mirror_verify_has_blockers"

    checks = _verified_checks(verify_row)
    if checks.get("ref_verified") is not True:
        return False, "source_mirror_verify_ref_not_verified"
    if not checks.get("git_root"):
        return False, "source_mirror_verify_missing_git_root"
    if not checks.get("matched_repo_identity"):
        return False, "source_mirror_verify_missing_repo_identity"
    resolved_ref = _resolved_ref(checks)
    if not resolved_ref:
        return False, "source_mirror_verify_missing_resolved_ref"
    job_ref = _job_ref(job)
    verified_refs = _strings(checks.get("refs"))
    if job_ref and job_ref != resolved_ref and job_ref not in verified_refs:
        return False, "job_ref_mismatches_source_mirror_resolved_ref"
    return True, ""


def _scan_task(job: dict[str, Any], verify_row: dict[str, Any]) -> dict[str, Any]:
    row_id = _job_row_ids(job)[0]
    checks = _verified_checks(verify_row)
    git_root = str(checks.get("git_root") or "")
    commit_sha = _resolved_ref(checks)
    repo_identity = str(checks.get("matched_repo_identity") or "")
    task_id = f"scan-task-{_stable_slug(row_id)}"

    return {
        "schema": TASK_SCHEMA,
        "task_id": task_id,
        "source_job_id": job.get("job_id"),
        "source_row_id": row_id,
        "task_type": "source_review_scan_task",
        "lane": "mirror_verified_source_review",
        "target": job.get("target"),
        "repo_url": job.get("repo"),
        "repo_identity": repo_identity,
        "git_root": git_root,
        "commit_sha": commit_sha,
        "ref_kind": job.get("ref_kind"),
        "advisory_only": True,
        "submit_ready": False,
        "evidence_class": "mirror_verified_source_review_task",
        "exploit_proof": False,
        "severity_claim": "",
        "exploitability_claim": "",
        "impact_claim": "",
        "proof_boundary": SOURCE_REVIEW_PROOF_BOUNDARY,
        "source_mirror_verify": {
            "status": verify_row.get("status"),
            "ref_verified": checks.get("ref_verified"),
            "git_root": git_root,
            "matched_repo_identity": repo_identity,
            "head": checks.get("head"),
            "branch": checks.get("branch"),
            "refs": _strings(checks.get("refs")),
            "resolved_ref": commit_sha,
        },
        "review_objective": (
            "Inspect this verified local source ref for reusable source-review leads "
            "and scanner seeds. Stop at source-review disposition unless separate "
            "local impact proof is produced later."
        ),
        "allowed_actions": [
            "inspect local source and patch context",
            "run offline source or semantic scanners against the verified checkout",
            "record killed/duplicate/source-review-only disposition",
        ],
        "disallowed_claims": [
            "severity",
            "exploitability",
            "impact",
            "submission readiness",
            "detector promotion readiness",
        ],
        "terminal_state_options": [
            "source_review_lead_recorded",
            "killed_duplicate_or_oos",
            "needs_detector_or_fixture_followup",
            "needs_separate_impact_proof",
        ],
        "suggested_commands": [
            f"git -C {git_root} rev-parse --verify {commit_sha}^{{commit}}",
            f"git -C {git_root} show --stat --patch --find-renames {commit_sha}",
        ],
        "source_next_action": job.get("next_action"),
        "evidence_paths": _strings(job.get("evidence_paths")),
    }


def build_scan_tasks(
    *,
    repo_root: Path,
    next_jobs_path: Path = DEFAULT_NEXT_JOBS,
    verify_path: Path = DEFAULT_VERIFY,
    date: str = DEFAULT_DATE,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    next_jobs_abs = next_jobs_path if next_jobs_path.is_absolute() else repo_root / next_jobs_path
    verify_abs = verify_path if verify_path.is_absolute() else repo_root / verify_path
    next_jobs = _read_json(next_jobs_abs)
    verify = _read_json(verify_abs)
    if not isinstance(next_jobs, dict):
        raise ValueError("next-jobs JSON must be an object")
    if not isinstance(verify, dict):
        raise ValueError("source-mirror-verify JSON must be an object")

    verify_index = _verify_by_id(verify)
    tasks: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for job in _as_list(next_jobs.get("jobs")):
        if not isinstance(job, dict):
            continue
        ok, reason = _is_verified_job(job, verify_index)
        if not ok:
            skipped.append(
                {
                    "job_id": job.get("job_id"),
                    "row_ids": _job_row_ids(job),
                    "job_class": job.get("job_class"),
                    "lane": job.get("lane"),
                    "reason": reason,
                }
            )
            continue
        row_id = _job_row_ids(job)[0]
        tasks.append(_scan_task(job, verify_index[row_id]))

    tasks = sorted(tasks, key=lambda row: str(row.get("task_id")))
    skipped = sorted(skipped, key=lambda row: str(row.get("job_id") or ""))
    target_counts: dict[str, int] = {}
    repo_counts: dict[str, int] = {}
    for task in tasks:
        target = str(task.get("target") or "unknown")
        repo = str(task.get("repo_identity") or "unknown")
        target_counts[target] = target_counts.get(target, 0) + 1
        repo_counts[repo] = repo_counts.get(repo, 0) + 1

    return {
        "schema": SCHEMA,
        "date": date,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "repo_root": str(repo_root),
        "network_used": False,
        "input_reports": {
            "commit_mining_next_jobs": _relpath(repo_root, next_jobs_abs),
            "source_mirror_verify": _relpath(repo_root, verify_abs),
        },
        "advisory_only": True,
        "submit_ready": False,
        "evidence_class": "mirror_verified_source_review_task",
        "proof_boundary": SOURCE_REVIEW_PROOF_BOUNDARY,
        "summary": {
            "input_job_count": len(_as_list(next_jobs.get("jobs"))),
            "source_mirror_verify_result_count": len(_as_list(verify.get("results"))),
            "emitted_task_count": len(tasks),
            "skipped_job_count": len(skipped),
            "target_counts": dict(sorted(target_counts.items())),
            "repo_counts": dict(sorted(repo_counts.items())),
        },
        "tasks": tasks,
        "skipped_jobs": skipped,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    tasks = [task for task in _as_list(report.get("tasks")) if isinstance(task, dict)]
    lines = [
        f"# Commit Mining Scan Tasks - {report.get('date') or DEFAULT_DATE}",
        "",
        "Offline source-review packets emitted only for mirror-verified next-job rows.",
        "",
        "## Counts",
        "",
        f"- Input jobs: {summary.get('input_job_count', 0)}",
        f"- Source mirror verify rows: {summary.get('source_mirror_verify_result_count', 0)}",
        f"- Emitted scan tasks: {summary.get('emitted_task_count', 0)}",
        f"- Skipped jobs: {summary.get('skipped_job_count', 0)}",
        "",
        "## Proof Boundary",
        "",
        str(report.get("proof_boundary") or SOURCE_REVIEW_PROOF_BOUNDARY),
        "",
        "## Emitted Tasks",
        "",
    ]
    if not tasks:
        lines.append("- None")
    for task in tasks:
        lines.append(
            f"- `{task.get('task_id')}`: `{task.get('repo_identity')}` "
            f"`{task.get('commit_sha')}` ({task.get('source_row_id')})"
        )
        lines.append(f"  - Git root: `{task.get('git_root')}`")
        lines.append("  - Claim boundary: advisory source-review task; no exploit, severity, impact, or submission claim.")
    lines.extend(["", "## Inputs", ""])
    input_reports = report.get("input_reports")
    if isinstance(input_reports, dict):
        for name, path in sorted(input_reports.items()):
            lines.append(f"- {name}: `{path}`")
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--date", default=DEFAULT_DATE)
    parser.add_argument("--next-jobs", type=Path, default=DEFAULT_NEXT_JOBS)
    parser.add_argument("--source-mirror-verify", type=Path, default=DEFAULT_VERIFY)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--markdown-out", type=Path, default=DEFAULT_MD_OUT)
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    report = build_scan_tasks(
        repo_root=repo_root,
        next_jobs_path=args.next_jobs,
        verify_path=args.source_mirror_verify,
        date=args.date,
    )
    out_path = args.out if args.out.is_absolute() else repo_root / args.out
    md_path = args.markdown_out if args.markdown_out.is_absolute() else repo_root / args.markdown_out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        count = report["summary"]["emitted_task_count"]
        skipped = report["summary"]["skipped_job_count"]
        print(f"wrote {out_path} and {md_path} (scan_tasks={count}, skipped_jobs={skipped})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
