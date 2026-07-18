#!/usr/bin/env python3
"""Emit the next offline jobs from the commit-mining lifecycle ledger."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.commit_mining_next_jobs.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_PROOF_BOUNDARY = (
    "A next-job row is routing and execution planning only; it does not prove "
    "exploitability, scanner coverage, detector promotion readiness, or "
    "submission readiness."
)
JOB_CLASSES = (
    "ready_jobs",
    "blocked_jobs",
    "detector_needed_jobs",
    "source_needed_jobs",
)
INPUT_REPORTS = {
    "commit_lifecycle_ledger": "reports/commit_lifecycle_ledger_{date}.json",
    "source_mirror_queue": "reports/source_mirror_queue_{date}.json",
    "source_mirror_verify": "reports/source_mirror_verify_{date}.json",
    "detector_proof_gap_queue": "reports/detector_proof_gap_queue_{date}.json",
    "rust_detector_coverage": "reports/rust_detector_coverage_{date}.json",
}
DETECTOR_SECTIONS = (
    "rust_lift_needed",
    "fixture_needed",
    "backend_needed",
)


def _read_json(path: Path, *, required: bool = False) -> Any | None:
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _relpath(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _input_path(repo_root: Path, name: str, date: str) -> Path:
    return repo_root / INPUT_REPORTS[name].format(date=date)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []


def _stable_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug or "job"


def _job_sort_key(job: dict[str, Any]) -> tuple[Any, ...]:
    priority_rank = {"high": 0, "medium": 1, "low": 2}
    class_rank = {name: idx for idx, name in enumerate(JOB_CLASSES)}
    return (
        class_rank.get(str(job.get("job_class")), 99),
        priority_rank.get(str(job.get("priority")), 9),
        str(job.get("job_id") or ""),
    )


def _count_by(jobs: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for job in jobs:
        key = str(job.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"name": key, "count": counts[key]} for key in sorted(counts)]


def _verify_results_by_id(payload: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in _as_list(payload.get("results")):
        if isinstance(row, dict) and row.get("id"):
            out[str(row["id"])] = row
    return out


def _source_job(
    row: dict[str, Any],
    proof_boundary: str,
    verify_by_id: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    row_id = str(row.get("source_row_id") or row.get("row_id") or "source-row")
    ready = row.get("mirror_status") == "queued_for_local_mirror_verification"
    verify_row = (verify_by_id or {}).get(row_id)
    verify_status = str(verify_row.get("status") or "") if isinstance(verify_row, dict) else ""
    verify_blockers = _strings(verify_row.get("blockers")) if isinstance(verify_row, dict) else []

    job_class = "ready_jobs" if ready else "source_needed_jobs"
    lane = "local_mirror_verification" if ready else "source_resolution"
    title = (
        f"Verify local mirror for {row_id}"
        if ready
        else f"Resolve source identity for {row_id}"
    )
    action = (
        "Verify the commit in an existing local mirror, then record the mirror proof before scan-task emission."
        if ready
        else str(row.get("blocker") or row.get("required_resolution") or "Resolve source identity before mining.")
    )
    blocker = None if ready else row.get("blocker")

    if ready and verify_status == "verified":
        lane = "mirror_verified_scan_task_candidate"
        title = f"Convert verified local mirror for {row_id}"
        action = "Use the verified local mirror/ref as input for a bounded source-review or scan-task packet; this is still not exploit proof."
    elif ready and verify_status == "blocked":
        job_class = "source_needed_jobs"
        lane = "local_mirror_verification_blocked"
        title = f"Unblock local mirror for {row_id}"
        action = "; ".join(verify_blockers) or "Local mirror verification blocked."
        blocker = action

    command = str(row.get("safe_local_command_template") or "")
    commands = [] if not command or command.startswith("# blocked:") else [command]
    job = {
        "job_id": f"{'ready' if ready else 'source'}-mirror-{_stable_slug(row_id)}",
        "job_class": job_class,
        "source": "source_mirror_queue",
        "priority": str(row.get("priority") or ("medium" if ready else "low")),
        "lane": lane,
        "title": title,
        "target": row.get("target"),
        "repo": row.get("repo_url"),
        "ref": row.get("ref"),
        "ref_kind": row.get("ref_kind"),
        "row_ids": [row_id],
        "next_action": action,
        "blocker": blocker,
        "commands": commands,
        "evidence_paths": _strings(row.get("evidence_paths")),
        "proof_boundary": proof_boundary,
    }
    if isinstance(verify_row, dict):
        checks = verify_row.get("checks") if isinstance(verify_row.get("checks"), dict) else {}
        job["source_mirror_verify"] = {
            "status": verify_status,
            "blockers": verify_blockers,
            "git_root": checks.get("git_root"),
            "matched_repo_identity": checks.get("matched_repo_identity"),
            "ref_verified": checks.get("ref_verified"),
        }
    return job


def _queue_job_class(item: dict[str, Any]) -> str:
    text = " ".join(
        str(item.get(key) or "")
        for key in ("item_id", "lane", "title", "detail")
    ).lower()
    if any(
        token in text
        for token in (
            "keep closed",
            "self_learning_or_no_action",
            "self-learning rows out",
            "blocked",
            "prerequisite",
            "no action",
            "roadmap",
        )
    ):
        return "blocked_jobs"
    if any(token in text for token in ("source", "corpus", "ref", "mirror", "full-sha", "scan task")):
        return "source_needed_jobs"
    if "detector" in text:
        return "detector_needed_jobs"
    return "blocked_jobs"


def _ledger_queue_job(item: dict[str, Any], proof_boundary: str) -> dict[str, Any] | None:
    item_id = str(item.get("item_id") or "")
    if not item_id:
        return None
    job_class = _queue_job_class(item)
    return {
        "job_id": f"ledger-{_stable_slug(item_id)}",
        "job_class": job_class,
        "source": "commit_lifecycle_ledger.concrete_queue",
        "priority": str(item.get("priority") or "low"),
        "lane": item.get("lane"),
        "title": item.get("title") or item_id,
        "target": None,
        "repo": None,
        "ref": None,
        "ref_kind": None,
        "row_ids": _strings(item.get("row_ids")),
        "next_action": item.get("detail") or item.get("title") or item_id,
        "blocker": "lifecycle queue dependency or no-action guard" if job_class == "blocked_jobs" else None,
        "depends_on": _strings(item.get("depends_on")),
        "commands": [],
        "evidence_paths": _strings(item.get("evidence_paths")),
        "proof_boundary": proof_boundary,
    }


def _detector_rows(detector_queue: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(detector_queue, dict):
        return []
    rows: list[dict[str, Any]] = []
    for section in DETECTOR_SECTIONS:
        bucket = detector_queue.get(section)
        if not isinstance(bucket, dict):
            continue
        for row in _as_list(bucket.get("rows")):
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _detector_job(row: dict[str, Any], proof_boundary: str) -> dict[str, Any]:
    queue_id = str(row.get("queue_id") or row.get("scanner_id") or row.get("detector_id") or "detector")
    blockers = _strings(row.get("blockers"))
    detector_paths = _strings(row.get("detector_paths"))
    commands = [
        command
        for command in (
            row.get("suggested_inspection_command"),
            row.get("suggested_test_command"),
        )
        if isinstance(command, str) and command.strip()
    ]
    return {
        "job_id": f"detector-{_stable_slug(queue_id)}",
        "job_class": "detector_needed_jobs",
        "source": "detector_proof_gap_queue",
        "priority": "high" if row.get("section") == "rust_lift_needed" else "medium",
        "lane": row.get("source_burndown_lane") or row.get("section") or "detector_repair",
        "title": f"Repair detector proof gap for {queue_id}",
        "target": queue_id,
        "repo": None,
        "ref": None,
        "ref_kind": None,
        "row_ids": [queue_id],
        "next_action": row.get("suggested_next_action") or row.get("action") or "Repair detector proof gap.",
        "blocker": ", ".join(blockers) if blockers else None,
        "commands": commands,
        "detector_paths": detector_paths,
        "evidence_paths": _strings(row.get("source_paths")) or detector_paths,
        "proof_boundary": proof_boundary,
    }


def _rust_coverage_jobs(
    rust_coverage: dict[str, Any] | None,
    seen_detector_ids: set[str],
    proof_boundary: str,
) -> list[dict[str, Any]]:
    if not isinstance(rust_coverage, dict):
        return []
    missing = rust_coverage.get("missing_fixture")
    if not isinstance(missing, dict):
        return []

    jobs: list[dict[str, Any]] = []
    for row in _as_list(missing.get("detectors")):
        if not isinstance(row, dict):
            continue
        detector_id = str(row.get("detector_id") or "")
        if not detector_id or detector_id in seen_detector_ids:
            continue
        seen_detector_ids.add(detector_id)
        jobs.append(
            {
                "job_id": f"detector-rust-coverage-{_stable_slug(detector_id)}",
                "job_class": "detector_needed_jobs",
                "source": "rust_detector_coverage",
                "priority": "high",
                "lane": "rust_fixture_or_runner_gap",
                "title": f"Add Rust fixture coverage for {detector_id}",
                "target": detector_id,
                "repo": None,
                "ref": None,
                "ref_kind": None,
                "row_ids": [detector_id],
                "next_action": row.get("suggested_next_action")
                or "Add positive/negative Rust fixtures and runner coverage.",
                "blocker": ", ".join(_strings(row.get("truth_inventory_blockers"))) or None,
                "commands": _strings(row.get("next_commands")),
                "detector_paths": [row.get("detector_path")] if isinstance(row.get("detector_path"), str) else [],
                "evidence_paths": _strings(row.get("next_files")),
                "proof_boundary": proof_boundary,
            }
        )
    return jobs


def build_next_jobs(repo_root: Path, date: str = DEFAULT_DATE) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    input_paths = {name: _input_path(repo_root, name, date) for name in INPUT_REPORTS}
    ledger = _read_json(input_paths["commit_lifecycle_ledger"], required=True)
    source_mirror = _read_json(input_paths["source_mirror_queue"])
    source_mirror_verify = _read_json(input_paths["source_mirror_verify"])
    detector_queue = _read_json(input_paths["detector_proof_gap_queue"])
    rust_coverage = _read_json(input_paths["rust_detector_coverage"])

    if not isinstance(ledger, dict):
        raise ValueError("commit lifecycle ledger must be a JSON object")

    proof_boundary = str(ledger.get("proof_boundary") or DEFAULT_PROOF_BOUNDARY)
    jobs: list[dict[str, Any]] = []
    verify_by_id = _verify_results_by_id(source_mirror_verify if isinstance(source_mirror_verify, dict) else None)

    if isinstance(source_mirror, dict):
        for row in _as_list(source_mirror.get("queue_rows")):
            if isinstance(row, dict):
                jobs.append(_source_job(row, proof_boundary, verify_by_id))

    for item in _as_list(ledger.get("concrete_queue")):
        if isinstance(item, dict):
            job = _ledger_queue_job(item, proof_boundary)
            if job is not None:
                jobs.append(job)

    seen_detector_ids: set[str] = set()
    for row in _detector_rows(detector_queue):
        detector_id = str(row.get("queue_id") or row.get("scanner_id") or row.get("detector_id") or "")
        if detector_id:
            seen_detector_ids.add(detector_id)
        jobs.append(_detector_job(row, proof_boundary))
    jobs.extend(_rust_coverage_jobs(rust_coverage, seen_detector_ids, proof_boundary))

    jobs = sorted(jobs, key=_job_sort_key)
    class_counts = {name: 0 for name in JOB_CLASSES}
    for job in jobs:
        job_class = str(job.get("job_class"))
        class_counts[job_class] = class_counts.get(job_class, 0) + 1

    reports_found = [
        name for name, path in input_paths.items() if path.exists()
    ]
    reports_missing = [
        _relpath(repo_root, path) for path in input_paths.values() if not path.exists()
    ]

    return {
        "schema": SCHEMA,
        "date": date,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "repo_root": str(repo_root),
        "network_used": False,
        "input_reports": {
            name: _relpath(repo_root, path) for name, path in input_paths.items()
        },
        "reports_found": reports_found,
        "reports_missing": reports_missing,
        "proof_boundary": proof_boundary,
        "summary": {
            "job_count": len(jobs),
            "class_counts": class_counts,
            "priority_counts": _count_by(jobs, "priority"),
            "source_counts": _count_by(jobs, "source"),
            "ledger_row_count": len(_as_list(ledger.get("rows"))),
            "ledger_queue_count": len(_as_list(ledger.get("concrete_queue"))),
        },
        "jobs": jobs,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    class_counts = summary.get("class_counts") if isinstance(summary.get("class_counts"), dict) else {}
    date = str(report.get("date") or DEFAULT_DATE)
    lines = [
        f"# Commit Mining Next Jobs - {date}",
        "",
        "Offline runner output from the current commit lifecycle ledger and local reports.",
        "",
        "## Counts",
        "",
        f"- Total jobs: {summary.get('job_count', 0)}",
    ]
    for name in JOB_CLASSES:
        lines.append(f"- {name}: {class_counts.get(name, 0)}")
    lines.extend(
        [
            "",
            "## Proof Boundary",
            "",
            str(report.get("proof_boundary") or DEFAULT_PROOF_BOUNDARY),
            "",
            "## Top Jobs",
            "",
        ]
    )

    jobs = _as_list(report.get("jobs"))
    for job_class in JOB_CLASSES:
        class_jobs = [job for job in jobs if isinstance(job, dict) and job.get("job_class") == job_class]
        lines.append(f"### {job_class}")
        lines.append("")
        if not class_jobs:
            lines.append("- None")
            lines.append("")
            continue
        for job in class_jobs[:10]:
            title = job.get("title") or job.get("job_id")
            priority = job.get("priority") or "unknown"
            lines.append(f"- `{job.get('job_id')}` ({priority}): {title}")
            next_action = job.get("next_action")
            if next_action:
                lines.append(f"  - Next: {next_action}")
        lines.append("")

    lines.extend(
        [
            "## Inputs",
            "",
        ]
    )
    input_reports = report.get("input_reports")
    if isinstance(input_reports, dict):
        for name, path in sorted(input_reports.items()):
            lines.append(f"- {name}: `{path}`")
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--date", default=DEFAULT_DATE)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="JSON output path. Defaults to reports/commit_mining_next_jobs_<date>.json.",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=None,
        help="Markdown output path. Defaults to docs/COMMIT_MINING_NEXT_JOBS_<date>.md.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    report = build_next_jobs(repo_root, args.date)
    out_path = args.out or repo_root / "reports" / f"commit_mining_next_jobs_{args.date}.json"
    md_path = args.markdown_out or repo_root / "docs" / f"COMMIT_MINING_NEXT_JOBS_{args.date}.md"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        counts = report["summary"]["class_counts"]
        print(
            "wrote "
            f"{out_path} and {md_path} "
            f"(ready={counts.get('ready_jobs', 0)}, "
            f"blocked={counts.get('blocked_jobs', 0)}, "
            f"detector_needed={counts.get('detector_needed_jobs', 0)}, "
            f"source_needed={counts.get('source_needed_jobs', 0)})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
