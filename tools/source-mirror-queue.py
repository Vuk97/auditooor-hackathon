#!/usr/bin/env python3
"""Build an offline source mirror/replay queue from existing report artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA = "auditooor.source_mirror_queue.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_REPORTS = {
    "source_ref_plan": "reports/source_ref_replay_manifest_plan_2026-05-05.json",
    "local_corpus": "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
    "commit_lifecycle": "reports/commit_lifecycle_ledger_2026-05-05.json",
}
QUEUE_READY = "queued_for_local_mirror_verification"
QUEUE_BLOCKED = "blocked_pending_resolution"
QUEUE_BLOCKED_MISSING_REPO = "blocked_missing_repo_identity"
PROOF_BOUNDARY = (
    "Queue rows describe source-mirror readiness only; they do not prove exploitability, "
    "scanner coverage, detector promotion readiness, or submission readiness."
)


def _read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _full_sha(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if len(value) == 40 and all(ch in "0123456789abcdef" for ch in value):
        return value
    return None


def _short_sha(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if 7 <= len(value) <= 39 and all(ch in "0123456789abcdef" for ch in value):
        return value
    return None


def _github_repo_url(repo: str | None) -> str | None:
    if not isinstance(repo, str) or not repo.strip() or "/" not in repo:
        return None
    return f"https://github.com/{repo.strip()}"


def _extract_repo_ref_from_url(url: str) -> tuple[str | None, str | None]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None, None
    if parsed.netloc not in {"github.com", "raw.githubusercontent.com"}:
        return None, None

    parts = [part for part in parsed.path.split("/") if part]
    if parsed.netloc == "raw.githubusercontent.com":
        if len(parts) >= 3:
            return f"{parts[0]}/{parts[1]}", parts[2]
        return None, None

    if len(parts) < 4:
        return None, None
    repo = f"{parts[0]}/{parts[1]}"
    kind = parts[2]
    if kind in {"commit", "tree"} and len(parts) >= 4:
        return repo, parts[3]
    if kind == "blob" and len(parts) >= 4:
        return repo, parts[3]
    return repo, None


def _canonical_repo_ref(row: dict[str, Any]) -> tuple[str | None, str | None, str]:
    repo = row.get("repo") if isinstance(row.get("repo"), str) else None
    commit = _full_sha(row.get("commit")) if isinstance(row.get("commit"), str) else None
    ref = row.get("ref") if isinstance(row.get("ref"), str) else None

    if commit:
        return repo, commit, "full_sha"
    if _full_sha(ref):
        return repo, _full_sha(ref), "full_sha"
    if _short_sha(ref):
        return repo, _short_sha(ref), "short_sha"
    if isinstance(ref, str) and ref.startswith(("http://", "https://")):
        parsed_repo, parsed_ref = _extract_repo_ref_from_url(ref)
        repo = repo or parsed_repo
        if _full_sha(parsed_ref):
            return repo, _full_sha(parsed_ref), "full_sha"
        if _short_sha(parsed_ref):
            return repo, _short_sha(parsed_ref), "short_sha"
        if parsed_ref:
            return repo, parsed_ref, "named_ref"
        return repo, ref, "unsupported_url"
    if isinstance(ref, str) and ref.strip():
        return repo, ref.strip(), "named_ref"
    return repo, None, "missing_ref"


def _priority(row: dict[str, Any], ref_kind: str, mirror_status: str) -> str:
    lifecycle_state = str(row.get("lifecycle_state") or "")
    if mirror_status == QUEUE_READY:
        if lifecycle_state in {"context_only_scope_anchor", "self_learning_only", "closed_no_action"}:
            return "medium"
        return "high"
    if ref_kind in {"short_sha", "named_ref"}:
        return "medium" if row.get("repo") else "low"
    return "low"


def _required_resolution(repo_url: str | None, ref_kind: str, mirror_status: str) -> str:
    if mirror_status == QUEUE_READY:
        return "local_mirror_verification"
    if ref_kind == "full_sha":
        return "attach_repo_identity_then_verify_mirror"
    if ref_kind == "short_sha":
        if repo_url:
            return "expand_to_full_sha_lockfile"
        return "attach_repo_identity_and_expand_to_full_sha"
    if ref_kind == "named_ref":
        if repo_url:
            return "pin_named_ref_to_full_sha_lockfile"
        return "attach_repo_identity_and_pin_named_ref"
    return "manual_source_ref_triage"


def _blocker(repo_url: str | None, ref_kind: str, mirror_status: str) -> str | None:
    if mirror_status == QUEUE_READY:
        return None
    if repo_url is None:
        return "repo identity missing; cannot verify or lock the source ref locally"
    if ref_kind == "short_sha":
        return "short SHA is mutable-by-ambiguity until resolved to a full 40-character commit"
    if ref_kind == "named_ref":
        return "named ref is mutable until pinned in a local resolution lockfile"
    if ref_kind == "full_sha":
        return "full SHA exists but the repo identity is still missing"
    return "source ref could not be normalized into a replay-safe local verification target"


def _safe_local_command_template(repo: str | None, ref: str | None, mirror_status: str) -> str:
    if mirror_status != QUEUE_READY or not repo or not ref:
        return (
            "# blocked: resolve repo identity and pin a full 40-character commit before "
            "running any local mirror verification command"
        )
    return f"git -C {{mirror_root}}/{repo} rev-parse --verify {ref}^{{commit}}"


def _row_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        {"high": 0, "medium": 1, "low": 2}.get(str(row.get("priority") or ""), 9),
        str(row.get("repo_url") or ""),
        str(row.get("ref") or ""),
        str(row.get("source_row_id") or ""),
    )


def _count_by(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"name": key, "count": counts[key]} for key in sorted(counts)]


def _git_head_short(repo_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short=9", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value or None


def build_queue(repo_root: Path) -> dict[str, Any]:
    reports = {name: _read_json(repo_root / relpath) for name, relpath in DEFAULT_REPORTS.items()}
    found = [name for name, payload in reports.items() if payload is not None]
    missing = [name for name, payload in reports.items() if payload is None]

    source_ref_plan = reports["source_ref_plan"] if isinstance(reports["source_ref_plan"], dict) else {}
    local_corpus = reports["local_corpus"] if isinstance(reports["local_corpus"], dict) else {}
    lifecycle = reports["commit_lifecycle"] if isinstance(reports["commit_lifecycle"], dict) else {}
    lifecycle_rows = lifecycle.get("rows") if isinstance(lifecycle.get("rows"), list) else []

    queue_rows: list[dict[str, Any]] = []
    for raw in lifecycle_rows:
        if not isinstance(raw, dict):
            continue
        repo, ref, ref_kind = _canonical_repo_ref(raw)
        if ref is None:
            continue
        repo_url = _github_repo_url(repo)
        if ref_kind == "full_sha" and repo_url:
            mirror_status = QUEUE_READY
        elif repo_url is None:
            mirror_status = QUEUE_BLOCKED_MISSING_REPO
        else:
            mirror_status = QUEUE_BLOCKED
        queue_rows.append(
            {
                "source_row_id": raw.get("row_id"),
                "repo_url": repo_url,
                "ref": ref,
                "ref_kind": ref_kind,
                "required_resolution": _required_resolution(repo_url, ref_kind, mirror_status),
                "mirror_status": mirror_status,
                "safe_local_command_template": _safe_local_command_template(repo, ref, mirror_status),
                "blocker": _blocker(repo_url, ref_kind, mirror_status),
                "priority": _priority(raw, ref_kind, mirror_status),
                "source_lifecycle_state": raw.get("lifecycle_state"),
                "source_ref_type": raw.get("ref_type"),
                "target": raw.get("target"),
                "evidence_paths": raw.get("evidence_paths") if isinstance(raw.get("evidence_paths"), list) else [],
            }
        )

    queue_rows.sort(key=_row_sort_key)
    corpus_counts = local_corpus.get("corpus_reference_counts")
    if not isinstance(corpus_counts, list):
        corpus_counts = []

    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "repo_root": str(repo_root),
        "branch": "continuation-plan",
        "repo_head_short": _git_head_short(repo_root),
        "network_used": False,
        "proof_boundary": PROOF_BOUNDARY,
        "reports_found": found,
        "reports_missing": missing,
        "input_reports": {
            name: str(repo_root / relpath)
            for name, relpath in DEFAULT_REPORTS.items()
        },
        "source_ref_manifest_limits": source_ref_plan.get("remaining_limits", []),
        "local_corpus_reference_counts": corpus_counts,
        "summary": {
            "row_count": len(queue_rows),
            "ready_for_local_mirror_verification": sum(
                1 for row in queue_rows if row["mirror_status"] == QUEUE_READY
            ),
            "blocked_rows": sum(1 for row in queue_rows if row["mirror_status"] != QUEUE_READY),
            "mirror_status_counts": _count_by(queue_rows, "mirror_status"),
            "ref_kind_counts": _count_by(queue_rows, "ref_kind"),
            "priority_counts": _count_by(queue_rows, "priority"),
        },
        "queue_rows": queue_rows,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Source Mirror Queue - 2026-05-05",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Repo root: `{report['repo_root']}`",
        f"- Branch: `{report['branch']}`",
        f"- Network used: `{report['network_used']}`",
        f"- Proof boundary: {report['proof_boundary']}",
        f"- Input reports found: {', '.join(report['reports_found']) or 'none'}",
        f"- Input reports missing: {', '.join(report['reports_missing']) or 'none'}",
        "",
        "## Summary",
        "",
        f"- Queue rows: {summary['row_count']}",
        f"- Ready for local mirror verification: {summary['ready_for_local_mirror_verification']}",
        f"- Blocked rows: {summary['blocked_rows']}",
        "",
        "## Mirror Status Counts",
        "",
    ]
    for row in summary["mirror_status_counts"]:
        lines.append(f"- `{row['name']}`: {row['count']}")
    lines.extend(
        [
            "",
            "## Ref Kind Counts",
            "",
        ]
    )
    for row in summary["ref_kind_counts"]:
        lines.append(f"- `{row['name']}`: {row['count']}")
    lines.extend(
        [
            "",
            "## Queue Rows",
            "",
            "| Priority | Repo URL | Ref | Ref Kind | Mirror Status | Required Resolution | Blocker |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in report["queue_rows"]:
        blocker = row["blocker"] or ""
        lines.append(
            "| {priority} | {repo_url} | `{ref}` | `{ref_kind}` | `{mirror_status}` | "
            "`{required_resolution}` | {blocker} |".format(
                priority=row["priority"],
                repo_url=row["repo_url"] or "",
                ref=row["ref"],
                ref_kind=row["ref_kind"],
                mirror_status=row["mirror_status"],
                required_resolution=row["required_resolution"],
                blocker=blocker.replace("|", "\\|"),
            )
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an offline source mirror/replay queue.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing reports/",
    )
    parser.add_argument("--json-out", type=Path, required=True, help="Write the JSON report here.")
    parser.add_argument(
        "--markdown-out",
        type=Path,
        help="Optionally write a markdown summary here.",
    )
    args = parser.parse_args()

    report = build_queue(args.repo_root.resolve())
    args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
