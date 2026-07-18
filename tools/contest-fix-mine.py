#!/usr/bin/env python3
"""contest-fix-mine.py — advisory-only Phase 2 seed for §J contest mining.

This tool consumes the Phase 1 contest registry plus the fetched repo layout
under `/private/tmp/contest_targets/` and emits bounded scan-task artifacts
from real post-audit Git commits.

Hard rules:
  - Advisory only. Output rows are scan tasks, not findings.
  - Every row stamps `evidence_class: advisory_fix_commit_diff`.
  - Every row stamps `submit_ready: false`.
  - No severity, exploitability, or submission claim is emitted.
  - Fail closed when operator-pinned commit or fetched repo inputs are missing.

Usage:
  python3 tools/contest-fix-mine.py --contest-id cantina-morpho-blue-2024q1
  python3 tools/contest-fix-mine.py --contest-id ... --output-dir /tmp/out
  python3 tools/contest-fix-mine.py --contest-id ... --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "reference" / "contest_registry.jsonl"
DEFAULT_FETCH_ROOT = Path("/private/tmp/contest_targets")
DEFAULT_OUTPUT_ROOT = "contest_fix_mines"
TASK_SCHEMA = "auditooor.contest_fix_scan_task.v1"
SUMMARY_SCHEMA = "auditooor.contest_fix_mine.v1"
REVIEW_SCHEMA = "auditooor.contest_fix_exploit_review.v1"
REVIEW_PACKET_SCHEMA = "auditooor.contest_fix_exploit_review_packet.v1"
TODO_PIN = "<TODO_OPERATOR>"
KEYWORD_RE = re.compile(
    r"(?:fix|audit|vuln|secur|cve|bounty|disclos|reentr|overflow|underflow|"
    r"[hmc]-[0-9]+|spearbit|trail[ ._-]?of[ ._-]?bits|cantina|sherlock|"
    r"code4rena|immunefi|access[ ._-]?control|privilege)",
    re.I,
)
SOURCE_EXTENSIONS = {".sol", ".rs", ".move", ".vy"}
MAX_CANDIDATE_COMMITS = 25
MAX_CHANGED_SOURCE_FILES = 3
MAX_CHANGED_SOURCE_LINES = 200
MAX_REVIEW_PACKETS = 10
MAX_PROOF_FOLLOWONS = 3

FIX_SHAPE_PATTERNS = [
    (re.compile(r"^\+\s*require\s*\("), "added-require"),
    (re.compile(r"^\+.*nonReentrant"), "added-nonreentrant"),
    (re.compile(r"^\+.*onlyRole|^\+.*onlyOwner"), "added-access-control"),
    (re.compile(r"^\+.*SafeERC20|^\+.*safeTransfer"), "added-safe-transfer"),
    (re.compile(r"^\+.*whenNotPaused"), "added-pause-check"),
    (re.compile(r"^\-.*\babi\.encodePacked\b.*\+.*\babi\.encode\b"), "encodePacked-to-encode"),
    (re.compile(r"^\+.*uint(8|16|32|64|128|248)"), "downsize-uint"),
    (re.compile(r"^\+.*block\.timestamp.*[<>]=?"), "added-timestamp-check"),
    (re.compile(r"^\+.*!=\s*address\(0\)|^\+.*==\s*address\(0\)"), "added-zero-address-check"),
    (re.compile(r"^\+.*slippage|^\+.*minOut|^\+.*minAmount"), "added-slippage-guard"),
    (re.compile(r"^\+.*deadline"), "added-deadline"),
    (re.compile(r"^\+.*chainid|^\+.*block\.chainid"), "added-chainid-binding"),
    (re.compile(r"^\-.*ecrecover"), "removed-raw-ecrecover"),
    (re.compile(r"^\+.*accrueInterest|^\+.*_accrue"), "added-accrue-first"),
    (re.compile(r"^\+.*_disableInitializers"), "added-disable-initializers"),
    (re.compile(r"^\-.*delegatecall"), "removed-delegatecall"),
    (re.compile(r"^\+.*mulDiv|^\+.*FullMath"), "added-mulDiv-math"),
]


class ContestFixMineError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepoSpec:
    url: str
    commit_pin: str
    notes: str

    @property
    def basename(self) -> str:
        stripped = self.url.rstrip("/")
        stripped = stripped[:-4] if stripped.endswith(".git") else stripped
        return Path(stripped).name or "repo"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ContestFixMineError(f"invalid JSONL {path}:{lineno}: {exc}") from exc
            if not isinstance(row, dict):
                raise ContestFixMineError(f"invalid JSONL {path}:{lineno}: row must be object")
            rows.append(row)
    return rows


def load_registry_row(contest_id: str, registry_path: Path = REGISTRY_PATH) -> dict[str, Any]:
    for row in _read_jsonl(registry_path):
        if row.get("contest_id") == contest_id:
            return row
    raise ContestFixMineError(f"contest_id not found in registry: {contest_id}")


def repo_specs(row: dict[str, Any]) -> list[RepoSpec]:
    raw_repos = row.get("target_repos")
    if not isinstance(raw_repos, list) or not raw_repos:
        raise ContestFixMineError(f"contest {row.get('contest_id')} has no target_repos")
    specs: list[RepoSpec] = []
    for raw in raw_repos:
        if not isinstance(raw, dict):
            raise ContestFixMineError("target_repos rows must be objects")
        url = str(raw.get("url") or "").strip()
        commit_pin = str(raw.get("commit_pin") or "").strip()
        notes = str(raw.get("notes") or "").strip()
        if not url or not commit_pin:
            raise ContestFixMineError("target_repos rows require url and commit_pin")
        if commit_pin == TODO_PIN:
            raise ContestFixMineError(
                f"contest {row.get('contest_id')} repo {url} still has operator TODO commit_pin"
            )
        specs.append(RepoSpec(url=url, commit_pin=commit_pin, notes=notes))
    return specs


def _run_git(args: list[str], cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ContestFixMineError(
            f"git {' '.join(args)} failed in {cwd}: {proc.stderr.strip()[:200]}"
        )
    return proc.stdout


def _run_git_with_input(args: list[str], cwd: Path, stdin: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ContestFixMineError(
            f"git {' '.join(args)} failed in {cwd}: {proc.stderr.strip()[:200]}"
        )
    return proc.stdout


def _fetch_repo_dir(fetch_root: Path, contest_id: str, spec: RepoSpec) -> Path:
    repo_dir = fetch_root / contest_id / spec.basename
    if not repo_dir.is_dir():
        raise ContestFixMineError(f"missing fetched repo dir: {repo_dir}")
    if not (repo_dir / "pre_audit").is_dir():
        raise ContestFixMineError(f"missing pre_audit worktree: {repo_dir / 'pre_audit'}")
    if not (repo_dir / "post_audit").is_dir():
        raise ContestFixMineError(f"missing post_audit worktree: {repo_dir / 'post_audit'}")
    return repo_dir


def _is_source_file(path: str) -> bool:
    p = Path(path)
    if p.suffix.lower() not in SOURCE_EXTENSIONS:
        return False
    lower = path.lower()
    return not any(part in lower for part in ("/test", "/tests", "/mock", "/mocks"))


def _classify_bug_hints(message: str, patch_text: str, files: list[str]) -> list[str]:
    text = " ".join([message, patch_text, " ".join(files)]).lower()
    hints: list[str] = []
    patterns = [
        ("access-control", ("onlyowner", "role", "admin", "permission", "auth")),
        ("reentrancy", ("reentrant", "nonreentrant", ".call(", "callback")),
        ("oracle-validation", ("oracle", "price", "stale", "roundid", "answeredinround")),
        ("share-accounting", ("erc4626", "converttoshares", "previewdeposit", "totalassets", "shares")),
        ("slippage-validation", ("slippage", "minamount", "amountoutminimum", "priceimpact")),
        ("bounds-check", ("require(", "revert", "overflow", "underflow", "bounds")),
    ]
    for label, tokens in patterns:
        if any(token in text for token in tokens):
            hints.append(label)
    return hints or ["generic-fix-diff"]


def _classify_fix_shapes(patch_text: str) -> list[str]:
    shapes: list[str] = []
    for line in patch_text.splitlines():
        for rx, tag in FIX_SHAPE_PATTERNS:
            if rx.search(line) and tag not in shapes:
                shapes.append(tag)
    return shapes


def _changed_source_line_count(changed_files: list[dict[str, Any]]) -> int:
    total = 0
    for row in changed_files:
        try:
            total += int(row.get("additions") or 0) + int(row.get("deletions") or 0)
        except (TypeError, ValueError):
            continue
    return total


def _repo_dir_from_task(task: dict[str, Any]) -> Path:
    source_ref = str(task.get("source_ref") or "").strip()
    if source_ref:
        path = Path(source_ref)
        if path.name == "post_audit":
            return path.parent
        return path
    raise ContestFixMineError("scan task has no source_ref")


def _local_mirror_status(repo_dir: Path, commit_pin: str) -> dict[str, Any]:
    pre = repo_dir / "pre_audit"
    post = repo_dir / "post_audit"
    return {
        "repo_dir": str(repo_dir),
        "pre_audit_exists": pre.is_dir(),
        "post_audit_exists": post.is_dir(),
        "commit_pin": commit_pin,
        "commit_pin_resolved": bool(commit_pin and commit_pin != TODO_PIN),
    }


def _source_diff_and_patch_id(
    *,
    repo_dir: Path,
    commit_sha: str,
    paths: list[str],
) -> tuple[str, str]:
    patch = _run_git(
        ["show", "--format=", "--patch", "--unified=3", commit_sha, "--", *paths],
        cwd=repo_dir / "post_audit",
    )
    if not patch.strip():
        raise ContestFixMineError("source-only diff unavailable")
    try:
        out = _run_git_with_input(["patch-id", "--stable"], cwd=repo_dir / "post_audit", stdin=patch)
        patch_id = out.split()[0] if out.split() else ""
    except ContestFixMineError:
        patch_id = ""
    if not patch_id:
        patch_id = hashlib.sha256(patch.encode("utf-8", "ignore")).hexdigest()
    return patch, patch_id


def _existing_class_hits(fix_shapes: list[str], repo_root: Path = REPO_ROOT) -> tuple[list[str], list[str]]:
    corpora = [
        repo_root / "reference" / "patterns.dsl",
        repo_root / "detectors" / "_tier_registry.yaml",
        repo_root / "tools" / "novelty_promotion_log.json",
    ]
    missing = [str(path) for path in corpora if not path.exists()]
    if not fix_shapes:
        return [], missing

    haystacks: list[tuple[str, str]] = []
    for path in corpora:
        if not path.exists():
            continue
        if path.is_file():
            try:
                haystacks.append((str(path), path.read_text(errors="ignore")[:500_000]))
            except OSError:
                continue
            continue
        for child in path.rglob("*"):
            if not child.is_file() or child.suffix.lower() not in {".yaml", ".yml", ".json", ".py", ".md"}:
                continue
            try:
                haystacks.append((str(child), child.read_text(errors="ignore")[:80_000]))
            except OSError:
                continue

    hits: list[str] = []
    for shape in fix_shapes:
        for source, text in haystacks:
            if shape in text:
                hits.append(f"{shape}:{source}")
                break
    return hits, missing


def _changed_files(repo_dir: Path, base_commit: str, head_commit: str) -> list[dict[str, Any]]:
    diff_range = f"{base_commit}..{head_commit}"
    out = _run_git(["diff", "--name-only", diff_range], cwd=repo_dir / "post_audit")
    files = [line.strip() for line in out.splitlines() if line.strip()]
    rows: list[dict[str, Any]] = []
    for rel in files:
        if not _is_source_file(rel):
            continue
        added = _run_git(["diff", "--numstat", diff_range, "--", rel], cwd=repo_dir / "post_audit")
        additions = deletions = 0
        for line in added.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2] == rel:
                try:
                    additions = int(parts[0]) if parts[0].isdigit() else 0
                    deletions = int(parts[1]) if parts[1].isdigit() else 0
                except ValueError:
                    additions = deletions = 0
        rows.append(
            {
                "path": rel,
                "additions": additions,
                "deletions": deletions,
            }
        )
    return rows


def _task_row(
    *,
    contest: dict[str, Any],
    spec: RepoSpec,
    repo_dir: Path,
    commit_sha: str,
    subject: str,
    changed_files: list[dict[str, Any]],
    patch_excerpt: str,
) -> dict[str, Any]:
    bug_hints = _classify_bug_hints(subject, patch_excerpt, [row["path"] for row in changed_files])
    return {
        "schema": TASK_SCHEMA,
        "contest_id": str(contest.get("contest_id") or ""),
        "platform": str(contest.get("platform") or ""),
        "protocol": str(contest.get("protocol") or ""),
        "repo_url": spec.url,
        "repo_basename": spec.basename,
        "audit_window_end_commit": spec.commit_pin,
        "commit_sha": commit_sha,
        "commit_subject": subject,
        "changed_files": changed_files,
        "bug_class_hints": bug_hints,
        "source_ref": f"{repo_dir}/post_audit",
        "evidence_class": "advisory_fix_commit_diff",
        "submit_ready": False,
        "severity_claim": "",
        "exploitability_claim": "",
        "impact_claim": "",
        "next_action": "review changed source files and run source/semantic scan; do not infer exploitability from fix diff alone",
        "suggested_commands": [
            f"git -C {repo_dir / 'post_audit'} show --stat --patch {commit_sha}",
            f"rg -n \"{re.escape(spec.basename)}\" {repo_dir / 'post_audit'}",
        ],
        "notes": [
            "Advisory scan task only.",
            "Pre/post diff is a high-signal source of scan leads, not proof of exploitability.",
        ],
        "patch_excerpt": patch_excerpt,
    }


def build_payload(
    *,
    contest_id: str,
    registry_path: Path = REGISTRY_PATH,
    fetch_root: Path = DEFAULT_FETCH_ROOT,
    output_dir: Path | None = None,
) -> tuple[dict[str, Any], Path]:
    contest = load_registry_row(contest_id, registry_path=registry_path)
    specs = repo_specs(contest)
    output_root = output_dir or (REPO_ROOT / DEFAULT_OUTPUT_ROOT / contest_id)
    tasks: list[dict[str, Any]] = []
    repo_summaries: list[dict[str, Any]] = []
    for spec in specs:
        repo_dir = _fetch_repo_dir(fetch_root, contest_id, spec)
        log_out = _run_git(
            [
                "log",
                "--pretty=%H\t%s",
                f"{spec.commit_pin}..HEAD",
            ],
            cwd=repo_dir / "post_audit",
        )
        candidates = []
        for line in log_out.splitlines():
            if "\t" not in line:
                continue
            sha, subject = line.split("\t", 1)
            if not KEYWORD_RE.search(subject):
                continue
            changed = _changed_files(repo_dir, f"{sha}^", sha)
            if not changed:
                continue
            patch = _run_git(["show", "--format=", "--unified=3", sha, "--", *[row["path"] for row in changed]], cwd=repo_dir / "post_audit")
            excerpt = "\n".join(line for line in patch.splitlines()[:80]).strip()
            candidates.append(
                _task_row(
                    contest=contest,
                    spec=spec,
                    repo_dir=repo_dir,
                    commit_sha=sha,
                    subject=subject,
                    changed_files=changed,
                    patch_excerpt=excerpt,
                )
            )
        repo_summaries.append(
            {
                "repo_url": spec.url,
                "repo_basename": spec.basename,
                "audit_window_end_commit": spec.commit_pin,
                "candidate_task_count": len(candidates),
            }
        )
        tasks.extend(candidates)
    payload = {
        "schema": SUMMARY_SCHEMA,
        "generated_at_utc": _now_iso(),
        "contest_id": contest_id,
        "platform": contest.get("platform"),
        "protocol": contest.get("protocol"),
        "advisory_only": True,
        "submit_ready": False,
        "evidence_class": "advisory_fix_commit_diff",
        "task_count": len(tasks),
        "repos": repo_summaries,
        "tasks": tasks,
    }
    return payload, output_root


def _offline_blocker_payload(contest_id: str, blocker: str, detail: str) -> dict[str, Any]:
    return {
        "schema": REVIEW_SCHEMA,
        "generated_at_utc": _now_iso(),
        "contest_id": contest_id,
        "advisory_only": True,
        "submit_ready": False,
        "evidence_class": "advisory_fix_commit_diff",
        "candidate_commit_count": 0,
        "ranked_packet_count": 0,
        "blocked_packet_count": 1,
        "proof_followon_count": 0,
        "limits": {
            "max_candidate_commits": MAX_CANDIDATE_COMMITS,
            "max_changed_source_files": MAX_CHANGED_SOURCE_FILES,
            "max_changed_source_lines": MAX_CHANGED_SOURCE_LINES,
            "max_review_packets": MAX_REVIEW_PACKETS,
            "max_proof_followons": MAX_PROOF_FOLLOWONS,
        },
        "review_packets": [],
        "blocked_packets": [
            {
                "schema": REVIEW_PACKET_SCHEMA,
                "contest_id": contest_id,
                "rank": None,
                "review_verdict": "blocked_missing_local_context",
                "score": 0,
                "blockers": [blocker],
                "blocker_detail": detail,
                "advisory_only": True,
                "submit_ready": False,
                "evidence_class": "advisory_fix_commit_diff",
                "dedupe": {
                    "dedupe_key": "",
                    "patch_id": "",
                    "duplicate_in_run": False,
                    "duplicate_of": "",
                },
                "originality_gate": {
                    "status": "not_run_blocked",
                    "covered_by_existing_class": False,
                    "matching_existing_classes": [],
                    "required_before_poc": [
                        "tools/submission-corpus-map.py",
                        "tools/variant-detector.py",
                    ],
                    "poc_investment_allowed": False,
                },
            }
        ],
        "proof_followon_candidates": [],
    }


def _score_packet(
    *,
    subject: str,
    bug_hints: list[str],
    fix_shapes: list[str],
    file_count: int,
    total_lines: int,
) -> tuple[int, list[str]]:
    score = 0
    signals: list[str] = []
    if KEYWORD_RE.search(subject):
        score += 20
        signals.append("commit_subject_keyword_hit")
    if 0 < file_count <= MAX_CHANGED_SOURCE_FILES:
        score += 15
        signals.append("bounded_production_source_file_count")
    if 0 < total_lines <= 50:
        score += 15
        signals.append("small_patch_size")
    elif total_lines <= MAX_CHANGED_SOURCE_LINES:
        score += 8
        signals.append("medium_patch_size")
    if bug_hints and bug_hints != ["generic-fix-diff"]:
        score += 15
        signals.append("specific_bug_class_hint")
    if fix_shapes:
        score += 20
        signals.append("recognized_fix_shape")
    return score, signals


def _review_verdict(score: int, blockers: list[str]) -> str:
    if blockers:
        return "blocked_missing_local_context"
    if score >= 65:
        return "high_signal_exploit_seed"
    if score >= 40:
        return "needs_local_scan_only"
    return "source_only_not_exploitable_yet"


def _review_packet_for_task(
    task: dict[str, Any],
    *,
    seen_patch_ids: dict[str, str],
) -> dict[str, Any]:
    blockers: list[str] = []
    commit_sha = str(task.get("commit_sha") or "")
    subject = str(task.get("commit_subject") or "")
    changed_files = [row for row in task.get("changed_files", []) if isinstance(row, dict)]
    changed_paths = [str(row.get("path") or "") for row in changed_files if row.get("path")]
    total_lines = _changed_source_line_count(changed_files)
    file_count = len(changed_files)
    commit_pin = str(task.get("audit_window_end_commit") or "")
    repo_basename = str(task.get("repo_basename") or "")
    repo_dir = Path(".")
    mirror_status: dict[str, Any] = {}
    patch_text = str(task.get("patch_excerpt") or "")
    patch_id = ""

    try:
        repo_dir = _repo_dir_from_task(task)
        mirror_status = _local_mirror_status(repo_dir, commit_pin)
        if not mirror_status["commit_pin_resolved"]:
            blockers.append("unresolved_commit_pin")
        if not mirror_status["pre_audit_exists"]:
            blockers.append("missing_pre_audit")
        if not mirror_status["post_audit_exists"]:
            blockers.append("missing_post_audit")
        if not changed_paths:
            blockers.append("no_changed_source_files")
        if file_count > MAX_CHANGED_SOURCE_FILES:
            blockers.append("source_file_bound_exceeded")
        if total_lines > MAX_CHANGED_SOURCE_LINES:
            blockers.append("source_line_bound_exceeded")
        if not blockers:
            patch_text, patch_id = _source_diff_and_patch_id(
                repo_dir=repo_dir,
                commit_sha=commit_sha,
                paths=changed_paths,
            )
    except ContestFixMineError as exc:
        blockers.append(str(exc))
        if not mirror_status:
            mirror_status = {
                "repo_dir": str(repo_dir),
                "pre_audit_exists": False,
                "post_audit_exists": False,
                "commit_pin": commit_pin,
                "commit_pin_resolved": bool(commit_pin and commit_pin != TODO_PIN),
            }

    if patch_id and patch_id in seen_patch_ids:
        blockers.append("duplicate_patch_in_run")
        duplicate_of = seen_patch_ids[patch_id]
    else:
        duplicate_of = ""
        if patch_id:
            seen_patch_ids[patch_id] = commit_sha

    fix_shapes = _classify_fix_shapes(patch_text)
    bug_hints = [str(item) for item in task.get("bug_class_hints", [])]
    score, signals = _score_packet(
        subject=subject,
        bug_hints=bug_hints,
        fix_shapes=fix_shapes,
        file_count=file_count,
        total_lines=total_lines,
    )
    if blockers:
        score = 0
    class_hits, missing_corpora = _existing_class_hits(fix_shapes)
    covered_by_existing_class = bool(class_hits)
    status = "covered_by_existing_class" if covered_by_existing_class else "not_run_no_candidate_draft"
    dedupe_key = "|".join(
        [
            "contest_fix_commit",
            str(task.get("contest_id") or ""),
            repo_basename,
            patch_id or commit_sha,
        ]
    )
    scanner_workspace = repo_dir / "post_audit"
    return {
        "schema": REVIEW_PACKET_SCHEMA,
        "contest_id": str(task.get("contest_id") or ""),
        "platform": str(task.get("platform") or ""),
        "protocol": str(task.get("protocol") or ""),
        "repo_url": str(task.get("repo_url") or ""),
        "repo_basename": repo_basename,
        "audit_window_end_commit": commit_pin,
        "commit_sha": commit_sha,
        "commit_subject": subject,
        "changed_files": changed_files,
        "changed_source_file_count": file_count,
        "total_changed_source_lines": total_lines,
        "inferred_fix_shape": fix_shapes or ["unclassified-fix-shape"],
        "bug_class_hints": bug_hints,
        "rank": None,
        "score": score,
        "rank_signals": signals,
        "review_verdict": _review_verdict(score, blockers),
        "local_mirror_status": mirror_status,
        "dedupe": {
            "dedupe_key": dedupe_key,
            "patch_id": patch_id,
            "duplicate_in_run": bool(duplicate_of),
            "duplicate_of": duplicate_of,
        },
        "originality_gate": {
            "status": status,
            "covered_by_existing_class": covered_by_existing_class,
            "matching_existing_classes": class_hits,
            "missing_local_corpora": missing_corpora,
            "required_before_poc": [
                "tools/submission-corpus-map.py <workspace> <candidate-brief.md>",
                "tools/variant-detector.py <workspace> <candidate-brief.md> --json",
            ],
            "poc_investment_allowed": False,
            "reason": "review packet is not a candidate draft and local novelty/variant gates have not run",
        },
        "downstream_scanner_commands": [
            f"python3 tools/workspace-scan-orchestrator.py --workspace {scanner_workspace}",
            f"git -C {scanner_workspace} show --stat --patch {commit_sha}",
        ],
        "blockers": blockers,
        "proof_followon_slot": False,
        "advisory_only": True,
        "submit_ready": False,
        "evidence_class": "advisory_fix_commit_diff",
        "severity_claim": "",
        "exploitability_claim": "",
        "impact_claim": "",
    }


def build_review_payload(scan_payload: dict[str, Any]) -> dict[str, Any]:
    tasks = list(scan_payload.get("tasks") or [])[:MAX_CANDIDATE_COMMITS]
    seen_patch_ids: dict[str, str] = {}
    packets = [
        _review_packet_for_task(task, seen_patch_ids=seen_patch_ids)
        for task in tasks
        if isinstance(task, dict)
    ]
    ranked = [p for p in packets if not p["blockers"]]
    ranked.sort(key=lambda row: (-int(row["score"]), row["commit_sha"]))
    ranked = ranked[:MAX_REVIEW_PACKETS]
    for idx, packet in enumerate(ranked, 1):
        packet["rank"] = idx
    proof_followons = []
    for packet in ranked:
        if len(proof_followons) >= MAX_PROOF_FOLLOWONS:
            break
        if packet["review_verdict"] in {"high_signal_exploit_seed", "needs_local_scan_only"}:
            packet["proof_followon_slot"] = True
            proof_followons.append(packet)
    blocked = [p for p in packets if p["blockers"]]
    return {
        "schema": REVIEW_SCHEMA,
        "generated_at_utc": _now_iso(),
        "contest_id": str(scan_payload.get("contest_id") or ""),
        "platform": scan_payload.get("platform"),
        "protocol": scan_payload.get("protocol"),
        "advisory_only": True,
        "submit_ready": False,
        "evidence_class": "advisory_fix_commit_diff",
        "candidate_commit_count": len(tasks),
        "ranked_packet_count": len(ranked),
        "blocked_packet_count": len(blocked),
        "proof_followon_count": len(proof_followons),
        "limits": {
            "max_candidate_commits": MAX_CANDIDATE_COMMITS,
            "max_changed_source_files": MAX_CHANGED_SOURCE_FILES,
            "max_changed_source_lines": MAX_CHANGED_SOURCE_LINES,
            "max_review_packets": MAX_REVIEW_PACKETS,
            "max_proof_followons": MAX_PROOF_FOLLOWONS,
        },
        "review_packets": ranked,
        "blocked_packets": blocked,
        "proof_followon_candidates": proof_followons,
    }


def load_scan_tasks(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return _offline_blocker_payload("", "missing_scan_tasks_json", f"missing scan_tasks.json: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _offline_blocker_payload("", "invalid_scan_tasks_json", str(exc))
    if not isinstance(payload, dict):
        return _offline_blocker_payload("", "invalid_scan_tasks_json", "scan_tasks.json root must be an object")
    return payload


def write_review_outputs(payload: dict[str, Any], output_root: Path) -> tuple[Path, Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    json_path = output_root / "review_packets.json"
    md_path = output_root / "review_packets.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Contest Fix-Commit Review Packets",
        "",
        f"- contest_id: `{payload.get('contest_id', '')}`",
        "- advisory_only: `true`",
        f"- evidence_class: `{payload['evidence_class']}`",
        f"- ranked_packet_count: `{payload['ranked_packet_count']}`",
        f"- blocked_packet_count: `{payload['blocked_packet_count']}`",
        f"- proof_followon_count: `{payload['proof_followon_count']}`",
        "",
        "| Rank | Commit | Verdict | Score | Dedupe key | Originality gate | Blockers |",
        "|---:|---|---|---:|---|---|---|",
    ]
    rows = list(payload.get("review_packets", [])) + list(payload.get("blocked_packets", []))
    if not rows:
        lines.append("| - | - | no qualifying advisory review packets | 0 | - | - | - |")
    for packet in rows:
        blockers = ", ".join(packet.get("blockers") or []) or "none"
        rank = packet.get("rank") if packet.get("rank") is not None else "-"
        lines.append(
            f"| {rank} | `{str(packet.get('commit_sha', ''))[:7]}` | {packet.get('review_verdict', '')} | "
            f"{packet.get('score', 0)} | `{packet.get('dedupe', {}).get('dedupe_key', '')}` | "
            f"{packet.get('originality_gate', {}).get('status', '')} | {blockers} |"
        )
    md_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return json_path, md_path


def write_outputs(payload: dict[str, Any], output_root: Path) -> tuple[Path, Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    json_path = output_root / "scan_tasks.json"
    md_path = output_root / "scan_tasks.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Contest Fix-Commit Scan Tasks",
        "",
        f"- contest_id: `{payload['contest_id']}`",
        f"- advisory_only: `true`",
        f"- evidence_class: `{payload['evidence_class']}`",
        f"- task_count: `{payload['task_count']}`",
        "",
        "| Commit | Repo | Files | Bug-class hints | Advisory next action |",
        "|---|---|---:|---|---|",
    ]
    for task in payload["tasks"]:
        lines.append(
            f"| `{task['commit_sha'][:7]}` | `{task['repo_basename']}` | `{len(task['changed_files'])}` | "
            f"{', '.join(task['bug_class_hints'])} | {task['next_action']} |"
        )
    if not payload["tasks"]:
        lines.append("| - | - | 0 | none | no qualifying advisory fix-commit scan tasks found |")
    md_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contest-id", required=True)
    parser.add_argument("--registry-path", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--fetch-root", type=Path, default=DEFAULT_FETCH_ROOT)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--scan-tasks-path",
        type=Path,
        help="Build only the bounded offline review packet lane from an existing scan_tasks.json",
    )
    parser.add_argument("--json", action="store_true", help="print JSON payload to stdout")
    args = parser.parse_args(argv)
    try:
        if args.scan_tasks_path:
            payload = load_scan_tasks(args.scan_tasks_path)
            out_root = args.output_dir or args.scan_tasks_path.parent
            review_payload = (
                payload
                if payload.get("schema") == REVIEW_SCHEMA
                else build_review_payload(payload)
            )
            write_review_outputs(review_payload, out_root)
            payload = review_payload
        else:
            payload, out_root = build_payload(
                contest_id=args.contest_id,
                registry_path=args.registry_path,
                fetch_root=args.fetch_root,
                output_dir=args.output_dir,
            )
            write_outputs(payload, out_root)
            review_payload = build_review_payload(payload)
            write_review_outputs(review_payload, out_root)
    except ContestFixMineError as exc:
        print(f"[contest-fix-mine] {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
