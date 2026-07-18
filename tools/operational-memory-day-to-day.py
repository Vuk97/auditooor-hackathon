#!/usr/bin/env python3
"""Build the daily operational-memory packet.

The packet is deliberately offline. It imports the current operator memory,
vault indexes, local git log, source-root/mirror rules, known-limitations
burndown map, Rust readiness doctrine, and harness queue boundaries into a
small day-to-day lane contract.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


DEFAULT_DATE = "2026-05-05"
DEFAULT_MEMORY_PATH = Path("/Users/wolf/.codex/memories/auditooor_perpetual_loop.md")
DEFAULT_VAULT_PATH = Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault")


@dataclass(frozen=True)
class ArtifactSpec:
    path: str
    kind: str
    purpose: str
    required: bool = True
    absolute: bool = False


@dataclass(frozen=True)
class Lane:
    lane_id: str
    title: str
    intent: str
    read_first: list[str]
    current_signals: list[str]
    refill_queues: list[str]
    dispatch_blockers: list[str]
    closeout_required: list[str]
    verification_commands: list[str]
    artifact_class: str


ARTIFACT_SPECS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec(
        str(DEFAULT_MEMORY_PATH),
        "operator-memory",
        "current perpetual-loop brief and memory lift ordering",
        absolute=True,
    ),
    ArtifactSpec(
        str(DEFAULT_VAULT_PATH / "INDEX.md"),
        "memory-index",
        "vault note counts and category index",
        required=False,
        absolute=True,
    ),
    ArtifactSpec(
        str(DEFAULT_VAULT_PATH / "INDEX_active.md"),
        "memory-index",
        "live control-plane entry point",
        required=False,
        absolute=True,
    ),
    ArtifactSpec(
        str(DEFAULT_VAULT_PATH / "DASHBOARD.md"),
        "memory-index",
        "vault dashboard, stale-source warnings, and top limitations",
        required=False,
        absolute=True,
    ),
    ArtifactSpec(
        str(DEFAULT_VAULT_PATH / "NEXT_LOOP.md"),
        "memory-index",
        "gap-analyzer next-loop candidate queue",
        required=False,
        absolute=True,
    ),
    ArtifactSpec(
        "docs/MEMORY_ARCHITECTURE_2026-05-04.md",
        "memory-design",
        "L0-L4 memory architecture and commit/mirror category contract",
    ),
    ArtifactSpec(
        "reports/memory_rollup_self_test.json",
        "memory-verification",
        "rollup self-test counts and daily/weekly refresh evidence",
        required=False,
    ),
    ArtifactSpec(
        "reports/memory_gap_analyzer_self_test.json",
        "memory-verification",
        "next-loop gap analyzer and dispatcher self-test evidence",
        required=False,
    ),
    ArtifactSpec(
        "reports/memory_tier1_emitters_self_test.json",
        "memory-verification",
        "anti-pattern/tools-api/bug-class emitter self-test evidence",
        required=False,
    ),
    ArtifactSpec(
        "tools/memory-deep-crawler.py",
        "memory-tool",
        "commit, Codex memory, routine, workspace, and error mirror emitter",
        required=False,
    ),
    ArtifactSpec(
        "tools/obsidian-vault-emit.py",
        "memory-tool",
        "canonical vault source mirror emitter",
        required=False,
    ),
    ArtifactSpec(
        "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
        "known-limitations",
        "machine-readable limitation row states and next commands",
    ),
    ArtifactSpec(
        "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.md",
        "known-limitations",
        "human companion and truth-source warning",
        required=False,
    ),
    ArtifactSpec(
        "docs/PROJECT_SOURCE_ROOTS.md",
        "source-mirror",
        "source-root declaration, mirror verification, and proof-boundary policy",
    ),
    ArtifactSpec(
        "tools/project-source-root-readiness.py",
        "source-mirror",
        "source-root readiness validator",
        required=False,
    ),
    ArtifactSpec(
        "docs/RUST_SOURCE_GRAPH.md",
        "rust-coverage",
        "Rust source-shape graph contract and semantic boundary",
    ),
    ArtifactSpec(
        "docs/RUST_SYMBOLIC_GAP.md",
        "rust-coverage",
        "Rust symbolic verification gap and accepted limits",
        required=False,
    ),
    ArtifactSpec(
        "tools/rust-base-readiness.py",
        "rust-coverage",
        "Base/Rust/DLT no-network readiness gate",
        required=False,
    ),
    ArtifactSpec(
        "docs/INVARIANT_LEDGER.md",
        "harness-queue",
        "invariant ledger and harness queue semantics",
    ),
    ArtifactSpec(
        "docs/HARNESS_HARDENING_2026-05-04.md",
        "harness-queue",
        "smoke-pass-only harness hardening doctrine",
        required=False,
    ),
    ArtifactSpec(
        "tools/invariant-harness-planner.py",
        "harness-queue",
        "high-impact queue builder",
        required=False,
    ),
    ArtifactSpec(
        "tools/high-impact-execution-bridge.py",
        "harness-queue",
        "high-impact execution readiness bridge",
        required=False,
    ),
)


def _resolve(root: Path, spec: ArtifactSpec) -> Path:
    path = Path(spec.path).expanduser()
    return path if spec.absolute else root / path


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _line_count(path: Path) -> int:
    text = _read_text(path)
    return len(text.splitlines()) if text else 0


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _run_git(root: Path, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    out: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        if ":" not in raw or raw.startswith(" "):
            continue
        key, value = raw.split(":", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _extract_memory_lifts(memory_text: str) -> list[str]:
    lifts: list[str] = []
    lines = memory_text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if stripped.startswith("- ") and any(token in stripped for token in ("MCL-", "MFL-")):
            parts = [stripped[2:].strip()]
            index += 1
            while index < len(lines):
                continuation = lines[index]
                cont_stripped = continuation.strip()
                if not cont_stripped or cont_stripped.startswith("- "):
                    break
                if continuation.startswith((" ", "\t")):
                    parts.append(cont_stripped)
                    index += 1
                    continue
                break
            lifts.append(" ".join(parts))
            continue
        if any(token in stripped for token in ("MCL-", "MFL-")):
            lifts.append(stripped.lstrip("- ").strip())
        index += 1
    return lifts


def _extract_markdown_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped.startswith("|") or "---" in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) >= 2:
            rows.append(cells)
    return rows


def _artifact_path_for_output(path: Path, spec: ArtifactSpec) -> str:
    return str(path if spec.absolute else Path(spec.path))


def collect_artifacts(
    root: Path,
    *,
    memory_path: Path | None = None,
    vault_path: Path | None = None,
) -> list[dict[str, Any]]:
    specs: list[ArtifactSpec] = []
    for spec in ARTIFACT_SPECS:
        path_text = spec.path
        absolute = spec.absolute
        if spec.kind == "operator-memory" and memory_path is not None:
            path_text = str(memory_path)
            absolute = True
        elif spec.kind == "memory-index" and vault_path is not None:
            original = Path(spec.path)
            path_text = str(vault_path / original.name)
            absolute = True
        replacement = ArtifactSpec(
            path_text,
            spec.kind,
            spec.purpose,
            spec.required,
            absolute,
        )
        specs.append(replacement)

    artifacts: list[dict[str, Any]] = []
    for spec in specs:
        path = _resolve(root, spec)
        exists = path.is_file()
        artifacts.append(
            {
                "path": _artifact_path_for_output(path, spec),
                "kind": spec.kind,
                "purpose": spec.purpose,
                "required": spec.required,
                "exists": exists,
                "line_count": _line_count(path) if exists else 0,
            }
        )
    return artifacts


def collect_vault_status(root: Path, vault_path: Path) -> dict[str, Any]:
    index = vault_path / "INDEX.md"
    active = vault_path / "INDEX_active.md"
    dashboard = vault_path / "DASHBOARD.md"
    next_loop = vault_path / "NEXT_LOOP.md"
    index_text = _read_text(index)
    active_text = _read_text(active)
    dashboard_text = _read_text(dashboard)
    next_loop_text = _read_text(next_loop)
    index_fm = _parse_frontmatter(index_text)
    active_fm = _parse_frontmatter(active_text)
    dashboard_fm = _parse_frontmatter(dashboard_text)
    next_fm = _parse_frontmatter(next_loop_text)

    repository = ""
    repo_match = re.search(r"`(/[^`]+)`", index_text)
    if repo_match:
        repository = repo_match.group(1)
    stale_warnings = [
        line.strip("> ").strip()
        for line in dashboard_text.splitlines()
        if "[!warning]" in line or "modified" in line and "last vault sync" in line
    ]
    root_resolved = str(root.resolve())
    repo_matches_root = bool(repository) and str(Path(repository).expanduser().resolve()) == root_resolved
    status = "missing"
    if index.is_file() and active.is_file():
        status = "current-root" if repo_matches_root else "external-or-stale-root"
        if stale_warnings:
            status = "needs-refresh"

    next_loop_rows = [
        {
            "rank": cells[0].strip("` "),
            "gap_id": cells[1].strip("` "),
            "category": cells[2].strip("` "),
            "priority": cells[3].strip("` "),
            "title": cells[4],
        }
        for cells in _extract_markdown_table_rows(next_loop_text)
        if cells and cells[0].isdigit()
    ][:10]
    return {
        "vault_path": str(vault_path),
        "status": status,
        "index_present": index.is_file(),
        "active_present": active.is_file(),
        "dashboard_present": dashboard.is_file(),
        "next_loop_present": next_loop.is_file(),
        "generated": index_fm.get("generated") or dashboard_fm.get("generated") or "",
        "last_sync": dashboard_fm.get("last_sync") or "",
        "repository": repository,
        "repo_root": root_resolved,
        "repository_matches_current_root": repo_matches_root,
        "total_notes": _intish(index_fm.get("total_notes") or dashboard_fm.get("total_notes")),
        "verified_detectors": _intish(active_fm.get("verified_detectors") or dashboard_fm.get("verified_detectors")),
        "loops_in_flight": _intish(active_fm.get("loops_in_flight") or dashboard_fm.get("in_flight_loops")),
        "stale_warning_count": len(stale_warnings),
        "stale_warnings": stale_warnings,
        "next_loop_total_candidates": _intish(next_fm.get("total_candidates")),
        "next_loop_top_n": _intish(next_fm.get("top_n")),
        "next_loop_rows": next_loop_rows,
    }


def _intish(value: Any) -> int:
    if value is None:
        return 0
    match = re.search(r"\d+", str(value).replace(",", ""))
    return int(match.group(0)) if match else 0


def collect_commit_scan(root: Path, limit: int = 8) -> dict[str, Any]:
    branch = _run_git(root, ["branch", "--show-current"])
    head = _run_git(root, ["rev-parse", "--short", "HEAD"])
    raw = _run_git(
        root,
        [
            "log",
            f"-n{limit}",
            "--date=short",
            "--pretty=format:%h%x09%ad%x09%s",
        ],
    )
    commits: list[dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        sha, date, subject = parts
        topic = _commit_topic(subject)
        commits.append(
            {
                "sha": sha,
                "date": date,
                "subject": subject,
                "topic": topic,
                "scan_task": f"git show --stat --summary {sha}",
            }
        )
    topic_counts = dict(sorted(Counter(c["topic"] for c in commits).items()))
    return {
        "branch": branch,
        "head": head,
        "commit_count": len(commits),
        "topic_counts": topic_counts,
        "commits": commits,
        "proof_boundary": "Local git log only; no fetch, no GitHub API, no network.",
    }


def _commit_topic(subject: str) -> str:
    lowered = subject.lower()
    mapping = (
        ("memory", ("memory", "vault", "rollup", "gap")),
        ("known-limitations", ("limitation", "burndown", "known")),
        ("rust-coverage", ("rust", "dlt", "reth", "base")),
        ("harness", ("harness", "invariant", "poc-execution", "forge")),
        ("source-mirror", ("source", "mirror", "root", "proof")),
        ("dispatch", ("dispatch", "agent", "worker", "prompt")),
    )
    for topic, needles in mapping:
        if any(needle in lowered for needle in needles):
            return topic
    return "general"


def collect_known_limitations(root: Path) -> dict[str, Any]:
    path = root / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
    payload = _read_json(path)
    rows = payload.get("rows") if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        rows = []
    by_group: dict[str, dict[str, int]] = {}
    terminal_states: Counter[str] = Counter()
    open_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        group = str(row.get("priority_group") or "unknown")
        met = row.get("stop_condition_met") is True
        bucket = by_group.setdefault(group, {"total": 0, "met": 0, "open": 0})
        bucket["total"] += 1
        bucket["met" if met else "open"] += 1
        terminal_states[str(row.get("terminal_state") or "unknown")] += 1
        if not met:
            open_rows.append(
                {
                    "limitation_id": str(row.get("limitation_id") or ""),
                    "priority_group": group,
                    "title": str(row.get("title") or ""),
                    "terminal_state": str(row.get("terminal_state") or ""),
                    "next_command": str(row.get("next_command") or ""),
                    "stop_condition": str(row.get("stop_condition") or ""),
                }
            )
    priority_order = {"current_priority": 0, "P0": 1, "P1": 2, "P2": 3, "cross_cut": 4}
    open_rows.sort(key=lambda r: (priority_order.get(r["priority_group"], 99), r["limitation_id"]))
    harness_rows = [
        row
        for row in open_rows
        if re.search(r"harness|invariant|execution manifest|poc", json.dumps(row), re.I)
    ]
    return {
        "path": "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
        "row_count": len(rows),
        "met_count": sum(1 for row in rows if isinstance(row, dict) and row.get("stop_condition_met") is True),
        "open_count": len(open_rows),
        "by_group": dict(sorted(by_group.items(), key=lambda item: priority_order.get(item[0], 99))),
        "terminal_state_counts": dict(sorted(terminal_states.items())),
        "top_open_rows": open_rows[:10],
        "harness_related_open_rows": harness_rows[:10],
        "proof_boundary": "Seed/workspace burndown accounting is a dispatch queue, not proof-grade closure.",
    }


def collect_rust_coverage(root: Path) -> dict[str, Any]:
    rust_tools = sorted(path.name for path in (root / "tools").glob("rust-*.py"))
    rust_tests = sorted(path.name for path in (root / "tools" / "tests").glob("test_rust*.py"))
    makefile_text = _read_text(root / "Makefile")
    return {
        "rust_source_graph_doc_present": (root / "docs" / "RUST_SOURCE_GRAPH.md").is_file(),
        "rust_symbolic_gap_doc_present": (root / "docs" / "RUST_SYMBOLIC_GAP.md").is_file(),
        "rust_base_readiness_tool_present": (root / "tools" / "rust-base-readiness.py").is_file(),
        "rust_scan_readiness_target_present": "rust-scan-readiness:" in makefile_text,
        "rust_tool_count": len(rust_tools),
        "rust_test_count": len(rust_tests),
        "sample_tools": rust_tools[:12],
        "proof_boundary": (
            "Rust coverage is source-shape/readiness accounting unless a workspace "
            "has fresh roots, scan summaries, runtime semantic blockers, and proved execution evidence."
        ),
    }


def build_lanes(packet_inputs: dict[str, Any]) -> list[Lane]:
    vault = packet_inputs["vault_status"]
    commits = packet_inputs["commit_scan"]
    limitations = packet_inputs["known_limitations"]
    rust = packet_inputs["rust_coverage"]
    memory_lifts = packet_inputs["memory_lifts"]
    stale = vault.get("stale_warning_count", 0)
    top_gap_titles = [row["title"] for row in vault.get("next_loop_rows", [])[:3]]
    top_commit_subjects = [row["subject"] for row in commits.get("commits", [])[:3]]
    top_limitations = [
        f"{row['limitation_id']}: {row['next_command']}"
        for row in limitations.get("top_open_rows", [])[:5]
    ]
    harness_rows = [
        f"{row['limitation_id']}: {row['next_command']}"
        for row in limitations.get("harness_related_open_rows", [])[:5]
    ]
    return [
        Lane(
            lane_id="memory_brief_index",
            title="Memory Brief + Index",
            intent="Start every day from callable memory, active vault indexes, and gap-analyzer candidates.",
            read_first=[
                str(packet_inputs["memory_path"]),
                str(packet_inputs["vault_path"] / "INDEX_active.md"),
                str(packet_inputs["vault_path"] / "NEXT_LOOP.md"),
                "docs/MEMORY_ARCHITECTURE_2026-05-04.md",
            ],
            current_signals=[
                f"memory_lifts={len(memory_lifts)}",
                f"vault_status={vault['status']}",
                f"vault_notes={vault.get('total_notes', 0)}",
                f"next_loop_candidates={vault.get('next_loop_total_candidates', 0)}",
                *top_gap_titles,
            ],
            refill_queues=[
                "obsidian-vault/NEXT_LOOP.md top heuristic gaps",
                "reports/memory_gap_analyzer_self_test.json sample candidates",
                "MCL/MFL lift queue from operator memory",
            ],
            dispatch_blockers=[
                "Vault recommendations lack sample size, evidence path, or declared FP/FN risk.",
                "Memory text is being used as proof instead of routing context.",
                "Provider routing relies on under-powered calibration rows.",
            ],
            closeout_required=[
                "Write final artifact, terminal status, cannot-judge notes, and next queue for each bounded task.",
                "Promote repeated mistakes into anti-pattern/tool gates, not ad hoc reminders.",
                "Keep external provider outputs advisory unless calibration permits promotion.",
            ],
            verification_commands=[
                "python3 tools/memory-gap-analyzer.py --help",
                "python3 tools/memory-deep-crawler.py --status",
            ],
            artifact_class="planning",
        ),
        Lane(
            lane_id="commit_scan_tasks",
            title="Commit Scan Tasks",
            intent="Turn the local git log into bounded review tasks without fetch or network assumptions.",
            read_first=[
                "local git log -n 8",
                "tools/memory-deep-crawler.py commits section",
                "docs/MEMORY_ARCHITECTURE_2026-05-04.md commit category",
            ],
            current_signals=[
                f"branch={commits.get('branch') or 'unknown'}",
                f"head={commits.get('head') or 'unknown'}",
                f"commit_scan_count={commits.get('commit_count', 0)}",
                *top_commit_subjects,
            ],
            refill_queues=[
                "git show --stat --summary <sha> for every recent local commit",
                "obsidian-vault/commits/<sha>.md mirror refresh",
                "decision notes derived from commit-message decision blocks",
            ],
            dispatch_blockers=[
                "A commit task requires GitHub state, remote fetch, or CI status in no-network mode.",
                "A commit touches unowned files for this lane.",
                "A commit summary is promoted before local diff/stat review.",
            ],
            closeout_required=[
                "Record reviewed SHAs and topics.",
                "Queue follow-up work by topic instead of broad rescans.",
                "Refresh commit mirror only through local git log inputs.",
            ],
            verification_commands=[
                "git log -n 8 --date=short --pretty=format:%h%x09%ad%x09%s",
                "git show --stat --summary <sha>",
            ],
            artifact_class="planning",
        ),
        Lane(
            lane_id="source_mirror_verify",
            title="Source Mirror Verify",
            intent="Keep vault/source mirrors honest about their root, freshness, and proof boundary.",
            read_first=[
                str(packet_inputs["vault_path"] / "DASHBOARD.md"),
                "docs/PROJECT_SOURCE_ROOTS.md",
                "tools/project-source-root-readiness.py",
                "tools/obsidian-vault-emit.py",
            ],
            current_signals=[
                f"mirror_status={vault['status']}",
                f"mirror_repo={vault.get('repository') or 'unknown'}",
                f"repo_matches_current_root={vault.get('repository_matches_current_root')}",
                f"stale_warnings={stale}",
            ],
            refill_queues=[
                "make vault-refresh when dashboard reports stale source warnings",
                "make project-source-root-readiness WS=<workspace> JSON=1 for source-root claims",
                "make impact-binding-source-harness-discovery WS=<workspace> JSON=1 after roots validate",
            ],
            dispatch_blockers=[
                "Vault source root differs from the current worktree and the row is treated as current without cross-check.",
                "A declared root points at generated fixtures, docs, submissions, detectors, or tooling.",
                "Source-root readiness is treated as source citation or submission proof.",
            ],
            closeout_required=[
                "Record mirror status and any stale warnings before dispatch.",
                "Keep source-root readiness separate from source-proof records.",
                "Cite exact workspace-local source lines before promotion.",
            ],
            verification_commands=[
                "make vault-refresh",
                "make project-source-root-readiness WS=<workspace> JSON=1",
            ],
            artifact_class="verification",
        ),
        Lane(
            lane_id="known_limitation_dispatch",
            title="Known Limitation Dispatch",
            intent="Select next work from row-level stop conditions and exact next commands.",
            read_first=[
                "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
                "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.md",
                "tools/known-limitations-check.sh",
            ],
            current_signals=[
                f"known_limitation_rows={limitations.get('row_count', 0)}",
                f"open_rows={limitations.get('open_count', 0)}",
                f"met_rows={limitations.get('met_count', 0)}",
                *top_limitations,
            ],
            refill_queues=[
                "current_priority and P0 open rows first",
                "row.next_command from KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
                "make known-limitations-check STRICT=1 after row work lands",
            ],
            dispatch_blockers=[
                "A row has no named blocker, exact next command, or replayable evidence.",
                "Seed-map counts are quoted as current workspace closure counts.",
                "Mechanics-only passing is treated as backlog closure.",
            ],
            closeout_required=[
                "Update row evidence and terminal state only after the stop condition is actually met.",
                "Preserve blocked_named vs closed distinction.",
                "Rerun known limitation and harness gates after meaningful work.",
            ],
            verification_commands=[
                "make known-limitations-check",
                "make known-limitations-check STRICT=1",
            ],
            artifact_class="verification",
        ),
        Lane(
            lane_id="rust_coverage",
            title="Rust Coverage",
            intent="Route Rust/Base/DLT work through source-shape readiness and explicit semantic blockers.",
            read_first=[
                "docs/RUST_SOURCE_GRAPH.md",
                "docs/RUST_SYMBOLIC_GAP.md",
                "docs/PROJECT_SOURCE_ROOTS.md Base / Reth / TEE / ZK pre-scan readiness",
                "tools/rust-base-readiness.py",
            ],
            current_signals=[
                f"rust_tools={rust.get('rust_tool_count', 0)}",
                f"rust_tests={rust.get('rust_test_count', 0)}",
                f"rust_scan_readiness_target={rust.get('rust_scan_readiness_target_present')}",
                "symbolic_status=no_drop_in_halmos_equivalent",
            ],
            refill_queues=[
                "make rust-scan-readiness WS=<workspace> STRICT=1",
                "make rust-base-readiness WS=<workspace> ... JSON=1",
                "make rust-runtime-semantic-blockers WS=<workspace> GENERATE=1",
                "scan-rust summaries and runtime/DLT evidence validators",
            ],
            dispatch_blockers=[
                "No declared Rust/DLT source root or stale scan summary.",
                "Rust source graph is treated as semantic completeness.",
                "Kani/Miri/Creusot-style notes are treated as existing auditooor proof tooling.",
            ],
            closeout_required=[
                "Record root readiness blockers before launching long scanners.",
                "Write runtime semantic blocker rows for unresolved trait/cfg/macro/client semantics.",
                "Keep Rust detector promotion behind fixture/replay smoke, not source-shape hints.",
            ],
            verification_commands=[
                "make rust-scan-readiness WS=<workspace> STRICT=1",
                "make rust-base-readiness WS=<workspace> JSON=1",
            ],
            artifact_class="verification",
        ),
        Lane(
            lane_id="harness_queues",
            title="Harness Queues",
            intent="Move only exact High/Critical rows from queue to scaffold to execution record.",
            read_first=[
                "docs/INVARIANT_LEDGER.md harness queue section",
                "docs/HARNESS_HARDENING_2026-05-04.md",
                "tools/invariant-harness-planner.py",
                "tools/high-impact-execution-bridge.py",
            ],
            current_signals=[
                f"harness_related_open_limitations={len(limitations.get('harness_related_open_rows', []))}",
                *harness_rows,
            ],
            refill_queues=[
                "<workspace>/.audit_logs/invariant_ledger_deep_summary.json harness queue",
                "<workspace>/.auditooor/harness_plans.json",
                "<workspace>/.auditooor/high_impact_execution_bridge.json",
                "poc-execution-record handoff commands emitted by the bridge",
            ],
            dispatch_blockers=[
                "Impact contract missing or incomplete for a High/Critical row.",
                "Scaffold readiness is treated as exploit proof.",
                "Smoke-passing fixture output lacks semantic lint/diversity/cross-fixture checks.",
            ],
            closeout_required=[
                "Record scaffold attempts and execution-record commands separately.",
                "Mark RESULT=needs_human until a real execution result is inspected.",
                "Keep blocked_missing_impact_contract rows out of runnable harness lanes.",
            ],
            verification_commands=[
                "make harness-plan WS=<workspace> ALL=1",
                "make high-impact-execution-bridge WS=<workspace>",
                "make poc-execution-record WS=<workspace> BRIEF=<brief> CMD=<cmd> RESULT=needs_human IMPACT=unknown",
            ],
            artifact_class="proof-readiness",
        ),
    ]


def build_global_blockers(required_missing: list[str], vault_status: dict[str, Any]) -> list[dict[str, str]]:
    blockers = [
        {
            "id": "no-network-assumption",
            "stops": "daily dispatch",
            "condition": "the lane requires gh, fetch, provider calls, or live web state",
        },
        {
            "id": "no-memory-as-proof",
            "stops": "candidate promotion",
            "condition": "memory/vault rows are routing context, not source, impact, or execution proof",
        },
        {
            "id": "no-mechanics-only-closure",
            "stops": "known-limitations closure",
            "condition": "a command passing does not meet the row stop condition by itself",
        },
        {
            "id": "no-scaffold-as-exploit-proof",
            "stops": "harness promotion",
            "condition": "harness plans, scaffold attempts, and handoff briefs are proof-readiness only",
        },
    ]
    if vault_status.get("status") in {"needs-refresh", "external-or-stale-root"}:
        blockers.append(
            {
                "id": "source-mirror-cross-check",
                "stops": "vault-derived claims",
                "condition": f"vault status is {vault_status.get('status')}; cross-check current repo before quoting counts",
            }
        )
    for missing in required_missing:
        blockers.append(
            {
                "id": "missing-required-artifact",
                "stops": "daily packet confidence",
                "condition": f"required source artifact is missing: {missing}",
            }
        )
    return blockers


def build_packet(
    root: Path,
    date: str = DEFAULT_DATE,
    memory_path: Path | None = None,
    vault_path: Path | None = None,
) -> dict[str, Any]:
    memory = (memory_path or DEFAULT_MEMORY_PATH).expanduser()
    vault = (vault_path or DEFAULT_VAULT_PATH).expanduser()
    artifacts = collect_artifacts(root, memory_path=memory, vault_path=vault)
    required_missing = [
        artifact["path"]
        for artifact in artifacts
        if artifact["required"] and not artifact["exists"]
    ]
    memory_text = _read_text(memory)
    memory_lifts = _extract_memory_lifts(memory_text)
    vault_status = collect_vault_status(root, vault)
    commit_scan = collect_commit_scan(root)
    known_limitations = collect_known_limitations(root)
    rust_coverage = collect_rust_coverage(root)
    packet_inputs = {
        "memory_path": memory,
        "vault_path": vault,
        "memory_lifts": memory_lifts,
        "vault_status": vault_status,
        "commit_scan": commit_scan,
        "known_limitations": known_limitations,
        "rust_coverage": rust_coverage,
    }
    lanes = build_lanes(packet_inputs)
    lane_dicts = [asdict(lane) for lane in lanes]
    blockers = build_global_blockers(required_missing, vault_status)
    artifact_class_counts = dict(sorted(Counter(lane.artifact_class for lane in lanes).items()))
    return {
        "date": date,
        "packet": "operational-memory-day-to-day",
        "schema": "auditooor.operational_memory_day_to_day.v2",
        "repo_root": str(root.resolve()),
        "summary": {
            "lane_count": len(lane_dicts),
            "read_first_count": sum(len(lane.read_first) for lane in lanes),
            "current_signal_count": sum(len(lane.current_signals) for lane in lanes),
            "refill_queue_count": sum(len(lane.refill_queues) for lane in lanes),
            "dispatch_blocker_count": sum(len(lane.dispatch_blockers) for lane in lanes),
            "closeout_count": sum(len(lane.closeout_required) for lane in lanes),
            "verification_command_count": sum(len(lane.verification_commands) for lane in lanes),
            "required_artifacts_missing": len(required_missing),
            "global_blocker_count": len(blockers),
            "artifact_class_counts": artifact_class_counts,
        },
        "lane_ids": [lane.lane_id for lane in lanes],
        "global_blockers": blockers,
        "memory_lifts": memory_lifts,
        "vault_status": vault_status,
        "commit_scan": commit_scan,
        "known_limitations": known_limitations,
        "rust_coverage": rust_coverage,
        "artifacts": artifacts,
        "lanes": lane_dicts,
    }


def render_markdown(packet: dict[str, Any]) -> str:
    summary = packet["summary"]
    lines = [
        f"# Operational Memory Day-to-Day Packet - {packet['date']}",
        "",
        "Offline packet for day-to-day auditooor operation. It imports the current memory brief/index, local commit scan tasks, source mirror status, known-limitations dispatch rows, Rust coverage boundaries, and harness queues.",
        "",
        "## Counts",
        "",
        f"- Lanes: {summary['lane_count']} ({', '.join(packet['lane_ids'])})",
        f"- Read-first items: {summary['read_first_count']}",
        f"- Current signals: {summary['current_signal_count']}",
        f"- Refill queues: {summary['refill_queue_count']}",
        f"- Lane dispatch blockers: {summary['dispatch_blocker_count']}",
        f"- Closeout requirements: {summary['closeout_count']}",
        f"- Verification commands: {summary['verification_command_count']}",
        f"- Required source artifacts missing: {summary['required_artifacts_missing']}",
        f"- Artifact classes: {json.dumps(summary['artifact_class_counts'], sort_keys=True)}",
        "",
        "## Global Dispatch Blockers",
        "",
    ]
    for blocker in packet["global_blockers"]:
        lines.append(f"- `{blocker['id']}` stops {blocker['stops']}: {blocker['condition']}")

    lines.extend(["", "## Imported Signals", ""])
    vault = packet["vault_status"]
    lines.extend(
        [
            f"- Vault status: `{vault['status']}`; notes={vault.get('total_notes', 0)}; stale_warnings={vault.get('stale_warning_count', 0)}",
            f"- Vault repository: `{vault.get('repository') or 'unknown'}`; current root match={vault.get('repository_matches_current_root')}",
            f"- Commit scan: branch=`{packet['commit_scan'].get('branch') or 'unknown'}` head=`{packet['commit_scan'].get('head') or 'unknown'}` rows={packet['commit_scan'].get('commit_count', 0)}",
            f"- Known limitations: rows={packet['known_limitations'].get('row_count', 0)} open={packet['known_limitations'].get('open_count', 0)} met={packet['known_limitations'].get('met_count', 0)}",
            f"- Rust coverage tools/tests: {packet['rust_coverage'].get('rust_tool_count', 0)} / {packet['rust_coverage'].get('rust_test_count', 0)}",
        ]
    )

    lines.extend(["", "## Memory Lift Queue", ""])
    if packet["memory_lifts"]:
        lines.extend(f"- {lift}" for lift in packet["memory_lifts"])
    else:
        lines.append("- No MCL/MFL lift line found in the memory source.")

    lines.extend(["", "## Lanes", ""])
    for lane in packet["lanes"]:
        lines.extend(
            [
                f"### {lane['title']} (`{lane['lane_id']}`)",
                "",
                f"**Intent:** {lane['intent']}",
                "",
                "**Read first:**",
            ]
        )
        lines.extend(f"- {item}" for item in lane["read_first"])
        lines.extend(["", "**Current signals:**"])
        lines.extend(f"- {item}" for item in lane["current_signals"])
        lines.extend(["", "**Queues that refill work:**"])
        lines.extend(f"- {item}" for item in lane["refill_queues"])
        lines.extend(["", "**Blockers that stop dispatch:**"])
        lines.extend(f"- {item}" for item in lane["dispatch_blockers"])
        lines.extend(["", "**Finalize after each bounded task:**"])
        lines.extend(f"- {item}" for item in lane["closeout_required"])
        lines.extend(["", "**Verification commands:**"])
        lines.extend(f"- `{item}`" for item in lane["verification_commands"])
        lines.extend(["", f"**Artifact class:** `{lane['artifact_class']}`", ""])

    lines.extend(["## Known Limitation Open Queue", ""])
    for row in packet["known_limitations"].get("top_open_rows", []):
        lines.append(
            f"- `{row['limitation_id']}` ({row['priority_group']}, {row['terminal_state']}): {row['title']} -> `{row['next_command']}`"
        )
    if not packet["known_limitations"].get("top_open_rows"):
        lines.append("- No open known-limitation rows parsed.")

    lines.extend(["", "## Commit Scan Tasks", ""])
    for row in packet["commit_scan"].get("commits", []):
        lines.append(
            f"- `{row['sha']}` {row['date']} [{row['topic']}] {row['subject']} -> `{row['scan_task']}`"
        )
    if not packet["commit_scan"].get("commits"):
        lines.append("- No local git commits parsed.")

    lines.extend(["", "## Source Artifacts", ""])
    for artifact in packet["artifacts"]:
        status = "present" if artifact["exists"] else "missing"
        required = "required" if artifact["required"] else "optional"
        lines.append(
            f"- `{artifact['path']}` - {status}, {required}, {artifact['kind']}, {artifact['line_count']} lines"
        )
    lines.append("")
    return "\n".join(lines)


def write_packet(root: Path, packet: dict[str, Any], md_out: Path, json_out: Path) -> None:
    md_path = md_out if md_out.is_absolute() else root / md_out
    json_path = json_out if json_out.is_absolute() else root / json_out
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(packet), encoding="utf-8")
    json_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--date", default=DEFAULT_DATE)
    parser.add_argument("--memory-path", type=Path, default=DEFAULT_MEMORY_PATH)
    parser.add_argument("--vault-path", type=Path, default=DEFAULT_VAULT_PATH)
    parser.add_argument(
        "--md-out",
        type=Path,
        default=Path("docs") / f"OPERATIONAL_MEMORY_DAY_TO_DAY_{DEFAULT_DATE}.md",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("reports") / f"operational_memory_day_to_day_{DEFAULT_DATE}.json",
    )
    parser.add_argument(
        "--format",
        choices=("summary", "json", "markdown"),
        default="summary",
    )
    parser.add_argument("--no-write", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.expanduser().resolve()
    packet = build_packet(root, args.date, args.memory_path, args.vault_path)
    if not args.no_write:
        write_packet(root, packet, args.md_out, args.json_out)

    if args.format == "json":
        print(json.dumps(packet, indent=2, sort_keys=True))
    elif args.format == "markdown":
        print(render_markdown(packet))
    else:
        summary = packet["summary"]
        print(
            "operational-memory-day-to-day "
            f"lanes={summary['lane_count']} "
            f"read_first={summary['read_first_count']} "
            f"signals={summary['current_signal_count']} "
            f"refill_queues={summary['refill_queue_count']} "
            f"lane_blockers={summary['dispatch_blocker_count']} "
            f"global_blockers={summary['global_blocker_count']} "
            f"missing_required={summary['required_artifacts_missing']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
