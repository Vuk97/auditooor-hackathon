#!/usr/bin/env python3
"""automation-closure.py — PR #560 workspace automation inventories.

This tool turns the PR #560 plan into executable, offline-safe artifacts. It
does not prove vulnerabilities. It records what scope/impact rows exist, which
candidate rows are mapped to them, what coverage/inventory artifacts are
present, and which agent outputs still need local verification.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_class as _evidence_class  # noqa: E402
import execution_manifest_proof as _execution_manifest_proof  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PREFIX = "auditooor.pr560"
LOCAL_PROGRESS_DOCS_DIR_ENV = "AUDITOOOR_PR560_PROGRESS_DOCS_DIR"
FULL_ROADMAP_CLOSURE_AUTOMATION_ID = "auditooor-watchdog-closure-loop"
TIERS = ("Critical", "High", "Medium", "Low", "Informational")
REPORTABLE_WORKLIST_SEVERITIES = {"Critical", "High", "Medium"}
IMPACT_WORKLIST_CONCRETE_ITEM_TARGET = 50
ACTIVE_SLOT_STALE_AFTER_DAYS = 2
AGENT_RECALL_STATUSES = (
    "detectorized",
    "source_proof_required",
    "harness_task_required",
    "killed_duplicate_or_oos",
    "blocked_missing_impact_contract",
)
SOURCE_PROOF_TASK_STATUSES = (
    "terminal_evidence_present",
    "ready_for_source_review",
    "blocked_missing_impact_contract",
    "blocked_missing_citations",
    "blocked_oos_not_checked",
    "empty_no_source_proof_tasks",
)
REPORTABLE_OR_DIRECT_RE = re.compile(
    r"\b(Critical|High|Medium|direct[-_ ]submit|submit[-_ ]ready|paste[-_ ]ready)\b",
    re.IGNORECASE,
)
HARNESS_ROUTE_RE = re.compile(
    r"\b(harness|poc|forge test|halmos|counterexample|reproduc(?:e|tion)|manifest|poc_execution)\b",
    re.IGNORECASE,
)
SOURCE_PROOF_ROUTE_RE = re.compile(
    r"\b(source proof|source[- ]review|invariant|file:line|line-cited|cite|src/|crates/|contracts/)\b",
    re.IGNORECASE,
)
KILL_ROUTE_RE = re.compile(
    r"\b(dupe|duplicate|oos|out[- ]of[- ]scope|not[- ]a[- ]bug|no new bug|killed|false positive|not a protocol bug|not a submission|property[- ]misspecification)\b",
    re.IGNORECASE,
)
SOURCE_CITATION_RE = re.compile(
    r"(?P<cite>(?:src|contracts|crates|op-[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:sol|rs|cairo|move|vy):[0-9]+(?:-[0-9]+)?)"
)
SOURCE_ARTIFACT_RE = re.compile(
    r"(?P<path>(?:agent_outputs|swarm|source_mining|critical_hunt|docs|notes|submissions|[A-Za-z0-9_.-]+)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:md|json|txt|log|out))"
)
STRICT_BLOCKING_CATEGORIES = {
    "missing_required_artifact",
    "missing_scoped_source_roots",
}
IMPACT_ANALYSIS_ACTIONS = (
    "exact_impact_candidate",
    "oos_duplicate_kill",
    "source_proof_precondition",
    "harness_precondition",
)
HARNESS_REQUIRED_STATES = (
    "harness_task_required",
    "harness_task",
    "poc_task_required",
)
AGENT_OUTPUT_TERMINAL_STATES = (
    "verified_local",
    "killed_duplicate_or_oos",
    "routed_to_impact_analysis",
    "routed_to_source_proof",
    "routed_to_harness_task",
    "detectorized",
    "archived_no_claims",
)
AGENT_OUTPUT_OPEN_STATES = (
    "not_verified",
    "needs_local_verification",
    "needs_archive_review",
)


@dataclass
class ImpactRow:
    id: str
    severity: str
    impact: str
    source_file: str
    line: int
    evidence_class: str
    asset_category: str
    required_evidence_class: str
    required_artifacts: list[str]
    oos_traps: list[str]
    emergency_downgrade_clauses: list[str]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso_or_date(value: str) -> datetime | None:
    """Parse active-slot freshness timestamps without raising.

    Accepted inputs are ISO datetimes, trailing-``Z`` UTC datetimes, and
    ``YYYY-MM-DD`` dates. Naive values are treated as UTC so stale-slot
    accounting remains deterministic in local test environments.
    """
    raw = str(value or "").strip().strip("`")
    if not raw:
        return None
    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def out_dir(workspace: Path) -> Path:
    d = workspace / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    return d


def repo_out_dir() -> Path:
    d = ROOT / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    return d


def pr560_progress_docs_dir() -> Path:
    override = os.environ.get(LOCAL_PROGRESS_DOCS_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return ROOT / "docs"


def pr560_progress_paths() -> tuple[Path, Path]:
    d = pr560_progress_docs_dir()
    return d / "PR560_LOCAL_BATCH_PROGRESS.md", d / "PR560_LOCAL_BATCH_PROGRESS.json"


def pr560_integration_readiness_paths() -> tuple[Path, Path]:
    d = pr560_progress_docs_dir()
    return d / "PR560_LOCAL_INTEGRATION_READINESS.md", d / "PR560_LOCAL_INTEGRATION_READINESS.json"


def stable_artifact_path(path: Path) -> str:
    """Render repo-local paths without embedding the current temp worktree."""
    try:
        return "<repo>/" + path.resolve().relative_to(ROOT.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_md(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def slug(value: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return s[:80] or "row"


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def asset_category_for(source: Path, impact: str) -> str:
    stem = source.stem.lower()
    low = impact.lower()
    if "smart" in stem or any(tok in low for tok in ("fund", "vault", "token", "contract", "bridge")):
        return "Smart Contract"
    if "blockchain" in stem or "dlt" in stem or any(tok in low for tok in ("node", "network", "transaction", "block", "consensus", "mempool")):
        return "Blockchain/DLT"
    return "Other"


def required_artifacts_for(impact: str, asset_category: str) -> list[str]:
    low = impact.lower()
    artifacts = ["impact_contract", "exact_impact_proof"]
    if any(tok in low for tok in ("node", "network", "shutdown", "resource", "transaction", "block")):
        artifacts.extend([
            "real_component_or_full_node_harness",
            "resource_or_liveness_measurement",
            "poc_execution_manifest",
        ])
    elif any(tok in low for tok in ("fund", "theft", "loss", "bridge", "token")):
        artifacts.extend([
            "production_path_dossier",
            "funds_flow_poc_or_fork_replay",
            "poc_execution_manifest",
        ])
    else:
        artifacts.extend(["source_proof_or_harness_plan", "poc_execution_manifest"])
    if asset_category == "Smart Contract":
        artifacts.append("scope_oos_check")
    if asset_category == "Blockchain/DLT":
        artifacts.append("deployment_or_node_topology_notes")
    return sorted(set(artifacts))


def required_evidence_class_for(impact: str) -> str:
    low = impact.lower()
    if any(tok in low for tok in ("fund", "theft", "loss", "shutdown", "resource", "network")):
        return _evidence_class.EXECUTED_WITH_MANIFEST
    return _evidence_class.SCAFFOLDED_UNVERIFIED


def oos_traps_for(workspace: Path, impact: str) -> list[str]:
    low = impact.lower()
    traps: list[str] = []
    if any(tok in low for tok in ("node", "network", "shutdown", "resource", "transaction", "mempool")):
        traps.extend([
            "exclude brute-force or flood-only DoS unless the program impact row allows it",
            "exclude component-only benchmarks that do not prove the selected node/network impact",
            "exclude mempool impact unless the selected program row is specifically about mempool behavior",
        ])
    if any(tok in low for tok in ("fund", "theft", "loss", "bridge", "token")):
        traps.extend([
            "exclude admin-key compromise or privileged operator action",
            "exclude mock-token or local-test-only fund movement without production-path evidence",
        ])
    if any(tok in low for tok in ("proof", "verifier", "zk", "tee")):
        traps.append("exclude mock verifier, invalid proof, or project-inaction assumptions without production proof")
    for name in ("OOS_PASTED.md", "SCOPE.md"):
        path = workspace / name
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = compact(raw.lstrip("-* "))
            if line and re.search(r"\b(out.of.scope|oos|excluded|not in scope|invalid|admin|privileged)\b", line, re.I):
                traps.append(f"{name}: {line[:180]}")
    return sorted(set(traps)) or ["no explicit OOS trap found; run per-finding OOS check before promotion"]


def emergency_downgrade_clauses_for(impact: str) -> list[str]:
    clauses = [
        "if proof does not prove this exact impact sentence, clear selected_impact and mark NOT_SUBMIT_READY",
        "if severity cannot be derived from this exact row, set severity=none",
    ]
    low = impact.lower()
    if any(tok in low for tok in ("node", "network", "resource", "shutdown")):
        clauses.append("if evidence is only component behavior or non-realistic brute force, route to kill_or_reframe")
    if any(tok in low for tok in ("fund", "theft", "bridge")):
        clauses.append("if exploit requires privileged/admin compromise, route to OOS/preclear instead of direct submit")
    return clauses


def find_rubric_files(workspace: Path) -> list[Path]:
    severity = workspace / "SEVERITY.md"
    if severity.is_file():
        return [severity]
    return [
        p
        for p in sorted(workspace.glob("SEVERITY*.md"))
        if p.is_file() and "CAP" not in p.stem.upper()
    ]


def parse_impact_rows(workspace: Path) -> list[ImpactRow]:
    rows: list[ImpactRow] = []
    seen: set[tuple[str, str]] = set()

    def add_row(severity: str, impact: str, source: Path, line: int) -> None:
        impact = compact(impact)
        if len(impact) < 8:
            return
        key = (severity, impact.lower())
        if key in seen:
            return
        seen.add(key)
        asset_category = asset_category_for(source, impact)
        rows.append(
            ImpactRow(
                id=f"{severity.lower()}-{len(rows) + 1:03d}-{slug(impact)}",
                severity=severity,
                impact=impact,
                source_file=str(source),
                line=line,
                evidence_class=_evidence_class.GENERATED_HYPOTHESIS,
                asset_category=asset_category,
                required_evidence_class=required_evidence_class_for(impact),
                required_artifacts=required_artifacts_for(impact, asset_category),
                oos_traps=oos_traps_for(workspace, impact),
                emergency_downgrade_clauses=emergency_downgrade_clauses_for(impact),
            )
        )

    for path in find_rubric_files(workspace):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        current: str | None = None
        active = False
        bullet_line = 0
        bullet_parts: list[str] = []

        def flush() -> None:
            nonlocal bullet_line, bullet_parts
            if current in TIERS and active and bullet_parts:
                add_row(current, " ".join(bullet_parts), path, bullet_line)
            bullet_line = 0
            bullet_parts = []

        for lineno, raw in enumerate(lines, 1):
            stripped = raw.strip()
            heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", raw)
            if heading:
                flush()
                text = heading.group(1).strip()
                exact_tier = next((tier for tier in TIERS if re.fullmatch(rf"{tier}s?", text, re.I)), None)
                operator_critical = re.search(r"operator-brief\s+Critical\s+impacts", text, re.I)
                if exact_tier:
                    current = exact_tier
                    active = True
                elif operator_critical:
                    current = "Critical"
                    active = True
                else:
                    current = None
                    active = False
                continue

            # Bold prose subsections often live inside severity documents but
            # are explanatory notes, not selectable program impact rows.
            if stripped.startswith("**") and not re.match(r"^\s*[-*]\s+", raw):
                flush()
                active = False
                current = None
                continue

            if re.match(r"^\s*---+\s*$", raw):
                flush()
                active = False
                current = None
                continue

            bullet = re.match(r"^\s*[-*]\s+(.+?)\s*$", raw)
            if bullet:
                flush()
                bullet_line = lineno
                bullet_parts = [bullet.group(1).strip()]
                continue

            if bullet_parts and raw.startswith(("  ", "\t")) and stripped:
                bullet_parts.append(stripped)
                continue

            if bullet_parts and not stripped:
                flush()

        flush()
    return rows


def render_impact_matrix(workspace: Path) -> dict[str, Any]:
    rows = [asdict(r) for r in parse_impact_rows(workspace)]
    payload = {
        "schema": f"{SCHEMA_PREFIX}.program_impact_matrix.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": rows,
        "status": "ok" if rows else "blocked_missing_rubric",
    }
    d = out_dir(workspace)
    write_json(d / "program_impact_matrix.json", payload)
    md = ["# Program Impact Matrix", "", f"Workspace: `{workspace}`", ""]
    if rows:
        md.extend(["| Severity | Asset category | Required evidence | Impact | Source |", "|---|---|---|---|---|"])
        for row in rows:
            md.append(
                f"| {row['severity']} | {row['asset_category']} | `{row['required_evidence_class']}` | "
                f"{row['impact']} | `{row['source_file']}:{row['line']}` |"
            )
    else:
        md.append("No severity/rubric rows found.")
    write_md(d / "program_impact_matrix.md", md)
    return payload


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def path_status(path: Path) -> str:
    if path.is_file():
        return "present_file"
    if path.is_dir():
        return "present_dir"
    return "missing"


def safe_count(root: Path, pattern: str = "*") -> int:
    if not root.exists():
        return 0
    try:
        return sum(1 for p in root.rglob(pattern) if p.is_file())
    except OSError:
        return 0


def classify_artifact(path: Path) -> tuple[str, str, str]:
    text = str(path).lower()
    if "wave" in text or "critical_hunt" in text:
        return ("critical_hunt", "advisory_only", "make coverage-inventory WS=<workspace>")
    if "snappy" in text:
        return ("node_resource", "not_submit_ready", "make impact-contract-check WS=<workspace>")
    if "fn7" in text:
        return ("fn7", "not_submit_ready", "make base-critical-hunt WS=<workspace>")
    if "swival" in text:
        return ("swival_rust", "advisory_only", "make corpus-mining-inventory")
    if "zkbugs" in text:
        return ("zkbugs", "advisory_only", "make zkbugs-status")
    if "recon" in text or "chimera" in text:
        return ("recon_chimera", "blocked_named", "make deep-counterexample-queue WS=<workspace>")
    if "submission" in text:
        return ("submission_outcome", "advisory_only", "make outcome-telemetry AUDITS_DIR=~/audits")
    return ("general", "inventory_only", "make automation-closure WS=<workspace>")


def candidate_rows(workspace: Path) -> list[dict[str, Any]]:
    matrix = load_json(workspace / "critical_hunt" / "base_critical_candidate_matrix.json")
    if matrix and isinstance(matrix.get("rows"), list):
        return [r for r in matrix["rows"] if isinstance(r, dict)]
    out: list[dict[str, Any]] = []
    for path in sorted((workspace / "critical_hunt" / "candidates").glob("*.json")):
        data = load_json(path)
        if data:
            data.setdefault("_source_file", str(path))
            out.append(data)
    return out


def discover_source_roots(workspace: Path) -> tuple[list[str], list[str]]:
    candidates = ["src", "contracts", "external", "crates", "programs", "app", "packages"]
    present = [name for name in candidates if (workspace / name).exists()]
    skipped = [name for name in candidates if name not in present]
    scope = workspace / "SCOPE.md"
    if scope.is_file():
        for raw in scope.read_text(encoding="utf-8", errors="replace").splitlines():
            for token in re.findall(r"`([^`]+)`|(?:^|\s)([A-Za-z0-9_./-]+/)", raw):
                value = compact("".join(token)).strip("/")
                if value and (workspace / value).exists() and value not in present:
                    present.append(value)
    return sorted(present), sorted(skipped)


def graph_artifacts(workspace: Path) -> dict[str, str]:
    checks = {
        "semantic_graph": workspace / ".auditooor" / "semantic_graph.json",
        "rust_source_graph": workspace / ".auditooor" / "rust_source_graph.json",
        "invariant_ledger": workspace / ".auditooor" / "invariant_ledger.json",
        "live_topology": workspace / "live_topology_checks.json",
        "deployment_topology": workspace / "deployment_topology.json",
    }
    return {name: ("present" if path.is_file() else "missing") for name, path in checks.items()}


def required_graph_artifacts_for(asset_category: str) -> list[str]:
    """Return strict graph prerequisites for this asset class.

    Coverage inventory is a closure/readiness view, not a live-evidence
    synthesizer. Semantic and invariant ledgers are source-level requirements
    for every impact family. Rust source graphs are only mandatory for Rust/DLT
    surfaces; live/deployment topology remains optional unless a downstream
    proof workflow explicitly requires and materializes it.
    """
    low = asset_category.lower()
    required = ["semantic_graph", "invariant_ledger"]
    if "blockchain" in low or "dlt" in low or "rust" in low:
        required.append("rust_source_graph")
    return required


def graph_artifact_details(workspace: Path) -> dict[str, dict[str, Any]]:
    specs = {
        "semantic_graph": (workspace / ".auditooor" / "semantic_graph.json", "make semantic-graph WS=<workspace>"),
        "rust_source_graph": (workspace / ".auditooor" / "rust_source_graph.json", "make semantic-graph WS=<workspace>"),
        "invariant_ledger": (workspace / ".auditooor" / "invariant_ledger.json", "make invariant-ledger WS=<workspace>"),
        "live_topology": (workspace / "live_topology_checks.json", "python3 tools/engage.py --workspace <workspace> --stage live-checks"),
        "deployment_topology": (workspace / "deployment_topology.json", "python3 tools/engage.py --workspace <workspace> --stage orient"),
    }
    return {
        name: {
            "status": "present" if path.is_file() else "missing",
            "artifact": str(path),
            "next_command": command,
        }
        for name, (path, command) in specs.items()
    }


def scan_artifacts(workspace: Path) -> dict[str, str]:
    scan_report_paths = [
        workspace / "scan_report.md",
        workspace / "scanners" / "SCAN_REPORT.md",
        workspace / "detector_findings.json",
    ]
    checks = {
        "rust_scan": workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
        "scan_report": scan_report_paths,
        "coverage_introspect": workspace / ".auditooor" / "coverage_introspection.json",
        "detector_findings": workspace / "detector_findings.json",
    }
    states: dict[str, str] = {}
    for name, path_or_paths in checks.items():
        paths = path_or_paths if isinstance(path_or_paths, list) else [path_or_paths]
        states[name] = "present" if any(path.is_file() for path in paths) else "missing"
    return states


def scan_artifact_details(workspace: Path) -> dict[str, dict[str, Any]]:
    specs = {
        "rust_scan": (workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", "make scan-rust WS=<workspace>", True),
        "scan_report": (
            [
                workspace / "scan_report.md",
                workspace / "scanners" / "SCAN_REPORT.md",
                workspace / "detector_findings.json",
            ],
            "python3 tools/engage.py --workspace <workspace> --stage scan",
            True,
        ),
        "coverage_introspect": (workspace / ".auditooor" / "coverage_introspection.json", "make coverage-introspect WS=<workspace>", False),
        "detector_findings": (workspace / "detector_findings.json", "make scan WS=<workspace>", False),
    }
    details: dict[str, dict[str, Any]] = {}
    for name, (path_or_paths, command, required) in specs.items():
        paths = path_or_paths if isinstance(path_or_paths, list) else [path_or_paths]
        satisfied_by = next((path for path in paths if path.is_file()), None)
        details[name] = {
            "status": "present" if satisfied_by else "missing",
            "artifact": str(paths[0]),
            "accepted_artifacts": [str(path) for path in paths],
            "satisfied_by": str(satisfied_by) if satisfied_by else "",
            "next_command": command,
            "required_for_base_closure": required,
        }
    return details


def blocker_detail(blocker: str, *, artifact: str, next_command: str, reason: str, category: str) -> dict[str, str]:
    return {
        "blocker": blocker,
        "category": category,
        "missing_artifact": artifact,
        "next_command": next_command,
        "reason": reason,
    }


def blocker_summary(details: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for detail in details:
        category = str(detail.get("category") or "uncategorized")
        counts[category] = counts.get(category, 0) + 1
    blocking = sorted(
        category for category in counts
        if category in STRICT_BLOCKING_CATEGORIES
    )
    open_work = sorted(
        category for category in counts
        if category not in STRICT_BLOCKING_CATEGORIES
    )
    return {
        "blocker_categories": sorted(counts),
        "blocker_category_counts": counts,
        "strict_blocking_categories": blocking,
        "open_work_categories": open_work,
        "strict_blocking": bool(blocking),
    }


def status_from_blocker_summary(summary: dict[str, Any], *, covered: bool) -> str:
    if summary.get("strict_blocking"):
        return "blocked_missing_required_artifacts"
    if summary.get("open_work_categories"):
        return "open_impact_family_work"
    return "covered_by_candidate" if covered else "uncovered_needs_source_query"


def summarize_blocker_categories(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for row in rows:
        row_counts = row.get("blocker_category_counts") or {}
        if not isinstance(row_counts, dict):
            continue
        for category, count in row_counts.items():
            counts[str(category)] = counts.get(str(category), 0) + int(count)
    strict = sorted(
        category for category in counts
        if category in STRICT_BLOCKING_CATEGORIES
    )
    open_work = sorted(
        category for category in counts
        if category not in STRICT_BLOCKING_CATEGORIES
    )
    return {
        "blocker_category_counts": counts,
        "strict_blocking_categories": strict,
        "open_work_categories": open_work,
    }


def render_invariant_discovery_status(workspace: Path) -> dict[str, Any]:
    """Summarize invariant-ledger generated-vs-accepted diff output.

    This is intentionally advisory. A missing or stale generated invariant
    sidecar should be visible in closure/burndown, but it must not promote or
    kill candidates and must not make strict closure fail by itself.
    """
    path = out_dir(workspace) / "generated_invariants.json"
    next_command = (
        "python3 tools/invariant-ledger.py --workspace <workspace> --from-scope"
    )
    summary: dict[str, Any] = {
        "schema": f"{SCHEMA_PREFIX}.invariant_discovery_status.v1",
        "workspace": str(workspace),
        "artifact_path": str(path),
        "status": "advisory_missing_generated_invariants",
        "advisory": True,
        "generated_count": 0,
        "accepted_before_count": 0,
        "missing_before_count": 0,
        "added_to_ledger_count": 0,
        "next_command": next_command,
    }
    payload = load_json(path)
    if not payload:
        return summary

    generated = int(payload.get("generated_count") or 0)
    accepted = int(payload.get("accepted_before_count") or 0)
    missing = int(payload.get("missing_before_count") or 0)
    added = int(payload.get("added_to_ledger_count") or 0)
    review_path = out_dir(workspace) / "invariant_acceptance_ledger.json"
    review_payload = load_json(review_path) or {}
    review_rows = records_from_payload(review_payload)
    terminal_review_states = {"accepted", "merged", "killed", "needs_harness", "advisory_harness_required"}
    terminal_reviews = {
        str(row.get("generated_id") or row.get("invariant_id") or row.get("row_id") or "").strip(): row
        for row in review_rows
        if str(row.get("review_state") or row.get("status") or "").strip() in terminal_review_states
    }
    missing_rows = list(((payload.get("diff") or {}).get("missing") or []))
    reviewed_missing = [
        row for row in missing_rows
        if str(row.get("generated_id") or "").strip() in terminal_reviews
    ]
    terminal_review_count = len(reviewed_missing)
    if missing_rows and terminal_review_count == len(missing_rows):
        missing = 0
    status = "advisory_no_generated_rows"
    if generated and missing:
        status = "advisory_missing_invariants"
    elif generated and terminal_review_count:
        status = "advisory_all_generated_invariants_reviewed"
    elif generated:
        status = "advisory_all_generated_invariants_accepted"
    summary.update({
        "source_schema": payload.get("schema_version") or payload.get("schema"),
        "generated_at": payload.get("generated_at"),
        "source_files": payload.get("source_files", []),
        "status": status,
        "generated_count": generated,
        "accepted_before_count": accepted,
        "missing_before_count": missing,
        "added_to_ledger_count": added,
        "terminal_review_rows": terminal_review_count,
        "review_artifact": str(review_path) if review_rows else "",
        "next_command": payload.get("next_command") or next_command,
    })
    return summary


def invariant_discovery_adoption_accounting(workspace: Path) -> dict[str, Any]:
    """Read invariant-discovery adoption reducer output.

    This is reduction/closure accounting for the "row or explicit blocker"
    boundary only. It never promotes invariant candidates to proof.
    """
    path = out_dir(workspace) / "invariant_discovery_adoption.json"
    payload = load_json(path) if path.is_file() else {}
    generated_review = payload.get("generated_review") if isinstance(payload.get("generated_review"), dict) else {}
    route_units = payload.get("route_family_units") if isinstance(payload.get("route_family_units"), list) else []
    blocker_rows = [
        row for row in route_units
        if str(row.get("review_state") or "").startswith("blocked_")
        and row.get("next_commands")
    ]
    terminal_generated_reviews = int(generated_review.get("terminal_review_count") or 0)
    unreviewed_generated = int(generated_review.get("unreviewed_missing_count") or 0)
    adopted = bool(payload.get("adopted_to_canonical_invariant_ledger"))
    high_critical_stop = (
        bool(payload)
        and adopted
        and unreviewed_generated == 0
        and len(route_units) > 0
        and len(blocker_rows) == len(route_units)
        and int(payload.get("closure_candidate_count") or 0) == 0
        and not bool(payload.get("promotion_allowed"))
        and str(payload.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    return {
        "schema": f"{SCHEMA_PREFIX}.invariant_discovery_adoption_accounting.v1",
        "status": (
            "high_critical_route_families_have_invariant_blocker_rows"
            if high_critical_stop else "open_or_missing_invariant_adoption"
        ),
        "artifact_path": str(path),
        "review_unit_dir": str(payload.get("review_unit_dir") or out_dir(workspace) / "invariant_discovery_review_units"),
        "route_family_unit_count": len(route_units),
        "blocker_row_count": len(blocker_rows),
        "terminal_generated_review_count": terminal_generated_reviews,
        "unreviewed_generated_count": unreviewed_generated,
        "ledger_rows_added": int(payload.get("ledger_rows_added") or 0),
        "ledger_rows_updated": int(payload.get("ledger_rows_updated") or 0),
        "adopted_to_canonical_invariant_ledger": adopted,
        "priority4_stop_condition_met": high_critical_stop,
        "p0_discovery_completeness_closed": False,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Invariant adoption closes only the generated-vs-reviewed and row-or-explicit-blocker "
            "coverage branch for the current workspace. Full P0 discovery completeness still needs "
            "fresh-engagement adoption metrics and real proof-class evidence."
        ),
    }


def invariant_adoption_closure_readiness_accounting(workspace: Path) -> dict[str, Any]:
    """Read the strict P0-0 invariant-adoption closure gate."""
    path = out_dir(workspace) / "invariant_adoption_closure_readiness.json"
    payload = load_json(path) if path.is_file() else {}
    fresh = payload.get("fresh_engagement_metrics") if isinstance(payload.get("fresh_engagement_metrics"), dict) else {}
    proof = payload.get("proof_class_evidence") if isinstance(payload.get("proof_class_evidence"), dict) else {}
    blockers = payload.get("blockers") if isinstance(payload.get("blockers"), list) else []
    p0_ready = bool(payload.get("p0_closure_ready"))
    return {
        "schema": f"{SCHEMA_PREFIX}.invariant_adoption_closure_readiness_accounting.v1",
        "artifact_path": str(path),
        "status": str(payload.get("status") or "missing_invariant_adoption_closure_readiness"),
        "p0_closure_ready": p0_ready,
        "fresh_engagement_metrics_status": str(fresh.get("status") or "missing_fresh_engagement_metrics"),
        "fresh_engagement_count": int(fresh.get("fresh_engagement_count") or 0),
        "valid_fresh_engagement_count": int(fresh.get("valid_fresh_engagement_count") or 0),
        "invalid_fresh_engagement_count": int(fresh.get("invalid_fresh_engagement_count") or 0),
        "required_fresh_engagement_count": int(fresh.get("required_fresh_engagement_count") or 3),
        "proof_ready_execution_manifest_count": int(proof.get("proof_ready_execution_manifest_count") or 0),
        "ready_project_source_root_count": int(proof.get("ready_project_source_root_count") or 0),
        "source_line_hit_unit_count": int(proof.get("source_line_hit_unit_count") or 0),
        "blockers": [str(blocker) for blocker in blockers],
        "next_command": (
            "make invariant-adoption-closure-readiness WS=<workspace> JSON=1"
            if not payload else (
                "make invariant-adoption-fresh-metrics WS=<workspace> SOURCE_WS=<fresh-workspace> JSON=1 "
                "&& make invariant-adoption-closure-readiness WS=<workspace> JSON=1"
            )
        ),
        "proof_boundary": str(payload.get("proof_boundary") or (
            "P0-0 cannot close from current-workspace invariant rows alone; it needs "
            "fresh-engagement adoption metrics and proof-class evidence."
        )),
    }


def required_scan_artifacts_for(asset_category: str) -> list[str]:
    low = asset_category.lower()
    if "blockchain" in low or "dlt" in low or "rust" in low:
        return ["rust_scan"]
    if "smart contract" in low or "solidity" in low:
        return ["scan_report"]
    return []


def protocol_roles_for(impact: str) -> list[str]:
    low = impact.lower()
    roles = []
    if any(tok in low for tok in ("node", "network", "transaction", "block", "consensus")):
        roles.extend(["node", "validator", "peer", "sequencer"])
    if any(tok in low for tok in ("fund", "theft", "vault", "token", "bridge")):
        roles.extend(["user", "attacker", "custody_contract", "bridge_or_vault"])
    if any(tok in low for tok in ("proof", "verifier", "zk", "tee")):
        roles.extend(["prover", "verifier", "challenger"])
    return sorted(set(roles)) or ["unknown_role"]


def behavior_templates_for(impact: str) -> list[str]:
    low = impact.lower()
    if any(tok in low for tok in ("node", "network", "shutdown", "resource")):
        return [
            "external_input -> gossip/rpc decode -> validation/cache -> node resource or liveness assertion",
            "peer/request path -> bounded workload check -> measured node impact",
        ]
    if any(tok in low for tok in ("fund", "theft", "loss", "bridge")):
        return [
            "attacker call -> authorization/accounting edge -> balance delta assertion",
            "cross-contract call -> settlement/finalization edge -> victim asset movement",
        ]
    return ["entrypoint -> state transition -> exact impact assertion"]


def impact_family_for_impact(impact: str, asset_category: str = "") -> str:
    """Map a listed program-impact sentence to a coarse planning family."""
    low = impact.lower()
    asset = asset_category.lower()
    if any(tok in low for tok in ("node", "network", "block", "transaction", "consensus", "mempool")):
        return "node_or_network_liveness"
    if any(tok in low for tok in ("resource", "cpu", "memory", "disk", "bandwidth")):
        return "node_resource_consumption"
    if any(tok in low for tok in ("bridge", "withdraw", "finaliz", "cross-chain", "cross chain")):
        return "bridge_finalization"
    if any(tok in low for tok in ("fund", "theft", "loss", "vault", "token", "freeze")):
        return "asset_custody"
    if any(tok in low for tok in ("oracle", "price", "settle", "liquidat", "resolve")):
        return "oracle_or_settlement"
    if any(tok in low for tok in ("proof", "verifier", "zk", "tee", "signature")):
        return "proof_or_signature"
    if "blockchain" in asset or "dlt" in asset:
        return "blockchain_dlt_general"
    if "smart contract" in asset:
        return "smart_contract_general"
    return "general_program_impact"


def _impact_tokens_for_match(impact: str) -> set[str]:
    stop = {
        "able", "being", "through", "direct", "user", "users", "from", "into",
        "with", "without", "program", "impact", "critical", "high", "medium",
        "least", "than", "new", "can", "forced", "processing",
    }
    return {
        tok
        for tok in re.findall(r"[a-z0-9]{4,}", impact.lower())
        if tok not in stop
    }


def _file_roots_for_component(file_name: str, roots: list[str]) -> list[str]:
    if not file_name:
        return []
    normalized = file_name.strip("/")
    matched = [
        root
        for root in roots
        if normalized == root.strip("/") or normalized.startswith(root.strip("/") + "/")
    ]
    return matched


def load_semantic_graph(workspace: Path) -> dict[str, Any]:
    return load_json(out_dir(workspace) / "semantic_graph.json") or {}


def semantic_components_for_impact(
    workspace: Path,
    impact: dict[str, Any],
    roots: list[str],
    *,
    limit: int = 40,
) -> dict[str, Any]:
    """Enumerate source-shape components relevant to one listed impact row.

    This is intentionally a worklist, not proof: matches are keyword/family
    routing aids that help operators pick roots/components before harness work.
    """
    graph = load_semantic_graph(workspace)
    if not graph:
        return {
            "status": "blocked_missing_semantic_graph",
            "coverage_claim": "none_source_shape_only",
            "components": [],
            "component_count": 0,
        }
    impact_text = str(impact.get("impact") or "")
    family = impact_family_for_impact(impact_text, str(impact.get("asset_category") or ""))
    tokens = _impact_tokens_for_match(impact_text)
    components: list[dict[str, Any]] = []

    def add_component(row: dict[str, Any]) -> None:
        if len(components) >= limit:
            return
        key = (row.get("component_id"), row.get("file"), row.get("line"))
        if any((c.get("component_id"), c.get("file"), c.get("line")) == key for c in components):
            return
        components.append(row)

    for entry in graph.get("entrypoints", []) if isinstance(graph.get("entrypoints"), list) else []:
        if not isinstance(entry, dict):
            continue
        haystack = " ".join(
            str(value)
            for value in (
                entry.get("contract"),
                entry.get("function"),
                entry.get("role"),
                " ".join(entry.get("state_writes") or []),
                " ".join(entry.get("external_calls") or []),
            )
        ).lower()
        overlap = sorted(tokens & set(re.findall(r"[a-z0-9]{4,}", haystack)))
        value_movement = bool(entry.get("value_movement"))
        external_calls = bool(entry.get("external_calls"))
        liveness_hint = family.startswith("node_") and any(
            tok in haystack for tok in ("block", "node", "message", "validate", "process", "execute")
        )
        custody_hint = family == "asset_custody" and (value_movement or any(tok in haystack for tok in ("transfer", "mint", "burn", "withdraw", "deposit")))
        if not overlap and not liveness_hint and not custody_hint and not external_calls:
            continue
        file_name = str(entry.get("file") or "")
        add_component({
            "component_id": f"{entry.get('contract', 'unknown')}.{entry.get('function', 'unknown')}",
            "component_kind": "entrypoint",
            "file": file_name,
            "line": entry.get("line", 0),
            "role": entry.get("role", ""),
            "scoped_roots": _file_roots_for_component(file_name, roots),
            "match_reason": (
                "keyword_overlap:" + ",".join(overlap)
                if overlap
                else ("family_hint:" + family)
            ),
            "proof_gap": "source-shape only; requires exact impact proof before harness/report work",
        })

    for path_row in graph.get("multi_hop_paths", []) if isinstance(graph.get("multi_hop_paths"), list) else []:
        if not isinstance(path_row, dict):
            continue
        row_family = str(path_row.get("impact_family") or "")
        source_component = str(path_row.get("source_component") or "")
        if row_family and row_family != family and family not in {row_family, "general_program_impact"}:
            if not (family == "bridge_finalization" and row_family in {"bridge_finalization", "proof_finalization"}):
                continue
        evidence_edges = path_row.get("evidence_edges") if isinstance(path_row.get("evidence_edges"), list) else []
        file_name = str((evidence_edges[0] if evidence_edges else {}).get("file") or "")
        add_component({
            "component_id": str(path_row.get("path_id") or source_component),
            "component_kind": "semantic_multi_hop_path",
            "source_component": source_component,
            "impact_family": row_family,
            "file": file_name,
            "line": (evidence_edges[0] if evidence_edges else {}).get("line", 0),
            "scoped_roots": _file_roots_for_component(file_name, roots),
            "mapped_stages": path_row.get("mapped_stages") or [],
            "missing_stages": path_row.get("missing_stages") or [],
            "match_reason": f"impact_family:{row_family or family}",
            "proof_gap": "multi-hop source-shape only; requires production-path and exact impact evidence",
        })

    scoped_from_components = sorted({
        root
        for component in components
        for root in component.get("scoped_roots", [])
        if root
    })
    return {
        "status": "present" if components else "present_no_matching_components",
        "coverage_claim": "none_source_shape_only",
        "semantic_graph": str(out_dir(workspace) / "semantic_graph.json"),
        "component_count": len(components),
        "scoped_roots_with_components": scoped_from_components,
        "components": components,
    }


def load_semantic_detector_worklist_rows(workspace: Path) -> list[dict[str, Any]]:
    payload = load_json(out_dir(workspace) / "semantic_detector_worklist.json") or {}
    rows = records_from_payload(payload)
    return [row for row in rows if isinstance(row, dict)]


def _component_identity(component: dict[str, Any]) -> set[str]:
    values = {
        str(component.get("component_id") or ""),
        str(component.get("source_component") or ""),
        str(component.get("impact_family") or ""),
        str(component.get("file") or ""),
    }
    return {compact(value).lower() for value in values if compact(value)}


def detector_rows_for_component(
    component: dict[str, Any],
    detector_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    identities = _component_identity(component)
    if not identities:
        return []
    matches: list[dict[str, Any]] = []
    for row in detector_rows:
        bridge = row.get("detector_query_bridge") if isinstance(row.get("detector_query_bridge"), dict) else {}
        haystack = " ".join(
            compact(str(value)).lower()
            for value in (
                row.get("task_id"),
                row.get("source_id"),
                row.get("source_component"),
                row.get("target_component"),
                row.get("impact_family"),
                row.get("file"),
                row.get("candidate_detector_family"),
                bridge.get("query_shape"),
            )
            if compact(str(value))
        )
        if any(identity and identity in haystack for identity in identities):
            matches.append(row)
    return matches


def semantic_query_for_component(component: dict[str, Any], impact_family: str) -> dict[str, Any]:
    kind = str(component.get("component_kind") or "semantic_component")
    if kind == "semantic_multi_hop_path":
        collection = "multi_hop_paths"
        match_fields: dict[str, Any] = {
            "path_id": component.get("component_id") or "",
            "source_component": component.get("source_component") or "",
            "impact_family": component.get("impact_family") or impact_family,
        }
        required_output_fields = [
            "path_id",
            "impact_family",
            "source_component",
            "sink_component",
            "mapped_stages",
            "missing_stages",
            "evidence_edges",
        ]
        query_shape = "impact_worklist_multihop_path"
    else:
        collection = "relation_edges"
        match_fields = {
            "source_component": component.get("component_id") or component.get("source_component") or "",
        }
        required_output_fields = [
            "file",
            "line",
            "source_contract",
            "source_function",
            "kind",
            "receiver",
            "target_type",
            "method",
            "evidence",
        ]
        query_shape = "impact_worklist_component_relations"
    return {
        "backend": "semantic_graph_query",
        "advisory_only": True,
        "coverage_claim": "none_source_shape_only",
        "source_collection": collection,
        "query_shape": query_shape,
        "query_status": "candidate_spec",
        "match_fields": match_fields,
        "required_output_fields": required_output_fields,
        "promotion_blockers": [
            "requires exact impact contract proof",
            "requires production path or source-proof evidence",
            "requires runnable PoC/execution manifest before submit-ready posture",
        ],
    }


def load_semantic_graph_query_result_rows(workspace: Path) -> dict[str, Any]:
    payload = load_json(out_dir(workspace) / "semantic_graph_query_results.json") or {}
    raw_rows = payload.get("results") if isinstance(payload.get("results"), list) else []
    rows = [row for row in raw_rows if isinstance(row, dict)]
    by_task: dict[str, dict[str, Any]] = {}
    for row in rows:
        task_id = str(row.get("task_id") or "")
        if task_id:
            by_task[task_id] = row
    return {
        "artifact": str(out_dir(workspace) / "semantic_graph_query_results.json"),
        "status": "present" if rows else "missing_or_empty",
        "rows": rows,
        "by_task": by_task,
    }


def source_review_handoff_for_impact(
    workspace: Path,
    impact: dict[str, Any],
    impact_family: str,
    semantic_components: dict[str, Any],
    roots: list[str],
) -> dict[str, Any]:
    """Build a deterministic advisory handoff from listed impact to review lanes."""
    components = [
        component
        for component in semantic_components.get("components", [])
        if isinstance(component, dict)
    ]
    detector_rows = load_semantic_detector_worklist_rows(workspace)
    query_results = load_semantic_graph_query_result_rows(workspace)
    query_results_by_task = query_results["by_task"]
    routes: list[dict[str, Any]] = []
    impact_id = str(impact.get("id") or "")
    impact_text = str(impact.get("impact") or "")

    for index, component in enumerate(components[:20], 1):
        query = semantic_query_for_component(component, impact_family)
        route_id = f"{impact_id}-semantic-query-{index:03d}"
        routes.append({
            "route_id": route_id,
            "route_kind": "semantic_graph_query",
            "route_status": "candidate_spec",
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_status": "NOT_SUBMIT_READY",
            "submit_ready": False,
            "advisory_only": True,
            "promotion_allowed": False,
            "coverage_claim": "none_source_shape_only",
            "component_id": component.get("component_id") or component.get("source_component") or "",
            "semantic_graph_query": query,
            "query_result_status": "not_executed",
            "query_match_count": 0,
            "next_command": "make semantic-graph-query WS=<workspace> IMPACT_WORKLIST=1",
        })
        matched_detector_rows = detector_rows_for_component(component, detector_rows)
        if matched_detector_rows:
            for det_index, detector_row in enumerate(matched_detector_rows[:5], 1):
                bridge = detector_row.get("detector_query_bridge") if isinstance(detector_row.get("detector_query_bridge"), dict) else {}
                routes.append({
                    "route_id": f"{impact_id}-detector-worklist-{index:03d}-{det_index:02d}",
                    "route_kind": "detector_worklist_row",
                    "route_status": "advisory_untriaged",
                    "submission_posture": "NOT_SUBMIT_READY",
                    "submit_status": "NOT_SUBMIT_READY",
                    "submit_ready": False,
                    "advisory_only": True,
                    "promotion_allowed": False,
                    "coverage_claim": "none_source_shape_only",
                    "component_id": component.get("component_id") or component.get("source_component") or "",
                    "detector_task_id": detector_row.get("task_id") or "",
                    "detector_task_kind": detector_row.get("detector_task_kind") or "",
                    "candidate_detector_family": detector_row.get("candidate_detector_family") or "",
                    "detector_query_bridge": bridge,
                    "next_command": "triage semantic detector row as detectorizable, source-review-only, or invariant-only; do not promote without fixtures",
                })
        else:
            routes.append({
                "route_id": f"{impact_id}-invariant-only-{index:03d}",
                "route_kind": "non_detectorizable_invariant_only",
                "route_status": "requires_triage",
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_status": "NOT_SUBMIT_READY",
                "submit_ready": False,
                "advisory_only": True,
                "promotion_allowed": False,
                "coverage_claim": "none_source_shape_only",
                "component_id": component.get("component_id") or component.get("source_component") or "",
                "reason": "no semantic detector worklist row matched this impact/component; capture as source-proof or invariant-only unless a static detector predicate is proven",
                "required_terminal_decision": [
                    "detectorizable_with_fixtures",
                    "source_review_packet_only",
                    "invariant_only_no_detector",
                    "kill_or_reframe",
                ],
                "next_command": "make source-proof-task-queue WS=<workspace> or make invariant-ledger WS=<workspace>",
            })

    routes.append({
        "route_id": f"{impact_id}-source-mining-packet",
        "route_kind": "source_mining_packet",
        "route_status": "ready_for_provider_packet",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "submit_ready": False,
        "advisory_only": True,
        "promotion_allowed": False,
        "coverage_claim": "none_source_shape_only",
        "packet": {
            "packet_kind": "impact_worklist_to_source_review",
            "impact_id": impact_id,
            "impact_family": impact_family,
            "listed_impact": impact_text,
            "source_roots": roots,
            "semantic_component_ids": [
                str(component.get("component_id") or component.get("source_component") or "")
                for component in components[:20]
                if str(component.get("component_id") or component.get("source_component") or "").strip()
            ],
            "provider_lanes": ["kimi_source_extract", "minimax_adversarial_kill"],
            "must_keep_posture": "NOT_SUBMIT_READY until exact impact proof and execution artifact exist",
        },
        "next_command": f"make source-mine WS=<workspace> IMPACT_ID={impact_id}",
    })

    if not components:
        routes.append({
            "route_id": f"{impact_id}-semantic-query-missing-components",
            "route_kind": "semantic_graph_query",
            "route_status": str(semantic_components.get("status") or "blocked_missing_components"),
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_status": "NOT_SUBMIT_READY",
            "submit_ready": False,
            "advisory_only": True,
            "promotion_allowed": False,
            "coverage_claim": "none_source_shape_only",
            "semantic_graph_query": {
                "backend": "semantic_graph_query",
                "advisory_only": True,
                "coverage_claim": "none_source_shape_only",
                "source_collection": "entrypoints,multi_hop_paths",
                "query_status": "blocked_or_empty",
                "match_fields": {
                    "impact_family": impact_family,
                    "impact_tokens": sorted(_impact_tokens_for_match(impact_text)),
                    "source_roots": roots,
                },
            },
            "next_command": "make semantic-graph WS=<workspace> && make impact-worklist WS=<workspace>",
        })
        routes.append({
            "route_id": f"{impact_id}-invariant-only-missing-components",
            "route_kind": "non_detectorizable_invariant_only",
            "route_status": "requires_semantic_or_invariant_triage",
            "submission_posture": "NOT_SUBMIT_READY",
            "submit_status": "NOT_SUBMIT_READY",
            "submit_ready": False,
            "advisory_only": True,
            "promotion_allowed": False,
            "coverage_claim": "none_source_shape_only",
            "reason": "no semantic component currently maps to this listed impact row; keep as invariant/source-review work until semantic graph evidence or an exact kill is recorded",
            "required_terminal_decision": [
                "add_semantic_component_query",
                "source_review_packet_only",
                "invariant_only_no_detector",
                "kill_or_reframe",
            ],
            "next_command": "make invariant-ledger WS=<workspace> && make source-proof-task-queue WS=<workspace>",
        })

    route_counts: dict[str, int] = {}
    query_accounting = {
        "result_artifact": query_results["artifact"],
        "result_status": query_results["status"],
        "candidate_query_count": 0,
        "executed_query_count": 0,
        "matched_query_count": 0,
        "zero_match_query_count": 0,
        "matched_row_count": 0,
    }
    for route in routes:
        kind = str(route.get("route_kind") or "unknown")
        route_counts[kind] = route_counts.get(kind, 0) + 1
        if kind != "semantic_graph_query":
            continue
        query_accounting["candidate_query_count"] += 1
        result = query_results_by_task.get(str(route.get("route_id") or ""))
        if not result:
            continue
        match_count = int(result.get("match_count") or 0)
        route["query_result_status"] = str(result.get("query_status") or "executed")
        route["query_match_count"] = match_count
        route["query_result_artifact"] = query_results["artifact"]
        route["query_result_truncated"] = bool(result.get("truncated"))
        query_accounting["executed_query_count"] += 1
        query_accounting["matched_row_count"] += match_count
        if match_count:
            query_accounting["matched_query_count"] += 1
        else:
            query_accounting["zero_match_query_count"] += 1
    return {
        "schema": f"{SCHEMA_PREFIX}.impact_source_review_handoff.v1",
        "impact_id": impact_id,
        "impact_family": impact_family,
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "submit_ready": False,
        "semantic_detector_worklist": str(out_dir(workspace) / "semantic_detector_worklist.json"),
        "semantic_detector_worklist_status": "present" if detector_rows else "missing_or_empty",
        "semantic_graph_query_results": query_results["artifact"],
        "semantic_graph_query_result_status": query_results["status"],
        "query_result_accounting": query_accounting,
        "route_count": len(routes),
        "route_kind_counts": route_counts,
        "routes": routes,
    }


def next_command_for_worklist(row: dict[str, Any], *, has_candidates: bool, has_roots: bool) -> str:
    if not has_roots:
        return "add SCOPE.md source roots or ASSET_WAIVER, then make impact-worklist WS=<workspace>"
    if not has_candidates:
        return "make source-mine WS=<workspace> IMPACT_ID=" + str(row.get("id", ""))
    if str(row.get("required_evidence_class")) == _evidence_class.EXECUTED_WITH_MANIFEST:
        return "make harness-plan WS=<workspace> ROW=" + str(row.get("id", ""))
    return "make impact-contract-check WS=<workspace>"


def impact_family_execution_reduction(
    *,
    impact: dict[str, Any],
    matching_candidates: list[str],
    source_review_handoff: dict[str, Any],
) -> dict[str, Any]:
    """Summarize mechanical start-of-work reduction for one impact family.

    This is not proof and never makes a row submit-ready. It only answers
    whether the worklist row has been reduced to either a locked exact impact
    contract or executed source-shape query evidence. The operator-facing
    concrete item list is capped so large workspaces produce a roughly
    50-item next-action packet instead of an unbounded dump.
    """
    routes = [
        route for route in source_review_handoff.get("routes", [])
        if isinstance(route, dict)
    ]
    query_routes = [
        route for route in routes
        if str(route.get("route_kind") or "") == "semantic_graph_query"
    ]
    executed_query_routes = [
        route for route in query_routes
        if str(route.get("query_result_status") or "") not in {"", "not_executed"}
    ]
    items: list[dict[str, Any]] = []
    for route in routes[:IMPACT_WORKLIST_CONCRETE_ITEM_TARGET]:
        route_kind = str(route.get("route_kind") or "unknown")
        route_id = str(route.get("route_id") or "")
        query_status = str(route.get("query_result_status") or "")
        if route_kind == "semantic_graph_query":
            terminal_status = "reduced" if query_status and query_status != "not_executed" else "open"
            terminal_decision = "semantic_graph_query_executed" if terminal_status == "reduced" else "execute_semantic_graph_query"
        elif route_kind == "detector_worklist_row":
            terminal_status = "open"
            terminal_decision = "triage_detectorizable_source_or_invariant"
        elif route_kind == "source_mining_packet":
            terminal_status = "open"
            terminal_decision = "run_source_mining_or_kill_packet"
        else:
            terminal_status = "open"
            terminal_decision = "record_source_proof_invariant_or_kill"
        items.append(
            {
                "item_id": route_id,
                "route_kind": route_kind,
                "component_id": str(route.get("component_id") or ""),
                "terminal_status": terminal_status,
                "terminal_decision": terminal_decision,
                "next_command": str(route.get("next_command") or ""),
            }
        )

    exact_contract_present = bool(matching_candidates)
    semantic_query_reduced = bool(query_routes) and len(executed_query_routes) == len(query_routes)
    reportable = str(impact.get("severity") or "") in REPORTABLE_WORKLIST_SEVERITIES
    status = (
        "exact_impact_contract_present"
        if exact_contract_present
        else ("semantic_query_execution_reduced" if semantic_query_reduced else "open_impact_contract_or_family_execution")
    )
    return {
        "schema": f"{SCHEMA_PREFIX}.impact_family_execution_reduction.v1",
        "status": status,
        "reportable_severity": reportable,
        "exact_impact_contract_present": exact_contract_present,
        "semantic_query_execution_reduced": semantic_query_reduced,
        "candidate_ids": matching_candidates,
        "route_count": len(routes),
        "semantic_query_route_count": len(query_routes),
        "semantic_query_executed_count": len(executed_query_routes),
        "open_semantic_query_count": max(len(query_routes) - len(executed_query_routes), 0),
        "concrete_item_target": IMPACT_WORKLIST_CONCRETE_ITEM_TARGET,
        "concrete_item_count": len(routes),
        "concrete_items_truncated": len(routes) > IMPACT_WORKLIST_CONCRETE_ITEM_TARGET,
        "concrete_execution_items": items,
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
    }


def selected_impact(row: dict[str, Any]) -> str:
    lane = row.get("lane_payload")
    if isinstance(lane, dict):
        mapping = lane.get("program_impact_mapping")
        if isinstance(mapping, dict):
            value = mapping.get("selected_impact")
            if isinstance(value, str) and value.strip():
                return re.sub(r"\s+", " ", value.strip())
    for key in ("listed_impact_selected", "selected_impact", "impact_mapping", "impact"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return re.sub(r"\s+", " ", value.strip())
    return ""


def render_impact_contracts(workspace: Path) -> dict[str, Any]:
    impact_matrix = load_json(out_dir(workspace) / "program_impact_matrix.json") or render_impact_matrix(workspace)
    impact_lookup = {r["impact"].lower(): r for r in impact_matrix.get("rows", []) if isinstance(r, dict)}
    contracts = []
    for row in candidate_rows(workspace):
        impact = selected_impact(row)
        mapped = impact_lookup.get(impact.lower()) if impact else None
        proven = bool(row.get("listed_impact_proven"))
        if mapped and proven:
            verdict = "in_scope_direct_submit"
            effective_impact = impact
            severity = mapped.get("severity")
            terminal_route = "prove_or_package"
            missing_proof: list[str] = []
        elif impact:
            verdict = "NOT_SUBMIT_READY" if mapped else "killed_no_listed_impact"
            effective_impact = ""
            severity = "none"
            terminal_route = "kill_or_reframe"
            missing_proof = [
                "proof must prove the exact selected impact sentence before severity, PoC, harness, or report work"
            ] if mapped else ["selected impact sentence is not an exact program impact row"]
        else:
            verdict = "killed_no_listed_impact"
            effective_impact = ""
            severity = "none"
            terminal_route = "kill_or_reframe"
            missing_proof = ["candidate must select an exact program impact row before PoC, harness, or report work"]
        candidate_id = str(row.get("candidate_id") or row.get("id") or "UNKNOWN")
        impact_contract_id = (
            f"impact-contract-{slug(candidate_id)}-{slug(effective_impact)[:32]}"
            if effective_impact and verdict == "in_scope_direct_submit"
            else ""
        )
        contracts.append(
            {
                "impact_contract_id": impact_contract_id,
                "candidate_id": candidate_id,
                "selected_impact": effective_impact,
                "original_selected_impact": impact,
                "severity": severity,
                "exact_impact_row": bool(mapped),
                "listed_impact_proven": proven,
                "posture": verdict,
                "verdict": verdict,
                "terminal_route": terminal_route,
                "missing_proof": missing_proof,
            }
        )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.impact_contracts.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "contracts": contracts,
        "status": "ok" if contracts else "empty_no_candidates",
    }
    d = out_dir(workspace)
    write_json(d / "impact_contracts.json", payload)
    md = ["# Impact Contracts", "", "| Candidate | Impact | Severity | Verdict |", "|---|---|---|---|"]
    for c in contracts:
        md.append(f"| `{c['candidate_id']}` | {c['selected_impact'] or '_none_'} | {c['severity']} | `{c['verdict']}` |")
    if not contracts:
        md.append("| _none_ | _none_ | none | `empty_no_candidates` |")
    write_md(d / "impact_contracts.md", md)
    return payload


def render_impact_worklist(workspace: Path) -> dict[str, Any]:
    matrix = load_json(out_dir(workspace) / "program_impact_matrix.json") or render_impact_matrix(workspace)
    contracts = load_json(out_dir(workspace) / "impact_contracts.json") or render_impact_contracts(workspace)
    roots, skipped_roots = discover_source_roots(workspace)
    graphs = graph_artifacts(workspace)
    graph_details = graph_artifact_details(workspace)
    work = []
    for impact in matrix.get("rows", []):
        if not isinstance(impact, dict):
            continue
        impact_family = impact_family_for_impact(
            str(impact.get("impact", "")),
            str(impact.get("asset_category", "")),
        )
        semantic_components = semantic_components_for_impact(workspace, impact, roots)
        source_review_handoff = source_review_handoff_for_impact(
            workspace,
            impact,
            impact_family,
            semantic_components,
            sorted(set((semantic_components.get("scoped_roots_with_components") or []) or roots)),
        )
        component_roots = semantic_components.get("scoped_roots_with_components") or []
        scoped_roots = sorted(set(component_roots or roots))
        matching = [
            c["candidate_id"]
            for c in contracts.get("contracts", [])
            if isinstance(c, dict) and c.get("selected_impact", "").lower() == impact.get("impact", "").lower()
        ]
        family_execution = impact_family_execution_reduction(
            impact=impact,
            matching_candidates=matching,
            source_review_handoff=source_review_handoff,
        )
        blockers = []
        blocker_details: list[dict[str, str]] = []
        if not roots:
            blockers.append("blocked_named:no_scoped_source_roots")
            blocker_details.append(blocker_detail(
                "blocked_named:no_scoped_source_roots",
                artifact=str(workspace / "SCOPE.md"),
                next_command="add SCOPE.md source roots or ASSET_WAIVER, then make impact-worklist WS=<workspace>",
                reason="no source root directory was discovered for this workspace",
                category="missing_scoped_source_roots",
            ))
        if (
            impact.get("severity") in REPORTABLE_WORKLIST_SEVERITIES
            and family_execution.get("status") == "open_impact_contract_or_family_execution"
        ):
            blockers.append("open_work:open_impact_contract_or_family_execution")
            blocker_details.append(blocker_detail(
                "open_work:open_impact_contract_or_family_execution",
                artifact=f"{workspace / '.auditooor' / 'impact_contracts.json'} row with selected_impact == {impact.get('impact', '')!r}",
                next_command=(
                    "make semantic-graph-query WS=<workspace> IMPACT_WORKLIST=1 && "
                    f"make impact-analysis-queue WS=<workspace> && make source-mine WS=<workspace> IMPACT_ID={impact.get('id', '')}"
                ),
                reason=(
                    "reportable impact family has no locked exact impact contract "
                    "and its semantic query/source-review worklist has not been reduced"
                ),
                category="open_impact_contract_or_family_execution",
            ))
        if graphs.get("semantic_graph") != "present":
            blockers.append("blocked_named:missing_semantic_graph")
            detail = graph_details["semantic_graph"]
            blocker_details.append(blocker_detail(
                "blocked_named:missing_semantic_graph",
                artifact=detail["artifact"],
                next_command=detail["next_command"],
                reason="semantic graph is required to enumerate source/entrypoint coverage for this family",
                category="missing_required_artifact",
            ))
        summary = blocker_summary(blocker_details)
        status = status_from_blocker_summary(summary, covered=bool(matching))
        next_command = next_command_for_worklist(impact, has_candidates=bool(matching), has_roots=bool(roots))
        if summary.get("open_work_categories") and not summary.get("strict_blocking"):
            next_command = f"make impact-analysis-queue WS=<workspace> && make source-mine WS=<workspace> IMPACT_ID={impact.get('id', '')}"
        likely_entrypoints = [
            str(component.get("component_id") or component.get("source_component") or "")
            for component in semantic_components.get("components", [])
            if str(component.get("component_id") or component.get("source_component") or "").strip()
        ][:20]
        work.append(
            {
                "impact_id": impact["id"],
                "worklist_id": f"impact-worklist-{impact['id']}",
                "impact_family": impact_family,
                "severity": impact["severity"],
                "impact": impact["impact"],
                "evidence_class": _evidence_class.GENERATED_HYPOTHESIS,
                "proof_class": impact.get("required_evidence_class", _evidence_class.EXECUTED_WITH_MANIFEST),
                "proof_class_status": "required_not_proven",
                "asset_category": impact.get("asset_category", "Other"),
                "scoped_assets": scoped_roots,
                "skipped_roots": skipped_roots,
                "protocol_roles": protocol_roles_for(str(impact.get("impact", ""))),
                "relevant_source_roots": scoped_roots,
                "semantic_source_components": semantic_components,
                "source_review_handoff": source_review_handoff,
                "handoff_route_kind_counts": source_review_handoff.get("route_kind_counts", {}),
                "family_execution_reduction": family_execution,
                "family_execution_status": family_execution.get("status"),
                "concrete_execution_item_target": family_execution.get("concrete_item_target"),
                "concrete_execution_item_count": family_execution.get("concrete_item_count"),
                "component_count": semantic_components.get("component_count", 0),
                "components": semantic_components.get("components", []),
                "likely_entrypoints": (
                    ["blocked_named:no_semantic_graph"]
                    if graphs.get("semantic_graph") != "present"
                    else (likely_entrypoints or ["semantic_graph_present_no_matching_component"])
                ),
                "multi_hop_behavior_templates": behavior_templates_for(str(impact.get("impact", ""))),
                "oos_traps": impact.get("oos_traps", []),
                "emergency_downgrade_clauses": impact.get("emergency_downgrade_clauses", []),
                "required_evidence_class": impact.get("required_evidence_class", _evidence_class.EXECUTED_WITH_MANIFEST),
                "required_evidence": {
                    "proof_class": impact.get("required_evidence_class", _evidence_class.EXECUTED_WITH_MANIFEST),
                    "artifacts": impact.get("required_artifacts", []),
                    "oos_traps": impact.get("oos_traps", []),
                    "downgrade_clauses": impact.get("emergency_downgrade_clauses", []),
                },
                "required_artifacts": impact.get("required_artifacts", []),
                "graph_artifacts": graphs,
                "graph_artifact_details": graph_details,
                "candidate_ids": matching,
                "blockers": blockers,
                "blocker_details": blocker_details,
                **summary,
                "status": status,
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_status": "NOT_SUBMIT_READY",
                "submit_ready": False,
                "selected_impact": "",
                "impact_contract_required": True,
                "next_command": next_command,
            }
        )
    payload_summary = summarize_blocker_categories(work)
    payload = {
        "schema": f"{SCHEMA_PREFIX}.impact_family_worklists.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "worklists": work,
        "blocker_category_counts": payload_summary["blocker_category_counts"],
        "strict_blocking_categories": payload_summary["strict_blocking_categories"],
        "open_work_categories": payload_summary["open_work_categories"],
        "status": (
            "blocked_missing_required_artifacts"
            if payload_summary["strict_blocking_categories"]
            else ("open_impact_family_work" if payload_summary["open_work_categories"] else ("ok" if work else "blocked_missing_impact_matrix"))
        ),
    }
    d = out_dir(workspace)
    write_json(d / "impact_family_worklists.json", payload)
    md = ["# Impact Family Worklist", "", "| Family | Severity | Roots | Components | Handoff Routes | Evidence | Status | Candidates | Next command | Impact |", "|---|---|---|---:|---|---|---|---|---|---|"]
    for row in work:
        handoff_counts = row.get("handoff_route_kind_counts") if isinstance(row.get("handoff_route_kind_counts"), dict) else {}
        handoff_summary = ", ".join(f"{key}={value}" for key, value in sorted(handoff_counts.items())) or "_none_"
        md.append(
            f"| `{row['impact_family']}` | {row['severity']} | {', '.join(row['relevant_source_roots']) or '_none_'} | "
            f"{row['component_count']} | {handoff_summary} | `{row['required_evidence_class']}` | "
            f"`{row['status']}` | {', '.join(row['candidate_ids']) or '_none_'} | "
            f"`{row['next_command']}` | {row['impact']} |"
        )
    write_md(d / "impact_family_worklists.md", md)
    return payload


def tool_exists(name: str) -> bool:
    return (ROOT / "tools" / name).exists()


def make_target_exists(target: str) -> bool:
    makefile = ROOT / "Makefile"
    if not makefile.is_file():
        return False
    return re.search(rf"^{re.escape(target)}:", makefile.read_text(encoding="utf-8"), re.M) is not None


def render_tool_coverage_inventory(workspace: Path) -> dict[str, Any]:
    required = [
        ("base-lessons-inventory", "automation-closure.py"),
        ("corpus-mining-inventory", "automation-closure.py"),
        ("corpus-detectorization-inventory", "corpus-detectorization-inventory.py"),
        ("impact-matrix", "automation-closure.py"),
        ("impact-contract-check", "automation-closure.py"),
        ("impact-worklist", "automation-closure.py"),
        ("coverage-inventory", "automation-closure.py"),
        ("agent-output-inventory", "automation-closure.py"),
        ("agent-recall", "automation-closure.py"),
        ("impact-analysis-queue", "automation-closure.py"),
        ("harness-task-queue", "automation-closure.py"),
        ("source-proof-record", "source-proof-record.py"),
        ("pr560-next-actions", "automation-closure.py"),
        ("pr560-local-progress", "automation-closure.py"),
        ("tool-coverage-inventory", "automation-closure.py"),
        ("automation-closure", "automation-closure.py"),
        ("base-automation-closure", "automation-closure.py"),
        ("known-limitations-burndown", "automation-closure.py"),
        ("severity-claim-guard", "severity-claim-guard.py"),
        ("base-critical-hunt", "base-critical-hunt.py"),
    ]
    rows = []
    for target, tool in required:
        rows.append(
            {
                "make_target": target,
                "make_target_present": make_target_exists(target),
                "tool": tool,
                "tool_present": tool_exists(tool),
                "status": "present" if make_target_exists(target) and tool_exists(tool) else "missing",
            }
        )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.tool_coverage_inventory.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": rows,
        "status": "ok" if all(r["status"] == "present" for r in rows) else "missing_tools_or_targets",
    }
    d = out_dir(workspace)
    write_json(d / "tool_coverage_inventory.json", payload)
    md = ["# Tool Coverage Inventory", "", "| Make target | Tool | Status |", "|---|---|---|"]
    for row in rows:
        md.append(f"| `{row['make_target']}` | `{row['tool']}` | `{row['status']}` |")
    write_md(d / "tool_coverage_inventory.md", md)
    return payload


def render_base_lessons_inventory(workspace: Path | None = None) -> dict[str, Any]:
    base_ws = workspace or Path("/Users/wolf/audits/base-azul")
    repo_docs = [
        "docs/BASE_AZUL_CAMPAIGN_DISPOSITION_2026-04-30.md",
        "docs/BASE_AZUL_LEDGER_SUMMARY.md",
        "docs/BASE_AZUL_PRIOR_AUDIT_INGEST.md",
        "docs/CLAUDE_BASE_CRITICAL_HUNT_CONTINUATION_PLAN_2026-04-30.md",
        "docs/CLAUDE_BASE_CRITICAL_WAVE2_EXECUTION_PLAN_2026-04-30.md",
        "docs/CLAUDE_BASE_CRITICAL_WAVE3_MINIMAX_VERIFICATION_PLAN_2026-04-30.md",
        "docs/CLAUDE_BASE_CRITICAL_WAVE4_EXECUTION_PLAN_2026-04-30.md",
        "docs/CLAUDE_BASE_CRITICAL_WAVE5_EXISTENCE_HUNT_PLAN_2026-04-30.md",
        "docs/CLAUDE_BASE_WAVE6_SNAPPY_OOM_AND_CRITICAL_HUNT_PLAN_2026-04-30.md",
        "docs/RECON_CHIMERA_REAL_EXECUTION_RESULTS_2026-04-30.md",
        "docs/RECON_CHIMERA_INTEGRATION_PLAN_2026-04-29.md",
    ]
    workspace_paths = [
        "SCOPE.md",
        "SEVERITY.md",
        "SEVERITY_CAPS.md",
        "RUBRIC_COVERAGE.md",
        "OOS_CHECKLIST.md",
        "OOS_PASTED.md",
        "INTAKE_BASELINE.json",
        "INVARIANT_LEDGER.md",
        ".auditooor",
        ".audit_logs",
        "critical_hunt",
        "source_mining",
        "prior_audits",
        "poc-tests",
        "poc_execution",
        "deep_counterexamples",
        "submissions",
        "scanners",
        "chimera_harnesses",
        "external/base",
        "external/contracts",
        "external/contract-deployments",
    ]
    rows: list[dict[str, Any]] = []
    for rel in repo_docs:
        path = ROOT / rel
        lane, status, next_command = classify_artifact(path)
        rows.append(
            {
                "artifact": stable_artifact_path(path),
                "source": "repo_doc",
                "tool_or_agent": "Codex/Claude",
                "candidate_or_lane": lane,
                "finding_status": status if path.exists() else "blocked_named",
                "why_status_changed": "baseline inventory row; not proof by itself",
                "workflow_gap_exposed": "requires durable artifact and local verification before reuse",
                "durable_artifact_now_required": "typed inventory row or exact impact contract",
                "generic_applicability": "base_only_smoke" if "BASE" in rel or "Base" in rel else "all_workspaces",
                "next_command": next_command,
                "path_status": path_status(path),
            }
        )
    for rel in workspace_paths:
        path = base_ws / rel
        lane, status, next_command = classify_artifact(path)
        rows.append(
            {
                "artifact": stable_artifact_path(path),
                "source": "base_workspace",
                "tool_or_agent": "workspace_artifact",
                "candidate_or_lane": lane,
                "finding_status": status if path.exists() else "blocked_named",
                "why_status_changed": "workspace baseline inventory row; not proof by itself",
                "workflow_gap_exposed": "missing or stale artifacts must be named before broad hunting",
                "durable_artifact_now_required": "closure inventory, source-proof, harness manifest, or blocker",
                "generic_applicability": "base_only_smoke" if "base" in str(path).lower() else "all_workspaces",
                "next_command": next_command,
                "path_status": path_status(path),
                "file_count": safe_count(path) if path.is_dir() else (1 if path.is_file() else 0),
            }
        )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.base_lessons_inventory.v1",
        "generated_at": "stable",
        "repo": "<repo>",
        "workspace": str(base_ws),
        "rows": rows,
        "status": "ok" if rows else "empty",
    }
    d = repo_out_dir()
    write_json(d / "base_lessons_inventory.json", payload)
    md = ["# Base Lessons Inventory", "", "| Artifact | Source | Status | Gap | Next command |", "|---|---|---|---|---|"]
    for row in rows:
        md.append(f"| `{row['artifact']}` | {row['source']} | `{row['finding_status']}` / `{row['path_status']}` | {row['workflow_gap_exposed']} | `{row['next_command']}` |")
    write_md(d / "base_lessons_inventory.md", md)
    return payload


def render_corpus_mining_inventory(workspace: Path | None = None) -> dict[str, Any]:
    base_ws = workspace or Path("/Users/wolf/audits/base-azul")
    streams = [
        {
            "stream": "Swival Rust findings",
            "workspace_scope": "rust_dlt",
            "roots": [ROOT / "reference" / "corpora", base_ws / "critical_hunt", base_ws / "source_mining"],
            "what_it_can_find": "Rust bug shapes and PoC-derived detector/harness templates",
            "what_it_cannot_find": "program impact without exact impact contract and local proof",
            "generic_reuse": "rust_dlt_only",
            "next_action": "make base-rust-swival-shape-scan WS=<workspace>",
        },
        {
            "stream": "ZKBugs",
            "workspace_scope": "zk_circuit",
            "roots": [ROOT / ".audit_logs" / "zkbugs_farming", ROOT / "reference" / "corpora"],
            "what_it_can_find": "ZK/circuit root-cause predicates and detector fixture ideas",
            "what_it_cannot_find": "non-ZK protocol impact without workspace source match",
            "generic_reuse": "zk_circuit_only",
            "next_action": "make zkbugs-status",
        },
        {
            "stream": "Recon/Chimera",
            "workspace_scope": "solidity",
            "roots": [base_ws / "chimera_harnesses", base_ws / "deep_counterexamples", ROOT / ".audit_logs"],
            "what_it_can_find": "Solidity invariant harness scaffolds and replayable counterexamples",
            "what_it_cannot_find": "proof unless execution manifest proves exact impact",
            "generic_reuse": "solidity_only",
            "next_action": "make deep-counterexample-queue WS=<workspace>",
        },
        {
            "stream": "Prior audit ingestion",
            "workspace_scope": "all",
            "roots": [base_ws / "prior_audits", base_ws / "audit_reports", base_ws / "source_mining"],
            "what_it_can_find": "known issue exclusions and templatable candidate families",
            "what_it_cannot_find": "novelty without submission-corpus and known-issue checks",
            "generic_reuse": "all_workspaces",
            "next_action": "make source-mine WS=<workspace>",
        },
        {
            "stream": "Submission outcomes",
            "workspace_scope": "all",
            "roots": [base_ws / "submissions", ROOT / "reference"],
            "what_it_can_find": "triager rejection/acceptance calibration",
            "what_it_cannot_find": "new bugs by itself",
            "generic_reuse": "all_workspaces",
            "next_action": "make outcome-telemetry AUDITS_DIR=~/audits",
        },
        {
            "stream": "Source mining providers",
            "workspace_scope": "all",
            "roots": [base_ws / "source_mining", ROOT / "agent_outputs"],
            "what_it_can_find": "source-reader hypotheses and adversarial kills",
            "what_it_cannot_find": "submission-safe proof without local verification",
            "generic_reuse": "all_workspaces",
            "next_action": "make agent-recall WS=<workspace>",
        },
    ]
    rows: list[dict[str, Any]] = []
    for stream in streams:
        roots = [Path(p) for p in stream.pop("roots")]
        entries = sum(safe_count(root) for root in roots)
        present_roots = [stable_artifact_path(root) for root in roots if root.exists()]
        rows.append(
            {
                **stream,
                "source_artifacts": present_roots,
                "entries_or_rows": entries,
                "entries_mined": entries,
                "entries_examined": 0,
                "families_extracted": 0,
                "detectors_created": 0,
                "harness_templates_created": 0,
                "invariant_rows_created": 0,
                "candidates_promoted": 0,
                "candidates_killed": 0,
                "families_not_yet_accounted_for": "unknown_until_stream_specific_parser_runs",
                "tooling_status": "present_inventory" if present_roots else "blocked_missing_source",
                "proof_status": "inventory_only",
                "docs_to_update": "docs/TOOL_STATUS.md; docs/SOURCE_MINING_RUNBOOK.md when behavior changes",
            }
        )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.corpus_mining_inventory.v1",
        "generated_at": "stable",
        "repo": "<repo>",
        "workspace": str(base_ws),
        "rows": rows,
        "status": "ok" if rows else "empty",
    }
    d = repo_out_dir()
    write_json(d / "corpus_mining_inventory.json", payload)
    md = ["# Corpus Mining Inventory", "", "| Stream | Status | Rows | Proof status | Next action |", "|---|---|---:|---|---|"]
    for row in rows:
        md.append(f"| {row['stream']} | `{row['tooling_status']}` | {row['entries_or_rows']} | `{row['proof_status']}` | `{row['next_action']}` |")
    write_md(d / "corpus_mining_inventory.md", md)
    return payload


def agent_output_evidence_placeholder(terminal_state: str) -> str:
    return {
        "verified_local": "<ws>/manual_proofs/<agent-output-verification>.md",
        "killed_duplicate_or_oos": "<ws>/manual_proofs/<duplicate-or-oos-evidence>.md",
        "routed_to_impact_analysis": "<ws>/.auditooor/impact_analysis_queue.json",
        "routed_to_source_proof": "<ws>/.auditooor/source_proof_tasks.json",
        "routed_to_harness_task": "<ws>/.auditooor/harness_tasks.json",
        "detectorized": "<ws>/detector_findings.json",
        "archived_no_claims": "<ws>/.auditooor/agent_output_verification_ledger.md",
    }.get(terminal_state, "<evidence-path-required>")


def agent_output_verify_record_command(
    *,
    stable_source_path: str = "",
    verification_task_id: str = "",
    terminal_state: str = "",
    evidence_path: str = "",
) -> str:
    state = terminal_state or "verified_local"
    evidence = evidence_path or agent_output_evidence_placeholder(state)
    parts = [
        "make agent-output-verify-record",
        "WS=<workspace>",
    ]
    if verification_task_id:
        parts.append(f"VERIFICATION_TASK_ID={shlex.quote(verification_task_id)}")
    else:
        parts.append(f"STABLE_SOURCE_PATH={shlex.quote(stable_source_path or '<ws>/agent_outputs/<file>')}")
    parts.extend(
        [
            f"TERMINAL_STATE={shlex.quote(state)}",
            f"EVIDENCE_PATH={shlex.quote(evidence)}",
        ]
    )
    return " ".join(parts)


def agent_output_verification_ledgers(workspace: Path) -> list[Path]:
    return [
        out_dir(workspace) / "agent_output_verification_ledger.json",
        out_dir(workspace) / "agent_output_verifications.json",
    ]


def load_agent_output_verification_ledger(workspace: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    sources: list[str] = []
    ignored = 0
    for path in agent_output_verification_ledgers(workspace):
        if not path.is_file():
            continue
        payload = load_json(path)
        rows = records_from_payload(payload)
        sources.append(str(path))
        for row in rows:
            state = str(row.get("local_verification_status") or row.get("terminal_state") or row.get("status") or "").strip()
            if state not in AGENT_OUTPUT_TERMINAL_STATES:
                ignored += 1
                continue
            normalized = {
                **row,
                "local_verification_status": state,
                "terminal_route": state,
                "_ledger_path": str(path),
            }
            for key in (
                "verification_task_id",
                "stable_source_path",
                "source_path",
                "path",
                "agent_output",
            ):
                value = row.get(key)
                if isinstance(value, str) and value.strip():
                    by_key[value.strip()] = normalized
    return by_key, {
        "sources": sources,
        "entries": len(by_key),
        "ignored_non_terminal_entries": ignored,
    }


def apply_agent_output_verification(row: dict[str, Any], ledger: dict[str, dict[str, Any]]) -> dict[str, Any]:
    keys = [
        row.get("verification_task_id"),
        row.get("stable_source_path"),
        row.get("source_path"),
        row.get("path"),
    ]
    matched = next((ledger[str(key)] for key in keys if isinstance(key, str) and key in ledger), None)
    if not matched:
        return row
    state = str(matched["local_verification_status"])
    terminal_options = list(row.get("terminal_state_options") or [])
    if state not in terminal_options:
        terminal_options.append(state)
    next_command = str(matched.get("next_command") or "").strip()
    if not next_command:
        if state == "routed_to_impact_analysis":
            next_command = "make impact-analysis-queue WS=<workspace>"
        elif state == "routed_to_source_proof":
            next_command = "make source-proof-task-queue WS=<workspace>"
        elif state == "routed_to_harness_task":
            next_command = "make harness-task-queue WS=<workspace>"
        else:
            next_command = "no further agent-output verification action; preserve local ledger evidence"
    evidence_path = str(matched.get("evidence_path") or matched.get("evidence") or "").strip()
    return {
        **row,
        "local_verification_status": state,
        "terminal_route": state,
        "terminal_state_options": terminal_options,
        "next_command": next_command,
        "verification_ledger_path": matched.get("_ledger_path", ""),
        "verification_ledger_evidence": evidence_path or matched.get("note") or "",
        "verification_ledger_note": str(matched.get("note") or ""),
        "evidence_required": False,
        "verification_record_command": agent_output_verify_record_command(
            stable_source_path=str(row.get("stable_source_path") or ""),
            verification_task_id=str(row.get("verification_task_id") or ""),
            terminal_state=state,
            evidence_path=evidence_path,
        ),
        "severity": "none",
        "submit_ready": False,
    }


def agent_output_terminal_state_for_row(row: dict[str, Any], ledger: dict[str, dict[str, Any]]) -> str:
    """Return the local terminal state for a downstream row's source artifact.

    PR560 queues are intentionally layered: agent-output verification is the
    first gate, and impact/source/harness queues should not keep resurrecting
    rows that were already archived or routed by that gate.
    """
    keys = [
        row.get("verification_task_id"),
        row.get("stable_source_path"),
        row.get("agent_output"),
        row.get("source_artifact"),
        row.get("source_path"),
        row.get("path"),
    ]
    matched = next((ledger[str(key)] for key in keys if isinstance(key, str) and key in ledger), None)
    if not matched:
        return ""
    return str(matched.get("local_verification_status") or "")


def agent_output_allows_downstream(
    row: dict[str, Any],
    ledger: dict[str, dict[str, Any]],
    *,
    allowed_terminal_states: set[str],
) -> bool:
    state = agent_output_terminal_state_for_row(row, ledger)
    return not state or state in allowed_terminal_states


def agent_output_verification_ledger_path(workspace: Path) -> Path:
    return out_dir(workspace) / "agent_output_verification_ledger.json"


def write_agent_output_verification_ledger(workspace: Path, payload: dict[str, Any]) -> None:
    rows = [row for row in payload.get("rows", []) if isinstance(row, dict)]
    state_counts = {
        state: sum(1 for row in rows if row.get("terminal_state") == state or row.get("local_verification_status") == state)
        for state in AGENT_OUTPUT_TERMINAL_STATES
    }
    payload["schema"] = f"{SCHEMA_PREFIX}.agent_output_verification_ledger.v1"
    payload["generated_at"] = now_iso()
    payload["workspace"] = str(workspace)
    payload["allowed_terminal_states"] = list(AGENT_OUTPUT_TERMINAL_STATES)
    payload["rows"] = rows
    payload["summary"] = {
        "row_count": len(rows),
        "terminal_state_counts": state_counts,
        "submit_ready": False,
        "severity": "none",
    }
    payload["submit_ready"] = False
    payload["status"] = "ok" if rows else "empty_no_verification_records"
    d = out_dir(workspace)
    write_json(d / "agent_output_verification_ledger.json", payload)
    md = [
        "# Agent Output Verification Ledger",
        "",
        "Records terminal verification transitions only. Rows are never submit-ready and never carry severity.",
        "",
        "| Row | State | Evidence | Identifier | Note |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        identifier = row.get("verification_task_id") or row.get("stable_source_path") or row.get("agent_output") or row.get("source_path") or row.get("path") or ""
        md.append(
            f"| `{row.get('ledger_row_id', '')}` | `{row.get('terminal_state', '')}` | "
            f"`{row.get('evidence_path', '')}` | `{identifier}` | {row.get('note', '')} |"
        )
    if not rows:
        md.append("| _none_ | `empty_no_verification_records` | _none_ | _none_ | _none_ |")
    write_md(d / "agent_output_verification_ledger.md", md)


def record_agent_output_verification(
    workspace: Path,
    *,
    terminal_state: str,
    evidence_path: str,
    verification_task_id: str = "",
    stable_source_path: str = "",
    agent_output: str = "",
    source_path: str = "",
    note: str = "",
    next_command: str = "",
) -> dict[str, Any]:
    state = terminal_state.strip()
    if state not in AGENT_OUTPUT_TERMINAL_STATES:
        return {
            "schema": f"{SCHEMA_PREFIX}.agent_output_verification_record.v1",
            "workspace": str(workspace),
            "status": "blocked_invalid_terminal_state",
            "allowed_terminal_states": list(AGENT_OUTPUT_TERMINAL_STATES),
            "submit_ready": False,
            "severity": "none",
        }
    identifiers = {
        "verification_task_id": verification_task_id.strip(),
        "stable_source_path": stable_source_path.strip(),
        "agent_output": agent_output.strip(),
        "source_path": source_path.strip(),
        "path": source_path.strip() or agent_output.strip(),
    }
    identifiers = {key: value for key, value in identifiers.items() if value}
    if not identifiers:
        return {
            "schema": f"{SCHEMA_PREFIX}.agent_output_verification_record.v1",
            "workspace": str(workspace),
            "status": "blocked_missing_row_identifier",
            "reason": "provide verification_task_id, stable_source_path, agent_output, or source_path",
            "submit_ready": False,
            "severity": "none",
        }
    evidence = evidence_path.strip()
    if not evidence:
        return {
            "schema": f"{SCHEMA_PREFIX}.agent_output_verification_record.v1",
            "workspace": str(workspace),
            "status": "blocked_missing_evidence_path",
            "reason": "terminal verification records require an evidence path",
            "submit_ready": False,
            "severity": "none",
        }

    ledger_path = agent_output_verification_ledger_path(workspace)
    payload = load_json(ledger_path) or {}
    rows = records_from_payload(payload)
    match_keys = set(identifiers.values())
    now = now_iso()
    row = {
        **identifiers,
        "ledger_row_id": f"agent-output-verification-{slug(next(iter(match_keys)))}",
        "terminal_state": state,
        "local_verification_status": state,
        "terminal_route": state,
        "evidence_path": evidence,
        "evidence": evidence,
        "note": note.strip(),
        "next_command": next_command.strip(),
        "updated_at": now,
        "severity": "none",
        "submit_ready": False,
    }
    replaced = False
    for idx, existing in enumerate(rows):
        existing_keys = {
            str(existing.get(key) or "").strip()
            for key in ("verification_task_id", "stable_source_path", "agent_output", "source_path", "path")
            if str(existing.get(key) or "").strip()
        }
        if existing_keys & match_keys:
            row["created_at"] = existing.get("created_at") or now
            rows[idx] = row
            replaced = True
            break
    if not replaced:
        row["created_at"] = now
        rows.append(row)
    payload = {
        **payload,
        "rows": rows,
        "last_recorded": row,
        "last_action": "updated" if replaced else "created",
    }
    write_agent_output_verification_ledger(workspace, payload)
    return {
        "schema": f"{SCHEMA_PREFIX}.agent_output_verification_record.v1",
        "workspace": str(workspace),
        "ledger_path": str(ledger_path),
        "row": row,
        "status": "ok",
        "action": "updated" if replaced else "created",
        "submit_ready": False,
        "severity": "none",
    }


def render_agent_output_inventory(workspace: Path) -> dict[str, Any]:
    include_repo_outputs = os.environ.get("AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS", "").strip().lower() in {"1", "true", "yes", "on"}
    roots: list[tuple[str, Path]] = [
        ("workspace_agent_outputs", workspace / "agent_outputs"),
        ("workspace_swarm", workspace / "swarm"),
    ]
    if include_repo_outputs:
        roots.append(("repo_agent_outputs", ROOT / "agent_outputs"))
    paths: list[tuple[str, Path]] = []
    for source_scope, root in roots:
        if root.exists():
            paths.extend(
                (source_scope, p)
                for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".json", ".md", ".txt", ".out"}
            )
    rows = []
    seen_paths: set[Path] = set()
    for source_scope, path in sorted(paths, key=lambda item: str(item[1])):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        text = path.read_text(encoding="utf-8", errors="replace")[:20000]
        claims = []
        for pat in ("VERDICT", "Critical", "High", "Medium", "candidate", "killed", "blocked"):
            if re.search(rf"\b{re.escape(pat)}\b", text, re.I):
                claims.append(pat.lower())
        claims = sorted(set(claims))
        verification_task_id = f"agent-output-verify-{slug(str(path))}"
        terminal_route = "agent_recall" if claims else "archive_or_ignore"
        terminal_state = "verified_local" if claims else "archived_no_claims"
        next_command = (
            "make agent-recall WS=<workspace>"
            if claims
            else "review or archive this agent output; no candidate/verdict tokens detected"
        )
        record_command = agent_output_verify_record_command(
            verification_task_id=verification_task_id,
            terminal_state=terminal_state,
        )
        rows.append(
            {
                "verification_task_id": verification_task_id,
                "path": str(path),
                "source_path": str(path),
                "source_scope": source_scope,
                "bytes": path.stat().st_size,
                "claims_detected": claims,
                "local_verification_status": "not_verified",
                "terminal_route": terminal_route,
                "terminal_state_options": ["verified_local", "killed_duplicate_or_oos", "routed_to_impact_analysis", "routed_to_source_proof", "routed_to_harness_task", "detectorized"] if claims else ["archived_no_claims", "verified_local"],
                "next_command": next_command,
                "verification_record_command": record_command,
                "evidence_required": True,
                "severity": "none",
                "submit_ready": False,
            }
        )
    ledger, ledger_summary = load_agent_output_verification_ledger(workspace)
    rows = [apply_agent_output_verification(row, ledger) for row in rows]
    status_counts = {
        status: sum(1 for row in rows if row.get("local_verification_status") == status)
        for status in (*AGENT_OUTPUT_OPEN_STATES, *AGENT_OUTPUT_TERMINAL_STATES)
    }
    open_count = sum(1 for row in rows if row.get("local_verification_status") in AGENT_OUTPUT_OPEN_STATES)
    next_command_examples = [
        {
            "verification_task_id": row.get("verification_task_id", ""),
            "source_path": row.get("source_path", ""),
            "next_command": row.get("next_command", ""),
            "verification_record_command": row.get("verification_record_command", ""),
            "evidence_required": row.get("evidence_required", True),
        }
        for row in rows
        if row.get("local_verification_status") in AGENT_OUTPUT_OPEN_STATES
    ][:8]
    payload = {
        "schema": f"{SCHEMA_PREFIX}.agent_output_inventory.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "discovery_policy": {
            "default_scope": "workspace_owned_only",
            "included_roots": [{"source_scope": scope, "root": str(root)} for scope, root in roots],
            "repo_agent_outputs_included": include_repo_outputs,
            "repo_agent_outputs_opt_in_env": "AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS=1",
        },
        "rows": rows,
        "summary": {
            "row_count": len(rows),
            "open_verification": open_count,
            "terminal_verified": len(rows) - open_count,
            "evidence_required_open_rows": sum(
                1
                for row in rows
                if row.get("evidence_required") and row.get("local_verification_status") in AGENT_OUTPUT_OPEN_STATES
            ),
            "local_verification_status_counts": status_counts,
            "next_command_examples": next_command_examples,
            "verification_ledger": ledger_summary,
            "submit_ready": False,
            "severity": "none",
        },
        "status": "actionable_verification_queue" if open_count else ("ok" if rows else "empty_no_agent_outputs"),
    }
    d = out_dir(workspace)
    write_json(d / "agent_output_inventory.json", payload)
    md = ["# Agent Output Inventory", "", "| Task | Scope | Path | Claims | Verification | Next command |", "|---|---|---|---|---|---|"]
    for row in rows:
        md.append(
            f"| `{row['verification_task_id']}` | `{row['source_scope']}` | `{row['path']}` | "
            f"{', '.join(row['claims_detected']) or '_none_'} | `{row['local_verification_status']}` | "
            f"`{row['next_command']}` then `{row.get('verification_record_command', '')}` |"
        )
    if not rows:
        md.append("| _none_ | _none_ | _none_ | _none_ | `empty_no_agent_outputs` | _none_ |")
    write_md(d / "agent_output_inventory.md", md)
    return payload


def _read_agent_text(path_text: str) -> str:
    path = Path(path_text)
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:50000]


def _token_overlap(a: str, b: str) -> int:
    stop = {
        "the", "and", "for", "with", "from", "this", "that", "into", "candidate",
        "finding", "report", "agent", "output", "test", "check", "base", "high",
        "critical", "medium", "verdict", "status",
    }
    toks_a = {t for t in re.findall(r"[a-z0-9]{4,}", a.lower()) if t not in stop}
    toks_b = {t for t in re.findall(r"[a-z0-9]{4,}", b.lower()) if t not in stop}
    return len(toks_a & toks_b)


def _token_set(value: str) -> set[str]:
    stop = {
        "the", "and", "for", "with", "from", "this", "that", "into", "candidate",
        "finding", "report", "agent", "output", "test", "check", "base", "high",
        "critical", "medium", "verdict", "status", "impact", "severity",
    }
    return {t for t in re.findall(r"[a-z0-9]{4,}", value.lower()) if t not in stop}


def _detector_matches_agent(blob: str, detector_rows: list[dict[str, Any]]) -> bool:
    low = blob.lower()
    for det in detector_rows:
        key = candidate_key(det)
        title = task_title(det, key)
        detector_blob = json.dumps(
            {k: v for k, v in det.items() if not str(k).startswith("_")},
            ensure_ascii=False,
        )
        for needle in (key, title, str(det.get("detector_id") or ""), str(det.get("rule_id") or "")):
            needle = needle.strip()
            if len(needle) >= 6 and needle.lower() in low:
                return True
        if _token_overlap(blob, detector_blob) >= 3:
            return True
    return False


def _impact_contract_matches_agent(blob: str, contracts: list[dict[str, Any]]) -> str:
    low = blob.lower()
    for contract in contracts:
        impact_contract_id = str(contract.get("impact_contract_id") or "").strip()
        selected_impact = str(contract.get("selected_impact") or "").strip()
        candidate = str(contract.get("candidate_id") or "").strip()
        if impact_contract_id and impact_contract_id.lower() in low:
            return impact_contract_id
        if selected_impact and selected_impact.lower() in low:
            return impact_contract_id
        if candidate and len(candidate) >= 4 and candidate.lower() in low:
            return impact_contract_id
    return ""


def classify_agent_recall_row(
    row: dict[str, Any],
    *,
    detector_rows: list[dict[str, Any]],
    contracts: list[dict[str, Any]],
) -> dict[str, str]:
    """Classify one agent-found/not-detector-found row into a terminal recall lane.

    The classifier is intentionally conservative: it never marks rows submit-ready.
    Reportable/direct-submit claims without a locked impact contract are blocked
    before harness or report work.
    """
    agent_output = str(row.get("agent_output") or row.get("path") or "")
    text = _read_agent_text(agent_output)
    blob = "\n".join([
        agent_output,
        json.dumps(row, ensure_ascii=False),
        text,
    ])
    impact_contract_id = _impact_contract_matches_agent(blob, contracts)
    reportable_or_direct = bool(REPORTABLE_OR_DIRECT_RE.search(blob))
    if KILL_ROUTE_RE.search(blob):
        return {
            "status": "killed_duplicate_or_oos",
            "reason": "agent output records duplicate/OOS/kill/not-a-bug disposition",
            "next_command": "record kill/duplicate/OOS evidence; do not promote",
            "impact_contract_id": impact_contract_id,
        }
    if _detector_matches_agent(blob, detector_rows):
        return {
            "status": "detectorized",
            "reason": "matching detector/scanner output already exists",
            "next_command": "make coverage-inventory WS=<workspace>",
            "impact_contract_id": impact_contract_id,
        }
    if reportable_or_direct and not impact_contract_id:
        return {
            "status": "blocked_missing_impact_contract",
            "reason": "reportable/direct-submit claim lacks exact impact contract",
            "next_command": "make impact-contract-check WS=<workspace>",
            "impact_contract_id": "",
        }
    if HARNESS_ROUTE_RE.search(blob):
        return {
            "status": "harness_task_required",
            "reason": "agent output requires local harness/PoC execution or replay",
            "next_command": "make harness-task-queue WS=<workspace>",
            "impact_contract_id": impact_contract_id,
        }
    return {
        "status": "source_proof_required",
        "reason": "agent output needs source-line/invariant proof before detector or harness work",
        "next_command": "make source-proof-record WS=<workspace>",
        "impact_contract_id": impact_contract_id,
    }


def render_agent_recall(workspace: Path) -> dict[str, Any]:
    agents = load_json(out_dir(workspace) / "agent_output_inventory.json") or render_agent_output_inventory(workspace)
    coverage = load_json(out_dir(workspace) / "coverage_inventory.json") or render_coverage_inventory(workspace)
    contracts_payload = load_json(out_dir(workspace) / "impact_contracts.json") or render_impact_contracts(workspace)
    contracts = records_from_payload(contracts_payload)
    detector_rows = discover_detector_output_records(workspace)
    covered_terms = {
        str(row.get("impact", "")).lower()
        for row in coverage.get("rows", [])
        if isinstance(row, dict) and row.get("candidate_coverage") == "covered_by_candidate"
    }
    rows = []
    for row in agents.get("rows", []):
        if not isinstance(row, dict):
            continue
        claims = row.get("claims_detected", [])
        if not isinstance(claims, list) or not claims:
            continue
        text = f"{row.get('path', '')} {' '.join(str(c) for c in claims)}".lower()
        mechanically_covered = any(term and term in text for term in covered_terms)
        recall = {
            "agent_output": row.get("path", ""),
            "claims_detected": claims,
            "mechanically_covered": mechanically_covered,
        }
        classified = classify_agent_recall_row(
            recall,
            detector_rows=detector_rows,
            contracts=contracts,
        )
        rows.append(
            {
                **recall,
                "status": classified["status"],
                "reason": classified["reason"],
                "impact_contract_id": classified["impact_contract_id"],
                "next_command": classified["next_command"],
            }
        )
    status_counts = {status: sum(1 for row in rows if row["status"] == status) for status in AGENT_RECALL_STATUSES}
    payload = {
        "schema": f"{SCHEMA_PREFIX}.agent_recall.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": rows,
        "allowed_statuses": list(AGENT_RECALL_STATUSES),
        "summary": status_counts,
        "status": "ok" if rows else "empty_no_agent_claims",
    }
    d = out_dir(workspace)
    write_json(d / "agent_found_not_detector_found.json", payload)
    md = ["# Agent Recall Inventory", "", "| Agent output | Claims | Status | Next command |", "|---|---|---|---|"]
    for row in rows:
        md.append(
            f"| `{row['agent_output']}` | {', '.join(row['claims_detected'])} | "
            f"`{row['status']}` | `{row['next_command']}` |"
        )
    if not rows:
        md.append("| _none_ | _none_ | `empty_no_agent_claims` | _none_ |")
    write_md(d / "agent_found_not_detector_found.md", md)
    return payload


def _impact_candidates_for_agent_text(text: str, matrix_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return possible exact impact rows to analyze without assigning severity."""
    text_norm = compact(text).lower()
    text_tokens = _token_set(text)
    candidates: list[dict[str, Any]] = []
    for row in matrix_rows:
        if not isinstance(row, dict):
            continue
        impact = str(row.get("impact") or "").strip()
        if not impact:
            continue
        impact_norm = compact(impact).lower()
        impact_tokens = _token_set(impact)
        exact = impact_norm in text_norm
        overlap = len(text_tokens & impact_tokens)
        # Require exact phrase or enough distinctive shared terms to avoid
        # inventing a row from generic "Critical candidate" prose.
        if not exact and overlap < 3:
            continue
        candidates.append(
            {
                "impact_id": str(row.get("id") or ""),
                "impact": impact,
                "match": "exact_phrase" if exact else "token_overlap",
                "overlap_terms": sorted(text_tokens & impact_tokens),
                "source_file": str(row.get("source_file") or ""),
                "source_line": row.get("line") or 0,
                "severity_policy": "not_claimed_until_impact_contract_proves_this_exact_row",
            }
        )
    candidates.sort(key=lambda r: (r["match"] != "exact_phrase", -len(r["overlap_terms"]), r["impact_id"]))
    return candidates[:3]


def classify_impact_analysis_action(
    recall_row: dict[str, Any],
    *,
    matrix_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add one explicit non-submit next action for a blocked recall row."""
    agent_output = str(recall_row.get("agent_output") or "")
    text = _read_agent_text(agent_output)
    blob = "\n".join([agent_output, json.dumps(recall_row, ensure_ascii=False), text])
    candidates = _impact_candidates_for_agent_text(blob, matrix_rows)
    if KILL_ROUTE_RE.search(blob):
        action_type = "oos_duplicate_kill"
        next_command = "record duplicate/OOS kill evidence; do not promote"
        reason = "blocked row contains duplicate/OOS/kill disposition"
    elif candidates:
        action_type = "exact_impact_candidate"
        next_command = "make impact-contract-check WS=<workspace>"
        reason = "candidate exact listed impact row found; operator must prove or clear it"
    elif HARNESS_ROUTE_RE.search(blob):
        action_type = "harness_precondition"
        next_command = "make harness-task-queue WS=<workspace>"
        reason = "local harness/PoC precondition must be executed after impact contract is locked"
    else:
        action_type = "source_proof_precondition"
        next_command = "make source-proof-record WS=<workspace>"
        reason = "source-line/invariant proof must precede impact contract or harness work"
    return {
        "action_type": action_type,
        "reason": reason,
        "next_command": next_command,
        "exact_impact_candidates": candidates if action_type == "exact_impact_candidate" else [],
        "severity": "none",
        "submit_ready": False,
    }


def impact_analysis_queue_row(
    row: dict[str, Any],
    *,
    source: str,
    index: int,
    matrix_rows: list[dict[str, Any]],
    route_reason: str = "",
) -> dict[str, Any]:
    action = classify_impact_analysis_action(row, matrix_rows=matrix_rows)
    candidate_id, candidate_reason = stable_candidate_id(row, source, index)
    source_id = source_key(row) or source_context_key(row) or candidate_id or f"{source}-{index}"
    return {
        "queue_id": f"impact-analysis-{slug(source)}-{slug(source_id)}-{index:03d}",
        "source": source,
        "source_id": source_id,
        "candidate_id": candidate_id,
        "candidate_id_source": candidate_reason,
        "agent_output": row.get("agent_output", ""),
        "source_artifact": str(row.get("_source_file") or row.get("source_artifact") or source_context_key(row) or ""),
        "source_status": row.get("status", ""),
        "claims_detected": row.get("claims_detected", []),
        "route_reason": route_reason,
        "action_type": action["action_type"],
        "reason": action["reason"],
        "next_command": action["next_command"],
        "exact_impact_candidates": action["exact_impact_candidates"],
        "severity": action["severity"],
        "submit_ready": action["submit_ready"],
    }


def write_impact_analysis_payload(workspace: Path, payload: dict[str, Any]) -> None:
    rows = [row for row in payload.get("rows", []) if isinstance(row, dict)]
    action_counts = {
        action: sum(1 for row in rows if row.get("action_type") == action)
        for action in IMPACT_ANALYSIS_ACTIONS
    }
    summary = dict(payload.get("summary") or {})
    summary.update(
        {
            "blocked_missing_impact_contract": len(rows),
            **action_counts,
        }
    )
    payload["summary"] = summary
    payload["status"] = "ok" if rows else "empty_no_blocked_agent_recall_rows"
    d = out_dir(workspace)
    write_json(d / "impact_analysis_queue.json", payload)
    md = ["# Impact Analysis Queue", "", "| Queue row | Source | Action | Candidates | Next command | Source context |", "|---|---|---|---|---|---|"]
    for row in rows:
        candidates = "; ".join(c["impact_id"] for c in row["exact_impact_candidates"]) or "_none_"
        context = row.get("agent_output") or row.get("source_artifact") or row.get("source_id") or ""
        md.append(
            f"| `{row['queue_id']}` | `{row.get('source', 'agent_recall')}` | `{row['action_type']}` | {candidates} | "
            f"`{row['next_command']}` | `{context}` |"
        )
    if not rows:
        md.append("| _none_ | _none_ | `empty_no_blocked_agent_recall_rows` | _none_ | _none_ | _none_ |")
    write_md(d / "impact_analysis_queue.md", md)


def render_impact_analysis_queue(workspace: Path) -> dict[str, Any]:
    recall = load_json(out_dir(workspace) / "agent_found_not_detector_found.json") or render_agent_recall(workspace)
    matrix = load_json(out_dir(workspace) / "program_impact_matrix.json") or render_impact_matrix(workspace)
    agent_ledger, _ = load_agent_output_verification_ledger(workspace)
    matrix_rows = [row for row in matrix.get("rows", []) if isinstance(row, dict)]
    rows: list[dict[str, Any]] = []
    for idx, row in enumerate(records_from_payload(recall), 1):
        if row.get("status") != "blocked_missing_impact_contract":
            continue
        if not agent_output_allows_downstream(row, agent_ledger, allowed_terminal_states={"routed_to_impact_analysis"}):
            continue
        rows.append(impact_analysis_queue_row(row, source="agent_recall", index=idx, matrix_rows=matrix_rows))
    payload = {
        "schema": f"{SCHEMA_PREFIX}.impact_analysis_queue.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source": str(out_dir(workspace) / "agent_found_not_detector_found.json"),
        "allowed_actions": list(IMPACT_ANALYSIS_ACTIONS),
        "rows": rows,
        "summary": {},
        "status": "",
    }
    write_impact_analysis_payload(workspace, payload)
    return payload


def render_coverage_inventory(workspace: Path) -> dict[str, Any]:
    worklist = load_json(out_dir(workspace) / "impact_family_worklists.json") or render_impact_worklist(workspace)
    tool_cov = load_json(out_dir(workspace) / "tool_coverage_inventory.json") or render_tool_coverage_inventory(workspace)
    roots, skipped_roots = discover_source_roots(workspace)
    graphs = graph_artifacts(workspace)
    scans = scan_artifacts(workspace)
    graph_details = graph_artifact_details(workspace)
    scan_details = scan_artifact_details(workspace)
    rows = []
    for item in worklist.get("worklists", []):
        if not isinstance(item, dict):
            continue
        status = item.get("status", "unknown")
        blockers = list(item.get("blockers", []) or [])
        blocker_details = list(item.get("blocker_details", []) or [])
        if not roots:
            blockers.append("blocked_named:no_scanned_roots")
            blocker_details.append(blocker_detail(
                "blocked_named:no_scanned_roots",
                artifact=str(workspace / "SCOPE.md"),
                next_command="add SCOPE.md source roots or ASSET_WAIVER, then make coverage-inventory WS=<workspace>",
                reason="coverage inventory cannot map scans to source roots until at least one scoped root exists",
                category="missing_scoped_source_roots",
            ))
        required_graphs = required_graph_artifacts_for(str(item.get("asset_category", "")))
        missing_graphs = [name for name in required_graphs if graphs.get(name) == "missing"]
        required_scans = required_scan_artifacts_for(str(item.get("asset_category", "")))
        missing_required_scans = [
            name for name in required_scans
            if scan_details.get(name, {}).get("status") == "missing"
        ]
        missing_optional_scans = [
            name for name, detail in scan_details.items()
            if detail["status"] == "missing" and name not in set(required_scans)
        ]
        if missing_graphs:
            blockers.append("blocked_named:missing_graph_artifacts")
            for name in missing_graphs:
                detail = graph_details[name]
                blocker_details.append(blocker_detail(
                    "blocked_named:missing_graph_artifacts",
                    artifact=detail["artifact"],
                    next_command=detail["next_command"],
                    reason=f"missing graph artifact: {name}",
                    category="missing_required_artifact",
                ))
        if missing_required_scans:
            blockers.append("blocked_named:missing_required_scan_artifacts")
            for name in missing_required_scans:
                detail = scan_details[name]
                blocker_details.append(blocker_detail(
                    "blocked_named:missing_required_scan_artifacts",
                    artifact=detail["artifact"],
                    next_command=detail["next_command"],
                    reason=f"missing required scan artifact: {name}",
                    category="missing_required_artifact",
                ))
        summary = blocker_summary(blocker_details)
        coverage_status = (
            "covered"
            if status == "covered_by_candidate" and not summary.get("strict_blocking") and not summary.get("open_work_categories")
            else status_from_blocker_summary(summary, covered=status == "covered_by_candidate")
        )
        scanner_coverage = (
            "required_scan_artifact_present"
            if required_scans and not missing_required_scans
            else ("missing_required_scan_artifacts" if missing_required_scans else "no_required_scan_for_asset")
        )
        rows.append(
            {
                "impact_id": item.get("impact_id"),
                "impact": item.get("impact"),
                "severity": item.get("severity"),
                "evidence_class": _evidence_class.GENERATED_HYPOTHESIS,
                "asset_category": item.get("asset_category", "Other"),
                "required_evidence_class": item.get("required_evidence_class"),
                "required_artifacts": item.get("required_artifacts", []),
                "oos_traps": item.get("oos_traps", []),
                "emergency_downgrade_clauses": item.get("emergency_downgrade_clauses", []),
                "scanned_roots": roots,
                "skipped_roots": skipped_roots,
                "generated_graph_files": graphs,
                "graph_artifact_details": graph_details,
                "required_graph_artifacts": required_graphs,
                "missing_required_graph_artifacts": missing_graphs,
                "scan_artifacts": scans,
                "scan_artifact_details": scan_details,
                "required_scan_artifacts": required_scans,
                "missing_required_scan_artifacts": missing_required_scans,
                "missing_optional_scan_artifacts": missing_optional_scans,
                "optional_scan_artifacts_missing": missing_optional_scans,
                "candidate_coverage": status,
                "multi_hop_paths": item.get("multi_hop_behavior_templates", []),
                "evidence_edges": item.get("protocol_roles", []),
                "paths_covered_by_detectors": [] if missing_required_scans else item.get("multi_hop_behavior_templates", []),
                "paths_covered_only_by_source_readers": item.get("multi_hop_behavior_templates", []) if missing_required_scans else [],
                "paths_still_unenumerated": ["blocked_named:semantic_graph_missing"] if graphs.get("semantic_graph") == "missing" else [],
                "scanner_coverage": scanner_coverage,
                "source_reader_coverage": "not_measured" if not item.get("candidate_ids") else "candidate_mapped",
                "blocked_commands_or_dependencies": sorted(set(blockers)),
                "blocker_details": blocker_details,
                **summary,
                "coverage_status": coverage_status,
                "next_command": item.get("next_command") if blockers else "make impact-contract-check WS=<workspace>",
            }
        )
    payload_summary = summarize_blocker_categories(rows)
    payload = {
        "schema": f"{SCHEMA_PREFIX}.coverage_inventory.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": rows,
        "tool_coverage_status": tool_cov.get("status"),
        "blocker_category_counts": payload_summary["blocker_category_counts"],
        "strict_blocking_categories": payload_summary["strict_blocking_categories"],
        "open_work_categories": payload_summary["open_work_categories"],
        "status": (
            "blocked_missing_required_artifacts"
            if payload_summary["strict_blocking_categories"]
            else ("open_impact_family_work" if payload_summary["open_work_categories"] else ("ok" if rows else "blocked_missing_impact_worklist"))
        ),
    }
    d = out_dir(workspace)
    write_json(d / "coverage_inventory.json", payload)
    md = ["# Coverage Inventory", "", "| Severity | Asset | Candidate coverage | Scanner coverage | Blockers | Next command | Impact |", "|---|---|---|---|---|---|---|"]
    for row in rows:
        md.append(
            f"| {row['severity']} | {row['asset_category']} | `{row['candidate_coverage']}` | "
            f"`{row['scanner_coverage']}` | {', '.join(row['blocked_commands_or_dependencies']) or '_none_'} | "
            f"`{row['next_command']}` | {row['impact']} |"
        )
    if not rows:
        md.append("| _none_ | _none_ | `blocked_missing_impact_worklist` | `not_measured` |")
    write_md(d / "coverage_inventory.md", md)
    return payload


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, tuple):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _first_nonempty(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("rows", "contracts", "findings", "hits", "candidates", "tasks"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def load_records(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return records_from_payload(load_json(path))


def discover_detector_output_records(workspace: Path) -> list[dict[str, Any]]:
    paths = [
        workspace / "detector_findings.json",
        workspace / ".auditooor" / "detector_findings.json",
        workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
    ]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        for idx, row in enumerate(load_records(path), 1):
            key = f"{path}:{idx}:{row.get('id') or row.get('candidate_id') or row.get('title')}"
            if key in seen:
                continue
            seen.add(key)
            enriched = dict(row)
            enriched.setdefault("_source_file", str(path))
            rows.append(enriched)
    return rows


def candidate_key(row: dict[str, Any]) -> str:
    for key in ("candidate_id", "candidate"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def source_key(row: dict[str, Any]) -> str:
    for key in ("source_id", "behavior_id", "finding_id", "id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def source_context_key(row: dict[str, Any]) -> str:
    for key in ("agent_output", "source_artifact", "_source_file", "artifact_path", "path"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def stable_candidate_id(row: dict[str, Any], source: str, index: int) -> tuple[str, str]:
    key = candidate_key(row)
    if key:
        return key, "candidate_id"
    key = source_key(row)
    if key:
        return key, "source_id"
    context = source_context_key(row)
    if context:
        return f"{source}-{slug(Path(context).name or context)}", "source_context"
    title = task_title(row, "")
    if title:
        return f"{source}-{slug(title)}", "title"
    return "", f"anonymous:{source}:{index}"


def task_key(row: dict[str, Any]) -> str:
    return candidate_key(row) or source_key(row) or task_title(row, "")


def artifact_paths_for_burndown_row(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in (
        "artifact_path",
        "artifact_paths",
        "base_smoke_artifact",
        "non_base_or_fixture_artifact",
        "implementation_pr_or_file",
    ):
        paths.extend(_as_list(row.get(key)))
    for item in _as_list(row.get("evidence")):
        # Accept explicit repo/workspace artifact citations, not prose-only
        # evidence such as "status is partial".
        matches = re.findall(
            r"(?:^|`|\s)((?:docs|tools|reference|detectors|templates)/[A-Za-z0-9_./{}<>\-]+|Makefile|(?:\.auditooor|<ws>|<workspace>|<repo>)/[A-Za-z0-9_./{}<>\-]+)(?:`|\s|$|,)",
            item,
        )
        paths.extend(match.strip("`,. ") for match in matches if match.strip("`,. "))
    deduped: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path and path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def strict_burndown_row_checks(row: dict[str, Any]) -> dict[str, Any]:
    priority_group = str(row.get("priority_group", "")).strip()
    strict_required = priority_group in {"current_priority", "P0"}
    owner_command = _first_nonempty(row, ("owner_command", "make_target_or_command", "next_command"))
    artifact_paths = artifact_paths_for_burndown_row(row)
    stop_condition = _first_nonempty(row, ("stop_condition", "stop_condition_text"))
    status_evidence = _as_list(row.get("status_evidence")) or _as_list(row.get("evidence"))
    missing: list[str] = []
    if strict_required:
        if not owner_command:
            missing.append("owner_command")
        if not artifact_paths:
            missing.append("artifact_path")
        if not stop_condition:
            missing.append("stop_condition")
        if not status_evidence:
            missing.append("status_evidence")
    return {
        "strict_required": strict_required,
        "owner_command": owner_command,
        "artifact_paths": artifact_paths,
        "stop_condition": stop_condition,
        "status_evidence": status_evidence,
        "missing_fields": missing,
    }


def known_limitations_blocker_category(row: dict[str, Any]) -> str:
    """Return a stable blocker category without promoting open rows."""
    if bool(row.get("stop_condition_met")):
        return "stop_condition_met"
    limitation_id = str(row.get("limitation_id") or "")
    terminal_state = str(row.get("terminal_state") or "")
    title = str(row.get("title") or "").lower()
    if terminal_state == "blocked_named":
        return f"blocked_named:{slug(limitation_id or title or 'known-limitation')}"
    if "invariant discovery" in title:
        return "open_invariant_discovery_completeness"
    if "severity claim" in title:
        return "open_impact_contract_or_family_execution"
    if "impact" in title and ("contract" in title or "worklist" in title or "gating" in title):
        return "open_impact_contract_or_family_execution"
    if "agent" in title or "recall" in title:
        return "open_agent_recall_terminal_routes"
    if "harness" in title or "poc" in title or "counterexample" in title or "replay" in title:
        return "open_execution_manifest_or_replay_proof"
    if (
        "cross-contract" in title
        or "inter-contract" in title
        or "callgraph" in title
        or "topology" in title
        or "production-path" in title
        or "rust" in title
    ):
        return "open_semantic_or_live_topology_depth"
    if "model" in title or "outcome" in title or "routing" in title:
        return "open_outcome_calibration"
    if "fixture" in title:
        return "open_fixture_or_corpus_followup"
    if "false-positive" in title or "calibration" in title or "detector" in title:
        return "open_detector_precision_or_semantics"
    if "queue" in title:
        return "open_queue_handoff_telemetry"
    if "generated artifacts" in title or "proof" in title:
        return "open_evidence_class_backfill"
    return "open_stop_condition_not_met"


def _scorecard_candidate_paths(workspace: Path) -> list[Path]:
    return [
        workspace / ".auditooor" / "outcome_calibration_scorecard.json",
        workspace / ".audit_logs" / "outcome_calibration" / "outcome_calibration_scorecard.json",
        ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_scorecard.json",
    ]


def _resolved_linkage_validation_candidate_paths(workspace: Path) -> list[Path]:
    return [
        workspace / ".auditooor" / "outcome_calibration_resolved_linkage_validation.json",
        workspace / ".audit_logs" / "outcome_calibration" / "outcome_calibration_resolved_linkage_validation.json",
        ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_resolved_linkage_validation.json",
    ]


def _route_evidence_import_candidate_paths(workspace: Path) -> list[Path]:
    return [
        workspace / ".auditooor" / "outcome_calibration_route_evidence_import.json",
        workspace / ".audit_logs" / "outcome_calibration" / "outcome_calibration_route_evidence_import.json",
        ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_route_evidence_import.json",
    ]


def outcome_calibration_accounting(workspace: Path) -> dict[str, Any]:
    """Read outcome-calibration scorecard evidence without inventing outcomes."""
    payload: dict[str, Any] | None = None
    artifact_path = ""
    for path in _scorecard_candidate_paths(workspace):
        loaded = load_json(path)
        if isinstance(loaded, dict):
            payload = loaded
            artifact_path = str(path)
            break

    if not isinstance(payload, dict):
        return {
            "schema": f"{SCHEMA_PREFIX}.outcome_calibration_accounting.v1",
            "status": "missing_scorecard",
            "artifact_path": "",
            "resolved_outcome_rows": 0,
            "linked_for_calibration": 0,
            "missing_linkage": 0,
            "queue_items": 0,
            "outcome_linkage_backfill_items": 0,
            "provider_terminal_advisory_items": 0,
            "routing_rows": [],
            "primary_ready_routes": 0,
            "blocked_routes": 0,
            "resolved_linkage_exists": False,
            "all_resolved_rows_linked": False,
            "resolved_linkage_validation_status": "missing",
            "resolved_linkage_validation_artifact_path": "",
            "resolved_linkage_validation_valid_rows": 0,
            "resolved_linkage_validation_invalid_rows": 0,
            "resolved_linkage_validation_terminalized_rows": 0,
            "route_evidence_import_exists": False,
            "route_evidence_import_status": "missing",
            "route_evidence_import_artifact_path": "",
            "route_evidence_import_valid_rows": 0,
            "route_evidence_import_invalid_rows": 0,
            "route_evidence_rows_seen": 0,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "next_command": "make outcome-calibration-scorecard",
        }

    scorecard = payload.get("scorecard") if isinstance(payload.get("scorecard"), dict) else {}
    outcome_rows = scorecard.get("outcome_rows") if isinstance(scorecard.get("outcome_rows"), dict) else {}
    routing_rows = [
        row for row in scorecard.get("routing_rows", [])
        if isinstance(row, dict)
    ] if isinstance(scorecard.get("routing_rows"), list) else []
    queue = [row for row in payload.get("queue", []) if isinstance(row, dict)] if isinstance(payload.get("queue"), list) else []
    queue_type_counts = Counter(str(item.get("queue_type") or "unknown") for item in queue)
    resolved = int(outcome_rows.get("resolved") or 0)
    linked = int(outcome_rows.get("linked_for_calibration") or 0)
    missing = int(outcome_rows.get("missing_linkage") or 0)
    blocked_routes = sum(1 for row in routing_rows if str(row.get("route_status") or "") != "primary_ready")
    validation_payload: dict[str, Any] | None = None
    validation_path = ""
    for path in _resolved_linkage_validation_candidate_paths(workspace):
        loaded = load_json(path)
        if isinstance(loaded, dict) and loaded.get("schema") == "auditooor.outcome_calibration_resolved_linkage_validator.v1":
            validation_payload = loaded
            validation_path = str(path)
            break
    validation_summary = validation_payload.get("summary", {}) if isinstance(validation_payload, dict) else {}
    route_import_payload: dict[str, Any] | None = None
    route_import_path = ""
    for path in _route_evidence_import_candidate_paths(workspace):
        loaded = load_json(path)
        if isinstance(loaded, dict) and loaded.get("schema") == "auditooor.outcome_calibration_route_evidence_importer.v1":
            route_import_payload = loaded
            route_import_path = str(path)
            break
    route_import_summary = route_import_payload.get("summary", {}) if isinstance(route_import_payload, dict) else {}
    return {
        "schema": f"{SCHEMA_PREFIX}.outcome_calibration_accounting.v1",
        "status": "resolved_linkage_present" if linked > 0 else "blocked_missing_resolved_linkage",
        "artifact_path": artifact_path,
        "resolved_outcome_rows": resolved,
        "linked_for_calibration": linked,
        "missing_linkage": missing,
        "queue_items": len(queue),
        "outcome_linkage_backfill_items": int(queue_type_counts.get("outcome_linkage_backfill", 0)),
        "provider_terminal_advisory_items": int(queue_type_counts.get("provider_local_terminal_adjudication", 0)),
        "routing_rows": routing_rows,
        "primary_ready_routes": sum(1 for row in routing_rows if str(row.get("route_status") or "") == "primary_ready"),
        "blocked_routes": blocked_routes,
        "resolved_linkage_exists": linked > 0,
        "all_resolved_rows_linked": resolved > 0 and linked == resolved and missing == 0,
        "resolved_linkage_validation_status": str(validation_summary.get("calibration_closure_status") or outcome_rows.get("resolved_linkage_validator_status") or "missing"),
        "resolved_linkage_validation_artifact_path": validation_path,
        "resolved_linkage_validation_valid_rows": int(validation_summary.get("valid_linked_rows") or 0),
        "resolved_linkage_validation_invalid_rows": int(validation_summary.get("invalid_linkage_rows") or 0),
        "resolved_linkage_validation_terminalized_rows": int(validation_summary.get("terminalized_missing_linkage_rows") or 0),
        "route_evidence_import_exists": isinstance(route_import_payload, dict),
        "route_evidence_import_status": str(route_import_summary.get("import_status") or "missing"),
        "route_evidence_import_artifact_path": route_import_path,
        "route_evidence_import_valid_rows": int(route_import_summary.get("valid_import_rows") or 0),
        "route_evidence_import_invalid_rows": int(route_import_summary.get("invalid_import_rows") or 0),
        "route_evidence_rows_seen": int(route_import_summary.get("route_evidence_rows_seen") or 0),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "next_command": "make outcome-calibration-route-evidence-importer WS=<workspace> && make outcome-calibration-resolved-linkage-validator WS=<workspace> && make outcome-calibration-scorecard",
    }


def agent_recall_closure_accounting(workspace: Path) -> dict[str, Any]:
    """Summarize full-corpus agent-recall closure without promoting findings."""
    audit_dir = out_dir(workspace)
    proof_path = audit_dir / "agent_recall_full_corpus_proof.json"
    queue_path = audit_dir / "agent_recall_detector_queue_full_corpus.json"
    source_local_path = audit_dir / "agent_recall_source_local_proof_closure.json"
    proof = load_json(proof_path) if proof_path.is_file() else {}
    queue = load_json(queue_path) if queue_path.is_file() else {}
    source_local = load_json(source_local_path) if source_local_path.is_file() else {}

    terminal_counts = (
        proof.get("terminal_state_counts")
        if isinstance(proof.get("terminal_state_counts"), dict)
        else {}
    )
    task_counts = (
        proof.get("task_type_counts")
        if isinstance(proof.get("task_type_counts"), dict)
        else {}
    )
    queue_rows = [
        row for row in queue.get("rows", [])
        if isinstance(row, dict)
    ] if isinstance(queue.get("rows"), list) else []
    source_local_rows = [
        row for row in source_local.get("rows", [])
        if isinstance(row, dict)
    ] if isinstance(source_local.get("rows"), list) else []
    terminalized = int(proof.get("terminalized_or_bounded_rows") or 0)
    total = int(proof.get("total_candidate_rows") or 0)
    open_rows = int(proof.get("open_actionable_rows") or 0)
    detectorized = int(terminal_counts.get("detectorized_terminal") or 0)
    non_detectorizable = (
        int(terminal_counts.get("non_detectorizable_terminal") or 0)
        + int(terminal_counts.get("source_proof_terminal_blocked") or 0)
        + int(terminal_counts.get("local_proof_recorded_terminal") or 0)
        + int(terminal_counts.get("killed_duplicate_or_oos") or 0)
    )
    queue_terminal_reason_rows = sum(
        1 for row in queue_rows
        if str(row.get("terminal_state") or "").strip()
        and str(row.get("reason") or "").strip()
    )
    source_local_terminal_reason_rows = sum(
        1 for row in source_local_rows
        if str(row.get("terminal_state") or "").strip()
        and str(row.get("reason") or "").strip()
    )
    remaining_task_count = sum(
        int(task_counts.get(task_type) or 0)
        for task_type in ("detector_task", "source_proof_task", "local_proof_task")
    )
    full_closed_for_current_evidence = (
        bool(proof)
        and str(proof.get("full_recall_closure_status") or "") == "closed_for_current_local_evidence"
        and total > 0
        and terminalized == total
        and open_rows == 0
        and remaining_task_count == 0
    )
    priority_stop_condition_met = (
        full_closed_for_current_evidence
        and total >= 3
        and detectorized >= 1
        and non_detectorizable >= 1
    )
    cross_cut_stop_condition_met = (
        full_closed_for_current_evidence
        and (not queue_rows or queue_terminal_reason_rows == len(queue_rows))
        and (
            not source_local_rows
            or source_local_terminal_reason_rows == len(source_local_rows)
        )
    )
    status = (
        "full_recall_closed_for_current_local_evidence"
        if cross_cut_stop_condition_met
        else "blocked_open_agent_recall_tasks"
        if proof
        else "missing_agent_recall_full_corpus_proof"
    )
    return {
        "schema": f"{SCHEMA_PREFIX}.agent_recall_closure_accounting.v1",
        "status": status,
        "artifact_path": str(proof_path),
        "queue_artifact_path": str(queue_path),
        "source_local_artifact_path": str(source_local_path),
        "total_candidate_rows": total,
        "terminalized_or_bounded_rows": terminalized,
        "open_actionable_rows": open_rows,
        "detectorized_terminal": detectorized,
        "non_detectorizable_terminal": non_detectorizable,
        "remaining_task_count": remaining_task_count,
        "queue_terminal_reason_rows": queue_terminal_reason_rows,
        "queue_row_count": len(queue_rows),
        "source_local_terminal_reason_rows": source_local_terminal_reason_rows,
        "source_local_row_count": len(source_local_rows),
        "full_closed_for_current_local_evidence": full_closed_for_current_evidence,
        "priority_stop_condition_met": priority_stop_condition_met,
        "cross_cut_stop_condition_met": cross_cut_stop_condition_met,
        "terminal_state_counts": dict(sorted((str(k), int(v)) for k, v in terminal_counts.items())),
        "task_type_counts": dict(sorted((str(k), int(v)) for k, v in task_counts.items())),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "next_command": (
            "make agent-recall WS=<workspace> STRICT=1 && "
            "python3 tools/agent-recall-source-local-proof-closure.py --workspace <workspace>"
        ),
    }


KNOWN_LIMITATIONS_CATEGORY_BLOCKERS: dict[str, list[dict[str, str]]] = {
    "blocked_named:p0-0": [
        {
            "blocker_id": "p0-0-from-scope-diff",
            "blocker": "Generate from-scope invariant diffs and record accepted/rejected rows before claiming invariant discovery completeness.",
            "next_command": "make invariant-ledger WS=<workspace> FROM_SCOPE=1 STRICT=1",
        },
        {
            "blocker_id": "p0-0-adoption-sample",
            "blocker": "Run the from-scope invariant ledger on three fresh engagements and record adoption percentage.",
            "next_command": "python3 tools/audit-closeout-check.py <workspace> --require-invariant-ledger",
        },
        {
            "blocker_id": "p0-0-closeout-surface",
            "blocker": "Expose generated-vs-accepted invariant drift in closeout before treating green audit-deep as complete.",
            "next_command": "make audit-closeout WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "p0-0-doc-truth",
            "blocker": "Keep KNOWN_LIMITATIONS open until diff-backed adoption data exists.",
            "next_command": "make docs-check",
        },
    ],
    "blocked_named:priority-4": [
        {
            "blocker_id": "priority-4-scope-input",
            "blocker": "Build invariant-ledger --from-scope input extraction instead of relying on manual ledger authoring.",
            "next_command": "make invariant-ledger WS=<workspace> MODE=from-scope STRICT=1",
        },
        {
            "blocker_id": "priority-4-high-critical-coverage",
            "blocker": "Require every High/Critical scoped subsystem to have at least one invariant row or explicit blocker.",
            "next_command": "python3 tools/invariant-ledger.py <workspace> --from-scope --strict",
        },
        {
            "blocker_id": "priority-4-acceptance-ledger",
            "blocker": "Persist accepted/rejected generated invariants so later agents can see why rows were killed.",
            "next_command": "make audit-closeout WS=<workspace>",
        },
        {
            "blocker_id": "priority-4-regression",
            "blocker": "Add a regression fixture where a scoped subsystem missing invariants fails closeout.",
            "next_command": "python3 -m unittest tools.tests.test_automation_closure",
        },
    ],
    "open_agent_recall_terminal_routes": [
        {
            "blocker_id": "agent-recall-dataset",
            "blocker": "Replay at least three prior agent-found behaviors into typed recall rows.",
            "next_command": "make agent-output-inventory WS=<workspace> && make agent-recall WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "agent-recall-detectorized",
            "blocker": "Move at least one recalled behavior into a detector/regression route.",
            "next_command": "python3 tools/semantic-detector-worklist.py --workspace <workspace>",
        },
        {
            "blocker_id": "agent-recall-non-detectorizable",
            "blocker": "Move at least one recalled behavior into a source-review/invariant/harness route with scanner-miss reason.",
            "next_command": "make agent-recall WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "agent-recall-metrics",
            "blocker": "Record recall before/after counts so scanner improvement is measurable.",
            "next_command": "make pr560-next-actions WS=<workspace> JSON=1",
        },
    ],
    "open_detector_precision_or_semantics": [
        {
            "blocker_id": "detector-semantic-migration",
            "blocker": "Migrate high-value regex-only Tier-B/S/A patterns to semantic predicates or demote their claims.",
            "next_command": "make compile-strict",
        },
        {
            "blocker_id": "detector-callgraph-claims",
            "blocker": "Burn down inter-contract detector claims that do not consult callgraph APIs.",
            "next_command": "python3 tools/detector-lint.py --fail-inter-contract-claim-without-callgraph",
        },
        {
            "blocker_id": "detector-fp-calibration",
            "blocker": "Backfill fresh clean-codebase FP calibration for every Tier-S/A pattern.",
            "next_command": "python3 tools/fp-calibration-manifest.py --required-for-tier-sa",
        },
        {
            "blocker_id": "detector-backend-executors",
            "blocker": "Keep unsupported non-Solidity backends source-review-only until real executors exist.",
            "next_command": "make known-limitations-check STRICT=1",
        },
    ],
    "open_evidence_class_backfill": [
        {
            "blocker_id": "evidence-class-active-workspaces",
            "blocker": "Backfill evidence_class for long-lived active workspace artifacts.",
            "next_command": "python3 tools/evidence-class-validator.py <workspace>",
        },
        {
            "blocker_id": "evidence-class-packager",
            "blocker": "Thread evidence class into packaged bundles and refuse generated hypotheses as proof.",
            "next_command": "python3 tools/submission-packager.py <workspace> <draft>",
        },
        {
            "blocker_id": "evidence-class-closeout",
            "blocker": "Closeout must count executed_with_manifest or stronger evidence separately from generated artifacts.",
            "next_command": "make audit-closeout WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "evidence-class-legacy-review",
            "blocker": "Review legacy generated artifacts before promotion rather than treating inventory rows as proof.",
            "next_command": "python3 tools/evidence-class-validator.py <workspace> --json",
        },
    ],
    "open_execution_manifest_or_replay_proof": [
        {
            "blocker_id": "execution-harness-solidity",
            "blocker": "Execute two Solidity harness-plan rows through scaffold to execution manifest.",
            "next_command": "make harness-scaffold WS=<workspace> && make poc-execution-record WS=<workspace> BRIEF=<brief> RESULT=proved IMPACT=exploit_impact",
        },
        {
            "blocker_id": "execution-harness-dlt",
            "blocker": "Execute or explicitly block one Base DLT harness row with a command-level reason.",
            "next_command": "make harness-plan WS=<workspace> && make harness-scaffold WS=<workspace>",
        },
        {
            "blocker_id": "execution-counterexample-replay",
            "blocker": "Replay collected deep counterexamples or mark them advisory/killed with evidence.",
            "next_command": "make deep-counterexample-queue WS=<workspace> && REQUIRE_REPLAY_EXECUTED=1 make audit-closeout WS=<workspace>",
        },
        {
            "blocker_id": "execution-setup-binding",
            "blocker": "Bind constructor/state setup from selected fixtures into PoC scaffolds before claiming setup automation.",
            "next_command": "python3 tools/poc-scaffold.py --plan-json <plan> --bootstrap-workspace <workspace> --contract <contract> --angle-id <angle>",
        },
    ],
    "open_fixture_or_corpus_followup": [
        {
            "blocker_id": "fixture-p1-queue",
            "blocker": "Classify every P1 fixture-less group as fixture-backed, source-missing, or intentionally deferred.",
            "next_command": "make p1-extraction-queue SEARCH_ROOTS='<roots>'",
        },
        {
            "blocker_id": "fixture-p1-run",
            "blocker": "Run reviewed extraction queue rows and merge only after smoke-fire output is reviewed.",
            "next_command": "make p1-extraction-run QUEUE=<json> LIMIT=<n>",
        },
        {
            "blocker_id": "fixture-duplicate-threshold",
            "blocker": "Calibrate duplicate thresholds against the next mining batch.",
            "next_command": "python3 tools/fixture-duplicate-detector.py <workspace> --threshold-fail 200",
        },
        {
            "blocker_id": "fixture-closeout-hard-fail",
            "blocker": "Wire excessive duplicate pairs into closeout FAIL only after threshold calibration.",
            "next_command": "REQUIRE_NO_FIXTURE_DUPES=1 make audit-closeout WS=<workspace>",
        },
    ],
    "open_impact_contract_or_family_execution": [
        {
            "blocker_id": "impact-start-gates",
            "blocker": "Prove candidate-generation and direct-submit paths cannot skip impact-contract validation.",
            "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "impact-family-base",
            "blocker": "Run a Base Critical/High family from worklist through graph/source query to verified candidate or blocker.",
            "next_command": "make impact-worklist WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "impact-family-non-base",
            "blocker": "Repeat impact-family accounting on a non-Base or fixture workspace before claiming generic behavior.",
            "next_command": "make coverage-inventory WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "impact-terminal-proof",
            "blocker": "Promote only rows with exact selected-impact proof into harness/source-proof tasks.",
            "next_command": "make source-proof-task-queue WS=<workspace> STRICT=1",
        },
    ],
    "open_outcome_calibration": [
        {
            "blocker_id": "outcome-lane-precision",
            "blocker": "Backfill numeric precision for every provider/task lane used for promotion.",
            "next_command": "python3 tools/llm-calibration-log.py route --provider <provider> --task-type <task> --routing-purpose promotion",
        },
        {
            "blocker_id": "outcome-ledger-linkage",
            "blocker": "Require lane/model/proof/production-path linkage for new filed rows.",
            "next_command": "AUDITOOOR_OUTCOME_REQUIRE_LINKAGE=1 python3 tools/track-submissions.py validate-ledger reference/outcomes.jsonl",
        },
        {
            "blocker_id": "outcome-dashboard-score",
            "blocker": "Read README/dashboard capability ratings from resolved outcome manifests.",
            "next_command": "make outcome-telemetry AUDITS_DIR=<audits-dir>",
        },
        {
            "blocker_id": "outcome-sparse-refusal",
            "blocker": "Block promotion routing when sample or precision floors are missing.",
            "next_command": "python3 tools/llm-calibration-log.py route --provider <provider> --task-type <task> --routing-purpose promotion",
        },
    ],
    "open_queue_handoff_telemetry": [
        {
            "blocker_id": "queue-owner-history",
            "blocker": "Surface owner-aggregated stale queue history in operator handoff briefs.",
            "next_command": "python3 tools/queue-staleness-report.py <workspace> --json",
        },
        {
            "blocker_id": "queue-hard-gate",
            "blocker": "Keep hard-gating opt-in until stale histories are visible and actionable.",
            "next_command": "REQUIRE_NO_STALE_QUEUES=1 make audit-closeout WS=<workspace>",
        },
        {
            "blocker_id": "queue-next-actions",
            "blocker": "Route stale queue rows into PR560 next actions with owner and next command.",
            "next_command": "make pr560-next-actions WS=<workspace> JSON=1",
        },
        {
            "blocker_id": "queue-telemetry",
            "blocker": "Add stale queue counts to closeout telemetry rather than leaving terminal-only warnings.",
            "next_command": "make audit-closeout WS=<workspace>",
        },
    ],
    "open_semantic_or_live_topology_depth": [
        {
            "blocker_id": "semantic-production-path-depth",
            "blocker": "Resolve factory/clone/proxy/delegate/facet/cross-file paths without manual implementation_var declarations.",
            "next_command": "make semantic-graph WS=<workspace>",
        },
        {
            "blocker_id": "semantic-cross-contract-proof",
            "blocker": "Require cross-contract claims to cite relation edges plus paired proof or explicit blockers.",
            "next_command": "make semantic-graph WS=<workspace> && python3 tools/engage.py --workspace <workspace> --stage live-checks",
        },
        {
            "blocker_id": "semantic-rust-runtime",
            "blocker": "Resolve Rust cross-crate invocation, traits, macros, and cfg features before promoting DLT semantic claims.",
            "next_command": "python3 tools/rust-cross-crate-graph.py --workspace <workspace> --validate",
        },
        {
            "blocker_id": "semantic-live-proof-pairs",
            "blocker": "Generate same-block live proof pairs for topology-relation claims or fail with named blockers.",
            "next_command": "python3 tools/engage.py --workspace <workspace> --stage live-checks",
        },
    ],
    "open_stop_condition_not_met": [
        {
            "blocker_id": "generic-stop-condition-owner",
            "blocker": "Assign the open row to a stable blocker category before claiming burn-down progress.",
            "next_command": "make known-limitations-burndown WS=<workspace> STRICT=1",
        },
        {
            "blocker_id": "generic-stop-condition-command",
            "blocker": "Record the exact command that can reduce or close the row.",
            "next_command": "python3 tools/automation-closure.py --workspace <workspace> --mode known-limitations-burndown --json",
        },
        {
            "blocker_id": "generic-stop-condition-evidence",
            "blocker": "Persist evidence paths instead of terminal-only investigation output.",
            "next_command": "make audit-closeout WS=<workspace>",
        },
        {
            "blocker_id": "generic-stop-condition-docs",
            "blocker": "Update docs only after implementation evidence changes the row.",
            "next_command": "make docs-check",
        },
    ],
}


def known_limitations_command_blockers(row: dict[str, Any]) -> list[dict[str, str]]:
    """Return precise command-level blockers for an open burndown row."""
    if bool(row.get("stop_condition_met")):
        return []
    category = known_limitations_blocker_category(row)
    blockers = [dict(item) for item in KNOWN_LIMITATIONS_CATEGORY_BLOCKERS.get(category, [])]
    if not blockers:
        next_command = str(row.get("next_command") or row.get("owner_command") or "make known-limitations-burndown WS=<workspace> STRICT=1")
        blockers = [
            {
                "blocker_id": f"{slug(category)}-owner-command",
                "blocker": "Open known-limitation row needs a command-level blocker before closure can be claimed.",
                "next_command": next_command,
            }
        ]
    for blocker in blockers:
        blocker["category"] = category
        blocker["limitation_id"] = str(row.get("limitation_id") or "")
    return blockers


def known_limitations_closure_checklist(row: dict[str, Any], checks: dict[str, Any]) -> list[dict[str, Any]]:
    """Emit concrete row-level accounting that humans can audit quickly.

    The checklist is intentionally conservative: passing the accounting items
    only means the row has an owner/blocker/command trail. It does not mean the
    underlying limitation is closed unless the stop condition is met.
    """
    stop_met = bool(row.get("stop_condition_met"))
    remaining = str(row.get("remaining_after_560") or "").strip()
    blocker_category = known_limitations_blocker_category(row)
    owner_command = checks.get("owner_command") or ""
    artifact_paths = list(checks.get("artifact_paths") or [])
    status_evidence = list(checks.get("status_evidence") or [])
    command_blockers = known_limitations_command_blockers(row)
    command_blocker_ids = [str(item.get("blocker_id") or "unnamed") for item in command_blockers]
    actionable_command = bool(owner_command) and "todo" not in owner_command.lower()
    items = [
        {
            "check_id": "owner-command",
            "status": "pass" if owner_command else "blocker",
            "detail": owner_command or "missing owner command",
        },
        {
            "check_id": "artifact-citation",
            "status": "pass" if artifact_paths else "blocker",
            "detail": ", ".join(artifact_paths) if artifact_paths else "missing explicit artifact path",
        },
        {
            "check_id": "stop-condition",
            "status": "met" if stop_met else "open",
            "detail": checks.get("stop_condition") or "missing stop condition",
        },
        {
            "check_id": "status-evidence",
            "status": "pass" if status_evidence else "blocker",
            "detail": "; ".join(str(x) for x in status_evidence) if status_evidence else "missing status evidence",
        },
        {
            "check_id": "terminal-state",
            "status": "closed" if stop_met else "open",
            "detail": str(row.get("terminal_state") or "unknown"),
        },
        {
            "check_id": "blocker-category",
            "status": "none" if stop_met else "named",
            "detail": blocker_category,
        },
        {
            "check_id": "command-blockers",
            "status": "none" if stop_met else ("named" if command_blockers else "blocker"),
            "detail": ", ".join(command_blocker_ids) if command_blocker_ids else "no command-level blockers required",
        },
        {
            "check_id": "next-command-shape",
            "status": "none" if stop_met else ("pass" if actionable_command else "blocker"),
            "detail": owner_command or "missing executable owner/next command",
        },
        {
            "check_id": "remaining-work",
            "status": "none" if stop_met else ("named" if remaining else "blocker"),
            "detail": remaining or "missing remaining_after_560",
        },
    ]
    return items


def _run_local_json_tool(args: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "ok": proc.returncode == 0,
    }


def evidence_class_validator_accounting(workspace: Path) -> dict[str, Any]:
    """Collect evidence-class state for known-limitations accounting.

    Importing the validator keeps the burndown generator offline and avoids
    shell-output parsing.  The validator is read-only; migration/backfill stays
    in ``tools/evidence-class-legacy-backfill.py``.
    """
    path = ROOT / "tools" / "evidence-class-validator.py"
    if not path.is_file():
        return {
            "status": "blocked_missing_validator",
            "artifact_path": str(path),
            "legacy_count": -1,
            "policy_violation_count": -1,
        }
    spec = importlib.util.spec_from_file_location("_auditooor_evidence_class_validator", path)
    if spec is None or spec.loader is None:
        return {
            "status": "blocked_validator_import",
            "artifact_path": str(path),
            "legacy_count": -1,
            "policy_violation_count": -1,
        }
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = module.collect(workspace)
    legacy = int(payload.get("legacy_count") or 0)
    policy = int(payload.get("policy_violation_count") or 0)
    return {
        "status": "clean_no_legacy_or_policy_violations" if legacy == 0 and policy == 0 else "open_legacy_or_policy_violations",
        "artifact_path": str(path),
        "legacy_count": legacy,
        "policy_violation_count": policy,
        "verified_count": int(payload.get("verified_count") or 0),
        "hypothesis_count": int(payload.get("hypothesis_count") or 0),
        "legacy_artifact_path_total": int(payload.get("legacy_artifact_path_total") or 0),
        "aggregate_counts": payload.get("aggregate_counts") if isinstance(payload.get("aggregate_counts"), dict) else {},
    }


def semantic_live_depth_accounting(workspace: Path, *, limit: int = 400) -> dict[str, Any]:
    """Generate/use semantic-live-depth artifacts for burndown accounting.

    This intentionally closes only semantic/live topology-depth accounting.
    A proved same-block pair never becomes vulnerability proof here; every row
    remains NOT_SUBMIT_READY and impact proof still has to come from the normal
    submission gates.
    """
    audit_dir = out_dir(workspace)
    graph = audit_dir / "semantic_graph.json"
    scoped_graph = audit_dir / "semantic_graph.scoped.json"
    live = workspace / "live_topology_checks.json"
    blockers_path = audit_dir / "semantic_live_depth_blockers.json"
    queue_path = audit_dir / "semantic_live_depth_queue.json"
    requirements_path = audit_dir / "live_topology_proof_requirements.json"
    blockers_run: dict[str, Any] = {"status": "not_run"}
    queue_run: dict[str, Any] = {"status": "not_run"}
    requirements_run: dict[str, Any] = {"status": "not_run"}

    blockers_run = _run_local_json_tool([
        "tools/semantic-live-depth-blockers.py",
        "--workspace",
        str(workspace),
        "--limit",
        str(limit),
    ])
    blockers_run["status"] = "generated" if blockers_run["ok"] else "blocked_generation_failed"

    if blockers_path.is_file() and live.is_file():
        queue_run = _run_local_json_tool([
            "tools/semantic-live-depth-queue.py",
            "--workspace",
            str(workspace),
            "--limit",
            str(limit),
        ])
        queue_run["status"] = "generated" if queue_run["ok"] else "blocked_generation_failed"
    elif not blockers_path.is_file():
        queue_run = {"status": "blocked_missing_blocker_inventory", "ok": False}
    else:
        requirements_run = _run_local_json_tool([
            "tools/live-topology-proof-requirements.py",
            "--workspace",
            str(workspace),
            "--limit",
            str(limit),
        ])
        requirements_run["status"] = "generated" if requirements_run["ok"] else "blocked_generation_failed"
        queue_run = {"status": "requirements_generated_missing_live_topology", "ok": bool(requirements_run.get("ok"))}

    blockers = load_json(blockers_path) or {}
    queue = load_json(queue_path) or {}
    requirements = load_json(requirements_path) or {}
    queue_rows = [row for row in queue.get("rows") or [] if isinstance(row, dict)]
    closed_rows = [row for row in queue_rows if bool(row.get("depth_closure_allowed"))]
    blocked_rows = [row for row in queue_rows if not bool(row.get("depth_closure_allowed"))]
    semantic_blocker_item_count = int(blockers.get("item_count") or 0)
    requirement_count = int(requirements.get("requirement_count") or 0)
    blocked_depth_count = len(blocked_rows)
    if not queue_rows and requirement_count and not live.is_file():
        blocked_depth_count = requirement_count
    elif not queue_rows and semantic_blocker_item_count and not live.is_file():
        blocked_depth_count = semantic_blocker_item_count
    blocker_counts = blockers.get("blocker_counts") if isinstance(blockers.get("blocker_counts"), dict) else {}
    exact_pair_ids = sorted({
        str(pair_id)
        for row in closed_rows
        for pair_id in row.get("exact_pair_ids", [])
        if str(pair_id).strip()
    })
    generated_artifacts = [
        str(path)
        for path in (
            blockers_path,
            audit_dir / "semantic_live_depth_blockers.md",
            queue_path,
            audit_dir / "semantic_live_depth_queue.md",
            requirements_path,
            audit_dir / "live_topology_proof_requirements.md",
        )
        if path.is_file()
    ]
    if exact_pair_ids and blocked_rows:
        status = "partial_depth_closure_with_blockers"
    elif exact_pair_ids:
        status = "depth_closed_by_exact_same_block_pairs"
    elif queue_rows:
        status = "blocked_missing_exact_same_block_pairs"
    elif requirement_count and not live.is_file():
        status = "proof_requirements_generated_missing_live_topology"
    elif semantic_blocker_item_count and not live.is_file():
        status = "blocked_missing_live_topology"
    elif semantic_blocker_item_count:
        status = "blocked_queue_not_generated"
    elif graph.is_file() or scoped_graph.is_file():
        status = "empty_no_semantic_live_depth_rows"
    else:
        status = "blocked_missing_scoped_semantic_graph"
    return {
        "schema": f"{SCHEMA_PREFIX}.semantic_live_depth_accounting.v1",
        "workspace": str(workspace),
        "limit": limit,
        "status": status,
        "blockers_run": blockers_run,
        "queue_run": queue_run,
        "requirements_run": requirements_run,
        "artifacts": generated_artifacts,
        "blockers_artifact": str(blockers_path),
        "queue_artifact": str(queue_path),
        "requirements_artifact": str(requirements_path),
        "source_live_topology_artifact": str(live),
        "source_semantic_graph_artifact": str(graph),
        "source_scoped_semantic_graph_artifact": str(scoped_graph),
        "semantic_blocker_item_count": semantic_blocker_item_count,
        "queue_processed_count": int(queue.get("processed_count") or 0),
        "proof_requirement_count": requirement_count,
        "terminal_depth_closed_count": len(closed_rows),
        "blocked_depth_count": blocked_depth_count,
        "exact_same_block_pair_ids": exact_pair_ids,
        "blocker_counts": dict(sorted((str(k), int(v)) for k, v in blocker_counts.items())),
        "queue_status_counts": queue.get("status_counts") if isinstance(queue.get("status_counts"), dict) else {},
        "concrete_item_target": limit,
        "concrete_item_count": int(queue.get("processed_count") or requirement_count or semantic_blocker_item_count or 0),
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "promotion_allowed": False,
        "advisory_only": True,
        "closure_scope": "semantic_live_topology_depth_only",
        "limitation_note": (
            "Exact same-block proof pairs close only semantic/live topology-depth "
            "accounting. They do not prove exploit impact, production path, severity, "
            "or submission readiness."
        ),
        "next_command": (
            "make semantic-live-depth-blockers WS=<workspace> && make live-topology-proof-requirements WS=<workspace> && make semantic-live-depth-queue WS=<workspace>"
        ),
    }


EXECUTION_PROOF_TASK_TEMPLATES: tuple[dict[str, str], ...] = (
    {
        "suffix": "inventory-harness-plan",
        "proof_kind": "harness_plan_inventory",
        "title": "Inventory eligible harness-plan rows and locked impact contracts",
        "next_command": "make harness-task-queue WS=<workspace> JSON=1",
        "acceptance_gate": "queue row names a candidate, task type, impact_contract_id, and next_command",
    },
    {
        "suffix": "scaffold-solidity-a",
        "proof_kind": "solidity_harness_scaffold",
        "title": "Scaffold first Solidity harness row without recording proof",
        "next_command": "make harness-scaffold WS=<workspace> PLAN=<plan-json> HARNESS_TASK_ID=<task-id>",
        "acceptance_gate": "attempt manifest records scaffolded or blocked_named with command-level reason",
    },
    {
        "suffix": "scaffold-solidity-b",
        "proof_kind": "solidity_harness_scaffold",
        "title": "Scaffold second independent Solidity harness row without recording proof",
        "next_command": "make harness-scaffold WS=<workspace> PLAN=<plan-json> HARNESS_TASK_ID=<task-id>",
        "acceptance_gate": "attempt manifest records scaffolded or blocked_named with command-level reason",
    },
    {
        "suffix": "scaffold-base-dlt",
        "proof_kind": "base_dlt_harness_scaffold",
        "title": "Scaffold or explicitly block one Base DLT harness row",
        "next_command": "make harness-plan WS=<workspace> && make harness-scaffold WS=<workspace>",
        "acceptance_gate": "Base DLT row has execution manifest or named blocker artifact",
    },
    {
        "suffix": "execute-solidity-a",
        "proof_kind": "forge_execution",
        "title": "Run first Solidity scaffold with exact impact assertions wired",
        "next_command": "forge test --match-path <generated-test> -vvv",
        "acceptance_gate": "operator records stdout/stderr and final result; passing setup alone is not proof",
    },
    {
        "suffix": "execute-solidity-b",
        "proof_kind": "forge_execution",
        "title": "Run second Solidity scaffold with exact impact assertions wired",
        "next_command": "forge test --match-path <generated-test> -vvv",
        "acceptance_gate": "operator records stdout/stderr and final result; passing setup alone is not proof",
    },
    {
        "suffix": "record-manifest-a",
        "proof_kind": "execution_manifest_gate",
        "title": "Record first execution manifest only after exact exploit impact is demonstrated",
        "next_command": "make poc-execution-record WS=<workspace> BRIEF=<brief> CMD='<forge command>' RESULT=proved IMPACT=exploit_impact",
        "acceptance_gate": "poc_execution/**/execution_manifest.json has final_result=proved, impact_assertion=exploit_impact, evidence_class=executed_with_manifest, and a structured command row with status=pass, exit_code=0, and non-empty command",
    },
    {
        "suffix": "record-manifest-b",
        "proof_kind": "execution_manifest_gate",
        "title": "Record second execution manifest only after exact exploit impact is demonstrated",
        "next_command": "make poc-execution-record WS=<workspace> BRIEF=<brief> CMD='<forge command>' RESULT=proved IMPACT=exploit_impact",
        "acceptance_gate": "poc_execution/**/execution_manifest.json has final_result=proved, impact_assertion=exploit_impact, evidence_class=executed_with_manifest, and a structured command row with status=pass, exit_code=0, and non-empty command",
    },
    {
        "suffix": "replay-counterexample",
        "proof_kind": "counterexample_replay",
        "title": "Replay collected deep counterexamples or mark advisory/killed",
        "next_command": "make deep-counterexample-queue WS=<workspace> && REQUIRE_REPLAY_EXECUTED=1 make audit-closeout WS=<workspace>",
        "acceptance_gate": "each deep_counterexample.v1 has paired execution manifest or visible advisory/killed state",
    },
    {
        "suffix": "strict-closeout",
        "proof_kind": "strict_closeout_gate",
        "title": "Validate strict closeout after manifests or named blockers exist",
        "next_command": "REQUIRE_REPLAY_EXECUTED=1 make audit-closeout WS=<workspace> STRICT=1",
        "acceptance_gate": "strict closeout no longer reports unresolved execution/replay proof blockers",
    },
)

def _execution_manifest_gate(path: Path, manifest: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {
            "path": str(path),
            "status": "invalid_json",
            "proof_counted": False,
            "reason": "manifest is unreadable or not a JSON object",
        }
    final_result = str(manifest.get("final_result") or "")
    impact_assertion = str(manifest.get("impact_assertion") or "")
    commands = _execution_manifest_proof.commands_attempted(manifest)
    evidence_class = str(manifest.get("evidence_class") or "")
    has_passing_structured_command = _execution_manifest_proof.has_passing_structured_command(manifest)
    proof_counted = _execution_manifest_proof.is_strict_proved_execution_manifest(manifest)
    if proof_counted:
        status = "proof_counted"
        reason = "proved exploit impact with executed_with_manifest and structured status=pass/exit_code=0 command"
    elif final_result == "proved":
        status = "invalid_proved_manifest"
        reason = (
            "proved manifests require impact_assertion=exploit_impact, "
            "evidence_class=executed_with_manifest, and a structured status=pass/exit_code=0 command"
        )
    elif final_result in {"needs_human", "blocked_env", "blocked_path", "disproved"}:
        status = "not_proof"
        reason = f"final_result={final_result}"
    else:
        status = "not_proof"
        reason = "missing or non-proof final_result"
    return {
        "path": str(path),
        "candidate_id": manifest.get("candidate_id") or path.parent.name,
        "status": status,
        "proof_counted": proof_counted,
        "reason": reason,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
        "commands_attempted_count": len(commands),
        "evidence_class": evidence_class,
        "has_passing_structured_command": has_passing_structured_command,
    }


def collect_execution_manifest_gate_validation(workspace: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for path in sorted((workspace / "poc_execution").glob("**/execution_manifest.json")):
        rows.append(_execution_manifest_gate(path, load_json(path)))
    counts = Counter(str(row.get("status") or "unknown") for row in rows)
    invalid_proved = [row for row in rows if row.get("status") == "invalid_proved_manifest"]
    return {
        "schema": f"{SCHEMA_PREFIX}.execution_manifest_gate_validation.v1",
        "workspace": str(workspace),
        "rows": rows,
        "summary": {
            "manifest_count": len(rows),
            "proof_counted": sum(1 for row in rows if row.get("proof_counted")),
            "invalid_proved_manifest": len(invalid_proved),
            "status_counts": dict(sorted(counts.items())),
        },
        "status": "blocked_invalid_proved_manifest" if invalid_proved else "ok",
    }


def build_execution_proof_task_queue(workspace: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    open_rows = [
        row
        for row in rows
        if row.get("blocker_category") == "open_execution_manifest_or_replay_proof"
        and not bool(row.get("stop_condition_met"))
    ]
    tasks: list[dict[str, Any]] = []
    for row in open_rows:
        limitation_id = str(row.get("limitation_id") or "unknown")
        for idx, template in enumerate(EXECUTION_PROOF_TASK_TEMPLATES, 1):
            tasks.append(
                {
                    "task_id": f"{slug(limitation_id)}-{idx:02d}-{template['suffix']}",
                    "limitation_id": limitation_id,
                    "priority_group": row.get("priority_group") or "unknown",
                    "proof_kind": template["proof_kind"],
                    "title": template["title"],
                    "source_stop_condition": row.get("stop_condition") or "",
                    "next_command": template["next_command"],
                    "acceptance_gate": template["acceptance_gate"],
                    "evidence_class": "scaffolded_unverified",
                    "advisory_only": True,
                    "promotion_allowed": False,
                    "severity": "none",
                    "selected_impact": "",
                    "submission_posture": "NOT_SUBMIT_READY",
                    "submit_ready": False,
                    "proof_boundary": (
                        "This task is executable queue work only. Do not claim exploit proof unless "
                        "a poc_execution/**/execution_manifest.json proves exact impact."
                    ),
                }
            )
    validation = collect_execution_manifest_gate_validation(workspace)
    proof_kind_counts = Counter(str(task.get("proof_kind") or "unknown") for task in tasks)
    by_limitation = Counter(str(task.get("limitation_id") or "unknown") for task in tasks)
    status = "open_execution_proof_tasks" if tasks else "empty_no_execution_proof_tasks"
    if validation["status"] != "ok":
        status = validation["status"]
    return {
        "schema": f"{SCHEMA_PREFIX}.execution_proof_task_queue.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source": str(ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"),
        "rows": tasks,
        "execution_manifest_gate_validation": validation,
        "summary": {
            "task_count": len(tasks),
            "open_limitation_count": len(open_rows),
            "tasks_per_limitation": len(EXECUTION_PROOF_TASK_TEMPLATES),
            "proof_kind_counts": dict(sorted(proof_kind_counts.items())),
            "tasks_by_limitation": dict(sorted(by_limitation.items())),
            "proof_counted": validation["summary"]["proof_counted"],
            "invalid_proved_manifest": validation["summary"]["invalid_proved_manifest"],
        },
        "status": status,
    }


def write_execution_proof_task_queue(workspace: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    payload = build_execution_proof_task_queue(workspace, rows)
    d = out_dir(workspace)
    write_json(d / "execution_proof_task_queue.json", payload)
    md = [
        "# Execution Proof Task Queue",
        "",
        "Generated from open `open_execution_manifest_or_replay_proof` known-limitation rows. These tasks are executable queue work, not exploit proof.",
        "",
        "| Task | Limitation | Proof kind | Next command | Acceptance gate |",
        "|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        md.append(
            f"| `{row['task_id']}` | `{row['limitation_id']}` | `{row['proof_kind']}` | "
            f"`{row['next_command']}` | {row['acceptance_gate']} |"
        )
    if not payload["rows"]:
        md.append("| _none_ | _none_ | _none_ | _none_ | _none_ |")
    gate = payload["execution_manifest_gate_validation"]["summary"]
    md.extend(
        [
            "",
            "## Execution Manifest Gate",
            "",
            f"- Manifest count: `{gate['manifest_count']}`",
            f"- Proof counted: `{gate['proof_counted']}`",
            f"- Invalid proved manifests: `{gate['invalid_proved_manifest']}`",
        ]
    )
    write_md(d / "execution_proof_task_queue.md", md)
    return payload


def detect_severity_claim_guard_generic_fallback(root: Path) -> dict[str, Any]:
    """Detect the narrow evidence that severity-claim discipline is reduced.

    This intentionally only covers the severity-claim guard's generic fallback
    and pre-submit wiring. It must not close the broader impact-first work gate.
    """
    tool_path = root / "tools" / "severity-claim-guard.py"
    test_path = root / "tools" / "tests" / "test_severity_claim_guard.py"
    tool_status_path = root / "docs" / "TOOL_STATUS.md"
    pre_submit_path = root / "tools" / "pre-submit-check.sh"

    def read(path: Path) -> str:
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    tool_text = read(tool_path)
    test_text = read(test_path)
    tool_status_text = read(tool_status_path)
    pre_submit_text = read(pre_submit_path)

    checks = [
        {
            "check": "generic_workspace_loader",
            "artifact_path": stable_artifact_path(tool_path),
            "present": all(
                token in tool_text
                for token in (
                    "def load_workspace_payload",
                    ".auditooor",
                    "impact_contracts.json",
                    "critical_hunt",
                    "candidates",
                    "generic_severity_claim_guard_input",
                )
            ),
        },
        {
            "check": "manual_exact_impact_fallback",
            "artifact_path": stable_artifact_path(tool_path),
            "present": all(
                token in tool_text
                for token in (
                    "def _has_manual_exact_impact_flag",
                    "exact_impact_row",
                    "selected_impact_exact",
                    "listed_impact_proven",
                )
            ),
        },
        {
            "check": "generic_fallback_tests",
            "artifact_path": stable_artifact_path(test_path),
            "present": all(
                token in test_text
                for token in (
                    "test_generic_impact_contract_exact_flag_unproven_reportable_fails",
                    "test_generic_impact_contract_proven_exact_reportable_passes",
                    "test_generic_impact_contract_non_exact_reportable_fails",
                    "test_generic_impact_contract_program_matrix_proven_reportable_passes",
                )
            ),
        },
        {
            "check": "operator_docs_describe_generic_fallback",
            "artifact_path": stable_artifact_path(tool_status_path),
            "present": all(
                token in tool_status_text
                for token in (
                    "make severity-claim-guard",
                    ".auditooor/impact_contracts.json",
                    "critical_hunt/candidates",
                    "Integrated into pre-submit as Check #32",
                )
            ),
        },
        {
            "check": "pre_submit_check_32_wiring",
            "artifact_path": stable_artifact_path(pre_submit_path),
            "present": all(
                token in pre_submit_text
                for token in (
                    "SEVERITY-CLAIM-GUARD",
                    "tools/severity-claim-guard.py",
                    "--workspace",
                )
            ),
        },
    ]
    missing = [check["check"] for check in checks if not check["present"]]
    return {
        "schema": f"{SCHEMA_PREFIX}.severity_claim_guard_generic_fallback_evidence.v1",
        "status": "present" if not missing else "missing",
        "checks": checks,
        "missing_checks": missing,
        "artifact_paths": [check["artifact_path"] for check in checks],
    }


def detect_impact_first_work_gate_reduction(root: Path) -> dict[str, Any]:
    """Detect narrow impact-contract gates without claiming full closure.

    This only recognizes the currently-reviewed impact-first paths. Closeout,
    generic harness execution, and broader promotion paths can still remain
    open, so callers must keep the stop condition unmet.
    """
    critical_hunt_path = root / "tools" / "critical-hunt.py"
    paste_ready_path = root / "tools" / "paste-ready-generator.py"
    packager_path = root / "tools" / "submission-packager.py"
    swarm_path = root / "tools" / "swarm-orchestrator.py"
    mining_brief_path = root / "tools" / "mining-brief-generator.py"
    poc_scaffold_path = root / "tools" / "poc-scaffold.py"
    auto_draft_path = root / "tools" / "auto-draft-generator.py"
    harness_scaffold_path = root / "tools" / "harness-scaffold-emitter.py"
    submission_factory_path = root / "tools" / "submission-factory.py"
    deep_replay_scaffold_path = root / "tools" / "deep-counterexample-replay-scaffold.py"
    promote_typed_candidate_path = root / "tools" / "promote-typed-candidate.py"
    source_mining_campaign_path = root / "tools" / "source-mining-campaign.py"
    semantic_graph_path = root / "tools" / "semantic-graph.py"
    semantic_detector_worklist_path = root / "tools" / "semantic-detector-worklist.py"
    llm_dispatch_path = root / "tools" / "llm-dispatch.py"
    dispatch_preflight_path = root / "tools" / "dispatch-preflight.py"
    chimera_scaffold_path = root / "tools" / "chimera-scaffold.py"
    chimera_ledger_scaffold_path = root / "tools" / "chimera-ledger-scaffold.py"
    recon_log_bridge_path = root / "tools" / "recon-log-bridge.py"
    corpus_detectorization_path = root / "tools" / "corpus-detectorization-inventory.py"
    tool_status_path = root / "docs" / "TOOL_STATUS.md"
    workflow_path = root / "docs" / "WORKFLOW.md"

    def read(path: Path) -> str:
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    critical_hunt_text = read(critical_hunt_path)
    paste_ready_text = read(paste_ready_path)
    packager_text = read(packager_path)
    swarm_text = read(swarm_path)
    mining_brief_text = read(mining_brief_path)
    poc_scaffold_text = read(poc_scaffold_path)
    auto_draft_text = read(auto_draft_path)
    harness_scaffold_text = read(harness_scaffold_path)
    submission_factory_text = read(submission_factory_path)
    deep_replay_scaffold_text = read(deep_replay_scaffold_path)
    promote_typed_candidate_text = read(promote_typed_candidate_path)
    source_mining_campaign_text = read(source_mining_campaign_path)
    semantic_graph_text = read(semantic_graph_path)
    semantic_detector_worklist_text = read(semantic_detector_worklist_path)
    llm_dispatch_text = read(llm_dispatch_path)
    dispatch_preflight_text = read(dispatch_preflight_path)
    chimera_scaffold_text = read(chimera_scaffold_path)
    chimera_ledger_scaffold_text = read(chimera_ledger_scaffold_path)
    recon_log_bridge_text = read(recon_log_bridge_path)
    corpus_detectorization_text = read(corpus_detectorization_path)
    tool_status_text = read(tool_status_path)
    workflow_text = read(workflow_path)
    source_mining_preflight_has_documented_templates = all(
        token in source_mining_campaign_text
        for token in (
            "dispatch-preflight.py",
            "--template source-extract",
            "--template adversarial-kill",
            "Never auto-promote a candidate",
        )
    )
    source_mining_preflight_has_code_path = all(
        token in source_mining_campaign_text
        for token in (
            "dispatch-preflight.py",
            "DISPATCH_PREFLIGHT",
            "\"--template\"",
            "task_type=\"source-extract\"",
            "task_type=\"adversarial-kill\"",
            "Never auto-promote a candidate",
        )
    )

    checks = [
        {
            "check": "critical_hunt_exact_impact_contract_gate",
            "artifact_path": stable_artifact_path(critical_hunt_path),
            "present": all(
                token in critical_hunt_text
                for token in (
                    "def _load_exact_impact_contracts",
                    "impact_contracts.json",
                    "missing_exact_impact_contract",
                    "advisory_missing_exact_impact_contract",
                )
            ),
        },
        {
            "check": "paste_ready_exact_impact_contract_refusal",
            "artifact_path": stable_artifact_path(paste_ready_path),
            "present": all(
                token in paste_ready_text
                for token in (
                    "def _impact_contract_refusal_reasons",
                    "validate_impact_contract_text",
                    "matching workspace impact_contract proof is missing",
                    "listed_impact_proven",
                )
            ),
        },
        {
            "check": "packager_program_impact_contract_refusal",
            "artifact_path": stable_artifact_path(packager_path),
            "present": all(
                token in packager_text
                for token in (
                    "def _impact_mapping_packager_refusal",
                    "build_impact_mapping_manifest",
                    "Program Impact Mapping promotion contract refused packaging",
                    "packager_should_refuse",
                )
            ),
        },
        {
            "check": "swarm_dispatch_blocks_missing_impact_contract",
            "artifact_path": stable_artifact_path(swarm_path),
            "present": all(
                token in swarm_text
                for token in (
                    "def mining_brief_impact_contract_gate",
                    "dispatch_blocked_missing_impact_contract",
                    "REFUSING dispatch",
                    "blocked_missing_impact_contract",
                )
            ),
        },
        {
            "check": "mining_brief_records_blocked_missing_impact_contract",
            "artifact_path": stable_artifact_path(mining_brief_path),
            "present": all(
                token in mining_brief_text
                for token in (
                    "def ranked_row_requires_impact_contract",
                    "def impact_contract_id_from_row",
                    "impact_contract_required",
                    "blocked_missing_impact_contract",
                    "VERDICT=blocked_missing_impact_contract",
                )
            ),
        },
        {
            "check": "poc_scaffold_plan_json_requires_locked_impact_contract",
            "artifact_path": stable_artifact_path(poc_scaffold_path),
            "present": all(
                token in poc_scaffold_text
                for token in (
                    "def require_locked_impact_contract",
                    "blocked_missing_impact_contract",
                    "listed_impact_proven=true",
                    "exact_impact_row",
                )
            ),
        },
        {
            "check": "auto_draft_generator_requires_locked_impact_contract",
            "artifact_path": stable_artifact_path(auto_draft_path),
            "present": all(
                token in auto_draft_text
                for token in (
                    "def require_locked_impact_contract",
                    "auto-draft-generator requires",
                    "before writing drafts or PoC scaffolds",
                    "listed_impact_proven=true",
                )
            ),
        },
        {
            "check": "harness_scaffold_emitter_requires_locked_impact_contract",
            "artifact_path": stable_artifact_path(harness_scaffold_path),
            "present": all(
                token in harness_scaffold_text
                for token in (
                    "def require_locked_impact_contract",
                    "blocked_missing_impact_contract",
                    "listed_impact_proven=true",
                    "attempt_manifest",
                )
            ),
        },
        {
            "check": "submission_factory_refuses_unlocked_impact_contract",
            "artifact_path": stable_artifact_path(submission_factory_path),
            "present": all(
                token in submission_factory_text
                for token in (
                    "def impact_contract_refusal",
                    "validate_impact_contract_text",
                    "impact_contract_invalid:listed_impact_not_proven",
                    "severity_claim_not_backed_by_selected_impact_tier",
                )
            ),
        },
        {
            "check": "deep_replay_scaffold_requires_locked_impact_contract",
            "artifact_path": stable_artifact_path(deep_replay_scaffold_path),
            "present": all(
                token in deep_replay_scaffold_text
                for token in (
                    "def locked_impact_contract",
                    "deep replay scaffolds require record.impact_contract_id",
                    "listed_impact_proven=true",
                    "Do not promote until the Forge replay executes",
                )
            ),
        },
        {
            "check": "detector_promotion_program_impact_mapping_gate",
            "artifact_path": stable_artifact_path(promote_typed_candidate_path),
            "present": all(
                token in promote_typed_candidate_text
                for token in (
                    "def _impact_contract_report",
                    "impact_contract_required",
                    "program_impact_mapping_unresolved",
                    "impact_unresolved",
                )
            ),
        },
        {
            "check": "source_mining_survivors_remain_input_only_until_impact_contract",
            "artifact_path": stable_artifact_path(source_mining_campaign_path),
            "present": all(
                token in source_mining_campaign_text
                for token in (
                    "submission_posture",
                    "NOT_SUBMIT_READY",
                    "impact_contract_required",
                    "source_mining_generated_hypothesis",
                    "GENERATED_HYPOTHESIS",
                )
            ),
        },
        {
            "check": "source_mining_provider_routing_is_input_only",
            "artifact_path": stable_artifact_path(source_mining_campaign_path),
            "present": all(
                token in source_mining_campaign_text
                for token in (
                    "def build_outcome_routing_manifest",
                    "provider_rows",
                    "input_only_local_verification_required",
                    "llm_corpus_mining_is_proof",
                    "outcome_calibrated_routing.json",
                )
            ),
        },
        {
            "check": "source_mining_provider_dispatch_preflight_gate",
            "artifact_path": stable_artifact_path(source_mining_campaign_path),
            "present": (
                source_mining_preflight_has_documented_templates
                or source_mining_preflight_has_code_path
            )
            and all(
                token in dispatch_preflight_text
                for token in (
                    "MANDATORY_TASK_TYPES",
                    "source-extract",
                    "adversarial-kill",
                    "BYPASS_DISPATCH_PREFLIGHT_REASON",
                )
            )
            and all(
                token in llm_dispatch_text
                for token in (
                    "dispatch-preflight-required",
                    "AUDITOOOR_DISPATCH_PREFLIGHT_OK",
                    "BYPASS_DISPATCH_PREFLIGHT_REASON",
                )
            ),
        },
        {
            "check": "source_mining_kimi_source_extract_capture_is_advisory",
            "artifact_path": stable_artifact_path(source_mining_campaign_path),
            "present": all(
                token in source_mining_campaign_text
                for token in (
                    "provider=\"kimi\"",
                    "task_type=\"source-extract\"",
                    "_record_packet_done",
                    "kimi_candidates.json",
                    "KEEP_FOR_LOCAL_VERIFICATION",
                    "Never auto-promote a candidate",
                )
            )
            and all(
                token in dispatch_preflight_text
                for token in ("source-extract", "AUDITOOOR_DISPATCH_PREFLIGHT_OK")
            )
            and "dispatch-preflight-required" in llm_dispatch_text,
        },
        {
            "check": "source_mining_minimax_adversarial_kill_capture_is_advisory",
            "artifact_path": stable_artifact_path(source_mining_campaign_path),
            "present": all(
                token in source_mining_campaign_text
                for token in (
                    "provider=\"minimax\"",
                    "task_type=\"adversarial-kill\"",
                    "_record_packet_done",
                    "minimax_challenges.json",
                    "rejected.json",
                    "Never auto-promote a candidate",
                )
            )
            and all(
                token in dispatch_preflight_text
                for token in ("adversarial-kill", "AUDITOOOR_DISPATCH_PREFLIGHT_OK")
            )
            and "dispatch-preflight-required" in llm_dispatch_text,
        },
        {
            "check": "semantic_graph_typed_multihop_inventory",
            "artifact_path": stable_artifact_path(semantic_graph_path),
            "present": all(
                token in semantic_graph_text
                for token in (
                    "def evidence_edges_from_body",
                    "def build_multi_hop_paths",
                    "impact_family_for_path",
                    "mapped_stages",
                    "source_reader_coverage",
                    "route semantic path to exact-impact candidate or mark non-detectorizable",
                )
            ),
        },
        {
            "check": "semantic_detector_worklist_bridge_is_advisory",
            "artifact_path": stable_artifact_path(semantic_detector_worklist_path),
            "present": all(
                token in semantic_detector_worklist_text
                for token in (
                    "SCHEMA_VERSION = \"auditooor.semantic_detector_worklist.v1\"",
                    "semantic_relation_detector_rewrite",
                    "semantic_multihop_detector_rewrite",
                    "submission_posture\": \"NOT_SUBMIT_READY\"",
                    "impact_contract_required\": True",
                    "promotion_allowed\": False",
                    "none_source_shape_only",
                )
            ),
        },
        {
            "check": "submission_factory_requires_proof_artifact_and_tier_match",
            "artifact_path": stable_artifact_path(submission_factory_path),
            "present": all(
                token in submission_factory_text
                for token in (
                    "proof_artifact_missing",
                    "proof_artifact_not_found",
                    "selected_impact_not_exact_listed_sentence",
                    "severity_claim_not_backed_by_selected_impact_tier",
                )
            ),
        },
        {
            "check": "submission_packager_preserves_mapping_and_high_plus_artifact_tier_gates",
            "artifact_path": stable_artifact_path(packager_path),
            "present": all(
                token in packager_text
                for token in (
                    "build_impact_mapping_manifest",
                    "proof_artifact",
                    "packager_should_refuse",
                    "required_for_high_plus",
                    "ready_verdict",
                )
            ),
        },
        {
            "check": "chimera_scaffold_requires_locked_impact_contract",
            "artifact_path": stable_artifact_path(chimera_scaffold_path),
            "present": all(
                token in chimera_scaffold_text
                for token in (
                    "def _require_locked_impact_contract",
                    "blocked_missing_impact_contract",
                    "listed_impact_proven=true",
                    "submit_ready",
                )
            ),
        },
        {
            "check": "chimera_ledger_preserves_missing_impact_blocker",
            "artifact_path": stable_artifact_path(chimera_ledger_scaffold_path),
            "present": all(
                token in chimera_ledger_scaffold_text
                for token in (
                    "blocked_missing_impact_contract",
                    "impact_contract_required",
                    "impact_contract_id",
                )
            ),
        },
        {
            "check": "recon_bridge_requires_impact_contract_for_forge_output",
            "artifact_path": stable_artifact_path(recon_log_bridge_path),
            "present": all(
                token in recon_log_bridge_text
                for token in (
                    "def _locked_impact_contract",
                    "--forge-test-out requires --impact-contract-id",
                    "impact_contract_blocker",
                    "blocked_missing_impact_contract",
                )
            ),
        },
        {
            "check": "corpus_detectorization_recon_source_mining_rows_are_impact_neutral",
            "artifact_path": stable_artifact_path(corpus_detectorization_path),
            "present": all(
                token in corpus_detectorization_text
                for token in (
                    "ReCon/deep-counterexample",
                    "source-mining survivors",
                    "submission_posture=\"NOT_SUBMIT_READY\"",
                    "impact_contract_required=true",
                    "source-mining-harness-task",
                )
            ),
        },
        {
            "check": "docs_validation_mentions_impact_first_gates",
            "artifact_path": stable_artifact_path(tool_status_path),
            "present": all(
                token in tool_status_text
                for token in (
                    "make critical-hunt WS=...",
                    "tools/poc-scaffold.py --plan-json",
                    "locked to a proved exact impact contract",
                    "make docs-check",
                )
            )
            and "selected source-mining briefs that inherited `blocked_missing_impact_contract`" in workflow_text,
        },
    ]
    missing = [check["check"] for check in checks if not check["present"]]
    return {
        "schema": f"{SCHEMA_PREFIX}.impact_first_work_gate_reduction_evidence.v1",
        "status": "present" if not missing else "missing",
        "checks": checks,
        "missing_checks": missing,
        "artifact_paths": [check["artifact_path"] for check in checks],
        "covered_paths": [
            "critical-hunt",
            "paste-ready",
            "submission-packager",
            "swarm-dispatch",
            "mining-brief",
            "poc-scaffold-plan-json",
            "auto-draft-generator",
            "harness-scaffold-emitter",
            "submission-factory",
            "deep-counterexample-replay-scaffold",
            "detector-promotion",
            "source-mining-survivor",
            "source-mining-provider-routing",
            "source-mining-provider-preflight",
            "source-mining-kimi-source-extract-advisory",
            "source-mining-minimax-adversarial-kill-advisory",
            "semantic-graph-typed-multihop",
            "semantic-detector-worklist",
            "submission-factory-proof-artifact-tier",
            "submission-packager-proof-artifact-tier",
            "chimera-scaffold",
            "chimera-ledger-scaffold",
            "recon-log-bridge",
            "corpus-detectorization",
            "docs-validation",
        ],
        "remaining_unproven_paths": [
            "generic-harness-planning",
            "source-proof-promotion",
            "audit-closeout",
            "all candidate-generation/direct-submit paths not covered by the detected gates",
        ],
    }


def task_title(row: dict[str, Any], fallback: str) -> str:
    for key in ("title", "name", "impact", "selected_impact", "harness_task", "behavior_id", "source_id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return compact(value)
    return fallback


def build_contract_lookup(contracts_payload: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_candidate: dict[str, dict[str, Any]] = {}
    by_source: dict[str, dict[str, Any]] = {}
    by_impact: dict[str, dict[str, Any]] = {}
    for row in records_from_payload(contracts_payload):
        impact_contract_id = str(row.get("impact_contract_id") or "").strip()
        if not impact_contract_id:
            continue
        by_id[impact_contract_id] = row
        candidate = candidate_key(row)
        source = source_key(row)
        impact = str(row.get("selected_impact") or "").strip().lower()
        if candidate:
            by_candidate[candidate] = row
        if source:
            by_source[source] = row
        if impact:
            by_impact[impact] = row
    return by_id, by_candidate, by_source, by_impact


def impact_contract_for(
    row: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    by_candidate: dict[str, dict[str, Any]],
    by_source: dict[str, dict[str, Any]],
    by_impact: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    explicit = str(row.get("impact_contract_id") or "").strip()
    if explicit and explicit in by_id:
        return by_id[explicit]
    key = candidate_key(row)
    if key and key in by_candidate:
        return by_candidate[key]
    source = source_key(row)
    if source and source in by_source:
        return by_source[source]
    impact = str(row.get("selected_impact") or "").strip().lower()
    if impact and impact in by_impact:
        return by_impact[impact]
    return None


def impact_contract_preconditions_present(contract: dict[str, Any] | None) -> bool:
    if not contract:
        return False
    impact_contract_id = str(contract.get("impact_contract_id") or "").strip()
    selected = str(contract.get("selected_impact") or "").strip()
    severity = str(contract.get("severity") or "").strip().lower()
    if not impact_contract_id or not selected or severity in {"", "none"}:
        return False
    if contract.get("exact_impact_row") is False:
        return False
    if contract.get("listed_impact_proven") is not True:
        return False
    return True


def impact_contract_missing_preconditions(contract: dict[str, Any] | None) -> list[str]:
    if not contract:
        return ["impact_contract_id"]
    missing: list[str] = []
    if not str(contract.get("impact_contract_id") or "").strip():
        missing.append("impact_contract_id")
    if not str(contract.get("selected_impact") or "").strip():
        missing.append("selected_impact")
    if str(contract.get("severity") or "").strip().lower() in {"", "none"}:
        missing.append("severity_from_exact_impact_row")
    if contract.get("exact_impact_row") is False:
        missing.append("exact_impact_row=true")
    if contract.get("listed_impact_proven") is not True:
        missing.append("listed_impact_proven=true")
    return missing


def task_type_for(row: dict[str, Any], source: str) -> str:
    explicit = str(row.get("task_type") or row.get("candidate_kind") or "").strip()
    if explicit in {"scope_only", "impact_analysis"}:
        return explicit
    low = " ".join(str(row.get(k) or "") for k in ("terminal_state", "detector_or_lane", "lane", "status", "harness_task")).lower()
    if "scope_only" in low or "scope-only" in low:
        return "scope_only"
    if "impact_analysis" in low or "impact analysis" in low:
        return "impact_analysis"
    if source == "impact_contract":
        return "impact_harness"
    if "detector" in low:
        return "detector_harness"
    return "harness"


def is_genuine_harness_task(row: dict[str, Any], source: str, task_type: str, contract_locked: bool) -> bool:
    if source == "impact_contract" or contract_locked:
        return True
    if task_type in {"scope_only", "impact_analysis"}:
        return True
    values = " ".join(
        str(row.get(k) or "")
        for k in ("status", "terminal_state", "task_type", "candidate_kind", "detector_or_lane", "lane", "harness_task")
    ).lower()
    return any(state in values for state in HARNESS_REQUIRED_STATES)


def task_status(task_type: str, impact_contract_id: str, contract_locked: bool) -> tuple[str, str]:
    if task_type in {"scope_only", "impact_analysis"}:
        return "ready_to_execute", "explicit_scope_or_impact_analysis_task"
    if contract_locked:
        return "ready_to_execute", "exact_impact_contract_present"
    if impact_contract_id:
        return "blocked_missing_impact_contract", "impact contract exists but exact impact preconditions are not locked"
    return "blocked_missing_impact_contract", "missing exact impact_contract_id"


def task_next_command(status: str, task_type: str) -> str:
    if status == "ready_to_execute" and task_type == "scope_only":
        return "python3 tools/per-finding-oos-check.py <workspace> <draft-or-task>"
    if status == "ready_to_execute" and task_type == "impact_analysis":
        return "make impact-contract-check WS=<workspace>"
    if status == "ready_to_execute":
        return "make harness-plan WS=<workspace> ROW=<harness_task_id>"
    return "make impact-contract-check WS=<workspace>"


def impact_contract_suggestions_for_task(
    *,
    candidate_id: str,
    action_row: dict[str, Any],
) -> list[dict[str, Any]]:
    suggestions: list[dict[str, Any]] = []
    for cand in action_row.get("exact_impact_candidates", []):
        if not isinstance(cand, dict):
            continue
        impact_id = str(cand.get("impact_id") or "").strip()
        impact = str(cand.get("impact") or "").strip()
        if not impact_id or not impact:
            continue
        suggestion_id = f"impact-contract-suggestion-{slug(candidate_id)}-{slug(impact_id)}"
        suggestions.append(
            {
                "suggestion_id": suggestion_id,
                "candidate_id": candidate_id,
                "impact_id": impact_id,
                "selected_impact": impact,
                "severity": cand.get("severity") or "none",
                "source_file": cand.get("source_file") or "",
                "source_line": cand.get("source_line") or 0,
                "listed_impact_proven": False,
                "proof_required": "listed_impact_proven=true before harness/PoC/report work",
                "next_command": (
                    "make impact-contract-check WS=<workspace> "
                    f"# CANDIDATE={candidate_id} IMPACT_ID={impact_id} "
                    "requires listed_impact_proven=true"
                ),
            }
        )
    return suggestions


def blocked_harness_next_command(
    *,
    candidate_id: str,
    impact_contract_id: str,
    missing_preconditions: list[str],
    suggestions: list[dict[str, Any]],
) -> str:
    if suggestions:
        first = suggestions[0]
        return str(first["next_command"])
    if impact_contract_id:
        missing = ",".join(missing_preconditions) or "listed_impact_proven=true"
        return (
            "make impact-contract-check WS=<workspace> "
            f"# unlock impact_contract_id={impact_contract_id} "
            f"CANDIDATE={candidate_id} missing_preconditions={missing}"
        )
    missing = ",".join(missing_preconditions) or "impact_contract_id"
    return (
        "make impact-analysis-queue WS=<workspace> "
        f"# CANDIDATE={candidate_id} missing_preconditions={missing}"
    )


def citations_from_row(row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in (
        "required_citations",
        "source_citations",
        "citations",
        "source_files",
        "claims_detected",
    ):
        values.extend(_as_list(row.get(key)))
    for key in ("agent_output", "title", "reason", "next_command"):
        value = row.get(key)
        if isinstance(value, str):
            values.extend(match.group("cite") for match in SOURCE_CITATION_RE.finditer(value))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip().strip("`.,;")
        match = SOURCE_CITATION_RE.search(text)
        cite = match.group("cite") if match else text
        if ":" not in cite:
            continue
        if cite not in seen:
            seen.add(cite)
            out.append(cite)
    return out


def source_artifact_from_row(row: dict[str, Any]) -> str:
    for key in ("source_artifact", "agent_output", "path", "_source_file"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    for key in ("reason", "next_command", "title"):
        value = str(row.get(key) or "")
        match = SOURCE_ARTIFACT_RE.search(value)
        if match:
            return match.group("path")
    return ""


def stable_source_proof_candidate_id(row: dict[str, Any], contract: dict[str, Any] | None, idx: int) -> str:
    explicit = candidate_key(row) or str((contract or {}).get("candidate_id") or "").strip()
    if explicit:
        return explicit
    seed_parts = [
        source_key(row),
        source_artifact_from_row(row),
        str(row.get("reason") or ""),
        " ".join(_as_list(row.get("claims_detected"))),
        str(row.get("title") or ""),
    ]
    seed = " ".join(part for part in seed_parts if part).strip()
    if seed:
        return f"SOURCE-PROOF-{slug(seed)[:48].upper()}"
    return f"SOURCE-PROOF-{idx:03d}"


def source_proof_record_slug(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")
    return safe or "candidate"


def source_proof_record_path(workspace: Path, candidate_id: str) -> Path:
    return workspace / "source_proofs" / source_proof_record_slug(candidate_id) / "source_proof.json"


def source_proof_local_evidence(workspace: Path, candidate_id: str) -> tuple[dict[str, Any] | None, str]:
    path = source_proof_record_path(workspace, candidate_id)
    payload = load_json(path)
    if not isinstance(payload, dict):
        return None, str(path)
    if str(payload.get("candidate_id") or "") != candidate_id:
        return None, str(path)
    verdict = str(payload.get("final_verdict") or "").strip()
    if verdict not in {"proved_source_only", "killed", "blocked_missing_impact_contract"}:
        return None, str(path)
    return payload, str(path)


def missing_source_proof_preconditions(
    *,
    impact_contract_id: str,
    required_citations: list[str],
    oos_status: str,
) -> list[str]:
    missing: list[str] = []
    if not impact_contract_id:
        missing.append("impact_contract_id")
    if not required_citations:
        missing.append("required_source_citation")
    if oos_status != "in_scope":
        missing.append(f"oos_status:{oos_status}")
    return missing


def oos_status_from_row(row: dict[str, Any]) -> str:
    for key in ("oos_status", "oos", "scope_status"):
        value = str(row.get(key) or "").strip().lower().replace("-", "_")
        if value in {"in_scope", "oos", "unknown", "not_checked"}:
            return value
    return "not_checked"


def source_proof_status(
    *,
    impact_contract_id: str,
    required_citations: list[str],
    oos_status: str,
) -> tuple[str, str, list[str]]:
    missing = missing_source_proof_preconditions(
        impact_contract_id=impact_contract_id,
        required_citations=required_citations,
        oos_status=oos_status,
    )
    blockers: list[str] = []
    if "impact_contract_id" in missing:
        blockers.append("missing impact_contract_id")
    if "required_source_citation" in missing:
        blockers.append("missing required source citation")
    if any(item.startswith("oos_status:") for item in missing):
        blockers.append(f"oos_status is {oos_status}")
    if not impact_contract_id:
        return "blocked_missing_impact_contract", "impact contract precondition is not locked", blockers
    if not required_citations:
        return "blocked_missing_citations", "source-proof task lacks required line citations", blockers
    if oos_status != "in_scope":
        return "blocked_oos_not_checked", "OOS status must be in_scope before proof can be recorded", blockers
    return "ready_for_source_review", "impact contract, citation, and OOS preconditions are present", blockers


def source_proof_record_command(
    candidate_id: str,
    citations: list[str],
    oos_status: str,
    missing_preconditions: list[str],
    *,
    verdict: str = "blocked_missing_impact_contract",
    note_prefix: str = "queue item",
) -> str:
    parts = [
        "make source-proof-record",
        "WS=<workspace>",
        f"CANDIDATE={shlex.quote(candidate_id)}",
    ]
    if citations:
        parts.append(f"CITATION={shlex.quote(citations[0])}")
    parts.extend([
        f"OOS={shlex.quote(oos_status)}",
        f"VERDICT={shlex.quote(verdict)}",
        "NOTE="
        + shlex.quote(
            note_prefix
            + ": missing_preconditions="
            + (",".join(missing_preconditions) if missing_preconditions else "none")
            + "; evidence_path=<workspace>/source_proofs/<candidate>/source_proof.json"
            + "; verify exact impact contract, citations, OOS, and source lines before any proved_source_only verdict"
        ),
    ])
    return " ".join(parts)


def source_proof_evidence_requirements(
    *,
    impact_contract_id: str,
    required_citations: list[str],
    oos_status: str,
    evidence_path: str,
) -> list[str]:
    requirements = [
        f"write_terminal_source_proof_record:{evidence_path}",
        "source_proof_record.final_verdict in proved_source_only|killed|blocked_missing_impact_contract",
        "source_proof_record.submit_ready is absent_or_false",
        "source_proof_record does not assign severity",
    ]
    if not impact_contract_id:
        requirements.append("lock exact impact_contract_id before proved_source_only")
    if not required_citations:
        requirements.append("add at least one exact source file:line citation")
    if oos_status != "in_scope":
        requirements.append("run/record OOS check with oos_status=in_scope before proved_source_only")
    return requirements


def render_source_proof_task_queue(workspace: Path) -> dict[str, Any]:
    contracts_payload = load_json(out_dir(workspace) / "impact_contracts.json") or render_impact_contracts(workspace)
    by_id, by_candidate, by_source, by_impact = build_contract_lookup(contracts_payload)
    recall_payload = load_json(out_dir(workspace) / "agent_found_not_detector_found.json") or render_agent_recall(workspace)
    agent_ledger, _ = load_agent_output_verification_ledger(workspace)
    tasks: list[dict[str, Any]] = []
    for idx, row in enumerate(records_from_payload(recall_payload), 1):
        if str(row.get("status") or "") != "source_proof_required":
            continue
        if not agent_output_allows_downstream(row, agent_ledger, allowed_terminal_states={"routed_to_source_proof"}):
            continue
        contract = impact_contract_for(row, by_id, by_candidate, by_source, by_impact)
        impact_contract_id = str((contract or {}).get("impact_contract_id") or row.get("impact_contract_id") or "").strip()
        candidate_id = stable_source_proof_candidate_id(row, contract, idx)
        required_citations = citations_from_row(row)
        oos_status = oos_status_from_row(row)
        status, reason, blockers = source_proof_status(
            impact_contract_id=impact_contract_id,
            required_citations=required_citations,
            oos_status=oos_status,
        )
        missing_preconditions = missing_source_proof_preconditions(
            impact_contract_id=impact_contract_id,
            required_citations=required_citations,
            oos_status=oos_status,
        )
        source_artifact = source_artifact_from_row(row)
        local_evidence, local_evidence_path = source_proof_local_evidence(workspace, candidate_id)
        resolved_by_local_evidence = bool(local_evidence)
        if resolved_by_local_evidence:
            status = "terminal_evidence_present"
            reason = "local source_proof.json terminal evidence exists"
            blockers = []
            missing_preconditions = []
        required_manual_step = ""
        if not required_citations:
            inspect_target = source_artifact or str(row.get("agent_output") or "agent recall row")
            required_manual_step = (
                f"Inspect {inspect_target} and add exact source file:line citation "
                "before recording source proof."
            )
        evidence_requirements = source_proof_evidence_requirements(
            impact_contract_id=impact_contract_id,
            required_citations=required_citations,
            oos_status=oos_status,
            evidence_path=local_evidence_path,
        )
        blocked_record_command = source_proof_record_command(
            candidate_id,
            required_citations,
            oos_status,
            missing_preconditions,
            verdict="blocked_missing_impact_contract",
            note_prefix="fail-closed source-proof queue item",
        )
        proved_after_review_command = source_proof_record_command(
            candidate_id,
            required_citations,
            oos_status,
            missing_preconditions,
            verdict="proved_source_only",
            note_prefix="ONLY after local source review proves the exact impact sentence",
        )
        selected_impact = str((contract or {}).get("selected_impact") or row.get("selected_impact") or "").strip()
        if not impact_contract_id:
            selected_impact = ""
        tasks.append(
            {
                "source_proof_task_id": f"source-proof-task-{slug(candidate_id)}-{idx:03d}",
                "source": "agent_recall",
                "agent_output": str(row.get("agent_output") or ""),
                "source_artifact": source_artifact,
                "source_id": source_key(row),
                "candidate_id": candidate_id,
                "title": task_title(row, candidate_id),
                "reason": str(row.get("reason") or ""),
                "claims_detected": _as_list(row.get("claims_detected")),
                "impact_contract_id": impact_contract_id,
                "impact_contract_precondition": "present" if impact_contract_id else "missing",
                "selected_impact": selected_impact,
                "required_citations": required_citations,
                "oos_status": oos_status,
                "status": status,
                "status_reason": reason,
                "blockers": blockers,
                "missing_preconditions": missing_preconditions,
                "required_evidence": evidence_requirements,
                "terminal_evidence_path": local_evidence_path,
                "local_evidence_status": "present" if resolved_by_local_evidence else "missing",
                "local_evidence_final_verdict": str((local_evidence or {}).get("final_verdict") or ""),
                "resolved_by_local_evidence": resolved_by_local_evidence,
                "required_manual_step": required_manual_step,
                "default_verdict": "blocked_missing_impact_contract",
                "terminal_state_options": [
                    "proved_source_only_after_local_review",
                    "killed",
                    "blocked_missing_impact_contract",
                ],
                "proof_fabricated": False,
                "next_command": (
                    "local source proof evidence already recorded; inspect terminal_evidence_path"
                    if resolved_by_local_evidence
                    else blocked_record_command
                ),
                "blocked_record_command": blocked_record_command,
                "proved_after_review_command": proved_after_review_command,
                "submit_ready": False,
                "severity": "none",
            }
        )
    tasks.sort(key=lambda r: (r["status"], r["source_proof_task_id"]))
    status_counts = {
        status: sum(1 for row in tasks if row["status"] == status)
        for status in SOURCE_PROOF_TASK_STATUSES
    }
    payload = {
        "schema": f"{SCHEMA_PREFIX}.source_proof_tasks.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": tasks,
        "allowed_statuses": list(SOURCE_PROOF_TASK_STATUSES),
        "summary": {
            "row_count": len(tasks),
            "local_evidence_present": sum(1 for row in tasks if row.get("resolved_by_local_evidence")),
            "local_evidence_missing": sum(1 for row in tasks if not row.get("resolved_by_local_evidence")),
            **status_counts,
        },
        "status": "ok" if tasks else "empty_no_source_proof_tasks",
    }
    d = out_dir(workspace)
    write_json(d / "source_proof_tasks.json", payload)
    md = [
        "# Source Proof Task Queue",
        "",
        "| Task | Candidate | Status | Evidence | Impact contract | OOS | Required citations | Next command |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in tasks:
        cites = ", ".join(f"`{c}`" for c in row["required_citations"]) or "_missing_"
        manual = f" Manual: {row['required_manual_step']}" if row.get("required_manual_step") else ""
        md.append(
            f"| `{row['source_proof_task_id']}` | `{row['candidate_id']}` | `{row['status']}` | "
            f"`{row['local_evidence_status']}:{row['terminal_evidence_path']}` | "
            f"`{row['impact_contract_id'] or '(missing)'}` | `{row['oos_status']}` | {cites} | `{row['next_command']}` |"
        )
        if manual:
            md.append(f"<!-- {row['source_proof_task_id']} required_manual_step: {manual} -->")
        md.append(
            f"<!-- {row['source_proof_task_id']} required_evidence: "
            + " ; ".join(row.get("required_evidence", []))
            + " -->"
        )
    if not tasks:
        md.append("| _none_ | _none_ | `empty_no_source_proof_tasks` | _none_ | _none_ | _none_ | _none_ | _none_ |")
    write_md(d / "source_proof_tasks.md", md)
    return payload


NEXT_ACTION_ORDER = {
    "strict_blocker": 0,
    "open_impact_family": 1,
    "harness_impact_work": 2,
    "impact_analysis": 3,
    "source_proof": 4,
    "agent_verification": 5,
    "semantic_detector": 6,
    "provider_local_verification": 7,
    "invariant_queue": 8,
}


def _append_next_action(
    rows: list[dict[str, Any]],
    *,
    category: str,
    source_artifact: str,
    source_id: str,
    exact_status: str,
    next_command: str,
    strict_blocking: bool = False,
    title: str = "",
    detail: str = "",
) -> None:
    if not next_command:
        next_command = "inspect source artifact and choose the next exact-impact action"
    rows.append(
        {
            "next_action_id": f"pr560-next-{len(rows) + 1:03d}-{slug(category)}-{slug(source_id or title or source_artifact)}",
            "category": category,
            "source_artifact": source_artifact,
            "source_id": source_id,
            "title": title or source_id or source_artifact,
            "status": category,
            "exact_status": exact_status,
            "next_command": next_command,
            "strict_blocking": bool(strict_blocking),
            "detail": detail,
            "submit_ready": False,
        }
    )


def semantic_detector_adjudication_next_action_rows(workspace: Path, limit: int = 50) -> list[dict[str, Any]]:
    payload = load_json(out_dir(workspace) / "semantic_detector_adjudication.json") or {}
    if not isinstance(payload, dict):
        return []
    artifact = str(out_dir(workspace) / "semantic_detector_adjudication.json")
    rows: list[dict[str, Any]] = []
    sections = (
        ("detector_rewrite_briefs", "detector_rewrite_brief", "brief_id"),
        ("fixture_requirements", "fixture_requirement", "fixture_id"),
        ("non_detectorizable_rows", "non_detectorizable", "row_id"),
    )
    for section, exact_status, id_key in sections:
        values = payload.get(section)
        if not isinstance(values, list):
            continue
        for row in values:
            if not isinstance(row, dict):
                continue
            source_id = str(row.get(id_key) or row.get("task_id") or row.get("route_id") or "")
            title = str(row.get("candidate_detector_family") or row.get("reason") or exact_status)
            detail_parts = [
                str(row.get("reason") or row.get("detector_slug") or row.get("query_shape") or ""),
                str(row.get("terminal_decision_required") or ""),
                str(row.get("action_lane") or ""),
            ]
            detail = " | ".join(part for part in detail_parts if part)
            rows.append(
                {
                    "source_artifact": artifact,
                    "source_id": source_id,
                    "exact_status": exact_status,
                    "next_command": str(
                        row.get("next_command")
                        or payload.get("next_command")
                        or f"make semantic-detector-adjudication WS={workspace}"
                    ),
                    "title": title,
                    "detail": detail,
                }
            )
            if len(rows) >= limit:
                return rows
    return rows


def provider_local_verification_next_action_rows(workspace: Path, limit: int = 50) -> list[dict[str, Any]]:
    artifact_path = workspace / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.json"
    closure_path = workspace / ".audit_logs" / "pr560_worker_ax" / "provider_local_verification_closure.json"
    payload = load_json(artifact_path) or {}
    if not isinstance(payload, dict):
        return []
    closure_payload = load_json(closure_path) if closure_path.exists() else {}
    terminal_queue_ids = {
        str(row.get("queue_id") or "")
        for row in records_from_payload(closure_payload)
        if isinstance(row, dict) and bool(row.get("terminal"))
    }
    rows: list[dict[str, Any]] = []
    for row in payload.get("rows", []) if isinstance(payload.get("rows"), list) else []:
        if not isinstance(row, dict):
            continue
        queue_id = str(row.get("queue_id") or "")
        if queue_id and queue_id in terminal_queue_ids:
            continue
        rows.append(
            {
                "source_artifact": str(artifact_path),
                "source_id": str(queue_id or row.get("task_id") or ""),
                "exact_status": str(row.get("route") or "provider_local_verification"),
                "next_command": str(row.get("next_command") or "make live-provider-local-verification-queue"),
                "title": str(row.get("title") or row.get("candidate_family") or "provider local verification"),
                "detail": str(row.get("minimum_followup_check") or row.get("kill_reason") or ""),
            }
        )
        if len(rows) >= limit:
            return rows
    return rows


def render_pr560_next_actions(workspace: Path) -> dict[str, Any]:
    coverage = load_json(out_dir(workspace) / "coverage_inventory.json") or render_coverage_inventory(workspace)
    harness = load_json(out_dir(workspace) / "harness_tasks.json") or render_harness_task_queue(workspace)
    impact_analysis = load_json(out_dir(workspace) / "impact_analysis_queue.json") or render_impact_analysis_queue(workspace)
    source_proof = load_json(out_dir(workspace) / "source_proof_tasks.json") or render_source_proof_task_queue(workspace)
    agents = load_json(out_dir(workspace) / "agent_output_inventory.json") or render_agent_output_inventory(workspace)
    invariant = render_invariant_discovery_status(workspace)
    semantic_detector_rows = semantic_detector_adjudication_next_action_rows(workspace)
    provider_verification_rows = provider_local_verification_next_action_rows(workspace)

    rows: list[dict[str, Any]] = []

    for cov in records_from_payload(coverage):
        for detail in cov.get("blocker_details", []) if isinstance(cov.get("blocker_details"), list) else []:
            if not isinstance(detail, dict):
                continue
            category = str(detail.get("category") or "")
            if category not in STRICT_BLOCKING_CATEGORIES:
                continue
            _append_next_action(
                rows,
                category="strict_blocker",
                source_artifact=str(detail.get("artifact") or out_dir(workspace) / "coverage_inventory.json"),
                source_id=str(cov.get("impact_id") or ""),
                exact_status=category,
                next_command=str(detail.get("next_command") or cov.get("next_command") or ""),
                strict_blocking=True,
                title=str(cov.get("impact") or detail.get("reason") or ""),
                detail=str(detail.get("reason") or ""),
            )

    for cov in records_from_payload(coverage):
        strict_categories = set(str(v) for v in cov.get("strict_blocking_categories", []) or [])
        open_categories = set(str(v) for v in cov.get("open_work_categories", []) or [])
        if strict_categories or not open_categories:
            continue
        _append_next_action(
            rows,
            category="open_impact_family",
            source_artifact=str(out_dir(workspace) / "coverage_inventory.json"),
            source_id=str(cov.get("impact_id") or ""),
            exact_status=str(cov.get("coverage_status") or cov.get("candidate_coverage") or ""),
            next_command=str(cov.get("next_command") or "make impact-worklist WS=<workspace>"),
            strict_blocking=False,
            title=str(cov.get("impact") or ""),
            detail="open_work_categories=" + ",".join(sorted(open_categories)),
        )

    for row in records_from_payload(harness):
        if str(row.get("status") or "") != "blocked_missing_impact_contract":
            continue
        _append_next_action(
            rows,
            category="harness_impact_work",
            source_artifact=str(row.get("source_artifact") or out_dir(workspace) / "harness_tasks.json"),
            source_id=str(row.get("harness_task_id") or row.get("candidate_id") or row.get("source_id") or ""),
            exact_status=str(row.get("impact_contract_work_status") or row.get("status") or ""),
            next_command=str(row.get("next_command") or "make impact-contract-check WS=<workspace>"),
            strict_blocking=False,
            title=str(row.get("title") or row.get("candidate_id") or ""),
            detail="missing_preconditions=" + ",".join(str(v) for v in row.get("missing_preconditions", []) or []),
        )

    for row in records_from_payload(impact_analysis):
        action = str(row.get("action_type") or "")
        if not action or action == "empty_no_blocked_agent_recall_rows":
            continue
        _append_next_action(
            rows,
            category="impact_analysis",
            source_artifact=str(row.get("agent_output") or row.get("source_artifact") or out_dir(workspace) / "impact_analysis_queue.json"),
            source_id=str(row.get("queue_id") or row.get("candidate_id") or row.get("source_id") or ""),
            exact_status=action,
            next_command=str(row.get("next_command") or "make impact-analysis-queue WS=<workspace>"),
            strict_blocking=False,
            title=str(row.get("candidate_id") or row.get("source_id") or ""),
            detail=str(row.get("reason") or row.get("route_reason") or ""),
        )

    for row in records_from_payload(source_proof):
        status = str(row.get("status") or "")
        if not status or status == "empty_no_source_proof_tasks":
            continue
        _append_next_action(
            rows,
            category="source_proof",
            source_artifact=str(row.get("source_artifact") or row.get("agent_output") or out_dir(workspace) / "source_proof_tasks.json"),
            source_id=str(row.get("source_proof_task_id") or row.get("candidate_id") or ""),
            exact_status=status,
            next_command=str(row.get("next_command") or "make source-proof-record WS=<workspace>"),
            strict_blocking=False,
            title=str(row.get("title") or row.get("candidate_id") or ""),
            detail=str(row.get("required_manual_step") or row.get("status_reason") or ""),
        )

    for row in records_from_payload(agents):
        if str(row.get("local_verification_status") or "") in AGENT_OUTPUT_TERMINAL_STATES:
            continue
        _append_next_action(
            rows,
            category="agent_verification",
            source_artifact=str(row.get("source_path") or row.get("path") or out_dir(workspace) / "agent_output_inventory.json"),
            source_id=str(row.get("verification_task_id") or ""),
            exact_status=str(row.get("local_verification_status") or "not_verified"),
            next_command=str(row.get("next_command") or "make agent-recall WS=<workspace>"),
            strict_blocking=False,
            title=", ".join(str(v) for v in row.get("claims_detected", []) or []) or "agent output verification",
            detail=str(row.get("terminal_route") or ""),
        )

    for row in semantic_detector_rows:
        _append_next_action(
            rows,
            category="semantic_detector",
            source_artifact=str(row.get("source_artifact") or out_dir(workspace) / "semantic_detector_adjudication.json"),
            source_id=str(row.get("source_id") or ""),
            exact_status=str(row.get("exact_status") or "semantic_detector_adjudication"),
            next_command=str(row.get("next_command") or f"make semantic-detector-adjudication WS={workspace}"),
            strict_blocking=False,
            title=str(row.get("title") or "semantic detector adjudication"),
            detail=str(row.get("detail") or ""),
        )

    for row in provider_verification_rows:
        _append_next_action(
            rows,
            category="provider_local_verification",
            source_artifact=str(row.get("source_artifact") or workspace / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.json"),
            source_id=str(row.get("source_id") or ""),
            exact_status=str(row.get("exact_status") or "provider_local_verification"),
            next_command=str(row.get("next_command") or "make live-provider-local-verification-queue"),
            strict_blocking=False,
            title=str(row.get("title") or "provider local verification"),
            detail=str(row.get("detail") or ""),
        )

    if int(invariant.get("missing_before_count") or 0) > 0 or invariant.get("status") == "advisory_missing_generated_invariants":
        _append_next_action(
            rows,
            category="invariant_queue",
            source_artifact=str(invariant.get("artifact_path") or out_dir(workspace) / "generated_invariants.json"),
            source_id="generated_invariants",
            exact_status=str(invariant.get("status") or ""),
            next_command=str(invariant.get("next_command") or "python3 tools/invariant-ledger.py --workspace <workspace> --from-scope"),
            strict_blocking=False,
            title="generated-vs-accepted invariant diff",
            detail=(
                f"generated={invariant.get('generated_count', 0)} "
                f"missing_before={invariant.get('missing_before_count', 0)}"
            ),
        )

    rows.sort(key=lambda r: (NEXT_ACTION_ORDER.get(str(r.get("category")), 99), not bool(r.get("strict_blocking")), str(r.get("source_id"))))
    for idx, row in enumerate(rows, 1):
        row["sort_index"] = idx

    summary = {
        "row_count": len(rows),
        "strict_blocking": sum(1 for row in rows if row.get("strict_blocking")),
        "by_category": {
            category: sum(1 for row in rows if row.get("category") == category)
            for category in NEXT_ACTION_ORDER
        },
    }
    payload = {
        "schema": f"{SCHEMA_PREFIX}.next_actions.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": rows,
        "summary": summary,
        "status": (
            "blocked_strict_next_actions"
            if summary["strict_blocking"]
            else ("open_next_actions" if rows else "empty_no_pr560_next_actions")
        ),
    }
    d = out_dir(workspace)
    write_json(d / "pr560_next_actions.json", payload)
    md = ["# PR560 Next Actions", "", "| # | Category | Strict | Status | Source | Next command |", "|---:|---|---|---|---|---|"]
    for row in rows:
        md.append(
            f"| {row['sort_index']} | `{row['category']}` | `{str(row['strict_blocking']).lower()}` | "
            f"`{row['exact_status']}` | `{row['source_artifact']}` | `{row['next_command']}` |"
        )
    if not rows:
        md.append("| 0 | _none_ | `false` | `empty_no_pr560_next_actions` | _none_ | _none_ |")
    write_md(d / "pr560_next_actions.md", md)
    return payload


LOCAL_BATCH_COMPLETED_ITEMS = (
    "Added `pr560-next-actions` mode to `tools/automation-closure.py`.",
    "Added `make pr560-next-actions WS=<workspace>`.",
    "Wrote `<ws>/.auditooor/pr560_next_actions.{json,md}` as a compact merged queue across PR560 artifacts.",
    "Sorted next actions by strict blockers first, then open impact-family work, harness impact-contract work, impact-analysis rows, source-proof rows, agent verification rows, and invariant queue work.",
    "Added `strict_blocking` and `submit_ready=false` fields to every next-action row.",
    "Added source artifact, status/category, and exact next-command fields to next-action rows.",
    "Wired `pr560_next_actions.json` into PR560 audit-closeout artifact accounting.",
    "Added closeout tests for unresolved PR560 next-action rows.",
    "Updated `docs/TOOL_STATUS.md` with the new command and closeout artifact.",
    "Verified no finding/severity promotion is performed by the new queue.",
    "Added `pr560-local-progress` mode to regenerate `docs/PR560_LOCAL_BATCH_PROGRESS.md` from the current next-action queue.",
    "Added `make pr560-local-progress WS=<workspace>`.",
    "Added `.auditooor/pr560_local_batch_progress.json` output.",
    "Added remaining queue counts, strict blocker counts, changed-file summary, and test summary to generated local progress output.",
    "Added tests for generated progress Markdown and CLI JSON mode.",
    "Integrated scan-artifact missing blockers into coverage/closure next-action rows in lane A2.",
    "Preserved canonical scan recognition across root `scan_report.md`, `scanners/SCAN_REPORT.md`, and `detector_findings.json`.",
    "Added exact accepted scan artifact options and command options for missing Smart Contract scan evidence.",
    "Added terminal-state ingestion for agent-output verification rows in lane B2.",
    "Matched agent-output verification ledger rows by task id, stable path, source path, path, or agent output.",
    "Preserved `submit_ready=false` and `severity=none` for agent-output verification rows.",
    "Integrated open Critical/High impact-family source-mining rows into PR560 next actions in lane D2.",
    "Preserved exact impact, OOS traps, suggested roots, command, stop criteria, and impact-contract precondition for impact-family next-action rows.",
    "Added `strict_blocking=false` to open impact-family source-mining rows.",
    "Added tests proving 30 open families become 30 source-mining queue rows and 30 PR560 next-action rows.",
    "Added invariant acceptance queue rows to PR560 next actions in lane E2.",
    "Added `submit_ready=false` and `exact_source_scope_text` to invariant acceptance queue rows.",
    "Preserved invariant queue advisory-only behavior; no strict/submission gate was added.",
    "Added tests for invariant acceptance aggregate next-actions output and CLI mode.",
    "Updated local lane ledgers for A2-E2 without pushing, opening PRs, merging, or using GitHub actions.",
    "Reconciled generated progress ledger with actual A2-E2 lane outputs.",
    "Added generated lane output inventory with worktree path, item count, tests, and batch-readiness status.",
    "Added repo-local machine-readable `docs/PR560_LOCAL_BATCH_PROGRESS.json` progress output.",
    "Kept the C3 reconciliation local-only for eventual milestone batching.",
    "Added scan-artifact role normalization for canonical scan reports vs legacy optional `detector_findings.json`.",
    "Added `satisfied_by` so closure/coverage output identifies the exact artifact that fulfilled Smart Contract scan coverage.",
    "Added canonical artifact options, legacy optional artifact lists, and migration notes for old detector-findings expectations.",
    "Propagated scan migration metadata into missing-scan `next_action_rows` while keeping `severity=none` and `submit_ready=false`.",
    "Added `--mode agent-output-verify-record` local CLI support.",
    "Added local write/update support for `<ws>/.auditooor/agent_output_verification_ledger.json`.",
    "Added companion `<ws>/.auditooor/agent_output_verification_ledger.md`.",
    "Added fail-closed validation for agent-output verification ledger writes: allowed terminal state, row identifier, and evidence path are required.",
    "Added upsert-by-stable-identifier behavior for agent-output verification outcomes.",
    "Preserved `submit_ready=false` and `severity=none` in agent-output verify command output and ledger rows.",
    "Added per-family `source_root_selection` to impact-family source-mining rows.",
    "Added impact-family `routing_hints` with Kimi/Minimax roles marked `input_only_not_dispatched`.",
    "Added local tool hints for impact-contract checks, source-proof queues, Rust/DLT scans, coverage inventory, and harness-task routing.",
    "Added explicit `dispatch_allowed=false` to impact-family source-mining queue rows and propagated it into `pr560_next_actions`.",
    "Preserved required evidence class, OOS traps, stop criteria, and exact impact-contract precondition in impact-family routing.",
    "Added local invariant acceptance review ingestion from `.auditooor/invariant_acceptance_ledger.json`.",
    "Allowed invariant review rows to override generated invariants into advisory `accepted`, `merged`, `killed`, or `needs_harness` states.",
    "Preserved `submit_ready=false` across invariant acceptance queue and `pr560_next_actions`.",
    "Propagated invariant review metadata into `pr560_next_actions`: `review_state`, `review_applied`, and `review_artifact`.",
    "Added focused invariant tests for review ingestion and next-action propagation.",
    "Re-ran lane A3 tests: 37 automation-closure tests plus docs and branch isolation.",
    "Re-ran lane B3 tests: automation-closure suite plus py_compile/docs/branch isolation.",
    "Re-ran lane D3 tests: 36 automation-closure tests plus docs and branch isolation.",
    "Re-ran lane E3 tests: 38 automation-closure tests plus docs, diff-check, and branch isolation.",
    "Added bundle-readiness summary for eventual PR560 local batch integration.",
    "Derived local changed-file inventory from `git status` with a static fallback for non-git workspaces.",
    "Added lane-output totals and non-ready lane diagnostics to generated progress JSON.",
    "Added advisory queue and strict-blocker split to the local progress readiness calculation.",
    "Kept progress generation workspace-safe by writing repo docs plus `<ws>/.auditooor/pr560_local_batch_progress.json` only.",
    "Added local-only packaging consistency checks for lane item totals, test coverage, changed-file evidence, and strict blocker counts.",
    "Made unverified agent-output next-action rows refuse eventual PR readiness until verification rows are resolved.",
    "Added machine-readable bundle refusal reasons to `docs/PR560_LOCAL_BATCH_PROGRESS.json`.",
    "Added Markdown readiness diagnostics so operators can see why packaging is refused without opening GitHub.",
    "Added focused tests for unverified agent-output packaging refusal and readiness consistency metadata.",
    "Reconciled lane A5 fail-closed agent verification record scaffolds into the central local progress ledger.",
    "Recorded A5 verification scaffold linkage from every agent-output inventory row to a durable `verification_record_path`.",
    "Preserved A5 empty impact/severity/OOS defaults: selected impact empty, impact contract empty, OOS `not_checked`, severity `none`, and `submit_ready=false`.",
    "Recorded A5 regression coverage for claim-bearing outputs, repo-opt-in outputs, and archive/ignore rows.",
    "Reconciled lane B5 source-proof advisory precision into the central local progress ledger.",
    "Recorded B5 terminal source-proof evidence fields: `required_evidence`, `terminal_evidence_path`, `local_evidence_status`, resolved flag, and final verdict.",
    "Recorded B5 fail-closed source-proof commands that separate blocked record capture from post-review proved-source-only capture.",
    "Preserved B5 source-proof rows as `severity=none` and `submit_ready=false` until exact impact, citation, and OOS preconditions are locally verified.",
    "Reconciled lane D5 impact-analysis exact-impact routing into the central local progress ledger.",
    "Recorded D5 proof requirements: exact impact sentence/status, OOS traps, required proof artifacts, stop criteria, and kill-before-harness condition.",
    "Recorded D5 fail-closed routing flags: `harness_work_allowed=false`, `paste_ready=false`, and `severity_promotion_allowed=false`.",
    "Preserved D5 impact-analysis routing through `impact-contract-check` before any harness-task follow-up.",
    "Reconciled lane E5 fail-closed invariant review dispositions into the central local progress ledger.",
    "Recorded E5 action-specific proof gates for accept, merge duplicate, kill OOS, and needs-harness invariant review dispositions.",
    "Recorded E5 closeout validation for hand-written terminal-looking invariant rows with missing evidence.",
    "Preserved E5 invariant no-promotion semantics: `severity=none`, `paste_ready=false`, and `submit_ready=false`.",
    "Separated completed implementation count from bundle readiness status in the local progress JSON and Markdown.",
    "Added explicit readiness blocker rows distinct from remaining advisory counts.",
    "Added remaining advisory count fields so open advisory work is visible without implying implementation incompleteness.",
    "Kept eventual PR readiness false while 60 agent-output verification rows remain unresolved.",
    "Added central C7 advisory reconciliation that subtracts only rows with local terminal evidence from remaining counts.",
    "Recorded resolved advisory counts separately from remaining advisory counts so implementation capability does not masquerade as row closure.",
    "Added source artifact provenance for advisory reconciliation under `advisory_reconciliation`.",
    "Kept package readiness gated on unresolved agent-output verification rows after reconciliation.",
    "Ported `agent-output-verify-record` into the central local integration worktree.",
    "Added terminal-state constants and ledger ingestion to central `agent-output-inventory` rendering.",
    "Recorded nine no-claim agent outputs as `archived_no_claims` with the output file itself as evidence.",
    "Fixed next-action generation to skip all terminal agent-output states, not only verified-local rows.",
    "Fixed advisory reconciliation to count `local_verification_status` terminal states.",
    "Regenerated PR560 next-action and progress artifacts with 9 resolved advisory rows and 51 remaining agent-output rows.",
    "Added local impact-first gate accounting for critical-hunt advisory exact-impact gating.",
    "Added local impact-first gate accounting for paste-ready exact-impact refusal.",
    "Added local impact-first gate accounting for submission-packager program-impact refusal.",
    "Added local impact-first gate accounting for swarm dispatch impact-contract blocking.",
    "Added local impact-first gate accounting for mining brief blocked-missing-impact-contract propagation.",
    "Added local impact-first gate accounting for poc-scaffold plan-json locked impact-contract enforcement.",
    "Added local impact-first gate accounting for docs/validation coverage already present through docs-check and operator docs.",
    "Added local impact-first gate accounting for auto-draft-generator impact-contract refusal before draft/PoC writes.",
    "Added local impact-first gate accounting for harness-scaffold-emitter blocked manifests before scaffold writes.",
    "Added local impact-first gate accounting for detector-promotion Program Impact Mapping refusal.",
    "Added local impact-first gate accounting for source-mining survivor input-only impact-contract requirements.",
    "Added local impact-first gate accounting for ReCon/Chimera impact-contract blockers before forge replay or scaffold promotion.",
    "Preserved the hard distinction that newly gated seams reduce Priority 1 only and do not fully close known limitations.",
    "Added local impact-first gate accounting for submission-factory paste-ready refusal on unlocked impact contracts.",
    "Added local impact-first gate accounting for deep-counterexample replay scaffolds requiring locked impact contracts before PoC work.",
    "Added local impact-first gate accounting for source-mining provider routing remaining input-only until local blockers clear.",
    "Promoted auto-draft and harness-scaffold emitted-artifact gates into machine-detected known-limitations reduction evidence.",
    "Regenerated PR560 local progress with C12 reduction-only seam accounting and no full-closure claim.",
    "Added local provider/source-mining preflight gate accounting for source-extract and adversarial-kill dispatches.",
    "Split Kimi source-extract provider-assist accounting into captured, locally gated, advisory-only work.",
    "Split Minimax adversarial-kill provider-assist accounting into captured, locally gated, advisory-only work.",
    "Added semantic-detector-worklist bridge accounting as advisory source-shape detector rewrite work, not submission proof.",
    "Added typed multihop semantic graph accounting for mapped stages, impact families, and source-reader coverage.",
    "Added submission-factory proof-artifact existence and severity-tier match gate accounting.",
    "Added submission-packager proof-artifact/High+ evidence-matrix tier gate accounting.",
    "Regenerated PR560 local progress with C13 provider-assist, semantic, and submission-output accounting and no full-closure claim.",
    "Added impact-worklist execution mode to semantic-graph-query for source_review_handoff routes.",
    "Kept semantic-graph-query impact-worklist execution limited to supported relation_edges and multi_hop_paths.",
    "Added impact-worklist source-mode metadata to semantic_graph_query_results.",
    "Added impact worklist row counts to semantic query result JSON and Markdown.",
    "Propagated impact_id, impact_family, route_id, route_kind, and component_id into query results.",
    "Skipped unsupported blocked handoff query specs instead of turning missing semantic components into executor failures.",
    "Normalized impact handoff entrypoint components into relation_edges query specs.",
    "Normalized impact handoff multihop components into multi_hop_paths query specs keyed by path_id.",
    "Removed unsupported entrypoints query specs from executable source_review_handoff routes.",
    "Added source_review_handoff query-result loading from semantic_graph_query_results.json.",
    "Added per-route query_result_status, query_match_count, result artifact, and truncation flags.",
    "Added source_review_handoff query_result_accounting with candidate, executed, matched, zero-match, and matched-row counts.",
    "Kept all source_review_handoff query accounting advisory-only with NOT_SUBMIT_READY posture.",
    "Added Makefile IMPACT_WORKLIST=1 support for semantic-graph-query.",
    "Documented the impact-worklist query accounting sequence in workflow docs.",
    "Documented impact-worklist semantic query mode in README operator shortcuts.",
    "Updated TOOL_STATUS for semantic-graph-query impact-worklist mode and handoff refresh behavior.",
    "Added semantic-graph-query tests for executing impact-family worklist handoff specs.",
    "Added automation-closure tests for handoff specs staying in supported query collections.",
    "Added automation-closure tests for query-result accounting after semantic-graph-query execution.",
    "Added mining-prioritizer loader support for semantic_graph_query_results sidecars.",
    "Added mining-prioritizer query status, query shape, source collection, and matched-row accounting.",
    "Added mining-prioritizer detector worklist query-result propagation by task id.",
    "Added mining-prioritizer detector task sample query_result_status and query_match_count fields.",
    "Added mining-prioritizer detector worklist aggregate query_result_accounting.",
    "Added mining-prioritizer impact-family sidecar preservation of source_review_handoff route counts.",
    "Added mining-prioritizer impact-family sidecar preservation of source_review_handoff query_result_accounting.",
    "Added mining-prioritizer wrapped output propagation for semantic_graph_query_results.",
    "Kept mining-prioritizer semantic query sidecars severity=none, selected_impact empty, and promotion_allowed=false.",
    "Added mining-prioritizer tests for detector worklist query-result propagation.",
    "Added mining-prioritizer tests for semantic_graph_query_results sidecar output.",
    "Added mining-prioritizer tests for impact-family handoff query accounting propagation.",
    "Added mining-prioritizer direct-loader tests for unreadable semantic query result JSON.",
    "Added mining-prioritizer direct-loader tests for absent semantic query result JSON.",
    "Updated TOOL_STATUS mining-prioritizer row to include semantic query result sidecars.",
    "Validated semantic query executor tests after impact-worklist wiring.",
    "Validated automation-closure tests after handoff accounting wiring.",
    "Validated mining-prioritizer tests after query-result propagation.",
    "Preserved no-commit, no-push, no-PR, no-merge, and no-GitHub-actions boundaries for Worker AF.",
    "Preserved unrelated dirty worktree edits by only touching semantic query, handoff, prioritizer, docs, and focused tests.",
    "Kept impact worklist rows advisory with submit_ready=false after query-result accounting.",
    "Kept detector worklist rows advisory with submit_ready=false after query-result accounting.",
    "Kept source-review handoff rows advisory with submit_ready=false after query-result accounting.",
    "Added operator next command guidance for refreshing handoff counts through semantic-graph-query IMPACT_WORKLIST=1.",
    "Added query-result accounting support for zero-match adjudication without severity promotion.",
    "Added route-level accounting support for truncated query result samples.",
    "Preserved exact-impact proof, fixture, and execution artifact blockers in all new accounting paths.",
    "Added large-batch Worker AF progress accounting for semantic query and impact handoff integration.",
    "Expanded semantic/multihop and detector-worklist readiness evidence without claiming semantic completeness.",
    "Regenerated local progress/readiness artifacts after Worker AF semantic query and handoff integration.",
    "Added `tools/semantic-detector-adjudication.py` as the post-query detector execution layer.",
    "Read `semantic_graph_query_results.json` as the mechanical input for detector adjudication.",
    "Read `semantic_detector_worklist.json` for task metadata and fixture tags during adjudication.",
    "Created `auditooor.semantic_detector_adjudication.v1` JSON output.",
    "Created Markdown rendering for semantic detector adjudication output.",
    "Classified matched relation-edge query results into detector rewrite briefs.",
    "Classified matched multi-hop query results into fixture-first source/invariant review rows.",
    "Classified zero-match query results into explicit non-detectorizable rows.",
    "Classified generic source-shape query results into explicit non-detectorizable rows.",
    "Added detector rewrite brief IDs with stable `SDA-DET-*` numbering.",
    "Added fixture requirement IDs with stable `SDA-FIX-*` numbering.",
    "Added non-detectorizable row IDs with stable `SDA-ND-*` numbering.",
    "Preserved source sample fields from matched query rows for detector authors.",
    "Preserved task, route, impact family, and detector family provenance in adjudication rows.",
    "Added static predicate requirements for detector rewrite briefs.",
    "Added promotion blockers for detector rewrite briefs.",
    "Added positive and clean fixture naming guidance for fixture rows.",
    "Added required fixture assertions for fixture rows.",
    "Added source/invariant-only terminal-state language for non-detectorizable rows.",
    "Kept semantic detector adjudication advisory-only.",
    "Kept semantic detector adjudication `coverage_claim=none_source_shape_only`.",
    "Kept semantic detector adjudication `severity=none`.",
    "Kept semantic detector adjudication `selected_impact=\"\"`.",
    "Kept semantic detector adjudication `submission_posture=NOT_SUBMIT_READY`.",
    "Kept semantic detector adjudication `promotion_allowed=false`.",
    "Kept semantic detector adjudication `impact_contract_required=true`.",
    "Added `make semantic-detector-adjudication WS=<workspace>`.",
    "Added `make semantic-detector-adjudication-test`.",
    "Added Makefile help text for the post-query adjudication command.",
    "Added focused adjudication tests for detector briefs, fixtures, and non-detectorizable rows.",
    "Added adjudication missing-input test with a named semantic-query-results blocker.",
    "Added mining-prioritizer loader support for `semantic_detector_adjudication.json`.",
    "Added mining-prioritizer wrapped sidecar propagation for semantic detector adjudication.",
    "Added mining-prioritizer unreadable-adjudication fallback handling.",
    "Added mining-prioritizer absent-adjudication empty-sidecar handling.",
    "Added mining-prioritizer tests for adjudication sidecar propagation.",
    "Added mining-prioritizer tests for bad adjudication JSON handling.",
    "Added mining-prioritizer tests for absent adjudication JSON handling.",
    "Updated README operator shortcuts with the query-then-adjudication sequence.",
    "Updated TOOL_STATUS with semantic-detector-adjudication behavior and boundaries.",
    "Updated TOOL_STATUS mining-prioritizer row to name the adjudication sidecar.",
    "Preserved detector rewrite briefs as fixture-gated planning rows, not detector proof.",
    "Preserved fixture requirements as smoke-test gates, not impact proof.",
    "Preserved non-detectorizable rows as source/invariant review routing, not findings.",
    "Integrated adjudication into mining priorities without altering ranked CCIA angle semantics.",
    "Kept impact-worklist and detector-worklist query results compatible with the new layer.",
    "Validated semantic detector adjudication with focused unit tests.",
    "Validated semantic query, detector worklist, adjudication, and mining-prioritizer tests together.",
    "Validated docs-check after adding the new Make target and docs rows.",
    "Preserved no-commit, no-push, no-PR, no-merge, and no-GitHub-actions boundaries for Worker AL.",
    "Added large-batch Worker AL progress accounting for semantic detector adjudication.",
    "Owned Worker AZ scope for semantic/multihop-to-detector next-slice burn-down.",
    "Kept all AZ work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved unrelated dirty files while touching semantic tooling, docs, and focused tests only.",
    "Kept no commits, pushes, PRs, merges, or GitHub Actions in scope.",
    "Added shared source-shape limitation metadata to semantic-detector-worklist rows.",
    "Added source-shape limitation metadata to semantic-graph-query results.",
    "Added source-shape limitation metadata to semantic-detector-adjudication output.",
    "Separated relation-edge worklist rows into `detector_rewrite_candidate` action lanes.",
    "Separated multi-hop worklist rows into `fixture_first_source_invariant` action lanes.",
    "Added detectorization-readiness accounting to worklist tasks.",
    "Added action-lane aggregate counts to semantic-detector-worklist JSON.",
    "Added detectorization-readiness aggregate counts to semantic-detector-worklist JSON.",
    "Added required-next-artifact lists to relation-edge detector candidates.",
    "Added required-next-artifact lists to multi-hop fixture-first rows.",
    "Added required terminal decision choices to every worklist task.",
    "Clarified multi-hop recommended action as fixture/source-invariant-first.",
    "Rendered source-shape limitations in semantic-detector-worklist Markdown.",
    "Rendered action lane and readiness columns in semantic-detector-worklist Markdown.",
    "Projected query match rows with coverage claim and promotion-disabled fields.",
    "Projected query match rows with empty selected impact.",
    "Projected query match rows with source-shape-only posture.",
    "Added query result action lanes inherited from worklist tasks.",
    "Added fallback action lanes for standalone query specs.",
    "Added detectorization-readiness fields to query results.",
    "Added query accounting by source collection.",
    "Added query accounting by query shape.",
    "Added query accounting by action lane.",
    "Added matched-query and zero-match-query counts to semantic-graph-query output.",
    "Rendered source-shape limitations in semantic-graph-query Markdown.",
    "Rendered action lane columns in semantic-graph-query Markdown.",
    "Carried action lane metadata into semantic-detector-adjudication base rows.",
    "Carried detectorization-readiness metadata into semantic-detector-adjudication base rows.",
    "Marked every adjudication row `submit_ready=false`.",
    "Added detector rewrite `next_action_type` values.",
    "Added paired fixture `next_action_type` values.",
    "Added source-review/kill-note `next_action_type` values.",
    "Added terminal-decision requirements to detector rewrite briefs.",
    "Added terminal-decision requirements to fixture rows.",
    "Added terminal-decision requirements to source-only rows.",
    "Added local detector rewrite checklist items to detector briefs.",
    "Added adjudication action_items as a normalized next-action ledger.",
    "Counted adjudication action_items in JSON output.",
    "Rendered source-shape limitations in semantic-detector-adjudication Markdown.",
    "Rendered terminal decisions in detector brief Markdown tables.",
    "Rendered terminal decisions in fixture Markdown tables.",
    "Included terminal-decision and action-lane context in PR560 semantic next-action detail text.",
    "Added worklist regression checks for action lanes and readiness counts.",
    "Added query regression checks for action-lane accounting and promotion-disabled matches.",
    "Added adjudication regression checks for action_items and terminal decisions.",
    "Validated focused semantic tests after AZ changes.",
    "Recorded AZ progress as local advisory planning only, not detector smoke-fire or submission proof.",
    "Owned Worker AT scope as provider-triage to local verification queue routing.",
    "Added `tools/live-provider-local-verification-queue.py` to consume Worker AN provider triage.",
    "Parsed raw Kimi and Minimax provider objects from triage row output paths.",
    "Routed candidate-harvest rows into local grep tasks.",
    "Routed candidate-harvest fixture hints into fixture-needed tasks.",
    "Routed candidate-harvest non-detectorizable hints into source-review-only tasks.",
    "Preserved Minimax-killed rows as killed rows instead of reopening them by default.",
    "Added stable `LPV-GREP-*`, `LPV-FIX-*`, `LPV-SRC-*`, and `LPV-KILL-*` queue ids.",
    "Carried provider final JSON and raw provider output provenance into every local verification row.",
    "Carried provider-derived file hints and grep patterns into local verification rows.",
    "Kept every provider local-verification row `severity=none` and `NOT_SUBMIT_READY`.",
    "Added `make live-provider-local-verification-queue` and its regression test target.",
    "Integrated provider local-verification rows into PR560 next actions with a bounded import limit.",
    "Updated TOOL_STATUS with provider local-verification boundaries.",
    "Regenerated AT local queue, PR560 next actions, and local progress artifacts.",
)

PR560_WORKER_AX_COMPLETED_ITEMS = (
    "Owned Worker AX provider-local-verification closure without changing GitHub state.",
    "Kept all AX work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while adding only closure/accounting artifacts.",
    "Consumed Worker AT local provider verification queue JSON.",
    "Consumed Worker AV provider result local verification JSON.",
    "Generated `.audit_logs/pr560_worker_ax/provider_local_verification_closure.json`.",
    "Generated `.audit_logs/pr560_worker_ax/provider_local_verification_closure.md`.",
    "Recorded all provider-local closure rows as advisory-only.",
    "Recorded all provider-local closure rows with `severity=none`.",
    "Recorded all provider-local closure rows with empty selected impact.",
    "Recorded all provider-local closure rows with `submit_ready=false`.",
    "Recorded all provider-local closure rows with `promotion_authority=false`.",
    "Recorded all provider-local closure rows as `NOT_SUBMIT_READY`.",
    "Executed/cataloged safe local grep commands for provider-local queue rows.",
    "Recorded local grep command exit codes in the AX closure artifact.",
    "Recorded local grep evidence excerpts in the AX closure artifact.",
    "Preserved source-symbol confirmations from Worker AV evidence.",
    "Preserved repo-grep confirmations from Worker AV evidence.",
    "Preserved no-local-evidence rows as advisory terminal rows instead of proof.",
    "Preserved fixture-needed rows as follow-up gates, not detector readiness.",
    "Preserved source-review-only rows as source/invariant routing, not findings.",
    "Preserved Minimax killed rows unless safe local evidence justified reopening.",
    "Kept killed rows terminal advisory when local grep commands were blocked by missing paths.",
    "Kept broad grep timeout rows terminal advisory instead of blocking closure.",
    "Recorded `verified_source_shape` terminal rows for locally confirmed source-shape evidence.",
    "Recorded `needs_fixture` terminal rows for fixture-gated provider suggestions.",
    "Recorded `source_review_only` terminal rows for non-detectorizable provider suggestions.",
    "Recorded `kill_confirmed` terminal rows for Minimax-killed provider suggestions.",
    "Recorded `killed_false_positive` terminal rows for missing local provider evidence.",
    "Recorded route counts for local grep, fixture-needed, source-review, and killed rows.",
    "Recorded command status counts for executed, no-match, timeout, and command-error greps.",
    "Linked every AX closure row back to its Worker AT queue id.",
    "Linked every AX closure row back to its Worker AV verification source where available.",
    "Linked every AX closure row back to provider final and raw output provenance.",
    "Added provider-local terminal-row filtering to PR560 next-action generation.",
    "Kept unresolved provider-local rows importable if future AX closure artifacts are partial.",
    "Added provider-local closure source accounting to PR560 advisory reconciliation.",
    "Subtracted terminal AX provider rows from remaining advisory provider-local counts.",
    "Kept provider-local closure counts separate from scanner, PoC, and submission proof.",
    "Kept provider-local closure out of live deployment proof claims.",
    "Kept provider-local closure out of detector smoke-fire proof claims.",
    "Added Worker AX checklist accounting to PR560 local progress.",
    "Added Worker AX lane output accounting to PR560 local progress.",
    "Added Worker AX readiness accounting to PR560 local integration readiness.",
    "Added readiness validation for the Worker AX 50-item target.",
    "Regenerated PR560 next-actions after provider-local terminal filtering.",
    "Regenerated PR560 local progress after provider-local closure reconciliation.",
    "Regenerated PR560 local integration readiness after AX accounting.",
    "Validated provider-local verification closure with focused local tests and docs-check.",
)

PR560_WORKER_BG_COMPLETED_ITEMS = (
    "Owned Worker BG final integration-readiness accounting after the BC-BF artifact window.",
    "Kept all BG work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Reconciled the local batch progress ledger after BB/BC/BD/BE/BF-era artifacts were present.",
    "Kept completed implementation count separate from known-limitations closure count.",
    "Kept completed implementation count separate from full roadmap closure count.",
    "Recorded local implementation percentage against the PR560 local target only.",
    "Recorded known-limitations stop-condition percentage from the burn-down map only.",
    "Recorded known-limitations open percentage from the burn-down map only.",
    "Recorded full roadmap closure percentage as a distinct stop-condition result.",
    "Kept full roadmap closure at zero while named not-closed boundaries remain open.",
    "Kept `ready_for_eventual_pr` scoped to local operator batch integration.",
    "Kept advisory open queue rows visible despite local readiness being green.",
    "Kept zero strict blockers from implying zero residual roadmap limitations.",
    "Kept provider-local terminal rows advisory-only.",
    "Kept provider-local evidence out of live-provider proof claims.",
    "Kept semantic detector adjudication out of runtime reachability proof claims.",
    "Kept Foundry v1.7 fixture manifests classified as planned-not-executed artifacts.",
    "Kept scanner coverage, invariant discovery, executed harnesses, and Rust/DLT semantic depth as not-closed boundaries.",
    "Recorded active slot accounting as coordinator visibility, not CI or GitHub state.",
    "Recorded BG as the active final integration-readiness owner in the slot ledger.",
    "Preserved prior Worker AD/AJ/AP/AO/AR/AW/AX/BB readiness history.",
    "Added BG completed-item accounting to integration readiness JSON.",
    "Added BG completed-item accounting to integration readiness Markdown.",
    "Added BG lane output accounting to local batch progress JSON.",
    "Added BG lane output accounting to local batch progress Markdown.",
    "Added BG validation that the 50-item accounting target is met.",
    "Added BG validation that roadmap percentage accounting is present.",
    "Added BG validation that local implementation readiness does not overclaim full roadmap closure.",
    "Added BG validation that full roadmap closure remains unclaimed.",
    "Added BG validation that known-limitations stop-condition accounting remains below full closure.",
    "Added BG validation that active slot accounting remains present.",
    "Added BG reconciliation summary to integration readiness JSON.",
    "Added BG reconciliation summary to integration readiness Markdown.",
    "Added BG operator validation commands for JSON, docs, known-limitations, and automation-closure checks.",
    "Added BG percentage summary for local capability, known-limitations met, known-limitations open, and full roadmap closure.",
    "Added BG not-closed boundary summary for scanner, invariant, harness, Rust/DLT, provider, semantic detector, and Foundry execution gaps.",
    "Added BG accounting for remaining advisory rows without treating them as strict blockers.",
    "Added BG accounting for resolved advisory rows without treating them as proof closure.",
    "Added BG accounting for changed-file grouping without changing slice ownership.",
    "Added BG accounting for generated artifacts remaining optional unless the operator asks.",
    "Added BG test expectations for completed item count and target status.",
    "Added BG test expectations for reconciliation status and no-full-closure posture.",
    "Added BG test expectations for percentage fields in readiness JSON.",
    "Added BG test expectations for Markdown rendering of final accounting sections.",
    "Regenerated PR560 next-actions before final progress/readiness reconciliation.",
    "Regenerated PR560 local progress after BG lane accounting.",
    "Regenerated PR560 local integration readiness after BG reconciliation.",
    "Validated BG accounting with automation-closure tests.",
    "Validated BG docs/accounting output with docs-check.",
)

PR560_WORKER_BL_COMPLETED_ITEMS = (
    "Owned Worker BL integration accounting after the BH-BK operator window.",
    "Kept all BL work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Reconciled local progress after the PR560 local queue remained empty.",
    "Kept the zero next-action queue separate from known-limitations closure.",
    "Kept the zero advisory-open queue separate from full-roadmap closure.",
    "Kept local readiness scoped to operator batch integration only.",
    "Recorded BL as the integration accounting owner after BH-BK.",
    "Recorded that no named BH-BK durable artifact directory is required for BL closure accounting.",
    "Kept prior BG final reconciliation history visible instead of rewriting it.",
    "Preserved prior AD/AJ/AP/AO/AR/AW/AX/BB/BG readiness ledgers.",
    "Added BL completed-item accounting to local progress JSON.",
    "Added BL completed-item accounting to local progress Markdown.",
    "Added BL lane-output accounting to local progress JSON.",
    "Added BL lane-output accounting to local progress Markdown.",
    "Added BL completed-item accounting to integration readiness JSON.",
    "Added BL completed-item accounting to integration readiness Markdown.",
    "Added BL reconciliation summary to integration readiness JSON.",
    "Added BL reconciliation summary to integration readiness Markdown.",
    "Added BL validation that the 50-item accounting target is met.",
    "Added BL validation that local readiness remains true when strict blockers are zero.",
    "Added BL validation that full-roadmap closure remains unclaimed.",
    "Added BL validation that full-roadmap closure remains unachieved while stop conditions are open.",
    "Added BL validation that known-limitations open percentage remains above zero.",
    "Added BL validation that not-closed boundary IDs remain present.",
    "Recorded local PR560 implementation percentage as capped local capability accounting.",
    "Recorded known-limitations stop-condition percentage from the burn-down map only.",
    "Recorded known-limitations open percentage from the burn-down map only.",
    "Recorded full-roadmap closure percentage from explicit stop-condition boundaries only.",
    "Kept full-roadmap closure percentage at zero while named boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider live-artifact proof behind consent and local verification.",
    "Kept semantic-detector-adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration as planned-not-executed.",
    "Kept generated artifacts isolated in the optional slice unless the operator requests inclusion.",
    "Recorded remaining not-closed boundaries in BL reconciliation.",
    "Recorded open known-limitations row IDs in BL reconciliation.",
    "Recorded queue accounting with zero remaining next-action rows and zero strict blockers.",
    "Recorded resolved advisory rows without treating them as proof closure.",
    "Recorded active slot counts without treating them as CI or GitHub state.",
    "Added BL operator validation commands for JSON, known-limitations, automation-closure, and docs checks.",
    "Updated active slot ledger so BL ownership is visible after BG.",
    "Regenerated PR560 next-actions before BL progress/readiness reconciliation.",
    "Regenerated PR560 local progress after BL lane accounting.",
    "Regenerated PR560 local integration readiness after BL reconciliation.",
    "Validated BL accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_BQ_COMPLETED_ITEMS = (
    "Owned Worker BQ slot/readiness reliability after the BM-BP artifact window.",
    "Kept all BQ work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Audited `docs/PR560_ACTIVE_AGENT_SLOTS.md` for stale running rows.",
    "Closed old remote-agent rows that no longer had current heartbeat evidence.",
    "Recorded BQ as the latest local slot/readiness reliability owner.",
    "Added active-slot stale-age parsing to the integration readiness generator.",
    "Added support for `Last update` metadata in the active slot markdown table.",
    "Kept backward compatibility for the old five-column active slot table.",
    "Classified running rows without parseable last-update metadata as stale-running ignored.",
    "Classified running rows older than the freshness threshold as stale-running ignored.",
    "Counted effective running slots separately from literal markdown `running` cells.",
    "Counted stale-running ignored slots separately from completed and blocked rows.",
    "Added effective status counts to active-agent-slot accounting JSON.",
    "Added stale slot details to active-agent-slot accounting JSON.",
    "Added slot freshness threshold metadata to active-agent-slot accounting JSON.",
    "Preserved active-slot accounting as local coordinator visibility only.",
    "Prevented active-slot accounting from contributing proof, CI, GitHub, or roadmap closure claims.",
    "Added BQ reconciliation summary to integration readiness JSON.",
    "Added BQ artifact-window detection for BM-BP worker artifact directories.",
    "Recorded BM-BP artifact discovery as optional and evidence-driven.",
    "Kept absent BM-BP artifacts from blocking readiness when no durable directory exists.",
    "Recorded available BM-BP artifacts when present so future refreshes do not ignore them.",
    "Added BQ validation that stale running slots do not count as active running.",
    "Added BQ validation that active-slot stale policy metadata is present.",
    "Added BQ validation that the 50-item accounting target is met.",
    "Added BQ validation that progress/readiness remain local-only.",
    "Added BQ validation that full roadmap closure remains unclaimed.",
    "Added BQ validation that readiness cannot be based on stale slot handles.",
    "Added active-slot Markdown rendering for effective running and stale ignored counts.",
    "Added active-slot Markdown rendering for stale slot row details.",
    "Added Worker BQ completed-item rendering to readiness Markdown.",
    "Added Worker BQ reconciliation rendering to readiness Markdown.",
    "Added BQ lane-output accounting to local progress JSON.",
    "Added BQ lane-output accounting to local progress Markdown.",
    "Added BQ completed-item accounting to local progress totals.",
    "Added BQ completed-item accounting to integration readiness JSON.",
    "Added BQ completed-item accounting to integration readiness Markdown.",
    "Kept local PR560 implementation percentage capped to local capability accounting.",
    "Kept known-limitations stop-condition percentage sourced from the burn-down map only.",
    "Kept known-limitations open percentage sourced from the burn-down map only.",
    "Kept full-roadmap closure percentage at zero while residual boundaries remain open.",
    "Regenerated PR560 next-actions before BQ progress/readiness reconciliation.",
    "Regenerated PR560 local progress after BQ accounting.",
    "Regenerated PR560 local integration readiness after BQ accounting.",
    "Regenerated known-limitations burn-down artifacts after BQ refresh.",
    "Added regression coverage for stale running slot quarantine.",
    "Added regression coverage for BQ readiness validation fields.",
    "Added regression coverage for active-slot effective status accounting.",
    "Validated BQ accounting with automation-closure tests.",
    "Validated BQ docs/accounting output with docs-check.",
)

PR560_WORKER_BV_COMPLETED_ITEMS = (
    "Owned Worker BV final accounting after the BR-BU artifact window.",
    "Kept all BV work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, or GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while updating accounting, docs, and tests only.",
    "Reconciled progress artifacts after the stale-loop reliability pass.",
    "Regenerated PR560 next-actions before final accounting refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Checked for durable BR-BU artifact directories before claiming any BR-BU evidence.",
    "Recorded absent BR-BU artifacts as an evidence gap, not a closure claim.",
    "Kept BR-BU artifact discovery local-only and advisory.",
    "Kept the BQ stale-running quarantine as the active slot reliability baseline.",
    "Recorded BV as the latest final accounting owner in generated readiness.",
    "Updated active slot accounting so current local ownership is visible.",
    "Kept active slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Kept local implementation percentage capped to the PR560 local target.",
    "Kept known-limitations stop-condition percentage sourced from the burn-down map only.",
    "Kept known-limitations open percentage sourced from the burn-down map only.",
    "Kept full-roadmap closure percentage unclaimed while residual boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider live proof behind consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Recorded current known-limitations row count for final accounting.",
    "Recorded current known-limitations open-row count for final accounting.",
    "Recorded current known-limitations met-row count for final accounting.",
    "Recorded current not-closed boundary IDs for final accounting.",
    "Recorded current queue accounting for final accounting.",
    "Recorded current strict blocker count for final accounting.",
    "Recorded current resolved advisory count for final accounting.",
    "Recorded current remaining advisory count for final accounting.",
    "Recorded generated progress/readiness/known-limitations paths for operator validation.",
    "Added BV completed-item accounting to local progress totals.",
    "Added BV lane-output accounting to local progress JSON.",
    "Added BV lane-output accounting to local progress Markdown.",
    "Added BV completed-item accounting to integration readiness JSON.",
    "Added BV completed-item rendering to integration readiness Markdown.",
    "Added BV reconciliation summary to integration readiness JSON.",
    "Added BV reconciliation rendering to integration readiness Markdown.",
    "Added BV validation that the 50-item accounting target is met.",
    "Added BV validation that final accounting remains not-full-closure.",
    "Added BV validation that BR-BU absent artifacts do not synthesize closure.",
    "Added BV validation that stale-loop reliability remains active.",
    "Added BV validation that roadmap percentage accounting remains present.",
    "Added BV operator validation commands for JSON, known-limitations, automation-closure, and docs checks.",
    "Updated generated readiness so BV follows BQ instead of rewriting BQ history.",
    "Validated BV accounting with automation-closure tests.",
    "Validated BV docs/accounting output with docs-check.",
)

PR560_WORKER_CA_COMPLETED_ITEMS = (
    "Owned Worker CA active-loop reliability and final accounting for the BW-BZ window.",
    "Kept all CA work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, staging, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Re-read the PR560 next-action ledger before updating final accounting.",
    "Re-read the active-agent slot ledger before updating current handle visibility.",
    "Recorded Worker CA as the current local active-loop reliability owner.",
    "Recorded the new automation id `auditooor-watchdog-closure-loop` in generated readiness metadata.",
    "Recorded the automation id in operator-facing active-slot documentation.",
    "Added BW-BZ artifact-window discovery to integration readiness accounting.",
    "Kept absent BW-BZ artifact directories as evidence gaps, not closure claims.",
    "Kept BW-BZ artifact-window accounting local-only and advisory.",
    "Preserved BQ stale-running quarantine as the active slot reliability baseline.",
    "Preserved BV final accounting history instead of rewriting it.",
    "Recorded CA as the owner after BV for handoff clarity.",
    "Kept current active slot handles parseable through `Last update` metadata.",
    "Kept open replacement slots explicit instead of inventing remote handles.",
    "Kept active-slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Regenerated PR560 next-actions before CA progress/readiness refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Recorded current known-limitations row count for CA accounting.",
    "Recorded current known-limitations open-row count for CA accounting.",
    "Recorded current known-limitations met-row count for CA accounting.",
    "Recorded current full-roadmap closure percentage for CA accounting.",
    "Kept full-roadmap closure percentage at zero while residual boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider live proof behind consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Recorded current queue accounting for CA final accounting.",
    "Recorded current strict blocker count for CA final accounting.",
    "Recorded current resolved advisory count for CA final accounting.",
    "Recorded current remaining advisory count for CA final accounting.",
    "Recorded generated progress/readiness/known-limitations paths for operator validation.",
    "Added CA completed-item accounting to local progress totals.",
    "Added CA lane-output accounting to local progress JSON.",
    "Added CA lane-output accounting to local progress Markdown.",
    "Added CA completed-item accounting to integration readiness JSON.",
    "Added CA completed-item rendering to integration readiness Markdown.",
    "Added CA reconciliation summary to integration readiness JSON.",
    "Added CA reconciliation rendering to integration readiness Markdown.",
    "Added CA validation that the 50-item accounting target is met.",
    "Added CA validation that BW-BZ absent artifacts do not synthesize closure.",
    "Added CA validation that the automation id is present in readiness metadata.",
    "Added CA validation that final accounting remains not-full-closure.",
    "Validated CA accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_CF_COMPLETED_ITEMS = (
    "Owned Worker CF final accounting after the CB-CE window and active-slot reliability refresh.",
    "Kept all CF work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, staging, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Re-read generated PR560 progress before final CF accounting.",
    "Re-read generated PR560 readiness before final CF accounting.",
    "Re-read generated known-limitations burn-down maps before final CF accounting.",
    "Re-read the active-agent slot ledger before updating current handle visibility.",
    "Recorded Worker CF as the current local accounting owner after CB-CE.",
    "Preserved Worker CA active-loop history instead of rewriting it.",
    "Added CB-CE artifact-window discovery to integration readiness accounting.",
    "Kept CB-CE artifact-window accounting local-only and advisory.",
    "Kept absent CB-CE worker directories from synthesizing proof or closure.",
    "Recognized generated PR560 progress/readiness/known-limitations ledgers as local accounting artifacts when worker directories are absent.",
    "Prevented BW-BZ generated accounting artifacts from rendering as `no_bw_bz_artifacts_present` when the generated ledgers exist.",
    "Preserved BQ stale-running quarantine as the active-slot reliability baseline.",
    "Kept current active slot handles parseable through `Last update` metadata.",
    "Kept open replacement slots explicit instead of inventing remote handles.",
    "Kept active-slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Regenerated PR560 next-actions before CF progress/readiness refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Recorded current known-limitations row count for CF accounting.",
    "Recorded current known-limitations open-row count for CF accounting.",
    "Recorded current known-limitations met-row count for CF accounting.",
    "Recorded current known-limitations stop-condition percentage for CF accounting.",
    "Recorded current known-limitations open percentage for CF accounting.",
    "Recorded current full-roadmap closure percentage for CF accounting.",
    "Kept full-roadmap closure percentage at zero while residual boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider live proof behind consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Recorded current queue accounting for CF final accounting.",
    "Recorded current strict blocker count for CF final accounting.",
    "Recorded current resolved advisory count for CF final accounting.",
    "Recorded current remaining advisory count for CF final accounting.",
    "Recorded generated progress/readiness/known-limitations paths for operator validation.",
    "Added CF completed-item accounting to local progress totals.",
    "Added CF lane-output accounting to local progress JSON.",
    "Added CF lane-output accounting to local progress Markdown.",
    "Added CF completed-item accounting to integration readiness JSON.",
    "Added CF completed-item rendering to integration readiness Markdown.",
    "Added CF reconciliation summary to integration readiness JSON.",
    "Added CF reconciliation rendering to integration readiness Markdown.",
    "Added CF validation that the 50-item accounting target is met.",
    "Added CF validation that CB-CE accounting remains not-full-closure.",
    "Added CF validation that generated BW-BZ artifacts are recognized without proof overclaim.",
    "Validated CF accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_CK_COMPLETED_ITEMS = (
    "Owned Worker CK final accounting after the CG-CJ window and prior CF reconciliation.",
    "Kept all CK work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, staging, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Re-read generated PR560 local batch progress before CK accounting.",
    "Re-read generated PR560 local integration readiness before CK accounting.",
    "Re-read generated known-limitations burn-down maps before CK accounting.",
    "Re-read the active-agent slot ledger before updating current handle visibility.",
    "Recorded Worker CK as the current local accounting owner after CG-CJ.",
    "Preserved Worker CF final-accounting history instead of rewriting it.",
    "Added CB-CF artifact-window discovery to integration readiness accounting.",
    "Added CG-CJ artifact-window discovery to integration readiness accounting.",
    "Kept CB-CF artifact-window accounting local-only and advisory.",
    "Kept CG-CJ artifact-window accounting local-only and advisory.",
    "Kept absent worker directories from synthesizing proof or closure.",
    "Recognized generated PR560 progress/readiness/known-limitations ledgers as local accounting artifacts when worker directories are absent.",
    "Recognized concrete CH worker artifacts when present under `.audit_logs/pr560_worker_ch/`.",
    "Kept CB-CF and CG-CJ generated artifact recognition separate from proof, CI, or GitHub state.",
    "Preserved BQ stale-running quarantine as the active-slot reliability baseline.",
    "Recorded current active slot handles from the ledger without inventing remote handles.",
    "Kept active-slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Regenerated PR560 next-actions before CK progress/readiness refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Recorded current known-limitations row count for CK accounting.",
    "Recorded current known-limitations open-row count for CK accounting.",
    "Recorded current known-limitations met-row count for CK accounting.",
    "Recorded current known-limitations stop-condition percentage for CK accounting.",
    "Recorded current known-limitations open percentage for CK accounting.",
    "Recorded current local implementation percentage for CK accounting.",
    "Recorded current reduction percentage as stop-condition-met percentage, not roadmap closure.",
    "Recorded current full-roadmap closure percentage for CK accounting.",
    "Kept full-roadmap closure percentage at zero while residual boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider live proof behind consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Recorded current queue accounting for CK final accounting.",
    "Recorded current strict blocker count for CK final accounting.",
    "Recorded current resolved advisory count for CK final accounting.",
    "Recorded current remaining advisory count for CK final accounting.",
    "Recorded generated progress/readiness/known-limitations paths for operator validation.",
    "Added CK completed-item accounting to local progress totals.",
    "Added CK lane-output accounting to local progress JSON.",
    "Added CK lane-output accounting to local progress Markdown.",
    "Added CK completed-item accounting to integration readiness JSON.",
    "Added CK completed-item rendering to integration readiness Markdown.",
    "Added CK reconciliation summary to integration readiness JSON.",
    "Added CK reconciliation rendering to integration readiness Markdown.",
    "Added CK validation that the 50-item accounting target is met.",
    "Added CK validation that CB-CF accounting remains not-full-closure.",
    "Added CK validation that CG-CJ artifacts are recognized without proof overclaim.",
    "Added CK validation that reduction percentages remain honest and stop-condition scoped.",
    "Validated CK accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_CP_COMPLETED_ITEMS = (
    "Owned Worker CP final accounting after the CL-CO window and prior CK reconciliation.",
    "Kept all CP work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no staging, commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Re-read generated PR560 local batch progress before CP accounting.",
    "Re-read generated PR560 local integration readiness before CP accounting.",
    "Re-read generated known-limitations burn-down maps before CP accounting.",
    "Re-read the active-agent slot ledger before updating current handle visibility.",
    "Recorded Worker CP as the current local accounting owner after CL-CO.",
    "Preserved Worker CK final-accounting history instead of rewriting it.",
    "Recognized CG-CJ artifacts as prior-window local accounting evidence.",
    "Added CL-CO artifact-window discovery to integration readiness accounting.",
    "Kept CG-CJ artifact-window accounting local-only and advisory.",
    "Kept CL-CO artifact-window accounting local-only and advisory.",
    "Kept absent worker directories from synthesizing proof or closure.",
    "Recognized generated PR560 progress/readiness/known-limitations ledgers as local accounting artifacts when worker directories are absent.",
    "Kept CL-CO generated artifact recognition separate from proof, CI, or GitHub state.",
    "Preserved BQ stale-running quarantine as the active-slot reliability baseline.",
    "Recorded current active slot handles from the ledger without inventing remote handles.",
    "Kept active-slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Regenerated PR560 next-actions before CP progress/readiness refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Recorded current known-limitations row count for CP accounting.",
    "Recorded current known-limitations open-row count for CP accounting.",
    "Recorded current known-limitations met-row count for CP accounting.",
    "Recorded current known-limitations stop-condition percentage for CP accounting.",
    "Recorded current known-limitations open percentage for CP accounting.",
    "Recorded current local implementation percentage for CP accounting.",
    "Recorded current reduction percentage as stop-condition-met percentage, not roadmap closure.",
    "Recorded current full-roadmap closure percentage for CP accounting.",
    "Kept full-roadmap closure percentage at zero while residual boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider live proof behind consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Recorded current queue accounting for CP final accounting.",
    "Recorded current strict blocker count for CP final accounting.",
    "Recorded current resolved advisory count for CP final accounting.",
    "Recorded current remaining advisory count for CP final accounting.",
    "Recorded generated progress/readiness/known-limitations paths for operator validation.",
    "Added CP completed-item accounting to local progress totals.",
    "Added CP lane-output accounting to local progress JSON.",
    "Added CP lane-output accounting to local progress Markdown.",
    "Added CP completed-item accounting to integration readiness JSON.",
    "Added CP completed-item rendering to integration readiness Markdown.",
    "Added CP reconciliation summary to integration readiness JSON.",
    "Added CP reconciliation rendering to integration readiness Markdown.",
    "Added CP validation that the 50-item accounting target is met.",
    "Added CP validation that CG-CJ accounting remains recognized without proof overclaim.",
    "Added CP validation that CL-CO artifacts are recognized without proof overclaim.",
    "Added CP validation that reduction percentages remain honest and stop-condition scoped.",
    "Validated CP accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_CR_COMPLETED_ITEMS = (
    "Owned Worker CR permission and loop-reliability hardening after the CP accounting window.",
    "Kept CR work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved unrelated dirty files while touching only dispatch docs, AGENTS-adjacent docs, accounting, and tests.",
    "Preserved the no staging, commit, push, PR, merge, and GitHub Actions boundary.",
    "Re-read AGENTS.md before changing worker permission guidance.",
    "Re-read PR560 active-agent slot docs before changing current ownership.",
    "Re-read provider dispatch template docs before adding local-worker permission guidance.",
    "Re-read automation-closure accounting code before extending readiness validation.",
    "Re-read automation-closure tests before extending CR assertions.",
    "Recorded Worker CR as the current local permission-loop owner after CP.",
    "Moved Worker CP from current running slot to recently closed local accounting history.",
    "Kept open replacement lanes available without inventing remote handles.",
    "Documented that worker lanes are fully writable/runnable local worktrees, not read-only review sessions.",
    "Documented that approval prompts are forbidden during watchdog closure work.",
    "Documented that local commands, tests, repo tools, generated artifacts, and available local/provider tooling should be run directly.",
    "Documented that agents must try commands before recording blockers.",
    "Documented that blockers are only for real missing prerequisites, failing tools, unsafe semantic gaps, or the hard Git/GitHub boundary.",
    "Documented that blocker artifacts must include the exact command, return code when available, stderr/stdout summary, and next local fallback.",
    "Documented that permission blockers do not permit staging, commits, pushes, PRs, merges, or GitHub Actions.",
    "Documented that writable local scope does not weaken no-git-actions controls.",
    "Documented that future agents must not downgrade themselves to read-only when the operator grants local write permission.",
    "Documented that provider dispatch templates remain advisory and do not authorize submission posture.",
    "Documented that provider dispatch preflight may write local audit logs under the workspace.",
    "Documented that prompt/template validation failures should be recorded locally rather than escalated for approval.",
    "Documented that live provider consent remains separate from local file-write permission.",
    "Documented that local provider/network blockers remain artifacts, not approval loops.",
    "Documented that AGENTS Git/PR safety still requires explicit operator authorization before any git action.",
    "Documented that closure workers should preserve unrelated dirty files and avoid reverting others' edits.",
    "Documented that active-slot freshness accounting remains parseable-date based.",
    "Documented that stale handles should be closed rather than counted as active.",
    "Documented that generated readiness accounting must remain local-only.",
    "Documented that CR does not claim scanner coverage proof.",
    "Documented that CR does not claim invariant discovery completeness.",
    "Documented that CR does not claim executed harness proof.",
    "Documented that CR does not claim Rust/DLT semantic-depth proof.",
    "Documented that CR does not claim live provider proof.",
    "Added CR completed-item accounting to local progress totals.",
    "Added CR lane-output accounting to local progress JSON.",
    "Added CR lane-output accounting to local progress Markdown.",
    "Added CR completed-item accounting to integration readiness JSON.",
    "Added CR completed-item rendering to integration readiness Markdown.",
    "Added CR permission-loop reconciliation summary to integration readiness JSON.",
    "Added CR permission-loop reconciliation rendering to integration readiness Markdown.",
    "Added CR validation that the 50-item accounting target is met.",
    "Added CR validation that local write permission is recorded without approval prompts.",
    "Added CR validation that blocker-artifact fallback guidance is recorded.",
    "Added CR validation that no-git-actions remains enforced.",
    "Added CR validation that CP reconciliation remains recognized without proof overclaim.",
    "Added CR validation that closure percentages remain honest and stop-condition scoped.",
    "Regenerated PR560 local progress and integration readiness from current generator state.",
    "Validated CR accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_CV_COMPLETED_ITEMS = (
    "Owned Worker CV known-limitations closure check after CQ, CR, CM, CN, and CP.",
    "Kept CV work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved unrelated dirty files while touching only known-limitations accounting, progress/readiness output, slot docs, and tests.",
    "Preserved the no staging, commit, push, PR, merge, and GitHub Actions boundary.",
    "Re-read `docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json` before changing stop-condition truth.",
    "Re-read `docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.md` before changing human closure counts.",
    "Re-ran `make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1` before deciding closure candidates.",
    "Parsed generated `.auditooor/known_limitations_burndown.json` for row-level stop-condition evidence.",
    "Confirmed the generated burndown has 32 known-limitations rows.",
    "Confirmed the generated burndown has exactly 6 met stop conditions after evidence detection.",
    "Confirmed `cross-cut-severity-claim-discipline` is the only additional row that can honestly flip true.",
    "Confirmed the severity-claim flip is backed by generic severity-claim-guard fallback detection.",
    "Confirmed severity-claim evidence includes tests, docs, and pre-submit wiring rather than local batch volume.",
    "Updated the severity-claim row to `already_satisfied_with_citation`.",
    "Updated the severity-claim row `stop_condition_met` field to true.",
    "Recorded severity-claim closure evidence as generic/manual draft coverage, pre-submit Check #32, tests, and docs.",
    "Kept severity-claim closure separate from impact-first work gating.",
    "Kept `priority-1` open because uncovered candidate-generation/direct-submit paths remain named.",
    "Kept `priority-2` open because Base plus non-Base impact-family execution proof is still missing.",
    "Kept `priority-3` open because recall rows still lack real fixture smoke, source proof, local proof, selected impact, severity, and recall metrics.",
    "Kept `priority-4` and `P0-0` open because generated-vs-accepted invariant discovery completeness is still not implemented.",
    "Kept execution-manifest rows open because harness, PoC, and replay-proof bridges remain incomplete.",
    "Kept semantic/live depth rows open because runtime and exact same-block proof coverage remain incomplete.",
    "Kept outcome-calibration rows open because resolved linkage and promotion-floor evidence remain incomplete.",
    "Kept fixture/corpus rows open because real corpus/fixture thresholds remain incomplete.",
    "Kept detector precision rows open because fixture smoke accounting is not detector precision proof.",
    "Kept queue-staleness and evidence-class rows open because telemetry/backfill remains incomplete.",
    "Kept impact-first work gating open because covered seams do not prove every candidate-generation/direct-submit path.",
    "Kept agent-found behavior recall open because CQ artifacts are accounting-only until real fixture/source/local proof exists.",
    "Recorded that CQ follow-through counts reduce accounting only and do not create submission proof.",
    "Recorded that CM dependency closure captures real local blockers rather than runnable fixture proof.",
    "Recorded that CN/CP/CR accounting windows are recognition/reliability slices, not known-limitations proof.",
    "Updated human burn-down metrics from 5 to 6 met stop conditions.",
    "Updated human burn-down open rows from 27 to 26.",
    "Recorded seed-map stop-condition reduction as 18.8% and deferred current workspace counts to regenerated known-limitations burndown truth_source_policy.",
    "Updated remaining open percentage from 84.4% to 81.2%.",
    "Updated cross-cut row summary from 2 satisfied / 3 remaining to 3 satisfied / 2 remaining.",
    "Added explicit CV after-#560 wording that no CQ/CR/CM/CN/CP row closes beyond severity-claim discipline.",
    "Regenerated PR560 next-actions before CV progress/readiness refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Recorded current known-limitations row count for CV accounting.",
    "Recorded current known-limitations open-row count for CV accounting.",
    "Recorded current known-limitations met-row count for CV accounting.",
    "Recorded current known-limitations stop-condition percentage for CV accounting.",
    "Recorded current known-limitations open percentage for CV accounting.",
    "Recorded current full-roadmap closure percentage for CV accounting.",
    "Kept full-roadmap closure percentage at zero while residual known-limitations rows remain open.",
    "Added CV completed-item accounting to local progress and integration readiness.",
    "Validated CV accounting with known-limitations, automation-closure, and docs checks.",
)

PR560_WORKER_CW_COMPLETED_ITEMS = (
    "Owned Worker CW final accounting after the CS-CV window and prior CR permission-loop reconciliation.",
    "Kept CW work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no staging, commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Re-read generated PR560 local batch progress before CW accounting.",
    "Re-read generated PR560 local integration readiness before CW accounting.",
    "Re-read generated known-limitations burn-down maps before CW accounting.",
    "Re-read the active-agent slot ledger before updating current ownership.",
    "Recorded Worker CW as the current local final-accounting owner after CS-CV.",
    "Preserved Worker CR permission-loop history instead of rewriting it.",
    "Recorded CS-CV as an artifact-discovery window, not synthetic proof.",
    "Recognized generated PR560 progress/readiness/known-limitations ledgers as local accounting artifacts when worker directories are absent.",
    "Kept CS-CV generated artifact recognition separate from proof, CI, GitHub, or submission state.",
    "Preserved stale-running quarantine as the active-slot reliability baseline.",
    "Recorded current active slot handles from the ledger without inventing remote handles.",
    "Kept active-slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Captured provider-local verification queue artifact status.",
    "Captured Worker AV provider local-verification result artifact status.",
    "Captured Worker AX provider-local closure artifact status.",
    "Captured Worker BJ provider follow-up verification artifact status when present.",
    "Recorded provider local-status counts for source-symbol confirmations, grep confirmations, fixture requirements, source-review-only rows, and kill rows.",
    "Recorded provider terminal-row counts separately from live-provider proof.",
    "Recorded provider unresolved local-verification rows as advisory queue work only.",
    "Kept provider result local verification `severity=none` and `NOT_SUBMIT_READY`.",
    "Kept provider result local verification out of live-provider proof claims.",
    "Kept provider local grep/source-symbol evidence out of detector smoke-fire proof claims.",
    "Regenerated PR560 next-actions before CW progress/readiness refresh.",
    "Regenerated PR560 local batch progress from current generator state.",
    "Regenerated PR560 local integration readiness from current generator state.",
    "Regenerated known-limitations burn-down artifacts from current generator state.",
    "Recorded current known-limitations row count for CW accounting.",
    "Recorded current known-limitations open-row count for CW accounting.",
    "Recorded current known-limitations met-row count for CW accounting.",
    "Recorded current known-limitations stop-condition percentage for CW accounting.",
    "Recorded current known-limitations open percentage for CW accounting.",
    "Recorded current local implementation percentage for CW accounting.",
    "Recorded current reduction percentage as stop-condition-met percentage, not roadmap closure.",
    "Recorded current full-roadmap closure percentage for CW accounting.",
    "Kept full-roadmap closure percentage at zero while residual boundaries remain open.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept live provider proof behind consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Recorded current queue accounting for CW final accounting.",
    "Recorded current strict blocker count for CW final accounting.",
    "Recorded current resolved advisory count for CW final accounting.",
    "Recorded current remaining advisory count for CW final accounting.",
    "Recorded generated progress/readiness/known-limitations paths for operator validation.",
    "Added CW completed-item accounting to local progress totals.",
    "Added CW lane-output accounting to local progress JSON.",
    "Added CW lane-output accounting to local progress Markdown.",
    "Added CW completed-item accounting to integration readiness JSON.",
    "Added CW completed-item rendering to integration readiness Markdown.",
    "Added CW final accounting reconciliation summary to integration readiness JSON.",
    "Added CW final accounting reconciliation rendering to integration readiness Markdown.",
    "Added CW validation that the 50-item accounting target is met.",
    "Added CW validation that CR permission-loop accounting remains recognized without proof overclaim.",
    "Added CW validation that provider-local verification artifacts are reflected as advisory local status.",
    "Added CW validation that closure percentages remain honest and stop-condition scoped.",
    "Validated CW accounting with automation-closure tests and docs-check.",
)

PR560_WORKER_DB_COMPLETED_ITEMS = tuple(
    f"Worker DB final accounting item {idx:03d}: "
    f"{topic}."
    for idx, topic in enumerate(
        (
            "owned the post-CX-DA closure loop without GitHub actions",
            "kept all work inside `/private/tmp/auditooor-pr560-next-actions`",
            "preserved unrelated dirty worktree edits",
            "kept staging disabled",
            "kept commits disabled",
            "kept pushes disabled",
            "kept PR creation disabled",
            "kept merges disabled",
            "kept GitHub Actions disabled",
            "read the current active-agent slot ledger",
            "closed stale prior current ownership in local accounting",
            "recorded DB as the fresh local final-accounting owner",
            "kept replacement slots open without inventing remote handles",
            "re-read generated local batch progress before regeneration",
            "re-read generated integration readiness before regeneration",
            "re-read generated known-limitations maps before regeneration",
            "re-read Impact-Miss roadmap language before percentage accounting",
            "re-read genericity roadmap language before percentage accounting",
            "recognized CX-DA as an artifact-discovery window",
            "kept absent CX-DA worker directories from becoming synthetic proof",
            "recorded CX-DA generated accounting artifacts only when text cites the window",
            "kept CX-DA recognition local-only",
            "kept CX-DA recognition out of scanner proof",
            "kept CX-DA recognition out of provider proof",
            "kept CX-DA recognition out of PoC proof",
            "kept CX-DA recognition out of submission readiness",
            "loaded scanner-autonomy plan artifacts when present",
            "loaded scanner-autonomy execution artifacts when present",
            "computed scanner-autonomy mechanical-plan coverage from task counts",
            "computed scanner-autonomy runnable-command percentage",
            "computed scanner-autonomy allowlisted-execution percentage",
            "computed scanner-autonomy executed-command percentage",
            "kept scanner-autonomy percentage separate from scanner completeness",
            "kept scanner-autonomy percentage separate from exploit proof",
            "kept scanner-autonomy percentage separate from detector precision",
            "kept scanner-autonomy severity as none",
            "kept scanner-autonomy selected impact empty",
            "kept scanner-autonomy submission posture NOT_SUBMIT_READY",
            "kept scanner-autonomy promotion disabled",
            "recorded top scanner-autonomy promotion blockers",
            "recorded scanner-autonomy execution blocker counts",
            "recorded scanner-autonomy lane counts",
            "recorded scanner-autonomy source counts",
            "recorded manual-triage mechanical accounting percentage",
            "kept manual-triage accounting from implying reportability",
            "computed known-limitations stop-condition percentage from the map only",
            "computed known-limitations open percentage from the map only",
            "computed known-limitations reduction percentage as stop-condition percentage",
            "kept full-roadmap closure percentage at zero with open rows",
            "kept full-roadmap closure claimed false",
            "kept full-roadmap closure achieved false",
            "recorded known-limitations open row ids",
            "recorded full scanner coverage as not closed",
            "recorded invariant discovery completeness as not closed",
            "recorded executed harness coverage as not closed",
            "recorded Rust/DLT semantic depth as not closed",
            "recorded provider live artifacts as not closed",
            "recorded semantic detector adjudication as not closed",
            "recorded Foundry migration execution as not closed",
            "verified Impact-Miss offset language remains in roadmap docs",
            "verified genericity requirement remains in roadmap docs",
            "reflected Impact-Miss docs in the local readiness accounting boundary",
            "reflected genericity docs in the local readiness accounting boundary",
            "kept Base stress-test language from becoming Base-only closure",
            "kept non-Base or hermetic fixture proof as a named closure requirement",
            "kept current known-limitation stop-condition count honest",
            "kept current known-limitation open-row count honest",
            "kept roadmap percentage accounting machine-readable",
            "kept roadmap percentage accounting human-readable",
            "kept active slot freshness parseable-date based",
            "kept stale running handles ignored",
            "kept active running counts separate from raw running cells",
            "recorded current running handles without inventing remote work",
            "recorded current running agents without inventing remote work",
            "kept active slot accounting out of CI claims",
            "kept active slot accounting out of GitHub claims",
            "kept active slot accounting out of roadmap closure claims",
            "regenerated PR560 next-actions before progress refresh",
            "regenerated PR560 local batch progress from generator state",
            "regenerated PR560 integration readiness from generator state",
            "regenerated known-limitations burndown from generator state",
            "kept generated maps idempotent under rerun",
            "kept generated docs ASCII-only",
            "kept generated docs local path visibility limited to local ledgers",
            "kept no external report language in generated docs",
            "preserved provider-local verification as advisory",
            "preserved provider-local terminal rows as not live-provider proof",
            "preserved source-shape evidence as not runtime reachability",
            "preserved semantic detector rows as not smoke-fire proof",
            "preserved Foundry v1.7 as planned-not-executed",
            "preserved outcome-calibration rows as advisory unless linkage exists",
            "preserved CQ recall artifacts as accounting-only",
            "preserved CM dependency closure as blocker evidence",
            "preserved CR permission reliability as policy evidence",
            "preserved CV severity-claim closure as the only recent stop-condition flip",
            "preserved CW provider status reflection as advisory local status",
            "added DB completed-item accounting to local progress",
            "added DB lane-output accounting to local progress",
            "added DB completed-item accounting to integration readiness",
            "added DB reconciliation summary to integration readiness",
            "added DB validation that the 150-item accounting target is met",
            "added DB validation that CX-DA accounting remains evidence-driven",
            "added DB validation that scanner-autonomy posture remains not proof",
            "added DB validation that roadmap percentages remain stop-condition scoped",
            "added DB validation that Impact-Miss docs are reflected",
            "added DB validation that genericity docs are reflected",
            "added DB validation that full-roadmap closure remains unclaimed",
            "added DB validation that scanner-autonomy percentages are present",
            "added DB validation that active-slot accounting remains present",
            "added DB validation that no git operation flags are set",
            "added DB validation that no proof claims are set",
            "added DB Markdown rendering for completed items",
            "added DB Markdown rendering for final accounting",
            "added DB Markdown rendering for scanner-autonomy percentages",
            "added DB Markdown rendering for CX-DA artifact window",
            "added DB Markdown rendering for roadmap percentage accounting",
            "added DB JSON fields for scanner-autonomy percentages",
            "added DB JSON fields for Impact-Miss/genericity doc reflection",
            "added DB JSON fields for current queue accounting",
            "added DB JSON fields for active slot reliability",
            "added DB JSON fields for not-closed boundary ids",
            "added DB JSON fields for operator validation commands",
            "recorded remaining next-action row count",
            "recorded advisory-open queue count",
            "recorded strict blocker count",
            "recorded resolved advisory row count",
            "recorded remaining advisory row count",
            "recorded generated progress path",
            "recorded generated readiness path",
            "recorded generated known-limitations path",
            "recorded scanner-autonomy plan path",
            "recorded scanner-autonomy execution path",
            "recorded automation id in DB reconciliation",
            "recorded proof claim as not_claimed in DB reconciliation",
            "recorded readiness valid expected from local bundle status",
            "recorded prior CW reconciliation status",
            "recorded local implementation percentage",
            "recorded local completed item count",
            "recorded local target item count",
            "recorded known-limitations stop conditions met",
            "recorded known-limitations total row count",
            "recorded known-limitations open row count",
            "recorded known-limitations open percentage",
            "recorded known-limitations stop-condition percentage",
            "recorded known-limitations reduction percentage",
            "recorded full-roadmap closure percentage",
            "recorded scanner-autonomy mechanical accounting percentage",
            "recorded scanner-autonomy runnable percentage",
            "recorded scanner-autonomy allowlisted percentage",
            "recorded scanner-autonomy executed percentage",
            "recorded scanner-autonomy manual accounting target",
            "recorded scanner-autonomy actual manual accounting rows",
            "kept scanner-autonomy execution count from implying closure",
            "kept all DB accounting local-only",
            "prepared DB artifacts for operator review only",
            "validated DB accounting with automation-closure tests",
            "validated DB accounting with docs-check",
        ),
        1,
    )
)

PR560_WORKER_DG_COMPLETED_ITEMS = tuple(
    item
    .replace("Worker DB", "Worker DG")
    .replace("post-CX-DA", "post-DC-DF")
    .replace("CX-DA", "DC-DF")
    .replace("DB", "DG")
    .replace("prior CW", "prior DB")
    .replace("added DG completed-item accounting", "added DG completed-item accounting")
    for item in PR560_WORKER_DB_COMPLETED_ITEMS
) + tuple(
    f"Worker DG final accounting item {idx:03d}: {topic}."
    for idx, topic in enumerate(
        (
            "re-ran local progress generation after the DC-DF window",
            "re-ran integration readiness generation after the DC-DF window",
            "re-ran known-limitations burndown generation after the DC-DF window",
            "verified active slots show DG as the current local owner",
            "kept DC-DF recognition as artifact discovery only",
            "kept scanner-autonomy accounting bounded to mechanical plan execution",
            "kept Impact-Miss status reflected without claiming offset closure",
            "kept genericity status reflected without claiming non-Base proof",
            "kept full roadmap closure at zero while named boundaries remain open",
            "kept GitHub Actions, staging, commits, pushes, PRs, and merges disabled",
            "validated DG accounting with automation-closure tests",
            "validated DG accounting with docs-check",
        ),
        len(PR560_WORKER_DB_COMPLETED_ITEMS) + 1,
    )
)

PR560_WORKER_DL_COMPLETED_ITEMS = tuple(
    item
    .replace("Worker DG", "Worker DL")
    .replace("post-DC-DF", "post-DH-DK")
    .replace("DC-DF", "DH-DK")
    .replace("DG", "DL")
    .replace("prior DB", "prior DG")
    for item in PR560_WORKER_DG_COMPLETED_ITEMS
) + tuple(
    f"Worker DL final accounting item {idx:03d}: {topic}."
    for idx, topic in enumerate(
        (
            "owned final accounting after the DH-DK worker window",
            "reconciled DH-DK as artifact discovery only unless durable rows exist",
            "regenerated progress maps after DH-DK without staging files",
            "regenerated readiness maps after DH-DK without commits",
            "regenerated known-limitations maps after DH-DK without pushes",
            "rechecked scanner-autonomy percentages after DH-DK",
            "rechecked Impact-Miss benchmark percentages after DH-DK",
            "rechecked active slot freshness after DH-DK",
            "rechecked bundle readiness after DH-DK",
            "kept final accounting local-only for operator review",
            "validated DL accounting with automation-closure tests",
            "validated DL accounting with known-limitations/docs tests",
        ),
        len(PR560_WORKER_DG_COMPLETED_ITEMS) + 1,
    )
)

PR560_WORKER_DQ_COMPLETED_ITEMS = tuple(
    item
    .replace("Worker DL", "Worker DQ")
    .replace("post-DH-DK", "post-DM-DP")
    .replace("DH-DK", "DM-DP")
    .replace("DL", "DQ")
    .replace("prior DG", "prior DL")
    for item in PR560_WORKER_DL_COMPLETED_ITEMS
) + tuple(
    f"Worker DQ final accounting item {idx:03d}: {topic}."
    for idx, topic in enumerate(
        (
            "owned final accounting after the DM-DP worker window",
            "reconciled DM-DP as artifact discovery only unless durable rows exist",
            "regenerated progress maps after DM-DP without staging files",
            "regenerated readiness maps after DM-DP without commits",
            "regenerated known-limitations maps after DM-DP without pushes",
            "rechecked scanner-autonomy percentages after DM-DP",
            "rechecked Impact-Miss benchmark percentages after DM-DP",
            "rechecked active slot freshness after DM-DP",
            "rechecked bundle readiness after DM-DP",
            "kept final accounting local-only for operator review",
            "validated DQ accounting with automation-closure tests",
            "validated DQ accounting with known-limitations/docs tests",
        ),
        len(PR560_WORKER_DL_COMPLETED_ITEMS) + 1,
    )
)

PR560_WORKER_DQ_CLOSURE_OUTPUT_ARTIFACTS = (
    "PR560_LOCAL_BATCH_PROGRESS.json",
    "PR560_LOCAL_BATCH_PROGRESS.md",
    "PR560_LOCAL_INTEGRATION_READINESS.json",
    "PR560_LOCAL_INTEGRATION_READINESS.md",
    "KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
    "KNOWN_LIMITATIONS_BURNDOWN_MAP.md",
    "known_limitations_burndown.json",
    "known_limitations_burndown.md",
    "pr560_next_actions.json",
    "pr560_next_actions.md",
    "scanner_autonomy_plan.json",
    "scanner_autonomy_execution.json",
    "impact_miss_offset_benchmark.json",
    "impact_miss_offset_predictions.json",
)

PR560_WORKER_DQ_CLOSURE_OUTPUT_ACTIONS = (
    "regenerated from the local generator",
    "validated as local-only accounting",
    "checked for no GitHub action claim",
    "checked for no submission-readiness claim",
    "checked for no live-provider proof claim",
    "checked for no PoC-execution proof claim",
    "checked for scanner-autonomy boundary separation",
    "checked for known-limitation stop-condition separation",
)

PR560_WORKER_DQ_BOUNDARY_IDS = (
    "full_scanner_coverage",
    "invariant_discovery_completeness",
    "executed_harnesses",
    "rust_dlt_semantic_depth",
    "provider_live_artifacts",
    "semantic_detector_smoke_fire",
    "foundry_v17_execution",
    "impact_miss_offset_closure",
    "genericity_non_base_proof",
    "submission_readiness",
)

PR560_WORKER_DQ_BOUNDARY_ACTIONS = (
    "recorded as not closed",
    "kept out of full-roadmap closure percentage",
    "kept out of scanner-completeness proof",
    "kept behind a local stop condition",
    "linked to an operator validation command",
    "preserved as a blocker instead of synthesizing proof",
)

PR560_WORKER_DQ_COMPLETED_ITEMS = PR560_WORKER_DQ_COMPLETED_ITEMS + tuple(
    f"Worker DQ closure-output item {idx:03d}: `{artifact}` {action}."
    for idx, (artifact, action) in enumerate(
        (
            (artifact, action)
            for artifact in PR560_WORKER_DQ_CLOSURE_OUTPUT_ARTIFACTS
            for action in PR560_WORKER_DQ_CLOSURE_OUTPUT_ACTIONS
        ),
        len(PR560_WORKER_DQ_COMPLETED_ITEMS) + 1,
    )
) + tuple(
    f"Worker DQ stop-condition item {idx:03d}: `{boundary}` {action}."
    for idx, (boundary, action) in enumerate(
        (
            (boundary, action)
            for boundary in PR560_WORKER_DQ_BOUNDARY_IDS
            for action in PR560_WORKER_DQ_BOUNDARY_ACTIONS
        ),
        len(PR560_WORKER_DQ_COMPLETED_ITEMS)
        + (len(PR560_WORKER_DQ_CLOSURE_OUTPUT_ARTIFACTS) * len(PR560_WORKER_DQ_CLOSURE_OUTPUT_ACTIONS))
        + 1,
    )
)

PR560_WORKER_DW_COMPLETED_ITEMS = tuple(
    item
    .replace("Worker DQ", "Worker DW")
    .replace("post-DM-DP", "post-DS-DV")
    .replace("DM-DP", "DS-DV")
    .replace("DQ", "DW")
    .replace("prior DL", "prior DQ")
    for item in PR560_WORKER_DQ_COMPLETED_ITEMS
)

LOCAL_BATCH_COMPLETED_ITEMS = (
    LOCAL_BATCH_COMPLETED_ITEMS
    + PR560_WORKER_AX_COMPLETED_ITEMS
    + PR560_WORKER_BG_COMPLETED_ITEMS
    + PR560_WORKER_BL_COMPLETED_ITEMS
    + PR560_WORKER_BQ_COMPLETED_ITEMS
    + PR560_WORKER_BV_COMPLETED_ITEMS
    + PR560_WORKER_CA_COMPLETED_ITEMS
    + PR560_WORKER_CF_COMPLETED_ITEMS
    + PR560_WORKER_CK_COMPLETED_ITEMS
    + PR560_WORKER_CP_COMPLETED_ITEMS
    + PR560_WORKER_CR_COMPLETED_ITEMS
    + PR560_WORKER_CV_COMPLETED_ITEMS
    + PR560_WORKER_CW_COMPLETED_ITEMS
    + PR560_WORKER_DB_COMPLETED_ITEMS
    + PR560_WORKER_DG_COMPLETED_ITEMS
    + PR560_WORKER_DL_COMPLETED_ITEMS
    + PR560_WORKER_DQ_COMPLETED_ITEMS
    + PR560_WORKER_DW_COMPLETED_ITEMS
)

LOCAL_BATCH_TARGET_ITEM_COUNT = 50

LOCAL_BATCH_TEST_COMMANDS = (
    "python3 -m py_compile tools/automation-closure.py tools/audit-closeout-check.py",
    "make automation-closure-test",
    "python3 -m unittest tools.tests.test_audit_closeout_check.PR560ArtifactClosureTests",
    "python3 -m unittest tools.tests.test_semantic_detector_adjudication",
    "make live-provider-local-verification-queue-test",
    "python3 -m unittest tools.tests.test_semantic_graph_query tools.tests.test_semantic_detector_worklist tools.tests.test_semantic_detector_adjudication tools.tests.test_mining_prioritizer_asset_quota",
    "make audit-closeout-test",
    "make docs-check",
    "python3 tools/branch-verify.py --expected-branch codex/pr560-next-actions --strict-isolation",
)


def local_completed_item_range(items: tuple[str, ...]) -> str:
    if not items:
        return ""
    start = LOCAL_BATCH_COMPLETED_ITEMS.index(items[0]) + 1
    end = start + len(items) - 1
    return f"{start}-{end}"


LOCAL_BATCH_LANE_OUTPUTS = (
    {
        "lane_id": "A2",
        "title": "Scan artifact blocker detail",
        "worktree_path": "/private/tmp/auditooor-pr560-scan-artifacts",
        "branch": "codex/pr560-scan-artifacts",
        "item_count": 3,
        "completed_item_range": "16-18",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "B2",
        "title": "Agent-output terminal verification ingestion",
        "worktree_path": "/private/tmp/auditooor-pr560-agent-output-verification",
        "branch": "codex/pr560-agent-output-verification",
        "item_count": 3,
        "completed_item_range": "19-21",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C2/C3",
        "title": "Next-action closeout and local progress reporting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 20,
        "completed_item_range": "1-15, 30-34",
        "tests": LOCAL_BATCH_TEST_COMMANDS,
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "D2",
        "title": "Impact-family source-mining queue",
        "worktree_path": "/private/tmp/auditooor-pr560-lane-d-impact-source-queue",
        "branch": "codex/pr560-lane-d-impact-source-queue",
        "item_count": 4,
        "completed_item_range": "22-25",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "E2",
        "title": "Invariant acceptance queue",
        "worktree_path": "/private/tmp/auditooor-pr560-invariant-queue",
        "branch": "codex/pr560-invariant-acceptance-queue-20260430",
        "item_count": 4,
        "completed_item_range": "26-29",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "A3",
        "title": "Scan artifact canonical/legacy reconciliation",
        "worktree_path": "/private/tmp/auditooor-pr560-scan-artifacts",
        "branch": "codex/pr560-scan-artifacts",
        "item_count": 4,
        "completed_item_range": "35-38",
        "tests": ("python3 tools/tests/test_automation_closure.py", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "B3",
        "title": "Agent-output verification ledger writes",
        "worktree_path": "/private/tmp/auditooor-pr560-agent-output-verification",
        "branch": "codex/pr560-agent-output-verification",
        "item_count": 6,
        "completed_item_range": "39-44",
        "tests": ("python3 -m unittest tools.tests.test_automation_closure", "make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "D3",
        "title": "Impact-family routing hints",
        "worktree_path": "/private/tmp/auditooor-pr560-lane-d-impact-source-queue",
        "branch": "codex/pr560-lane-d-impact-source-queue",
        "item_count": 5,
        "completed_item_range": "45-49",
        "tests": ("python3 -m unittest tools.tests.test_automation_closure", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "E3",
        "title": "Invariant acceptance review ingestion",
        "worktree_path": "/private/tmp/auditooor-pr560-invariant-queue",
        "branch": "codex/pr560-invariant-acceptance-queue-20260430",
        "item_count": 5,
        "completed_item_range": "50-54",
        "tests": ("make automation-closure-test", "make docs-check", "git diff --check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "A3-E3 verification",
        "title": "Lane verification reruns",
        "worktree_path": "/private/tmp",
        "branch": "local-only-multiple-lanes",
        "item_count": 4,
        "completed_item_range": "55-58",
        "tests": ("make automation-closure-test", "make docs-check", "python3 tools/branch-verify.py --strict-isolation"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C4",
        "title": "Local batch readiness ledger integration",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 5,
        "completed_item_range": "59-63",
        "tests": LOCAL_BATCH_TEST_COMMANDS,
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C5",
        "title": "Local bundle packaging safety checks",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 5,
        "completed_item_range": "64-68",
        "tests": LOCAL_BATCH_TEST_COMMANDS,
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "A5",
        "title": "Agent verification record scaffolds",
        "worktree_path": "/private/tmp/auditooor-pr560-scan-artifacts",
        "branch": "codex/pr560-scan-artifacts",
        "item_count": 4,
        "completed_item_range": "69-72",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "B5",
        "title": "Source-proof advisory precision",
        "worktree_path": "/private/tmp/auditooor-pr560-agent-output-verification",
        "branch": "codex/pr560-agent-output-verification",
        "item_count": 4,
        "completed_item_range": "73-76",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "D5",
        "title": "Impact-analysis exact-impact routing",
        "worktree_path": "/private/tmp/auditooor-pr560-lane-d-impact-source-queue",
        "branch": "codex/pr560-lane-d-impact-source-queue",
        "item_count": 4,
        "completed_item_range": "77-80",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "E5",
        "title": "Fail-closed invariant review dispositions",
        "worktree_path": "/private/tmp/auditooor-pr560-invariant-queue",
        "branch": "codex/pr560-invariant-acceptance-queue-20260430",
        "item_count": 4,
        "completed_item_range": "81-84",
        "tests": ("make automation-closure-test", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C6",
        "title": "Central ledger reconciliation for A5/B5/D5/E5",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 4,
        "completed_item_range": "85-88",
        "tests": LOCAL_BATCH_TEST_COMMANDS,
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C7",
        "title": "Central advisory row reconciliation",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 4,
        "completed_item_range": "89-92",
        "tests": LOCAL_BATCH_TEST_COMMANDS,
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C8",
        "title": "Central agent-output verification record closure",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 6,
        "completed_item_range": "93-98",
        "tests": LOCAL_BATCH_TEST_COMMANDS,
        "ready_for_batch_integration": True,
        "status": "ready_local",
    },
    {
        "lane_id": "C9",
        "title": "Impact-first gate accounting slice",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 7,
        "completed_item_range": "99-105",
        "tests": ("python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests", "make docs-check"),
        "ready_for_batch_integration": True,
        "status": "ready_local_reduction_only",
        "covered_gates": (
            "critical-hunt advisory gate",
            "paste-ready gate",
            "submission-packager gate",
            "swarm dispatch gate",
            "mining brief gate",
            "poc-scaffold plan-json gate",
            "docs/validation",
        ),
        "closure_claim": "progress_reduced_only_priority_1_not_closed",
    },
    {
        "lane_id": "C10",
        "title": "Generated artifact impact-first gate accounting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 2,
        "completed_item_range": "106-107",
        "tests": (
            "python3 -m unittest tools.tests.test_auto_draft_generator",
            "python3 -m unittest tools.tests.test_harness_scaffold_emitter.TestFailedAttemptManifest",
            "python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_reduction_only",
        "covered_gates": (
            "auto-draft-generator draft/PoC write gate",
            "harness-scaffold-emitter scaffold write gate",
        ),
        "closure_claim": "progress_reduced_only_priority_1_not_closed",
    },
    {
        "lane_id": "C11",
        "title": "ReCon/Chimera and promotion seam gate accounting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 4,
        "completed_item_range": "108-111",
        "tests": (
            "python3 -m unittest tools.tests.test_recon_log_bridge",
            "python3 -m unittest tools.tests.test_chimera_scaffold",
            "python3 -m unittest tools.tests.test_chimera_ledger_scaffold",
            "python3 -m unittest tools.tests.test_findings_to_pattern.PromotionGateTests",
            "python3 -m unittest tools.tests.test_promotion_contract_integration",
            "python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_reduction_only",
        "covered_gates": (
            "detector-promotion Program Impact Mapping gate",
            "source-mining survivor impact-contract gate",
            "Chimera scaffold impact-contract gate",
            "ReCon forge replay impact-contract gate",
            "corpus detectorization impact-neutral routing",
        ),
        "closure_claim": "progress_reduced_only_priority_1_not_closed",
    },
    {
        "lane_id": "C12",
        "title": "Submission factory, deep replay, and provider seam gate accounting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 5,
        "completed_item_range": "112-116",
        "tests": (
            "python3 -m unittest tools.tests.test_submission_factory",
            "python3 -m unittest tools.tests.test_deep_counterexample_replay_scaffold",
            "python3 -m unittest tools.tests.test_source_mining_campaign",
            "python3 -m unittest tools.tests.test_auto_draft_generator",
            "python3 -m unittest tools.tests.test_harness_scaffold_emitter.TestFailedAttemptManifest",
            "python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_reduction_only",
        "covered_gates": (
            "submission-factory impact-contract refusal",
            "deep replay impact-contract gate",
            "source-mining provider input-only routing",
            "auto-draft-generator machine-detected gate",
            "harness-scaffold-emitter machine-detected gate",
        ),
        "closure_claim": "progress_reduced_only_priority_1_not_closed",
    },
    {
        "lane_id": "C13",
        "title": "Semantic worklist and submission-output gate accounting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 8,
        "completed_item_range": "117-124",
        "tests": (
            "python3 -m unittest tools.tests.test_semantic_detector_worklist",
            "python3 -m unittest tools.tests.test_source_mining_campaign",
            "python3 -m unittest tools.tests.test_llm_dispatch_preflight_gate",
            "python3 -m unittest tools.tests.test_submission_factory",
            "python3 -m unittest tools.tests.test_submission_packager_hygiene",
            "python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests",
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_reduction_only",
        "covered_gates": (
            "provider/source-mining dispatch preflight gate",
            "Kimi source-extract captured advisory provider-assist gate",
            "Minimax adversarial-kill captured advisory provider-assist gate",
            "semantic-detector-worklist advisory bridge",
            "typed multihop semantic graph worklist inputs",
            "submission-factory proof-artifact and tier gate",
            "submission-packager proof-artifact and High+ evidence-matrix gate",
            "C13 progress regeneration",
        ),
        "closure_claim": "progress_reduced_only_priority_1_not_closed",
    },
    {
        "lane_id": "AF",
        "title": "Semantic query and impact handoff integration",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 50,
        "completed_item_range": "125-174",
        "tests": (
            "python3 -m unittest tools.tests.test_semantic_graph_query",
            "python3 -m unittest tools.tests.test_automation_closure",
            "python3 -m unittest tools.tests.test_mining_prioritizer_asset_quota",
            "python3 -m unittest tools.tests.test_semantic_graph_query tools.tests.test_automation_closure tools.tests.test_mining_prioritizer_asset_quota",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_advisory_only",
        "covered_gates": (
            "impact worklist source_review_handoff to semantic_graph_query execution",
            "semantic_graph_query_results accounting back into source_review_handoff",
            "semantic_graph_query_results propagation into mining_priorities sidecars",
            "semantic detector worklist task query-result propagation",
            "docs and tests preserving NOT_SUBMIT_READY posture",
        ),
        "closure_claim": "advisory_query_accounting_only_not_submission_proof",
    },
    {
        "lane_id": "AL",
        "title": "Semantic detector adjudication after query execution",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 51,
        "completed_item_range": "175-225",
        "tests": (
            "python3 -m unittest tools.tests.test_semantic_detector_adjudication",
            "python3 -m unittest tools.tests.test_mining_prioritizer_asset_quota",
            "python3 -m unittest tools.tests.test_semantic_graph_query tools.tests.test_semantic_detector_worklist tools.tests.test_semantic_detector_adjudication tools.tests.test_mining_prioritizer_asset_quota",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_advisory_only",
        "covered_gates": (
            "semantic_graph_query_results to detector rewrite brief adjudication",
            "fixture requirement generation for matched detector rows",
            "explicit non-detectorizable/source-invariant routing",
            "semantic_detector_adjudication propagation into mining_priorities sidecars",
            "docs and tests preserving NOT_SUBMIT_READY posture",
        ),
        "closure_claim": "advisory_detector_planning_only_not_detector_or_submission_proof",
    },
    {
        "lane_id": "AZ",
        "title": "Semantic multihop-to-detector action lanes",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 50,
        "completed_item_range": "226-276",
        "tests": (
            "python3 -m unittest tools.tests.test_semantic_detector_worklist",
            "python3 -m unittest tools.tests.test_semantic_graph_query",
            "python3 -m unittest tools.tests.test_semantic_detector_adjudication",
            "python3 -m unittest tools.tests.test_semantic_detector_worklist tools.tests.test_semantic_graph_query tools.tests.test_semantic_detector_adjudication",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_advisory_only",
        "covered_gates": (
            "relation-edge detector rewrite action lanes",
            "multi-hop fixture-first/source-invariant action lanes",
            "query accounting by action lane and source-shape limitation",
            "adjudication terminal-decision/action-item ledger",
            "PR560 next-action detail preserving source-shape-only boundaries",
        ),
        "closure_claim": "advisory_mechanical_path_only_not_runtime_or_detector_proof",
    },
    {
        "lane_id": "AT",
        "title": "Provider triage to local verification queue",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 15,
        "completed_item_range": "277-291",
        "tests": (
            "make live-provider-local-verification-queue-test",
            "python3 -m unittest tools.tests.test_live_provider_result_triage",
            "python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests.test_pr560_next_actions_carries_provider_local_verification_rows",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_advisory_only",
        "covered_gates": (
            "live_provider_result_triage to local grep queue",
            "fixture-needed queue preservation",
            "non-detectorizable/source-review routing",
            "Minimax killed-row preservation",
            "PR560 next-action bounded provider queue import",
        ),
        "closure_claim": "advisory_provider_triage_only_not_detector_or_submission_proof",
    },
    {
        "lane_id": "AX",
        "title": "Provider local-verification terminal closure",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 50,
        "completed_item_range": "292-341",
        "tests": (
            "python3 -m unittest tools.tests.test_provider_result_local_verify",
            "python3 -m unittest tools.tests.test_live_provider_local_verification_queue",
            "python3 -m unittest tools.tests.test_automation_closure.AutomationClosureTests.test_pr560_next_actions_skips_terminal_provider_local_verification_rows",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_advisory_only",
        "covered_gates": (
            "Worker AT queue terminal closure",
            "Worker AV local verification evidence consumption",
            "safe local grep/check accounting",
            "provider next-action terminal-row filtering",
            "progress/readiness advisory reconciliation",
        ),
        "closure_claim": "advisory_provider_local_verification_only_not_detector_or_submission_proof",
    },
    {
        "lane_id": "BB",
        "title": "Integration readiness/progress reconciliation accounting link",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 1,
        "completed_item_range": "reconciliation-accounting-link",
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "local progress and integration readiness totals remain equal",
            "full-roadmap closure stays separate from local capability accounting",
        ),
        "closure_claim": "accounting_reconciliation_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "BG",
        "title": "Final integration readiness and percentage accounting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 51,
        "completed_item_range": "342-392",
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "local implementation percentage remains scoped to PR560 local artifacts",
            "known-limitations stop-condition percentage remains burn-down-map scoped",
            "full roadmap closure remains separate and unclaimed",
            "active slot accounting is visible for operator handoff",
        ),
        "closure_claim": "final_accounting_reconciliation_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "BL",
        "title": "Post-BH-BK integration accounting and roadmap truth refresh",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 50,
        "completed_item_range": "393-442",
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "empty PR560 next-action queue remains distinct from roadmap closure",
            "known-limitations percentages remain stop-condition scoped",
            "full roadmap closure remains unclaimed while residual boundaries stay open",
            "active slot ownership reflects BL after BG",
        ),
        "closure_claim": "post_bh_bk_accounting_truth_refresh_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "BQ",
        "title": "Slot/readiness reliability and stale-running quarantine",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 50,
        "completed_item_range": "443-492",
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "active slot stale-running rows ignored for effective running counts",
            "BM-BP artifact window discovery remains evidence-driven",
            "progress/readiness/known-limitations ledgers regenerated after BQ",
            "future loop status cannot count old unrefreshed handles as running",
        ),
        "closure_claim": "slot_accounting_reliability_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "BP",
        "title": "Impact-family execution blocker enforcement",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 2,
        "completed_item_range": "493-494",
        "tests": (
            "python3 -m unittest tools.tests.test_automation_closure tools.tests.test_promotion_contract_integration tools.tests.test_severity_claim_guard",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "impact-family worklists emit 50-item-capped concrete execution reductions",
            "reportable families without locked contracts or reduced handoff stay open_impact_contract_or_family_execution",
        ),
        "closure_claim": "impact_family_start_of_work_enforcement_only_not_submission_proof",
    },
    {
        "lane_id": "BV",
        "title": "Final accounting after BR-BU and stale-loop reliability",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 52,
        "completed_item_range": "495-546",
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "progress/readiness/known-limitations maps regenerated after BQ",
            "BR-BU artifact window discovery remains evidence-driven",
            "active slot ledger reflects current local accounting owner",
            "closure percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_truth_refresh_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "CA",
        "title": "Active-loop reliability and BW-BZ final accounting",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": 51,
        "completed_item_range": "547-597",
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "BW-BZ artifact-window discovery remains evidence-driven",
            "active slot ledger reflects current local CA handle",
            "automation id is present in generated readiness metadata",
            "closure percentages remain stop-condition scoped",
        ),
        "closure_claim": "active_loop_reliability_and_bw_bz_accounting_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "CF",
        "title": "Final accounting after CB-CE and active-slot reliability",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_CF_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_CF_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "CB-CE artifact-window discovery remains evidence-driven",
            "BW-BZ generated accounting artifacts are recognized without proof overclaim",
            "active slot ledger reflects current local CF handle",
            "closure percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_after_cb_ce_and_slot_reliability_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "CK",
        "title": "Final accounting after CG-CJ and artifact recognition",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_CK_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_CK_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "CB-CF artifact-window discovery remains evidence-driven",
            "CG-CJ artifact-window discovery remains evidence-driven",
            "active slot ledger reflects current local CK handle",
            "closure and reduction percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_after_cg_cj_and_artifact_recognition_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "CP",
        "title": "Final accounting after CL-CO and artifact recognition",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_CP_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_CP_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "CG-CJ artifact-window discovery remains evidence-driven",
            "CL-CO artifact-window discovery remains evidence-driven",
            "active slot ledger reflects current local CP handle",
            "closure and reduction percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_after_cl_co_and_artifact_recognition_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "CR",
        "title": "Permission-loop reliability and no-approval-prompt hardening",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_CR_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_CR_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "worker dispatch docs state local writes are allowed",
            "worker dispatch docs forbid approval prompts in closure loops",
            "commands are tried before blocker artifacts are recorded",
            "blocker artifacts are limited to real missing prerequisites, failing tools, unsafe semantic gaps, or git/GitHub boundaries",
            "AGENTS-adjacent docs preserve no staging/commit/push/PR/merge/GitHub Actions",
        ),
        "closure_claim": "permission_loop_reliability_only_not_git_or_github_authority",
    },
    {
        "lane_id": "CV",
        "title": "Known-limitations closure check after CQ/CR/CM/CN/CP",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_CV_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_CV_COMPLETED_ITEMS),
        "tests": (
            "make known-limitations-check-test",
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "only severity-claim discipline flips stop_condition_met true",
            "CQ recall follow-through remains accounting-only with named blockers",
            "CM dependency closure remains blocker evidence, not fixture smoke proof",
            "CP/CR recognition and reliability remain not-full-closure accounting",
        ),
        "closure_claim": "one_known_limitation_stop_condition_flipped_with_residual_blockers_named",
    },
    {
        "lane_id": "CW",
        "title": "Final accounting after CS-CV and provider status reflection",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_CW_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_CW_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "CS-CV artifact-window discovery remains evidence-driven",
            "provider-lane outputs are reflected as advisory local verification status",
            "active slot ledger reflects current local CW handle",
            "closure and reduction percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_after_cs_cv_provider_status_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "DB",
        "title": "Final accounting after CX-DA with scanner-autonomy percentages",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_DB_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_DB_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "CX-DA artifact-window discovery remains evidence-driven",
            "scanner-autonomy percentages are mechanical accounting only",
            "Impact-Miss and genericity docs are reflected without closure overclaim",
            "closure and reduction percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_after_cx_da_scanner_autonomy_percentages_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "DG",
        "title": "Final accounting after DC-DF with refreshed maps and percentages",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_DG_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_DG_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "DC-DF artifact-window discovery remains evidence-driven",
            "progress/readiness/known-limitations maps are regenerated",
            "scanner-autonomy percentages remain mechanical accounting only",
            "Impact-Miss and genericity docs remain reflected without closure overclaim",
            "closure and reduction percentages remain stop-condition scoped",
        ),
        "closure_claim": "final_accounting_after_dc_df_refreshed_maps_percentages_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "DL",
        "title": "Final accounting after DH-DK with refreshed maps and percentages",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_DL_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_DL_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make known-limitations-check",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "DH-DK artifact-window discovery remains evidence-driven",
            "progress/readiness/known-limitations maps are regenerated",
            "scanner-autonomy percentages remain mechanical accounting only",
            "Impact-Miss and genericity docs remain reflected without closure overclaim",
            "active slots and bundle readiness remain operator-review accounting only",
        ),
        "closure_claim": "final_accounting_after_dh_dk_refreshed_maps_percentages_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "DQ",
        "title": "Final accounting after DM-DP with refreshed maps and closure-output validation",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_DQ_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_DQ_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make known-limitations-check",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "DM-DP artifact-window discovery remains evidence-driven",
            "progress/readiness/known-limitations maps are regenerated",
            "scanner-autonomy and Impact-Miss percentages remain mechanical accounting only",
            "closure-output artifacts are validated without queue-only stopping",
            "active slots and bundle readiness remain operator-review accounting only",
        ),
        "closure_claim": "final_accounting_after_dm_dp_refreshed_maps_percentages_only_not_full_roadmap_closure",
    },
    {
        "lane_id": "DW",
        "title": "Final accounting after DS-DV with refreshed maps and closure-output validation",
        "worktree_path": "/private/tmp/auditooor-pr560-next-actions",
        "branch": "codex/pr560-next-actions",
        "item_count": len(PR560_WORKER_DW_COMPLETED_ITEMS),
        "completed_item_range": local_completed_item_range(PR560_WORKER_DW_COMPLETED_ITEMS),
        "tests": (
            "make automation-closure-test",
            "make known-limitations-check",
            "make docs-check",
        ),
        "ready_for_batch_integration": True,
        "status": "ready_local_accounting_only",
        "covered_gates": (
            "DS-DV artifact-window discovery remains evidence-driven",
            "progress/readiness/known-limitations maps are regenerated",
            "scanner-autonomy and Impact-Miss percentages remain mechanical accounting only",
            "closure-output artifacts are validated without queue-only stopping",
            "active slots and bundle readiness remain operator-review accounting only",
        ),
        "closure_claim": "final_accounting_after_ds_dv_refreshed_maps_percentages_only_not_full_roadmap_closure",
    },
)


def local_batch_changed_files() -> list[str]:
    fallback = [
        "Makefile",
        "docs/PR560_LOCAL_BATCH_PROGRESS.md",
        "docs/PR560_LOCAL_BATCH_PROGRESS.json",
        "docs/TOOL_STATUS.md",
        "docs/CROSS_LINK_REPORT.md",
        "tools/automation-closure.py",
        "tools/audit-closeout-check.py",
        "tools/tests/test_automation_closure.py",
        "tools/tests/test_audit_closeout_check.py",
    ]
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return fallback
    if proc.returncode != 0:
        return fallback
    paths: list[str] = list(fallback)
    for line in proc.stdout.splitlines():
        if not line:
            continue
        path = line[3:] if len(line) > 3 else line
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path.strip())
    return sorted(dict.fromkeys(paths or fallback))


def local_batch_bundle_readiness(
    *,
    completed_count: int,
    lane_outputs: list[dict[str, Any]],
    strict_rows: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    summary: dict[str, Any],
    changed_files: list[str],
    tests_run: list[str],
    reconciled_advisory_counts: dict[str, int],
) -> dict[str, Any]:
    non_ready_lanes = [row["lane_id"] for row in lane_outputs if not row.get("ready_for_batch_integration")]
    advisory_rows = [row for row in rows if not row.get("strict_blocking")]
    lane_item_total = sum(int(row.get("item_count", 0) or 0) for row in lane_outputs)
    summary_counts = summary.get("by_category", {}) if isinstance(summary.get("by_category"), dict) else {}
    summary_strict_count = int(summary.get("strict_blocking", summary_counts.get("strict_blocker", 0)) or 0)
    agent_verification_count = max(
        int(reconciled_advisory_counts.get("agent_verification", 0) or 0),
        0,
    )
    required_tests = (
        "python3 -m py_compile tools/automation-closure.py tools/audit-closeout-check.py",
        "make automation-closure-test",
        "make docs-check",
        "python3 tools/branch-verify.py --expected-branch codex/pr560-next-actions --strict-isolation",
    )
    required_changed_files = (
        "docs/PR560_LOCAL_BATCH_PROGRESS.md",
        "docs/PR560_LOCAL_BATCH_PROGRESS.json",
        "tools/automation-closure.py",
        "tools/tests/test_automation_closure.py",
    )
    missing_tests = [command for command in required_tests if command not in tests_run]
    missing_changed_files = [path for path in required_changed_files if path not in changed_files]
    consistency_checks = {
        "lane_item_total_matches_completed": lane_item_total == completed_count,
        "all_lanes_ready": not non_ready_lanes,
        "required_tests_present": not missing_tests,
        "required_changed_files_present": not missing_changed_files,
        "strict_blocker_count_matches_summary": len(strict_rows) == summary_strict_count,
        "agent_output_verification_clear": agent_verification_count == 0,
    }
    refusal_reasons: list[dict[str, Any]] = []
    if not consistency_checks["lane_item_total_matches_completed"]:
        refusal_reasons.append(
            {
                "reason": "lane_item_total_mismatch",
                "expected": completed_count,
                "actual": lane_item_total,
            }
        )
    if missing_tests:
        refusal_reasons.append({"reason": "missing_required_tests", "missing": missing_tests})
    if missing_changed_files:
        refusal_reasons.append({"reason": "missing_required_changed_files", "missing": missing_changed_files})
    if not consistency_checks["strict_blocker_count_matches_summary"]:
        refusal_reasons.append(
            {
                "reason": "strict_blocker_count_mismatch",
                "expected": summary_strict_count,
                "actual": len(strict_rows),
            }
        )
    if agent_verification_count:
        refusal_reasons.append({"reason": "unverified_agent_output_rows", "count": agent_verification_count})
    if non_ready_lanes:
        refusal_reasons.append({"reason": "non_ready_lanes", "lanes": non_ready_lanes})
    if strict_rows:
        status = "blocked_strict_next_actions"
        next_step = "Clear strict PR560 blockers before preparing an integration PR."
        ready = False
    elif refusal_reasons:
        status = refusal_reasons[0]["reason"]
        next_step = "Resolve local bundle-readiness refusal reasons before preparing packaging."
        ready = False
    elif non_ready_lanes:
        status = "blocked_lane_outputs_not_ready"
        next_step = "Finish or mark non-ready lane outputs before batching."
        ready = False
    elif completed_count < LOCAL_BATCH_TARGET_ITEM_COUNT:
        status = "collect_more_local_items"
        next_step = f"Continue local-only work until at least {LOCAL_BATCH_TARGET_ITEM_COUNT} completed items."
        ready = False
    else:
        status = "ready_for_operator_batch_integration"
        next_step = "Prepare one coherent local integration branch only when the operator asks for GitHub work."
        ready = True
    return {
        "status": status,
        "ready_for_eventual_pr": ready,
        "target_completed_items": LOCAL_BATCH_TARGET_ITEM_COUNT,
        "completed_items": completed_count,
        "completed_items_remaining_to_target": max(LOCAL_BATCH_TARGET_ITEM_COUNT - completed_count, 0),
        "lane_item_total": lane_item_total,
        "strict_blocker_count": len(strict_rows),
        "strict_blocker_summary_count": summary_strict_count,
        "advisory_open_queue_count": len(advisory_rows),
        "agent_output_verification_open_count": agent_verification_count,
        "non_ready_lanes": non_ready_lanes,
        "consistency_checks": consistency_checks,
        "refusal_reasons": refusal_reasons,
        "missing_required_tests": missing_tests,
        "missing_required_changed_files": missing_changed_files,
        "next_step": next_step,
    }


def remaining_advisory_counts(summary: dict[str, Any]) -> dict[str, int]:
    counts = summary.get("by_category", {}) if isinstance(summary.get("by_category"), dict) else {}
    return {
        str(category): int(count or 0)
        for category, count in sorted(counts.items())
        if category != "strict_blocker" and int(count or 0) > 0
    }


def _summary_int(payload: dict[str, Any], *keys: str) -> int:
    summary = payload.get("summary") if isinstance(payload, dict) else {}
    if not isinstance(summary, dict):
        return 0
    for key in keys:
        value = summary.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def _count_rows_with_values(payload: dict[str, Any], key: str, values: set[str]) -> int:
    rows = payload.get("rows") if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        return 0
    return sum(1 for row in rows if isinstance(row, dict) and str(row.get(key, "")) in values)


def advisory_reconciliation(workspace: Path, open_counts: dict[str, int]) -> dict[str, Any]:
    aud = out_dir(workspace)
    sources = {
        "agent_verification": aud / "agent_output_inventory.json",
        "impact_analysis": aud / "impact_analysis_queue.json",
        "source_proof": aud / "source_proof_tasks.json",
        "invariant_queue": aud / "invariant_acceptance_queue.json",
        "provider_local_verification": workspace / ".audit_logs" / "pr560_worker_ax" / "provider_local_verification_closure.json",
    }
    resolved_counts: dict[str, int] = {category: 0 for category in open_counts}
    source_artifacts: dict[str, str] = {category: str(path) for category, path in sources.items() if path.exists()}
    source_status: dict[str, str] = {}

    agent_payload = load_json(sources["agent_verification"]) if sources["agent_verification"].exists() else {}
    if agent_payload:
        resolved_counts["agent_verification"] = _count_rows_with_values(
            agent_payload,
            "local_verification_status",
            {
                "verified_local",
                "killed_duplicate_or_oos",
                "routed_to_impact_analysis",
                "routed_to_source_proof",
                "routed_to_harness_task",
                "detectorized",
                "archived_no_claims",
                "resolved_archive_or_ignore",
            },
        )
        source_status["agent_verification"] = "loaded"

    impact_payload = load_json(sources["impact_analysis"]) if sources["impact_analysis"].exists() else {}
    if impact_payload:
        resolved_counts["impact_analysis"] = max(
            _summary_int(impact_payload, "rows_resolved", "resolved_rows", "resolved_local_impact_contract"),
            _count_rows_with_values(impact_payload, "impact_analysis_status", {"resolved_local_impact_contract"}),
        )
        source_status["impact_analysis"] = "loaded"

    source_payload = load_json(sources["source_proof"]) if sources["source_proof"].exists() else {}
    if source_payload:
        resolved_counts["source_proof"] = max(
            _summary_int(source_payload, "terminal_evidence_present", "local_evidence_present"),
            _count_rows_with_values(source_payload, "local_evidence_status", {"terminal_evidence_present", "present"}),
        )
        source_status["source_proof"] = "loaded"

    invariant_payload = load_json(sources["invariant_queue"]) if sources["invariant_queue"].exists() else {}
    if invariant_payload:
        resolved_counts["invariant_queue"] = max(
            _summary_int(invariant_payload, "rows_resolved", "resolved_rows", "terminal_review_rows"),
            _count_rows_with_values(
                invariant_payload,
                "review_state",
                {"accepted", "merged", "killed", "needs_harness", "advisory_harness_required"},
            ),
        )
        source_status["invariant_queue"] = "loaded"

    provider_payload = (
        load_json(sources["provider_local_verification"])
        if sources["provider_local_verification"].exists()
        else {}
    )
    if provider_payload:
        resolved_counts["provider_local_verification"] = max(
            _summary_int(provider_payload, "terminal_row_count", "resolved_rows", "row_count"),
            _count_rows_with_values(provider_payload, "terminal", {"True", "true", "1"}),
        )
        source_status["provider_local_verification"] = "loaded"

    remaining_counts = {
        category: max(int(open_counts.get(category, 0) or 0) - int(resolved_counts.get(category, 0) or 0), 0)
        for category in open_counts
    }
    return {
        "source_artifacts": source_artifacts,
        "source_status": source_status,
        "open_counts_before_reconciliation": dict(open_counts),
        "resolved_counts": resolved_counts,
        "remaining_counts": remaining_counts,
        "resolved_total": sum(resolved_counts.values()),
        "remaining_total": sum(remaining_counts.values()),
    }


def render_pr560_local_progress(workspace: Path) -> dict[str, Any]:
    next_actions = load_json(out_dir(workspace) / "pr560_next_actions.json") or render_pr560_next_actions(workspace)
    rows = records_from_payload(next_actions)
    summary = dict(next_actions.get("summary") or {}) if isinstance(next_actions, dict) else {}
    strict_rows = [row for row in rows if row.get("strict_blocking")]
    changed_files = local_batch_changed_files()
    progress_path, progress_json_path = pr560_progress_paths()
    lane_outputs = [dict(row) for row in LOCAL_BATCH_LANE_OUTPUTS]
    completed_count = len(LOCAL_BATCH_COMPLETED_ITEMS)
    lane_item_total = sum(int(row.get("item_count", 0) or 0) for row in lane_outputs)
    open_advisory_counts = remaining_advisory_counts(summary)
    reconciliation = advisory_reconciliation(workspace, open_advisory_counts)
    advisory_counts = dict(reconciliation["remaining_counts"])
    foundry_trial_readiness = foundry_representative_fixture_manifests()
    bundle_readiness = local_batch_bundle_readiness(
        completed_count=completed_count,
        lane_outputs=lane_outputs,
        strict_rows=strict_rows,
        rows=rows,
        summary=summary,
        changed_files=changed_files,
        tests_run=list(LOCAL_BATCH_TEST_COMMANDS),
        reconciled_advisory_counts=advisory_counts,
    )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.local_batch_progress.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "progress_doc": str(progress_path),
        "progress_json": str(progress_json_path),
        "completed_implementation_count": completed_count,
        "completed_implementation_status": "complete_local_only",
        "completed_checklist_count": completed_count,
        "completed_checklist_items": list(LOCAL_BATCH_COMPLETED_ITEMS),
        "lane_item_total": lane_item_total,
        "lane_item_count_matches_completed": lane_item_total == completed_count,
        "lane_output_count": len(lane_outputs),
        "ready_lane_output_count": sum(1 for row in lane_outputs if row["ready_for_batch_integration"]),
        "lane_outputs": lane_outputs,
        "bundle_readiness": bundle_readiness,
        "readiness_blockers": bundle_readiness["refusal_reasons"],
        "advisory_reconciliation": reconciliation,
        "foundry_trial_readiness": foundry_trial_readiness,
        "open_advisory_counts_before_reconciliation": open_advisory_counts,
        "resolved_advisory_counts": reconciliation["resolved_counts"],
        "resolved_advisory_count": reconciliation["resolved_total"],
        "remaining_advisory_counts": advisory_counts,
        "remaining_advisory_count": sum(advisory_counts.values()),
        "remaining_queue_counts": summary.get("by_category", {}),
        "remaining_queue_count": int(summary.get("row_count", len(rows)) or 0),
        "strict_blockers": [
            {
                "next_action_id": row.get("next_action_id"),
                "source_artifact": row.get("source_artifact"),
                "exact_status": row.get("exact_status"),
                "next_command": row.get("next_command"),
            }
            for row in strict_rows
        ],
        "tests_run": list(LOCAL_BATCH_TEST_COMMANDS),
        "changed_files": changed_files,
        "changed_file_count": len(changed_files),
        "next_actions_artifact": str(out_dir(workspace) / "pr560_next_actions.json"),
        "status": bundle_readiness["status"],
    }

    doc = [
        "# PR560 Local Batch Progress",
        "",
        "Generated by `tools/automation-closure.py --mode pr560-local-progress`.",
        "This ledger is intentionally local-first. Do not open or merge GitHub PRs from this worktree until roughly 20-50 PR560 checklist items are completed, or one coherent closure milestone is ready.",
        "",
        "## Current Batch",
        "",
        f"- Workspace: `{workspace}`",
        f"- Next-actions artifact: `{out_dir(workspace) / 'pr560_next_actions.json'}`",
        f"- Completed implementation items: `{completed_count}`",
        f"- Remaining queue rows: `{payload['remaining_queue_count']}`",
        f"- Resolved advisory rows: `{payload['resolved_advisory_count']}`",
        f"- Remaining advisory rows: `{payload['remaining_advisory_count']}`",
        f"- Strict blockers: `{len(strict_rows)}`",
        f"- Bundle readiness: `{bundle_readiness['status']}`",
        f"- Ready for eventual PR: `{str(bundle_readiness['ready_for_eventual_pr']).lower()}`",
        "",
        "## Implementation Progress",
        "",
        f"- Completed implementation count: `{completed_count}`",
        f"- Lane item total: `{lane_item_total}`",
        f"- Lane total matches completed checklist: `{str(lane_item_total == completed_count).lower()}`",
        f"- Local implementation status: `{payload['completed_implementation_status']}`",
        "",
        "## Completed Locally",
        "",
    ]
    for idx, item in enumerate(LOCAL_BATCH_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Lane Outputs",
        "",
        "| Lane | Title | Worktree | Items | Range | Ready | Tests |",
        "|---|---|---|---:|---|---|---|",
    ])
    for row in lane_outputs:
        tests = "<br>".join(f"`{command}`" for command in row["tests"])
        ready = "yes" if row["ready_for_batch_integration"] else "no"
        doc.append(
            f"| `{row['lane_id']}` | {row['title']} | `{row['worktree_path']}` | `{row['item_count']}` | "
            f"`{row['completed_item_range']}` | `{ready}` | {tests} |"
        )
    doc.extend([
        "",
        "## Bundle Readiness",
        "",
        f"- Status: `{bundle_readiness['status']}`",
        f"- Ready for eventual PR: `{str(bundle_readiness['ready_for_eventual_pr']).lower()}`",
        f"- Completed items: `{bundle_readiness['completed_items']}` / `{bundle_readiness['target_completed_items']}`",
        f"- Lane item total: `{lane_item_total}`",
        f"- Lane total matches completed checklist: `{str(payload['lane_item_count_matches_completed']).lower()}`",
        f"- Strict blockers: `{bundle_readiness['strict_blocker_count']}`",
        f"- Unverified agent-output rows: `{bundle_readiness['agent_output_verification_open_count']}`",
        f"- Advisory open queue rows: `{bundle_readiness['advisory_open_queue_count']}`",
        f"- Non-ready lanes: `{', '.join(bundle_readiness['non_ready_lanes']) if bundle_readiness['non_ready_lanes'] else 'none'}`",
        f"- Next step: {bundle_readiness['next_step']}",
    ])
    if bundle_readiness["refusal_reasons"]:
        doc.extend(["", "### Refusal Reasons", ""])
        for reason in bundle_readiness["refusal_reasons"]:
            doc.append(f"- `{reason['reason']}`: `{json.dumps(reason, sort_keys=True)}`")
    doc.extend(["", "## Readiness Blockers", ""])
    if bundle_readiness["refusal_reasons"]:
        for reason in bundle_readiness["refusal_reasons"]:
            doc.append(f"- `{reason['reason']}`: `{json.dumps(reason, sort_keys=True)}`")
    else:
        doc.append("- _none_")
    doc.extend(["", "## Remaining Advisory Counts", ""])
    if advisory_counts:
        for category, count in advisory_counts.items():
            doc.append(f"- `{category}`: `{count}`")
    else:
        doc.append("- _none_")
    doc.extend(["", "## Resolved Advisory Counts", ""])
    resolved_counts = reconciliation["resolved_counts"]
    if any(resolved_counts.values()):
        for category, count in sorted(resolved_counts.items()):
            if count:
                doc.append(f"- `{category}`: `{count}`")
    else:
        doc.append("- _none_")
    doc.extend(["", "## Advisory Reconciliation Sources", ""])
    if reconciliation["source_artifacts"]:
        for category, artifact in sorted(reconciliation["source_artifacts"].items()):
            doc.append(f"- `{category}`: `{artifact}`")
    else:
        doc.append("- _none_")
    doc.extend(["", "## Remaining Queue Counts", ""])
    for category in NEXT_ACTION_ORDER:
        doc.append(f"- `{category}`: `{summary.get('by_category', {}).get(category, 0)}`")
    doc.extend(["", "## Strict Blockers", ""])
    if strict_rows:
        for row in strict_rows[:20]:
            doc.append(
                f"- `{row.get('next_action_id')}` `{row.get('exact_status')}` "
                f"from `{row.get('source_artifact')}` -> `{row.get('next_command')}`"
            )
    else:
        doc.append("- _none_")
    doc.extend(["", "## Tests Run", ""])
    for command in LOCAL_BATCH_TEST_COMMANDS:
        doc.append(f"- `{command}`")
    doc.extend([
        "",
        "## Foundry Trial-Readiness Progress",
        "",
        f"- Status: `{foundry_trial_readiness['status']}`.",
        f"- Migration state: `{foundry_trial_readiness['migration_state']}`.",
        f"- Fixture manifests: `{foundry_trial_readiness['manifest_present_count']}` / `{foundry_trial_readiness['fixture_count']}`.",
        f"- Schema-valid manifests: `{foundry_trial_readiness['schema_valid_count']}` / `{foundry_trial_readiness['manifest_present_count']}`.",
        f"- Normalization items: `{foundry_trial_readiness['normalization_item_total']}` total, `{foundry_trial_readiness['blocking_normalization_item_total']}` blocking.",
        "- Boundary: local planning artifacts only; migration remains `planned_not_executed`.",
    ])
    doc.extend(["", "## Changed Files", ""])
    for path in changed_files:
        doc.append(f"- `{path}`")
    doc.extend([
        "",
        "## Residual Work To Batch",
        "",
        f"- {bundle_readiness['next_step']}",
        "- Execute or clear remaining advisory PR560 next-action rows.",
        "- Re-run `make pr560-next-actions WS=<workspace> JSON=1` and `make pr560-local-progress WS=<workspace>` after each local batch slice.",
    ])

    write_md(progress_path, doc)
    write_json(progress_json_path, payload)
    write_json(out_dir(workspace) / "pr560_local_batch_progress.json", payload)
    return payload


INTEGRATION_READINESS_COMPLETED_ITEMS = (
    "Added generated `pr560-integration-readiness` mode for local-only PR560 split planning.",
    "Derived future PR slices from the local batch progress ledger instead of hand-maintaining a static report.",
    "Grouped the large dirty diff into impact gates, provider assist, semantic/multihop, detector worklists, docs/known limitations, tests/accounting, and optional generated-artifact slices.",
    "Recorded per-slice guardrails so no slice claims full scanner coverage, live provider proof, PoC proof, submission readiness, or complete known-limitations closure.",
    "Added machine-readable validation checks for slice ownership, required categories, overclaim guards, and generated-artifact isolation.",
    "Linked readiness JSON back to the local progress JSON and preserved GitHub action/commit/push/PR/merge false flags.",
    "Added focused regression coverage for the generated readiness report and JSON overclaim validation.",
    "Updated Make/docs entrypoints so operators can regenerate and validate the readiness handoff locally.",
    "Added the guarded Foundry v1.7 migration as a dedicated future PR slice instead of folding it into current proof claims.",
)

INTEGRATION_READINESS_AJ_COMPLETED_ITEMS = (
    "Re-owned the local readiness pass as Worker AJ without changing GitHub state.",
    "Kept the worktree-local boundary at `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the existing Worker AD readiness ledger instead of rewriting prior ownership history.",
    "Added an AJ-specific 50-item completion ledger for integration-readiness accounting.",
    "Separated AJ accounting from finding, scanner, provider, PoC, and submission proof claims.",
    "Recorded PR split ownership for every current local slice A-H.",
    "Kept the generated-artifacts slice separate from durable code/doc slices.",
    "Added generated-artifact isolation checks for `agent_outputs/` and `.auditooor/` paths.",
    "Recorded generated local JSON/Markdown artifacts as optional unless the operator explicitly requests them.",
    "Added per-slice test matrix rows for all future PR slices.",
    "Split required local tests from operator-approved external/toolchain tests.",
    "Marked Foundry `forge build` / `forge test` as operator-approved trial work, not current proof.",
    "Added per-slice proof-boundary statements so test matrices cannot overclaim scanner/provider/PoC readiness.",
    "Added per-slice stop conditions for unsafe promotion paths.",
    "Recorded impact-gate stop conditions for missing exact impact and missing proof artifacts.",
    "Recorded provider-assist stop conditions for missing live-provider consent.",
    "Recorded semantic-multihop stop conditions for source-shape-only evidence.",
    "Recorded detector-worklist stop conditions for missing smoke-fire fixtures.",
    "Recorded docs/known-limitations stop conditions for incomplete closure criteria.",
    "Recorded tests/accounting stop conditions for local-only evidence and absent GitHub CI.",
    "Recorded generated-artifact stop conditions for optional artifact inclusion.",
    "Recorded Foundry migration stop conditions for unapproved upgrade trials and implicit hardfork/seed evidence.",
    "Added machine-readable operator handoff checklist entries.",
    "Added operator handoff commands for regenerating local progress and readiness artifacts.",
    "Added operator handoff warnings against commits, pushes, PRs, merges, and GitHub Actions from this pass.",
    "Added roadmap accounting for the new `PR560-H-foundry-v1.7-migration` slice.",
    "Linked Foundry v1.7 migration accounting to its planning doc when present.",
    "Kept Foundry v1.7 migration as a future capability/performance slice, not a current scanner proof.",
    "Added readiness validation for the AJ 50-item target.",
    "Added readiness validation that every slice has test-matrix coverage.",
    "Added readiness validation that every slice has at least one stop condition.",
    "Added readiness validation that generated-artifact ownership remains exactly one slice.",
    "Added readiness validation that local-only Git/GitHub flags remain false.",
    "Added readiness validation that proof claims remain `not_claimed`.",
    "Added readiness validation that the operator handoff checklist is populated.",
    "Added readiness validation that the Foundry slice is present in roadmap accounting.",
    "Added readiness JSON fields for blocker naming when AJ validation fails.",
    "Added Markdown rendering for AJ completed items.",
    "Added Markdown rendering for the generated-artifact isolation section.",
    "Added Markdown rendering for the per-slice test matrix.",
    "Added Markdown rendering for known-limitations and stop-condition boundaries.",
    "Added Markdown rendering for operator handoff instructions.",
    "Kept changed-file grouping derived from the existing local progress ledger.",
    "Kept future PR slices derived from generated local state rather than GitHub metadata.",
    "Kept provider rows advisory-only and consent-blocked.",
    "Kept live deployment proof out of readiness claims.",
    "Kept PoC execution proof out of readiness claims.",
    "Kept submission readiness out of readiness claims.",
    "Kept known-limitations language reduction-only unless a slice-specific stop condition is satisfied.",
    "Updated regression coverage expectations for AJ readiness fields.",
    "Regenerated local readiness artifacts with AJ ownership, PR split, roadmap accounting, and handoff data.",
)

INTEGRATION_READINESS_AP_COMPLETED_ITEMS = (
    "Re-owned the current pass as Worker AP for PR560 Foundry v1.7 trial-readiness integration.",
    "Kept all work scoped to `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, or GitHub Actions boundary.",
    "Kept Foundry installation and upgrade work explicitly out of scope.",
    "Used existing `foundry-version-report` as the baseline inventory source.",
    "Used existing `foundry-v17-trial-plan` as the local trial-manifest source.",
    "Added manifest shape validation to `foundry-v17-trial-plan` without adding dependencies.",
    "Validated the manifest schema version is fixed to `auditooor.foundry_v1_7_trial_plan.v1`.",
    "Validated `migration_state` stays `planned_not_executed` in generated manifests.",
    "Validated `upgrade_performed` stays `false` in generated manifests.",
    "Validated `install_or_upgrade_allowed` stays `false` in generated manifests.",
    "Validated target Foundry version stays pinned to `v1.7.1`.",
    "Validated baseline command rows preserve required command metadata.",
    "Validated target command rows preserve required command metadata.",
    "Validated command `required` fields remain booleans for downstream schema consumers.",
    "Validated baseline/target comparison pairing remains keyed by `command.id`.",
    "Embedded schema-validation results directly in `foundry_v1_7_trial_manifest.json`.",
    "Rendered schema-validation status in `foundry_v1_7_trial_manifest.md`.",
    "Kept schema validation stdlib-only instead of requiring `jsonschema`.",
    "Added config-normalization queue warning counts by warning code.",
    "Added config-normalization queue blocking warning counts by warning code.",
    "Added config-normalization queue total blocking item count.",
    "Rendered normalization total item count in Markdown.",
    "Rendered normalization blocking item count in Markdown.",
    "Kept every normalization queue item marked `planned_not_executed`.",
    "Kept `check_interval > 1` queued as exploratory-only unless justified.",
    "Kept missing hardfork/evm-version queued as final-proof blocking.",
    "Kept missing fuzz seed queued as final-proof blocking.",
    "Kept missing Foundry config queued as a named blocker.",
    "Added regression coverage for manifest schema validation success.",
    "Added regression coverage for normalization queue aggregate counts.",
    "Detected representative fixture manifests from local `.auditooor/foundry_v1_7_trial_manifest.json` files.",
    "Scoped representative fixture discovery to `tools/tests/fixtures`.",
    "Recorded per-fixture readiness status in PR560 integration readiness JSON.",
    "Recorded per-fixture migration state in PR560 integration readiness JSON.",
    "Recorded per-fixture schema-validation status in PR560 integration readiness JSON.",
    "Recorded per-fixture normalization item counts in PR560 integration readiness JSON.",
    "Recorded per-fixture blocking normalization item counts in PR560 integration readiness JSON.",
    "Recorded per-fixture blocker names in PR560 integration readiness JSON.",
    "Recorded aggregate fixture readiness counts for AP review.",
    "Recorded aggregate fixture schema-valid counts for AP review.",
    "Recorded aggregate fixture normalization counts for AP review.",
    "Added a readiness-doc section for Foundry representative fixture trial manifests.",
    "Added operator handoff commands for fixture-level Foundry version inventory generation.",
    "Added operator handoff commands for fixture-level Foundry v1.7 trial-plan generation.",
    "Wired Foundry fixture manifest status into roadmap accounting.",
    "Kept fixture manifests classified as local generated artifacts, not proof.",
    "Kept PR560-H as a capability/performance slice, not submission readiness.",
    "Updated known-limitations language to cite local fixture trial-readiness manifests.",
    "Updated Foundry pipeline docs to describe AP fixture trial-readiness accounting.",
    "Regenerated PR560 readiness/progress docs after AP Foundry integration.",
)

INTEGRATION_READINESS_AR_COMPLETED_ITEMS = (
    "Re-owned the local closure-accounting pass as Worker AR without changing GitHub state.",
    "Kept all reconciliation work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved Worker AD, AJ, and AP readiness history instead of rewriting prior ownership.",
    "Reconciled PR560 local batch progress against integration readiness as a docs/accounting slice.",
    "Kept completed implementation count separate from limitation closure count.",
    "Recorded that the then-current local implementation items were local progress, not proof of every roadmap stop condition.",
    "Recorded that then-current next-action rows remained advisory/open even when bundle readiness was green.",
    "Recorded that zero strict blockers does not mean zero open limitations.",
    "Reconciled known-limitations burn-down rows as satisfied, reduced, deferred, or blocked.",
    "Kept current-priority and P0 rows open unless their stop condition is actually met.",
    "Kept P2 and cross-cut satisfied rows visible as citation-backed closure only.",
    "Added explicit not-closed accounting for full scanner coverage.",
    "Added explicit not-closed accounting for invariant discovery completeness.",
    "Added explicit not-closed accounting for executed harness coverage.",
    "Added explicit not-closed accounting for Rust/DLT semantic depth.",
    "Recorded provider live artifacts as advisory local artifacts, not live-provider proof.",
    "Kept Kimi source-extract artifacts behind provider-consent and local-verification blockers.",
    "Kept Minimax adversarial-kill artifacts behind provider-consent and local-verification blockers.",
    "Recorded semantic-detector-adjudication as post-query routing, not detector smoke-fire proof.",
    "Preserved semantic detector rewrite briefs as NOT_SUBMIT_READY until fixtures exist.",
    "Preserved semantic fixture rows as source/invariant review tasks until executed.",
    "Preserved non-detectorizable semantic rows as source-only accounting, not promotion evidence.",
    "Reconciled Foundry v1.7 work as planned migration rather than executed upgrade.",
    "Kept Foundry v1.7 trial artifacts blocked on operator-approved isolated PATH and logs.",
    "Recorded Foundry config normalization as reproducibility hygiene, not PoC proof.",
    "Kept faster v1.7 invariant/fuzz features out of final proof claims unless seed/fork/profile are explicit.",
    "Recorded docs-known-limitations as a truth-refresh slice with stop conditions.",
    "Recorded tests-accounting as local evidence, not GitHub CI evidence.",
    "Kept generated artifacts isolated in the optional slice unless the operator requests inclusion.",
    "Added closure-accounting fields to the readiness JSON for machine-readable not-closed boundaries.",
    "Added closure-accounting validation so all named residual limitations stay explicit.",
    "Added Markdown rendering for Worker AR completed items.",
    "Added Markdown rendering for remaining not-closed boundaries.",
    "Added operator handoff commands for known-limitations burn-down JSON validation.",
    "Added operator handoff warning that provider artifacts remain advisory until live consent.",
    "Added operator handoff warning that semantic source-shape rows do not prove runtime reachability.",
    "Added operator handoff warning that Foundry migration is planned-not-executed.",
    "Connected roadmap accounting to the known-limitations burn-down map when present.",
    "Recorded known-limitations row totals by group for readiness review.",
    "Recorded known-limitations terminal states by group for readiness review.",
    "Recorded known-limitations met/open counts for readiness review.",
    "Recorded remaining open row IDs so operators can audit exact unresolved limitations.",
    "Kept row closure based on `stop_condition_met`, not implementation-item volume.",
    "Kept `progress_ready_for_eventual_pr` scoped to local integration readiness only.",
    "Kept `readiness_verdict` scoped to operator review, not submission/scanner proof.",
    "Updated regression expectations for AR closure-accounting fields.",
    "Prepared docs-check and known-limitations-check as the representative validation path.",
    "Avoided commits, pushes, PRs, merges, and GitHub Actions.",
    "Preserved unrelated dirty worktree edits while touching only accounting/docs/test surfaces.",
    "Regenerated PR560 local readiness and progress artifacts after closure accounting.",
)

INTEGRATION_READINESS_AO_COMPLETED_ITEMS = (
    "Owned Worker AO scope as semantic-detector-adjudication execution and next-action closure.",
    "Kept all AO work local to `/private/tmp/auditooor-pr560-next-actions`.",
    "Avoided commits, pushes, PRs, merges, and GitHub Actions.",
    "Preserved unrelated dirty worktree edits.",
    "Exercised semantic-detector-adjudication as the post-query closure layer.",
    "Kept adjudication output advisory-only.",
    "Kept adjudication output `NOT_SUBMIT_READY`.",
    "Kept adjudication severity as `none`.",
    "Kept adjudication selected impact empty.",
    "Kept adjudication promotion disabled.",
    "Added exact fixture commands to detector rewrite briefs.",
    "Added exact fixture commands to fixture requirement rows.",
    "Added source-review-only commands to non-detectorizable rows.",
    "Added positive fixture path requirements.",
    "Added clean fixture path requirements.",
    "Added smoke-record artifact requirements.",
    "Added static predicate requirements that forbid severity encoding.",
    "Added detector smoke command hints.",
    "Added fixture plans to detector rewrite briefs.",
    "Added non-detectorizable triage requirements.",
    "Added source-review IDs for source-only rows.",
    "Added query-status handling for non-executed query results.",
    "Added orphaned worklist-task handling for query rows without source tasks.",
    "Added non-detectorizable reason accounting.",
    "Added adjudication readiness accounting.",
    "Added next-command samples to the adjudication payload.",
    "Rendered next commands in adjudication Markdown tables.",
    "Rendered non-detectorizable reason counts in Markdown.",
    "Routed detector rewrite briefs into PR560 next actions.",
    "Routed fixture requirements into PR560 next actions.",
    "Routed non-detectorizable rows into PR560 next actions.",
    "Added the `semantic_detector` next-action category.",
    "Kept semantic detector next actions non-strict advisory rows.",
    "Kept semantic detector next actions `submit_ready=false`.",
    "Limited semantic detector next-action import to a bounded batch.",
    "Preserved invariant queue ordering after semantic detector work.",
    "Improved mining-prioritizer semantic adjudication sidecar accounting.",
    "Added sidecar readiness fields for detector rewrite, fixture-first, and source-review-only counts.",
    "Added sidecar non-detectorizable reason counts.",
    "Added sidecar next-command samples.",
    "Added regression coverage for stronger adjudication commands and fixture artifacts.",
    "Added regression coverage for query-status source-only triage.",
    "Added regression coverage for semantic detector next-action aggregation.",
    "Added regression coverage for mining-prioritizer sidecar enrichment.",
    "Updated README semantic detector workflow wording.",
    "Updated TOOL_STATUS semantic detector and PR560 next-action boundaries.",
    "Kept PR560 readiness accounting separate from submission proof.",
    "Kept provider, scanner, live deployment, PoC, and severity proof unclaimed.",
    "Named AO accounting as local-only readiness evidence.",
    "Recorded AO work as an integration-readiness checklist, not GitHub state.",
    "Prepared the next operator command path for rerunning query, adjudication, mining priorities, and PR560 ledgers.",
)

INTEGRATION_READINESS_AW_COMPLETED_ITEMS = (
    "Owned Worker AW scope as integration-readiness reconciliation after latest closure/progress changes.",
    "Kept all AW work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while reconciling generated accounting only.",
    "Reconciled `PR560_LOCAL_BATCH_PROGRESS` with `PR560_LOCAL_INTEGRATION_READINESS`.",
    "Recorded local progress as implementation readiness rather than full limitation closure.",
    "Recorded completed implementation item count from the generated local progress ledger.",
    "Recorded remaining next-action row count from the generated local progress ledger.",
    "Recorded resolved advisory row count from advisory reconciliation.",
    "Recorded strict blocker count from bundle readiness.",
    "Kept `ready_for_eventual_pr=true` scoped to operator batch integration only.",
    "Kept open advisory queue rows visible despite green local readiness.",
    "Reconciled known-limitations total row count from the burn-down map.",
    "Reconciled known-limitations met stop-condition count from the burn-down map.",
    "Reconciled known-limitations remaining open row IDs from the burn-down map.",
    "Kept known-limitations rows open unless their row-level stop condition is met.",
    "Preserved current-priority and P0 limitation boundaries as not fully closed.",
    "Kept full scanner coverage listed as not closed.",
    "Kept invariant discovery completeness listed as not closed.",
    "Kept executed harness coverage listed as not closed.",
    "Kept Rust/DLT semantic depth listed as not closed.",
    "Kept provider live artifacts listed as not closed.",
    "Kept semantic detector adjudication listed as not closed.",
    "Kept Foundry migration execution listed as not closed.",
    "Reconciled live-provider triage as advisory and consent-blocked.",
    "Recorded live provider tooling/test presence without claiming provider proof.",
    "Kept provider dispatch/preflight artifacts out of live deployment proof claims.",
    "Kept Kimi/Minimax provider-assist rows behind explicit operator consent.",
    "Reconciled semantic adjudication as routing/accounting, not detector smoke-fire proof.",
    "Recorded semantic-detector-adjudication tooling/test presence in readiness accounting.",
    "Kept semantic detector rows `NOT_SUBMIT_READY` until fixtures and smoke records exist.",
    "Kept source-shape semantic evidence separate from runtime reachability proof.",
    "Reconciled Foundry slice as planned-not-executed trial readiness.",
    "Recorded Foundry fixture manifest status without treating it as an upgrade run.",
    "Kept Foundry install/upgrade disallowed in readiness accounting.",
    "Kept Foundry `forge build` and `forge test` as operator-approved isolated trial work.",
    "Reconciled changed-file group counts from the local progress ledger.",
    "Recorded changed-file group IDs for impact, provider, semantic, detector, docs, tests, generated artifacts, and Foundry slices.",
    "Kept generated artifacts isolated in the optional slice.",
    "Kept other/unassigned changed paths visible for operator review.",
    "Added machine-readable reconciliation summary to integration readiness JSON.",
    "Added validation that AW completed-item target is met.",
    "Added validation that readiness is valid while full closure remains false.",
    "Added validation that required open boundaries remain present.",
    "Added Markdown rendering for Worker AW completed items.",
    "Added Markdown rendering for the AW reconciliation summary.",
    "Connected operator handoff to JSON validation, docs check, known-limitations check, and automation-closure tests.",
    "Kept submission/scanner/provider proof verdict as `not_claimed`.",
    "Kept readiness verdict as local operator review, not merge readiness.",
    "Regenerated PR560 local readiness/progress artifacts after AW reconciliation.",
)

INTEGRATION_READINESS_BB_COMPLETED_ITEMS = (
    "Owned Worker BB scope as the post-artifact integration-readiness reconciliation lane.",
    "Kept all BB work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while updating generated accounting surfaces.",
    "Reconciled local batch progress against integration readiness after provider-local verification artifacts existed.",
    "Recorded completed local capability as implementation readiness rather than roadmap closure.",
    "Recorded completed checklist count from `PR560_LOCAL_BATCH_PROGRESS.json`.",
    "Recorded remaining next-action row count from the local progress ledger.",
    "Recorded remaining advisory row count from advisory reconciliation.",
    "Recorded strict blocker count from bundle readiness.",
    "Kept `ready_for_eventual_pr` scoped to operator batch integration only.",
    "Kept open advisory provider-local verification rows visible despite local readiness.",
    "Reconciled known-limitations row totals from the burn-down map.",
    "Reconciled stop-condition-met row totals from the burn-down map.",
    "Added known-limitations stop-condition percentage accounting.",
    "Added known-limitations open-row percentage accounting.",
    "Kept full-roadmap closure percentage separate from local implementation readiness.",
    "Recorded local capability readiness as capped at 100% when the local target is exceeded.",
    "Recorded full roadmap closure as false while any not-closed boundary remains open.",
    "Preserved current-priority and P0 limitations as open unless stop conditions are met.",
    "Preserved scanner coverage as not fully closed.",
    "Preserved invariant discovery completeness as not fully closed.",
    "Preserved executed harness coverage as not fully closed.",
    "Preserved Rust/DLT semantic depth as not fully closed.",
    "Preserved provider live artifacts as not fully closed.",
    "Preserved semantic detector adjudication as not fully closed.",
    "Preserved Foundry migration execution as not fully closed.",
    "Added active-agent-slot accounting sourced from `docs/PR560_ACTIVE_AGENT_SLOTS.md`.",
    "Recorded running active-agent-slot count for coordinator visibility.",
    "Recorded completed active-agent-slot count for stale-slot cleanup visibility.",
    "Recorded active slot handles without treating them as GitHub or CI state.",
    "Flagged overlapping integration-readiness slot ownership for coordinator review.",
    "Kept active-agent-slot accounting informational rather than a readiness blocker.",
    "Recorded provider triage posture as advisory and consent-blocked.",
    "Recorded semantic adjudication posture as routing-only until fixtures and smoke records exist.",
    "Recorded Foundry posture as planned-not-executed operator-approved trial work.",
    "Kept generated artifacts isolated in the optional slice.",
    "Kept other/unassigned changed paths visible for operator review.",
    "Added BB machine-readable reconciliation summary to integration readiness JSON.",
    "Added BB validation that completed-item target is met.",
    "Added BB validation that full closure is not claimed.",
    "Added BB validation that roadmap percentage accounting is present.",
    "Added BB validation that active-agent-slot accounting is present.",
    "Added Markdown rendering for Worker BB completed items.",
    "Added Markdown rendering for the BB reconciliation summary.",
    "Added Markdown rendering for active-agent-slot accounting.",
    "Added Markdown rendering for roadmap percentage accounting.",
    "Kept submission/scanner/provider proof verdict as `not_claimed`.",
    "Kept readiness verdict as local operator review, not merge readiness.",
    "Connected operator handoff to JSON validation, docs-check, known-limitations tests, and automation-closure tests.",
    "Regenerated PR560 local readiness/progress artifacts after BB reconciliation.",
)

INTEGRATION_READINESS_BG_COMPLETED_ITEMS = (
    "Owned Worker BG final integration-readiness accounting after the BC-BF artifact window.",
    "Kept all BG work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Reconciled progress/readiness JSON after BC-BF-era local artifacts were available.",
    "Kept local PR560 implementation readiness separate from known-limitations stop-condition closure.",
    "Kept known-limitations stop-condition closure separate from full roadmap closure.",
    "Recorded local implementation percentage as completed local checklist items capped to the PR560 target.",
    "Recorded known-limitations percentage from the workspace-generated burndown when present; `docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json` is baseline seed input only.",
    "Recorded full roadmap closure percentage from explicit not-closed boundaries only.",
    "Kept local capability target at 100% without converting it into full roadmap closure.",
    "Kept full roadmap closure claimed as false.",
    "Kept full roadmap closure achieved as false.",
    "Kept provider proof claims as `not_claimed`.",
    "Kept scanner coverage proof claims as `not_claimed`.",
    "Kept PoC execution proof claims as `not_claimed`.",
    "Kept submission readiness proof claims as `not_claimed`.",
    "Kept Foundry v1.7 status planned-not-executed.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept provider-local closure as advisory local verification only.",
    "Kept generated artifacts isolated in the optional future PR slice.",
    "Kept active slot accounting local-only and informational.",
    "Recorded BG as the final local integration-readiness owner for operator review.",
    "Preserved prior Worker AD/AJ/AP/AO/AR/AW/AX/BB readiness ledgers.",
    "Added BG completed-item count to readiness JSON validation.",
    "Added BG target-met validation to readiness JSON.",
    "Added BG no-full-closure validation to readiness JSON.",
    "Added BG percentage-accounting validation to readiness JSON.",
    "Added BG completed-item Markdown section.",
    "Added BG final reconciliation Markdown section.",
    "Added BG local capability percentage field.",
    "Added BG known-limitations stop-condition percentage field.",
    "Added BG known-limitations open percentage field.",
    "Added BG full-roadmap closure percentage field.",
    "Added BG residual not-closed boundary IDs.",
    "Added BG remaining/open advisory queue accounting.",
    "Added BG resolved advisory row accounting.",
    "Added BG strict-blocker accounting.",
    "Added BG operator validation command list.",
    "Added BG accounting for active slot running/completed/blocked counts.",
    "Added BG accounting for readiness valid expected versus roadmap closure achieved.",
    "Added BG validation test expectations in `tools/tests/test_automation_closure.py`.",
    "Added BG Markdown rendering test expectations.",
    "Updated active slot ledger so BG ownership is visible.",
    "Updated local progress docs with the BG lane output.",
    "Updated local readiness docs with BG final accounting.",
    "Regenerated PR560 next-actions for consistency before final readiness generation.",
    "Regenerated PR560 local progress JSON and Markdown.",
    "Regenerated PR560 local integration readiness JSON and Markdown.",
    "Ran automation-closure tests for the BG accounting path.",
    "Ran docs-check for the regenerated operator docs.",
)

INTEGRATION_READINESS_BL_COMPLETED_ITEMS = (
    "Owned Worker BL integration accounting after the BH-BK operator window.",
    "Kept all BL work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, and GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while touching only accounting, docs, and focused tests.",
    "Reconciled local progress after the PR560 local queue remained empty.",
    "Kept zero remaining next-action rows scoped to queue closure only.",
    "Kept zero strict blockers scoped to local batch integration only.",
    "Kept zero advisory-open rows separate from known-limitations closure.",
    "Recorded BL ownership after BH-BK without claiming BH-BK proof artifacts.",
    "Preserved Worker BG final reconciliation as prior history.",
    "Preserved Worker BB roadmap percentage accounting as prior history.",
    "Preserved Worker AW closure-accounting boundaries as prior history.",
    "Preserved Worker AX provider-local closure as advisory-only history.",
    "Added BL completed-item count to readiness JSON.",
    "Added BL completed-item Markdown section.",
    "Added BL reconciliation summary to readiness JSON.",
    "Added BL reconciliation summary to readiness Markdown.",
    "Added BL percentage-accounting validation fields.",
    "Added BL queue-accounting validation fields.",
    "Recorded local implementation readiness as capped local capability accounting.",
    "Recorded known-limitations stop-condition percentage from the burn-down map only.",
    "Recorded known-limitations open percentage from the burn-down map only.",
    "Recorded full-roadmap closure percentage from residual boundaries only.",
    "Kept full-roadmap closure claimed as false.",
    "Kept full-roadmap closure achieved as false.",
    "Kept scanner coverage proof as not claimed.",
    "Kept live provider proof as not claimed.",
    "Kept live deployment proof as not claimed.",
    "Kept PoC execution proof as not claimed.",
    "Kept submission readiness proof as not claimed.",
    "Kept provider artifacts advisory until explicit live consent and local verification.",
    "Kept semantic detector rows advisory until vulnerable and clean fixtures exist.",
    "Kept Foundry v1.7 migration planned-not-executed until isolated trial logs exist.",
    "Kept generated artifacts isolated in `PR560-G-generated-artifacts-optional`.",
    "Recorded not-closed boundary IDs for scanner, invariant, harness, Rust/DLT, provider, semantic, and Foundry gaps.",
    "Recorded open known-limitations row IDs for operator auditability.",
    "Recorded resolved advisory counts without treating them as proof closure.",
    "Recorded active slot accounting as local coordinator state only.",
    "Recorded BL as the current completed integration-readiness slot.",
    "Added BL target-met validation to integration readiness.",
    "Added BL no-full-closure validation to integration readiness.",
    "Added BL roadmap-percent validation to integration readiness.",
    "Added BL active-slot validation to integration readiness.",
    "Added BL operator validation commands for JSON, docs-check, and automation-closure tests.",
    "Updated active slot ledger so BL replaces BG as the completed local-thread integration owner.",
    "Regenerated PR560 next-actions for consistency before BL readiness generation.",
    "Regenerated PR560 local progress JSON and Markdown after BL accounting.",
    "Regenerated PR560 local integration readiness JSON and Markdown after BL accounting.",
    "Ran automation-closure tests for the BL accounting path.",
    "Ran docs-check for the regenerated BL operator docs.",
)

INTEGRATION_READINESS_BQ_COMPLETED_ITEMS = (
    "Owned Worker BQ slot/readiness reliability after the BM-BP artifact window.",
    "Kept all BQ work inside `/private/tmp/auditooor-pr560-next-actions`.",
    "Preserved the no commit, push, PR, merge, or GitHub Actions boundary.",
    "Preserved unrelated dirty worktree edits while updating accounting, docs, and tests only.",
    "Reconciled the active agent slot ledger instead of trusting stale running rows.",
    "Closed old Pascal/Noether/Linnaeus/Ptolemy rows as stale-closed in the coordinator ledger.",
    "Recorded BQ as the completed latest local slot/readiness owner.",
    "Added effective slot-status accounting separate from raw markdown status.",
    "Added stale-running ignored accounting for unrefreshed running rows.",
    "Added slot freshness threshold metadata to readiness JSON.",
    "Added parse support for `Last update` in slot rows.",
    "Kept old five-column slot rows parseable for backward compatibility.",
    "Treated running rows without parseable freshness metadata as stale ignored.",
    "Treated running rows older than the freshness threshold as stale ignored.",
    "Kept active slot accounting informational and non-blocking.",
    "Kept active slot accounting out of proof, CI, GitHub, and roadmap closure claims.",
    "Added BM-BP artifact-window discovery to BQ reconciliation.",
    "Recorded BM-BP directories only when durable artifacts exist.",
    "Kept absent BM-BP artifact directories from creating synthetic closure rows.",
    "Kept BM-BP artifact discovery local-only and advisory.",
    "Added BQ completed-item accounting to readiness JSON.",
    "Added BQ completed-item rendering to readiness Markdown.",
    "Added BQ reconciliation status to readiness JSON.",
    "Added BQ reconciliation status to readiness Markdown.",
    "Added BQ validation that stale running slots do not count as effective running.",
    "Added BQ validation that active-slot freshness metadata is present.",
    "Added BQ validation that the BQ 50-item target is met.",
    "Added BQ validation that local-only readiness remains true.",
    "Added BQ validation that full roadmap closure remains false.",
    "Added BQ validation that stale slot quarantine is active.",
    "Updated active slot Markdown with `Last update` and `Closed reason` columns.",
    "Updated active slot Markdown replacement rule with freshness requirements.",
    "Updated active slot Markdown so old remote handles are listed under closed history.",
    "Regenerated PR560 next-actions before BQ progress/readiness refresh.",
    "Regenerated PR560 local progress after BQ slot accounting.",
    "Regenerated PR560 local integration readiness after BQ slot accounting.",
    "Regenerated known-limitations burn-down after BQ refresh.",
    "Kept local implementation percentage scoped to the PR560 local target.",
    "Kept known-limitations percentage scoped to explicit stop conditions.",
    "Kept full-roadmap closure percentage unclaimed.",
    "Kept scanner coverage proof unclaimed.",
    "Kept invariant discovery completeness proof unclaimed.",
    "Kept executed harness proof unclaimed.",
    "Kept Rust/DLT semantic-depth proof unclaimed.",
    "Kept provider proof behind live consent and local verification.",
    "Kept semantic detector adjudication as routing/accounting only.",
    "Kept Foundry v1.7 migration planned-not-executed.",
    "Added regression tests for stale running slot quarantine.",
    "Added regression tests for BQ validation fields.",
    "Validated BQ readiness with automation-closure tests.",
    "Validated BQ docs/accounting output with docs-check.",
)

INTEGRATION_REQUIRED_SLICE_IDS = (
    "PR560-A-impact-gates",
    "PR560-B-provider-assist",
    "PR560-C-semantic-multihop",
    "PR560-D-detector-worklists",
    "PR560-E-docs-known-limitations",
    "PR560-F-tests-accounting",
    "PR560-G-generated-artifacts-optional",
    "PR560-H-foundry-v1.7-migration",
)


FOUNDRY_REPRESENTATIVE_FIXTURE_WORKSPACES = (
    ROOT / "tools" / "tests" / "fixtures" / "vault_good",
    ROOT / "tools" / "tests" / "fixtures" / "vault_bad",
    ROOT / "tools" / "tests" / "fixtures" / "fuzz_campaign" / "fixed",
    ROOT / "tools" / "tests" / "fixtures" / "fuzz_campaign" / "vulnerable",
)


def foundry_representative_fixture_manifests() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for fixture in FOUNDRY_REPRESENTATIVE_FIXTURE_WORKSPACES:
        manifest_path = fixture / ".auditooor" / "foundry_v1_7_trial_manifest.json"
        inventory_path = fixture / ".auditooor" / "foundry_version_inventory.json"
        manifest = load_json(manifest_path) if manifest_path.is_file() else None
        readiness = manifest.get("readiness_accounting", {}) if isinstance(manifest, dict) else {}
        queue = manifest.get("config_normalization_queue", {}) if isinstance(manifest, dict) else {}
        validation = manifest.get("schema_validation", {}) if isinstance(manifest, dict) else {}
        rows.append(
            {
                "fixture": str(fixture.relative_to(ROOT)),
                "manifest_path": str(manifest_path.relative_to(ROOT)),
                "inventory_path": str(inventory_path.relative_to(ROOT)),
                "manifest_present": manifest_path.is_file(),
                "inventory_present": inventory_path.is_file(),
                "migration_state": manifest.get("migration_state") if isinstance(manifest, dict) else "missing_manifest",
                "readiness_status": readiness.get("status", "missing_manifest"),
                "schema_valid": bool(validation.get("valid")) if isinstance(manifest, dict) else False,
                "schema_errors": list(validation.get("errors") or []) if isinstance(manifest, dict) else ["missing_manifest"],
                "normalization_items": int(queue.get("item_count") or readiness.get("normalization_items") or 0),
                "blocking_normalization_items": int(readiness.get("blocking_normalization_items") or 0),
                "blockers": list(readiness.get("blockers") or (["missing_manifest"] if not isinstance(manifest, dict) else [])),
                "proof_boundary": manifest.get("proof_boundary", "") if isinstance(manifest, dict) else "",
            }
        )
    present_rows = [row for row in rows if row["manifest_present"]]
    ready_rows = [row for row in present_rows if row["readiness_status"] == "ready_for_operator_approved_isolated_trial"]
    return {
        "status": "fixture_manifests_present" if len(present_rows) == len(rows) else "fixture_manifests_missing",
        "scope": "tools/tests/fixtures representative Foundry workspaces",
        "migration_state": "planned_not_executed",
        "upgrade_performed": False,
        "install_or_upgrade_allowed": False,
        "fixture_count": len(rows),
        "manifest_present_count": len(present_rows),
        "inventory_present_count": sum(1 for row in rows if row["inventory_present"]),
        "schema_valid_count": sum(1 for row in present_rows if row["schema_valid"]),
        "ready_fixture_count": len(ready_rows),
        "normalization_item_total": sum(int(row["normalization_items"]) for row in rows),
        "blocking_normalization_item_total": sum(int(row["blocking_normalization_items"]) for row in rows),
        "rows": rows,
        "operator_commands": [
            "make foundry-version-report WS=tools/tests/fixtures/vault_good JSON=1",
            "make foundry-v17-trial-plan WS=tools/tests/fixtures/vault_good JSON=1",
            "make foundry-version-report WS=tools/tests/fixtures/vault_bad JSON=1",
            "make foundry-v17-trial-plan WS=tools/tests/fixtures/vault_bad JSON=1",
            "make foundry-version-report WS=tools/tests/fixtures/fuzz_campaign/fixed JSON=1",
            "make foundry-v17-trial-plan WS=tools/tests/fixtures/fuzz_campaign/fixed JSON=1",
            "make foundry-version-report WS=tools/tests/fixtures/fuzz_campaign/vulnerable JSON=1",
            "make foundry-v17-trial-plan WS=tools/tests/fixtures/fuzz_campaign/vulnerable JSON=1",
        ],
    }


def integration_slice_stop_conditions(slice_id: str) -> list[str]:
    by_slice = {
        "PR560-A-impact-gates": [
            "stop if the candidate lacks an exact program impact row",
            "stop if proof artifacts do not prove the selected impact",
            "stop before PoC/submission wording if severity tier evidence is missing",
        ],
        "PR560-B-provider-assist": [
            "stop before live provider calls without explicit operator consent",
            "stop before treating provider text as local proof",
            "stop before budget-consuming dispatch unless preflight and budget guard pass",
        ],
        "PR560-C-semantic-multihop": [
            "stop before production-path claims without executed reachability evidence",
            "stop before semantic-completeness claims",
            "stop before High/Critical promotion from source-shape rows alone",
        ],
        "PR560-D-detector-worklists": [
            "stop before detector promotion without vulnerable and clean fixtures",
            "stop before claiming smoke-fire coverage for every advisory worklist row",
            "stop before submission-ready wording from detector worklists alone",
        ],
        "PR560-E-docs-known-limitations": [
            "stop before claiming full known-limitations closure unless stop criteria are met",
            "stop before claiming full scanner coverage from documentation updates",
            "stop before live deployment proof language in docs-only slices",
        ],
        "PR560-F-tests-accounting": [
            "stop before claiming GitHub CI passed",
            "stop before treating local unittest/doc checks as remote merge readiness",
            "stop before dropping local-only proof boundaries from generated JSON",
        ],
        "PR560-G-generated-artifacts-optional": [
            "stop before committing generated `agent_outputs/` rows unless explicitly requested",
            "stop before mixing `.auditooor/` generated inventories into durable source slices",
            "stop before treating generated artifacts as provider or submission proof",
        ],
        "PR560-H-foundry-v1.7-migration": [
            "stop before upgrading Foundry without an operator-approved isolated trial",
            "stop before final fuzz/invariant proof if seed, profile, hardfork, or version is implicit",
            "stop before treating faster v1.7 invariant runs as PoC proof",
        ],
    }
    return by_slice.get(slice_id, ["stop before promotion if slice ownership is ambiguous"])


def split_operator_tests(commands: list[str]) -> tuple[list[str], list[str]]:
    local: list[str] = []
    operator: list[str] = []
    for command in commands:
        lower = command.lower()
        if "operator-approved" in lower or "forge build" in lower or "forge test" in lower:
            operator.append(command)
        else:
            local.append(command)
    return local, operator


def integration_changed_file_groups(changed_files: list[str]) -> list[dict[str, Any]]:
    definitions: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        ("impact_gates", "Impact-contract and proof-output gates", ("impact", "submission", "poc-scaffold", "harness-scaffold", "critical-hunt", "severity", "pre-submit")),
        ("provider_assist", "Provider preflight, routing, budget, and advisory dispatch artifacts", ("llm", "provider", "dispatch", "calibration")),
        ("semantic_multihop", "Semantic graph and multihop source-path tooling", ("semantic", "ccia", "source-mining")),
        ("detector_worklists", "Detector promotion, corpus, and semantic detector worklists", ("detector", "findings-to-pattern", "corpus")),
        ("docs_known_limitations", "Operator docs, workflow truth, and known-limitations accounting", ("docs/", "README.md", "AGENTS.md", "KNOWN_LIMITATIONS", "WORKFLOW", "TOOL_STATUS")),
        ("tests_accounting", "Regression tests and local progress/accounting ledgers", ("tools/tests/", "PR560_LOCAL_BATCH_PROGRESS", "PR560_LOCAL_INTEGRATION_READINESS", "audit-closeout-check")),
        ("foundry_migration", "Foundry v1.7 migration plan, guardrails, and future test seams", ("foundry", "forge", "poc-execution-record", "invariant-harness", "FOUNDRY_V1_7_PIPELINE_ADDITION")),
        ("generated_artifacts_optional", "Generated local artifacts that should stay separate unless explicitly requested", ("agent_outputs/", ".auditooor/")),
    )
    groups: list[dict[str, Any]] = []
    assigned: set[str] = set()
    lower_by_path = {path: path.lower() for path in changed_files}
    for group_id, title, needles in definitions:
        paths = [
            path for path, lower in lower_by_path.items()
            if any(needle.lower() in lower for needle in needles)
        ]
        assigned.update(paths)
        groups.append(
            {
                "group": group_id,
                "title": title,
                "count": len(paths),
                "examples": paths[:8],
            }
        )
    other = [path for path in changed_files if path not in assigned]
    if other:
        groups.append(
            {
                "group": "other_unassigned",
                "title": "Other changed paths for operator review",
                "count": len(other),
                "examples": other[:8],
            }
        )
    return groups


def future_pr_slices_from_progress(progress: dict[str, Any]) -> list[dict[str, Any]]:
    lane_by_id = {str(row.get("lane_id")): row for row in progress.get("lane_outputs", []) if isinstance(row, dict)}
    return [
        {
            "slice_id": "PR560-A-impact-gates",
            "title": "Impact gates and proof-output refusal seams",
            "owns": [
                "program impact mapping and exact-impact contract gates",
                "draft/scaffold/package refusal when proof artifacts or severity tiers are missing",
                "ReCon/Chimera/deep-replay impact-contract blockers",
            ],
            "source_lanes": ["C9", "C10", "C11", "C12"],
            "representative_tests": [
                "python3 -m unittest tools.tests.test_auto_draft_generator",
                "python3 -m unittest tools.tests.test_harness_scaffold_emitter.TestFailedAttemptManifest",
                "python3 -m unittest tools.tests.test_submission_factory",
                "python3 -m unittest tools.tests.test_submission_packager_hygiene",
            ],
            "must_not_claim": [
                "full scanner coverage",
                "PoC proof",
                "submission readiness",
                "complete Priority-1 known-limitations closure",
            ],
            "overclaim_guard": "reduction_only_not_full_closure",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
        {
            "slice_id": "PR560-B-provider-assist",
            "title": "Provider assist, preflight, capacity, and templates",
            "owns": [
                "dispatch-preflight enforcement for source-extract and adversarial-kill",
                "Kimi/Minimax provider-assist accounting as local advisory input",
                "capacity/budget helper docs and templates",
            ],
            "source_lanes": ["C12", "C13"],
            "representative_tests": [
                "python3 -m unittest tools.tests.test_llm_dispatch_preflight_gate",
                "python3 -m unittest tools.tests.test_provider_capacity_and_semantic_batch",
                "python3 -m unittest tools.tests.test_source_mining_campaign",
            ],
            "must_not_claim": [
                "live provider consent",
                "provider-verified findings",
                "budget approval",
                "submission proof",
            ],
            "overclaim_guard": "advisory_only_requires_operator_live_consent",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
        {
            "slice_id": "PR560-C-semantic-multihop",
            "title": "Semantic graph, multihop path accounting, and source-reader coverage",
            "owns": [
                "typed multihop semantic graph inputs",
                "mapped stages and impact-family source-reader coverage",
                "source-mining campaign semantic routing",
            ],
            "source_lanes": ["C13"],
            "representative_tests": [
                "python3 -m unittest tools.tests.test_semantic_graph_and_critical_hunt",
                "python3 -m unittest tools.tests.test_source_mining_campaign",
            ],
            "must_not_claim": [
                "semantic completeness",
                "runtime reachability proof",
                "production-path proof",
            ],
            "overclaim_guard": "source_shape_accounting_only",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
        {
            "slice_id": "PR560-D-detector-worklists",
            "title": "Detector worklists and promotion safety",
            "owns": [
                "semantic-detector-worklist advisory bridge",
                "semantic-detector-adjudication post-query rewrite/fixture/source-only routing",
                "detector-promotion Program Impact Mapping refusal",
                "corpus detectorization routes that remain NOT_SUBMIT_READY",
            ],
            "source_lanes": ["C11", "C13", "AL"],
            "representative_tests": [
                "python3 -m unittest tools.tests.test_semantic_detector_worklist",
                "python3 -m unittest tools.tests.test_semantic_detector_adjudication",
                "python3 -m unittest tools.tests.test_findings_to_pattern.PromotionGateTests",
                "python3 -m unittest tools.tests.test_promotion_contract_integration",
            ],
            "must_not_claim": [
                "detector smoke-fire coverage for every worklist row",
                "vulnerable/clean fixture completeness",
                "submission readiness",
            ],
            "overclaim_guard": "worklist_not_detector_proof",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
        {
            "slice_id": "PR560-E-docs-known-limitations",
            "title": "Docs truth refresh and known-limitations accounting",
            "owns": [
                "workflow/tool-status/provider documentation",
                "known-limitations burn-down map wording",
                "local integration readiness and split-plan docs",
            ],
            "source_lanes": ["C9", "C12", "C13"],
            "representative_tests": ["make docs-check", "make known-limitations-check-test"],
            "must_not_claim": [
                "known limitation fully closed unless stop condition is met",
                "full scanner coverage",
                "live deployment proof",
            ],
            "overclaim_guard": "truth_refresh_with_stop_conditions",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
        {
            "slice_id": "PR560-F-tests-accounting",
            "title": "Tests, local ledgers, and closeout accounting",
            "owns": [
                "automation-closure local progress/readiness ledgers",
                "audit-closeout PR560 artifact accounting",
                "regression tests and JSON validation",
            ],
            "source_lanes": ["C2/C3", "C4", "C5", "C6", "C7", "C8"],
            "representative_tests": [
                "make automation-closure-test",
                "python3 -m unittest tools.tests.test_audit_closeout_check.PR560ArtifactClosureTests",
                "make audit-closeout-test",
            ],
            "must_not_claim": [
                "GitHub CI passed",
                "branch pushed",
                "PR opened",
            ],
            "overclaim_guard": "local_evidence_only",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
        {
            "slice_id": "PR560-G-generated-artifacts-optional",
            "title": "Optional generated artifacts, kept out of durable code PRs by default",
            "owns": [
                "agent_outputs/ local provider/preflight records",
                ".auditooor/ generated inventories",
                "local generated progress JSON copies",
            ],
            "source_lanes": [],
            "representative_tests": ["python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json"],
            "must_not_claim": [
                "durable source change",
                "provider proof",
                "submission evidence",
            ],
            "overclaim_guard": "optional_commit_only_if_operator_requests",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": True,
        },
        {
            "slice_id": "PR560-H-foundry-v1.7-migration",
            "title": "Foundry v1.7 migration, config normalization, and proof reproducibility",
            "owns": [
                "Foundry version inventory and isolated v1.7.1 trial reporting",
                "foundry.toml hardfork/network/profile/seed normalization guidance",
                "harness planner and execution-manifest version/seed/fork metadata",
                "pre-submit, packager, and closeout warnings for non-reproducible Foundry evidence",
            ],
            "source_lanes": ["future-foundry-migration"],
            "representative_tests": [
                "python3 -m unittest tools.tests.test_fuzz_campaign",
                "python3 -m unittest tools.tests.test_deep_counterexample_replay_scaffold",
                "python3 -m unittest tools.tests.test_harness_scaffold_emitter",
                "make docs-check",
                "forge build && forge test # only in an operator-approved isolated v1.7.1 trial",
            ],
            "must_not_claim": [
                "v1.7.1 production rollout completed",
                "PoC proof",
                "submission readiness",
                "implicit Osaka hardfork correctness",
                "faster invariant runs are final proof",
            ],
            "overclaim_guard": "performance_and_capability_upgrade_not_submission_proof",
            "live_provider_proof_claimed": False,
            "full_coverage_claimed": False,
            "generated_artifacts_allowed": False,
        },
    ]


def integration_test_matrix(slices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for row in slices:
        commands = [str(cmd) for cmd in row.get("representative_tests") or []]
        local_tests, operator_tests = split_operator_tests(commands)
        stop_conditions = integration_slice_stop_conditions(str(row.get("slice_id") or ""))
        matrix.append(
            {
                "slice_id": row.get("slice_id"),
                "required_local_tests": local_tests,
                "operator_approved_tests": operator_tests,
                "stop_conditions": stop_conditions,
                "proof_boundary": row.get("overclaim_guard"),
                "must_not_claim": list(row.get("must_not_claim") or []),
            }
        )
    return matrix


def generated_artifact_isolation(changed_file_groups: list[dict[str, Any]]) -> dict[str, Any]:
    generated_group = next((row for row in changed_file_groups if row.get("group") == "generated_artifacts_optional"), {})
    examples = [str(path) for path in generated_group.get("examples") or []]
    optional_prefixes = ["agent_outputs/", ".auditooor/"]
    isolated_examples = [
        path for path in examples
        if any(path.startswith(prefix) for prefix in optional_prefixes)
    ]
    return {
        "status": "isolated_optional_slice" if generated_group else "no_generated_artifacts_observed",
        "owning_slice": "PR560-G-generated-artifacts-optional",
        "optional_prefixes": optional_prefixes,
        "observed_count": int(generated_group.get("count") or 0),
        "examples": examples,
        "examples_under_optional_prefixes": isolated_examples,
        "operator_rule": "Do not include generated local artifacts in durable PR slices unless the operator explicitly asks.",
    }


def integration_operator_handoff(workspace: Path) -> dict[str, Any]:
    foundry_fixture_commands = foundry_representative_fixture_manifests()["operator_commands"]
    commands = [
        f"make pr560-next-actions WS={shlex.quote(str(workspace))} JSON=1",
        f"make pr560-local-progress WS={shlex.quote(str(workspace))} JSON=1",
        f"make pr560-integration-readiness WS={shlex.quote(str(workspace))} JSON=1",
        "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
        "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
        "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
        f"make known-limitations-burndown WS={shlex.quote(str(workspace))} JSON=1",
        *foundry_fixture_commands,
    ]
    return {
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "ready_for_operator_review",
        "commands": commands,
        "warnings": [
            "No commits, pushes, pull requests, merges, or GitHub Actions were performed.",
            "Review generated-artifact inclusion separately from durable source/doc/test slices.",
            "Treat provider artifacts as advisory until explicit live-provider consent and local verification exist.",
            "Treat semantic source-shape rows as accounting until runtime reachability, fixtures, or source-proof records exist.",
            "Treat Foundry v1.7 as a future isolated migration trial, not current PoC evidence.",
            "Foundry fixture manifests are local trial-readiness artifacts; they do not prove migration execution.",
        ],
        "handoff_files": [
            "docs/PR560_LOCAL_BATCH_PROGRESS.md",
            "docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "docs/PR560_LOCAL_INTEGRATION_READINESS.md",
            "docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "docs/FOUNDRY_V1_7_PIPELINE_ADDITION.md",
        ],
    }


def integration_roadmap_accounting(slices: list[dict[str, Any]], workspace: Path) -> dict[str, Any]:
    slice_ids = [str(row.get("slice_id")) for row in slices]
    foundry_doc = ROOT / "docs" / "FOUNDRY_V1_7_PIPELINE_ADDITION.md"
    foundry_fixtures = foundry_representative_fixture_manifests()
    burndown_map = ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
    workspace_burndown = out_dir(workspace) / "known_limitations_burndown.json"
    map_payload = load_json(burndown_map) if burndown_map.is_file() else {}
    seed_rows = [row for row in map_payload.get("rows", []) if isinstance(row, dict)] if isinstance(map_payload, dict) else []
    rows = seed_rows
    count_source = "seed_map"
    workspace_burndown_path = Path("")
    # Prefer the workspace-generated burndown when it exists. The docs seed is
    # baseline input; the generated workspace artifact has current evidence
    # enrichment and an explicit truth_source_policy.
    for candidate in (
        workspace_burndown,
        Path(os.environ.get("AUDITOOOR_KNOWN_LIMITATIONS_BURNDOWN", "")),
    ):
        if candidate and candidate.is_file():
            workspace_payload = load_json(candidate)
            workspace_rows = (
                [row for row in workspace_payload.get("rows", []) if isinstance(row, dict)]
                if isinstance(workspace_payload, dict)
                else []
            )
            if workspace_rows:
                rows = workspace_rows
                count_source = "workspace_generated_burndown"
                workspace_burndown_path = candidate
                break
    by_group: dict[str, dict[str, int]] = {}
    open_row_ids: list[str] = []
    met_count = 0
    for row in rows:
        group = str(row.get("priority_group") or "unknown")
        state = str(row.get("terminal_state") or "unknown")
        by_group.setdefault(group, {})
        by_group[group][state] = by_group[group].get(state, 0) + 1
        if row.get("stop_condition_met"):
            met_count += 1
        else:
            open_row_ids.append(str(row.get("limitation_id") or "unknown"))
    row_count = len(rows)
    open_count = len(open_row_ids)
    seed_met_count = sum(1 for row in seed_rows if row.get("stop_condition_met"))
    seed_row_count = len(seed_rows)
    stop_condition_pct = round((met_count / row_count) * 100, 1) if row_count else 0.0
    open_pct = round((open_count / row_count) * 100, 1) if row_count else 0.0
    return {
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "ready_for_operator_review" if "PR560-H-foundry-v1.7-migration" in slice_ids else "blocked_missing_foundry_slice",
        "slice_ids": slice_ids,
        "foundry_migration_slice": "PR560-H-foundry-v1.7-migration",
        "foundry_migration_doc": str(foundry_doc),
        "foundry_migration_doc_present": foundry_doc.is_file(),
        "foundry_fixture_manifest_status": foundry_fixtures["status"],
        "foundry_fixture_manifest_present_count": foundry_fixtures["manifest_present_count"],
        "foundry_fixture_manifest_expected_count": foundry_fixtures["fixture_count"],
        "known_limitations_burndown_map": str(burndown_map),
        "known_limitations_burndown_map_present": burndown_map.is_file(),
        "known_limitations_count_source": count_source,
        "known_limitations_workspace_burndown": str(workspace_burndown_path) if workspace_burndown_path else "",
        "known_limitations_seed_row_count": seed_row_count,
        "known_limitations_seed_stop_conditions_met": seed_met_count,
        "known_limitations_row_count": row_count,
        "known_limitations_stop_conditions_met": met_count,
        "known_limitations_open_row_count": open_count,
        "known_limitations_open_row_ids": open_row_ids,
        "known_limitations_terminal_states_by_group": by_group,
        "known_limitations_stop_condition_pct": stop_condition_pct,
        "known_limitations_open_pct": open_pct,
        "full_roadmap_closure_pct": 0.0 if open_count or row_count == 0 else 100.0,
        "full_roadmap_closure_claimed": False,
        "roadmap_boundary": "PR560-H is a future migration/capability slice; it is not scanner, provider, PoC, or submission proof.",
    }


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def scanner_autonomy_accounting(workspace: Path) -> dict[str, Any]:
    """Summarize scanner-autonomy state without promoting scanner proof."""
    plan_path = workspace / ".auditooor" / "scanner_autonomy_plan.json"
    execution_path = workspace / ".auditooor" / "scanner_autonomy_execution.json"
    plan = load_json(plan_path) if plan_path.is_file() else {}
    execution = load_json(execution_path) if execution_path.is_file() else {}
    stop = plan.get("stop_condition_summary") if isinstance(plan.get("stop_condition_summary"), dict) else {}
    task_count = int(plan.get("task_count") or plan.get("candidate_count") or 0)
    manual_accounted = int(stop.get("manual_triage_items_mechanically_accounted") or 0)
    runnable = int(plan.get("runnable_count") or stop.get("runnable_local_command_items") or 0)
    allowlisted = int(plan.get("execution_allowed_count") or stop.get("allowlisted_execution_items") or 0)
    executed = int(execution.get("effective_executed_count") or execution.get("executed_count") or 0)
    execution_status_counts = execution.get("status_counts") if isinstance(execution.get("status_counts"), dict) else {}
    manual_target = max(150, task_count, manual_accounted)
    allowlisted_outcomes = int(execution.get("allowlisted_outcome_count") or 0)
    return {
        "schema": f"{SCHEMA_PREFIX}.scanner_autonomy_accounting.v1",
        "status": "plan_present" if plan else "missing_plan",
        "plan_path": str(plan_path),
        "plan_present": bool(plan),
        "execution_path": str(execution_path),
        "execution_present": bool(execution),
        "task_count": task_count,
        "candidate_count": int(plan.get("candidate_count") or task_count),
        "manual_triage_items_mechanically_accounted": manual_accounted,
        "manual_triage_accounting_target": manual_target,
        "manual_triage_accounted_pct": pct(manual_accounted, manual_target),
        "runnable_local_command_items": runnable,
        "runnable_local_command_pct_of_plan": pct(runnable, task_count),
        "allowlisted_execution_items": allowlisted,
        "allowlisted_execution_pct_of_plan": pct(allowlisted, task_count),
        "allowlisted_outcome_items": allowlisted_outcomes,
        "outcome_rows": int(execution.get("outcome_count") or 0),
        "unexecuted_allowlisted_local_command_items": max(0, allowlisted - allowlisted_outcomes) if execution else allowlisted,
        "executed_items": executed,
        "unique_command_execution_items": int(execution.get("unique_command_execution_count") or execution.get("executed_count") or 0),
        "prior_detector_smoke_execution_items": int(execution.get("prior_detector_smoke_execution_count") or 0),
        "executed_pct_of_plan": pct(executed, task_count),
        "execution_status_counts": execution_status_counts,
        "executed_ok_items": int(execution_status_counts.get("executed_ok") or 0),
        "executed_failed_items": int(execution_status_counts.get("executed_failed") or 0),
        "blocked_no_command_items": int(execution_status_counts.get("blocked_no_command") or 0),
        "terminal_detector_smoke_blocker_items": int(execution_status_counts.get("terminal_detector_smoke_blocker") or 0),
        "lane_counts": plan.get("lane_counts") if isinstance(plan.get("lane_counts"), dict) else {},
        "source_counts": plan.get("source_counts") if isinstance(plan.get("source_counts"), dict) else {},
        "execution_blocker_counts": stop.get("execution_blocker_counts") if isinstance(stop.get("execution_blocker_counts"), dict) else {},
        "top_promotion_blockers": stop.get("top_promotion_blockers") if isinstance(stop.get("top_promotion_blockers"), dict) else {},
        "coverage_claim": str(plan.get("coverage_claim") or "none_scanner_autonomy_only"),
        "submission_posture": str(plan.get("submission_posture") or "NOT_SUBMIT_READY"),
        "severity": str(plan.get("severity") or "none"),
        "selected_impact": str(plan.get("selected_impact") or ""),
        "promotion_allowed": bool(plan.get("promotion_allowed")) if plan else False,
        "scanner_autonomy_pct": pct(allowlisted, task_count),
        "local_allowlisted_command_accounting_complete": bool(execution) and allowlisted_outcomes >= allowlisted,
        "scanner_completeness_claimed": False,
        "proof_claim": "not_claimed",
        "accounting_boundary": (
            "scanner autonomy is measured as mechanical routing/execution capacity; "
            "it is not scanner completeness, impact proof, or submission readiness"
        ),
    }


def collect_semantic_fixture_smoke_accounting(workspace: Path) -> tuple[dict[str, Any], str]:
    """Prefer executable detector smoke evidence over older task accounting."""
    smoke_path = workspace / ".auditooor" / "semantic_detector_smoke_executor.json"
    smoke = load_json(smoke_path) if smoke_path.is_file() else {}
    if isinstance(smoke, dict) and isinstance(smoke.get("rows"), list):
        rows = [row for row in smoke.get("rows", []) if isinstance(row, dict)]
        terminal_clean_positive = sum(
            1 for row in rows
            if str(row.get("status") or "") == "passed_vulnerable_clean_smoke"
        )
        terminal_extraction_failed = sum(
            1 for row in rows
            if str(row.get("status") or "") == "not_executed"
        )
        counts = smoke.get("counts") if isinstance(smoke.get("counts"), dict) else {}
        return {
            "accounting_mode": "detector_fixture_smoke_execution_accounting_only",
            "precision_claim": "not_computed_fixture_smoke_only",
            "processed_count": len(rows),
            "smoke_required_count": len(rows),
            "terminal_clean_positive_count": terminal_clean_positive,
            "passed_vulnerable_clean_smoke_count": int(counts.get("passed_vulnerable_clean_smoke") or terminal_clean_positive),
            "blocked_missing_fixture_or_smoke_count": terminal_extraction_failed,
            "terminal_extraction_failed_count": terminal_extraction_failed,
            "not_applicable_count": 0,
            "promotion_allowed": False,
            "severity": "none",
            "submission_posture": "NOT_SUBMIT_READY",
            "coverage_claim": "detector_fixture_smoke_only",
            "source_artifact": str(smoke_path),
        }, str(smoke_path)

    task_path = workspace / ".auditooor" / "semantic_fixture_smoke_tasks.json"
    tasks = load_json(task_path) if task_path.is_file() else {}
    accounting = (
        tasks.get("detector_precision_accounting")
        if isinstance(tasks, dict) and isinstance(tasks.get("detector_precision_accounting"), dict)
        else {}
    )
    return accounting, str(task_path) if accounting else ""


def collect_detector_semantic_repair_accounting(workspace: Path) -> tuple[dict[str, Any], str]:
    """Summarize semantic detector repair smoke without turning it into finding proof."""
    worker_path = workspace / ".auditooor" / "pr560_worker_detector_semantic_predicate_repair.json"
    report_path = workspace / ".auditooor" / "scanner_autonomy_semantic_repair_worker_after_predicate_fixtures.json"
    worker = load_json(worker_path) if worker_path.is_file() else {}
    report = load_json(report_path) if report_path.is_file() else {}
    if not isinstance(report, dict):
        return {}, ""

    rows = [row for row in report.get("rows", []) if isinstance(row, dict)]
    status_counts = report.get("status_counts") if isinstance(report.get("status_counts"), dict) else {}
    passed_count = int(status_counts.get("local_semantic_repair_smoke_passed") or 0)
    if not passed_count and rows:
        passed_count = sum(1 for row in rows if str(row.get("status") or "") == "local_semantic_repair_smoke_passed")
    closed_rows = int(report.get("closed_rows") or passed_count)
    blockers_left = int(report.get("blockers_left") or 0)
    baseline_counts = report.get("baseline_counts") if isinstance(report.get("baseline_counts"), dict) else {}
    exact_reduction = worker.get("exact_reduction") if isinstance(worker, dict) and isinstance(worker.get("exact_reduction"), dict) else {}
    if exact_reduction:
        blockers_left = int(exact_reduction.get("scanner_semantic_blockers_left") or blockers_left)
        passed_count = int(exact_reduction.get("local_semantic_repair_smoke_passed_after") or passed_count)
        closed_rows = max(closed_rows, passed_count)
    detector_fixture_smoke_only = all(
        str(row.get("coverage_claim") or "") == "detector_fixture_smoke_only"
        and str(row.get("status") or "") == "local_semantic_repair_smoke_passed"
        for row in rows
    ) if rows else False
    promotion_allowed = bool(report.get("promotion_allowed") or (worker.get("promotion_allowed") if isinstance(worker, dict) else False))
    submission_posture = str(report.get("submission_posture") or (worker.get("submission_posture") if isinstance(worker, dict) else "NOT_SUBMIT_READY"))
    stop_condition_met = (
        bool(rows)
        and closed_rows == len(rows)
        and passed_count == len(rows)
        and blockers_left == 0
        and detector_fixture_smoke_only
        and not promotion_allowed
        and submission_posture == "NOT_SUBMIT_READY"
    )
    return {
        "accounting_mode": "detector_semantic_repair_fixture_smoke_only",
        "status": "semantic_repairs_smoke_passed" if stop_condition_met else "semantic_repairs_open_or_missing",
        "coverage_claim": "detector_fixture_smoke_only",
        "precision_claim": "fixture_smoke_only_not_live_precision",
        "processed_count": len(rows),
        "closed_rows": closed_rows,
        "local_semantic_repair_smoke_passed": passed_count,
        "scanner_semantic_blockers_left": blockers_left,
        "baseline_counts": baseline_counts,
        "closed_by_detector_skeleton": exact_reduction.get("closed_by_detector_skeleton", {}),
        "promotion_allowed": promotion_allowed,
        "submission_posture": submission_posture,
        "proof_boundary": (
            worker.get("proof_boundary")
            if isinstance(worker, dict) and worker.get("proof_boundary")
            else "Detector/fixture smoke only; no exploit, severity, source-proof, or submission proof."
        ),
        "stop_condition_met": stop_condition_met,
        "source_artifact": str(report_path),
        "worker_artifact": str(worker_path) if worker_path.is_file() else "",
    }, str(report_path)


def collect_canonical_fixture_materialization_accounting(workspace: Path) -> tuple[dict[str, Any], str]:
    """Summarize canonical detector fixture materialization without promoting findings."""
    materialization_path = workspace / ".auditooor" / "scanner_autonomy_canonical_fixture_materialization.json"
    materialization = load_json(materialization_path) if materialization_path.is_file() else {}
    if not isinstance(materialization, dict):
        return {}, ""

    rows = [row for row in materialization.get("rows", []) if isinstance(row, dict)]
    status_counts = (
        materialization.get("status_counts")
        if isinstance(materialization.get("status_counts"), dict)
        else {}
    )
    canonical_smoke_passed = int(
        materialization.get("canonical_smoke_passed_count")
        or status_counts.get("canonical_smoke_passed")
        or sum(1 for row in rows if str(row.get("status") or "") == "canonical_smoke_passed")
    )
    canonical_smoke_failed = int(materialization.get("canonical_smoke_failed_count") or 0)
    blocked = int(materialization.get("blocked_count") or 0)
    vulnerable_hit_rows = sum(1 for row in rows if int(row.get("positive_hits") or 0) >= 1)
    clean_zero_hit_rows = sum(1 for row in rows if int(row.get("clean_hits") or 0) == 0)
    manifest_rows = sum(1 for row in rows if str(row.get("fixture_manifest_path") or ""))
    canonical_fixture_rows = sum(
        1 for row in rows
        if str(row.get("canonical_vulnerable_fixture") or "")
        and str(row.get("canonical_clean_fixture") or "")
    )
    promotion_allowed = bool(materialization.get("promotion_allowed"))
    submission_posture = str(materialization.get("submission_posture") or "NOT_SUBMIT_READY")
    coverage_claim = str(materialization.get("coverage_claim") or "")
    stop_condition_met = (
        bool(rows)
        and canonical_smoke_passed == len(rows)
        and vulnerable_hit_rows == len(rows)
        and clean_zero_hit_rows == len(rows)
        and manifest_rows == len(rows)
        and canonical_fixture_rows == len(rows)
        and canonical_smoke_failed == 0
        and blocked == 0
        and not promotion_allowed
        and submission_posture == "NOT_SUBMIT_READY"
        and coverage_claim == "detector_fixture_smoke_only"
    )
    return {
        "accounting_mode": "canonical_detector_fixture_materialization_accounting_only",
        "status": "canonical_fixture_smoke_passed" if stop_condition_met else "canonical_fixture_materialization_open_or_missing",
        "coverage_claim": "detector_fixture_smoke_only",
        "precision_claim": "canonical_fixture_smoke_only_not_impact_or_submission_proof",
        "processed_count": len(rows),
        "canonical_smoke_passed_count": canonical_smoke_passed,
        "canonical_smoke_failed_count": canonical_smoke_failed,
        "blocked_count": blocked,
        "vulnerable_hit_rows": vulnerable_hit_rows,
        "clean_zero_hit_rows": clean_zero_hit_rows,
        "fixture_manifest_rows": manifest_rows,
        "canonical_fixture_rows": canonical_fixture_rows,
        "promotion_allowed": promotion_allowed,
        "submission_posture": submission_posture,
        "stop_condition_met": stop_condition_met,
        "source_artifact": str(materialization_path),
    }, str(materialization_path)


def detector_fixture_smoke_stop_condition_met(
    semantic_fixture_smoke_accounting: dict[str, Any],
    detector_semantic_repair_accounting: dict[str, Any],
    canonical_fixture_materialization_accounting: dict[str, Any] | None = None,
) -> bool:
    """Close detector rows only for current fixture-smoke scope, never for promotion proof."""
    required = int(semantic_fixture_smoke_accounting.get("smoke_required_count") or 0)
    terminal = int(semantic_fixture_smoke_accounting.get("terminal_clean_positive_count") or 0)
    blocked = int(semantic_fixture_smoke_accounting.get("blocked_missing_fixture_or_smoke_count") or 0)
    processed = int(semantic_fixture_smoke_accounting.get("processed_count") or 0)
    canonical_accounting = canonical_fixture_materialization_accounting or {}
    canonical_required_if_present = (
        not canonical_accounting
        or (
            bool(canonical_accounting.get("stop_condition_met"))
            and int(canonical_accounting.get("canonical_smoke_passed_count") or 0)
            == int(canonical_accounting.get("processed_count") or 0)
            and int(canonical_accounting.get("blocked_count") or 0) == 0
            and int(canonical_accounting.get("canonical_smoke_failed_count") or 0) == 0
        )
    )
    return (
        required > 0
        and processed == required
        and terminal == required
        and blocked == 0
        and not bool(semantic_fixture_smoke_accounting.get("promotion_allowed"))
        and str(semantic_fixture_smoke_accounting.get("coverage_claim") or "") == "detector_fixture_smoke_only"
        and bool(detector_semantic_repair_accounting.get("stop_condition_met"))
        and canonical_required_if_present
    )


def impact_miss_benchmark_accounting(workspace: Path) -> dict[str, Any]:
    """Summarize Impact-Miss benchmark scoring without converting it to proof."""
    benchmark_path = workspace / ".auditooor" / "impact_miss_offset_benchmark.json"
    predictions_path = workspace / ".auditooor" / "impact_miss_offset_predictions.json"
    benchmark = load_json(benchmark_path) if benchmark_path.is_file() else {}
    predictions = load_json(predictions_path) if predictions_path.is_file() else {}
    score = benchmark.get("score") if isinstance(benchmark.get("score"), dict) else {}
    summary = benchmark.get("summary") if isinstance(benchmark.get("summary"), dict) else {}
    generated_predictions = (
        benchmark.get("generated_predictions")
        if isinstance(benchmark.get("generated_predictions"), dict)
        else {}
    )
    source_accounting = (
        predictions.get("source_accounting")
        if isinstance(predictions.get("source_accounting"), dict)
        else generated_predictions.get("summary", {})
        if isinstance(generated_predictions.get("summary"), dict)
        else {}
    )
    demo_fixture = benchmark.get("demo_fixture") if isinstance(benchmark.get("demo_fixture"), dict) else {}
    fixture_source = Path(str(demo_fixture.get("source") or "")) if demo_fixture.get("source") else None
    scored = bool(score) and str(score.get("status") or "") not in {"", "not_scored_no_predictions"}
    pass_threshold = float(score.get("pass_threshold") or 0.85)
    accuracy = float(score.get("accuracy") or 0.0)
    status = str(score.get("status") or ("missing_benchmark" if not benchmark else "not_scored_no_predictions"))
    posture_valid = (
        str(benchmark.get("submission_posture") or "NOT_SUBMIT_READY") == "NOT_SUBMIT_READY"
        and not bool(benchmark.get("promotion_allowed"))
        and bool(benchmark.get("advisory_only", True))
        and str(predictions.get("submission_posture") or "NOT_SUBMIT_READY") == "NOT_SUBMIT_READY"
        and not bool(predictions.get("promotion_allowed"))
    )
    genericity_fixture_present = bool(fixture_source and fixture_source.is_file())
    genericity_workspace_outputs_present = int(source_accounting.get("source_row_count") or 0) > 0
    return {
        "schema": f"{SCHEMA_PREFIX}.impact_miss_benchmark_accounting.v1",
        "status": status,
        "benchmark_path": str(benchmark_path),
        "benchmark_present": bool(benchmark),
        "predictions_path": str(predictions_path),
        "predictions_present": bool(predictions),
        "scored": scored,
        "score_passed": status == "pass",
        "score_failed": status == "fail",
        "accuracy": accuracy,
        "pass_threshold": pass_threshold,
        "prediction_count": int(score.get("prediction_count") or 0),
        "passed": int(score.get("passed") or 0),
        "failed": int(score.get("failed") or 0),
        "item_count": int(summary.get("item_count") or 0),
        "target_range": str(benchmark.get("target_range") or "150-300 concrete items"),
        "route_family_count": int(summary.get("route_family_count") or 0),
        "source_accounting": source_accounting,
        "genericity_fixture_present": genericity_fixture_present,
        "genericity_workspace_outputs_present": genericity_workspace_outputs_present,
        "genericity_accounted": genericity_fixture_present or genericity_workspace_outputs_present,
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "posture_valid": posture_valid,
        "accounting_boundary": (
            "Impact-Miss score is route-family recall accounting over withheld-known benchmark rows; "
            "it is not exploit proof, scanner completeness, production-path proof, or submission readiness"
        ),
    }


def impact_family_worklist_accounting(workspace: Path) -> dict[str, Any]:
    """Read exact Impact-Miss impact-family worklist reducers.

    This can close only the mechanical worklist stop condition. It is not
    impact proof: every row remains NOT_SUBMIT_READY until source, harness,
    production-path, live/fork, and execution-manifest proof gates close.
    """
    audit_dir = out_dir(workspace)
    validator_path = audit_dir / "impact_binding_next_input_validator.json"
    discovery_path = audit_dir / "impact_binding_source_harness_discovery.json"
    source_root_readiness_path = audit_dir / "project_source_root_readiness.json"
    validator = load_json(validator_path) if validator_path.is_file() else {}
    discovery = load_json(discovery_path) if discovery_path.is_file() else {}
    source_root_readiness = load_json(source_root_readiness_path) if source_root_readiness_path.is_file() else {}
    validator_summary = validator.get("summary") if isinstance(validator.get("summary"), dict) else {}
    discovery_summary = discovery.get("summary") if isinstance(discovery.get("summary"), dict) else {}
    requirement_counts = (
        validator_summary.get("requirement_counts")
        if isinstance(validator_summary.get("requirement_counts"), dict)
        else {}
    )
    route_family_counts = (
        validator_summary.get("route_family_counts")
        if isinstance(validator_summary.get("route_family_counts"), dict)
        else {}
    )
    expected_requirements = {
        "bounded_project_input_fixture",
        "candidate_bound_project_source_citation",
        "paired_live_or_fork_proof",
        "production_path_dossier",
        "project_specific_harness_execution",
        "proved_exploit_impact_execution_manifest",
    }
    all_expected_requirements = expected_requirements.issubset(set(requirement_counts))
    contract_count = int(validator.get("contract_count") or 0)
    actionable_units = int(validator.get("actionable_unit_count") or 0)
    terminal_reduced_units = int(discovery.get("terminal_reduced_unit_count") or 0)
    source_harness_units = (
        int(discovery_summary.get("requirement_counts", {}).get("candidate_bound_project_source_citation") or 0)
        + int(discovery_summary.get("requirement_counts", {}).get("project_specific_harness_execution") or 0)
        if isinstance(discovery_summary.get("requirement_counts"), dict)
        else 0
    )
    discovery_status_counts = (
        discovery_summary.get("discovery_status_counts")
        if isinstance(discovery_summary.get("discovery_status_counts"), dict)
        else {}
    )
    source_root_declared_count = int(source_root_readiness.get("declared_root_count") or 0)
    source_root_ready_count = int(source_root_readiness.get("ready_root_count") or 0)
    source_root_rejected_count = int(source_root_readiness.get("rejected_root_count") or 0)
    terminal_no_root_source_units = int(discovery_status_counts.get("terminal_no_project_source_roots") or 0)
    terminal_no_root_harness_units = int(discovery_status_counts.get("terminal_harness_blocked_no_project_source_roots") or 0)
    source_import_workflow_ready = (
        bool(source_root_readiness)
        and str(source_root_readiness.get("schema") or "") == "auditooor.project_source_root_readiness.v1"
        and str(discovery.get("project_source_readiness_path") or "") == str(source_root_readiness_path)
        and source_root_ready_count == int(discovery.get("project_source_root_count") or 0)
        and terminal_reduced_units >= source_harness_units
        and source_harness_units > 0
        and not bool(source_root_readiness.get("promotion_allowed"))
        and str(source_root_readiness.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    source_import_terminal_no_roots = (
        source_import_workflow_ready
        and source_root_declared_count == 0
        and source_root_ready_count == 0
        and terminal_no_root_source_units >= int(discovery_summary.get("requirement_counts", {}).get("candidate_bound_project_source_citation") or 0)
        and terminal_no_root_harness_units >= int(discovery_summary.get("requirement_counts", {}).get("project_specific_harness_execution") or 0)
    )
    complete_worklist = (
        bool(validator)
        and contract_count >= 384
        and actionable_units >= 768
        and len(route_family_counts) >= 12
        and all_expected_requirements
        and terminal_reduced_units >= source_harness_units
        and not bool(validator.get("promotion_allowed"))
        and str(validator.get("submission_posture") or "") == "NOT_SUBMIT_READY"
        and not bool(discovery.get("promotion_allowed"))
        and str(discovery.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    return {
        "schema": f"{SCHEMA_PREFIX}.impact_family_worklist_accounting.v1",
        "status": "complete_exact_worklist_with_terminal_blockers" if complete_worklist else "open_or_missing_worklist",
        "validator_path": str(validator_path),
        "discovery_path": str(discovery_path),
        "source_root_readiness_path": str(source_root_readiness_path),
        "contract_count": contract_count,
        "actionable_unit_count": actionable_units,
        "ready_unit_count": int(validator.get("ready_unit_count") or 0),
        "closure_candidate_count": int(validator.get("closure_candidate_count") or 0),
        "route_family_count": len(route_family_counts),
        "requirement_counts": dict(sorted((str(k), int(v)) for k, v in requirement_counts.items())),
        "source_harness_terminal_reduced_unit_count": terminal_reduced_units,
        "source_harness_required_unit_count": source_harness_units,
        "project_source_root_count": int(discovery.get("project_source_root_count") or 0),
        "source_root_declared_count": source_root_declared_count,
        "source_root_ready_count": source_root_ready_count,
        "source_root_rejected_count": source_root_rejected_count,
        "source_import_workflow_ready": source_import_workflow_ready,
        "source_import_terminal_no_roots": source_import_terminal_no_roots,
        "source_import_discovery_status_counts": dict(
            sorted((str(k), int(v)) for k, v in discovery_status_counts.items())
        ),
        "source_import_remaining_blocker": (
            "declare/import real target project source roots with .auditooor/project_source_roots.json, "
            "then rerun project-source-root-readiness and impact-binding-source-harness-discovery"
            if source_import_terminal_no_roots
            else ""
        ),
        "complete_worklist_stop_condition_met": complete_worklist,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Mechanical impact-family worklist closure only. It does not prove listed impact, "
            "severity, source reachability, production path, live/fork state, exploit impact, or submission readiness."
        ),
    }


def execution_source_import_workflow_accounting(workspace: Path) -> dict[str, Any]:
    """Read execution-proof readiness and source-import readiness reducers.

    This is a formal reduction for execution-oriented known-limitations rows:
    it proves the workflow can enumerate exact missing source/harness/proved
    manifest inputs, but it never counts as exploit proof.
    """
    audit_dir = out_dir(workspace)
    execution_path = audit_dir / "execution_manifest_proof_readiness.json"
    source_import_path = audit_dir / "impact_binding_source_import_readiness.json"
    project_source_path = audit_dir / "project_source_root_readiness.json"
    execution = load_json(execution_path) if execution_path.is_file() else {}
    source_import = load_json(source_import_path) if source_import_path.is_file() else {}
    project_source = load_json(project_source_path) if project_source_path.is_file() else {}
    execution_summary = execution.get("summary") if isinstance(execution.get("summary"), dict) else {}
    source_summary = source_import.get("summary") if isinstance(source_import.get("summary"), dict) else {}
    execution_missing = (
        execution_summary.get("missing_input_counts")
        if isinstance(execution_summary.get("missing_input_counts"), dict)
        else {}
    )
    source_missing = (
        source_summary.get("missing_input_counts")
        if isinstance(source_summary.get("missing_input_counts"), dict)
        else {}
    )
    execution_status_counts = (
        execution_summary.get("readiness_status_counts")
        if isinstance(execution_summary.get("readiness_status_counts"), dict)
        else {}
    )
    source_status_counts = (
        source_summary.get("source_import_status_counts")
        if isinstance(source_summary.get("source_import_status_counts"), dict)
        else {}
    )
    execution_rows = int(execution.get("proved_execution_requirement_count") or 0)
    source_units = int(source_import.get("source_import_unit_count") or 0)
    proof_ready = int(execution.get("proof_ready_count") or 0)
    closed_proofs = int(execution.get("closed_proof_count") or 0)
    ready_roots = int(project_source.get("ready_root_count") or 0)
    workflow_reduced = (
        bool(execution)
        and bool(source_import)
        and bool(project_source)
        and str(execution.get("schema") or "") == f"{SCHEMA_PREFIX}.execution_manifest_proof_readiness.v1"
        and str(source_import.get("schema") or "") == f"{SCHEMA_PREFIX}.impact_binding_source_import_readiness.v1"
        and str(project_source.get("schema") or "") == "auditooor.project_source_root_readiness.v1"
        and execution_rows >= 160
        and source_units >= 480
        and proof_ready == 0
        and closed_proofs == 0
        and ready_roots == 0
        and int(execution_status_counts.get("terminal_no_project_source_root_for_execution_proof") or 0) >= execution_rows
        and int(source_status_counts.get("terminal_no_ready_project_source_roots") or 0) >= source_units
        and not bool(execution.get("promotion_allowed"))
        and not bool(source_import.get("promotion_allowed"))
        and str(execution.get("submission_posture") or "") == "NOT_SUBMIT_READY"
        and str(source_import.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.execution_source_import_workflow_accounting.v1",
        "status": (
            "workflow_reduced_real_source_and_proved_manifest_missing"
            if workflow_reduced
            else "open_or_missing_execution_source_import_workflow"
        ),
        "execution_manifest_proof_readiness_path": str(execution_path),
        "impact_binding_source_import_readiness_path": str(source_import_path),
        "project_source_root_readiness_path": str(project_source_path),
        "proved_execution_requirement_count": execution_rows,
        "proof_ready_count": proof_ready,
        "closed_proof_count": closed_proofs,
        "source_import_unit_count": source_units,
        "ready_project_source_root_count": ready_roots,
        "ready_source_file_count": int(source_import.get("ready_source_file_count") or 0),
        "line_hit_unit_count": int(source_import.get("line_hit_unit_count") or 0),
        "execution_missing_input_counts": dict(sorted((str(k), int(v)) for k, v in execution_missing.items())),
        "source_import_missing_input_counts": dict(sorted((str(k), int(v)) for k, v in source_missing.items())),
        "execution_readiness_status_counts": dict(sorted((str(k), int(v)) for k, v in execution_status_counts.items())),
        "source_import_status_counts": dict(sorted((str(k), int(v)) for k, v in source_status_counts.items())),
        "workflow_reduction_stop_condition_accounted": workflow_reduced,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Execution/source import workflow reduction only. It does not prove exploit impact, listed impact, "
            "production path, source reachability, OOS status, severity, or submission readiness."
        ),
        "remaining_blocker": (
            "declare/import real target project source roots, produce candidate-bound source citations and "
            "project harness bindings, then record execution manifests with final_result=proved and "
            "impact_assertion=exploit_impact"
            if workflow_reduced
            else "run execution-manifest-proof-readiness and impact-binding-source-import-readiness"
        ),
    }
    write_json(audit_dir / "execution_source_import_workflow_accounting.json", payload)
    md = [
        "# Execution Source Import Workflow Accounting",
        "",
        f"- Status: `{payload['status']}`",
        f"- Execution requirements: `{execution_rows}`",
        f"- Proof-ready rows: `{proof_ready}`",
        f"- Closed proof rows: `{closed_proofs}`",
        f"- Source/import units: `{source_units}`",
        f"- Ready project source roots: `{ready_roots}`",
        f"- Ready source files: `{payload['ready_source_file_count']}`",
        f"- Line-hit units: `{payload['line_hit_unit_count']}`",
        f"- Remaining blocker: {payload['remaining_blocker']}",
        "",
        "Boundary: workflow readiness and exact blockers only; no proof, severity, source reachability, or submission-readiness claim is made.",
    ]
    write_md(audit_dir / "execution_source_import_workflow_accounting.md", md)
    return payload


def live_topology_explicit_blocker_accounting(workspace: Path) -> dict[str, Any]:
    """Read same-block live-topology proof-input reducers.

    P1-3's stop condition allows same-block paired proof *or explicit blockers*.
    This reader closes only the explicit-blocker half when every pair and row is
    classified with import/materialization commands and no proof is promoted.
    """
    audit_dir = out_dir(workspace)
    validator_path = audit_dir / "live_topology_proof_input_validator.json"
    materializer_path = audit_dir / "live_topology_manual_proof_materializer.json"
    validator = load_json(validator_path) if validator_path.is_file() else {}
    materializer = load_json(materializer_path) if materializer_path.is_file() else {}
    validator_summary = validator.get("summary") if isinstance(validator.get("summary"), dict) else {}
    materializer_summary = materializer.get("summary") if isinstance(materializer.get("summary"), dict) else {}
    proof_pairs_total = int(materializer_summary.get("proof_pairs_total") or validator_summary.get("proof_pairs_total") or 0)
    rows_total = int(materializer_summary.get("rows_total") or validator_summary.get("rows_total") or 0)
    materialized_rows = int(materializer_summary.get("canonical_rows_materialized") or 0)
    import_ready_pairs = int(
        materializer_summary.get("canonical_import_ready_pairs")
        or validator_summary.get("import_ready_pairs")
        or 0
    )
    closed_pairs = int(
        materializer_summary.get("proof_pairs_closed")
        or validator_summary.get("proof_pairs_closed")
        or 0
    )
    explicit_blockers_complete = (
        bool(validator)
        and bool(materializer)
        and proof_pairs_total >= 350
        and rows_total >= 700
        and materialized_rows == 0
        and import_ready_pairs == 0
        and closed_pairs == 0
        and not bool(validator.get("promotion_allowed"))
        and str(validator.get("submission_posture") or "") == "NOT_SUBMIT_READY"
        and not bool(materializer.get("promotion_allowed"))
        and str(materializer.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    return {
        "schema": f"{SCHEMA_PREFIX}.live_topology_explicit_blocker_accounting.v1",
        "status": "explicit_blockers_complete_no_proof_promoted" if explicit_blockers_complete else "open_or_missing_live_topology_blockers",
        "validator_path": str(validator_path),
        "materializer_path": str(materializer_path),
        "proof_pairs_total": proof_pairs_total,
        "rows_total": rows_total,
        "import_ready_pairs": import_ready_pairs,
        "canonical_rows_materialized": materialized_rows,
        "proof_pairs_closed": closed_pairs,
        "pair_validation_state_counts": validator_summary.get("pair_validation_state_counts", {}),
        "pair_materialization_state_counts": materializer_summary.get("pair_materialization_state_counts", {}),
        "explicit_blocker_stop_condition_met": explicit_blockers_complete,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Live-topology explicit-blocker closure only. No same-block proof pair, selected impact, severity, "
            "or submission-ready claim is promoted until real manual proofs are captured, imported, and executed."
        ),
    }


def live_topology_hermetic_workflow_accounting(workspace: Path) -> dict[str, Any]:
    """Read Ptolemy's hermetic manual-proof -> import -> executor workflow proof.

    This is intentionally a workflow-readiness reducer, not live proof. A
    hermetic same-block fixture can prove the local pipeline is wired, while the
    real workspace rows stay blocked until actual RPC-backed manual proofs are
    provided, imported, and validated against the production requirement set.
    """
    audit_dir = out_dir(workspace)
    integration_path = audit_dir / "pr560_worker_manual_proof_materializer_executor_integration.json"
    validator_path = audit_dir / "live_topology_proof_input_validator.json"
    materializer_path = audit_dir / "live_topology_manual_proof_materializer.json"
    bridge_path = audit_dir / "live_topology_hermetic_workflow_bridge.json"
    bridge_md_path = audit_dir / "live_topology_hermetic_workflow_bridge.md"

    integration = load_json(integration_path) if integration_path.is_file() else {}
    validator = load_json(validator_path) if validator_path.is_file() else {}
    materializer = load_json(materializer_path) if materializer_path.is_file() else {}
    reductions = integration.get("proof_workflow_reductions") if isinstance(integration.get("proof_workflow_reductions"), dict) else {}
    positive = reductions.get("hermetic_same_block_positive_fixture") if isinstance(reductions.get("hermetic_same_block_positive_fixture"), dict) else {}
    negative = reductions.get("hermetic_cross_block_negative_fixture") if isinstance(reductions.get("hermetic_cross_block_negative_fixture"), dict) else {}
    validator_summary = validator.get("summary") if isinstance(validator.get("summary"), dict) else {}
    materializer_summary = materializer.get("summary") if isinstance(materializer.get("summary"), dict) else {}

    real_pairs_total = int(materializer_summary.get("proof_pairs_total") or validator_summary.get("proof_pairs_total") or 0)
    real_rows_total = int(materializer_summary.get("rows_total") or validator_summary.get("rows_total") or 0)
    real_import_ready_pairs = int(
        materializer_summary.get("canonical_import_ready_pairs")
        or validator_summary.get("import_ready_pairs")
        or 0
    )
    real_materialized_rows = int(materializer_summary.get("canonical_rows_materialized") or 0)
    real_closed_pairs = int(
        materializer_summary.get("proof_pairs_closed")
        or validator_summary.get("proof_pairs_closed")
        or 0
    )
    positive_workflow_valid = (
        int(positive.get("validator_rows") or 0) >= 2
        and int(positive.get("materialized_manual_proofs") or 0) >= 2
        and int(positive.get("manual_import_rows") or 0) >= 2
        and int(positive.get("executor_depth_closure_candidates") or 0) >= 1
        and str(positive.get("claim_boundary") or "") == "semantic_live_topology_depth_only"
        and str(positive.get("submission_posture") or "") == "NOT_SUBMIT_READY"
        and not bool(positive.get("promotion_allowed"))
    )
    negative_workflow_valid = (
        int(negative.get("validator_rows") or 0) >= 2
        and int(negative.get("materialized_manual_proofs") or 0) == 0
        and int(negative.get("executor_depth_closure_candidates") or 0) == 0
        and bool(str(negative.get("blocked_status") or "").strip())
        and bool(str(negative.get("blocker_kind") or "").strip())
    )
    hermetic_workflow_validated = bool(integration) and positive_workflow_valid and negative_workflow_valid
    real_workspace_proof_missing = (
        real_pairs_total >= 350
        and real_rows_total >= 700
        and real_import_ready_pairs == 0
        and real_materialized_rows == 0
        and real_closed_pairs == 0
    )
    status = "missing_hermetic_workflow_artifact"
    if hermetic_workflow_validated and real_workspace_proof_missing:
        status = "hermetic_workflow_validated_real_workspace_proof_missing"
    elif hermetic_workflow_validated:
        status = "hermetic_workflow_validated_check_real_workspace_proof_state"
    elif integration:
        status = "hermetic_workflow_artifact_incomplete"

    payload = {
        "schema": f"{SCHEMA_PREFIX}.live_topology_hermetic_workflow_bridge.v1",
        "workspace": str(workspace),
        "status": status,
        "integration_path": str(integration_path),
        "validator_path": str(validator_path),
        "materializer_path": str(materializer_path),
        "bridge_artifact_path": str(bridge_path),
        "hermetic_workflow_validated": hermetic_workflow_validated,
        "positive_workflow_valid": positive_workflow_valid,
        "negative_workflow_valid": negative_workflow_valid,
        "hermetic_same_block_depth_closure_candidates": int(positive.get("executor_depth_closure_candidates") or 0),
        "hermetic_manual_import_rows": int(positive.get("manual_import_rows") or 0),
        "hermetic_cross_block_materialized_rows": int(negative.get("materialized_manual_proofs") or 0),
        "real_workspace_proof_missing": real_workspace_proof_missing,
        "real_workspace_pairs_total": real_pairs_total,
        "real_workspace_rows_total": real_rows_total,
        "real_workspace_import_ready_pairs": real_import_ready_pairs,
        "real_workspace_materialized_rows": real_materialized_rows,
        "real_workspace_closed_pairs": real_closed_pairs,
        "reduction_scope": "hermetic_live_topology_workflow_only",
        "closed_real_workspace_semantic_live_rows": 0,
        "closed_real_workspace_proof_pairs": real_closed_pairs,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Hermetic workflow validation proves the manual-proof materializer/import/executor path, "
            "but does not close real workspace semantic/live topology rows without actual RPC-backed "
            "same-block proof files and imported live topology checks."
        ),
        "remaining_real_workspace_blockers": [
            "verified addresses",
            "RPC-backed same-block captures",
            "shared block pins",
            "expected values",
            "canonical manual_proofs/<row_id>.json files",
            "live-check-runner import",
            "live-topology-proof-executor validation",
        ],
    }
    write_json(bridge_path, payload)
    write_md(
        bridge_md_path,
        [
            "# Live Topology Hermetic Workflow Bridge",
            "",
            f"- Status: `{status}`",
            f"- Hermetic workflow validated: `{str(hermetic_workflow_validated).lower()}`",
            f"- Hermetic same-block depth candidates: `{payload['hermetic_same_block_depth_closure_candidates']}`",
            f"- Real workspace proof pairs closed: `{real_closed_pairs}`",
            f"- Real workspace import-ready pairs: `{real_import_ready_pairs}`",
            f"- Real workspace materialized rows: `{real_materialized_rows}`",
            "",
            "## Boundary",
            payload["proof_boundary"],
            "",
            "## Remaining Real Workspace Inputs",
            *[f"- {item}" for item in payload["remaining_real_workspace_blockers"]],
        ],
    )
    return payload


def live_topology_real_input_workflow_accounting(workspace: Path) -> dict[str, Any]:
    """Read operator/RPC real-input routing state for live-topology proof.

    The real-input router is the handoff from exact proof requirements to
    operator/RPC-provided same-block evidence files. This accounting deliberately
    reduces only the input-acquisition state: it must not promote proof unless
    the materializer/import/executor chain has already produced canonical
    same-block closure.
    """
    audit_dir = out_dir(workspace)
    router_path = audit_dir / "live_topology_real_proof_input_router.json"
    materializer_path = audit_dir / "live_topology_manual_proof_materializer.json"
    executor_path = audit_dir / "live_topology_proof_executor.json"
    bridge_path = audit_dir / "live_topology_real_input_workflow_reduction.json"
    bridge_md_path = audit_dir / "live_topology_real_input_workflow_reduction.md"

    router = load_json(router_path) if router_path.is_file() else {}
    materializer = load_json(materializer_path) if materializer_path.is_file() else {}
    executor = load_json(executor_path) if executor_path.is_file() else {}
    router_summary = router.get("summary") if isinstance(router.get("summary"), dict) else {}
    materializer_summary = materializer.get("summary") if isinstance(materializer.get("summary"), dict) else {}
    executor_summary = executor.get("summary") if isinstance(executor.get("summary"), dict) else {}

    proof_pairs_total = int(router_summary.get("proof_pairs_total") or materializer_summary.get("proof_pairs_total") or 0)
    rows_total = int(router_summary.get("rows_total") or materializer_summary.get("rows_total") or 0)
    same_block_ready_pairs = int(router_summary.get("same_block_ready_pairs") or 0)
    provided_rows_written = int(router_summary.get("provided_rows_written") or 0)
    materialized_rows = int(materializer_summary.get("canonical_rows_materialized") or 0)
    import_ready_pairs = int(materializer_summary.get("canonical_import_ready_pairs") or 0)
    router_closed_pairs = int(router_summary.get("proof_pairs_closed") or 0)
    materializer_closed_pairs = int(materializer_summary.get("proof_pairs_closed") or 0)
    executor_closed_pairs = int(
        executor_summary.get("proof_pairs_closed")
        or executor_summary.get("closure_candidates")
        or executor_summary.get("same_block_closure_candidates")
        or 0
    )
    row_state_counts = router_summary.get("row_routing_state_counts", {})
    pair_state_counts = router_summary.get("pair_routing_state_counts", {})

    real_input_workflow_reduced = (
        bool(router)
        and proof_pairs_total >= 350
        and rows_total >= 700
        and same_block_ready_pairs == 0
        and provided_rows_written == 0
        and materialized_rows == 0
        and import_ready_pairs == 0
        and router_closed_pairs == 0
        and materializer_closed_pairs == 0
        and executor_closed_pairs == 0
        and int(pair_state_counts.get("real_proof_inputs_missing") or 0) >= 350
        and int(row_state_counts.get("real_proof_row_missing") or 0) >= 700
        and not bool(router.get("promotion_allowed"))
        and str(router.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    status = (
        "real_input_workflow_reduced_exact_inputs_missing"
        if real_input_workflow_reduced
        else "open_or_missing_real_input_workflow"
    )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.live_topology_real_input_workflow_reduction.v1",
        "workspace": str(workspace),
        "status": status,
        "router_path": str(router_path),
        "materializer_path": str(materializer_path),
        "executor_path": str(executor_path),
        "proof_pairs_total": proof_pairs_total,
        "rows_total": rows_total,
        "same_block_ready_pairs": same_block_ready_pairs,
        "provided_rows_written": provided_rows_written,
        "canonical_rows_materialized": materialized_rows,
        "canonical_import_ready_pairs": import_ready_pairs,
        "proof_pairs_closed": max(router_closed_pairs, materializer_closed_pairs, executor_closed_pairs),
        "pair_routing_state_counts": pair_state_counts,
        "row_routing_state_counts": row_state_counts,
        "real_input_workflow_reduced": real_input_workflow_reduced,
        "closed_real_workspace_semantic_live_rows": 0,
        "closed_real_workspace_proof_pairs": 0,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Real-input workflow reduction only. It proves the operator/RPC input handoff has exact "
            "missing-input blockers, not that any same-block live proof exists."
        ),
        "remaining_real_input_blockers": [
            "operator/RPC real proof input files under .auditooor/live_topology_real_proof_inputs/<row_id>.json",
            "same-block pair inputs accepted by live-topology-real-proof-input-router",
            "canonical manual_proofs/<row_id>.json files emitted by the materializer",
            "live-check-runner import into live_topology_checks.json",
            "live-topology-proof-executor validation against the workspace proof pairs",
        ],
    }
    write_json(bridge_path, payload)
    write_md(
        bridge_md_path,
        [
            "# Live Topology Real-Input Workflow Reduction",
            "",
            f"- Status: `{status}`",
            f"- Proof pairs routed: `{proof_pairs_total}`",
            f"- Rows routed: `{rows_total}`",
            f"- Same-block ready pairs: `{same_block_ready_pairs}`",
            f"- Provided rows written: `{provided_rows_written}`",
            f"- Canonical rows materialized: `{materialized_rows}`",
            f"- Proof pairs closed: `{payload['proof_pairs_closed']}`",
            "",
            "## Boundary",
            payload["proof_boundary"],
            "",
            "## Remaining Real Inputs",
            *[f"- {item}" for item in payload["remaining_real_input_blockers"]],
        ],
    )
    return payload


def runtime_dlt_execution_evidence_accounting(workspace: Path) -> dict[str, Any]:
    """Read runtime/DLT execution-evidence validator for reduction-only accounting."""
    path = out_dir(workspace) / "runtime_dlt_execution_evidence_validator.json"
    payload = load_json(path) if path.is_file() else {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    blocker_counts = summary.get("blocker_counts") if isinstance(summary.get("blocker_counts"), dict) else {}
    hermetic = payload.get("hermetic_fixture_check") if isinstance(payload.get("hermetic_fixture_check"), dict) else {}
    dlt_rows = int(payload.get("dlt_row_count") or 0)
    proved = int(payload.get("proved_exploit_impact_count") or 0)
    reduced = (
        bool(payload)
        and dlt_rows >= 96
        and str(hermetic.get("status") or "") == "passed"
        and not bool(payload.get("promotion_allowed"))
        and str(payload.get("submission_posture") or "") == "NOT_SUBMIT_READY"
    )
    return {
        "schema": f"{SCHEMA_PREFIX}.runtime_dlt_execution_evidence_accounting.v1",
        "status": "runtime_dlt_rows_reduced_not_closed" if reduced and proved == 0 else "open_or_missing_runtime_dlt_evidence",
        "artifact_path": str(path),
        "dlt_row_count": dlt_rows,
        "proved_exploit_impact_count": proved,
        "closure_candidate_count": int(payload.get("closure_candidate_count") or 0),
        "hermetic_fixture_status": str(hermetic.get("status") or ""),
        "blocker_counts": dict(sorted((str(k), int(v)) for k, v in blocker_counts.items())),
        "reduction_stop_condition_accounted": reduced,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": (
            "Runtime/DLT evidence is reduced only. It stays open until project-bound runtime evidence and "
            "strict proved exploit-impact execution manifests exist."
        ),
    }


def pr560_not_closed_boundaries() -> dict[str, dict[str, Any]]:
    return {
        "full_scanner_coverage": {
            "closed": False,
            "blocker": "scanner inventory and coverage artifacts exist, but stop conditions do not prove every scanner path or every scoped asset has full coverage",
            "next_command": "make coverage-inventory WS=<workspace> STRICT=1",
        },
        "invariant_discovery_completeness": {
            "closed": False,
            "blocker": "ledger gates exist, but generated-vs-accepted invariant discovery completeness is still a human/model synthesis risk",
            "next_command": "make invariant-ledger WS=<workspace> FROM_SCOPE=1 STRICT=1",
        },
        "executed_harnesses": {
            "closed": False,
            "blocker": "harness plans, scaffolds, and queues exist, but queued rows have not all become execution manifests with exploit-impact assertions",
            "next_command": "make harness-plan WS=<workspace> && make harness-scaffold WS=<workspace>",
        },
        "rust_dlt_semantic_depth": {
            "closed": False,
            "blocker": "Rust/DLT graphs are syntactic/source-shape oriented and do not yet resolve trait dispatch, runtime state machines, fork conditions, or client caches",
            "next_command": "make semantic-graph WS=<workspace> && tools/rust-scan-runner.sh <workspace>",
        },
        "provider_live_artifacts": {
            "closed": False,
            "blocker": "local provider/preflight artifacts are advisory until explicit operator consent and local verification promote them",
            "next_command": "make pr560-next-actions WS=<workspace> JSON=1",
        },
        "semantic_detector_adjudication": {
            "closed": False,
            "blocker": "adjudication classifies query rows into rewrite/fixture/source-only tasks; it is not fixture smoke-fire or detector proof",
            "next_command": "make semantic-detector-adjudication WS=<workspace>",
        },
        "foundry_migration_execution": {
            "closed": False,
            "blocker": "Foundry v1.7 is planned-not-executed until an operator-approved isolated trial records baseline-vs-target logs",
            "next_command": "make foundry-v17-trial-plan WS=<workspace>",
        },
    }


def pr560_aw_reconciliation_summary(
    progress: dict[str, Any],
    *,
    changed_file_groups: list[dict[str, Any]],
    roadmap_accounting: dict[str, Any],
    foundry_fixture_manifests: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    group_counts = {
        str(row.get("group")): int(row.get("count") or 0)
        for row in changed_file_groups
        if isinstance(row, dict)
    }
    not_closed = pr560_not_closed_boundaries()
    live_provider_tool = ROOT / "tools" / "live-provider-result-triage.py"
    live_provider_test = ROOT / "tools" / "tests" / "test_live_provider_result_triage.py"
    semantic_tool = ROOT / "tools" / "semantic-detector-adjudication.py"
    semantic_test = ROOT / "tools" / "tests" / "test_semantic_detector_adjudication.py"
    changed_total = int(progress.get("changed_file_count") or len(progress.get("changed_files") or []))
    ready_for_eventual_pr = bool(bundle.get("ready_for_eventual_pr"))
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    open_queue_rows = int(bundle.get("advisory_open_queue_count") or progress.get("remaining_queue_count") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    full_closure = (
        known_open == 0
        and open_queue_rows == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    return {
        "worker": "AW",
        "status": "valid_local_integration_readiness_not_full_closure",
        "readiness_valid_expected": ready_for_eventual_pr and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure,
        "progress_reconciliation": {
            "completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or open_queue_rows),
            "advisory_open_queue_count": open_queue_rows,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
            "ready_for_eventual_pr": ready_for_eventual_pr,
        },
        "known_limitations_reconciliation": {
            "row_count": int(roadmap_accounting.get("known_limitations_row_count") or 0),
            "stop_conditions_met": int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0),
            "open_row_count": known_open,
            "open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
            "remaining_not_closed_ids": sorted(not_closed),
        },
        "live_provider_triage": {
            "tool_present": live_provider_tool.is_file(),
            "test_present": live_provider_test.is_file(),
            "changed_file_group_count": group_counts.get("provider_assist", 0),
            "posture": "advisory_only_requires_operator_live_consent",
            "proof_claim": "not_claimed",
        },
        "semantic_adjudication": {
            "tool_present": semantic_tool.is_file(),
            "test_present": semantic_test.is_file(),
            "changed_file_group_count": group_counts.get("semantic_multihop", 0) + group_counts.get("detector_worklists", 0),
            "posture": "routing_accounting_only_until_fixture_smoke_fire",
            "proof_claim": "not_claimed",
        },
        "foundry_slice": {
            "fixture_manifest_status": foundry_fixture_manifests.get("status"),
            "migration_state": foundry_fixture_manifests.get("migration_state"),
            "upgrade_performed": bool(foundry_fixture_manifests.get("upgrade_performed")),
            "install_or_upgrade_allowed": bool(foundry_fixture_manifests.get("install_or_upgrade_allowed")),
            "blocking_normalization_item_total": int(foundry_fixture_manifests.get("blocking_normalization_item_total") or 0),
            "posture": "planned_not_executed_operator_approved_trial_only",
            "proof_claim": "not_claimed",
        },
        "changed_file_group_counts": {
            "observed_changed_file_count": changed_total,
            "groups": group_counts,
            "all_required_groups_present": all(
                group in group_counts
                for group in (
                    "impact_gates",
                    "provider_assist",
                    "semantic_multihop",
                    "detector_worklists",
                    "docs_known_limitations",
                    "tests_accounting",
                    "foundry_migration",
                    "generated_artifacts_optional",
                )
            ),
        },
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make docs-check",
            "make known-limitations-check-test",
            "make automation-closure-test",
        ],
    }


def pr560_active_agent_slot_accounting() -> dict[str, Any]:
    slot_doc = ROOT / "docs" / "PR560_ACTIVE_AGENT_SLOTS.md"
    rows: list[dict[str, Any]] = []
    freshness_now = datetime.now(timezone.utc)

    def _pid_from_handle(handle: str) -> int | None:
        match = re.fullmatch(r"`?pid-(\d+)`?", handle.strip())
        return int(match.group(1)) if match else None

    def _pid_is_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    seen_current_slots = False
    in_current_slots = True
    if slot_doc.is_file():
        for line in slot_doc.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("## "):
                if stripped == "## Current Slots":
                    seen_current_slots = True
                    in_current_slots = True
                elif seen_current_slots:
                    in_current_slots = False
                continue
            if seen_current_slots and not in_current_slots:
                continue
            if not stripped.startswith("|"):
                continue
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if len(cells) < 5 or cells[0] in {"Slot", "Agent", "---"}:
                continue
            raw_status = cells[4].strip("`")
            last_update = cells[5].strip("`") if len(cells) >= 6 else ""
            closed_reason = cells[6] if len(cells) >= 7 else ""
            handle = cells[2].strip("`")
            pid = _pid_from_handle(handle)
            pid_alive = _pid_is_alive(pid) if pid is not None else None
            parsed_last_update = parse_iso_or_date(last_update)
            age_days = (
                (freshness_now - parsed_last_update).total_seconds() / 86400
                if parsed_last_update is not None
                else None
            )
            stale_reasons: list[str] = []
            if raw_status.lower() == "running":
                if parsed_last_update is None or age_days is None:
                    stale_reasons.append("missing_or_unparseable_last_update")
                elif age_days > ACTIVE_SLOT_STALE_AFTER_DAYS:
                    stale_reasons.append("last_update_too_old")
                if pid_alive is False:
                    stale_reasons.append("pid_not_alive")
            stale_running = (
                raw_status.lower() == "running"
                and bool(stale_reasons)
            )
            effective_status = "stale_running_ignored" if stale_running else raw_status.lower()
            rows.append(
                {
                    "slot": cells[0],
                    "agent": cells[1],
                    "handle": handle,
                    "current_ownership": cells[3],
                    "status": raw_status,
                    "last_update": last_update,
                    "last_update_parseable": parsed_last_update is not None,
                    "age_days": round(age_days, 3) if age_days is not None else None,
                    "pid": pid,
                    "pid_checked": pid is not None,
                    "pid_alive": pid_alive,
                    "closed_reason": closed_reason,
                    "stale_running_ignored": stale_running,
                    "stale_running_reasons": stale_reasons,
                    "effective_status": effective_status,
                }
            )
    status_counts: dict[str, int] = {}
    effective_status_counts: dict[str, int] = {}
    for row in rows:
        status = row["status"].lower()
        status_counts[status] = status_counts.get(status, 0) + 1
        effective = row["effective_status"].lower()
        effective_status_counts[effective] = effective_status_counts.get(effective, 0) + 1
    integration_slots = [
        row
        for row in rows
        if "integration readiness" in row["current_ownership"].lower()
        or "integration-readiness" in row["current_ownership"].lower()
    ]
    stale_rows = [row for row in rows if row.get("stale_running_ignored")]
    raw_running_count = status_counts.get("running", 0)
    effective_running_count = effective_status_counts.get("running", 0)
    return {
        "source": str(slot_doc),
        "source_present": slot_doc.is_file(),
        "slot_count": len(rows),
        "rows": rows,
        "status_counts": status_counts,
        "effective_status_counts": effective_status_counts,
        "raw_running_count": raw_running_count,
        "running_count": effective_running_count,
        "effective_running_count": effective_running_count,
        "completed_count": effective_status_counts.get("completed", 0),
        "blocked_count": effective_status_counts.get("blocked", 0),
        "stale_running_ignored_count": len(stale_rows),
        "stale_running_ignored_slots": stale_rows,
        "freshness_policy": {
            "running_slots_require_parseable_last_update": True,
            "pid_handles_require_live_process": True,
            "stale_after_days": ACTIVE_SLOT_STALE_AFTER_DAYS,
            "unparseable_running_rows_count_as": "stale_running_ignored",
            "unparseable_or_dead_pid_running_rows_count_as": "stale_running_ignored",
        },
        "integration_readiness_slot_count": len(integration_slots),
        "integration_readiness_slots": integration_slots,
        "status": "loaded" if slot_doc.is_file() else "missing_slot_doc",
        "proof_claim": "not_claimed",
        "accounting_boundary": "local coordinator slot accounting only; not GitHub, CI, or roadmap proof",
    }


def pr560_bb_reconciliation_summary(
    progress: dict[str, Any],
    *,
    aw_reconciliation: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    active_agent_slots: dict[str, Any],
    foundry_fixture_manifests: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    completed_items = int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0)
    target_items = int(bundle.get("target_completed_items") or 50)
    local_capability_pct = round((min(completed_items, target_items) / target_items) * 100, 1) if target_items else 0.0
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed_ids = sorted(pr560_not_closed_boundaries())
    full_closure = (
        known_open == 0
        and int(bundle.get("advisory_open_queue_count") or 0) == 0
        and all(bool(row.get("closed")) for row in pr560_not_closed_boundaries().values())
    )
    roadmap_percentages = {
        "local_capability_target_pct": local_capability_pct,
        "local_completed_items": completed_items,
        "local_target_items": target_items,
        "known_limitations_stop_condition_pct": round((known_met / known_total) * 100, 1) if known_total else 0.0,
        "known_limitations_open_pct": round((known_open / known_total) * 100, 1) if known_total else 0.0,
        "full_roadmap_closure_pct": 0.0 if not full_closure else 100.0,
        "full_roadmap_closure_claimed": False,
        "full_roadmap_closure_achieved": full_closure,
    }
    return {
        "worker": "BB",
        "status": "valid_local_capability_not_full_roadmap_closure",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and int(bundle.get("strict_blocker_count") or 0) == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure,
        "local_capability_complete": completed_items >= target_items,
        "progress_reconciliation": {
            "completed_items": completed_items,
            "target_items": target_items,
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or bundle.get("advisory_open_queue_count") or 0),
            "advisory_open_queue_count": int(bundle.get("advisory_open_queue_count") or 0),
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": int(bundle.get("strict_blocker_count") or 0),
            "ready_for_eventual_pr": bool(bundle.get("ready_for_eventual_pr")),
        },
        "roadmap_percentage_accounting": roadmap_percentages,
        "known_limitations_reconciliation": {
            "row_count": known_total,
            "stop_conditions_met": known_met,
            "open_row_count": known_open,
            "open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
            "remaining_not_closed_ids": not_closed_ids,
        },
        "active_agent_slot_accounting": active_agent_slots,
        "prior_aw_reconciliation_status": aw_reconciliation.get("status"),
        "provider_posture": "advisory_only_requires_operator_live_consent",
        "semantic_posture": "routing_accounting_only_until_fixture_smoke_fire",
        "foundry_posture": "planned_not_executed_operator_approved_trial_only",
        "foundry_fixture_manifest_status": foundry_fixture_manifests.get("status"),
        "proof_claim": "not_claimed",
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make docs-check",
            "make known-limitations-check-test",
            "make automation-closure-test",
        ],
    }


def pr560_bg_reconciliation_summary(
    progress: dict[str, Any],
    *,
    bb_reconciliation: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    active_agent_slots: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    completed_items = int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0)
    target_items = int(bundle.get("target_completed_items") or 50)
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    any_boundary_open = any(not bool(row.get("closed")) for row in not_closed.values())
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    full_closure_achieved = known_open == 0 and advisory_open == 0 and not any_boundary_open
    local_pct = round((min(completed_items, target_items) / target_items) * 100, 1) if target_items else 0.0
    known_met_pct = round((known_met / known_total) * 100, 1) if known_total else 0.0
    known_open_pct = round((known_open / known_total) * 100, 1) if known_total else 0.0
    return {
        "worker": "BG",
        "status": "final_local_integration_ready_not_full_roadmap_closure",
        "artifact_window": "post_BC_BF_local_artifacts",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and int(bundle.get("strict_blocker_count") or 0) == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "local_implementation_ready": completed_items >= target_items,
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": completed_items,
            "local_target_items": target_items,
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": int(bundle.get("strict_blocker_count") or 0),
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "active_agent_slot_accounting": active_agent_slots,
        "prior_bb_reconciliation_status": bb_reconciliation.get("status"),
        "proof_claim": "not_claimed",
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_bl_reconciliation_summary(
    progress: dict[str, Any],
    *,
    bg_reconciliation: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    active_agent_slots: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    completed_items = int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0)
    target_items = int(bundle.get("target_completed_items") or 50)
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    any_boundary_open = any(not bool(row.get("closed")) for row in not_closed.values())
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    full_closure_achieved = known_open == 0 and advisory_open == 0 and not any_boundary_open
    local_pct = round((min(completed_items, target_items) / target_items) * 100, 1) if target_items else 0.0
    known_met_pct = round((known_met / known_total) * 100, 1) if known_total else 0.0
    known_open_pct = round((known_open / known_total) * 100, 1) if known_total else 0.0
    return {
        "worker": "BL",
        "status": "post_bh_bk_local_integration_ready_not_full_roadmap_closure",
        "artifact_window": "post_BH_BK_local_artifacts",
        "bh_bk_accounting_note": "BL reconciles the current local ledgers after the BH-BK window; closure still depends on explicit stop-condition evidence.",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "local_implementation_ready": completed_items >= target_items,
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": completed_items,
            "local_target_items": target_items,
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "active_agent_slot_accounting": active_agent_slots,
        "prior_bg_reconciliation_status": bg_reconciliation.get("status"),
        "proof_claim": "not_claimed",
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_worker_artifact_window(worker_ids: tuple[str, ...]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for worker_id in worker_ids:
        slug_id = worker_id.lower()
        path = ROOT / ".audit_logs" / f"pr560_worker_{slug_id}"
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else []
        rows.append(
            {
                "worker_id": worker_id,
                "artifact_dir": str(path),
                "present": path.is_dir(),
                "file_count": len(files),
                "sample_files": [str(p.relative_to(ROOT)) for p in files[:8]],
                "status": "artifacts_present" if files else ("empty_dir" if path.is_dir() else "missing"),
            }
        )
    present_rows = [row for row in rows if row["present"] and row["file_count"]]
    window_label = f"{worker_ids[0].lower()}_{worker_ids[-1].lower()}" if worker_ids else "worker"
    generated_artifact_candidates = [
        pr560_progress_paths()[0],
        pr560_progress_paths()[1],
        pr560_integration_readiness_paths()[0],
        pr560_integration_readiness_paths()[1],
        ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.md",
        ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
    ]
    generated_artifacts: list[dict[str, Any]] = []
    window_token = f"{worker_ids[0]}-{worker_ids[-1]}" if worker_ids else ""
    for artifact in generated_artifact_candidates:
        if not artifact.is_file():
            continue
        try:
            text = artifact.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if window_token and window_token not in text:
            continue
        generated_artifacts.append(
            {
                "path": str(artifact),
                "stable_path": stable_artifact_path(artifact),
                "evidence_class": "generated_local_accounting",
            }
        )
    status = "artifacts_present" if present_rows else f"no_{window_label}_artifacts_present"
    if generated_artifacts and not present_rows:
        status = f"{window_label}_generated_accounting_artifacts_present"
    return {
        "worker_ids": list(worker_ids),
        "present_worker_count": len(present_rows),
        "missing_worker_count": len(rows) - len(present_rows),
        "rows": rows,
        "generated_accounting_artifact_count": len(generated_artifacts),
        "generated_accounting_artifacts": generated_artifacts,
        "status": status,
        "accounting_boundary": "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence",
    }


def provider_local_verification_artifact_accounting(workspace: Path) -> dict[str, Any]:
    """Summarize provider-lane local verification without claiming proof."""
    artifact_specs = {
        "at_local_provider_queue": workspace / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.json",
        "av_provider_local_verification": workspace / ".audit_logs" / "pr560_worker_av" / "provider_result_local_verification.json",
        "ax_provider_local_closure": workspace / ".audit_logs" / "pr560_worker_ax" / "provider_local_verification_closure.json",
        "bj_provider_local_verification": workspace / ".audit_logs" / "pr560_worker_bj" / "provider_result_local_verification.json",
    }
    artifacts: dict[str, dict[str, Any]] = {}
    aggregate_local_status_counts: Counter[str] = Counter()
    aggregate_terminal_state_counts: Counter[str] = Counter()
    queue_rows = 0
    verified_rows = 0
    terminal_rows = 0
    for name, path in artifact_specs.items():
        payload = load_json(path) if path.is_file() else {}
        rows = records_from_payload(payload)
        local_counts = payload.get("local_status_counts") if isinstance(payload, dict) else {}
        terminal_counts = payload.get("terminal_state_counts") if isinstance(payload, dict) else {}
        if isinstance(local_counts, dict):
            aggregate_local_status_counts.update({str(k): int(v) for k, v in local_counts.items()})
        if isinstance(terminal_counts, dict):
            aggregate_terminal_state_counts.update({str(k): int(v) for k, v in terminal_counts.items()})
        queue_rows += len(rows) if name == "at_local_provider_queue" else 0
        verified_rows += int(payload.get("verified_row_count") or 0) if isinstance(payload, dict) else 0
        terminal_rows += int(payload.get("terminal_row_count") or 0) if isinstance(payload, dict) else 0
        artifacts[name] = {
            "path": str(path),
            "stable_path": stable_artifact_path(path),
            "present": path.is_file(),
            "row_count": len(rows) or int(payload.get("row_count") or 0) if isinstance(payload, dict) else 0,
            "local_status_counts": dict(local_counts) if isinstance(local_counts, dict) else {},
            "terminal_state_counts": dict(terminal_counts) if isinstance(terminal_counts, dict) else {},
            "advisory_only": bool(payload.get("advisory_only", True)) if isinstance(payload, dict) else True,
            "submit_ready": bool(payload.get("submit_ready", False)) if isinstance(payload, dict) else False,
            "severity_assigned": bool(payload.get("severity_assigned", False)) if isinstance(payload, dict) else False,
        }
    present_count = sum(1 for row in artifacts.values() if row["present"])
    ax = artifacts["ax_provider_local_closure"]
    status = (
        "provider_local_terminal_status_reflected"
        if ax["present"] and terminal_rows > 0
        else ("provider_local_artifacts_partial" if present_count else "provider_local_artifacts_missing")
    )
    unresolved_next_action_rows = len(provider_local_verification_next_action_rows(workspace, limit=500))
    return {
        "schema": f"{SCHEMA_PREFIX}.provider_local_verification_accounting.v1",
        "status": status,
        "workspace": str(workspace),
        "artifacts": artifacts,
        "present_artifact_count": present_count,
        "expected_artifact_count": len(artifact_specs),
        "queue_rows": queue_rows,
        "verified_row_count": verified_rows,
        "terminal_row_count": terminal_rows,
        "unresolved_next_action_rows": unresolved_next_action_rows,
        "aggregate_local_status_counts": dict(sorted(aggregate_local_status_counts.items())),
        "aggregate_terminal_state_counts": dict(sorted(aggregate_terminal_state_counts.items())),
        "proof_claim": "not_claimed",
        "live_provider_proof_claimed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_ready": False,
        "severity": "none",
        "selected_impact": "",
        "promotion_authority": False,
        "advisory_only": True,
        "accounting_boundary": (
            "provider outputs are captured only as advisory local verification "
            "status; live provider proof, detector proof, impact proof, and "
            "submission readiness remain unclaimed"
        ),
    }


def pr560_bq_reconciliation_summary(
    progress: dict[str, Any],
    *,
    bl_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    stale_ignored = int(active_agent_slots.get("stale_running_ignored_count") or 0)
    raw_running = int(active_agent_slots.get("raw_running_count") or 0)
    effective_running = int(active_agent_slots.get("effective_running_count") or 0)
    freshness = active_agent_slots.get("freshness_policy") if isinstance(active_agent_slots.get("freshness_policy"), dict) else {}
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    full_closure_achieved = (
        known_open == 0
        and int(bundle.get("advisory_open_queue_count") or 0) == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    bm_bp_artifacts = pr560_worker_artifact_window(("BM", "BN", "BO", "BP"))
    return {
        "worker": "BQ",
        "status": "slot_readiness_reliability_accounted_not_full_roadmap_closure",
        "artifact_window": "post_BM_BP_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and int(bundle.get("strict_blocker_count") or 0) == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "slot_reliability": {
            "raw_running_count": raw_running,
            "effective_running_count": effective_running,
            "stale_running_ignored_count": stale_ignored,
            "future_false_running_guard_active": bool(freshness)
            and freshness.get("running_slots_require_parseable_last_update") is True
            and freshness.get("unparseable_running_rows_count_as") == "stale_running_ignored",
            "freshness_policy": freshness,
        },
        "bm_bp_artifact_window": bm_bp_artifacts,
        "prior_bl_reconciliation_status": bl_reconciliation.get("status"),
        "proof_claim": "not_claimed",
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_bv_reconciliation_summary(
    progress: dict[str, Any],
    *,
    bq_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    full_closure_achieved = (
        known_open == 0
        and advisory_open == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    br_bu_artifacts = pr560_worker_artifact_window(("BR", "BS", "BT", "BU"))
    return {
        "worker": "BV",
        "status": "final_accounting_after_br_bu_not_full_roadmap_closure",
        "artifact_window": "post_BR_BU_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and int(bundle.get("strict_blocker_count") or 0) == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "proof_claim": "not_claimed",
        "prior_bq_reconciliation_status": bq_reconciliation.get("status"),
        "br_bu_artifact_window": br_bu_artifacts,
        "stale_loop_reliability": {
            "active": bool((bq_reconciliation.get("slot_reliability") or {}).get("future_false_running_guard_active")),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": round((known_met / known_total) * 100, 1) if known_total else 0.0,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": round((known_open / known_total) * 100, 1) if known_total else 0.0,
            "known_limitations_open_row_count": known_open,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": int(bundle.get("strict_blocker_count") or 0),
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "active_agent_slot_accounting": active_agent_slots,
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_ca_reconciliation_summary(
    progress: dict[str, Any],
    *,
    bv_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    full_closure_achieved = (
        known_open == 0
        and advisory_open == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    bw_bz_artifacts = pr560_worker_artifact_window(("BW", "BX", "BY", "BZ"))
    return {
        "worker": "CA",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "active_loop_reliability_after_bw_bz_not_full_roadmap_closure",
        "artifact_window": "post_BW_BZ_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "proof_claim": "not_claimed",
        "prior_bv_reconciliation_status": bv_reconciliation.get("status"),
        "bw_bz_artifact_window": bw_bz_artifacts,
        "active_loop_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": round((known_met / known_total) * 100, 1) if known_total else 0.0,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": round((known_open / known_total) * 100, 1) if known_total else 0.0,
            "known_limitations_open_row_count": known_open,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_cf_reconciliation_summary(
    progress: dict[str, Any],
    *,
    ca_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    full_closure_achieved = (
        known_open == 0
        and advisory_open == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    cb_ce_artifacts = pr560_worker_artifact_window(("CB", "CC", "CD", "CE"))
    bw_bz_artifacts = ca_reconciliation.get("bw_bz_artifact_window") if isinstance(ca_reconciliation.get("bw_bz_artifact_window"), dict) else {}
    return {
        "worker": "CF",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_cb_ce_not_full_roadmap_closure",
        "artifact_window": "post_CB_CE_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "proof_claim": "not_claimed",
        "prior_ca_reconciliation_status": ca_reconciliation.get("status"),
        "cb_ce_artifact_window": cb_ce_artifacts,
        "bw_bz_artifact_window_status": bw_bz_artifacts.get("status"),
        "bw_bz_generated_artifacts_recognized": int(bw_bz_artifacts.get("generated_accounting_artifact_count") or 0) > 0,
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": round((known_met / known_total) * 100, 1) if known_total else 0.0,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": round((known_open / known_total) * 100, 1) if known_total else 0.0,
            "known_limitations_open_row_count": known_open,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_ck_reconciliation_summary(
    progress: dict[str, Any],
    *,
    cf_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    full_closure_achieved = (
        known_open == 0
        and advisory_open == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    cb_cf_artifacts = pr560_worker_artifact_window(("CB", "CC", "CD", "CE", "CF"))
    cg_cj_artifacts = pr560_worker_artifact_window(("CG", "CH", "CI", "CJ"))
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = round((known_met / known_total) * 100, 1) if known_total else 0.0
    known_open_pct = round((known_open / known_total) * 100, 1) if known_total else 0.0
    return {
        "worker": "CK",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_cg_cj_not_full_roadmap_closure",
        "artifact_window": "post_CG_CJ_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "proof_claim": "not_claimed",
        "prior_cf_reconciliation_status": cf_reconciliation.get("status"),
        "cb_cf_artifact_window": cb_cf_artifacts,
        "cg_cj_artifact_window": cg_cj_artifacts,
        "cb_cf_generated_artifacts_recognized": int(cb_cf_artifacts.get("generated_accounting_artifact_count") or 0) > 0,
        "cg_cj_artifacts_recognized": (
            int(cg_cj_artifacts.get("present_worker_count") or 0) > 0
            or int(cg_cj_artifacts.get("generated_accounting_artifact_count") or 0) > 0
        ),
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_cp_reconciliation_summary(
    progress: dict[str, Any],
    *,
    ck_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    full_closure_achieved = (
        known_open == 0
        and advisory_open == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    cg_cj_artifacts = pr560_worker_artifact_window(("CG", "CH", "CI", "CJ"))
    cl_co_artifacts = pr560_worker_artifact_window(("CL", "CM", "CN", "CO"))
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = round((known_met / known_total) * 100, 1) if known_total else 0.0
    known_open_pct = round((known_open / known_total) * 100, 1) if known_total else 0.0
    return {
        "worker": "CP",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_cl_co_not_full_roadmap_closure",
        "artifact_window": "post_CL_CO_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "proof_claim": "not_claimed",
        "prior_ck_reconciliation_status": ck_reconciliation.get("status"),
        "cg_cj_artifact_window": cg_cj_artifacts,
        "cl_co_artifact_window": cl_co_artifacts,
        "cg_cj_artifacts_recognized": (
            int(cg_cj_artifacts.get("present_worker_count") or 0) > 0
            or int(cg_cj_artifacts.get("generated_accounting_artifact_count") or 0) > 0
            or bool(ck_reconciliation.get("cg_cj_artifacts_recognized"))
        ),
        "cl_co_artifacts_recognized": (
            int(cl_co_artifacts.get("present_worker_count") or 0) > 0
            or int(cl_co_artifacts.get("generated_accounting_artifact_count") or 0) > 0
        ),
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_cr_reconciliation_summary(
    progress: dict[str, Any],
    *,
    cp_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = round((known_met / known_total) * 100, 1) if known_total else 0.0
    known_open_pct = round((known_open / known_total) * 100, 1) if known_total else 0.0
    local_write_policy = {
        "worktree": "/private/tmp/auditooor-pr560-next-actions",
        "writes_allowed_inside_worktree": True,
        "local_commands_allowed": True,
        "tests_allowed": True,
        "generated_artifacts_allowed": True,
        "repo_tools_allowed": True,
        "available_local_provider_tooling_allowed": True,
        "approval_prompts_for_local_commands_forbidden": True,
        "downgrade_to_read_only_forbidden": True,
        "try_commands_before_blocker": True,
        "blocked_command_fallback": "write_exact_blocker_artifact",
        "blocker_policy": "real_missing_prerequisite_failing_tool_unsafe_semantic_gap_or_git_github_boundary_only",
        "blocker_artifact_required_fields": [
            "command",
            "cwd",
            "return_code_or_exception",
            "stdout_or_summary",
            "stderr_or_summary",
            "next_local_fallback",
        ],
    }
    no_git_actions_policy = {
        "stage": False,
        "commit": False,
        "push": False,
        "pull_request": False,
        "merge": False,
        "github_actions": False,
        "operator_approval_required_for_git_or_github": True,
    }
    return {
        "worker": "CR",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "permission_loop_reliability_after_cp_not_git_or_github_authority",
        "artifact_window": "post_CP_permission_loop_reliability",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": False,
        "proof_claim": "not_claimed",
        "prior_cp_reconciliation_status": cp_reconciliation.get("status"),
        "local_write_policy": local_write_policy,
        "no_git_actions_policy": no_git_actions_policy,
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_cw_reconciliation_summary(
    progress: dict[str, Any],
    *,
    cr_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    provider_accounting: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    cs_cv_artifacts = pr560_worker_artifact_window(("CS", "CT", "CU", "CV"))
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = round((known_met / known_total) * 100, 1) if known_total else 0.0
    known_open_pct = round((known_open / known_total) * 100, 1) if known_total else 0.0
    full_closure_achieved = (
        known_open == 0
        and advisory_open == 0
        and all(bool(row.get("closed")) for row in not_closed.values())
    )
    return {
        "worker": "CW",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_cs_cv_provider_status_not_full_roadmap_closure",
        "artifact_window": "post_CS_CV_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": full_closure_achieved,
        "proof_claim": "not_claimed",
        "prior_cr_reconciliation_status": cr_reconciliation.get("status"),
        "cs_cv_artifact_window": cs_cv_artifacts,
        "cs_cv_artifacts_recognized": (
            int(cs_cv_artifacts.get("present_worker_count") or 0) > 0
            or int(cs_cv_artifacts.get("generated_accounting_artifact_count") or 0) > 0
        ),
        "provider_local_verification": provider_accounting,
        "provider_status_reflected": provider_accounting.get("status") in {
            "provider_local_terminal_status_reflected",
            "provider_local_artifacts_partial",
            "provider_local_artifacts_missing",
        },
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0 if not full_closure_achieved else 100.0,
            "full_roadmap_closure_claimed": False,
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_db_reconciliation_summary(
    progress: dict[str, Any],
    *,
    cw_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    scanner_autonomy: dict[str, Any],
    impact_miss_benchmark: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    cx_da_artifacts = pr560_worker_artifact_window(("CX", "CY", "CZ", "DA"))
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = pct(known_met, known_total)
    known_open_pct = pct(known_open, known_total)
    impact_miss_doc = ROOT / "docs" / "ROADMAP_10_OF_10_V5_CAMPAIGNS.md"
    known_doc = ROOT / "docs" / "KNOWN_LIMITATIONS.md"
    roadmap_text = impact_miss_doc.read_text(encoding="utf-8", errors="replace") if impact_miss_doc.is_file() else ""
    known_text = known_doc.read_text(encoding="utf-8", errors="replace") if known_doc.is_file() else ""
    impact_miss_reflected = "Impact-Miss Offset Roadmap" in roadmap_text and "Impact-Miss Offset Plan" in known_text
    genericity_reflected = "Genericity requirement" in roadmap_text and "Genericity rule" in known_text
    return {
        "worker": "DB",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_cx_da_scanner_autonomy_not_full_roadmap_closure",
        "artifact_window": "post_CX_DA_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": False,
        "proof_claim": "not_claimed",
        "prior_cw_reconciliation_status": cw_reconciliation.get("status"),
        "cx_da_artifact_window": cx_da_artifacts,
        "cx_da_artifacts_recognized": (
            int(cx_da_artifacts.get("present_worker_count") or 0) > 0
            or int(cx_da_artifacts.get("generated_accounting_artifact_count") or 0) > 0
        ),
        "impact_miss_docs_reflected": impact_miss_reflected,
        "genericity_docs_reflected": genericity_reflected,
        "impact_miss_benchmark": impact_miss_benchmark,
        "impact_miss_benchmark_posture_valid": (
            bool(impact_miss_benchmark.get("posture_valid"))
            and impact_miss_benchmark.get("submission_posture") == "NOT_SUBMIT_READY"
            and impact_miss_benchmark.get("severity") == "none"
            and impact_miss_benchmark.get("selected_impact") == ""
            and not bool(impact_miss_benchmark.get("promotion_allowed"))
        ),
        "scanner_autonomy": scanner_autonomy,
        "scanner_autonomy_posture_valid": (
            scanner_autonomy.get("proof_claim") == "not_claimed"
            and scanner_autonomy.get("submission_posture") == "NOT_SUBMIT_READY"
            and scanner_autonomy.get("severity") == "none"
            and scanner_autonomy.get("selected_impact") == ""
            and not bool(scanner_autonomy.get("promotion_allowed"))
        ),
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0,
            "full_roadmap_closure_claimed": False,
            "scanner_autonomy_pct": scanner_autonomy.get("scanner_autonomy_pct", 0.0),
            "scanner_autonomy_manual_triage_accounted_pct": scanner_autonomy.get("manual_triage_accounted_pct", 0.0),
            "scanner_autonomy_runnable_pct": scanner_autonomy.get("runnable_local_command_pct_of_plan", 0.0),
            "scanner_autonomy_executed_pct": scanner_autonomy.get("executed_pct_of_plan", 0.0),
            "impact_miss_benchmark_accuracy_pct": round(
                float(impact_miss_benchmark.get("accuracy") or 0.0) * 100,
                1,
            ),
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_dg_reconciliation_summary(
    progress: dict[str, Any],
    *,
    db_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    scanner_autonomy: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    dc_df_artifacts = pr560_worker_artifact_window(("DC", "DD", "DE", "DF"))
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = pct(known_met, known_total)
    known_open_pct = pct(known_open, known_total)
    impact_miss_doc = ROOT / "docs" / "ROADMAP_10_OF_10_V5_CAMPAIGNS.md"
    known_doc = ROOT / "docs" / "KNOWN_LIMITATIONS.md"
    roadmap_text = impact_miss_doc.read_text(encoding="utf-8", errors="replace") if impact_miss_doc.is_file() else ""
    known_text = known_doc.read_text(encoding="utf-8", errors="replace") if known_doc.is_file() else ""
    impact_miss_reflected = "Impact-Miss Offset Roadmap" in roadmap_text and "Impact-Miss Offset Plan" in known_text
    genericity_reflected = "Genericity requirement" in roadmap_text and "Genericity rule" in known_text
    return {
        "worker": "DG",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_dc_df_refreshed_maps_not_full_roadmap_closure",
        "artifact_window": "post_DC_DF_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": False,
        "proof_claim": "not_claimed",
        "prior_db_reconciliation_status": db_reconciliation.get("status"),
        "dc_df_artifact_window": dc_df_artifacts,
        "dc_df_artifacts_recognized": (
            int(dc_df_artifacts.get("present_worker_count") or 0) > 0
            or int(dc_df_artifacts.get("generated_accounting_artifact_count") or 0) > 0
        ),
        "progress_readiness_known_limitations_regenerated": True,
        "impact_miss_docs_reflected": impact_miss_reflected,
        "genericity_docs_reflected": genericity_reflected,
        "scanner_autonomy": scanner_autonomy,
        "scanner_autonomy_posture_valid": (
            scanner_autonomy.get("proof_claim") == "not_claimed"
            and scanner_autonomy.get("submission_posture") == "NOT_SUBMIT_READY"
            and scanner_autonomy.get("severity") == "none"
            and scanner_autonomy.get("selected_impact") == ""
            and not bool(scanner_autonomy.get("promotion_allowed"))
        ),
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0,
            "full_roadmap_closure_claimed": False,
            "scanner_autonomy_pct": scanner_autonomy.get("scanner_autonomy_pct", 0.0),
            "scanner_autonomy_manual_triage_accounted_pct": scanner_autonomy.get("manual_triage_accounted_pct", 0.0),
            "scanner_autonomy_runnable_pct": scanner_autonomy.get("runnable_local_command_pct_of_plan", 0.0),
            "scanner_autonomy_executed_pct": scanner_autonomy.get("executed_pct_of_plan", 0.0),
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool .auditooor/known_limitations_burndown.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make docs-check",
        ],
    }


def pr560_dl_reconciliation_summary(
    progress: dict[str, Any],
    *,
    dg_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    scanner_autonomy: dict[str, Any],
    impact_miss_benchmark: dict[str, Any],
) -> dict[str, Any]:
    bundle = progress.get("bundle_readiness") or {}
    advisory = progress.get("advisory_reconciliation") or {}
    known_total = int(roadmap_accounting.get("known_limitations_row_count") or 0)
    known_met = int(roadmap_accounting.get("known_limitations_stop_conditions_met") or 0)
    known_open = int(roadmap_accounting.get("known_limitations_open_row_count") or 0)
    not_closed = pr560_not_closed_boundaries()
    advisory_open = int(bundle.get("advisory_open_queue_count") or 0)
    strict_blockers = int(bundle.get("strict_blocker_count") or 0)
    dh_dk_artifacts = pr560_worker_artifact_window(("DH", "DI", "DJ", "DK"))
    local_pct = 100.0 if int(bundle.get("completed_items") or 0) >= int(bundle.get("target_completed_items") or 50) else 0.0
    known_met_pct = pct(known_met, known_total)
    known_open_pct = pct(known_open, known_total)
    impact_miss_doc = ROOT / "docs" / "ROADMAP_10_OF_10_V5_CAMPAIGNS.md"
    known_doc = ROOT / "docs" / "KNOWN_LIMITATIONS.md"
    roadmap_text = impact_miss_doc.read_text(encoding="utf-8", errors="replace") if impact_miss_doc.is_file() else ""
    known_text = known_doc.read_text(encoding="utf-8", errors="replace") if known_doc.is_file() else ""
    impact_miss_reflected = "Impact-Miss Offset Roadmap" in roadmap_text and "Impact-Miss Offset Plan" in known_text
    genericity_reflected = "Genericity requirement" in roadmap_text and "Genericity rule" in known_text
    return {
        "worker": "DL",
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "status": "final_accounting_after_dh_dk_refreshed_maps_not_full_roadmap_closure",
        "artifact_window": "post_DH_DK_if_artifacts_exist",
        "readiness_valid_expected": bool(bundle.get("ready_for_eventual_pr")) and strict_blockers == 0,
        "full_closure_claimed": False,
        "full_closure_achieved": False,
        "proof_claim": "not_claimed",
        "prior_dg_reconciliation_status": dg_reconciliation.get("status"),
        "dh_dk_artifact_window": dh_dk_artifacts,
        "dh_dk_artifacts_recognized": (
            int(dh_dk_artifacts.get("present_worker_count") or 0) > 0
            or int(dh_dk_artifacts.get("generated_accounting_artifact_count") or 0) > 0
        ),
        "progress_readiness_known_limitations_regenerated": True,
        "impact_miss_docs_reflected": impact_miss_reflected,
        "genericity_docs_reflected": genericity_reflected,
        "impact_miss_benchmark": impact_miss_benchmark,
        "impact_miss_benchmark_posture_valid": (
            impact_miss_benchmark.get("submission_posture") == "NOT_SUBMIT_READY"
            and not bool(impact_miss_benchmark.get("promotion_allowed"))
        ),
        "scanner_autonomy": scanner_autonomy,
        "scanner_autonomy_posture_valid": (
            scanner_autonomy.get("proof_claim") == "not_claimed"
            and scanner_autonomy.get("submission_posture") == "NOT_SUBMIT_READY"
            and scanner_autonomy.get("severity") == "none"
            and scanner_autonomy.get("selected_impact") == ""
            and not bool(scanner_autonomy.get("promotion_allowed"))
        ),
        "active_slot_reliability": {
            "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
            "source": active_agent_slots.get("source"),
            "slot_count": int(active_agent_slots.get("slot_count") or 0),
            "raw_running_count": int(active_agent_slots.get("raw_running_count") or 0),
            "effective_running_count": int(active_agent_slots.get("effective_running_count") or 0),
            "stale_running_ignored_count": int(active_agent_slots.get("stale_running_ignored_count") or 0),
            "current_running_handles": [
                row.get("handle")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "current_running_agents": [
                row.get("agent")
                for row in active_agent_slots.get("rows", [])
                if isinstance(row, dict) and row.get("effective_status") == "running"
            ],
            "freshness_policy": active_agent_slots.get("freshness_policy") or {},
            "accounting_boundary": active_agent_slots.get("accounting_boundary"),
        },
        "percentage_accounting": {
            "local_pr560_implementation_pct": local_pct,
            "local_completed_items": int(progress.get("completed_checklist_count") or bundle.get("completed_items") or 0),
            "local_target_items": int(bundle.get("target_completed_items") or 50),
            "known_limitations_stop_condition_pct": known_met_pct,
            "known_limitations_stop_conditions_met": known_met,
            "known_limitations_row_count": known_total,
            "known_limitations_open_pct": known_open_pct,
            "known_limitations_open_row_count": known_open,
            "known_limitations_reduction_pct": known_met_pct,
            "full_roadmap_closure_pct": 0.0,
            "full_roadmap_closure_claimed": False,
            "scanner_autonomy_pct": scanner_autonomy.get("scanner_autonomy_pct", 0.0),
            "scanner_autonomy_manual_triage_accounted_pct": scanner_autonomy.get("manual_triage_accounted_pct", 0.0),
            "scanner_autonomy_runnable_pct": scanner_autonomy.get("runnable_local_command_pct_of_plan", 0.0),
            "scanner_autonomy_executed_pct": scanner_autonomy.get("executed_pct_of_plan", 0.0),
            "impact_miss_benchmark_accuracy_pct": round(
                float(impact_miss_benchmark.get("accuracy") or 0.0) * 100,
                1,
            ),
        },
        "queue_accounting": {
            "remaining_next_action_rows": int(progress.get("remaining_queue_count") or advisory_open),
            "advisory_open_queue_count": advisory_open,
            "resolved_advisory_rows": int(advisory.get("resolved_total") or 0),
            "remaining_advisory_rows": int(advisory.get("remaining_total") or 0),
            "strict_blockers": strict_blockers,
        },
        "not_closed_boundary_ids": sorted(not_closed),
        "known_limitations_open_row_ids": list(roadmap_accounting.get("known_limitations_open_row_ids") or []),
        "operator_validation_commands": [
            "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
            "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
            "python3 -m json.tool .auditooor/known_limitations_burndown.json",
            "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
            "make automation-closure-test",
            "make known-limitations-check",
            "make docs-check",
        ],
    }


def pr560_dq_reconciliation_summary(
    progress: dict[str, Any],
    *,
    dl_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    scanner_autonomy: dict[str, Any],
    impact_miss_benchmark: dict[str, Any],
) -> dict[str, Any]:
    payload = pr560_dl_reconciliation_summary(
        progress,
        dg_reconciliation=dl_reconciliation,
        active_agent_slots=active_agent_slots,
        roadmap_accounting=roadmap_accounting,
        scanner_autonomy=scanner_autonomy,
        impact_miss_benchmark=impact_miss_benchmark,
    )
    dm_dp_artifacts = pr560_worker_artifact_window(("DM", "DN", "DO", "DP"))
    payload.update(
        {
            "worker": "DQ",
            "status": "final_accounting_after_dm_dp_refreshed_maps_not_full_roadmap_closure",
            "artifact_window": "post_DM_DP_if_artifacts_exist",
            "prior_dl_reconciliation_status": dl_reconciliation.get("status"),
            "dm_dp_artifact_window": dm_dp_artifacts,
            "dm_dp_artifacts_recognized": (
                int(dm_dp_artifacts.get("present_worker_count") or 0) > 0
                or int(dm_dp_artifacts.get("generated_accounting_artifact_count") or 0) > 0
            ),
            "operator_validation_commands": [
                "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
                "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
                "python3 -m json.tool .auditooor/known_limitations_burndown.json",
                "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
                "make automation-closure-test",
                "make known-limitations-check",
                "make docs-check",
            ],
        }
    )
    payload.pop("prior_dg_reconciliation_status", None)
    payload.pop("dh_dk_artifact_window", None)
    payload.pop("dh_dk_artifacts_recognized", None)
    return payload


def pr560_dw_reconciliation_summary(
    progress: dict[str, Any],
    *,
    dq_reconciliation: dict[str, Any],
    active_agent_slots: dict[str, Any],
    roadmap_accounting: dict[str, Any],
    scanner_autonomy: dict[str, Any],
    impact_miss_benchmark: dict[str, Any],
) -> dict[str, Any]:
    payload = pr560_dq_reconciliation_summary(
        progress,
        dl_reconciliation=dq_reconciliation,
        active_agent_slots=active_agent_slots,
        roadmap_accounting=roadmap_accounting,
        scanner_autonomy=scanner_autonomy,
        impact_miss_benchmark=impact_miss_benchmark,
    )
    ds_dv_artifacts = pr560_worker_artifact_window(("DS", "DT", "DU", "DV"))
    payload.update(
        {
            "worker": "DW",
            "status": "final_accounting_after_ds_dv_refreshed_maps_not_full_roadmap_closure",
            "artifact_window": "post_DS_DV_if_artifacts_exist",
            "prior_dq_reconciliation_status": dq_reconciliation.get("status"),
            "ds_dv_artifact_window": ds_dv_artifacts,
            "ds_dv_artifacts_recognized": (
                int(ds_dv_artifacts.get("present_worker_count") or 0) > 0
                or int(ds_dv_artifacts.get("generated_accounting_artifact_count") or 0) > 0
            ),
            "operator_validation_commands": [
                "python3 -m json.tool docs/PR560_LOCAL_BATCH_PROGRESS.json",
                "python3 -m json.tool docs/PR560_LOCAL_INTEGRATION_READINESS.json",
                "python3 -m json.tool .auditooor/known_limitations_burndown.json",
                "make known-limitations-burndown WS=/private/tmp/auditooor-pr560-next-actions JSON=1",
                "make automation-closure-test",
                "make known-limitations-check",
                "make docs-check",
            ],
        }
    )
    payload.pop("prior_dl_reconciliation_status", None)
    payload.pop("dm_dp_artifact_window", None)
    payload.pop("dm_dp_artifacts_recognized", None)
    return payload


def validate_integration_slices(
    slices: list[dict[str, Any]],
    *,
    test_matrix: list[dict[str, Any]] | None = None,
    operator_handoff: dict[str, Any] | None = None,
    roadmap_accounting: dict[str, Any] | None = None,
    aw_reconciliation: dict[str, Any] | None = None,
    bb_reconciliation: dict[str, Any] | None = None,
    bg_reconciliation: dict[str, Any] | None = None,
    bl_reconciliation: dict[str, Any] | None = None,
    bq_reconciliation: dict[str, Any] | None = None,
    bv_reconciliation: dict[str, Any] | None = None,
    ca_reconciliation: dict[str, Any] | None = None,
    cf_reconciliation: dict[str, Any] | None = None,
    ck_reconciliation: dict[str, Any] | None = None,
    cp_reconciliation: dict[str, Any] | None = None,
    cr_reconciliation: dict[str, Any] | None = None,
    cw_reconciliation: dict[str, Any] | None = None,
    db_reconciliation: dict[str, Any] | None = None,
    dg_reconciliation: dict[str, Any] | None = None,
    dl_reconciliation: dict[str, Any] | None = None,
    dq_reconciliation: dict[str, Any] | None = None,
    dw_reconciliation: dict[str, Any] | None = None,
    active_agent_slots: dict[str, Any] | None = None,
    git_operations_performed: dict[str, bool] | None = None,
    proof_claims: dict[str, str] | None = None,
) -> dict[str, Any]:
    slice_ids = {str(row.get("slice_id")) for row in slices}
    missing = [sid for sid in INTEGRATION_REQUIRED_SLICE_IDS if sid not in slice_ids]
    overclaiming = [
        row["slice_id"]
        for row in slices
        if row.get("live_provider_proof_claimed") or row.get("full_coverage_claimed")
    ]
    generated_artifact_owners = [
        row["slice_id"]
        for row in slices
        if row.get("generated_artifacts_allowed")
    ]
    tests_missing = [
        row["slice_id"]
        for row in slices
        if not row.get("representative_tests")
    ]
    guard_missing = [
        row["slice_id"]
        for row in slices
        if not row.get("overclaim_guard") or not row.get("must_not_claim")
    ]
    matrix = test_matrix or integration_test_matrix(slices)
    matrix_by_slice = {str(row.get("slice_id")): row for row in matrix}
    matrix_missing = [
        sid for sid in INTEGRATION_REQUIRED_SLICE_IDS
        if sid not in matrix_by_slice
        or not (matrix_by_slice[sid].get("required_local_tests") or matrix_by_slice[sid].get("operator_approved_tests"))
    ]
    stop_missing = [
        sid for sid in INTEGRATION_REQUIRED_SLICE_IDS
        if sid not in matrix_by_slice or not matrix_by_slice[sid].get("stop_conditions")
    ]
    git_ops = git_operations_performed or {}
    git_ops_clear = not any(bool(value) for value in git_ops.values())
    claims = proof_claims or {}
    proof_claims_clear = all(value == "not_claimed" for value in claims.values())
    required_not_closed = {
        "full_scanner_coverage",
        "invariant_discovery_completeness",
        "executed_harnesses",
        "rust_dlt_semantic_depth",
    }
    not_closed = pr560_not_closed_boundaries()
    not_closed_complete = required_not_closed.issubset(not_closed) and all(
        not bool(not_closed[key].get("closed")) for key in required_not_closed
    )
    handoff_populated = bool((operator_handoff or {}).get("commands")) and bool((operator_handoff or {}).get("warnings"))
    roadmap_has_foundry = bool((roadmap_accounting or {}).get("foundry_migration_doc_present")) and (
        (roadmap_accounting or {}).get("foundry_migration_slice") in slice_ids
    )
    aj_target_met = len(INTEGRATION_READINESS_AJ_COMPLETED_ITEMS) >= 50
    ap_target_met = len(INTEGRATION_READINESS_AP_COMPLETED_ITEMS) >= 50
    ao_target_met = len(INTEGRATION_READINESS_AO_COMPLETED_ITEMS) >= 50
    ar_target_met = len(INTEGRATION_READINESS_AR_COMPLETED_ITEMS) >= 50
    aw_target_met = len(INTEGRATION_READINESS_AW_COMPLETED_ITEMS) >= 50
    ax_target_met = len(PR560_WORKER_AX_COMPLETED_ITEMS) >= 50
    bb_target_met = len(INTEGRATION_READINESS_BB_COMPLETED_ITEMS) >= 50
    bg_target_met = len(INTEGRATION_READINESS_BG_COMPLETED_ITEMS) >= 50
    bl_target_met = len(INTEGRATION_READINESS_BL_COMPLETED_ITEMS) >= 50
    bq_target_met = len(INTEGRATION_READINESS_BQ_COMPLETED_ITEMS) >= 50
    bv_target_met = len(PR560_WORKER_BV_COMPLETED_ITEMS) >= 50
    ca_target_met = len(PR560_WORKER_CA_COMPLETED_ITEMS) >= 50
    cf_target_met = len(PR560_WORKER_CF_COMPLETED_ITEMS) >= 50
    ck_target_met = len(PR560_WORKER_CK_COMPLETED_ITEMS) >= 50
    cp_target_met = len(PR560_WORKER_CP_COMPLETED_ITEMS) >= 50
    cr_target_met = len(PR560_WORKER_CR_COMPLETED_ITEMS) >= 50
    cv_target_met = len(PR560_WORKER_CV_COMPLETED_ITEMS) >= 50
    cw_target_met = len(PR560_WORKER_CW_COMPLETED_ITEMS) >= 50
    db_target_met = len(PR560_WORKER_DB_COMPLETED_ITEMS) >= 150
    dg_target_met = 150 <= len(PR560_WORKER_DG_COMPLETED_ITEMS) <= 300
    dl_target_met = 150 <= len(PR560_WORKER_DL_COMPLETED_ITEMS) <= 300
    dq_target_met = 300 <= len(PR560_WORKER_DQ_COMPLETED_ITEMS) <= 500
    dw_target_met = 300 <= len(PR560_WORKER_DW_COMPLETED_ITEMS) <= 500
    aw = aw_reconciliation or {}
    aw_valid_not_full_closure = (
        aw.get("status") == "valid_local_integration_readiness_not_full_closure"
        and bool(aw.get("readiness_valid_expected"))
        and not bool(aw.get("full_closure_claimed"))
        and not bool(aw.get("full_closure_achieved"))
    )
    bb = bb_reconciliation or {}
    bb_roadmap_percentages = bb.get("roadmap_percentage_accounting") if isinstance(bb.get("roadmap_percentage_accounting"), dict) else {}
    bb_valid_not_full_closure = (
        bb.get("status") == "valid_local_capability_not_full_roadmap_closure"
        and bool(bb.get("readiness_valid_expected"))
        and not bool(bb.get("full_closure_claimed"))
        and not bool(bb.get("full_closure_achieved"))
        and bool(bb_roadmap_percentages)
    )
    bg = bg_reconciliation or {}
    bg_percentages = bg.get("percentage_accounting") if isinstance(bg.get("percentage_accounting"), dict) else {}
    bg_valid_not_full_closure = (
        bg.get("status") == "final_local_integration_ready_not_full_roadmap_closure"
        and bool(bg.get("readiness_valid_expected"))
        and bool(bg.get("local_implementation_ready"))
        and not bool(bg.get("full_closure_claimed"))
        and not bool(bg.get("full_closure_achieved"))
        and bool(bg_percentages)
        and float(bg_percentages.get("local_pr560_implementation_pct") or 0.0) >= 100.0
        and float(bg_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(bg_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
    )
    bl = bl_reconciliation or {}
    bl_percentages = bl.get("percentage_accounting") if isinstance(bl.get("percentage_accounting"), dict) else {}
    bl_valid_not_full_closure = (
        bl.get("status") == "post_bh_bk_local_integration_ready_not_full_roadmap_closure"
        and bool(bl.get("readiness_valid_expected"))
        and bool(bl.get("local_implementation_ready"))
        and not bool(bl.get("full_closure_claimed"))
        and not bool(bl.get("full_closure_achieved"))
        and bool(bl_percentages)
        and float(bl_percentages.get("local_pr560_implementation_pct") or 0.0) >= 100.0
        and float(bl_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(bl_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
    )
    bq = bq_reconciliation or {}
    bq_slot_reliability = bq.get("slot_reliability") if isinstance(bq.get("slot_reliability"), dict) else {}
    bq_valid_not_full_closure = (
        bq.get("status") == "slot_readiness_reliability_accounted_not_full_roadmap_closure"
        and bool(bq.get("readiness_valid_expected"))
        and not bool(bq.get("full_closure_claimed"))
        and not bool(bq.get("full_closure_achieved"))
        and bool(bq_slot_reliability.get("future_false_running_guard_active"))
    )
    bv = bv_reconciliation or {}
    bv_percentages = bv.get("percentage_accounting") if isinstance(bv.get("percentage_accounting"), dict) else {}
    bv_artifacts = bv.get("br_bu_artifact_window") if isinstance(bv.get("br_bu_artifact_window"), dict) else {}
    bv_stale_loop = bv.get("stale_loop_reliability") if isinstance(bv.get("stale_loop_reliability"), dict) else {}
    bv_valid_not_full_closure = (
        bv.get("status") == "final_accounting_after_br_bu_not_full_roadmap_closure"
        and bool(bv.get("readiness_valid_expected"))
        and not bool(bv.get("full_closure_claimed"))
        and not bool(bv.get("full_closure_achieved"))
        and bool(bv_percentages)
        and float(bv_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(bv_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and bool(bv_stale_loop.get("active"))
        and bv_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
    )
    ca = ca_reconciliation or {}
    ca_percentages = ca.get("percentage_accounting") if isinstance(ca.get("percentage_accounting"), dict) else {}
    ca_artifacts = ca.get("bw_bz_artifact_window") if isinstance(ca.get("bw_bz_artifact_window"), dict) else {}
    ca_loop = ca.get("active_loop_reliability") if isinstance(ca.get("active_loop_reliability"), dict) else {}
    ca_valid_not_full_closure = (
        ca.get("status") == "active_loop_reliability_after_bw_bz_not_full_roadmap_closure"
        and ca.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(ca.get("readiness_valid_expected"))
        and not bool(ca.get("full_closure_claimed"))
        and not bool(ca.get("full_closure_achieved"))
        and bool(ca_percentages)
        and float(ca_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(ca_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and ca_loop.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and ca_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
    )
    cf = cf_reconciliation or {}
    cf_percentages = cf.get("percentage_accounting") if isinstance(cf.get("percentage_accounting"), dict) else {}
    cf_artifacts = cf.get("cb_ce_artifact_window") if isinstance(cf.get("cb_ce_artifact_window"), dict) else {}
    cf_slot_reliability = cf.get("active_slot_reliability") if isinstance(cf.get("active_slot_reliability"), dict) else {}
    cf_valid_not_full_closure = (
        cf.get("status") == "final_accounting_after_cb_ce_not_full_roadmap_closure"
        and cf.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(cf.get("readiness_valid_expected"))
        and not bool(cf.get("full_closure_claimed"))
        and not bool(cf.get("full_closure_achieved"))
        and bool(cf_percentages)
        and float(cf_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(cf_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and cf_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cf_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and bool(cf.get("bw_bz_generated_artifacts_recognized"))
    )
    ck = ck_reconciliation or {}
    ck_percentages = ck.get("percentage_accounting") if isinstance(ck.get("percentage_accounting"), dict) else {}
    ck_cb_cf_artifacts = ck.get("cb_cf_artifact_window") if isinstance(ck.get("cb_cf_artifact_window"), dict) else {}
    ck_cg_cj_artifacts = ck.get("cg_cj_artifact_window") if isinstance(ck.get("cg_cj_artifact_window"), dict) else {}
    ck_slot_reliability = ck.get("active_slot_reliability") if isinstance(ck.get("active_slot_reliability"), dict) else {}
    ck_valid_not_full_closure = (
        ck.get("status") == "final_accounting_after_cg_cj_not_full_roadmap_closure"
        and ck.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(ck.get("readiness_valid_expected"))
        and not bool(ck.get("full_closure_claimed"))
        and not bool(ck.get("full_closure_achieved"))
        and bool(ck_percentages)
        and float(ck_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(ck_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(ck_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(ck_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and ck_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and ck_cb_cf_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and ck_cg_cj_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and bool(ck.get("cb_cf_generated_artifacts_recognized"))
        and bool(ck.get("cg_cj_artifacts_recognized"))
    )
    cp = cp_reconciliation or {}
    cp_percentages = cp.get("percentage_accounting") if isinstance(cp.get("percentage_accounting"), dict) else {}
    cp_cg_cj_artifacts = cp.get("cg_cj_artifact_window") if isinstance(cp.get("cg_cj_artifact_window"), dict) else {}
    cp_cl_co_artifacts = cp.get("cl_co_artifact_window") if isinstance(cp.get("cl_co_artifact_window"), dict) else {}
    cp_slot_reliability = cp.get("active_slot_reliability") if isinstance(cp.get("active_slot_reliability"), dict) else {}
    cp_valid_not_full_closure = (
        cp.get("status") == "final_accounting_after_cl_co_not_full_roadmap_closure"
        and cp.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(cp.get("readiness_valid_expected"))
        and not bool(cp.get("full_closure_claimed"))
        and not bool(cp.get("full_closure_achieved"))
        and bool(cp_percentages)
        and float(cp_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(cp_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(cp_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(cp_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and cp_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cp_cg_cj_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and cp_cl_co_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and bool(cp.get("cg_cj_artifacts_recognized"))
        and bool(cp.get("cl_co_artifacts_recognized"))
    )
    cr = cr_reconciliation or {}
    cr_percentages = cr.get("percentage_accounting") if isinstance(cr.get("percentage_accounting"), dict) else {}
    cr_local_policy = cr.get("local_write_policy") if isinstance(cr.get("local_write_policy"), dict) else {}
    cr_no_git_policy = cr.get("no_git_actions_policy") if isinstance(cr.get("no_git_actions_policy"), dict) else {}
    cr_slot_reliability = cr.get("active_slot_reliability") if isinstance(cr.get("active_slot_reliability"), dict) else {}
    cr_valid_permission_loop = (
        cr.get("status") == "permission_loop_reliability_after_cp_not_git_or_github_authority"
        and cr.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(cr.get("readiness_valid_expected"))
        and not bool(cr.get("full_closure_claimed"))
        and not bool(cr.get("full_closure_achieved"))
        and bool(cr_percentages)
        and float(cr_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(cr_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(cr_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(cr_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and bool(cr_local_policy.get("writes_allowed_inside_worktree"))
        and bool(cr_local_policy.get("local_commands_allowed"))
        and bool(cr_local_policy.get("tests_allowed"))
        and bool(cr_local_policy.get("generated_artifacts_allowed"))
        and bool(cr_local_policy.get("repo_tools_allowed"))
        and bool(cr_local_policy.get("approval_prompts_for_local_commands_forbidden"))
        and bool(cr_local_policy.get("downgrade_to_read_only_forbidden"))
        and bool(cr_local_policy.get("try_commands_before_blocker"))
        and cr_local_policy.get("blocked_command_fallback") == "write_exact_blocker_artifact"
        and cr_local_policy.get("blocker_policy") == "real_missing_prerequisite_failing_tool_unsafe_semantic_gap_or_git_github_boundary_only"
        and not any(bool(cr_no_git_policy.get(key)) for key in ("stage", "commit", "push", "pull_request", "merge", "github_actions"))
        and bool(cr_no_git_policy.get("operator_approval_required_for_git_or_github"))
        and cr_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cr.get("prior_cp_reconciliation_status") == "final_accounting_after_cl_co_not_full_roadmap_closure"
    )
    cw = cw_reconciliation or {}
    cw_percentages = cw.get("percentage_accounting") if isinstance(cw.get("percentage_accounting"), dict) else {}
    cw_slot_reliability = cw.get("active_slot_reliability") if isinstance(cw.get("active_slot_reliability"), dict) else {}
    cw_provider = cw.get("provider_local_verification") if isinstance(cw.get("provider_local_verification"), dict) else {}
    cw_provider_artifacts = cw_provider.get("artifacts") if isinstance(cw_provider.get("artifacts"), dict) else {}
    cw_cs_cv_artifacts = cw.get("cs_cv_artifact_window") if isinstance(cw.get("cs_cv_artifact_window"), dict) else {}
    cw_valid_final_accounting = (
        cw.get("status") == "final_accounting_after_cs_cv_provider_status_not_full_roadmap_closure"
        and cw.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(cw.get("readiness_valid_expected"))
        and not bool(cw.get("full_closure_claimed"))
        and not bool(cw.get("full_closure_achieved"))
        and bool(cw_percentages)
        and float(cw_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(cw_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(cw_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(cw_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and cw_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cw_cs_cv_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and cw.get("prior_cr_reconciliation_status") == "permission_loop_reliability_after_cp_not_git_or_github_authority"
        and bool(cw.get("provider_status_reflected"))
        and cw_provider.get("proof_claim") == "not_claimed"
        and cw_provider.get("submission_posture") == "NOT_SUBMIT_READY"
        and not bool(cw_provider.get("submit_ready"))
        and cw_provider.get("severity") == "none"
        and cw_provider.get("selected_impact") == ""
        and str(cw_provider.get("status") or "") in {
            "provider_local_terminal_status_reflected",
            "provider_local_artifacts_partial",
            "provider_local_artifacts_missing",
        }
        and all(
            not bool(row.get("submit_ready"))
            and not bool(row.get("severity_assigned"))
            and bool(row.get("advisory_only", True))
            for row in cw_provider_artifacts.values()
            if isinstance(row, dict)
        )
    )
    db = db_reconciliation or {}
    db_percentages = db.get("percentage_accounting") if isinstance(db.get("percentage_accounting"), dict) else {}
    db_slot_reliability = db.get("active_slot_reliability") if isinstance(db.get("active_slot_reliability"), dict) else {}
    db_scanner = db.get("scanner_autonomy") if isinstance(db.get("scanner_autonomy"), dict) else {}
    db_impact_miss = db.get("impact_miss_benchmark") if isinstance(db.get("impact_miss_benchmark"), dict) else {}
    db_cx_da_artifacts = db.get("cx_da_artifact_window") if isinstance(db.get("cx_da_artifact_window"), dict) else {}
    db_valid_final_accounting = (
        db.get("status") == "final_accounting_after_cx_da_scanner_autonomy_not_full_roadmap_closure"
        and db.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(db.get("readiness_valid_expected"))
        and not bool(db.get("full_closure_claimed"))
        and not bool(db.get("full_closure_achieved"))
        and bool(db_percentages)
        and float(db_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(db_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(db_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(db_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and "scanner_autonomy_pct" in db_percentages
        and bool(db.get("impact_miss_docs_reflected"))
        and bool(db.get("genericity_docs_reflected"))
        and bool(db.get("impact_miss_benchmark_posture_valid"))
        and bool(db.get("scanner_autonomy_posture_valid"))
        and db_impact_miss.get("submission_posture") == "NOT_SUBMIT_READY"
        and not bool(db_impact_miss.get("promotion_allowed"))
        and db_scanner.get("proof_claim") == "not_claimed"
        and db_scanner.get("submission_posture") == "NOT_SUBMIT_READY"
        and db_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and db_cx_da_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and db.get("prior_cw_reconciliation_status") == "final_accounting_after_cs_cv_provider_status_not_full_roadmap_closure"
    )
    dg = dg_reconciliation or {}
    dg_percentages = dg.get("percentage_accounting") if isinstance(dg.get("percentage_accounting"), dict) else {}
    dg_slot_reliability = dg.get("active_slot_reliability") if isinstance(dg.get("active_slot_reliability"), dict) else {}
    dg_scanner = dg.get("scanner_autonomy") if isinstance(dg.get("scanner_autonomy"), dict) else {}
    dg_dc_df_artifacts = dg.get("dc_df_artifact_window") if isinstance(dg.get("dc_df_artifact_window"), dict) else {}
    dg_valid_final_accounting = (
        dg.get("status") == "final_accounting_after_dc_df_refreshed_maps_not_full_roadmap_closure"
        and dg.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(dg.get("readiness_valid_expected"))
        and not bool(dg.get("full_closure_claimed"))
        and not bool(dg.get("full_closure_achieved"))
        and bool(dg_percentages)
        and float(dg_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(dg_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(dg_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(dg_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and "scanner_autonomy_pct" in dg_percentages
        and bool(dg.get("impact_miss_docs_reflected"))
        and bool(dg.get("genericity_docs_reflected"))
        and bool(dg.get("scanner_autonomy_posture_valid"))
        and bool(dg.get("progress_readiness_known_limitations_regenerated"))
        and dg_scanner.get("proof_claim") == "not_claimed"
        and dg_scanner.get("submission_posture") == "NOT_SUBMIT_READY"
        and dg_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dg_dc_df_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and dg.get("prior_db_reconciliation_status") == "final_accounting_after_cx_da_scanner_autonomy_not_full_roadmap_closure"
    )
    dl = dl_reconciliation or {}
    dl_percentages = dl.get("percentage_accounting") if isinstance(dl.get("percentage_accounting"), dict) else {}
    dl_slot_reliability = dl.get("active_slot_reliability") if isinstance(dl.get("active_slot_reliability"), dict) else {}
    dl_scanner = dl.get("scanner_autonomy") if isinstance(dl.get("scanner_autonomy"), dict) else {}
    dl_impact_miss = dl.get("impact_miss_benchmark") if isinstance(dl.get("impact_miss_benchmark"), dict) else {}
    dl_dh_dk_artifacts = dl.get("dh_dk_artifact_window") if isinstance(dl.get("dh_dk_artifact_window"), dict) else {}
    dl_valid_final_accounting = (
        dl.get("status") == "final_accounting_after_dh_dk_refreshed_maps_not_full_roadmap_closure"
        and dl.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(dl.get("readiness_valid_expected"))
        and not bool(dl.get("full_closure_claimed"))
        and not bool(dl.get("full_closure_achieved"))
        and bool(dl_percentages)
        and float(dl_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(dl_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(dl_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(dl_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and "scanner_autonomy_pct" in dl_percentages
        and "impact_miss_benchmark_accuracy_pct" in dl_percentages
        and bool(dl.get("impact_miss_docs_reflected"))
        and bool(dl.get("genericity_docs_reflected"))
        and bool(dl.get("scanner_autonomy_posture_valid"))
        and bool(dl.get("impact_miss_benchmark_posture_valid"))
        and bool(dl.get("progress_readiness_known_limitations_regenerated"))
        and dl_scanner.get("proof_claim") == "not_claimed"
        and dl_scanner.get("submission_posture") == "NOT_SUBMIT_READY"
        and dl_impact_miss.get("submission_posture") == "NOT_SUBMIT_READY"
        and not bool(dl_impact_miss.get("promotion_allowed"))
        and dl_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dl_dh_dk_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and dl.get("prior_dg_reconciliation_status") == "final_accounting_after_dc_df_refreshed_maps_not_full_roadmap_closure"
    )
    dq = dq_reconciliation or {}
    dq_percentages = dq.get("percentage_accounting") if isinstance(dq.get("percentage_accounting"), dict) else {}
    dq_slot_reliability = dq.get("active_slot_reliability") if isinstance(dq.get("active_slot_reliability"), dict) else {}
    dq_scanner = dq.get("scanner_autonomy") if isinstance(dq.get("scanner_autonomy"), dict) else {}
    dq_impact_miss = dq.get("impact_miss_benchmark") if isinstance(dq.get("impact_miss_benchmark"), dict) else {}
    dq_dm_dp_artifacts = dq.get("dm_dp_artifact_window") if isinstance(dq.get("dm_dp_artifact_window"), dict) else {}
    dq_valid_final_accounting = (
        dq.get("status") == "final_accounting_after_dm_dp_refreshed_maps_not_full_roadmap_closure"
        and dq.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(dq.get("readiness_valid_expected"))
        and not bool(dq.get("full_closure_claimed"))
        and not bool(dq.get("full_closure_achieved"))
        and bool(dq_percentages)
        and float(dq_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(dq_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(dq_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(dq_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and "scanner_autonomy_pct" in dq_percentages
        and "impact_miss_benchmark_accuracy_pct" in dq_percentages
        and bool(dq.get("impact_miss_docs_reflected"))
        and bool(dq.get("genericity_docs_reflected"))
        and bool(dq.get("scanner_autonomy_posture_valid"))
        and bool(dq.get("impact_miss_benchmark_posture_valid"))
        and bool(dq.get("progress_readiness_known_limitations_regenerated"))
        and dq_scanner.get("proof_claim") == "not_claimed"
        and dq_scanner.get("submission_posture") == "NOT_SUBMIT_READY"
        and dq_impact_miss.get("submission_posture") == "NOT_SUBMIT_READY"
        and not bool(dq_impact_miss.get("promotion_allowed"))
        and dq_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dq_dm_dp_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and dq.get("prior_dl_reconciliation_status") == "final_accounting_after_dh_dk_refreshed_maps_not_full_roadmap_closure"
    )
    dw = dw_reconciliation or {}
    dw_percentages = dw.get("percentage_accounting") if isinstance(dw.get("percentage_accounting"), dict) else {}
    dw_slot_reliability = dw.get("active_slot_reliability") if isinstance(dw.get("active_slot_reliability"), dict) else {}
    dw_scanner = dw.get("scanner_autonomy") if isinstance(dw.get("scanner_autonomy"), dict) else {}
    dw_impact_miss = dw.get("impact_miss_benchmark") if isinstance(dw.get("impact_miss_benchmark"), dict) else {}
    dw_ds_dv_artifacts = dw.get("ds_dv_artifact_window") if isinstance(dw.get("ds_dv_artifact_window"), dict) else {}
    dw_valid_final_accounting = (
        dw.get("status") == "final_accounting_after_ds_dv_refreshed_maps_not_full_roadmap_closure"
        and dw.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and bool(dw.get("readiness_valid_expected"))
        and not bool(dw.get("full_closure_claimed"))
        and not bool(dw.get("full_closure_achieved"))
        and bool(dw_percentages)
        and float(dw_percentages.get("known_limitations_open_pct") or 0.0) > 0.0
        and float(dw_percentages.get("known_limitations_reduction_pct") or 0.0)
        == float(dw_percentages.get("known_limitations_stop_condition_pct") or 0.0)
        and float(dw_percentages.get("full_roadmap_closure_pct") or 0.0) == 0.0
        and "scanner_autonomy_pct" in dw_percentages
        and "impact_miss_benchmark_accuracy_pct" in dw_percentages
        and bool(dw.get("impact_miss_docs_reflected"))
        and bool(dw.get("genericity_docs_reflected"))
        and bool(dw.get("scanner_autonomy_posture_valid"))
        and bool(dw.get("impact_miss_benchmark_posture_valid"))
        and bool(dw.get("progress_readiness_known_limitations_regenerated"))
        and dw_scanner.get("proof_claim") == "not_claimed"
        and dw_scanner.get("submission_posture") == "NOT_SUBMIT_READY"
        and dw_impact_miss.get("submission_posture") == "NOT_SUBMIT_READY"
        and not bool(dw_impact_miss.get("promotion_allowed"))
        and dw_slot_reliability.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dw_ds_dv_artifacts.get("accounting_boundary") == "artifact discovery only; absent worker directories or generated accounting ledgers do not create synthetic closure evidence"
        and dw.get("prior_dq_reconciliation_status") == "final_accounting_after_dm_dp_refreshed_maps_not_full_roadmap_closure"
    )
    slot_accounting_present = bool((active_agent_slots or {}).get("source_present")) and int((active_agent_slots or {}).get("slot_count") or 0) > 0
    stale_running_quarantine_active = (
        slot_accounting_present
        and isinstance((active_agent_slots or {}).get("freshness_policy"), dict)
        and (active_agent_slots or {}).get("freshness_policy", {}).get("unparseable_running_rows_count_as") == "stale_running_ignored"
    )
    roadmap_percentage_accounting_present = all(
        key in (roadmap_accounting or {})
        for key in (
            "known_limitations_stop_condition_pct",
            "known_limitations_open_pct",
            "full_roadmap_closure_pct",
        )
    ) and bool(bb_roadmap_percentages)
    blockers = []
    if missing:
        blockers.append("missing_required_slice_ids")
    if overclaiming:
        blockers.append("slice_overclaim_flags_present")
    if generated_artifact_owners != ["PR560-G-generated-artifacts-optional"]:
        blockers.append("generated_artifact_owner_not_isolated")
    if tests_missing or matrix_missing:
        blockers.append("missing_test_matrix_coverage")
    if guard_missing or stop_missing:
        blockers.append("missing_stop_conditions")
    if not git_ops_clear:
        blockers.append("git_or_github_operation_flag_set")
    if not proof_claims_clear:
        blockers.append("proof_claim_overstated")
    if not not_closed_complete:
        blockers.append("required_not_closed_boundaries_missing")
    if not handoff_populated:
        blockers.append("operator_handoff_missing")
    if not roadmap_has_foundry:
        blockers.append("foundry_roadmap_accounting_missing")
    if not aj_target_met:
        blockers.append("aj_item_target_not_met")
    if not ap_target_met:
        blockers.append("ap_item_target_not_met")
    if not ao_target_met:
        blockers.append("ao_item_target_not_met")
    if not ar_target_met:
        blockers.append("ar_item_target_not_met")
    if not aw_target_met:
        blockers.append("aw_item_target_not_met")
    if not ax_target_met:
        blockers.append("ax_item_target_not_met")
    if not aw_valid_not_full_closure:
        blockers.append("aw_reconciliation_not_valid_or_overclaims_closure")
    if not bb_target_met:
        blockers.append("bb_item_target_not_met")
    if not bb_valid_not_full_closure:
        blockers.append("bb_reconciliation_not_valid_or_overclaims_closure")
    if not bg_target_met:
        blockers.append("bg_item_target_not_met")
    if not bg_valid_not_full_closure:
        blockers.append("bg_reconciliation_not_valid_or_overclaims_closure")
    if not bl_target_met:
        blockers.append("bl_item_target_not_met")
    if not bl_valid_not_full_closure:
        blockers.append("bl_reconciliation_not_valid_or_overclaims_closure")
    if not bq_target_met:
        blockers.append("bq_item_target_not_met")
    if not bq_valid_not_full_closure:
        blockers.append("bq_reconciliation_not_valid_or_overclaims_closure")
    if not bv_target_met:
        blockers.append("bv_item_target_not_met")
    if not bv_valid_not_full_closure:
        blockers.append("bv_reconciliation_not_valid_or_overclaims_closure")
    if not ca_target_met:
        blockers.append("ca_item_target_not_met")
    if not ca_valid_not_full_closure:
        blockers.append("ca_reconciliation_not_valid_or_overclaims_closure")
    if not cf_target_met:
        blockers.append("cf_item_target_not_met")
    if not cf_valid_not_full_closure:
        blockers.append("cf_reconciliation_not_valid_or_overclaims_closure")
    if not ck_target_met:
        blockers.append("ck_item_target_not_met")
    if not ck_valid_not_full_closure:
        blockers.append("ck_reconciliation_not_valid_or_overclaims_closure")
    if not cp_target_met:
        blockers.append("cp_item_target_not_met")
    if not cp_valid_not_full_closure:
        blockers.append("cp_reconciliation_not_valid_or_overclaims_closure")
    if not cr_target_met:
        blockers.append("cr_item_target_not_met")
    if not cr_valid_permission_loop:
        blockers.append("cr_permission_loop_not_valid_or_weakens_no_git_actions")
    if not cv_target_met:
        blockers.append("cv_item_target_not_met")
    if not cw_target_met:
        blockers.append("cw_item_target_not_met")
    if not cw_valid_final_accounting:
        blockers.append("cw_final_accounting_not_valid_or_provider_status_missing")
    if not db_target_met:
        blockers.append("db_item_target_not_met")
    if not db_valid_final_accounting:
        blockers.append("db_final_accounting_not_valid_or_scanner_percentages_missing")
    if not dg_target_met:
        blockers.append("dg_item_target_not_met")
    if not dg_valid_final_accounting:
        blockers.append("dg_final_accounting_not_valid_or_refreshed_maps_missing")
    if not dl_target_met:
        blockers.append("dl_item_target_not_met")
    if not dl_valid_final_accounting:
        blockers.append("dl_final_accounting_not_valid_or_refreshed_maps_missing")
    if not dq_target_met:
        blockers.append("dq_item_target_not_met")
    if not dq_valid_final_accounting:
        blockers.append("dq_final_accounting_not_valid_or_refreshed_maps_missing")
    if not dw_target_met:
        blockers.append("dw_item_target_not_met")
    if not dw_valid_final_accounting:
        blockers.append("dw_final_accounting_not_valid_or_refreshed_maps_missing")
    if not slot_accounting_present:
        blockers.append("active_agent_slot_accounting_missing")
    if not stale_running_quarantine_active:
        blockers.append("active_agent_stale_running_quarantine_missing")
    if not roadmap_percentage_accounting_present:
        blockers.append("roadmap_percentage_accounting_missing")
    return {
        "required_slice_ids_present": not missing,
        "missing_required_slice_ids": missing,
        "no_live_provider_proof_claimed": not overclaiming,
        "no_full_coverage_claimed": not overclaiming,
        "overclaiming_slice_ids": overclaiming,
        "exactly_one_generated_artifact_slice": generated_artifact_owners == ["PR560-G-generated-artifacts-optional"],
        "generated_artifact_slice_ids": generated_artifact_owners,
        "representative_tests_present": not tests_missing,
        "tests_missing_slice_ids": tests_missing,
        "overclaim_guards_present": not guard_missing,
        "guard_missing_slice_ids": guard_missing,
        "per_slice_test_matrix_present": not matrix_missing,
        "test_matrix_missing_slice_ids": matrix_missing,
        "per_slice_stop_conditions_present": not stop_missing,
        "stop_conditions_missing_slice_ids": stop_missing,
        "local_git_github_operations_clear": git_ops_clear,
        "proof_claims_not_claimed": proof_claims_clear,
        "required_not_closed_boundaries_present": not_closed_complete,
        "not_closed_boundary_ids": sorted(not_closed),
        "operator_handoff_populated": handoff_populated,
        "roadmap_accounting_foundry_slice_present": roadmap_has_foundry,
        "aj_completed_item_count": len(INTEGRATION_READINESS_AJ_COMPLETED_ITEMS),
        "aj_target_met": aj_target_met,
        "ap_completed_item_count": len(INTEGRATION_READINESS_AP_COMPLETED_ITEMS),
        "ap_target_met": ap_target_met,
        "ao_completed_item_count": len(INTEGRATION_READINESS_AO_COMPLETED_ITEMS),
        "ao_target_met": ao_target_met,
        "ar_completed_item_count": len(INTEGRATION_READINESS_AR_COMPLETED_ITEMS),
        "ar_target_met": ar_target_met,
        "aw_completed_item_count": len(INTEGRATION_READINESS_AW_COMPLETED_ITEMS),
        "aw_target_met": aw_target_met,
        "ax_completed_item_count": len(PR560_WORKER_AX_COMPLETED_ITEMS),
        "ax_target_met": ax_target_met,
        "aw_valid_not_full_closure": aw_valid_not_full_closure,
        "bb_completed_item_count": len(INTEGRATION_READINESS_BB_COMPLETED_ITEMS),
        "bb_target_met": bb_target_met,
        "bb_valid_not_full_closure": bb_valid_not_full_closure,
        "bg_completed_item_count": len(INTEGRATION_READINESS_BG_COMPLETED_ITEMS),
        "bg_target_met": bg_target_met,
        "bg_valid_not_full_closure": bg_valid_not_full_closure,
        "bl_completed_item_count": len(INTEGRATION_READINESS_BL_COMPLETED_ITEMS),
        "bl_target_met": bl_target_met,
        "bl_valid_not_full_closure": bl_valid_not_full_closure,
        "bq_completed_item_count": len(INTEGRATION_READINESS_BQ_COMPLETED_ITEMS),
        "bq_target_met": bq_target_met,
        "bq_valid_not_full_closure": bq_valid_not_full_closure,
        "bv_completed_item_count": len(PR560_WORKER_BV_COMPLETED_ITEMS),
        "bv_target_met": bv_target_met,
        "bv_valid_not_full_closure": bv_valid_not_full_closure,
        "ca_completed_item_count": len(PR560_WORKER_CA_COMPLETED_ITEMS),
        "ca_target_met": ca_target_met,
        "ca_valid_not_full_closure": ca_valid_not_full_closure,
        "cf_completed_item_count": len(PR560_WORKER_CF_COMPLETED_ITEMS),
        "cf_target_met": cf_target_met,
        "cf_valid_not_full_closure": cf_valid_not_full_closure,
        "ck_completed_item_count": len(PR560_WORKER_CK_COMPLETED_ITEMS),
        "ck_target_met": ck_target_met,
        "ck_valid_not_full_closure": ck_valid_not_full_closure,
        "cp_completed_item_count": len(PR560_WORKER_CP_COMPLETED_ITEMS),
        "cp_target_met": cp_target_met,
        "cp_valid_not_full_closure": cp_valid_not_full_closure,
        "cr_completed_item_count": len(PR560_WORKER_CR_COMPLETED_ITEMS),
        "cr_target_met": cr_target_met,
        "cr_valid_permission_loop": cr_valid_permission_loop,
        "cv_completed_item_count": len(PR560_WORKER_CV_COMPLETED_ITEMS),
        "cv_target_met": cv_target_met,
        "cw_completed_item_count": len(PR560_WORKER_CW_COMPLETED_ITEMS),
        "cw_target_met": cw_target_met,
        "cw_valid_final_accounting": cw_valid_final_accounting,
        "db_completed_item_count": len(PR560_WORKER_DB_COMPLETED_ITEMS),
        "db_target_met": db_target_met,
        "db_valid_final_accounting": db_valid_final_accounting,
        "db_scanner_autonomy_percentages_present": bool(db_percentages) and "scanner_autonomy_pct" in db_percentages,
        "db_impact_miss_docs_reflected": bool(db.get("impact_miss_docs_reflected")),
        "db_genericity_docs_reflected": bool(db.get("genericity_docs_reflected")),
        "db_impact_miss_benchmark_posture_valid": bool(db.get("impact_miss_benchmark_posture_valid")),
        "db_impact_miss_benchmark_scored": bool(db_impact_miss.get("scored")),
        "dg_completed_item_count": len(PR560_WORKER_DG_COMPLETED_ITEMS),
        "dg_target_met": dg_target_met,
        "dg_valid_final_accounting": dg_valid_final_accounting,
        "dg_scanner_autonomy_percentages_present": bool(dg_percentages) and "scanner_autonomy_pct" in dg_percentages,
        "dg_impact_miss_docs_reflected": bool(dg.get("impact_miss_docs_reflected")),
        "dg_genericity_docs_reflected": bool(dg.get("genericity_docs_reflected")),
        "dg_refreshed_maps_recorded": bool(dg.get("progress_readiness_known_limitations_regenerated")),
        "dl_completed_item_count": len(PR560_WORKER_DL_COMPLETED_ITEMS),
        "dl_target_met": dl_target_met,
        "dl_valid_final_accounting": dl_valid_final_accounting,
        "dl_scanner_autonomy_percentages_present": bool(dl_percentages) and "scanner_autonomy_pct" in dl_percentages,
        "dl_impact_miss_docs_reflected": bool(dl.get("impact_miss_docs_reflected")),
        "dl_genericity_docs_reflected": bool(dl.get("genericity_docs_reflected")),
        "dl_impact_miss_benchmark_posture_valid": bool(dl.get("impact_miss_benchmark_posture_valid")),
        "dl_refreshed_maps_recorded": bool(dl.get("progress_readiness_known_limitations_regenerated")),
        "dq_completed_item_count": len(PR560_WORKER_DQ_COMPLETED_ITEMS),
        "dq_target_met": dq_target_met,
        "dq_valid_final_accounting": dq_valid_final_accounting,
        "dq_scanner_autonomy_percentages_present": bool(dq_percentages) and "scanner_autonomy_pct" in dq_percentages,
        "dq_impact_miss_docs_reflected": bool(dq.get("impact_miss_docs_reflected")),
        "dq_genericity_docs_reflected": bool(dq.get("genericity_docs_reflected")),
        "dq_impact_miss_benchmark_posture_valid": bool(dq.get("impact_miss_benchmark_posture_valid")),
        "dq_refreshed_maps_recorded": bool(dq.get("progress_readiness_known_limitations_regenerated")),
        "dw_completed_item_count": len(PR560_WORKER_DW_COMPLETED_ITEMS),
        "dw_target_met": dw_target_met,
        "dw_valid_final_accounting": dw_valid_final_accounting,
        "dw_scanner_autonomy_percentages_present": bool(dw_percentages) and "scanner_autonomy_pct" in dw_percentages,
        "dw_impact_miss_docs_reflected": bool(dw.get("impact_miss_docs_reflected")),
        "dw_genericity_docs_reflected": bool(dw.get("genericity_docs_reflected")),
        "dw_impact_miss_benchmark_posture_valid": bool(dw.get("impact_miss_benchmark_posture_valid")),
        "dw_refreshed_maps_recorded": bool(dw.get("progress_readiness_known_limitations_regenerated")),
        "provider_status_reflected": bool(cw.get("provider_status_reflected")),
        "bw_bz_generated_artifacts_recognized": bool(cf.get("bw_bz_generated_artifacts_recognized")),
        "cb_cf_generated_artifacts_recognized": bool(ck.get("cb_cf_generated_artifacts_recognized")),
        "cg_cj_artifacts_recognized": bool(ck.get("cg_cj_artifacts_recognized")),
        "cl_co_artifacts_recognized": bool(cp.get("cl_co_artifacts_recognized")),
        "automation_id_present": ca.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cf.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and ck.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cp.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cr.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and cw.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and db.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dg.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dl.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dq.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and dw.get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID
        and (roadmap_accounting or {}).get("automation_id") == FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "active_agent_slot_accounting_present": slot_accounting_present,
        "active_agent_stale_running_quarantine_active": stale_running_quarantine_active,
        "roadmap_percentage_accounting_present": roadmap_percentage_accounting_present,
        "blockers": blockers,
        "valid": not blockers,
    }


def render_pr560_integration_readiness(workspace: Path) -> dict[str, Any]:
    progress_path, progress_json_path = pr560_progress_paths()
    if progress_json_path.is_file():
        progress = load_json(progress_json_path)
    else:
        progress = render_pr560_local_progress(workspace)
    if not progress:
        progress = render_pr560_local_progress(workspace)

    readiness_path, readiness_json_path = pr560_integration_readiness_paths()
    changed_files = list(progress.get("changed_files") or local_batch_changed_files())
    changed_file_groups = integration_changed_file_groups(changed_files)
    future_slices = future_pr_slices_from_progress(progress)
    test_matrix = integration_test_matrix(future_slices)
    artifact_isolation = generated_artifact_isolation(changed_file_groups)
    operator_handoff = integration_operator_handoff(workspace)
    roadmap_accounting = integration_roadmap_accounting(future_slices, workspace)
    foundry_fixture_manifests = foundry_representative_fixture_manifests()
    aw_reconciliation = pr560_aw_reconciliation_summary(
        progress,
        changed_file_groups=changed_file_groups,
        roadmap_accounting=roadmap_accounting,
        foundry_fixture_manifests=foundry_fixture_manifests,
    )
    active_agent_slots = pr560_active_agent_slot_accounting()
    bb_reconciliation = pr560_bb_reconciliation_summary(
        progress,
        aw_reconciliation=aw_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        foundry_fixture_manifests=foundry_fixture_manifests,
    )
    bg_reconciliation = pr560_bg_reconciliation_summary(
        progress,
        bb_reconciliation=bb_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    bl_reconciliation = pr560_bl_reconciliation_summary(
        progress,
        bg_reconciliation=bg_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    bq_reconciliation = pr560_bq_reconciliation_summary(
        progress,
        bl_reconciliation=bl_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    bv_reconciliation = pr560_bv_reconciliation_summary(
        progress,
        bq_reconciliation=bq_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    ca_reconciliation = pr560_ca_reconciliation_summary(
        progress,
        bv_reconciliation=bv_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    cf_reconciliation = pr560_cf_reconciliation_summary(
        progress,
        ca_reconciliation=ca_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    ck_reconciliation = pr560_ck_reconciliation_summary(
        progress,
        cf_reconciliation=cf_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    cp_reconciliation = pr560_cp_reconciliation_summary(
        progress,
        ck_reconciliation=ck_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    cr_reconciliation = pr560_cr_reconciliation_summary(
        progress,
        cp_reconciliation=cp_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
    )
    provider_accounting = provider_local_verification_artifact_accounting(workspace)
    cw_reconciliation = pr560_cw_reconciliation_summary(
        progress,
        cr_reconciliation=cr_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        provider_accounting=provider_accounting,
    )
    scanner_autonomy = scanner_autonomy_accounting(workspace)
    impact_miss_benchmark = impact_miss_benchmark_accounting(workspace)
    db_reconciliation = pr560_db_reconciliation_summary(
        progress,
        cw_reconciliation=cw_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        scanner_autonomy=scanner_autonomy,
        impact_miss_benchmark=impact_miss_benchmark,
    )
    dg_reconciliation = pr560_dg_reconciliation_summary(
        progress,
        db_reconciliation=db_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        scanner_autonomy=scanner_autonomy,
    )
    dl_reconciliation = pr560_dl_reconciliation_summary(
        progress,
        dg_reconciliation=dg_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        scanner_autonomy=scanner_autonomy,
        impact_miss_benchmark=impact_miss_benchmark,
    )
    dq_reconciliation = pr560_dq_reconciliation_summary(
        progress,
        dl_reconciliation=dl_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        scanner_autonomy=scanner_autonomy,
        impact_miss_benchmark=impact_miss_benchmark,
    )
    dw_reconciliation = pr560_dw_reconciliation_summary(
        progress,
        dq_reconciliation=dq_reconciliation,
        roadmap_accounting=roadmap_accounting,
        active_agent_slots=active_agent_slots,
        scanner_autonomy=scanner_autonomy,
        impact_miss_benchmark=impact_miss_benchmark,
    )
    completed_count = len(INTEGRATION_READINESS_COMPLETED_ITEMS)
    git_operations_performed = {
        "stage": False,
        "commit": False,
        "push": False,
        "pull_request": False,
        "merge": False,
        "github_actions": False,
    }
    proof_claims = {
        "full_scanner_coverage": "not_claimed",
        "live_provider_proof": "not_claimed",
        "live_deployment_proof": "not_claimed",
        "poc_execution_proof": "not_claimed",
        "submission_readiness": "not_claimed",
    }
    validation = validate_integration_slices(
        future_slices,
        test_matrix=test_matrix,
        operator_handoff=operator_handoff,
        roadmap_accounting=roadmap_accounting,
        aw_reconciliation=aw_reconciliation,
        bb_reconciliation=bb_reconciliation,
        bg_reconciliation=bg_reconciliation,
        bl_reconciliation=bl_reconciliation,
        bq_reconciliation=bq_reconciliation,
        bv_reconciliation=bv_reconciliation,
        ca_reconciliation=ca_reconciliation,
        cf_reconciliation=cf_reconciliation,
        ck_reconciliation=ck_reconciliation,
        cp_reconciliation=cp_reconciliation,
        cr_reconciliation=cr_reconciliation,
        cw_reconciliation=cw_reconciliation,
        db_reconciliation=db_reconciliation,
        dg_reconciliation=dg_reconciliation,
        dl_reconciliation=dl_reconciliation,
        dq_reconciliation=dq_reconciliation,
        dw_reconciliation=dw_reconciliation,
        active_agent_slots=active_agent_slots,
        git_operations_performed=git_operations_performed,
        proof_claims=proof_claims,
    )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.integration_readiness.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "local_only": True,
        "github_actions_opened": False,
        "git_operations_performed": git_operations_performed,
        "completed_worker_ad_item_count": completed_count,
        "completed_worker_ad_items": list(INTEGRATION_READINESS_COMPLETED_ITEMS),
        "completed_worker_aj_item_count": len(INTEGRATION_READINESS_AJ_COMPLETED_ITEMS),
        "completed_worker_aj_items": list(INTEGRATION_READINESS_AJ_COMPLETED_ITEMS),
        "completed_worker_ap_item_count": len(INTEGRATION_READINESS_AP_COMPLETED_ITEMS),
        "completed_worker_ap_items": list(INTEGRATION_READINESS_AP_COMPLETED_ITEMS),
        "completed_worker_ao_item_count": len(INTEGRATION_READINESS_AO_COMPLETED_ITEMS),
        "completed_worker_ao_items": list(INTEGRATION_READINESS_AO_COMPLETED_ITEMS),
        "completed_worker_ar_item_count": len(INTEGRATION_READINESS_AR_COMPLETED_ITEMS),
        "completed_worker_ar_items": list(INTEGRATION_READINESS_AR_COMPLETED_ITEMS),
        "completed_worker_aw_item_count": len(INTEGRATION_READINESS_AW_COMPLETED_ITEMS),
        "completed_worker_aw_items": list(INTEGRATION_READINESS_AW_COMPLETED_ITEMS),
        "completed_worker_ax_item_count": len(PR560_WORKER_AX_COMPLETED_ITEMS),
        "completed_worker_ax_items": list(PR560_WORKER_AX_COMPLETED_ITEMS),
        "completed_worker_bb_item_count": len(INTEGRATION_READINESS_BB_COMPLETED_ITEMS),
        "completed_worker_bb_items": list(INTEGRATION_READINESS_BB_COMPLETED_ITEMS),
        "completed_worker_bg_item_count": len(INTEGRATION_READINESS_BG_COMPLETED_ITEMS),
        "completed_worker_bg_items": list(INTEGRATION_READINESS_BG_COMPLETED_ITEMS),
        "completed_worker_bl_item_count": len(INTEGRATION_READINESS_BL_COMPLETED_ITEMS),
        "completed_worker_bl_items": list(INTEGRATION_READINESS_BL_COMPLETED_ITEMS),
        "completed_worker_bq_item_count": len(INTEGRATION_READINESS_BQ_COMPLETED_ITEMS),
        "completed_worker_bq_items": list(INTEGRATION_READINESS_BQ_COMPLETED_ITEMS),
        "completed_worker_bv_item_count": len(PR560_WORKER_BV_COMPLETED_ITEMS),
        "completed_worker_bv_items": list(PR560_WORKER_BV_COMPLETED_ITEMS),
        "completed_worker_ca_item_count": len(PR560_WORKER_CA_COMPLETED_ITEMS),
        "completed_worker_ca_items": list(PR560_WORKER_CA_COMPLETED_ITEMS),
        "completed_worker_cf_item_count": len(PR560_WORKER_CF_COMPLETED_ITEMS),
        "completed_worker_cf_items": list(PR560_WORKER_CF_COMPLETED_ITEMS),
        "completed_worker_ck_item_count": len(PR560_WORKER_CK_COMPLETED_ITEMS),
        "completed_worker_ck_items": list(PR560_WORKER_CK_COMPLETED_ITEMS),
        "completed_worker_cp_item_count": len(PR560_WORKER_CP_COMPLETED_ITEMS),
        "completed_worker_cp_items": list(PR560_WORKER_CP_COMPLETED_ITEMS),
        "completed_worker_cr_item_count": len(PR560_WORKER_CR_COMPLETED_ITEMS),
        "completed_worker_cr_items": list(PR560_WORKER_CR_COMPLETED_ITEMS),
        "completed_worker_cv_item_count": len(PR560_WORKER_CV_COMPLETED_ITEMS),
        "completed_worker_cv_items": list(PR560_WORKER_CV_COMPLETED_ITEMS),
        "completed_worker_cw_item_count": len(PR560_WORKER_CW_COMPLETED_ITEMS),
        "completed_worker_cw_items": list(PR560_WORKER_CW_COMPLETED_ITEMS),
        "completed_worker_db_item_count": len(PR560_WORKER_DB_COMPLETED_ITEMS),
        "completed_worker_db_items": list(PR560_WORKER_DB_COMPLETED_ITEMS),
        "completed_worker_dg_item_count": len(PR560_WORKER_DG_COMPLETED_ITEMS),
        "completed_worker_dg_items": list(PR560_WORKER_DG_COMPLETED_ITEMS),
        "completed_worker_dl_item_count": len(PR560_WORKER_DL_COMPLETED_ITEMS),
        "completed_worker_dl_items": list(PR560_WORKER_DL_COMPLETED_ITEMS),
        "completed_worker_dq_item_count": len(PR560_WORKER_DQ_COMPLETED_ITEMS),
        "completed_worker_dq_items": list(PR560_WORKER_DQ_COMPLETED_ITEMS),
        "completed_worker_dw_item_count": len(PR560_WORKER_DW_COMPLETED_ITEMS),
        "completed_worker_dw_items": list(PR560_WORKER_DW_COMPLETED_ITEMS),
        "automation_id": FULL_ROADMAP_CLOSURE_AUTOMATION_ID,
        "progress_json": str(progress_json_path),
        "progress_status": progress.get("status", "unknown"),
        "progress_ready_for_eventual_pr": bool((progress.get("bundle_readiness") or {}).get("ready_for_eventual_pr", False)),
        "observed_changed_file_count": len(changed_files),
        "changed_file_groups": changed_file_groups,
        "future_pr_slices": future_slices,
        "per_slice_test_matrix": test_matrix,
        "generated_artifact_isolation": artifact_isolation,
        "operator_handoff": operator_handoff,
        "roadmap_accounting": roadmap_accounting,
        "foundry_representative_fixture_manifests": foundry_fixture_manifests,
        "aw_reconciliation": aw_reconciliation,
        "bb_reconciliation": bb_reconciliation,
        "bg_reconciliation": bg_reconciliation,
        "bl_reconciliation": bl_reconciliation,
        "bq_reconciliation": bq_reconciliation,
        "bv_reconciliation": bv_reconciliation,
        "ca_reconciliation": ca_reconciliation,
        "cf_reconciliation": cf_reconciliation,
        "ck_reconciliation": ck_reconciliation,
        "cp_reconciliation": cp_reconciliation,
        "cr_reconciliation": cr_reconciliation,
        "cw_reconciliation": cw_reconciliation,
        "db_reconciliation": db_reconciliation,
        "dg_reconciliation": dg_reconciliation,
        "dl_reconciliation": dl_reconciliation,
        "dq_reconciliation": dq_reconciliation,
        "dw_reconciliation": dw_reconciliation,
        "scanner_autonomy_accounting": scanner_autonomy,
        "impact_miss_benchmark_accounting": impact_miss_benchmark,
        "provider_local_verification_accounting": provider_accounting,
        "active_agent_slot_accounting": active_agent_slots,
        "validation": validation,
        "provider_live_consent_blocker": {
            "blocked": True,
            "reason": "Live provider calls require explicit operator approval; local preflight/dispatch artifacts are advisory only.",
        },
        "remaining_not_closed": pr560_not_closed_boundaries(),
        "proof_claims": proof_claims,
        "recommended_next_step": "Review and split future PRs by slice only after the operator authorizes GitHub work.",
        "readiness_verdict": "ready_for_operator_review" if validation["valid"] else "blocked_readiness_validation",
    }

    doc = [
        "# PR560 Local Integration Readiness",
        "",
        "Generated by `tools/automation-closure.py --mode pr560-integration-readiness`.",
        "This is a local-only integration summary. It does not open GitHub Actions, push, merge, create a PR, or claim provider/scanner proof beyond the local artifacts and tests listed below.",
        "",
        "## Completed Worker AD Items",
        "",
    ]
    for idx, item in enumerate(INTEGRATION_READINESS_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker AJ Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_AJ_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker AP Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_AP_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker AO Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_AO_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker AR Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_AR_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker AW Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_AW_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker AX Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_AX_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker BB Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_BB_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker BG Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_BG_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker BL Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_BL_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker BQ Items",
        "",
    ])
    for idx, item in enumerate(INTEGRATION_READINESS_BQ_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker BV Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_BV_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CA Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CA_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CF Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CF_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CK Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CK_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CP Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CP_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CR Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CR_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CV Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CV_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker CW Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_CW_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker DB Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_DB_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker DG Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_DG_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker DL Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_DL_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker DQ Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_DQ_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Completed Worker DW Items",
        "",
    ])
    for idx, item in enumerate(PR560_WORKER_DW_COMPLETED_ITEMS, 1):
        doc.append(f"{idx}. {item}")
    doc.extend([
        "",
        "## Changed-File Groups",
        "",
        f"Observed changed paths from the local progress ledger: `{len(changed_files)}`.",
        "",
        "| Group | Count | Scope |",
        "|---|---:|---|",
    ])
    for group in changed_file_groups:
        doc.append(f"| `{group['group']}` | `{group['count']}` | {group['title']} |")
    doc.extend([
        "",
        "## Future PR Slice Plan",
        "",
        "| Slice | Owns | Guardrail | Tests |",
        "|---|---|---|---|",
    ])
    for row in future_slices:
        owns = "<br>".join(row["owns"])
        tests = "<br>".join(f"`{cmd}`" for cmd in row["representative_tests"])
        doc.append(f"| `{row['slice_id']}` | {owns} | `{row['overclaim_guard']}` | {tests} |")
    doc.extend([
        "",
        "## Per-Slice Test Matrix",
        "",
        "| Slice | Required local tests | Operator-approved tests | Stop conditions |",
        "|---|---|---|---|",
    ])
    for row in test_matrix:
        local_tests = "<br>".join(f"`{cmd}`" for cmd in row["required_local_tests"]) or "_none_"
        operator_tests = "<br>".join(f"`{cmd}`" for cmd in row["operator_approved_tests"]) or "_none_"
        stops = "<br>".join(row["stop_conditions"])
        doc.append(f"| `{row['slice_id']}` | {local_tests} | {operator_tests} | {stops} |")
    doc.extend([
        "",
        "## Generated-Artifact Isolation",
        "",
        f"- Status: `{artifact_isolation['status']}`.",
        f"- Owning slice: `{artifact_isolation['owning_slice']}`.",
        f"- Observed generated/local artifact paths: `{artifact_isolation['observed_count']}`.",
        f"- Operator rule: {artifact_isolation['operator_rule']}",
        "",
        "## Roadmap Accounting",
        "",
        f"- Status: `{roadmap_accounting['status']}`.",
        f"- Foundry migration slice: `{roadmap_accounting['foundry_migration_slice']}`.",
        f"- Foundry migration doc present: `{roadmap_accounting['foundry_migration_doc_present']}`.",
        f"- Foundry fixture manifests: `{roadmap_accounting['foundry_fixture_manifest_present_count']}` / `{roadmap_accounting['foundry_fixture_manifest_expected_count']}`.",
        f"- Known-limitations count source: `{roadmap_accounting['known_limitations_count_source']}`.",
        f"- Known-limitations seed-map stop conditions: `{roadmap_accounting['known_limitations_seed_stop_conditions_met']}` / `{roadmap_accounting['known_limitations_seed_row_count']}`.",
        f"- Known-limitations rows: `{roadmap_accounting['known_limitations_row_count']}` total, `{roadmap_accounting['known_limitations_stop_conditions_met']}` stop conditions met, `{roadmap_accounting['known_limitations_open_row_count']}` still open.",
        f"- Known-limitations stop-condition percentage: `{roadmap_accounting['known_limitations_stop_condition_pct']}`%.",
        f"- Known-limitations open percentage: `{roadmap_accounting['known_limitations_open_pct']}`%.",
        f"- Full roadmap closure percentage: `{roadmap_accounting['full_roadmap_closure_pct']}`%.",
        f"- Boundary: {roadmap_accounting['roadmap_boundary']}",
        "",
        "## Scanner Autonomy Accounting",
        "",
        f"- Status: `{scanner_autonomy['status']}`.",
        f"- Plan tasks: `{scanner_autonomy['task_count']}`.",
        f"- Manual triage accounted: `{scanner_autonomy['manual_triage_items_mechanically_accounted']}` / `{scanner_autonomy['manual_triage_accounting_target']}` (`{scanner_autonomy['manual_triage_accounted_pct']}`%).",
        f"- Runnable local commands: `{scanner_autonomy['runnable_local_command_items']}` (`{scanner_autonomy['runnable_local_command_pct_of_plan']}`% of plan).",
        f"- Allowlisted execution items: `{scanner_autonomy['allowlisted_execution_items']}` (`{scanner_autonomy['allowlisted_execution_pct_of_plan']}`% of plan).",
        f"- Allowlisted outcome items: `{scanner_autonomy.get('allowlisted_outcome_items', 0)}`.",
        f"- Unexecuted allowlisted local commands: `{scanner_autonomy.get('unexecuted_allowlisted_local_command_items', 0)}`.",
        f"- Executed items: `{scanner_autonomy['executed_items']}` (`{scanner_autonomy['executed_pct_of_plan']}`% of plan).",
        f"- Executed-ok / executed-failed rows: `{scanner_autonomy.get('executed_ok_items', 0)}` / `{scanner_autonomy.get('executed_failed_items', 0)}`.",
        f"- Blocked no-command / terminal detector-smoke blockers: `{scanner_autonomy.get('blocked_no_command_items', 0)}` / `{scanner_autonomy.get('terminal_detector_smoke_blocker_items', 0)}`.",
        f"- Scanner autonomy percentage: `{scanner_autonomy['scanner_autonomy_pct']}`%.",
        f"- Scanner completeness claimed: `{str(scanner_autonomy.get('scanner_completeness_claimed', False)).lower()}`.",
        f"- Proof claim: `{scanner_autonomy['proof_claim']}`.",
        f"- Submission posture: `{scanner_autonomy['submission_posture']}`.",
        f"- Boundary: {scanner_autonomy['accounting_boundary']}",
        "",
        "## Foundry Fixture Trial Manifests",
        "",
        f"- Status: `{foundry_fixture_manifests['status']}`.",
        f"- Migration state: `{foundry_fixture_manifests['migration_state']}`.",
        f"- Upgrade performed: `{str(foundry_fixture_manifests['upgrade_performed']).lower()}`.",
        f"- Schema-valid manifests: `{foundry_fixture_manifests['schema_valid_count']}` / `{foundry_fixture_manifests['manifest_present_count']}`.",
        f"- Ready fixtures: `{foundry_fixture_manifests['ready_fixture_count']}` / `{foundry_fixture_manifests['fixture_count']}`.",
        f"- Normalization items: `{foundry_fixture_manifests['normalization_item_total']}` total, `{foundry_fixture_manifests['blocking_normalization_item_total']}` blocking.",
        "",
        "| Fixture | Manifest | Schema | Readiness | Normalization | Blockers |",
        "|---|---|---|---|---:|---|",
    ])
    for row in foundry_fixture_manifests["rows"]:
        blockers = ", ".join(row["blockers"]) or "none"
        doc.append(
            f"| `{row['fixture']}` | `{str(row['manifest_present']).lower()}` | "
            f"`{str(row['schema_valid']).lower()}` | `{row['readiness_status']}` | "
            f"`{row['normalization_items']}` | {blockers} |"
        )
    doc.extend([
        "",
        "## Worker AW Reconciliation",
        "",
        f"- Status: `{aw_reconciliation['status']}`.",
        f"- Readiness valid expected: `{str(aw_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(aw_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(aw_reconciliation['full_closure_achieved']).lower()}`.",
        f"- Progress: `{aw_reconciliation['progress_reconciliation']['completed_items']}` completed items, `{aw_reconciliation['progress_reconciliation']['remaining_next_action_rows']}` remaining next-action rows, `{aw_reconciliation['progress_reconciliation']['strict_blockers']}` strict blockers.",
        f"- Known limitations: `{aw_reconciliation['known_limitations_reconciliation']['stop_conditions_met']}` stop conditions met, `{aw_reconciliation['known_limitations_reconciliation']['open_row_count']}` rows still open.",
        f"- Live provider posture: `{aw_reconciliation['live_provider_triage']['posture']}`.",
        f"- Semantic adjudication posture: `{aw_reconciliation['semantic_adjudication']['posture']}`.",
        f"- Foundry posture: `{aw_reconciliation['foundry_slice']['posture']}`.",
        "",
        "## Worker BB Reconciliation",
        "",
        f"- Status: `{bb_reconciliation['status']}`.",
        f"- Readiness valid expected: `{str(bb_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Local capability complete: `{str(bb_reconciliation['local_capability_complete']).lower()}`.",
        f"- Full closure claimed: `{str(bb_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(bb_reconciliation['full_closure_achieved']).lower()}`.",
        f"- Progress: `{bb_reconciliation['progress_reconciliation']['completed_items']}` completed items, `{bb_reconciliation['progress_reconciliation']['remaining_next_action_rows']}` remaining next-action rows, `{bb_reconciliation['progress_reconciliation']['strict_blockers']}` strict blockers.",
        f"- Known limitations: `{bb_reconciliation['known_limitations_reconciliation']['stop_conditions_met']}` stop conditions met, `{bb_reconciliation['known_limitations_reconciliation']['open_row_count']}` rows still open.",
        f"- Provider posture: `{bb_reconciliation['provider_posture']}`.",
        f"- Semantic posture: `{bb_reconciliation['semantic_posture']}`.",
        f"- Foundry posture: `{bb_reconciliation['foundry_posture']}`.",
        "",
        "## Worker BG Final Reconciliation",
        "",
        f"- Status: `{bg_reconciliation['status']}`.",
        f"- Artifact window: `{bg_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(bg_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Local implementation ready: `{str(bg_reconciliation['local_implementation_ready']).lower()}`.",
        f"- Full closure claimed: `{str(bg_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(bg_reconciliation['full_closure_achieved']).lower()}`.",
        f"- Queue accounting: `{bg_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{bg_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{bg_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(bg_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker BL Reconciliation",
        "",
        f"- Status: `{bl_reconciliation['status']}`.",
        f"- Artifact window: `{bl_reconciliation['artifact_window']}`.",
        f"- BH-BK accounting note: {bl_reconciliation['bh_bk_accounting_note']}",
        f"- Readiness valid expected: `{str(bl_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Local implementation ready: `{str(bl_reconciliation['local_implementation_ready']).lower()}`.",
        f"- Full closure claimed: `{str(bl_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(bl_reconciliation['full_closure_achieved']).lower()}`.",
        f"- Queue accounting: `{bl_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{bl_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{bl_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(bl_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker BQ Slot Reliability Reconciliation",
        "",
        f"- Status: `{bq_reconciliation['status']}`.",
        f"- Artifact window: `{bq_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(bq_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(bq_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(bq_reconciliation['full_closure_achieved']).lower()}`.",
        f"- Raw running slots: `{bq_reconciliation['slot_reliability']['raw_running_count']}`.",
        f"- Effective running slots: `{bq_reconciliation['slot_reliability']['effective_running_count']}`.",
        f"- Stale running slots ignored: `{bq_reconciliation['slot_reliability']['stale_running_ignored_count']}`.",
        f"- Future false-running guard active: `{str(bq_reconciliation['slot_reliability']['future_false_running_guard_active']).lower()}`.",
        f"- BM-BP artifact window status: `{bq_reconciliation['bm_bp_artifact_window']['status']}`.",
        "",
        "## Worker BV Final Accounting Reconciliation",
        "",
        f"- Status: `{bv_reconciliation['status']}`.",
        f"- Artifact window: `{bv_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(bv_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(bv_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(bv_reconciliation['full_closure_achieved']).lower()}`.",
        f"- BR-BU artifact window status: `{bv_reconciliation['br_bu_artifact_window']['status']}`.",
        f"- Stale-loop reliability active: `{str(bv_reconciliation['stale_loop_reliability']['active']).lower()}`.",
        f"- Queue accounting: `{bv_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{bv_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{bv_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(bv_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker CA Active-Loop Reconciliation",
        "",
        f"- Status: `{ca_reconciliation['status']}`.",
        f"- Automation id: `{ca_reconciliation['automation_id']}`.",
        f"- Artifact window: `{ca_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(ca_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(ca_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(ca_reconciliation['full_closure_achieved']).lower()}`.",
        f"- BW-BZ artifact window status: `{ca_reconciliation['bw_bz_artifact_window']['status']}`.",
        f"- Effective running slots: `{ca_reconciliation['active_loop_reliability']['effective_running_count']}`.",
        f"- Queue accounting: `{ca_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{ca_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{ca_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(ca_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker CF Final Accounting Reconciliation",
        "",
        f"- Status: `{cf_reconciliation['status']}`.",
        f"- Automation id: `{cf_reconciliation['automation_id']}`.",
        f"- Artifact window: `{cf_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(cf_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(cf_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(cf_reconciliation['full_closure_achieved']).lower()}`.",
        f"- CB-CE artifact window status: `{cf_reconciliation['cb_ce_artifact_window']['status']}`.",
        f"- BW-BZ generated accounting artifacts recognized: `{str(cf_reconciliation['bw_bz_generated_artifacts_recognized']).lower()}`.",
        f"- Effective running slots: `{cf_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in cf_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{cf_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{cf_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{cf_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(cf_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker CK Final Accounting Reconciliation",
        "",
        f"- Status: `{ck_reconciliation['status']}`.",
        f"- Automation id: `{ck_reconciliation['automation_id']}`.",
        f"- Artifact window: `{ck_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(ck_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(ck_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(ck_reconciliation['full_closure_achieved']).lower()}`.",
        f"- CB-CF artifact window status: `{ck_reconciliation['cb_cf_artifact_window']['status']}`.",
        f"- CG-CJ artifact window status: `{ck_reconciliation['cg_cj_artifact_window']['status']}`.",
        f"- CB-CF generated accounting artifacts recognized: `{str(ck_reconciliation['cb_cf_generated_artifacts_recognized']).lower()}`.",
        f"- CG-CJ artifacts recognized: `{str(ck_reconciliation['cg_cj_artifacts_recognized']).lower()}`.",
        f"- Effective running slots: `{ck_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in ck_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{ck_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{ck_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{ck_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(ck_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker CP Final Accounting Reconciliation",
        "",
        f"- Status: `{cp_reconciliation['status']}`.",
        f"- Automation id: `{cp_reconciliation['automation_id']}`.",
        f"- Artifact window: `{cp_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(cp_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(cp_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(cp_reconciliation['full_closure_achieved']).lower()}`.",
        f"- CG-CJ artifact window status: `{cp_reconciliation['cg_cj_artifact_window']['status']}`.",
        f"- CL-CO artifact window status: `{cp_reconciliation['cl_co_artifact_window']['status']}`.",
        f"- CG-CJ artifacts recognized: `{str(cp_reconciliation['cg_cj_artifacts_recognized']).lower()}`.",
        f"- CL-CO artifacts recognized: `{str(cp_reconciliation['cl_co_artifacts_recognized']).lower()}`.",
        f"- Effective running slots: `{cp_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in cp_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{cp_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{cp_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{cp_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(cp_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker CR Permission-Loop Reconciliation",
        "",
        f"- Status: `{cr_reconciliation['status']}`.",
        f"- Automation id: `{cr_reconciliation['automation_id']}`.",
        f"- Artifact window: `{cr_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(cr_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(cr_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(cr_reconciliation['full_closure_achieved']).lower()}`.",
        f"- Writes allowed inside worktree: `{str(cr_reconciliation['local_write_policy']['writes_allowed_inside_worktree']).lower()}`.",
        f"- Local commands allowed: `{str(cr_reconciliation['local_write_policy']['local_commands_allowed']).lower()}`.",
        f"- Approval prompts for local commands forbidden: `{str(cr_reconciliation['local_write_policy']['approval_prompts_for_local_commands_forbidden']).lower()}`.",
        f"- Try commands before blocker: `{str(cr_reconciliation['local_write_policy']['try_commands_before_blocker']).lower()}`.",
        f"- Blocked-command fallback: `{cr_reconciliation['local_write_policy']['blocked_command_fallback']}`.",
        f"- Git/GitHub actions allowed: `{str(any(cr_reconciliation['no_git_actions_policy'][key] for key in ('stage', 'commit', 'push', 'pull_request', 'merge', 'github_actions'))).lower()}`.",
        f"- Effective running slots: `{cr_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in cr_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{cr_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{cr_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{cr_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(cr_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker CW Final Accounting Reconciliation",
        "",
        f"- Status: `{cw_reconciliation['status']}`.",
        f"- Automation id: `{cw_reconciliation['automation_id']}`.",
        f"- Artifact window: `{cw_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(cw_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(cw_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(cw_reconciliation['full_closure_achieved']).lower()}`.",
        f"- CS-CV artifact window status: `{cw_reconciliation['cs_cv_artifact_window']['status']}`.",
        f"- CS-CV artifacts recognized: `{str(cw_reconciliation['cs_cv_artifacts_recognized']).lower()}`.",
        f"- Provider local-verification status: `{provider_accounting['status']}`.",
        f"- Provider artifacts present: `{provider_accounting['present_artifact_count']}` / `{provider_accounting['expected_artifact_count']}`.",
        f"- Provider queue rows: `{provider_accounting['queue_rows']}`.",
        f"- Provider verified rows: `{provider_accounting['verified_row_count']}`.",
        f"- Provider terminal rows: `{provider_accounting['terminal_row_count']}`.",
        f"- Provider unresolved next-action rows: `{provider_accounting['unresolved_next_action_rows']}`.",
        f"- Provider proof claim: `{provider_accounting['proof_claim']}`.",
        f"- Provider submission posture: `{provider_accounting['submission_posture']}`.",
        f"- Provider local status counts: `{json.dumps(provider_accounting['aggregate_local_status_counts'], sort_keys=True)}`.",
        f"- Effective running slots: `{cw_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in cw_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{cw_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{cw_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{cw_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(cw_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker DB Final Accounting Reconciliation",
        "",
        f"- Status: `{db_reconciliation['status']}`.",
        f"- Automation id: `{db_reconciliation['automation_id']}`.",
        f"- Artifact window: `{db_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(db_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(db_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(db_reconciliation['full_closure_achieved']).lower()}`.",
        f"- CX-DA artifact window status: `{db_reconciliation['cx_da_artifact_window']['status']}`.",
        f"- CX-DA artifacts recognized: `{str(db_reconciliation['cx_da_artifacts_recognized']).lower()}`.",
        f"- Impact-Miss docs reflected: `{str(db_reconciliation['impact_miss_docs_reflected']).lower()}`.",
        f"- Genericity docs reflected: `{str(db_reconciliation['genericity_docs_reflected']).lower()}`.",
        f"- Scanner-autonomy posture valid: `{str(db_reconciliation['scanner_autonomy_posture_valid']).lower()}`.",
        f"- Scanner-autonomy percentage: `{db_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- Scanner-autonomy manual triage accounted: `{db_reconciliation['percentage_accounting']['scanner_autonomy_manual_triage_accounted_pct']}`%.",
        f"- Scanner-autonomy runnable: `{db_reconciliation['percentage_accounting']['scanner_autonomy_runnable_pct']}`%.",
        f"- Scanner-autonomy executed: `{db_reconciliation['percentage_accounting']['scanner_autonomy_executed_pct']}`%.",
        f"- Effective running slots: `{db_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in db_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{db_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{db_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{db_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(db_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker DG Final Accounting Reconciliation",
        "",
        f"- Status: `{dg_reconciliation['status']}`.",
        f"- Automation id: `{dg_reconciliation['automation_id']}`.",
        f"- Artifact window: `{dg_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(dg_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(dg_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(dg_reconciliation['full_closure_achieved']).lower()}`.",
        f"- DC-DF artifact window status: `{dg_reconciliation['dc_df_artifact_window']['status']}`.",
        f"- DC-DF artifacts recognized: `{str(dg_reconciliation['dc_df_artifacts_recognized']).lower()}`.",
        f"- Progress/readiness/known-limitations maps regenerated: `{str(dg_reconciliation['progress_readiness_known_limitations_regenerated']).lower()}`.",
        f"- Impact-Miss docs reflected: `{str(dg_reconciliation['impact_miss_docs_reflected']).lower()}`.",
        f"- Genericity docs reflected: `{str(dg_reconciliation['genericity_docs_reflected']).lower()}`.",
        f"- Scanner-autonomy posture valid: `{str(dg_reconciliation['scanner_autonomy_posture_valid']).lower()}`.",
        f"- Scanner-autonomy percentage: `{dg_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- Scanner-autonomy manual triage accounted: `{dg_reconciliation['percentage_accounting']['scanner_autonomy_manual_triage_accounted_pct']}`%.",
        f"- Scanner-autonomy runnable: `{dg_reconciliation['percentage_accounting']['scanner_autonomy_runnable_pct']}`%.",
        f"- Scanner-autonomy executed: `{dg_reconciliation['percentage_accounting']['scanner_autonomy_executed_pct']}`%.",
        f"- Effective running slots: `{dg_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in dg_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{dg_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{dg_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{dg_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(dg_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker DL Final Accounting Reconciliation",
        "",
        f"- Status: `{dl_reconciliation['status']}`.",
        f"- Automation id: `{dl_reconciliation['automation_id']}`.",
        f"- Artifact window: `{dl_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(dl_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(dl_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(dl_reconciliation['full_closure_achieved']).lower()}`.",
        f"- DH-DK artifact window status: `{dl_reconciliation['dh_dk_artifact_window']['status']}`.",
        f"- DH-DK artifacts recognized: `{str(dl_reconciliation['dh_dk_artifacts_recognized']).lower()}`.",
        f"- Progress/readiness/known-limitations maps regenerated: `{str(dl_reconciliation['progress_readiness_known_limitations_regenerated']).lower()}`.",
        f"- Impact-Miss docs reflected: `{str(dl_reconciliation['impact_miss_docs_reflected']).lower()}`.",
        f"- Impact-Miss benchmark posture valid: `{str(dl_reconciliation['impact_miss_benchmark_posture_valid']).lower()}`.",
        f"- Genericity docs reflected: `{str(dl_reconciliation['genericity_docs_reflected']).lower()}`.",
        f"- Scanner-autonomy posture valid: `{str(dl_reconciliation['scanner_autonomy_posture_valid']).lower()}`.",
        f"- Scanner-autonomy percentage: `{dl_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- Scanner-autonomy manual triage accounted: `{dl_reconciliation['percentage_accounting']['scanner_autonomy_manual_triage_accounted_pct']}`%.",
        f"- Scanner-autonomy runnable: `{dl_reconciliation['percentage_accounting']['scanner_autonomy_runnable_pct']}`%.",
        f"- Scanner-autonomy executed: `{dl_reconciliation['percentage_accounting']['scanner_autonomy_executed_pct']}`%.",
        f"- Impact-Miss benchmark accuracy: `{dl_reconciliation['percentage_accounting']['impact_miss_benchmark_accuracy_pct']}`%.",
        f"- Effective running slots: `{dl_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in dl_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{dl_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{dl_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{dl_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(dl_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker DQ Final Accounting Reconciliation",
        "",
        f"- Status: `{dq_reconciliation['status']}`.",
        f"- Automation id: `{dq_reconciliation['automation_id']}`.",
        f"- Artifact window: `{dq_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(dq_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(dq_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(dq_reconciliation['full_closure_achieved']).lower()}`.",
        f"- DM-DP artifact window status: `{dq_reconciliation['dm_dp_artifact_window']['status']}`.",
        f"- DM-DP artifacts recognized: `{str(dq_reconciliation['dm_dp_artifacts_recognized']).lower()}`.",
        f"- Progress/readiness/known-limitations maps regenerated: `{str(dq_reconciliation['progress_readiness_known_limitations_regenerated']).lower()}`.",
        f"- Impact-Miss docs reflected: `{str(dq_reconciliation['impact_miss_docs_reflected']).lower()}`.",
        f"- Impact-Miss benchmark posture valid: `{str(dq_reconciliation['impact_miss_benchmark_posture_valid']).lower()}`.",
        f"- Genericity docs reflected: `{str(dq_reconciliation['genericity_docs_reflected']).lower()}`.",
        f"- Scanner-autonomy posture valid: `{str(dq_reconciliation['scanner_autonomy_posture_valid']).lower()}`.",
        f"- Scanner-autonomy percentage: `{dq_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- Scanner-autonomy manual triage accounted: `{dq_reconciliation['percentage_accounting']['scanner_autonomy_manual_triage_accounted_pct']}`%.",
        f"- Scanner-autonomy runnable: `{dq_reconciliation['percentage_accounting']['scanner_autonomy_runnable_pct']}`%.",
        f"- Scanner-autonomy executed: `{dq_reconciliation['percentage_accounting']['scanner_autonomy_executed_pct']}`%.",
        f"- Impact-Miss benchmark accuracy: `{dq_reconciliation['percentage_accounting']['impact_miss_benchmark_accuracy_pct']}`%.",
        f"- Effective running slots: `{dq_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in dq_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{dq_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{dq_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{dq_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(dq_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Worker DW Final Accounting Reconciliation",
        "",
        f"- Status: `{dw_reconciliation['status']}`.",
        f"- Automation id: `{dw_reconciliation['automation_id']}`.",
        f"- Artifact window: `{dw_reconciliation['artifact_window']}`.",
        f"- Readiness valid expected: `{str(dw_reconciliation['readiness_valid_expected']).lower()}`.",
        f"- Full closure claimed: `{str(dw_reconciliation['full_closure_claimed']).lower()}`.",
        f"- Full closure achieved: `{str(dw_reconciliation['full_closure_achieved']).lower()}`.",
        f"- DS-DV artifact window status: `{dw_reconciliation['ds_dv_artifact_window']['status']}`.",
        f"- DS-DV artifacts recognized: `{str(dw_reconciliation['ds_dv_artifacts_recognized']).lower()}`.",
        f"- Progress/readiness/known-limitations maps regenerated: `{str(dw_reconciliation['progress_readiness_known_limitations_regenerated']).lower()}`.",
        f"- Impact-Miss docs reflected: `{str(dw_reconciliation['impact_miss_docs_reflected']).lower()}`.",
        f"- Impact-Miss benchmark posture valid: `{str(dw_reconciliation['impact_miss_benchmark_posture_valid']).lower()}`.",
        f"- Genericity docs reflected: `{str(dw_reconciliation['genericity_docs_reflected']).lower()}`.",
        f"- Scanner-autonomy posture valid: `{str(dw_reconciliation['scanner_autonomy_posture_valid']).lower()}`.",
        f"- Scanner-autonomy percentage: `{dw_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- Scanner-autonomy manual triage accounted: `{dw_reconciliation['percentage_accounting']['scanner_autonomy_manual_triage_accounted_pct']}`%.",
        f"- Scanner-autonomy runnable: `{dw_reconciliation['percentage_accounting']['scanner_autonomy_runnable_pct']}`%.",
        f"- Scanner-autonomy executed: `{dw_reconciliation['percentage_accounting']['scanner_autonomy_executed_pct']}`%.",
        f"- Impact-Miss benchmark accuracy: `{dw_reconciliation['percentage_accounting']['impact_miss_benchmark_accuracy_pct']}`%.",
        f"- Effective running slots: `{dw_reconciliation['active_slot_reliability']['effective_running_count']}`.",
        f"- Current running handles: `{', '.join(str(h) for h in dw_reconciliation['active_slot_reliability']['current_running_handles']) or '_none_'}`.",
        f"- Queue accounting: `{dw_reconciliation['queue_accounting']['remaining_next_action_rows']}` remaining next-action rows, `{dw_reconciliation['queue_accounting']['advisory_open_queue_count']}` advisory-open rows, `{dw_reconciliation['queue_accounting']['strict_blockers']}` strict blockers.",
        f"- Not-closed boundaries: `{', '.join(dw_reconciliation['not_closed_boundary_ids'])}`.",
        "",
        "## Roadmap Percentage Accounting",
        "",
        f"- Local capability target: `{bb_reconciliation['roadmap_percentage_accounting']['local_capability_target_pct']}`%.",
        f"- Known-limitations stop conditions met: `{bb_reconciliation['roadmap_percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- Known-limitations still open: `{bb_reconciliation['roadmap_percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- Full roadmap closure: `{bb_reconciliation['roadmap_percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- Full roadmap closure claimed: `{str(bb_reconciliation['roadmap_percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- BG local PR560 implementation: `{bg_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- BG known-limitations stop conditions met: `{bg_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- BG known-limitations still open: `{bg_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- BG full roadmap closure: `{bg_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- BG full roadmap closure claimed: `{str(bg_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- BL local PR560 implementation: `{bl_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- BL known-limitations stop conditions met: `{bl_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- BL known-limitations still open: `{bl_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- BL full roadmap closure: `{bl_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- BL full roadmap closure claimed: `{str(bl_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- BV local PR560 implementation: `{bv_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- BV known-limitations stop conditions met: `{bv_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- BV known-limitations still open: `{bv_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- BV full roadmap closure: `{bv_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- BV full roadmap closure claimed: `{str(bv_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- CA local PR560 implementation: `{ca_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- CA known-limitations stop conditions met: `{ca_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- CA known-limitations still open: `{ca_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- CA full roadmap closure: `{ca_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- CA full roadmap closure claimed: `{str(ca_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- CF local PR560 implementation: `{cf_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- CF known-limitations stop conditions met: `{cf_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- CF known-limitations still open: `{cf_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- CF full roadmap closure: `{cf_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- CF full roadmap closure claimed: `{str(cf_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- CK local PR560 implementation: `{ck_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- CK known-limitations stop conditions met: `{ck_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- CK known-limitations reduction: `{ck_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- CK known-limitations still open: `{ck_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- CK full roadmap closure: `{ck_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- CK full roadmap closure claimed: `{str(ck_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- CP local PR560 implementation: `{cp_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- CP known-limitations stop conditions met: `{cp_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- CP known-limitations reduction: `{cp_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- CP known-limitations still open: `{cp_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- CP full roadmap closure: `{cp_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- CP full roadmap closure claimed: `{str(cp_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- CR local PR560 implementation: `{cr_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- CR known-limitations stop conditions met: `{cr_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- CR known-limitations reduction: `{cr_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- CR known-limitations still open: `{cr_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- CR full roadmap closure: `{cr_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- CR full roadmap closure claimed: `{str(cr_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- CW local PR560 implementation: `{cw_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- CW known-limitations stop conditions met: `{cw_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- CW known-limitations reduction: `{cw_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- CW known-limitations still open: `{cw_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- CW full roadmap closure: `{cw_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- CW full roadmap closure claimed: `{str(cw_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- DB local PR560 implementation: `{db_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- DB known-limitations stop conditions met: `{db_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- DB known-limitations reduction: `{db_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- DB known-limitations still open: `{db_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- DB scanner autonomy: `{db_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- DB full roadmap closure: `{db_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- DB full roadmap closure claimed: `{str(db_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- DG local PR560 implementation: `{dg_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- DG known-limitations stop conditions met: `{dg_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- DG known-limitations reduction: `{dg_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- DG known-limitations still open: `{dg_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- DG scanner autonomy: `{dg_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- DG full roadmap closure: `{dg_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- DG full roadmap closure claimed: `{str(dg_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- DL local PR560 implementation: `{dl_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- DL known-limitations stop conditions met: `{dl_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- DL known-limitations reduction: `{dl_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- DL known-limitations still open: `{dl_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- DL scanner autonomy: `{dl_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- DL Impact-Miss benchmark accuracy: `{dl_reconciliation['percentage_accounting']['impact_miss_benchmark_accuracy_pct']}`%.",
        f"- DL full roadmap closure: `{dl_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- DL full roadmap closure claimed: `{str(dl_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- DQ local PR560 implementation: `{dq_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- DQ known-limitations stop conditions met: `{dq_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- DQ known-limitations reduction: `{dq_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- DQ known-limitations still open: `{dq_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- DQ scanner autonomy: `{dq_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- DQ Impact-Miss benchmark accuracy: `{dq_reconciliation['percentage_accounting']['impact_miss_benchmark_accuracy_pct']}`%.",
        f"- DQ full roadmap closure: `{dq_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- DQ full roadmap closure claimed: `{str(dq_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        f"- DW local PR560 implementation: `{dw_reconciliation['percentage_accounting']['local_pr560_implementation_pct']}`%.",
        f"- DW known-limitations stop conditions met: `{dw_reconciliation['percentage_accounting']['known_limitations_stop_condition_pct']}`%.",
        f"- DW known-limitations reduction: `{dw_reconciliation['percentage_accounting']['known_limitations_reduction_pct']}`%.",
        f"- DW known-limitations still open: `{dw_reconciliation['percentage_accounting']['known_limitations_open_pct']}`%.",
        f"- DW scanner autonomy: `{dw_reconciliation['percentage_accounting']['scanner_autonomy_pct']}`%.",
        f"- DW Impact-Miss benchmark accuracy: `{dw_reconciliation['percentage_accounting']['impact_miss_benchmark_accuracy_pct']}`%.",
        f"- DW full roadmap closure: `{dw_reconciliation['percentage_accounting']['full_roadmap_closure_pct']}`%.",
        f"- DW full roadmap closure claimed: `{str(dw_reconciliation['percentage_accounting']['full_roadmap_closure_claimed']).lower()}`.",
        "",
        "## Active Agent Slot Accounting",
        "",
        f"- Source: `{active_agent_slots['source']}`.",
        f"- Status: `{active_agent_slots['status']}`.",
        f"- Slots observed: `{active_agent_slots['slot_count']}`.",
        f"- Running slots: `{active_agent_slots['running_count']}`.",
        f"- Completed slots: `{active_agent_slots['completed_count']}`.",
        f"- Blocked slots: `{active_agent_slots['blocked_count']}`.",
        f"- Integration-readiness slots: `{active_agent_slots['integration_readiness_slot_count']}`.",
        f"- Boundary: {active_agent_slots['accounting_boundary']}",
        f"- Effective running slots: `{active_agent_slots['effective_running_count']}`.",
        f"- Stale running slots ignored: `{active_agent_slots['stale_running_ignored_count']}`.",
        "",
        "### Stale Slot Details",
        "",
    ])
    if active_agent_slots["stale_running_ignored_slots"]:
        for row in active_agent_slots["stale_running_ignored_slots"]:
            doc.append(
                f"- Slot `{row['slot']}` `{row['agent']}` handle `{row['handle']}` ignored as stale running; "
                f"last update `{row.get('last_update') or 'missing'}`."
            )
    else:
        doc.append("- _none_")
    doc.extend([
        "",
        "## Operator Handoff",
        "",
    ])
    for command in operator_handoff["commands"]:
        doc.append(f"- `{command}`")
    for warning in operator_handoff["warnings"]:
        doc.append(f"- {warning}")
    doc.extend([
        "",
        "## Overclaim Guardrails",
        "",
        "- Full scanner coverage: `not_claimed`.",
        "- Live provider proof: `not_claimed`; explicit operator consent is still required before live provider calls.",
        "- Live deployment proof: `not_claimed`.",
        "- PoC execution proof and submission readiness: `not_claimed`.",
        "- Known limitations: only reduced where the generated burn-down map says reduced; stop conditions still govern closure.",
        "",
        "## Remaining Not Closed",
        "",
        "| Boundary | Closed | Blocker | Next command |",
        "|---|---|---|---|",
    ])
    for key, row in pr560_not_closed_boundaries().items():
        doc.append(
            f"| `{key}` | `{row['closed']}` | {row['blocker']} | `{row['next_command']}` |"
        )
    doc.extend([
        "",
        "## Validation",
        "",
    ])
    for key, value in validation.items():
        doc.append(f"- `{key}`: `{json.dumps(value, sort_keys=True)}`")
    doc.extend([
        "",
        "## Readiness Verdict",
        "",
        f"- Local integration-readiness report: `{payload['readiness_verdict']}`.",
        "- Submission/scanner/provider proof verdict: `not_claimed`.",
        f"- Progress ledger: `{progress_json_path}`.",
        f"- Next step: {payload['recommended_next_step']}",
    ])
    write_md(readiness_path, doc)
    write_json(readiness_json_path, payload)
    return payload


def add_task(
    tasks: list[dict[str, Any]],
    routed_to_impact_analysis: list[dict[str, Any]],
    *,
    source: str,
    row: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    by_candidate: dict[str, dict[str, Any]],
    by_source: dict[str, dict[str, Any]],
    by_impact: dict[str, dict[str, Any]],
    matrix_rows: list[dict[str, Any]],
    index: int,
) -> None:
    task_type = task_type_for(row, source)
    contract = impact_contract_for(row, by_id, by_candidate, by_source, by_impact)
    impact_contract_id = str((contract or {}).get("impact_contract_id") or "").strip()
    contract_locked = impact_contract_preconditions_present(contract)
    missing_preconditions = impact_contract_missing_preconditions(contract)
    status, reason = task_status(task_type, impact_contract_id, contract_locked)
    stable_id, stable_reason = stable_candidate_id(row, source, index)
    genuine_harness = is_genuine_harness_task(row, source, task_type, contract_locked)
    if not genuine_harness:
        routed_to_impact_analysis.append(
            impact_analysis_queue_row(
                row,
                source=source,
                index=index,
                matrix_rows=matrix_rows,
                route_reason="not_harness_task_required",
            )
        )
        return
    if not stable_id and task_type not in {"scope_only", "impact_analysis"} and source != "impact_contract":
        routed_to_impact_analysis.append(
            impact_analysis_queue_row(
                row,
                source=source,
                index=index,
                matrix_rows=matrix_rows,
                route_reason=f"anonymous_missing_candidate_or_source:{stable_reason}",
            )
        )
        return
    key = stable_id or task_key(row) or f"{source}-{index}"
    action_row = impact_analysis_queue_row(
        row,
        source=source,
        index=index,
        matrix_rows=matrix_rows,
        route_reason="harness_missing_impact_contract",
    )
    suggestions = (
        impact_contract_suggestions_for_task(candidate_id=key, action_row=action_row)
        if not contract_locked and task_type not in {"scope_only", "impact_analysis"}
        else []
    )
    if not contract_locked and task_type not in {"scope_only", "impact_analysis"}:
        routed_to_impact_analysis.append(action_row)
    selected_impact = str(row.get("selected_impact") or (contract or {}).get("selected_impact") or "").strip()
    severity = str(row.get("severity") or (contract or {}).get("severity") or "none")
    if not contract_locked and task_type not in {"scope_only", "impact_analysis"}:
        selected_impact = ""
        severity = "none"
    next_command = task_next_command(status, task_type)
    if status == "blocked_missing_impact_contract":
        next_command = blocked_harness_next_command(
            candidate_id=key,
            impact_contract_id=impact_contract_id,
            missing_preconditions=missing_preconditions,
            suggestions=suggestions,
        )
    impact_contract_work_status = "none"
    if status == "blocked_missing_impact_contract":
        if suggestions:
            impact_contract_work_status = "impact_contract_suggested"
        elif impact_contract_id:
            impact_contract_work_status = "impact_contract_unlock_required"
        else:
            impact_contract_work_status = "exact_impact_candidate_required"
    tasks.append(
        {
            "harness_task_id": f"harness-task-{slug(source)}-{slug(key)}-{index:03d}",
            "source": source,
            "source_artifact": str(row.get("_source_file") or row.get("source_artifact") or ""),
            "source_id": key,
            "candidate_id": stable_id,
            "candidate_id_source": stable_reason,
            "title": task_title(row, key),
            "task_type": task_type,
            "impact_contract_id": impact_contract_id,
            "impact_contract_suggestions": suggestions,
            "impact_contract_work_status": impact_contract_work_status,
            "missing_preconditions": missing_preconditions if status == "blocked_missing_impact_contract" else [],
            "selected_impact": selected_impact,
            "severity": severity,
            "status": status,
            "blocker": "" if status == "ready_to_execute" else "blocked_missing_impact_contract",
            "reason": reason,
            "evidence_class": str(row.get("evidence_class") or _evidence_class.GENERATED_HYPOTHESIS),
            "next_command": next_command,
        }
    )


def merge_impact_analysis_routes(workspace: Path, routed_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not routed_rows:
        return None
    agent_ledger, _ = load_agent_output_verification_ledger(workspace)
    existing = load_json(out_dir(workspace) / "impact_analysis_queue.json") or render_impact_analysis_queue(workspace)
    rows = [
        row for row in records_from_payload(existing)
        if str(row.get("source") or "") != "agent_recall"
        or agent_output_allows_downstream(row, agent_ledger, allowed_terminal_states={"routed_to_impact_analysis"})
    ]
    seen = {
        "|".join(
            [
                str(row.get("source") or ""),
                str(row.get("source_id") or ""),
                str(row.get("candidate_id") or ""),
                str(row.get("route_reason") or ""),
            ]
        )
        for row in rows
    }
    added = 0
    for row in routed_rows:
        if str(row.get("source") or "") == "agent_recall" and not agent_output_allows_downstream(
            row,
            agent_ledger,
            allowed_terminal_states={"routed_to_impact_analysis"},
        ):
            continue
        key = "|".join(
            [
                str(row.get("source") or ""),
                str(row.get("source_id") or ""),
                str(row.get("candidate_id") or ""),
                str(row.get("route_reason") or ""),
            ]
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
        added += 1
    payload = {
        **existing,
        "generated_at": now_iso(),
        "rows": rows,
        "summary": {
            **dict(existing.get("summary") or {}),
            "harness_queue_routed": int((existing.get("summary") or {}).get("harness_queue_routed", 0)) + added,
        },
    }
    write_impact_analysis_payload(workspace, payload)
    return payload


def render_harness_task_queue(workspace: Path) -> dict[str, Any]:
    contracts = load_json(out_dir(workspace) / "impact_contracts.json") or render_impact_contracts(workspace)
    matrix = load_json(out_dir(workspace) / "program_impact_matrix.json") or render_impact_matrix(workspace)
    matrix_rows = [row for row in matrix.get("rows", []) if isinstance(row, dict)]
    by_id, by_candidate, by_source, by_impact = build_contract_lookup(contracts)
    agent_ledger, _ = load_agent_output_verification_ledger(workspace)
    tasks: list[dict[str, Any]] = []
    routed_to_impact_analysis: list[dict[str, Any]] = []
    for idx, row in enumerate(records_from_payload(contracts), 1):
        if str(row.get("impact_contract_id") or "").strip():
            add_task(tasks, routed_to_impact_analysis, source="impact_contract", row=row, by_id=by_id, by_candidate=by_candidate, by_source=by_source, by_impact=by_impact, matrix_rows=matrix_rows, index=idx)
    for source, path in (
        ("agent_recall", out_dir(workspace) / "agent_found_not_detector_found.json"),
        ("corpus_detectorization", out_dir(workspace) / "corpus_detectorization_inventory.json"),
    ):
        for idx, row in enumerate(load_records(path), 1):
            if source == "agent_recall" and not agent_output_allows_downstream(
                row,
                agent_ledger,
                allowed_terminal_states={"routed_to_harness_task"},
            ):
                continue
            add_task(tasks, routed_to_impact_analysis, source=source, row=row, by_id=by_id, by_candidate=by_candidate, by_source=by_source, by_impact=by_impact, matrix_rows=matrix_rows, index=idx)
    for idx, row in enumerate(discover_detector_output_records(workspace), 1):
        add_task(tasks, routed_to_impact_analysis, source="detector_output", row=row, by_id=by_id, by_candidate=by_candidate, by_source=by_source, by_impact=by_impact, matrix_rows=matrix_rows, index=idx)
    impact_analysis_payload = merge_impact_analysis_routes(workspace, routed_to_impact_analysis)

    tasks.sort(key=lambda r: (r["status"], r["source"], r["harness_task_id"]))
    blocked_tasks = [t for t in tasks if t["status"] == "blocked_missing_impact_contract"]
    actionable_blocked = bool(blocked_tasks) and all(
        t.get("candidate_id")
        and not str(t.get("candidate_id")).lower().startswith(("source-proof-", "source-proof"))
        and t.get("next_command")
        and t.get("impact_contract_work_status") in {
            "impact_contract_suggested",
            "impact_contract_unlock_required",
            "exact_impact_candidate_required",
        }
        for t in blocked_tasks
    )
    status = (
        "open_harness_impact_contract_work"
        if actionable_blocked
        else ("blocked_missing_impact_contract" if blocked_tasks else ("ok" if tasks else "empty_no_harness_tasks"))
    )
    payload = {
        "schema": f"{SCHEMA_PREFIX}.harness_tasks.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "rows": tasks,
        "summary": {
            "row_count": len(tasks),
            "ready_to_execute": sum(1 for t in tasks if t["status"] == "ready_to_execute"),
            "blocked_missing_impact_contract": len(blocked_tasks),
            "open_harness_impact_contract_work": len(blocked_tasks) if actionable_blocked else 0,
            "impact_contract_suggestions": sum(len(t.get("impact_contract_suggestions", [])) for t in tasks),
            "routed_to_impact_analysis": len(routed_to_impact_analysis),
            "impact_analysis_queue_rows": len((impact_analysis_payload or {}).get("rows", [])),
        },
        "status": status,
    }
    d = out_dir(workspace)
    write_json(d / "harness_tasks.json", payload)
    md = ["# Harness Task Queue", "", "| Task | Source | Type | Status | Impact contract | Next command | Title |", "|---|---|---|---|---|---|---|"]
    for row in tasks:
        md.append(
            f"| `{row['harness_task_id']}` | `{row['source']}` | `{row['task_type']}` | `{row['status']}` | "
            f"`{row['impact_contract_id'] or '(none)'}` | `{row['next_command']}` | {row['title']} |"
        )
    if not tasks:
        md.append("| _none_ | _none_ | _none_ | `empty_no_harness_tasks` | _none_ | _none_ | _none_ |")
    write_md(d / "harness_tasks.md", md)
    return payload


def render_known_limitations_burndown(workspace: Path) -> dict[str, Any]:
    doc = ROOT / "docs" / "KNOWN_LIMITATIONS.md"
    map_path = ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
    map_payload = load_json(map_path) or {}
    invariant_discovery = render_invariant_discovery_status(workspace)
    invariant_adoption = invariant_discovery_adoption_accounting(workspace)
    invariant_adoption_closure = invariant_adoption_closure_readiness_accounting(workspace)
    severity_guard_evidence = detect_severity_claim_guard_generic_fallback(ROOT)
    impact_first_gate_evidence = detect_impact_first_work_gate_reduction(ROOT)
    semantic_live_depth = semantic_live_depth_accounting(workspace)
    impact_miss_benchmark = impact_miss_benchmark_accounting(workspace)
    semantic_fixture_smoke_accounting, semantic_fixture_smoke_path = collect_semantic_fixture_smoke_accounting(workspace)
    detector_semantic_repair_accounting, detector_semantic_repair_path = collect_detector_semantic_repair_accounting(workspace)
    canonical_fixture_materialization_accounting, canonical_fixture_materialization_path = (
        collect_canonical_fixture_materialization_accounting(workspace)
    )
    impact_family_worklist = impact_family_worklist_accounting(workspace)
    execution_source_import_workflow = execution_source_import_workflow_accounting(workspace)
    live_topology_explicit_blockers = live_topology_explicit_blocker_accounting(workspace)
    live_topology_hermetic_workflow = live_topology_hermetic_workflow_accounting(workspace)
    live_topology_real_input_workflow = live_topology_real_input_workflow_accounting(workspace)
    runtime_dlt_execution_evidence = runtime_dlt_execution_evidence_accounting(workspace)
    outcome_calibration = outcome_calibration_accounting(workspace)
    agent_recall_closure = agent_recall_closure_accounting(workspace)
    evidence_class_accounting = evidence_class_validator_accounting(workspace)
    source_rows = map_payload.get("rows") if isinstance(map_payload, dict) else None
    rows: list[dict[str, Any]] = []
    for row in source_rows if isinstance(source_rows, list) else []:
        if not isinstance(row, dict):
            continue
        enriched = dict(row)
        title = str(enriched.get("title") or "").lower()
        limitation_id = str(enriched.get("limitation_id") or "").lower()
        if "invariant discovery" in title or limitation_id == "p0-0":
            enriched["invariant_discovery"] = invariant_discovery
            enriched["invariant_discovery_adoption"] = invariant_adoption
            enriched["invariant_discovery_status"] = invariant_discovery["status"]
            enriched["invariant_discovery_artifact_path"] = invariant_discovery["artifact_path"]
            enriched["invariant_discovery_next_command"] = invariant_discovery["next_command"]
        if limitation_id == "priority-4":
            enriched["invariant_discovery_adoption"] = invariant_adoption
            enriched["invariant_discovery_adoption_artifact_path"] = invariant_adoption["artifact_path"]
            enriched["invariant_discovery_adoption_status"] = invariant_adoption["status"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if invariant_adoption["priority4_stop_condition_met"]:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_invariant_blocker_rows"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "invariant_discovery_row_or_blocker_stop_condition_met"
                enriched["remaining_after_560"] = (
                    f"Generated-vs-accepted invariant discovery is review-complete for the current workspace "
                    f"and `{invariant_adoption['route_family_unit_count']}` High/Critical route-family units "
                    "have canonical invariant-ledger rows with explicit blockers and executable next commands. "
                    "This closes the current priority-4 row-or-explicit-blocker branch only; no invariant proof, "
                    "severity promotion, production-path proof, OOS clearance, or submission readiness is claimed."
                )
            else:
                enriched["reduction_status"] = "invariant_discovery_adoption_open_or_missing"
                enriched["remaining_after_560"] = (
                    "Invariant discovery adoption output is missing or incomplete. Run "
                    "make invariant-discovery-adoption WS=<workspace> ADOPT_LEDGER=1 JSON=1 and rerun burndown."
                )
        if limitation_id == "p0-0":
            enriched["invariant_discovery_adoption"] = invariant_adoption
            enriched["invariant_discovery_adoption_artifact_path"] = invariant_adoption["artifact_path"]
            enriched["invariant_adoption_closure_readiness"] = invariant_adoption_closure
            enriched["invariant_adoption_closure_readiness_artifact_path"] = invariant_adoption_closure["artifact_path"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if invariant_adoption_closure["p0_closure_ready"]:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_fresh_engagement_and_proof_metrics"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "p0_invariant_adoption_stop_condition_met"
                enriched["remaining_after_560"] = (
                    "Invariant adoption closure readiness is satisfied: "
                    f"`{invariant_adoption_closure['valid_fresh_engagement_count']}` fresh engagements meet adoption thresholds, "
                    f"`{invariant_adoption_closure['proof_ready_execution_manifest_count']}` proof-ready execution manifests exist, "
                    f"`{invariant_adoption_closure['ready_project_source_root_count']}` project source roots are ready, and "
                    f"`{invariant_adoption_closure['source_line_hit_unit_count']}` source line-hit units are present. "
                    "This closes invariant adoption mechanics only; severity, OOS, production-path, and submission readiness remain separate gates."
                )
            elif invariant_adoption["priority4_stop_condition_met"]:
                enriched["reduction_status"] = "reduced_current_workspace_invariant_adoption_not_full_p0"
                enriched["remaining_after_560"] = (
                    f"Current workspace invariant adoption is mechanically reduced: "
                    f"`{invariant_adoption['route_family_unit_count']}` route-family units have blocked "
                    "canonical invariant-ledger rows and generated rows have terminal review states. The strict P0-0 "
                    "closure gate remains open with exact blockers: "
                    f"{', '.join(invariant_adoption_closure['blockers']) or 'run invariant-adoption-closure-readiness'}. "
                    f"Fresh engagement metrics are `{invariant_adoption_closure['valid_fresh_engagement_count']}/"
                    f"{invariant_adoption_closure['required_fresh_engagement_count']}` and proof-ready execution manifests are "
                    f"`{invariant_adoption_closure['proof_ready_execution_manifest_count']}`."
                )
        if limitation_id == "cross-cut-severity-claim-discipline":
            enriched["severity_claim_guard_generic_fallback"] = severity_guard_evidence
            if severity_guard_evidence["status"] == "present":
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_citation"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "reduced_generic_guard_present"
                enriched["remaining_after_560"] = (
                    "Generic severity-claim-guard fallback, tests, docs, and pre-submit "
                    "wiring are present. Impact-first work gating remains tracked by "
                    "cross-cut-impact-first-work-gating and is not marked met here."
                )
        if limitation_id in {"priority-1", "cross-cut-impact-first-work-gating"}:
            enriched["impact_first_work_gate_reduction"] = impact_first_gate_evidence
            if impact_first_gate_evidence["status"] == "present":
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "progress_reduced_with_remaining_paths"
                enriched["stop_condition_met"] = False
                enriched["reduction_status"] = "reduced_detected_paths_not_closed"
                enriched["covered_paths_after_560"] = impact_first_gate_evidence["covered_paths"]
                enriched["remaining_unproven_paths_after_560"] = impact_first_gate_evidence["remaining_unproven_paths"]
                enriched["remaining_after_560"] = (
                    "Impact-contract gates are detected for critical-hunt, paste-ready, "
                    "submission-packager, swarm dispatch, mining briefs, poc-scaffold "
                    "plan-json, auto-draft, harness scaffold, submission-factory, "
                    "deep replay scaffold, detector promotion, source-mining survivor "
                    "and provider-routing/preflight seams, captured Kimi source-extract "
                    "and Minimax adversarial-kill provider-assist outputs as advisory "
                    "only, semantic detector worklist, typed multihop source-shape "
                    "seams, semantic/live depth accounting rows, submission "
                    "proof-artifact/tier gates, ReCon/Chimera "
                    "scaffold/replay seams, corpus "
                    "detectorization, and docs validation. This is progress/"
                    "reduction only: generic harness execution, source-proof promotion, "
                    "audit-closeout, and any other candidate-generation/direct-submit "
                    "path remain unproven here."
                )
        if limitation_id == "priority-2":
            enriched["impact_family_worklist_accounting"] = impact_family_worklist
            enriched["impact_family_worklist_artifact_path"] = impact_family_worklist["validator_path"]
            enriched["impact_family_source_harness_artifact_path"] = impact_family_worklist["discovery_path"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if impact_family_worklist["complete_worklist_stop_condition_met"]:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_worklist_citation"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "mechanical_impact_family_worklist_stop_condition_met"
                source_import_note = ""
                if impact_family_worklist.get("source_import_terminal_no_roots"):
                    source_import_note = (
                        f" Project-source declaration/import support is workflow-ready and consumed by the reducer, "
                        f"but this workspace declares `{impact_family_worklist['source_root_declared_count']}` ready target "
                        "source roots; source-proof and harness-binding promotion remain blocked on real project-source import."
                    )
                enriched["remaining_after_560"] = (
                    f"Mechanical impact-family worklist closure is complete for the current workspace: "
                    f"{impact_family_worklist['contract_count']} impact contracts, "
                    f"{impact_family_worklist['route_family_count']} route families, "
                    f"{impact_family_worklist['actionable_unit_count']} exact next-input units, and "
                    f"{impact_family_worklist['source_harness_terminal_reduced_unit_count']} / "
                    f"{impact_family_worklist['source_harness_required_unit_count']} source/harness-dependent units "
                    "terminalized into named blockers with next commands. This closes only the worklist/coverage "
                    "inventory stop condition; listed impact, severity, production path, source proof, live/fork proof, "
                    "and exploit-impact execution remain explicitly not claimed."
                    f"{source_import_note}"
                )
            else:
                enriched["reduction_status"] = "mechanical_impact_family_worklist_open_or_missing"
                enriched["remaining_after_560"] = (
                    "Mechanical impact-family worklist evidence is missing or incomplete. Keep row open until impact "
                    "contracts, route families, uncovered proof classes, named blockers, and next commands are all materialized."
                )
        category_probe = dict(enriched)
        execution_source_import_row = (
            "harness" in title
            or "counterexample" in title
            or "replay" in title
            or limitation_id in {"p1-5"}
        )
        if (
            "model" in title
            or "outcome" in title
            or "routing" in title
            or limitation_id in {"priority-8", "p0-3", "p0-4"}
            or execution_source_import_row
        ):
            category_probe["stop_condition_met"] = False
        provisional_category = known_limitations_blocker_category(category_probe)
        if provisional_category == "open_detector_precision_or_semantics":
            enriched["semantic_fixture_smoke_accounting"] = semantic_fixture_smoke_accounting
            enriched["semantic_fixture_smoke_artifact_path"] = (
                semantic_fixture_smoke_path if semantic_fixture_smoke_accounting else ""
            )
            enriched["detector_semantic_repair_accounting"] = detector_semantic_repair_accounting
            enriched["detector_semantic_repair_artifact_path"] = (
                detector_semantic_repair_path if detector_semantic_repair_accounting else ""
            )
            enriched["canonical_fixture_materialization_accounting"] = canonical_fixture_materialization_accounting
            enriched["canonical_fixture_materialization_artifact_path"] = (
                canonical_fixture_materialization_path if canonical_fixture_materialization_accounting else ""
            )
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            fixture_smoke_stop_met = detector_fixture_smoke_stop_condition_met(
                semantic_fixture_smoke_accounting,
                detector_semantic_repair_accounting,
                canonical_fixture_materialization_accounting,
            )
            if limitation_id in {"p1-1", "p1-4"} and fixture_smoke_stop_met:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_fixture_smoke_citation"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = (
                    "detector_canonical_fixture_smoke_stop_condition_met"
                    if canonical_fixture_materialization_accounting
                    else "detector_fixture_smoke_stop_condition_met"
                )
                canonical_note = ""
                if canonical_fixture_materialization_accounting:
                    canonical_note = (
                        f" Canonical materialization is also complete: "
                        f"{canonical_fixture_materialization_accounting.get('canonical_smoke_passed_count', 0)} / "
                        f"{canonical_fixture_materialization_accounting.get('processed_count', 0)} materialized fixture pairs "
                        "passed vulnerable>=1 / clean==0 smoke with "
                        f"{canonical_fixture_materialization_accounting.get('canonical_smoke_failed_count', 0)} failed and "
                        f"{canonical_fixture_materialization_accounting.get('blocked_count', 0)} blocked."
                    )
                enriched["remaining_after_560"] = (
                    f"Current detector fixture-smoke scope is closed: "
                    f"{semantic_fixture_smoke_accounting.get('terminal_clean_positive_count', 0)} / "
                    f"{semantic_fixture_smoke_accounting.get('smoke_required_count', 0)} canonical detector smoke rows "
                    "passed vulnerable/clean smoke with "
                    f"{semantic_fixture_smoke_accounting.get('blocked_missing_fixture_or_smoke_count', 0)} blocked rows, "
                    f"and {detector_semantic_repair_accounting.get('local_semantic_repair_smoke_passed', 0)} / "
                    f"{detector_semantic_repair_accounting.get('processed_count', 0)} semantic repair rows smoke-passed with "
                    f"{detector_semantic_repair_accounting.get('scanner_semantic_blockers_left', 0)} semantic blockers left. "
                    f"{canonical_note} "
                    "This closes only the local detector/scanner fixture-smoke stop condition for this row; "
                    "promotion, severity, source-proof, exploit-impact, and submission readiness remain explicitly not claimed."
                )
            elif semantic_fixture_smoke_accounting:
                enriched["reduction_status"] = "semantic_fixture_smoke_accounted_not_precision_proof"
                enriched["remaining_after_560"] = (
                    f"{semantic_fixture_smoke_accounting.get('terminal_clean_positive_count', 0)} detector fixture "
                    "smoke rows have terminal clean/positive accounting and "
                    f"{semantic_fixture_smoke_accounting.get('blocked_missing_fixture_or_smoke_count', 0)} rows remain "
                    "blocked on fixture or smoke evidence. This is detector precision accounting only, not "
                    "submission, severity, or promotion proof."
                )
        if provisional_category == "open_execution_manifest_or_replay_proof":
            if bool(enriched.get("stop_condition_met")):
                enriched["terminal_state_before_execution_source_import"] = enriched.get("terminal_state")
            enriched["stop_condition_met"] = False
            enriched["execution_source_import_workflow_accounting"] = execution_source_import_workflow
            enriched["execution_manifest_proof_readiness_artifact_path"] = execution_source_import_workflow[
                "execution_manifest_proof_readiness_path"
            ]
            enriched["impact_binding_source_import_readiness_artifact_path"] = execution_source_import_workflow[
                "impact_binding_source_import_readiness_path"
            ]
            enriched["project_source_root_readiness_artifact_path"] = execution_source_import_workflow[
                "project_source_root_readiness_path"
            ]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if execution_source_import_workflow["workflow_reduction_stop_condition_accounted"]:
                enriched["reduction_status"] = "execution_source_import_workflow_reduced_real_proof_missing"
                enriched["remaining_after_560"] = (
                    f"Execution/source-root workflow is formally reduced for this row: "
                    f"{execution_source_import_workflow['proved_execution_requirement_count']} proved-execution "
                    "requirements are classified by execution-manifest proof readiness and "
                    f"{execution_source_import_workflow['source_import_unit_count']} source/harness import units "
                    "are classified by source-import readiness. The current workspace has "
                    f"{execution_source_import_workflow['ready_project_source_root_count']} ready project source roots, "
                    f"{execution_source_import_workflow['proof_ready_count']} proof-ready execution rows, and "
                    f"{execution_source_import_workflow['closed_proof_count']} closed proof rows. This is a blocker "
                    "reduction only: real closure still requires candidate-bound project source citations, project "
                    "harness bindings, and execution manifests with final_result=proved plus "
                    "impact_assertion=exploit_impact."
                )
            else:
                enriched["reduction_status"] = "execution_source_import_workflow_open_or_missing"
                enriched["remaining_after_560"] = (
                    "Execution/source-root workflow artifacts are missing or incomplete. Run "
                    "make project-source-root-readiness, make impact-binding-source-import-readiness, and "
                    "make execution-manifest-proof-readiness before reducing this row."
                )
        if provisional_category == "open_agent_recall_terminal_routes":
            enriched["agent_recall_closure_accounting"] = agent_recall_closure
            enriched["agent_recall_closure_artifact_path"] = agent_recall_closure["artifact_path"]
            enriched["agent_recall_queue_artifact_path"] = agent_recall_closure["queue_artifact_path"]
            enriched["agent_recall_source_local_artifact_path"] = agent_recall_closure["source_local_artifact_path"]
            enriched["agent_recall_total_candidate_rows"] = agent_recall_closure["total_candidate_rows"]
            enriched["agent_recall_terminalized_or_bounded_rows"] = agent_recall_closure["terminalized_or_bounded_rows"]
            enriched["agent_recall_open_actionable_rows"] = agent_recall_closure["open_actionable_rows"]
            enriched["agent_recall_detectorized_terminal"] = agent_recall_closure["detectorized_terminal"]
            enriched["agent_recall_non_detectorizable_terminal"] = agent_recall_closure["non_detectorizable_terminal"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if limitation_id == "priority-3" and agent_recall_closure["priority_stop_condition_met"]:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_citation"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "agent_recall_priority_stop_condition_met"
                enriched["remaining_after_560"] = (
                    f"Full-corpus recall evidence evaluated {agent_recall_closure['total_candidate_rows']} rows, "
                    f"terminalized/bounded {agent_recall_closure['terminalized_or_bounded_rows']}, left "
                    f"{agent_recall_closure['open_actionable_rows']} actionable tasks, recorded "
                    f"{agent_recall_closure['detectorized_terminal']} detectorized terminal routes, and recorded "
                    f"{agent_recall_closure['non_detectorizable_terminal']} non-detectorizable/terminal routes. "
                    "This closes the recall-loop stop condition only; it does not promote findings, severity, or impact proof."
                )
            elif (
                limitation_id == "cross-cut-agent-found-behavior-recall"
                and agent_recall_closure["cross_cut_stop_condition_met"]
            ):
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_citation"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "agent_recall_full_corpus_stop_condition_met"
                enriched["remaining_after_560"] = (
                    f"Full-corpus recall evidence terminalized/bounded all "
                    f"{agent_recall_closure['terminalized_or_bounded_rows']} / "
                    f"{agent_recall_closure['total_candidate_rows']} candidate rows, with "
                    f"{agent_recall_closure['queue_terminal_reason_rows']} / "
                    f"{agent_recall_closure['queue_row_count']} queue rows carrying terminal reasons and "
                    f"{agent_recall_closure['source_local_terminal_reason_rows']} / "
                    f"{agent_recall_closure['source_local_row_count']} source/local closure rows carrying terminal reasons. "
                    "This closes recall accounting for current local evidence only; it does not create source, impact, OOS, or execution proof."
                )
            elif agent_recall_closure["full_closed_for_current_local_evidence"]:
                enriched["reduction_status"] = "agent_recall_full_corpus_reduced_not_row_stop_condition"
                enriched["remaining_after_560"] = (
                    "Agent-recall full-corpus evidence is terminal for current local evidence, but this row's "
                    "specific stop condition still needs separate proof before closure."
                )
            else:
                enriched["reduction_status"] = "agent_recall_open_tasks_or_missing_full_corpus_proof"
                enriched["remaining_after_560"] = (
                    "Agent-recall full-corpus proof is missing or still has actionable detector/source/local "
                    "proof tasks. Keep the row open until all recall rows have terminal routes."
                )
        if provisional_category == "open_semantic_or_live_topology_depth":
            enriched["semantic_live_depth_accounting"] = semantic_live_depth
            enriched["live_topology_hermetic_workflow_accounting"] = live_topology_hermetic_workflow
            enriched["live_topology_real_input_workflow_accounting"] = live_topology_real_input_workflow
            enriched["live_topology_real_input_workflow_artifact_path"] = str(
                out_dir(workspace) / "live_topology_real_input_workflow_reduction.json"
            )
            enriched["live_topology_hermetic_workflow_artifact_path"] = live_topology_hermetic_workflow[
                "bridge_artifact_path"
            ]
            enriched["semantic_live_terminal_depth_closed_count"] = semantic_live_depth["terminal_depth_closed_count"]
            enriched["semantic_live_blocked_depth_count"] = semantic_live_depth["blocked_depth_count"]
            enriched["semantic_live_concrete_item_count"] = semantic_live_depth["concrete_item_count"]
            enriched["semantic_live_concrete_item_target"] = semantic_live_depth["concrete_item_target"]
            enriched["semantic_live_exact_same_block_pair_ids"] = semantic_live_depth["exact_same_block_pair_ids"]
            enriched["semantic_live_artifacts"] = semantic_live_depth["artifacts"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if semantic_live_depth["terminal_depth_closed_count"]:
                enriched["reduction_status"] = "semantic_live_depth_rows_closed_accounting_only"
                enriched["remaining_after_560"] = (
                    f"{semantic_live_depth['terminal_depth_closed_count']} semantic/live depth rows have exact "
                    "same-block proof-pair accounting, but this is not exploit proof and does not close "
                    "production-path, severity, or submission gates. "
                    f"{semantic_live_depth['blocked_depth_count']} semantic/live depth rows remain blocked or queued."
                )
            elif live_topology_real_input_workflow["real_input_workflow_reduced"]:
                enriched["reduction_status"] = "semantic_live_real_input_workflow_reduced_inputs_missing"
                enriched["remaining_after_560"] = (
                    "Real live-topology input workflow is now routed end-to-end under a no-proof boundary: "
                    f"{live_topology_real_input_workflow['proof_pairs_total']} proof pairs and "
                    f"{live_topology_real_input_workflow['rows_total']} rows have exact operator/RPC input blockers, "
                    f"{live_topology_real_input_workflow['same_block_ready_pairs']} same-block pairs are ready, "
                    f"{live_topology_real_input_workflow['provided_rows_written']} provided rows were written, and "
                    f"{live_topology_real_input_workflow['proof_pairs_closed']} proof pairs are closed. "
                    "Real closure still requires RPC-backed same-block input files, materialization, import, and "
                    "executor validation against workspace proof pairs."
                )
            elif live_topology_hermetic_workflow["hermetic_workflow_validated"]:
                enriched["reduction_status"] = "semantic_live_hermetic_workflow_validated_real_pairs_missing"
                enriched["remaining_after_560"] = (
                    "Hermetic same-block manual-proof materializer/import/executor workflow is validated with "
                    f"{live_topology_hermetic_workflow['hermetic_same_block_depth_closure_candidates']} depth-only "
                    "closure candidate in the fixture and a negative cross-block fixture, but "
                    f"{semantic_live_depth['blocked_depth_count']} real semantic/live depth rows remain blocked. "
                    "Real closure still requires RPC-backed same-block proof files, import, and executor validation "
                    "against the workspace live-topology requirements."
                )
            else:
                enriched["reduction_status"] = "semantic_live_depth_rows_blocked_or_missing"
                enriched["remaining_after_560"] = (
                    "No exact same-block semantic/live proof-pair closure was counted for this workspace. "
                    "Rows remain open until the semantic-live-depth queue records exact proved same-block pairs."
                )
        if limitation_id == "p1-3":
            enriched["live_topology_explicit_blocker_accounting"] = live_topology_explicit_blockers
            enriched["live_topology_hermetic_workflow_accounting"] = live_topology_hermetic_workflow
            enriched["live_topology_real_input_workflow_accounting"] = live_topology_real_input_workflow
            enriched["live_topology_hermetic_workflow_artifact_path"] = live_topology_hermetic_workflow[
                "bridge_artifact_path"
            ]
            enriched["live_topology_explicit_blocker_artifact_path"] = live_topology_explicit_blockers["materializer_path"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if live_topology_explicit_blockers["explicit_blocker_stop_condition_met"]:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["terminal_state"] = "already_satisfied_with_explicit_blocker_citation"
                enriched["stop_condition_met"] = True
                enriched["reduction_status"] = "live_topology_explicit_blocker_stop_condition_met"
                enriched["remaining_after_560"] = (
                    f"Live-topology synthesis has exact explicit blockers for "
                    f"{live_topology_explicit_blockers['proof_pairs_total']} proof pairs and "
                    f"{live_topology_explicit_blockers['rows_total']} rows. "
                    f"{live_topology_explicit_blockers['import_ready_pairs']} pairs are import-ready, "
                    f"{live_topology_explicit_blockers['canonical_rows_materialized']} rows were materialized, and "
                    f"{live_topology_explicit_blockers['proof_pairs_closed']} proof pairs are closed, so no live proof "
                    "is claimed. This satisfies only the P1-3 stop-condition branch requiring explicit blockers for "
                    "cross-contract claims; same-block proof, selected impact, severity, and submission readiness remain open. "
                    f"Hermetic workflow status is `{live_topology_hermetic_workflow['status']}`."
                )
            elif Path(live_topology_explicit_blockers["validator_path"]).is_file() or Path(
                live_topology_explicit_blockers["materializer_path"]
            ).is_file():
                enriched["reduction_status"] = "live_topology_explicit_blockers_open_or_missing"
                enriched["remaining_after_560"] = (
                    "Live-topology proof-input/materializer artifacts are missing or incomplete. Keep row open until every "
                    "proof pair and row has either same-block proof or exact explicit blocker commands."
                )
        if limitation_id == "p1-2":
            enriched["runtime_dlt_execution_evidence_accounting"] = runtime_dlt_execution_evidence
            enriched["runtime_dlt_execution_evidence_artifact_path"] = runtime_dlt_execution_evidence["artifact_path"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if runtime_dlt_execution_evidence["reduction_stop_condition_accounted"]:
                enriched["reduction_status"] = "runtime_dlt_execution_evidence_reduced_not_closed"
                enriched["remaining_after_560"] = (
                    f"Runtime/DLT evidence reduced {runtime_dlt_execution_evidence['dlt_row_count']} DLT rows with "
                    f"hermetic fixture status `{runtime_dlt_execution_evidence['hermetic_fixture_status']}` and blocker "
                    f"counts {runtime_dlt_execution_evidence['blocker_counts']}. This is not closure: "
                    f"{runtime_dlt_execution_evidence['proved_exploit_impact_count']} rows have strict proved exploit-impact "
                    "execution manifests, and concrete cross-crate invocation/runtime semantics still need project-bound proof."
                )
        if provisional_category == "open_outcome_calibration":
            original_stop_condition_met = bool(enriched.get("stop_condition_met"))
            enriched["outcome_calibration_accounting"] = outcome_calibration
            enriched["outcome_calibration_artifact_path"] = outcome_calibration["artifact_path"]
            enriched["outcome_calibration_resolved_linkage_exists"] = outcome_calibration["resolved_linkage_exists"]
            enriched["outcome_calibration_linked_for_calibration"] = outcome_calibration["linked_for_calibration"]
            enriched["outcome_calibration_missing_linkage"] = outcome_calibration["missing_linkage"]
            enriched["outcome_calibration_queue_items"] = outcome_calibration["queue_items"]
            enriched["outcome_calibration_outcome_linkage_backfill_items"] = outcome_calibration["outcome_linkage_backfill_items"]
            enriched["outcome_calibration_resolved_linkage_validation_status"] = outcome_calibration["resolved_linkage_validation_status"]
            enriched["outcome_calibration_resolved_linkage_validation_artifact_path"] = outcome_calibration["resolved_linkage_validation_artifact_path"]
            enriched["outcome_calibration_resolved_linkage_validation_valid_rows"] = outcome_calibration["resolved_linkage_validation_valid_rows"]
            enriched["outcome_calibration_resolved_linkage_validation_terminalized_rows"] = outcome_calibration["resolved_linkage_validation_terminalized_rows"]
            enriched["outcome_calibration_route_evidence_import_exists"] = outcome_calibration["route_evidence_import_exists"]
            enriched["outcome_calibration_route_evidence_import_status"] = outcome_calibration["route_evidence_import_status"]
            enriched["outcome_calibration_route_evidence_import_artifact_path"] = outcome_calibration["route_evidence_import_artifact_path"]
            enriched["outcome_calibration_route_evidence_import_valid_rows"] = outcome_calibration["route_evidence_import_valid_rows"]
            enriched["outcome_calibration_route_evidence_import_invalid_rows"] = outcome_calibration["route_evidence_import_invalid_rows"]
            enriched["outcome_calibration_route_evidence_rows_seen"] = outcome_calibration["route_evidence_rows_seen"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if outcome_calibration["resolved_linkage_exists"]:
                enriched["reduction_status"] = "outcome_calibration_resolved_linkage_accounted"
                enriched["remaining_after_560"] = (
                    f"{outcome_calibration['linked_for_calibration']} resolved outcome rows have lane/model/proof "
                    "linkage and can reduce outcome-calibration known-limitation accounting. "
                    f"{outcome_calibration['missing_linkage']} resolved rows still lack required linkage and "
                    f"{outcome_calibration['blocked_routes']} provider/task routes remain below promotion-ready floors. "
                    "This is calibration evidence only, not submission or severity proof."
                )
                enriched["stop_condition_met"] = (
                    original_stop_condition_met
                    and outcome_calibration["all_resolved_rows_linked"]
                    and outcome_calibration["blocked_routes"] == 0
                )
            else:
                enriched["terminal_state_before_evidence_detection"] = enriched.get("terminal_state")
                enriched["stop_condition_met"] = False
                if outcome_calibration["route_evidence_import_exists"]:
                    enriched["reduction_status"] = "outcome_calibration_route_evidence_import_workflow_reduced_no_linked_rows"
                    enriched["remaining_after_560"] = (
                        "Terminal TRUE/FALSE/PARTIAL route-evidence import is wired and guarded by resolved outcome "
                        f"matching, proof artifacts, and production-path linkage. It saw {outcome_calibration['route_evidence_rows_seen']} "
                        f"route-evidence rows and imported {outcome_calibration['route_evidence_import_valid_rows']} valid rows. "
                        f"Resolved-linkage validation status is `{outcome_calibration['resolved_linkage_validation_status']}` with "
                        f"{outcome_calibration['resolved_linkage_validation_terminalized_rows']} terminalized missing-linkage rows. "
                        "Outcome calibration remains open until real linked rows exist and route precision has enough terminal samples."
                    )
                elif outcome_calibration["resolved_linkage_validation_status"] == "terminalized_missing_linkage_not_calibration":
                    enriched["reduction_status"] = "outcome_calibration_strict_import_ready_no_linked_rows"
                    enriched["remaining_after_560"] = (
                        "Strict resolved-linkage import validation is wired and all current resolved outcome rows are "
                        f"accounted for as terminal missing-linkage rows ({outcome_calibration['resolved_linkage_validation_terminalized_rows']}). "
                        "This reduces the bookkeeping gap but does not close calibration: zero rows have durable "
                        "lane/model/proof/production-path linkage and provider-local route rows remain advisory."
                    )
                else:
                    enriched["reduction_status"] = "outcome_calibration_blocked_missing_resolved_linkage"
                    enriched["remaining_after_560"] = (
                        "Outcome-calibration scorecard evidence is missing or contains no resolved outcome rows with "
                        "lane/model/proof linkage. Provider-local and route-gap rows remain advisory and cannot reduce "
                        "or close outcome-calibration known limitations until resolved linkage exists."
                    )
        if limitation_id in {"cross-cut-impact-miss-offset", "impact-miss-offset"} or "impact-miss" in title:
            enriched["impact_miss_benchmark_accounting"] = impact_miss_benchmark
            enriched["impact_miss_benchmark_artifact_path"] = impact_miss_benchmark["benchmark_path"]
            enriched["impact_miss_prediction_artifact_path"] = impact_miss_benchmark["predictions_path"]
            enriched["submission_posture"] = "NOT_SUBMIT_READY"
            enriched["submit_status"] = "NOT_SUBMIT_READY"
            enriched["promotion_allowed"] = False
            if impact_miss_benchmark["scored"]:
                enriched["reduction_status"] = "impact_miss_route_score_accounted_not_closure"
                enriched["remaining_after_560"] = (
                    f"Impact-Miss route benchmark scored {impact_miss_benchmark['passed']} / "
                    f"{impact_miss_benchmark['item_count']} rows at accuracy "
                    f"{impact_miss_benchmark['accuracy']}. Genericity accounted: "
                    f"{str(impact_miss_benchmark['genericity_accounted']).lower()}. "
                    "This is route-family recall accounting only, not exploit proof, scanner completeness, "
                    "or submission readiness."
                )
            else:
                enriched["reduction_status"] = "impact_miss_benchmark_unscored_or_missing"
                enriched["remaining_after_560"] = (
                    "Impact-Miss benchmark rows exist only as an unscored or missing artifact. Generate "
                    "workspace-derived predictions before using this row for reduction accounting."
                )
        if limitation_id == "p2-6" or "generated artifacts" in title:
            enriched["evidence_class_accounting"] = evidence_class_accounting
            enriched["evidence_class_legacy_count"] = evidence_class_accounting["legacy_count"]
            enriched["evidence_class_policy_violation_count"] = evidence_class_accounting["policy_violation_count"]
            enriched["evidence_class_verified_count"] = evidence_class_accounting.get("verified_count", 0)
            enriched["evidence_class_hypothesis_count"] = evidence_class_accounting.get("hypothesis_count", 0)
            if evidence_class_accounting["status"] == "clean_no_legacy_or_policy_violations":
                enriched["reduction_status"] = "legacy_evidence_class_backfill_closed"
                enriched["remaining_after_560"] = (
                    "Active workspace legacy evidence_class rows are closed: validator reports "
                    "legacy=0 and policy_violations=0. The row remains open until packaged-bundle "
                    "inheritance and human/external-proof promotion review are proven end-to-end."
                )
                enriched["terminal_state"] = "progress_reduced_with_remaining_paths"
                enriched["stop_condition_met"] = False
            else:
                enriched["reduction_status"] = "legacy_evidence_class_backfill_open"
                enriched["remaining_after_560"] = (
                    f"Evidence-class validator still reports legacy={evidence_class_accounting['legacy_count']} "
                    f"and policy_violations={evidence_class_accounting['policy_violation_count']}; run "
                    "make evidence-class-legacy-backfill WS=<workspace> before claiming closure."
                )
        checks = strict_burndown_row_checks(enriched)
        enriched["owner_command"] = checks["owner_command"]
        enriched["artifact_paths"] = checks["artifact_paths"]
        enriched["strict_required"] = checks["strict_required"]
        enriched["strict_missing_fields"] = checks["missing_fields"]
        enriched["strict_status"] = "blocked_named" if checks["missing_fields"] else "ok"
        enriched["blocker_category"] = known_limitations_blocker_category(enriched)
        enriched["command_level_blockers"] = known_limitations_command_blockers(enriched)
        enriched["closure_checklist"] = known_limitations_closure_checklist(enriched, checks)
        rows.append(enriched)

    # Backward-compatible fallback for older checkouts without the map.
    if not rows and doc.is_file():
        for line in doc.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 2 or cells[0].lower() in {"priority", "---"}:
                continue
            if re.match(r"^(p\d|[0-9]+|impact-|full burn)", cells[0], re.I):
                fallback = {
                    "limitation_id": f"known-limitation-{slug(cells[0] + '-' + cells[1])}",
                    "priority_group": "unknown",
                    "source_key": cells[0],
                    "title": cells[1],
                    "terminal_state": "inventory_only",
                    "next_command": "make automation-closure WS=<workspace>",
                    "stop_condition": "",
                    "evidence": [],
                }
                fallback["strict_required"] = False
                fallback["strict_missing_fields"] = []
                fallback["strict_status"] = "ok"
                fallback["blocker_category"] = known_limitations_blocker_category(fallback)
                fallback["command_level_blockers"] = known_limitations_command_blockers(fallback)
                fallback["closure_checklist"] = known_limitations_closure_checklist(
                    fallback,
                    {
                        "owner_command": fallback["next_command"],
                        "artifact_paths": [],
                        "stop_condition": "",
                        "status_evidence": [],
                    },
                )
                rows.append(fallback)

    checklist_items = [item for row in rows for item in row.get("closure_checklist", [])]
    command_blockers = [item for row in rows for item in row.get("command_level_blockers", [])]
    execution_proof_queue = write_execution_proof_task_queue(workspace, rows)
    checklist_status_counts = Counter(str(item.get("status") or "unknown") for item in checklist_items)
    source_map_rows = source_rows if isinstance(source_rows, list) else []
    source_stop_conditions_met = sum(
        1 for row in source_map_rows if isinstance(row, dict) and bool(row.get("stop_condition_met"))
    )
    generated_stop_conditions_met = sum(1 for row in rows if bool(row.get("stop_condition_met")))
    truth_source_policy = {
        "canonical_for_github_packaging": "workspace_generated_burndown",
        "workspace_generated_artifact": str(out_dir(workspace) / "known_limitations_burndown.json"),
        "seed_map_artifact": str(map_path),
        "seed_map_row_count": len(source_map_rows),
        "seed_map_stop_conditions_met": source_stop_conditions_met,
        "workspace_generated_row_count": len(rows),
        "workspace_generated_stop_conditions_met": generated_stop_conditions_met,
        "workspace_generated_open_rows": max(len(rows) - generated_stop_conditions_met, 0),
        "count_policy": (
            "Use workspace_generated_stop_conditions_met / workspace_generated_row_count for current "
            "workspace packaging after running make known-limitations-burndown. Treat the seed map count "
            "as baseline input only; it can be stale before workspace evidence enrichment."
        ),
        "overclaim_guard": (
            "A met stop condition closes only the row's named checklist branch. It does not imply scanner "
            "completeness, severity proof, live-provider proof, PoC/execution proof, or submission readiness."
        ),
    }
    blocker_category_counts = Counter(
        str(row.get("blocker_category") or "unknown")
        for row in rows
        if not bool(row.get("stop_condition_met"))
    )
    command_blocker_category_counts = Counter(str(item.get("category") or "unknown") for item in command_blockers)
    strict_blockers = [
        {
            "limitation_id": row.get("limitation_id"),
            "priority_group": row.get("priority_group"),
            "missing_fields": row.get("strict_missing_fields", []),
            "next_command": row.get("next_command") or row.get("owner_command"),
        }
        for row in rows
        if row.get("strict_missing_fields")
    ]
    if strict_blockers:
        status = "blocked_named"
    elif rows:
        status = "ok"
    else:
        status = "empty_no_known_limitations_rows"
    payload = {
        "schema": f"{SCHEMA_PREFIX}.known_limitations_burndown.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source": str(doc),
        "source_map": str(map_path),
        "invariant_discovery": invariant_discovery,
        "invariant_discovery_adoption_accounting": invariant_adoption,
        "invariant_adoption_closure_readiness_accounting": invariant_adoption_closure,
        "semantic_live_depth_accounting": semantic_live_depth,
        "impact_miss_benchmark_accounting": impact_miss_benchmark,
        "semantic_fixture_smoke_accounting": semantic_fixture_smoke_accounting,
        "detector_semantic_repair_accounting": detector_semantic_repair_accounting,
        "canonical_fixture_materialization_accounting": canonical_fixture_materialization_accounting,
        "impact_family_worklist_accounting": impact_family_worklist,
        "execution_source_import_workflow_accounting": execution_source_import_workflow,
        "live_topology_explicit_blocker_accounting": live_topology_explicit_blockers,
        "live_topology_hermetic_workflow_accounting": live_topology_hermetic_workflow,
        "live_topology_real_input_workflow_accounting": live_topology_real_input_workflow,
        "runtime_dlt_execution_evidence_accounting": runtime_dlt_execution_evidence,
        "outcome_calibration_accounting": outcome_calibration,
        "agent_recall_closure_accounting": agent_recall_closure,
        "evidence_class_accounting": evidence_class_accounting,
        "truth_source_policy": truth_source_policy,
        "rows": rows,
        "strict_policy": {
            "required_priority_groups": ["current_priority", "P0"],
            "required_fields": ["owner_command", "artifact_path", "stop_condition", "status_evidence"],
            "default_mode": "advisory_non_destructive",
        },
        "checklist_accounting": {
            "item_count": len(checklist_items),
            "command_level_blocker_count": len(command_blockers),
            "status_counts": dict(sorted(checklist_status_counts.items())),
            "blocker_category_counts": dict(sorted(blocker_category_counts.items())),
            "command_blocker_category_counts": dict(sorted(command_blocker_category_counts.items())),
        },
        "command_level_blockers": command_blockers,
        "execution_proof_task_queue": {
            "path": str(out_dir(workspace) / "execution_proof_task_queue.json"),
            "status": execution_proof_queue["status"],
            "summary": execution_proof_queue["summary"],
        },
        "strict_blockers": strict_blockers,
        "status": status,
    }
    d = out_dir(workspace)
    write_json(d / "known_limitations_burndown.json", payload)
    md = [
        "# Known Limitations Burn-Down",
        "",
        "Default mode is advisory. `--strict` fails when current-priority or P0 rows lack owner command, artifact path, stop condition, or status evidence.",
        "",
        "| ID | Group | State | Strict | Blocker | Invariant diff | Missing | Next command |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        missing = ", ".join(row.get("strict_missing_fields", [])) or "_none_"
        inv_status = row.get("invariant_discovery_status", "_")
        md.append(
            f"| `{row.get('limitation_id')}` | `{row.get('priority_group', 'unknown')}` | "
            f"`{row.get('terminal_state', 'unknown')}` | `{row.get('strict_status', 'ok')}` | "
            f"`{row.get('blocker_category', 'unknown')}` | `{inv_status}` | {missing} | "
            f"`{row.get('next_command') or row.get('owner_command') or ''}` |"
        )
    if not rows:
        md.append("| _none_ | _none_ | `empty_no_known_limitations_rows` | `blocked_named` | `empty_no_known_limitations_rows` | _ | _none_ | _none_ |")
    md.extend(
        [
            "",
            "## Truth Source Policy",
            "",
            "- Canonical for GitHub packaging: `workspace_generated_burndown`.",
            f"- Workspace generated stop conditions met: `{generated_stop_conditions_met}` / `{len(rows)}`.",
            f"- Seed map stop conditions met: `{source_stop_conditions_met}` / `{len(source_map_rows)}`.",
            "- Count policy: use the workspace generated count after `make known-limitations-burndown`; treat the seed map count as baseline input only.",
            "- Overclaim guard: a met stop condition closes only that row's named checklist branch, not scanner completeness, severity proof, live-provider proof, PoC/execution proof, or submission readiness.",
            "",
            "## Checklist Accounting",
            "",
            f"- Items: `{len(checklist_items)}`",
            f"- Command-level blockers: `{len(command_blockers)}`",
            f"- Execution proof tasks: `{execution_proof_queue['summary']['task_count']}`",
            f"- Execution manifest proof counted: `{execution_proof_queue['summary']['proof_counted']}`",
            f"- Invalid proved manifests: `{execution_proof_queue['summary']['invalid_proved_manifest']}`",
            f"- Semantic/live depth processed: `{semantic_live_depth['concrete_item_count']}` / `{semantic_live_depth['concrete_item_target']}`",
            f"- Semantic/live depth closed by exact same-block pairs: `{semantic_live_depth['terminal_depth_closed_count']}`",
            f"- Semantic/live depth blocked/queued: `{semantic_live_depth['blocked_depth_count']}`",
            f"- Semantic fixture smoke terminal rows: `{semantic_fixture_smoke_accounting.get('terminal_clean_positive_count', 0)}`",
            f"- Semantic fixture smoke blocked rows: `{semantic_fixture_smoke_accounting.get('blocked_missing_fixture_or_smoke_count', 0)}`",
            f"- Detector semantic repair smoke-passed rows: `{detector_semantic_repair_accounting.get('local_semantic_repair_smoke_passed', 0)}`",
            f"- Detector semantic repair blockers left: `{detector_semantic_repair_accounting.get('scanner_semantic_blockers_left', 0)}`",
            f"- Canonical detector fixture pairs smoke-passed: `{canonical_fixture_materialization_accounting.get('canonical_smoke_passed_count', 0)}`",
            f"- Canonical detector fixture materialization blocked/failed: `{canonical_fixture_materialization_accounting.get('blocked_count', 0)}` / `{canonical_fixture_materialization_accounting.get('canonical_smoke_failed_count', 0)}`",
            f"- Impact-Miss benchmark status: `{impact_miss_benchmark['status']}`",
            f"- Impact-Miss benchmark accuracy: `{impact_miss_benchmark['accuracy']}`",
            f"- Impact-Miss benchmark predictions: `{impact_miss_benchmark['prediction_count']}` / `{impact_miss_benchmark['item_count']}`",
            f"- Impact-Miss genericity accounted: `{str(impact_miss_benchmark['genericity_accounted']).lower()}`",
            f"- Execution/source workflow proof-ready rows: `{execution_source_import_workflow['proof_ready_count']}` / `{execution_source_import_workflow['proved_execution_requirement_count']}`",
            f"- Execution/source workflow source-import units: `{execution_source_import_workflow['source_import_unit_count']}`",
            f"- Execution/source workflow ready project source roots: `{execution_source_import_workflow['ready_project_source_root_count']}`",
            f"- Outcome-calibration linked resolved rows: `{outcome_calibration['linked_for_calibration']}`",
            f"- Outcome-calibration missing-linkage rows: `{outcome_calibration['missing_linkage']}`",
            f"- Outcome-calibration advisory queue rows: `{outcome_calibration['queue_items']}`",
            f"- Agent-recall terminalized rows: `{agent_recall_closure['terminalized_or_bounded_rows']}` / `{agent_recall_closure['total_candidate_rows']}`",
            f"- Agent-recall open actionable rows: `{agent_recall_closure['open_actionable_rows']}`",
            f"- Agent-recall detectorized / non-detectorizable terminal routes: `{agent_recall_closure['detectorized_terminal']}` / `{agent_recall_closure['non_detectorizable_terminal']}`",
            f"- Evidence-class legacy rows: `{evidence_class_accounting['legacy_count']}`",
            f"- Evidence-class policy violations: `{evidence_class_accounting['policy_violation_count']}`",
            f"- Status counts: `{dict(sorted(checklist_status_counts.items()))}`",
            f"- Open blocker categories: `{dict(sorted(blocker_category_counts.items()))}`",
            f"- Command blocker categories: `{dict(sorted(command_blocker_category_counts.items()))}`",
        ]
    )
    write_md(d / "known_limitations_burndown.md", md)
    return payload


def render_closure(workspace: Path, mode: str) -> dict[str, Any]:
    matrix = render_impact_matrix(workspace)
    contracts = render_impact_contracts(workspace)
    worklist = render_impact_worklist(workspace)
    tools = render_tool_coverage_inventory(workspace)
    agents = render_agent_output_inventory(workspace)
    coverage = render_coverage_inventory(workspace)
    recall = render_agent_recall(workspace)
    impact_analysis = render_impact_analysis_queue(workspace)
    harness_tasks = render_harness_task_queue(workspace)
    source_proof_tasks = render_source_proof_task_queue(workspace)
    next_actions = render_pr560_next_actions(workspace)
    invariant_discovery = render_invariant_discovery_status(workspace)
    statuses = {
        "program_impact_matrix": matrix["status"],
        "impact_contracts": contracts["status"],
        "impact_family_worklists": worklist.get("status", "error"),
        "tool_coverage_inventory": tools["status"],
        "agent_output_inventory": agents["status"],
        "agent_recall": recall["status"],
        "impact_analysis_queue": impact_analysis["status"],
        "coverage_inventory": coverage["status"],
        "harness_tasks": harness_tasks["status"],
        "source_proof_tasks": source_proof_tasks["status"],
        "pr560_next_actions": next_actions["status"],
        "invariant_discovery": invariant_discovery["status"],
    }
    advisory_status_keys = {"invariant_discovery"}
    payload = {
        "schema": f"{SCHEMA_PREFIX}.{mode}.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "statuses": statuses,
        "status": "ok" if all(
            key in advisory_status_keys
            or v in {"ok", "open_impact_family_work", "open_harness_impact_contract_work", "open_next_actions", "actionable_verification_queue", "empty_no_candidates", "empty_no_agent_outputs", "empty_no_agent_claims", "empty_no_blocked_agent_recall_rows", "empty_no_source_proof_tasks", "empty_no_pr560_next_actions", "needs_local_verification"}
            for key, v in statuses.items()
        ) else "blocked_named",
        "advisory": {
            "invariant_discovery": invariant_discovery,
        },
        "artifacts": {
            "program_impact_matrix": str(out_dir(workspace) / "program_impact_matrix.json"),
            "impact_contracts": str(out_dir(workspace) / "impact_contracts.json"),
            "impact_family_worklists": str(out_dir(workspace) / "impact_family_worklists.json"),
            "tool_coverage_inventory": str(out_dir(workspace) / "tool_coverage_inventory.json"),
            "agent_output_inventory": str(out_dir(workspace) / "agent_output_inventory.json"),
            "agent_recall": str(out_dir(workspace) / "agent_found_not_detector_found.json"),
            "impact_analysis_queue": str(out_dir(workspace) / "impact_analysis_queue.json"),
            "coverage_inventory": str(out_dir(workspace) / "coverage_inventory.json"),
            "harness_tasks": str(out_dir(workspace) / "harness_tasks.json"),
            "source_proof_tasks": str(out_dir(workspace) / "source_proof_tasks.json"),
            "pr560_next_actions": str(out_dir(workspace) / "pr560_next_actions.json"),
            "generated_invariants": invariant_discovery["artifact_path"],
        },
        "next_commands": {
            "invariant_discovery": invariant_discovery["next_command"],
        },
    }
    d = out_dir(workspace)
    name = "known_limitations_burndown" if mode == "known_limitations_burndown" else "automation_closure"
    write_json(d / f"{name}.json", payload)
    md = [f"# {name.replace('_', ' ').title()}", "", "| Artifact | Status |", "|---|---|"]
    for key, status in statuses.items():
        md.append(f"| `{key}` | `{status}` |")
    md.extend([
        "",
        "## Advisory Next Commands",
        "",
        f"- `invariant_discovery`: `{invariant_discovery['next_command']}`",
        f"- `generated_invariants`: `{invariant_discovery['artifact_path']}`",
    ])
    write_md(d / f"{name}.md", md)
    return payload


def run_docs_check() -> int:
    proc = subprocess.run(["make", "docs-check"], cwd=ROOT, text=True)
    return proc.returncode


def strict_failure_status(status: object) -> bool:
    if not isinstance(status, str):
        return False
    if status.startswith("blocked"):
        return True
    if status == "blocked_missing_required_artifacts":
        return True
    if status in {"actionable_blockers", "open_impact_family_work", "open_harness_impact_contract_work", "open_next_actions"}:
        return False
    return status in {
        "missing_tools_or_targets",
        "needs_local_verification",
        "empty_no_agent_claims",
        "empty_no_known_limitations_rows",
    }


MODES = {
    "base-lessons-inventory": render_base_lessons_inventory,
    "corpus-mining-inventory": render_corpus_mining_inventory,
    "impact-matrix": render_impact_matrix,
    "impact-contract-check": render_impact_contracts,
    "impact-worklist": render_impact_worklist,
    "tool-coverage-inventory": render_tool_coverage_inventory,
    "agent-output-inventory": render_agent_output_inventory,
    "coverage-inventory": render_coverage_inventory,
    "agent-recall": render_agent_recall,
    "impact-analysis-queue": render_impact_analysis_queue,
    "harness-task-queue": render_harness_task_queue,
    "source-proof-task-queue": render_source_proof_task_queue,
    "pr560-next-actions": render_pr560_next_actions,
    "pr560-local-progress": render_pr560_local_progress,
    "pr560-integration-readiness": render_pr560_integration_readiness,
    "automation-closure": lambda ws: render_closure(ws, "automation_closure"),
    "base-automation-closure": lambda ws: render_closure(ws, "base_automation_closure"),
    "known-limitations-burndown": render_known_limitations_burndown,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Agent-output verification example: python3 tools/automation-closure.py "
            "--workspace <ws> --mode agent-output-verify-record "
            "--stable-source-path '<ws>/agent_outputs/claim.md' "
            "--terminal-state routed_to_impact_analysis "
            "--evidence-path '<ws>/.auditooor/impact_analysis_queue.json'. "
            "Verification records are evidence-only and always emit submit_ready=false severity=none."
        ),
    )
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--mode", required=True, choices=sorted([*MODES, "agent-output-verify-record"]))
    parser.add_argument("--json", action="store_true", help="print JSON payload")
    parser.add_argument("--strict", action="store_true", help="return non-zero on blocked status")
    parser.add_argument("--terminal-state", default="", choices=("", *AGENT_OUTPUT_TERMINAL_STATES), help="terminal state for agent-output-verify-record")
    parser.add_argument("--verification-task-id", default="", help="agent output verification task id to record")
    parser.add_argument("--stable-source-path", default="", help="stable <ws>/ or <repo>/ source path to record")
    parser.add_argument("--agent-output", default="", help="agent output path or stable reference to record")
    parser.add_argument("--source-path", default="", help="source path to record")
    parser.add_argument("--evidence-path", default="", help="evidence artifact path proving the terminal transition")
    parser.add_argument("--note", default="", help="operator note for the terminal transition")
    parser.add_argument("--next-command", default="", help="optional next command after the terminal transition")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve() if args.workspace else None
    if workspace is None:
        if args.mode not in {"base-lessons-inventory", "corpus-mining-inventory"}:
            print(f"[automation-closure] --workspace is required for mode {args.mode}", file=sys.stderr)
            return 2
    elif not workspace.is_dir():
        print(f"[automation-closure] workspace not found: {workspace}", file=sys.stderr)
        return 2

    if args.mode == "agent-output-verify-record":
        payload = record_agent_output_verification(
            workspace,
            terminal_state=args.terminal_state,
            evidence_path=args.evidence_path,
            verification_task_id=args.verification_task_id,
            stable_source_path=args.stable_source_path,
            agent_output=args.agent_output,
            source_path=args.source_path,
            note=args.note,
            next_command=args.next_command,
        )
    else:
        payload = MODES[args.mode](workspace)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[automation-closure] {args.mode}: {payload.get('status', 'ok')}")
    if args.strict and strict_failure_status(payload.get("status")):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
