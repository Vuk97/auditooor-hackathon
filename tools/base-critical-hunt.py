#!/usr/bin/env python3
# SCOPE-TIER: 5-step critical-candidate verifier (default-to-kill matrix + severity guard).
# NOT a duplicate of hunt-orchestrate.py (full-ws 10-step driver) or critical-hunt.py
# (lightweight advisory dossier emitter) - each covers a distinct tier.
"""Base critical-hunt orchestrator (PR #544 Lane H, Phase 1).

Runs the five required checks in sequence:

  1. base-critical-candidate-matrix       (default-to-kill matrix)
  2. severity-claim-guard                 (exact-impact proof guard)
  3. invariant-ledger --check             (advisory; --init if missing)
  4. program-impact-mapping-check          (advisory rubric grounding)
  5. audit-closeout-check                 (advisory unless ``--strict``)
  5b. base-consensus-patch-scan           (advisory; mined Base patch signals)
  6. candidate queue summary              (Markdown printed to stdout)
  7. coverage inventory                   (impact-family + recall surface)

Each step is captured into ``<ws>/critical_hunt/hunt_run.json`` so a
follow-up agent can replay outcomes. The orchestrator never invents
status: every step records the actual exit code of the underlying tool.

Default semantics:
  * Step 1 enforces default-to-kill regardless of ``--strict``.
  * Step 2 is a hard gate: no Critical/direct-ready over-claims.
  * Steps 3-5 are advisory unless ``--strict`` is passed; in that mode
    a non-zero exit from any step propagates.
  * Step 6 is informational only.

Stdlib-only. Idempotent. Offline-safe.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
SEVERITY_FILES = (
    "SEVERITY.md",
    "SEVERITY_SMART_CONTRACTS.md",
    "SEVERITY_BLOCKCHAIN_DLT.md",
    "RUBRIC_COVERAGE.md",
)
SCAN_ARTIFACT_CANDIDATES = (
    "scanners/rust/SCAN_RUST_SUMMARY.json",
    "scanners/rust/SCAN_RUST_SUMMARY.md",
    "audit/rust-scan/summary.md",
    "audit/scan/summary.md",
    "scan_results.json",
)
GRAPH_ARTIFACT_CANDIDATES = (
    ".auditooor/semantic_graph.json",
    ".auditooor/semantic_graph.md",
    "deployment_topology.json",
    "deployment_topology.md",
    "live_topology_checks.json",
    "LIVE_TOPOLOGY.md",
)
SNAPPY_ARTIFACT_CANDIDATES = (
    "critical_hunt/wave5_candidate_status.json",
    "critical_hunt/wave7_snappy_critical_variant/results.json",
    "critical_hunt/node_resource_wave5/snappy_oom_poc/results.md",
    "critical_hunt/node_resource_wave5/snappy_oom_poc/IMMUNEFI_PRECLEAR.md",
)
AGENT_HINT_RE = re.compile(
    r"\b(agent|claude|kimi|minimax|codex|source[- ]reader|source[- ]reading|llm)\b",
    re.IGNORECASE,
)
DETECTOR_HINT_RE = re.compile(
    r"\b(detector|scanner|semgrep|slither|cargo audit|scan[-_ ]rust|rust[-_ ]scan)\b",
    re.IGNORECASE,
)
SNAPPY_RE = re.compile(
    r"\b(snappy|decompress_vec|gossip decode|decode[- ]bomb)\b",
    re.IGNORECASE,
)
MEMPOOL_RE = re.compile(r"\bmempool\b", re.IGNORECASE)


def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def step_matrix(workspace: Path, strict: bool) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(TOOLS / "base-critical-candidate-matrix.py"),
        "--workspace",
        str(workspace),
    ]
    if strict:
        cmd.append("--strict")
    rc, out, err = _run(cmd)
    return {
        "step": "candidate_matrix",
        "rc": rc,
        "stdout": out,
        "stderr": err,
    }


def step_severity_claim_guard(workspace: Path) -> dict[str, Any]:
    rc, out, err = _run(
        [
            sys.executable,
            str(TOOLS / "severity-claim-guard.py"),
            "--workspace",
            str(workspace),
        ]
    )
    return {
        "step": "severity_claim_guard",
        "rc": rc,
        "stdout": out,
        "stderr": err,
    }


def step_invariant_ledger(workspace: Path) -> dict[str, Any]:
    ledger_json = workspace / ".auditooor" / "invariant_ledger.json"
    if not ledger_json.is_file():
        # Initialise so --check has something to look at; advisory in any case.
        _run(
            [
                sys.executable,
                str(TOOLS / "invariant-ledger.py"),
                "--workspace",
                str(workspace),
                "--init",
            ]
        )
    rc, out, err = _run(
        [
            sys.executable,
            str(TOOLS / "invariant-ledger.py"),
            "--workspace",
            str(workspace),
            "--check",
        ]
    )
    return {
        "step": "invariant_ledger_check",
        "rc": rc,
        "stdout": out,
        "stderr": err,
    }


def step_program_impact(workspace: Path) -> dict[str, Any]:
    rc, out, err = _run(
        [
            sys.executable,
            str(TOOLS / "program-impact-mapping-check.py"),
            "--workspace",
            str(workspace),
            "--allow-no-rubric",
        ]
    )
    return {
        "step": "program_impact_mapping_check",
        "rc": rc,
        "stdout": out,
        "stderr": err,
    }


def step_audit_closeout(workspace: Path) -> dict[str, Any]:
    rc, out, err = _run(
        [
            sys.executable,
            str(TOOLS / "audit-closeout-check.py"),
            "--workspace",
            str(workspace),
        ]
    )
    return {
        "step": "audit_closeout",
        "rc": rc,
        "stdout": out,
        "stderr": err,
    }


def step_consensus_patch_scan(workspace: Path) -> dict[str, Any]:
    """Advisory: run the Base consensus patch-regression scanner.

    Surfaces mined Base patch signals (e.g. ``0bbd206a`` deposits-only
    classifier) as regression candidates. Rows are advisory evidence, never
    submission-ready findings, so this step is never hard-gated: it is run
    WITHOUT ``--strict`` so emitted rows do not abort the orchestrator. The
    scanner's actual exit code is recorded for replay.
    """
    rc, out, err = _run(
        [
            sys.executable,
            str(TOOLS / "base-consensus-patch-scan.py"),
            "--workspace",
            str(workspace),
        ]
    )
    return {
        "step": "consensus_patch_scan",
        "rc": rc,
        "stdout": out,
        "stderr": err,
    }


def step_queue_summary(workspace: Path) -> dict[str, Any]:
    matrix_json = (
        workspace / "critical_hunt" / "base_critical_candidate_matrix.json"
    )
    if not matrix_json.is_file():
        return {
            "step": "queue_summary",
            "rc": 2,
            "stdout": "",
            "stderr": f"matrix JSON missing: {matrix_json}",
        }
    payload = json.loads(matrix_json.read_text(encoding="utf-8"))
    rows = payload.get("rows", []) or []
    by_status: dict[str, list[str]] = {}
    for row in rows:
        by_status.setdefault(row.get("candidate_status", "unknown"), []).append(
            row.get("candidate_id", "?")
        )
    lines = ["## Candidate Queue Summary", ""]
    if not rows:
        lines.append("_No candidates._")
    else:
        for status, ids in sorted(by_status.items()):
            lines.append(f"### {status} ({len(ids)})")
            for cid in ids:
                lines.append(f"- `{cid}`")
            lines.append("")
    summary = "\n".join(lines) + "\n"
    queue_path = workspace / "critical_hunt" / "queue_summary.md"
    queue_path.write_text(summary, encoding="utf-8")
    return {
        "step": "queue_summary",
        "rc": 0,
        "stdout": summary,
        "stderr": "",
    }


def _load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_matrix(workspace: Path) -> dict[str, Any]:
    path = workspace / "critical_hunt" / "base_critical_candidate_matrix.json"
    data = _load_json(path)
    return data if isinstance(data, dict) else {}


def _load_raw_candidates(workspace: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    cand_dir = workspace / "critical_hunt" / "candidates"
    if cand_dir.is_dir():
        for path in sorted(cand_dir.glob("*.json")):
            data = _load_json(path)
            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                cid = str(
                    entry.get("candidate_id")
                    or entry.get("id")
                    or entry.get("title")
                    or path.stem
                )
                entry = dict(entry)
                entry.setdefault("_source_path", _rel(workspace, path))
                out[cid] = entry
    aggregate = workspace / "critical_hunt" / "candidates.json"
    data = _load_json(aggregate) if aggregate.is_file() else None
    if isinstance(data, dict) and isinstance(data.get("candidates"), list):
        for entry in data["candidates"]:
            if not isinstance(entry, dict):
                continue
            cid = str(entry.get("candidate_id") or entry.get("id") or entry.get("title") or "")
            if not cid:
                continue
            entry = dict(entry)
            entry.setdefault("_source_path", _rel(workspace, aggregate))
            out.setdefault(cid, entry)
    return out


def _existing_artifacts(workspace: Path, candidates: tuple[str, ...]) -> list[str]:
    return [_rel(workspace, workspace / rel) for rel in candidates if (workspace / rel).exists()]


def _scope_sources(workspace: Path) -> list[str]:
    candidates = (*SEVERITY_FILES, "SCOPE.md", "INTAKE_BASELINE.json")
    return _existing_artifacts(workspace, candidates)


def _assets_in_scope(workspace: Path, rows: list[dict[str, Any]]) -> list[str]:
    baseline = _load_json(workspace / "INTAKE_BASELINE.json")
    assets = []
    if isinstance(baseline, dict) and isinstance(baseline.get("assets_in_scope"), list):
        assets.extend(str(a) for a in baseline["assets_in_scope"] if str(a).strip())
    for row in rows:
        asset = str(row.get("scope_asset") or "").strip()
        if asset:
            assets.append(asset)
    seen: set[str] = set()
    out: list[str] = []
    for asset in assets:
        key = asset.lower()
        if key not in seen:
            seen.add(key)
            out.append(asset)
    return out


def _impact_family(impact: str) -> str:
    text = impact.lower()
    if "snappy" in text or "resource consumption" in text or "resource" in text:
        return "node_resource_consumption"
    if "shutdown" in text or "offline" in text:
        return "node_shutdown"
    if "freeze" in text:
        return "funds_freeze"
    if "theft" in text or "steal" in text or "drain" in text:
        return "funds_theft"
    if "mempool" in text:
        return "mempool"
    return re.sub(r"[^a-z0-9]+", "_", impact.lower()).strip("_")[:48] or "unmapped"


# Canonical impact family names derived by semantic-graph.py (impact_family_for_path).
# Used to detect when _impact_family() returned a truncated/generic fallback string.
_CANONICAL_GRAPH_FAMILIES: frozenset[str] = frozenset({
    "bridge_finalization",
    "proof_dispute",
    "proof_finalization",
    "state_root_validation",
    "validation_path",
    "cache_provider_path",
    "source_multihop",
    "node_resource_consumption",
    "node_shutdown",
    "funds_freeze",
    "funds_theft",
    "mempool",
})


def _is_canonical_family(family: str) -> bool:
    """Return True when _impact_family() returned a known canonical value."""
    return family in _CANONICAL_GRAPH_FAMILIES


def _family_keyword_overlap(impact_text: str, graph_family: str) -> int:
    """Count how many words in graph_family appear in impact_text."""
    words = re.split(r"[_\s]+", graph_family.lower())
    text = impact_text.lower()
    return sum(1 for w in words if w and w in text)


def _resolve_impact_family(
    impact: str,
    graph_paths: list[dict[str, Any]],
) -> str:
    """Return the best impact family for *impact* prose.

    Uses _impact_family() first. If that returns a non-canonical truncated
    fallback, checks whether any graph-derived multi-hop path carries a
    canonical family whose keywords overlap with the prose, and returns
    that graph family instead.
    """
    family = _impact_family(impact)
    if _is_canonical_family(family):
        return family
    # Fallback: the truncated re.sub branch fired. Look for a graph path whose
    # canonical impact_family keyword-overlaps with the prose.
    best_family = family
    best_score = 0
    for path in graph_paths:
        gfamily = str(path.get("impact_family") or "")
        if not gfamily or not _is_canonical_family(gfamily):
            continue
        score = _family_keyword_overlap(impact, gfamily)
        if score > best_score:
            best_score = score
            best_family = gfamily
    return best_family


def _row_impacts(row: dict[str, Any]) -> set[str]:
    return {
        str(value).strip().lower()
        for value in (
            row.get("listed_impact_selected"),
            row.get("impact_mapping"),
        )
        if str(value).strip()
    }


def _load_semantic_graph_paths(workspace: Path) -> list[dict[str, Any]]:
    """Load multi_hop_paths from .auditooor/semantic_graph.json if present.

    Maps the graph-path schema (as emitted by semantic-graph.py) to the
    inventory multi-hop-path schema expected by _impact_family_worklists(),
    preserving path_id, impact_family, evidence_edges, and mapped_stages
    faithfully.
    """
    graph_json = workspace / ".auditooor" / "semantic_graph.json"
    if not graph_json.is_file():
        return []
    data = _load_json(graph_json)
    if not isinstance(data, dict):
        return []
    raw_paths = data.get("multi_hop_paths")
    if not isinstance(raw_paths, list):
        return []
    out: list[dict[str, Any]] = []
    for path in raw_paths:
        if not isinstance(path, dict):
            continue
        out.append(
            {
                "path_id": str(path.get("path_id") or f"SG-MH-{len(out) + 1:03d}"),
                "source": "semantic_graph",
                "candidate_id": path.get("candidate_id") or "",
                "impact_family": str(path.get("impact_family") or "source_multihop"),
                "source_component": str(path.get("source_component") or ""),
                "sink_component": str(path.get("sink_component") or ""),
                "path_summary": str(path.get("path_summary") or ""),
                "evidence_edges": list(path.get("evidence_edges") or []),
                "mapped_stages": list(path.get("mapped_stages") or []),
                "missing_stages": list(path.get("missing_stages") or []),
                "scanner_coverage": str(path.get("scanner_coverage") or "not_measured"),
                "source_reader_coverage": str(
                    path.get("source_reader_coverage") or "mapped_by_semantic_graph"
                ),
                "impact_contract_id": str(path.get("impact_contract_id") or ""),
                "next_action": str(
                    path.get("next_action")
                    or "route semantic path to exact-impact candidate or mark non-detectorizable"
                ),
            }
        )
    return out


def _extract_multi_hop_paths(rows: list[dict[str, Any]], scan_artifacts: list[str]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        text = " ".join(
            str(row.get(key) or "")
            for key in (
                "production_path",
                "required_proof",
                "scope_asset",
                "impact_mapping",
                "listed_impact_selected",
            )
        )
        if not re.search(r"(?:->|=>|multi[- ]hop|cross[- ]component|gossip|bridge|finali[sz]ation|proof|state root)", text, re.IGNORECASE):
            continue
        parts = [p.strip() for p in re.split(r"->|=>", str(row.get("production_path") or "")) if p.strip()]
        source = parts[0] if parts else str(row.get("scope_asset") or "unknown")
        sink = parts[-1] if len(parts) > 1 else str(row.get("impact_mapping") or "unknown")
        paths.append(
            {
                "path_id": f"MH-{idx:03d}",
                "candidate_id": row.get("candidate_id"),
                "impact_family": _impact_family(str(row.get("listed_impact_selected") or row.get("impact_mapping") or "")),
                "source_component": source,
                "sink_component": sink,
                "path_summary": text.strip() or "candidate row references a cross-component behavior",
                "evidence_edges": row.get("artifact_refs") or [],
                "scanner_coverage": "covered" if scan_artifacts else "not_observed",
                "source_reader_coverage": "covered" if any(AGENT_HINT_RE.search(str(ref)) for ref in row.get("artifact_refs") or []) else "not_observed",
                "impact_contract_id": row.get("candidate_id") if row.get("listed_impact_proven") else "",
                "next_action": "execute_or_package" if row.get("candidate_status") == "executable" else "route_to_invariant_harness_or_reframe",
            }
        )
    return paths


def _has_detector_hit(raw: dict[str, Any], row: dict[str, Any]) -> bool:
    for key in ("detector_hits", "scanner_hits", "scan_hits", "detectors"):
        value = raw.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, str) and value.strip():
            return True
    blob = json.dumps(raw, ensure_ascii=False) + " " + json.dumps(row, ensure_ascii=False)
    return bool(DETECTOR_HINT_RE.search(blob))


def _agent_found_not_detector_found(
    rows: list[dict[str, Any]],
    raw_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        cid = str(row.get("candidate_id") or "")
        raw = raw_by_id.get(cid, {})
        blob = json.dumps(raw, ensure_ascii=False) + " " + json.dumps(row, ensure_ascii=False)
        if not AGENT_HINT_RE.search(blob):
            continue
        if _has_detector_hit(raw, row):
            continue
        out.append(
            {
                "behavior_id": cid or f"agent-gap-{len(out) + 1}",
                "source_index": raw.get("_source_path") or "",
                "candidate_id": cid,
                "impact_family": _impact_family(str(row.get("listed_impact_selected") or row.get("impact_mapping") or "")),
                "detector_status": "not_found",
                "durable_route": raw.get("durable_route") or raw.get("router") or "detector_gap_or_source_review",
                "artifact_refs": row.get("artifact_refs") or [],
            }
        )
    return out


def _snappy_artifact_rows(workspace: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    wave5 = workspace / "critical_hunt" / "wave5_candidate_status.json"
    data = _load_json(wave5)
    if isinstance(data, dict) and isinstance(data.get("candidates"), list):
        for item in data["candidates"]:
            if not isinstance(item, dict):
                continue
            blob = json.dumps(item, ensure_ascii=False)
            if not SNAPPY_RE.search(blob):
                continue
            out.append(
                {
                    "candidate_id": item.get("id") or item.get("candidate_id"),
                    "selected_impact": item.get("impact_class_verbatim") or "",
                    "listed_impact_proven": False,
                    "candidate_status": item.get("verdict") or "not_submit_ready",
                    "node_resource_consumption_pct": None,
                    "shutdown_nodes_pct": None,
                    "realistic_non_bruteforce": False,
                    "network_level_evidence": _rel(workspace, wave5),
                    "component_poc_only": True,
                    "mempool_claimed": bool(MEMPOOL_RE.search(blob)),
                    "verdict": "NOT_SUBMIT_READY/kill_or_reframe",
                    "notes": [str(item.get("evidence") or "").strip()],
                    "artifact_refs": [
                        _rel(workspace, Path(ref))
                        for ref in item.get("files", [])
                        if isinstance(ref, str)
                    ],
                }
            )
    wave7 = workspace / "critical_hunt" / "wave7_snappy_critical_variant" / "results.json"
    data = _load_json(wave7)
    if isinstance(data, dict) and SNAPPY_RE.search(json.dumps(data, ensure_ascii=False)):
        measurement = data.get("measurement") if isinstance(data.get("measurement"), dict) else {}
        gates = data.get("gates") if isinstance(data.get("gates"), dict) else {}
        halt_gate = gates.get("network_level_confirm_halt") if isinstance(gates.get("network_level_confirm_halt"), dict) else {}
        resource_pct = None
        evidence = str(halt_gate.get("evidence") or data.get("summary") or "")
        pct_match = re.search(r"\bratio\s+([0-9]+(?:\.[0-9]+)?)%", evidence)
        if pct_match:
            resource_pct = float(pct_match.group(1))
        files = data.get("files") if isinstance(data.get("files"), dict) else {}
        out.append(
            {
                "candidate_id": "wave7-snappy-critical-variant",
                "selected_impact": "",
                "listed_impact_proven": False,
                "candidate_status": data.get("verdict") or "killed_no_amplification",
                "node_resource_consumption_pct": resource_pct,
                "shutdown_nodes_pct": None,
                "realistic_non_bruteforce": True,
                "network_level_evidence": _rel(workspace, wave7),
                "component_poc_only": False,
                "mempool_claimed": False,
                "verdict": "NOT_SUBMIT_READY/kill_or_reframe",
                "notes": [
                    str(data.get("summary") or "").strip(),
                    f"rss_delta_bytes={measurement.get('rss_delta_bytes')}",
                ],
                "artifact_refs": [
                    _rel(workspace, Path(ref))
                    for ref in files.values()
                    if isinstance(ref, str)
                ],
            }
        )
    if out:
        return out
    for rel in SNAPPY_ARTIFACT_CANDIDATES:
        path = workspace / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if not SNAPPY_RE.search(text):
            continue
        out.append(
            {
                "candidate_id": path.stem,
                "selected_impact": "",
                "listed_impact_proven": False,
                "candidate_status": "artifact_only",
                "node_resource_consumption_pct": None,
                "shutdown_nodes_pct": None,
                "realistic_non_bruteforce": False,
                "network_level_evidence": _rel(workspace, path),
                "component_poc_only": True,
                "mempool_claimed": bool(MEMPOOL_RE.search(text)),
                "verdict": "NOT_SUBMIT_READY/kill_or_reframe",
                "notes": ["Snappy artifact exists but no exact listed impact proof row was found."],
                "artifact_refs": [_rel(workspace, path)],
            }
        )
    return out


def _snappy_exact_impact_state(workspace: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    snappy_rows = [
        row
        for row in rows
        if SNAPPY_RE.search(json.dumps(row, ensure_ascii=False))
    ]
    states: list[dict[str, Any]] = []
    any_exact = False
    for row in snappy_rows:
        resource_pct = row.get("node_resource_consumption_pct")
        shutdown_pct = row.get("shutdown_nodes_pct")
        resource_ok = isinstance(resource_pct, (int, float)) and resource_pct >= 30
        shutdown_ok = isinstance(shutdown_pct, (int, float)) and shutdown_pct >= 30
        exact = (
            row.get("candidate_status") == "executable"
            and row.get("listed_impact_proven") is True
            and row.get("exact_impact_sentence_selected") is True
            and row.get("component_poc_only") is False
            and str(row.get("network_level_evidence") or "absent") != "absent"
            and bool(row.get("realistic_non_bruteforce"))
            and (resource_ok or shutdown_ok)
        )
        any_exact = any_exact or exact
        notes = row.get("notes") or []
        mempool_claimed = bool(MEMPOOL_RE.search(json.dumps(row, ensure_ascii=False)))
        states.append(
            {
                "candidate_id": row.get("candidate_id"),
                "selected_impact": row.get("listed_impact_selected") or "",
                "listed_impact_proven": bool(row.get("listed_impact_proven")),
                "candidate_status": row.get("candidate_status"),
                "node_resource_consumption_pct": resource_pct,
                "shutdown_nodes_pct": shutdown_pct,
                "realistic_non_bruteforce": bool(row.get("realistic_non_bruteforce")),
                "network_level_evidence": row.get("network_level_evidence") or "absent",
                "component_poc_only": bool(row.get("component_poc_only")),
                "mempool_claimed": mempool_claimed,
                "verdict": "exact_impact_proven" if exact else "NOT_SUBMIT_READY/kill_or_reframe",
                "notes": notes,
            }
        )
    states.extend(_snappy_artifact_rows(workspace))
    if not states:
        return {
            "state": "not_present",
            "mempool_impact_applicable": False,
            "rows": [],
        }
    return {
        "state": "exact_impact_proven" if any_exact else "NOT_SUBMIT_READY/kill_or_reframe",
        "mempool_impact_applicable": False,
        "rows": states,
    }


def _impact_family_worklists(
    listed_impacts: list[str],
    rows: list[dict[str, Any]],
    multi_hop_paths: list[dict[str, Any]],
    scan_artifacts: list[str],
    graph_artifacts: list[str],
    graph_paths: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    worklists: list[dict[str, Any]] = []
    uncovered: list[str] = []
    blocked: list[dict[str, Any]] = []
    _graph_paths: list[dict[str, Any]] = graph_paths if graph_paths is not None else []
    for impact in listed_impacts:
        impact_key = impact.strip().lower()
        family = _resolve_impact_family(impact, _graph_paths)
        matched_rows = [row for row in rows if impact_key in _row_impacts(row)]
        row_ids = [str(row.get("candidate_id") or "") for row in matched_rows]
        matching_paths = [path for path in multi_hop_paths if path["impact_family"] == family]
        executable = any(row.get("candidate_status") == "executable" for row in matched_rows)
        if executable:
            status = "PASS"
        elif matched_rows or matching_paths:
            status = "WARN"
        else:
            status = "FAIL"
            uncovered.append(impact)
        if matched_rows and not executable:
            blocked.append(
                {
                    "impact": impact,
                    "impact_family": family,
                    "candidate_ids": row_ids,
                    "reason": "candidate rows exist but no executable exact-impact proof",
                }
            )
        worklists.append(
            {
                "impact": impact,
                "impact_family": family,
                "status": status,
                "scanner_coverage": "present" if scan_artifacts else "missing",
                "graph_coverage": "present" if graph_artifacts else "missing",
                "source_reader_coverage": "present"
                if any(AGENT_HINT_RE.search(json.dumps(row, ensure_ascii=False)) for row in matched_rows)
                else "not_observed",
                "invariant_coverage": "present"
                if any("invariant" in json.dumps(row, ensure_ascii=False).lower() for row in matched_rows)
                else "not_observed",
                "harness_coverage": "present"
                if any(row.get("has_execution_manifest") for row in matched_rows)
                else "missing",
                "candidate_ids": row_ids,
                "multi_hop_path_ids": [path["path_id"] for path in matching_paths],
                "next_action": "package_or_regression"
                if executable
                else "add exact-impact harness/invariant/source-proof route",
            }
        )
    return worklists, uncovered, blocked


def render_coverage_markdown(payload: dict[str, Any]) -> str:
    lines = ["# Coverage Inventory", "", f"_Schema: `{payload['schema']}`_", ""]
    lines.append("## Impact Family Status")
    lines.append("")
    if payload["impact_family_worklists"]:
        lines.append("| impact_family | status | candidates | multi_hop_paths | next_action |")
        lines.append("|---|---|---|---|---|")
        for row in payload["impact_family_worklists"]:
            lines.append(
                "| {family} | `{status}` | {candidates} | {paths} | {next_action} |".format(
                    family=row["impact_family"],
                    status=row["status"],
                    candidates=", ".join(row["candidate_ids"]) or "_none_",
                    paths=", ".join(row["multi_hop_path_ids"]) or "_none_",
                    next_action=row["next_action"],
                )
            )
    else:
        lines.append("_No listed impacts found; coverage is incomplete until severity files are populated._")
    lines.append("")
    lines.append("## Agent Found, Not Detector Found")
    lines.append("")
    gaps = payload["agent_found_not_detector_found"]
    if gaps:
        lines.append("| behavior_id | impact_family | durable_route | artifact_refs |")
        lines.append("|---|---|---|---|")
        for gap in gaps:
            lines.append(
                "| `{}` | {} | {} | {} |".format(
                    gap["behavior_id"],
                    gap["impact_family"],
                    gap["durable_route"],
                    ", ".join(gap["artifact_refs"]) or "_none_",
                )
            )
    else:
        lines.append("_No agent-found/not-detector-found rows observed in existing candidate data._")
    lines.append("")
    lines.append("## Snappy Exact-Impact State")
    lines.append("")
    snappy = payload["snappy_exact_impact_state"]
    lines.append(f"- state: `{snappy['state']}`")
    lines.append("- mempool_impact_applicable: `false`")
    for row in snappy.get("rows", []):
        lines.append(
            "- `{}`: {} (resource_pct={}, shutdown_pct={}, realistic_non_bruteforce={})".format(
                row["candidate_id"],
                row["verdict"],
                row["node_resource_consumption_pct"],
                row["shutdown_nodes_pct"],
                row["realistic_non_bruteforce"],
            )
        )
    lines.append("")
    lines.append("## Blockers")
    lines.append("")
    if payload["blocked_named"]:
        for blocker in payload["blocked_named"]:
            lines.append(f"- {blocker['impact_family']}: {blocker['reason']}")
    else:
        lines.append("- _none_")
    lines.append("")
    lines.append("## Next Commands")
    lines.append("")
    for cmd in payload["next_commands"]:
        lines.append(f"- `{cmd}`")
    return "\n".join(lines) + "\n"


def build_coverage_inventory(workspace: Path) -> dict[str, Any]:
    matrix = _load_matrix(workspace)
    rows = matrix.get("rows") if isinstance(matrix.get("rows"), list) else []
    listed_impacts = matrix.get("listed_critical_impacts")
    if not isinstance(listed_impacts, list):
        listed_impacts = []
    raw_by_id = _load_raw_candidates(workspace)
    scan_artifacts = _existing_artifacts(workspace, SCAN_ARTIFACT_CANDIDATES)
    graph_artifacts = _existing_artifacts(workspace, GRAPH_ARTIFACT_CANDIDATES)
    # Paths derived from the candidate matrix rows.
    matrix_multi_hop_paths = _extract_multi_hop_paths(rows, scan_artifacts)
    # Paths derived from the semantic graph artifact (if present); these carry
    # canonical impact_family values that the matrix rows may lack.
    graph_multi_hop_paths = _load_semantic_graph_paths(workspace)
    # Merge: matrix paths first, then graph paths not already present by path_id.
    seen_path_ids: set[str] = {p["path_id"] for p in matrix_multi_hop_paths}
    for gp in graph_multi_hop_paths:
        if gp["path_id"] not in seen_path_ids:
            matrix_multi_hop_paths.append(gp)
            seen_path_ids.add(gp["path_id"])
    multi_hop_paths = matrix_multi_hop_paths
    worklists, uncovered, blocked = _impact_family_worklists(
        [str(item) for item in listed_impacts],
        rows,
        multi_hop_paths,
        scan_artifacts,
        graph_artifacts,
        graph_paths=graph_multi_hop_paths,
    )
    agent_gaps = _agent_found_not_detector_found(rows, raw_by_id)
    detector_recall = {
        "agent_found_total": len(agent_gaps),
        "agent_found_detector_missed": len(agent_gaps),
        "candidate_rows_total": len(rows),
        "recall_status": "gaps_observed" if agent_gaps else "no_agent_gap_rows_observed",
    }
    return {
        "schema": "auditooor.coverage_inventory.v1",
        "workspace": str(workspace),
        "scope_sources": _scope_sources(workspace),
        "assets_in_scope": _assets_in_scope(workspace, rows),
        "listed_impacts": [str(item) for item in listed_impacts],
        "scanned_roots": scan_artifacts,
        "scan_artifacts": scan_artifacts,
        "graph_artifacts": graph_artifacts,
        "multi_hop_paths": multi_hop_paths,
        "impact_family_worklists": worklists,
        "candidate_rows": rows,
        "agent_found_not_detector_found": agent_gaps,
        "detector_recall": detector_recall,
        "uncovered_impact_families": uncovered,
        "blocked_named": blocked,
        "snappy_exact_impact_state": _snappy_exact_impact_state(workspace, rows),
        "next_commands": [
            "python3 tools/base-critical-candidate-matrix.py --workspace <workspace>",
            "python3 tools/base-critical-hunt.py --workspace <workspace>",
            "python3 tools/severity-claim-guard.py --workspace <workspace>",
        ],
    }


def step_coverage_inventory(workspace: Path) -> dict[str, Any]:
    try:
        payload = build_coverage_inventory(workspace)
        out_dir = workspace / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "coverage_inventory.json"
        md_path = out_dir / "coverage_inventory.md"
        json_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        md_path.write_text(render_coverage_markdown(payload), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - defensive capture for run logs.
        return {
            "step": "coverage_inventory",
            "rc": 1,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
        }
    return {
        "step": "coverage_inventory",
        "rc": 0,
        "stdout": f"wrote {_rel(workspace, json_path)} and {_rel(workspace, md_path)}\n",
        "stderr": "",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="base-critical-hunt.py",
        description=(
            "Run the full Base critical-hunt orchestrator: candidate matrix, "
            "severity-claim guard, invariant-ledger check, "
            "program-impact-mapping check, audit-closeout, "
            "consensus patch-scan (advisory), queue summary, "
            "coverage inventory."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Propagate non-zero exits from advisory steps 3-5. Steps 1 "
            "(matrix) and 2 (severity guard) are always enforced."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[base-critical-hunt] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    results: list[dict[str, Any]] = []
    results.append(step_matrix(workspace, args.strict))
    results.append(step_severity_claim_guard(workspace))
    results.append(step_invariant_ledger(workspace))
    results.append(step_program_impact(workspace))
    results.append(step_audit_closeout(workspace))
    results.append(step_consensus_patch_scan(workspace))
    results.append(step_queue_summary(workspace))
    results.append(step_coverage_inventory(workspace))

    out_dir = workspace / "critical_hunt"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hunt_run.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.base_critical_hunt_run.v1",
                "workspace": str(workspace),
                "strict": args.strict,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Emit a one-line per step summary on stdout.
    print("[base-critical-hunt] step results:")
    for r in results:
        print(f"  - {r['step']}: rc={r['rc']}")
    print(
        f"[base-critical-hunt] wrote {(out_dir / 'hunt_run.json').relative_to(workspace)}"
    )

    # Step 1 (matrix) is always hard-enforced.
    if results[0]["rc"] != 0:
        return results[0]["rc"]
    # Step 2 is a hard exact-impact guard; rc=2 means the matrix was not
    # readable, which should not happen after step 1 succeeded.
    if results[1]["rc"] != 0:
        return results[1]["rc"]

    if args.strict:
        for r in results[2:5]:
            if r["rc"] not in (0, 2):  # rc=2 is conventional WARN in this repo
                return r["rc"]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
