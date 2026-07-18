#!/usr/bin/env python3
# <!-- r36-rebuttal: CHAIN-LIFT lane; file declared in .auditooor/agent_pathspec.json -->
"""chain-synth-driver.py - thin driver for novel multi-step chain synthesis.

CHAIN-LIFT (2026-05-28) - wires existing tools into a single pipeline:
  1. Read workspace exploit_queue.json + mined CCIA angles to collect
     broken_invariant_ids.
  2. Call vault_global_chain_template_match to find matching chain templates.
  3. Feed matches to deepseek-batch-gen-tok-chain-exploit.py to build a
     DeepSeek batch JSONL.
  4. Dispatch each task via tools/llm-dispatch.py --provider mimo and write
     chain-synthesis report to <workspace>/.auditooor/chain_synthesis_<date>.json.

Reuses existing tools; does NOT rebuild any framework.

PR8a PROOF-SEEKING (2026-05-30)
-------------------------------
Chain synthesis is no longer narrative-only. Each chain template is decomposed
into HOPS (one hop per member/matched invariant). Every hop must cite:
  - the broken cross-contract invariant id (INV-*), AND
  - evidence: a file:line citation OR a proof-obligation id, drawn from the
    workspace's exploit-queue entries / CCIA angles / invariant index.

A chain only ADVANCES (gets dispatched to the LLM) if EVERY hop has evidence
and the template has source-backed composition linkage. Chains with one or
more evidence-less hops, or no linkage between otherwise evidenced hops, are
NOT dispatched; they are reported with status="blocked-missing-hop-evidence".

Composing chains (advanced chains) enqueue a SINGLE multi-hop proof obligation
into <workspace>/.auditooor/chain_proof_obligations.json so the downstream
prove-top-leads / exploit-conversion loop can pick them up as one unit.

CLI
---
python3 tools/chain-synth-driver.py --workspace <ws> [--dry-run] [--json]
                                    [--require-hop-evidence | --no-require-hop-evidence]

Env
---
  MIMO_API_KEY, MIMO_BASE_URL, AUDITOOOR_LLM_NETWORK_CONSENT=1

Schema emitted: auditooor.chain_synthesis_report.v1
Proof-obligation schema: auditooor.chain_proof_obligation.v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.chain_synthesis_report.v1"
PROOF_OBLIGATION_SCHEMA_ID = "auditooor.chain_proof_obligation.v1"
EXPLOIT_QUEUE_FILE = ".auditooor/exploit_queue.json"
CCIA_ANGLES_FILE = ".auditooor/ccia_attack_angles.json"
# Mutation-verified break feed produced by the invariant-fuzz / mutation harness.
# Verified breaks here become first-class chain seeds (previously discarded).
BROKEN_INV_FEED_FILE = ".auditooor/broken_invariant_ids.json"
PROOF_OBLIGATIONS_FILE = ".auditooor/chain_proof_obligations.json"
VAULT_SERVER = "tools/vault-mcp-server.py"
BATCH_GEN = "tools/deepseek-batch-gen-tok-chain-exploit.py"
LLM_DISPATCH = "tools/llm-dispatch.py"
DEFAULT_MAX_CHAINS = 10
SOURCE_LINK_ARTIFACT_GLOBS = (
    ".auditooor/chain_synth_source_links.json",
    ".auditooor/source_artifacts/*.composition_link_source_artifact.json",
)
SOURCE_LINK_ALLOWED_STATUSES = {"live_candidate", "ready", "source_backed"}
SOURCE_LINK_IGNORED_STATUSES = {
    "killed", "refuted", "advisory_only", "candidate_not_submit_ready",
}
SUCCESSFUL_NARRATIVE_STATES = {
    "ok",
    "pass",
    "passed",
    "success",
    "succeeded",
    "complete",
    "completed",
    "source_backed",
    "proof_backed",
    "proof-backed",
    "proved",
    "proven",
}
BLOCKED_NARRATIVE_STATES = {
    "error",
    "fail",
    "failed",
    "failure",
    "blocked",
    "blocked_missing_impact_contract",
    "blocked_with_obligation",
    "candidate_not_submit_ready",
    "not_submit_ready",
    "advisory_only",
    "dry_run",
    "not_run",
    "no_run",
    "not_applicable",
    "unsupported_language",
    "coverage_incomplete",
    "scaffold_only",
    "scaffolded",
}
SOURCE_LINK_EDGE_KEYS = (
    "link_id",
    "status",
    "target_template_ids",
    "broken_invariant_ids",
    "from_invariant_id",
    "to_invariant_id",
    "from_queue_lead_id",
    "to_queue_lead_id",
    "from_output",
    "to_input",
    "source_refs",
    "from_source_refs",
    "to_source_refs",
    "causality",
    "manual_seeding_absent",
    "source_artifacts_complete",
    "kill_condition_answer",
    "artifact_path",
    "source_plan_artifact",
)
QUEUE_LEAD_ID_FIELDS = (
    "lead_id",
    "id",
    "task_id",
    "candidate_id",
    "angle_id",
)

# A real file:line citation: path-ish token followed by :<line>. Excludes the
# placeholder forms ("<workspace>/...", "unknown", "manual-source", "N/A").
_FILE_LINE_RE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]+:\d+")
# A proof-obligation id: PO-*, OBL-*, or a known proof_path harness id that is
# not one of the placeholder values.
_PROOF_OBLIGATION_ID_RE = re.compile(r"\b(?:PO|OBL|PROOF|PA)-[A-Za-z0-9_.-]+\b")
_PLACEHOLDER_EVIDENCE = {"", "unknown", "manual-source", "n/a", "none", "tbd",
                         "<workspace>/.auditooor/hacker_brief.md"}
_INV_ID_RE = re.compile(r"\bINV-[A-Za-z0-9_.-]+\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain_synthesis_report_path(workspace: Path) -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return workspace / ".auditooor" / f"chain_synthesis_{date_str}.json"


def _write_chain_synthesis_report(workspace: Path, report: dict, *, dry_run: bool) -> Path:
    report_path = _chain_synthesis_report_path(workspace)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    return report_path


def _audit_run_id(workspace: Path) -> str:
    env_value = os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID", "").strip()
    if env_value:
        return env_value
    digest = hashlib.sha256(str(workspace).encode("utf-8")).hexdigest()[:12]
    return f"chain-synth-{digest}"


def _audit_run_stage() -> str:
    return (
        os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_STAGE", "").strip()
        or os.environ.get("AUDITOOOR_CHAIN_SYNTH_STAGE", "").strip()
        or "chain-synth"
    )


def _display_path(path: Path, workspace: Path) -> str:
    try:
        resolved = path.resolve(strict=False)
        return str(resolved.relative_to(workspace.resolve(strict=False)))
    except (OSError, ValueError):
        return str(path)


def _file_fingerprint(path: Path, workspace: Path) -> dict[str, Any]:
    display = _display_path(path, workspace)
    if not path.is_file():
        return {"path": display, "exists": False}
    data = path.read_bytes()
    return {
        "path": display,
        "exists": True,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _input_fingerprints(
    workspace: Path,
    source_link_paths: list[Path],
) -> dict[str, Any]:
    return {
        "exploit_queue": _file_fingerprint(workspace / EXPLOIT_QUEUE_FILE, workspace),
        "ccia_angles": _file_fingerprint(workspace / CCIA_ANGLES_FILE, workspace),
        "broken_invariant_feed": _file_fingerprint(workspace / BROKEN_INV_FEED_FILE, workspace),
        "source_link_artifacts": [
            _file_fingerprint(path, workspace)
            for path in source_link_paths
        ],
    }


def _terminal_observability(
    *,
    workspace: Path,
    input_fingerprints: dict[str, Any],
    current_queue_lead_ids: set[str],
    current_queue_lead_invariant_ids: dict[str, set[str]],
    all_source_link_entries: list[dict],
    source_link_entries: list[dict],
    rejected_source_link_entries: int,
    source_link_artifacts: list[str],
    broken_ids: list[str],
    max_chains: int,
    require_hop_evidence: bool,
    dry_run: bool,
    template_match_status: str,
    matched_templates: list[dict] | None = None,
    evidence_index: dict[str, list[str]] | None = None,
    decorated: list[dict] | None = None,
    advancing: list[dict] | None = None,
    blocked: list[dict] | None = None,
    proof_obligations: list[dict] | None = None,
    dispatch_templates: list[dict] | None = None,
    batch_file: Path | None = None,
    dispatch_results: list[dict] | None = None,
    dispatch_errors: list[dict] | None = None,
    narratives: list[dict] | None = None,
) -> dict[str, Any]:
    matched_templates = matched_templates or []
    evidence_index = evidence_index or {}
    decorated = decorated or []
    advancing = advancing or []
    blocked = blocked or []
    proof_obligations = proof_obligations or []
    dispatch_templates = dispatch_templates or []
    dispatch_errors = dispatch_errors or []
    narratives = narratives or []
    # ADDITIVE: native def-use edges from the dataflow slice (empty + omitted when
    # .auditooor/dataflow_paths.jsonl is absent -> byte-identical to before).
    dataflow_edges = collect_dataflow_edges(workspace)
    # ADDITIVE: first-class data-stitched chains (chain_kind="dataflow_stitched"),
    # stitched from the SAME slice. Empty + omitted when the slice is absent, so the
    # report shape is byte-identical to before this source existed.
    dataflow_stitched_chains = build_dataflow_stitched_chains(workspace)
    out: dict[str, Any] = {
        "audit_run_id": _audit_run_id(workspace),
        "stage": _audit_run_stage(),
        "input_fingerprints": input_fingerprints,
        "input_counts": {
            "current_queue_leads": len(current_queue_lead_ids),
            "current_queue_lead_invariant_ids": sum(
                len(ids) for ids in current_queue_lead_invariant_ids.values()
            ),
            "source_link_artifacts": len(source_link_artifacts),
            "source_link_entries_total": len(all_source_link_entries),
            "source_link_entries": len(source_link_entries),
            "source_link_entries_rejected_stale_queue": rejected_source_link_entries,
            "broken_invariant_ids": len(broken_ids),
            "matched_templates": len(matched_templates),
            "evidence_indexed_invariants": len(evidence_index),
        },
        "template_match": {
            "status": template_match_status,
            "max_chains": max_chains,
            "broken_invariant_ids": len(broken_ids),
            "matched_templates": len(matched_templates),
            "template_ids": [_template_id(t) for t in matched_templates],
        },
        "advancement": {
            "require_hop_evidence": require_hop_evidence,
            "evaluated_templates": len(decorated),
            "advancing_chains": len(advancing),
            "blocked_chains": len(blocked),
            "dispatch_templates": len(dispatch_templates),
            "proof_obligations": len(proof_obligations),
        },
        "dispatch": {
            "dry_run": dry_run,
            "batch_jsonl": str(batch_file) if batch_file else None,
            "attempted": dispatch_results is not None,
            "dispatch_results": len(dispatch_results or []),
            "dispatch_errors": len(dispatch_errors),
            "narratives": len(narratives),
            "chains_synthesized": len(narratives),
        },
    }
    # Only surface the dataflow_edges block when the slice exists, so the report
    # shape is unchanged on workspaces without a dataflow slice.
    if dataflow_edges:
        out["dataflow_edges"] = dataflow_edges
        out["input_counts"]["dataflow_edges"] = len(dataflow_edges)
    # Only surface the data-stitched chains when at least one was built, so the report
    # shape is unchanged on workspaces without a stitchable slice.
    if dataflow_stitched_chains:
        out["dataflow_stitched_chains"] = dataflow_stitched_chains
        out["input_counts"]["dataflow_stitched_chains"] = len(dataflow_stitched_chains)
    return out


def collect_dataflow_edges(workspace: Path) -> list[dict[str, Any]]:
    """ADDITIVE source: read .auditooor/dataflow_paths.jsonl (the native def-use slice)
    and project each non-degraded DefUsePath into a source_backed_edge with REAL
    source/sink anchors + engine provenance. These edges are ADDED to the existing
    template/label edges, never replacing them. When the file is ABSENT this returns
    [] so chain-synth behaves exactly as before this source existed.

    A dataflow edge is a genuine source-cited hop: it carries the source@file:line ->
    sink@file:line, the inter-procedural hop count, guard status, and the engine's
    confidence so downstream tooling can rank IR-backed (semantic-ssa) over heuristic.
    """
    df = workspace / ".auditooor" / "dataflow_paths.jsonl"
    if not df.is_file():
        return []
    edges: list[dict[str, Any]] = []
    try:
        text = df.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            p = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if p.get("degraded"):
            continue
        src = p.get("source") or {}
        snk = p.get("sink") or {}
        src_file = src.get("file")
        snk_file = snk.get("file")
        if not src_file or not snk_file:
            continue
        src_ref = f"{src_file}:{src.get('line')}" if src.get("line") else str(src_file)
        snk_ref = f"{snk_file}:{snk.get('line')}" if snk.get("line") else str(snk_file)
        edges.append({
            "edge_kind": "dataflow",
            "path_id": p.get("path_id"),
            "language": p.get("language"),
            "engine": p.get("engine"),
            "confidence": p.get("confidence"),
            "unguarded": bool(p.get("unguarded")),
            "call_depth": p.get("call_depth"),
            "source_unit_ids": p.get("source_unit_ids") or [],
            "sink_unit_ids": p.get("sink_unit_ids") or [],
            "source": {"fn": src.get("fn"), "var": src.get("var"), "file_line": src_ref},
            "sink": {"callee": snk.get("callee"), "arg_pos": snk.get("arg_pos"), "file_line": snk_ref},
            "real_evidence": [src_ref, snk_ref],
            "provenance": "dataflow-slice.v1",
        })
    return edges


# --------------------------------------------------------------------------- #
# Bidirectional wiring 49b: data-stitched chains (chain_kind="dataflow_stitched")
#
# A data-stitched chain is a SEQUENCE of DefUsePaths where one path's SINK feeds
# the next path's SOURCE, forming entrypoint -> ... -> impact. The join (the
# "load-bearing var") is one of:
#   - storage join: path A writes storage var V (sink.kind=="storage-value",
#     sink.callee==V), path B reads that same var (source.kind=="state_var",
#     source.var==V). join_kind="storage", join_var=V.
#   - return->arg join: A's value reaches function F (sink.fn==F) and B's def-use
#     begins in F (source.fn==F). join_kind="fn", join_var=F.
#
# This is ADDITIVE: it ADDS a data-grounded chain source alongside the existing
# template/label chains, which are untouched. When the slice is ABSENT the builder
# returns [] so chain-synth is byte-identical to before this source existed.
# --------------------------------------------------------------------------- #

# Sink kinds that move/realize value or corrupt state == a chain IMPACT terminal.
_DATAFLOW_IMPACT_SINK_KINDS = frozenset(
    {"transfer", "transferFrom", "safeTransfer", "mint", "burn", "low_level_call"}
)
# Conservative caps so a 10k-row slice cannot blow up into a combinatorial chain set.
_DATAFLOW_STITCH_MAX_HOPS = 6        # max DefUsePaths stitched into one chain
_DATAFLOW_STITCH_MAX_CHAINS = 200    # max stitched chains emitted
_DATAFLOW_STITCH_MAX_FANOUT = 8      # max successor paths followed per join key


def _df_storage_write_var(path: dict[str, Any]) -> str | None:
    """The storage var a path WRITES (its sink), or None if the sink is not a storage write."""
    snk = path.get("sink") or {}
    if snk.get("kind") == "storage-value" and snk.get("callee"):
        return str(snk.get("callee"))
    return None


def _df_storage_read_var(path: dict[str, Any]) -> str | None:
    """The storage var a path READS as its SOURCE, or None if the source is not a state-var read."""
    src = path.get("source") or {}
    if src.get("kind") == "state_var" and src.get("var"):
        return str(src.get("var"))
    return None


def _df_sink_fn(path: dict[str, Any]) -> str | None:
    snk = path.get("sink") or {}
    return str(snk.get("fn")) if snk.get("fn") else None


def _df_source_fn(path: dict[str, Any]) -> str | None:
    src = path.get("source") or {}
    return str(src.get("fn")) if src.get("fn") else None


def _df_is_entrypoint(path: dict[str, Any]) -> bool:
    """A chain head: a path whose SOURCE is an external entrypoint param or tainted input."""
    src = path.get("source") or {}
    return src.get("kind") in ("param-entrypoint", "tainted-local")


def _df_is_impact(path: dict[str, Any]) -> bool:
    """A chain terminal: a path whose SINK moves value or corrupts state."""
    snk = path.get("sink") or {}
    return snk.get("kind") in _DATAFLOW_IMPACT_SINK_KINDS


def _df_file_line(node: dict[str, Any]) -> str:
    f = node.get("file")
    ln = node.get("line")
    if not f:
        return ""
    return f"{f}:{ln}" if ln else str(f)


def _load_dataflow_paths(workspace: Path) -> list[dict[str, Any]]:
    """Read the non-degraded DefUsePaths from the shared sidecar via dataflow_schema.read_paths.

    Falls back to a local jsonl parse if the schema module is not importable, so the
    builder never raises and stays byte-identical (returns []) on a no-slice workspace.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import dataflow_schema  # type: ignore
        return dataflow_schema.read_paths(workspace, skip_degraded=True)
    except Exception:
        df = workspace / ".auditooor" / "dataflow_paths.jsonl"
        if not df.is_file():
            return []
        out: list[dict[str, Any]] = []
        try:
            text = df.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(rec, dict) and not rec.get("degraded"):
                out.append(rec)
        return out


def build_dataflow_stitched_chains(
    workspace: Path,
    paths: list[dict[str, Any]] | None = None,
    *,
    max_hops: int = _DATAFLOW_STITCH_MAX_HOPS,
    max_chains: int = _DATAFLOW_STITCH_MAX_CHAINS,
    max_fanout: int = _DATAFLOW_STITCH_MAX_FANOUT,
) -> list[dict[str, Any]]:
    """ADDITIVE first-class chain source: stitch DefUsePaths into data-grounded chains.

    A chain is a stitched SEQUENCE of DefUsePaths where path[i]'s SINK feeds path[i+1]'s
    SOURCE (shared storage var, or return->arg via the same function). Each emitted chain
    is tagged chain_kind="dataflow_stitched" and carries the ordered path_ids + the
    load-bearing join var at each hop, plus the entrypoint and impact anchors.

    Default-off contract: returns [] when there is no slice (so the report shape is
    unchanged). Self-loops (a path stitched to itself) and revisited path_ids within a
    single chain are forbidden (cycle-safe via a visited set).

    Args mirror the module caps so a test can shrink them; production uses the defaults.
    """
    if paths is None:
        paths = _load_dataflow_paths(workspace)
    if not paths:
        return []

    # De-dup by path_id (a slice can repeat a row across re-runs); keep first occurrence.
    by_id: dict[str, dict[str, Any]] = {}
    for p in paths:
        pid = p.get("path_id")
        if pid and pid not in by_id:
            by_id[pid] = p
    ordered = list(by_id.values())

    # Build successor indexes: from a path's sink, what paths can follow.
    #   storage: writes var V -> paths whose source reads V
    #   fn:      reaches fn F -> paths whose source begins in F
    reads_by_var: dict[str, list[dict[str, Any]]] = {}
    src_by_fn: dict[str, list[dict[str, Any]]] = {}
    for p in ordered:
        rv = _df_storage_read_var(p)
        if rv:
            reads_by_var.setdefault(rv, []).append(p)
        sf = _df_source_fn(p)
        if sf:
            src_by_fn.setdefault(sf, []).append(p)

    def successors(path: dict[str, Any]) -> list[tuple[dict[str, Any], str, str]]:
        """Return (next_path, join_kind, join_var) for every path that path's sink feeds."""
        out: list[tuple[dict[str, Any], str, str]] = []
        wv = _df_storage_write_var(path)
        if wv:
            for nxt in reads_by_var.get(wv, [])[:max_fanout]:
                if nxt.get("path_id") != path.get("path_id"):
                    out.append((nxt, "storage", wv))
        sf = _df_sink_fn(path)
        if sf:
            for nxt in src_by_fn.get(sf, [])[:max_fanout]:
                if nxt.get("path_id") != path.get("path_id"):
                    out.append((nxt, "fn", sf))
        return out

    # Heads: entrypoint-sourced paths (deterministic order by path_id).
    heads = sorted(
        (p for p in ordered if _df_is_entrypoint(p)),
        key=lambda p: str(p.get("path_id")),
    )

    chains: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, ...]] = set()

    def emit_chain(seq: list[dict[str, Any]], joins: list[dict[str, Any]]) -> None:
        path_ids = tuple(str(p.get("path_id")) for p in seq)
        if path_ids in seen_signatures:
            return
        seen_signatures.add(path_ids)
        head = seq[0]
        tail = seq[-1]
        chains.append(
            {
                "chain_kind": "dataflow_stitched",
                "chain_id": "DFSC-" + hashlib.sha1(
                    "|".join(path_ids).encode("utf-8")
                ).hexdigest()[:12],
                "path_ids": list(path_ids),
                "hop_count": len(seq),
                "joins": joins,  # ordered, one per stitch: {join_kind, join_var, from_path, to_path}
                "join_vars": [j["join_var"] for j in joins],
                "entrypoint": {
                    "fn": (head.get("source") or {}).get("fn"),
                    "var": (head.get("source") or {}).get("var"),
                    "file_line": _df_file_line(head.get("source") or {}),
                },
                "impact": {
                    "kind": (tail.get("sink") or {}).get("kind"),
                    "callee": (tail.get("sink") or {}).get("callee"),
                    "fn": (tail.get("sink") or {}).get("fn"),
                    "file_line": _df_file_line(tail.get("sink") or {}),
                },
                "reaches_impact": _df_is_impact(tail),
                "unguarded": all(bool(p.get("unguarded")) for p in seq),
                "confidence": "semantic-ssa"
                if all(p.get("confidence") == "semantic-ssa" for p in seq)
                else "mixed",
                "languages": _dedup([str(p.get("language")) for p in seq]),
                "real_evidence": _dedup(
                    [_df_file_line(head.get("source") or {}), _df_file_line(tail.get("sink") or {})]
                    + [j["join_var"] for j in joins]
                ),
                "provenance": "dataflow-slice.v1",
            }
        )

    def walk(seq: list[dict[str, Any]], joins: list[dict[str, Any]], visited: set[str]) -> None:
        if len(chains) >= max_chains:
            return
        tail = seq[-1]
        # Emit a chain whenever the current tail is a value-moving impact AND we have
        # stitched at least one hop (a single path is already a dataflow_edge, not a chain).
        if len(seq) >= 2 and _df_is_impact(tail):
            emit_chain(seq, joins)
        if len(seq) >= max_hops:
            return
        for nxt, jkind, jvar in successors(tail):
            npid = str(nxt.get("path_id"))
            if npid in visited:
                continue  # cycle-safe: no revisits within a chain
            walk(
                seq + [nxt],
                joins + [{
                    "join_kind": jkind,
                    "join_var": jvar,
                    "from_path": str(tail.get("path_id")),
                    "to_path": npid,
                }],
                visited | {npid},
            )
            if len(chains) >= max_chains:
                return

    for head in heads:
        if len(chains) >= max_chains:
            break
        hpid = str(head.get("path_id"))
        walk([head], [], {hpid})

    # Deterministic order: impact-reaching chains first, then by hop_count desc, then id.
    chains.sort(key=lambda c: (not c["reaches_impact"], -c["hop_count"], c["chain_id"]))
    return chains[:max_chains]


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _dedup(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _extract_file_line_tokens(value: Any) -> list[str]:
    if isinstance(value, str):
        if value.strip().lower() in _PLACEHOLDER_EVIDENCE:
            return []
        return _dedup(_FILE_LINE_RE.findall(value))
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_extract_file_line_tokens(item))
        return _dedup(out)
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_extract_file_line_tokens(item))
        return _dedup(out)
    return []


def _extract_real_evidence_tokens(value: Any) -> list[str]:
    if isinstance(value, str):
        if value.strip().lower() in _PLACEHOLDER_EVIDENCE:
            return []
        return _dedup(
            _FILE_LINE_RE.findall(value) + _PROOF_OBLIGATION_ID_RE.findall(value)
        )
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_extract_real_evidence_tokens(item))
        return _dedup(out)
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_extract_real_evidence_tokens(item))
        return _dedup(out)
    return []


def _mentioned_invariant_ids(value: Any) -> list[str]:
    try:
        blob = json.dumps(value, default=str)
    except TypeError:
        blob = str(value)
    return _dedup(_INV_ID_RE.findall(blob))


def _declared_invariant_ids(entry: dict) -> list[str]:
    ids: list[str] = []
    for key in ("broken_invariant_ids", "matched_invariant_ids", "member_invariant_ids"):
        val = entry.get(key)
        if isinstance(val, list):
            ids.extend(x for x in val if isinstance(x, str) and _INV_ID_RE.fullmatch(x))
    for key in ("broken_invariant_id", "from_invariant_id", "to_invariant_id"):
        val = entry.get(key)
        if isinstance(val, str) and _INV_ID_RE.fullmatch(val):
            ids.append(val)
    return _dedup(ids)


def _all_invariant_ids(entry: dict) -> list[str]:
    return _dedup(_declared_invariant_ids(entry) + _mentioned_invariant_ids(entry))


def normalize_ccia_rows(doc: Any) -> list[dict]:
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if not isinstance(doc, dict):
        return []
    rows: list[dict] = []
    for key in ("attack_angles", "angles", "rows", "entries", "queue"):
        val = doc.get(key)
        if isinstance(val, list):
            rows.extend(x for x in val if isinstance(x, dict))
    return rows


def _entry_queue_lead_ids(entry: dict) -> list[str]:
    ids: list[str] = []
    if not isinstance(entry, dict):
        return ids
    for key in QUEUE_LEAD_ID_FIELDS:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            ids.append(value.strip())
    return _dedup(ids)


def _current_queue_entries(workspace: Path) -> list[dict]:
    entries: list[dict] = []
    queue = load_json(workspace / EXPLOIT_QUEUE_FILE)
    if isinstance(queue, dict):
        for key in ("queue", "entries"):
            for entry in queue.get(key, []) or []:
                if isinstance(entry, dict):
                    entries.append(entry)
    elif isinstance(queue, list):
        entries.extend(entry for entry in queue if isinstance(entry, dict))

    angles = load_json(workspace / CCIA_ANGLES_FILE)
    entries.extend(normalize_ccia_rows(angles))
    return [entry for entry in entries if _entry_is_real_queue_candidate(entry)]


def collect_current_queue_lead_ids(workspace: Path) -> set[str]:
    """Collect lead ids from current exploit queue and CCIA angle artifacts."""
    ids: list[str] = []
    for entry in _current_queue_entries(workspace):
        for lead_id in _entry_queue_lead_ids(entry):
            if lead_id not in ids:
                ids.append(lead_id)
    return set(ids)


def collect_current_queue_lead_invariant_ids(workspace: Path) -> dict[str, set[str]]:
    """Map each live queue lead id to its declared invariant ids."""
    out: dict[str, set[str]] = {}
    for entry in _current_queue_entries(workspace):
        lead_ids = _entry_queue_lead_ids(entry)
        inv_ids = set(_declared_invariant_ids(entry))
        if not lead_ids:
            continue
        for lead_id in lead_ids:
            out.setdefault(lead_id, set()).update(inv_ids)
    return out


# r36-rebuttal: lane chain-synth-fix registered for tools/chain-synth-driver.py only; no sibling overlap
def collect_broken_invariant_ids(workspace: Path) -> list[str]:
    """Gather INV-* ids from exploit queue + CCIA angles."""
    ids: list[str] = []

    # From real exploit-queue rows only. Root-level summary ids and rows without
    # a lead/angle identity do not constitute a real proof queue for chain-synth.
    queue = load_json(workspace / EXPLOIT_QUEUE_FILE)
    if isinstance(queue, dict):
        for entry in queue.get("entries", []):
            if not isinstance(entry, dict):
                continue
            if not _entry_is_real_queue_candidate(entry):
                continue
            for v in _all_invariant_ids(entry):
                if v not in ids:
                    ids.append(v)
        # exploit-queue rows live under the "queue" key (preflight-fuel writer)
        for entry in queue.get("queue", []):
            if not isinstance(entry, dict):
                continue
            if not _entry_is_real_queue_candidate(entry):
                continue
            for v in _all_invariant_ids(entry):
                if v not in ids:
                    ids.append(v)
    elif isinstance(queue, list):
        for entry in queue:
            if not isinstance(entry, dict):
                continue
            if not _entry_is_real_queue_candidate(entry):
                continue
            for v in _all_invariant_ids(entry):
                if v not in ids:
                    ids.append(v)

    # From CCIA angles
    angles = load_json(workspace / CCIA_ANGLES_FILE)
    for a in normalize_ccia_rows(angles):
        if not _entry_is_real_queue_candidate(a):
            continue
        for v in _all_invariant_ids(a):
            if v not in ids:
                ids.append(v)

    # From the mutation-verified break feed (.auditooor/broken_invariant_ids.json).
    # Previously DISCARDED: a mutation-verified invariant break never reached
    # chain-synth, so a real broken invariant produced zero chain seeds. We now
    # promote each row to a seed, gated STRICTLY on mutation_verified == True so a
    # vacuous / unverified break cannot inject a phantom seed (R80 - no vacuous
    # seed). Non-bool truthy values (e.g. the string "true") do NOT pass.
    feed = load_json(workspace / BROKEN_INV_FEED_FILE)
    if isinstance(feed, dict):
        for row in feed.get("broken_invariant_ids", []):
            if not isinstance(row, dict):
                continue
            if row.get("mutation_verified") is not True:
                continue
            inv = row.get("invariant_id", "")
            if not isinstance(inv, str) or not _INV_ID_RE.fullmatch(inv):
                continue
            if inv not in ids:
                ids.append(inv)

    # F1/E1.3 diagnostic: record how many INV ids were actually collected from the
    # queue. The chain-synth join is not code-dead - it is STARVED when the queue
    # carries 0 INV ids (the pre-F1 state: corpus-driven-hunt never ran, so every
    # row was attack_class=unknown). A regression asserts this is > 0 after F1
    # wiring. Stderr only (never pollutes the JSON chain output on stdout).
    import sys as _sys
    print("[chain-synth] collected_invariant_ids=%d from exploit_queue + ccia + "
          "broken-feed (0 => starved join: corpus-driven-hunt did not INV-ground "
          "the queue; F1/STEP 3.5)" % len(ids), file=_sys.stderr)

    return ids


# --------------------------------------------------------------------------- #
# PR8a proof-seeking: per-hop evidence index + hop decomposition + gating.
# --------------------------------------------------------------------------- #
def _is_real_evidence(token: Any) -> bool:
    """A token is real evidence if it is a file:line citation or a proof-obligation id."""
    return bool(_extract_real_evidence_tokens(token))


def _is_real_file_line_evidence(token: Any) -> bool:
    return bool(_extract_file_line_tokens(token))


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _file_line_ref_is_live(ref: str, workspace: Path) -> bool:
    text = str(ref or "").strip()
    if not text:
        return False
    path_part, sep, line_part = text.rpartition(":")
    if not sep or not path_part or not line_part.isdigit():
        return False
    path = Path(path_part)
    if not path.is_absolute():
        path = workspace / path
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(workspace.resolve(strict=False))
    except (OSError, ValueError):
        return False
    if not resolved.is_file():
        return False
    line_no = int(line_part)
    if line_no < 1:
        return False
    try:
        with resolved.open(encoding="utf-8", errors="ignore") as fh:
            for idx, _line in enumerate(fh, start=1):
                if idx >= line_no:
                    return True
    except OSError:
        return False
    return False


def candidate_source_link_paths(
    workspace: Path,
    explicit_paths: list[Path] | None = None,
) -> list[Path]:
    candidates: list[Path] = []
    for raw in explicit_paths or []:
        p = raw if raw.is_absolute() else workspace / raw
        candidates.append(p)
    for pat in SOURCE_LINK_ARTIFACT_GLOBS:
        candidates.extend(sorted(workspace.glob(pat)))
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key in seen or not p.is_file():
            continue
        seen.add(key)
        out.append(p)
    return out


def coerce_source_link_rows(doc: Any) -> list[dict]:
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if not isinstance(doc, dict):
        return []
    rows: list[dict] = []
    for key in ("links", "entries", "source_links", "source_backed_edges"):
        val = doc.get(key)
        if isinstance(val, list):
            for x in val:
                if not isinstance(x, dict):
                    continue
                copied = dict(x)
                for meta_key in ("source_plan_artifact", "workspace"):
                    if meta_key not in copied and meta_key in doc:
                        copied[meta_key] = doc.get(meta_key)
                rows.append(copied)
    return rows


def source_link_file_line_refs(entry: dict) -> list[str]:
    refs: list[str] = []
    for key in ("source_refs", "refs", "evidence_refs", "from_source_refs", "to_source_refs"):
        refs.extend(_extract_file_line_tokens(entry.get(key)))
    for key in ("source_ref", "from_source_ref", "to_source_ref"):
        refs.extend(_extract_file_line_tokens(entry.get(key)))
    return _dedup(refs)


def _entry_invariant_ids(entry: dict) -> list[str]:
    return _declared_invariant_ids(entry)


def _source_link_endpoint_ids(entry: dict) -> tuple[str | None, str | None]:
    from_inv = entry.get("from_invariant_id")
    to_inv = entry.get("to_invariant_id")
    if not isinstance(from_inv, str) or not _INV_ID_RE.fullmatch(from_inv):
        return None, None
    if not isinstance(to_inv, str) or not _INV_ID_RE.fullmatch(to_inv):
        return None, None
    if from_inv == to_inv:
        return None, None
    return from_inv, to_inv


def _source_link_declared_broken_ids(entry: dict) -> list[str]:
    value = entry.get("broken_invariant_ids")
    if not isinstance(value, list):
        return []
    return _dedup(x for x in value if isinstance(x, str) and _INV_ID_RE.fullmatch(x))


def source_link_invariant_ids(entries: list[dict]) -> list[str]:
    ids: list[str] = []
    for entry in entries:
        from_inv, to_inv = _source_link_endpoint_ids(entry)
        if from_inv and to_inv:
            ids.extend([from_inv, to_inv])
    return _dedup(ids)


def normalize_source_link_entry(
    entry: dict,
    artifact_path: Path | None = None,
) -> dict | None:
    if not isinstance(entry, dict):
        return None
    status = str(entry.get("status") or "").strip().lower()
    if status in SOURCE_LINK_IGNORED_STATUSES:
        return None
    if status not in SOURCE_LINK_ALLOWED_STATUSES:
        return None
    if not _truthy(entry.get("manual_seeding_absent")):
        return None
    if not _truthy(entry.get("source_artifacts_complete")):
        return None
    refs = source_link_file_line_refs(entry)
    if len(refs) < 2:
        return None
    from_inv, to_inv = _source_link_endpoint_ids(entry)
    if not from_inv or not to_inv:
        return None
    broken_ids = _source_link_declared_broken_ids(entry)
    if set(broken_ids) != {from_inv, to_inv}:
        return None
    out = {k: entry[k] for k in SOURCE_LINK_EDGE_KEYS if k in entry}
    out["status"] = status
    out["source_refs"] = refs
    out["from_invariant_id"] = from_inv
    out["to_invariant_id"] = to_inv
    out["broken_invariant_ids"] = [from_inv, to_inv]
    out["manual_seeding_absent"] = True
    out["source_artifacts_complete"] = True
    if artifact_path is not None:
        out["artifact_path"] = str(artifact_path)
    if "link_id" not in out:
        digest = hashlib.sha256(
            json.dumps(out, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        out["link_id"] = f"source-link-{digest}"
    return out


def load_source_link_entries(
    workspace: Path,
    explicit_paths: list[Path] | None = None,
) -> list[dict]:
    entries: list[dict] = []
    seen: set[str] = set()
    for path in candidate_source_link_paths(workspace, explicit_paths):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for row in coerce_source_link_rows(doc):
            norm = normalize_source_link_entry(row, artifact_path=path)
            if not norm:
                continue
            key = str(norm.get("link_id"))
            if key in seen:
                continue
            seen.add(key)
            entries.append(norm)
    return entries


def filter_source_link_entries_for_current_queue(
    entries: list[dict],
    current_queue_lead_ids: set[str],
    current_queue_lead_invariant_ids: dict[str, set[str]] | None = None,
    workspace: Path | None = None,
) -> list[dict]:
    """Keep source links that are backed by current producer and consumer queue rows."""
    if not current_queue_lead_ids:
        return []
    out: list[dict] = []
    for entry in entries:
        from_id = str(entry.get("from_queue_lead_id") or "").strip()
        to_id = str(entry.get("to_queue_lead_id") or "").strip()
        if not from_id or not to_id:
            continue
        if from_id == to_id:
            continue
        if from_id not in current_queue_lead_ids or to_id not in current_queue_lead_ids:
            continue
        from_inv, to_inv = _source_link_endpoint_ids(entry)
        if not from_inv or not to_inv:
            continue
        if current_queue_lead_invariant_ids is not None:
            if from_inv not in current_queue_lead_invariant_ids.get(from_id, set()):
                continue
            if to_inv not in current_queue_lead_invariant_ids.get(to_id, set()):
                continue
        if workspace is not None:
            if not _source_link_plan_artifact_is_live(entry, workspace):
                continue
            if not _source_link_refs_are_live(entry, workspace):
                continue
        copied = dict(entry)
        copied["current_queue_verified"] = True
        out.append(copied)
    return out


def _source_link_plan_artifact_is_live(entry: dict, workspace: Path) -> bool:
    raw = entry.get("source_plan_artifact")
    if not isinstance(raw, str) or not raw.strip():
        return False
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute():
        path = workspace / path
    try:
        path = path.resolve(strict=False)
        root = workspace.resolve(strict=False)
    except OSError:
        return False
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return path.is_file()


def _source_link_refs_are_live(entry: dict, workspace: Path) -> bool:
    refs = source_link_file_line_refs(entry)
    if not refs:
        return False
    for ref in refs:
        if not _file_line_ref_is_live(ref, workspace):
            return False
    return True


def _status_token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _entry_is_active_queue_candidate(entry: dict) -> bool:
    """Return true for queue rows that may support chain synthesis."""
    if not isinstance(entry, dict):
        return False
    if entry.get("error") or _truthy(entry.get("dry_run")):
        return False
    if _truthy(entry.get("candidate_not_submit_ready")):
        return False
    if _truthy(entry.get("advisory_only")):
        return False
    if _truthy(entry.get("does_not_claim_exploitability")):
        return False
    posture = _status_token(entry.get("submission_posture"))
    if posture in {"not_submit_ready", "not_ready", "hold", "blocked"}:
        return False
    state_values = [
        entry.get("status"),
        entry.get("verdict"),
        entry.get("result"),
        entry.get("final_result"),
        entry.get("proof_status"),
        entry.get("queue_status"),
    ]
    states = {_status_token(value) for value in state_values if str(value or "").strip()}
    if states & BLOCKED_NARRATIVE_STATES:
        return False
    return True


def _entry_is_real_queue_candidate(entry: dict) -> bool:
    """Return true for live queue rows that carry a real lead/angle identity."""
    return _entry_is_active_queue_candidate(entry) and bool(_entry_queue_lead_ids(entry))


def _is_successful_chain_narrative(row: dict) -> bool:
    if not isinstance(row, dict):
        return False
    if row.get("error") or _truthy(row.get("dry_run")):
        return False
    narrative = row.get("narrative")
    if not isinstance(narrative, dict) or not narrative:
        return False
    if set(narrative) == {"raw"}:
        return False
    if narrative.get("error") or _truthy(narrative.get("candidate_not_submit_ready")):
        return False
    if _truthy(narrative.get("advisory_only")) or _truthy(narrative.get("does_not_claim_exploitability")):
        return False
    state_values = [
        narrative.get("status"),
        narrative.get("verdict"),
        narrative.get("result"),
        narrative.get("final_result"),
    ]
    states = {_status_token(value) for value in state_values if str(value or "").strip()}
    if states & BLOCKED_NARRATIVE_STATES:
        return False
    if states & SUCCESSFUL_NARRATIVE_STATES:
        return True
    return True


def attach_source_link_edges_to_templates(
    matched_templates: list[dict],
    entries: list[dict],
) -> list[dict]:
    out: list[dict] = []
    for template in matched_templates:
        copied = dict(template)
        existing: list[dict] = []
        seen_link_ids: set[str] = set()
        template_id = _template_id(copied)
        hops = set(_template_invariant_hops(copied))
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if not _truthy(entry.get("current_queue_verified")):
                continue
            target_ids = entry.get("target_template_ids") or []
            if isinstance(target_ids, str):
                target_ids = [target_ids]
            from_inv, to_inv = _source_link_endpoint_ids(entry)
            if target_ids and template_id not in target_ids:
                continue
            if not from_inv or not to_inv or from_inv not in hops or to_inv not in hops:
                continue
            link_id = str(entry.get("link_id"))
            if link_id in seen_link_ids:
                continue
            existing.append(dict(entry))
            seen_link_ids.add(link_id)
        copied["source_backed_edges"] = existing
        out.append(copied)
    return out


def _collect_evidence_tokens(entry: dict) -> list[str]:
    """Pull every candidate evidence string out of one exploit-queue / CCIA entry."""
    tokens: list[str] = []
    scalar_fields = ("proof_path", "impact_path", "required_proof_path",
                     "root_cause_hypothesis", "next_command", "commit_point")
    list_fields = ("source_refs", "proof_artifact_precedent_refs",
                   "metric_integrity_refs", "falsification_requirements",
                   "evidence_incidents")
    for f in scalar_fields:
        tokens.extend(_extract_real_evidence_tokens(entry.get(f)))
    for f in list_fields:
        tokens.extend(_extract_real_evidence_tokens(entry.get(f)))
    return _dedup(tokens)


def _is_complete_source_link_entry(
    entry: dict,
    *,
    require_current_queue_verified: bool = False,
) -> bool:
    """Return true for normalized source-link rows that can support an edge."""
    status = str(entry.get("status") or "").strip().lower()
    from_id = str(entry.get("from_queue_lead_id") or "").strip()
    to_id = str(entry.get("to_queue_lead_id") or "").strip()
    from_inv, to_inv = _source_link_endpoint_ids(entry)
    endpoints = {from_inv, to_inv} if from_inv and to_inv else set()
    broken_ids = set(_source_link_declared_broken_ids(entry))
    return (
        status in SOURCE_LINK_ALLOWED_STATUSES
        and _truthy(entry.get("manual_seeding_absent"))
        and _truthy(entry.get("source_artifacts_complete"))
        and (not require_current_queue_verified or _truthy(entry.get("current_queue_verified")))
        and bool(from_id)
        and bool(to_id)
        and from_id != to_id
        and bool(endpoints)
        and broken_ids == endpoints
        and len(source_link_file_line_refs(entry)) >= 2
    )


def _coerce_real_evidence_tokens(value: Any) -> list[str]:
    if isinstance(value, (str, list)):
        return _extract_real_evidence_tokens(value)
    if isinstance(value, dict):
        return _extract_real_evidence_tokens(value)
    return []


def _structured_invariant_evidence(entry: dict) -> dict[str, list[str]]:
    """Return explicitly invariant-bound evidence from queue row metadata."""
    out: dict[str, list[str]] = {}
    for key in (
        "invariant_evidence",
        "evidence_by_invariant",
        "per_invariant_evidence",
        "broken_invariant_evidence",
    ):
        value = entry.get(key)
        if not isinstance(value, dict):
            continue
        for inv, evidence_value in value.items():
            if not isinstance(inv, str) or not _INV_ID_RE.fullmatch(inv):
                continue
            evidence = _coerce_real_evidence_tokens(evidence_value)
            if evidence:
                out.setdefault(inv, [])
                for ev in evidence:
                    if ev not in out[inv]:
                        out[inv].append(ev)
    return out


def build_invariant_evidence_index(
    workspace: Path,
    extra_entries: list[dict] | None = None,
) -> dict[str, list[str]]:
    """Map each INV-* id -> list of REAL evidence tokens (file:line / proof-obligation id).

    Evidence is harvested from exploit-queue entries and CCIA angles. Raw row
    evidence is attributed only when it binds to one invariant. Multi-invariant
    rows need explicit per-invariant evidence or a complete source-link row."""
    index: dict[str, list[str]] = {}

    def attribute(entry: dict) -> None:
        if not isinstance(entry, dict):
            return
        declared_ids = _declared_invariant_ids(entry)
        inv_ids = declared_ids or _mentioned_invariant_ids(entry)
        if not inv_ids:
            return
        structured = _structured_invariant_evidence(entry)
        for inv, evidence_values in structured.items():
            bucket = index.setdefault(inv, [])
            for ev in evidence_values:
                if ev not in bucket:
                    bucket.append(ev)
        evidence = _collect_evidence_tokens(entry)
        if not evidence:
            return
        if len(inv_ids) > 1 and not _is_complete_source_link_entry(entry):
            return
        for inv in inv_ids:
            bucket = index.setdefault(inv, [])
            for ev in evidence:
                if ev not in bucket:
                    bucket.append(ev)

    queue = load_json(workspace / EXPLOIT_QUEUE_FILE)
    if isinstance(queue, dict):
        for key in ("queue", "entries"):
            for entry in queue.get(key, []) or []:
                if not _entry_is_real_queue_candidate(entry):
                    continue
                attribute(entry)
    elif isinstance(queue, list):
        for entry in queue:
            if not _entry_is_real_queue_candidate(entry):
                continue
            attribute(entry)

    angles = load_json(workspace / CCIA_ANGLES_FILE)
    for a in normalize_ccia_rows(angles):
        if not _entry_is_real_queue_candidate(a):
            continue
        attribute(a)

    for entry in extra_entries or []:
        if _is_complete_source_link_entry(entry, require_current_queue_verified=True):
            attribute(entry)

    return index


def _template_invariant_hops(template: dict) -> list[str]:
    """Ordered, de-duplicated invariant ids that make up one chain template's hops."""
    hops: list[str] = []
    for f in ("member_invariant_ids", "matched_invariant_ids",
              "matched_invariant_ids_in_workspace"):
        for v in template.get(f, []) or []:
            if isinstance(v, str) and v not in hops:
                hops.append(v)
    return hops


def seeds_without_template(
    broken_ids: list[str],
    matched_templates: list[dict],
) -> list[str]:
    """Seeds (broken invariant ids) that no matched template covers as a hop.

    Without this, a mutation-verified break that promotes to a seed but matches
    no chain template is silently dropped - invisible to the operator. We surface
    each such seed as a 'seed_had_no_template' diagnostic so a real broken
    invariant with no template is VISIBLE work-to-do, not a silent zero.
    """
    covered: set[str] = set()
    for t in matched_templates or []:
        if isinstance(t, dict):
            covered.update(_template_invariant_hops(t))
    return [inv for inv in broken_ids if inv not in covered]


def _template_id(template: dict) -> str:
    """Return the stable id field used by matcher and older template shapes."""
    return (
        template.get("chain_template_id")
        or template.get("template_id")
        or template.get("id")
        or "unknown"
    )


def _template_composition_support(template: dict, hop_count: int) -> tuple[bool, list[str]]:
    """Return whether a multi-hop template has a source-backed linkage signal."""
    if hop_count <= 1:
        return False, ["single-detector-restatement"]

    def supported_edge(value: Any) -> bool:
        if isinstance(value, list):
            return any(supported_edge(item) for item in value)
        if isinstance(value, dict):
            return _is_complete_source_link_entry(
                value,
                require_current_queue_verified=True,
            )
        return False

    if supported_edge(template.get("source_backed_edges")):
        return True, ["source_backed_edges"]

    return False, ["missing-source-backed-composition-link"]


def _blocked_only_by_absent_source_links(
    *,
    blocked: list[dict],
    all_source_link_entries: list[dict],
    source_link_artifacts: list[str],
) -> bool:
    """Return true when templates matched but no source-backed chain input exists."""
    if not blocked or all_source_link_entries or source_link_artifacts:
        return False
    for row in blocked:
        support = set(row.get("composition_support") or [])
        if support != {"missing-source-backed-composition-link"}:
            return False
        if row.get("missing_evidence_hops"):
            return False
    return True


def _blocked_chain_needs_proof_obligation(decorated: dict) -> bool:
    """Return true when a blocked multi-hop chain should become source-mining work."""
    support = set(decorated.get("composition_support") or [])
    if support == {"single-detector-restatement"}:
        return False
    if int(decorated.get("hop_count") or 0) <= 1:
        return False
    return bool(decorated.get("missing_evidence_hops")) or not bool(
        decorated.get("composition_supported")
    )


def decorate_template_with_hop_evidence(
    template: dict,
    evidence_index: dict[str, list[str]],
) -> dict:
    """Build a per-hop evidence list for one template and decide if the chain advances.

    Returns a dict:
      {
        "template_id": ...,
        "hops": [{"invariant_id", "evidence", "has_evidence"}, ...],
        "advances": bool,            # True iff hops and composition are evidenced
        "missing_evidence_hops": [invariant_id, ...],
      }
    A template with zero hops cannot advance (nothing to prove)."""
    inv_hops = _template_invariant_hops(template)
    hops: list[dict] = []
    missing: list[str] = []
    for inv in inv_hops:
        ev = list(evidence_index.get(inv, []))
        has_ev = len(ev) > 0
        if not has_ev:
            missing.append(inv)
        hops.append({"invariant_id": inv, "evidence": ev, "has_evidence": has_ev})
    composition_supported, composition_support = _template_composition_support(
        template, len(hops)
    )
    advances = bool(hops) and not missing and composition_supported
    return {
        "template_id": _template_id(template),
        "hops": hops,
        "advances": advances,
        "missing_evidence_hops": missing,
        "hop_count": len(hops),
        "composition_supported": composition_supported,
        "composition_support": composition_support,
        "source_backed_edges": [
            dict(edge)
            for edge in (template.get("source_backed_edges") or [])
            if isinstance(edge, dict)
            and _is_complete_source_link_entry(
                edge,
                require_current_queue_verified=True,
            )
        ],
    }


def build_chain_proof_obligation(decorated: dict, workspace: Path) -> dict:
    """A single multi-hop proof obligation for one composed chain."""
    source_backed_edges: list[dict[str, Any]] = []
    for edge in decorated.get("source_backed_edges") or []:
        if not isinstance(edge, dict):
            continue
        source_backed_edges.append({
            "link_id": edge.get("link_id"),
            "from_queue_lead_id": edge.get("from_queue_lead_id"),
            "to_queue_lead_id": edge.get("to_queue_lead_id"),
            "from_invariant_id": edge.get("from_invariant_id"),
            "to_invariant_id": edge.get("to_invariant_id"),
            "broken_invariant_ids": source_link_invariant_ids([edge]),
            "source_refs": source_link_file_line_refs(edge),
            "from_source_refs": _extract_file_line_tokens(edge.get("from_source_refs")),
            "to_source_refs": _extract_file_line_tokens(edge.get("to_source_refs")),
            "current_queue_verified": _truthy(edge.get("current_queue_verified")),
            "from_output": edge.get("from_output"),
            "to_input": edge.get("to_input"),
            "causality": edge.get("causality"),
            "artifact_path": edge.get("artifact_path"),
            "source_plan_artifact": edge.get("source_plan_artifact"),
        })
    return {
        "schema": PROOF_OBLIGATION_SCHEMA_ID,
        "obligation_id": f"CPO-{decorated['template_id']}",
        "template_id": decorated["template_id"],
        "workspace": str(workspace),
        "generated_at": utc_now(),
        "hop_count": decorated["hop_count"],
        "advancement_status": (
            "advancing" if decorated.get("advances") else "blocked-missing-hop-evidence"
        ),
        "missing_evidence_hops": list(decorated.get("missing_evidence_hops") or []),
        "composition_supported": bool(decorated.get("composition_supported")),
        "composition_support": list(decorated.get("composition_support") or []),
        "hops": [
            {
                "step": i + 1,
                "broken_invariant_id": h["invariant_id"],
                "evidence": h["evidence"],
            }
            for i, h in enumerate(decorated["hops"])
        ],
        "source_backed_edges": source_backed_edges,
        # The composed chain is proven only when ALL hops are jointly demonstrated.
        "proof_status": "pending",
        "discharge_condition": (
            "All hops jointly demonstrated end-to-end: each broken invariant must "
            "be exercised in sequence with the cited evidence reachable under scope."
        ),
    }


def write_proof_obligations(workspace: Path, obligations: list[dict]) -> Path:
    """Persist composed-chain proof obligations (idempotent merge by obligation_id)."""
    path = workspace / PROOF_OBLIGATIONS_FILE
    existing = load_json(path)
    rows: list[dict] = []
    if isinstance(existing, dict):
        rows = existing.get("obligations", []) or []
    elif isinstance(existing, list):
        rows = existing
    by_id = {r.get("obligation_id"): r for r in rows if isinstance(r, dict)}
    for ob in obligations:
        by_id[ob["obligation_id"]] = ob
    doc = {
        "schema": "auditooor.chain_proof_obligations_index.v1",
        "workspace": str(workspace),
        "updated_at": utc_now(),
        "obligations": list(by_id.values()),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2))
    return path


def call_vault_global_chain_template_match(
    repo_root: Path,
    workspace: Path,
    broken_inv_ids: list[str],
    max_matches: int = DEFAULT_MAX_CHAINS,
) -> dict[str, Any]:
    """Call vault_global_chain_template_match via vault-mcp-server.py subprocess."""
    args_payload = {
        "workspace_path": str(workspace),
        "broken_invariant_ids": broken_inv_ids,
        "max_matches": max_matches,
        "min_match_density": 0.25,
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(repo_root / VAULT_SERVER),
            "--call",
            "vault_global_chain_template_match",
            "--args",
            json.dumps(args_payload),
        ],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    if proc.returncode != 0:
        print(f"[chain-synth-driver] vault call failed: {proc.stderr[:300]}", file=sys.stderr)
        return {}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}


def build_batch_jsonl(
    repo_root: Path,
    workspace_handle: str,
    matched_templates: list[dict],
    output_dir: Path,
    dry_run: bool = False,
) -> Path | None:
    """Run deepseek-batch-gen-tok-chain-exploit.py to emit a JSONL batch."""
    matches_payload = {workspace_handle: matched_templates}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="chain_synth_matches_"
    ) as f:
        json.dump(matches_payload, f)
        matches_file = Path(f.name)

    cmd = [
        sys.executable,
        str(repo_root / BATCH_GEN),
        "--matches-json",
        str(matches_file),
        "--output-dir",
        str(output_dir),
        "--max-tuples-per-workspace",
        str(DEFAULT_MAX_CHAINS),
        "--json",
    ]
    before = set(output_dir.glob("*.jsonl")) if output_dir.exists() else set()
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root))
    matches_file.unlink(missing_ok=True)
    if proc.returncode != 0:
        print(f"[chain-synth-driver] batch gen failed: {proc.stderr[:300]}", file=sys.stderr)
        return None
    try:
        summary = json.loads(proc.stdout)
        out_path = Path(str(summary.get("output_path") or ""))
        if out_path.is_file():
            return out_path
    except (json.JSONDecodeError, TypeError, OSError):
        pass
    # Fallback: only accept files created by this generator run. Never reuse a
    # stale batch from an earlier chain-synth invocation.
    batch_files = sorted(
        (p for p in output_dir.glob("*.jsonl") if p not in before),
        key=lambda p: (p.stat().st_mtime, str(p)),
    )
    return batch_files[-1] if batch_files else None


def dispatch_batch(
    repo_root: Path,
    batch_jsonl: Path,
    dry_run: bool = False,
) -> list[dict]:
    """Send each task in the batch to the LLM via llm-dispatch.py --provider mimo."""
    results: list[dict] = []
    tasks = [json.loads(l) for l in batch_jsonl.read_text().splitlines() if l.strip()]
    for i, task in enumerate(tasks):
        prompt = task.get("prompt") or task.get("user_message", "")
        if not prompt:
            continue
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix=f"chain_task_{i}_"
        ) as f:
            f.write(prompt)
            prompt_file = Path(f.name)

        cmd = [
            sys.executable,
            str(repo_root / LLM_DISPATCH),
            "--prompt-file",
            str(prompt_file),
            "--provider",
            "mimo",
            "--max-tokens",
            "1500",
            "--operator-live-network-consent",
            "--task-type",
            "chain-synth",
        ]
        if dry_run:
            results.append({"task_id": task.get("task_id", f"task-{i}"), "dry_run": True, "prompt_len": len(prompt)})
            prompt_file.unlink(missing_ok=True)
            continue

        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root))
        prompt_file.unlink(missing_ok=True)
        if proc.returncode == 0:
            try:
                narrative = json.loads(proc.stdout)
            except json.JSONDecodeError:
                narrative = {"raw": proc.stdout[:2000]}
            results.append({"task_id": task.get("task_id", f"task-{i}"), "narrative": narrative})
        else:
            results.append({"task_id": task.get("task_id", f"task-{i}"), "error": proc.stderr[:300]})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path,
                        help="Audit workspace root (e.g. /Users/wolf/audits/hyperbridge).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build batch JSONL but do not call LLM.")
    parser.add_argument("--json", action="store_true", help="Emit JSON report to stdout.")
    parser.add_argument("--max-chains", type=int, default=DEFAULT_MAX_CHAINS)
    parser.add_argument(
        "--source-link-artifact",
        action="append",
        type=Path,
        default=[],
        help="Explicit source-link artifact to feed chain synthesis without mutating queues.",
    )
    parser.add_argument(
        "--require-hop-evidence",
        dest="require_hop_evidence",
        action="store_true",
        default=True,
        help="Only advance chains where every hop cites a broken invariant + "
             "evidence (file:line / proof-obligation id). On by default (PR8a).",
    )
    parser.add_argument(
        "--no-require-hop-evidence",
        dest="require_hop_evidence",
        action="store_false",
        help="Legacy compatibility only. The driver still gates dispatch on source-backed hop evidence.",
    )
    args = parser.parse_args()
    if not args.require_hop_evidence:
        print(
            "[chain-synth-driver] --no-require-hop-evidence is report-only; "
            "dispatch remains gated on source-backed hop evidence",
            file=sys.stderr,
        )
        args.require_hop_evidence = True

    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 1

    repo_root = Path(__file__).resolve().parent.parent
    source_link_input_paths = candidate_source_link_paths(workspace, args.source_link_artifact)
    input_fingerprints = _input_fingerprints(workspace, source_link_input_paths)
    all_source_link_entries = load_source_link_entries(workspace, args.source_link_artifact)
    current_queue_lead_ids = collect_current_queue_lead_ids(workspace)
    current_queue_lead_invariant_ids = collect_current_queue_lead_invariant_ids(workspace)
    source_link_entries = filter_source_link_entries_for_current_queue(
        all_source_link_entries,
        current_queue_lead_ids,
        current_queue_lead_invariant_ids,
        workspace,
    )
    rejected_source_link_entries = len(all_source_link_entries) - len(source_link_entries)
    source_link_artifacts = sorted({
        str(e.get("artifact_path"))
        for e in all_source_link_entries
        if e.get("artifact_path")
    })
    print(
        f"[chain-synth-driver] source_link_entries: {len(source_link_entries)} "
        f"(rejected_stale_queue={rejected_source_link_entries})",
        file=sys.stderr,
    )

    # Step 1: collect broken_invariant_ids
    broken_ids = collect_broken_invariant_ids(workspace)
    for inv in source_link_invariant_ids(source_link_entries):
        if inv not in broken_ids:
            broken_ids.append(inv)
    print(f"[chain-synth-driver] broken_invariant_ids collected: {len(broken_ids)}", file=sys.stderr)

    if not broken_ids:
        print("[chain-synth-driver] no INV-* ids found in exploit_queue / ccia_angles; "
              "no chain templates can be matched. Run make exploit-queue-update WS=<ws> first.",
              file=sys.stderr)
        report = {
            "schema": SCHEMA_ID,
            "generated_at": utc_now(),
            "workspace": str(workspace),
            "broken_invariant_ids": [],
            "source_link_entries": len(source_link_entries),
            "source_link_entries_total": len(all_source_link_entries),
            "source_link_entries_rejected_stale_queue": rejected_source_link_entries,
            "source_link_artifacts": source_link_artifacts,
            "matched_templates": 0,
            "chains_synthesized": 0,
            "status": "no-invariant-ids",
            "narratives": [],
        }
        report.update(_terminal_observability(
            workspace=workspace,
            input_fingerprints=input_fingerprints,
            current_queue_lead_ids=current_queue_lead_ids,
            current_queue_lead_invariant_ids=current_queue_lead_invariant_ids,
            all_source_link_entries=all_source_link_entries,
            source_link_entries=source_link_entries,
            rejected_source_link_entries=rejected_source_link_entries,
            source_link_artifacts=source_link_artifacts,
            broken_ids=broken_ids,
            max_chains=args.max_chains,
            require_hop_evidence=args.require_hop_evidence,
            dry_run=args.dry_run,
            template_match_status="skipped-no-invariant-ids",
        ))
        report_path = _write_chain_synthesis_report(workspace, report, dry_run=args.dry_run)
        if args.json:
            print(json.dumps(report, indent=2))
        elif not args.dry_run:
            print(f"matched_templates=0 chains_synthesized=0 status=no-invariant-ids report={report_path}")
        return 0

    # Step 2: match templates
    match_result = call_vault_global_chain_template_match(
        repo_root, workspace, broken_ids, args.max_chains
    )
    matched_templates = match_result.get("matched_templates", [])
    if not isinstance(matched_templates, list):
        matched_templates = []
    matched_templates = attach_source_link_edges_to_templates(
        matched_templates, source_link_entries,
    )
    print(f"[chain-synth-driver] matched_templates: {len(matched_templates)}", file=sys.stderr)

    # Per-seed visibility: a (mutation-verified) broken invariant that promoted to
    # a seed but matches no chain template is surfaced, not silently dropped.
    seed_had_no_template = seeds_without_template(broken_ids, matched_templates)
    for inv in seed_had_no_template:
        print(
            f"[chain-synth-driver] seed_had_no_template: {inv} "
            f"(verified break has no matching chain template)",
            file=sys.stderr,
        )

    if not matched_templates:
        report = {
            "schema": SCHEMA_ID,
            "generated_at": utc_now(),
            "workspace": str(workspace),
            "broken_invariant_ids": broken_ids,
            "seed_had_no_template": seed_had_no_template,
            "source_link_entries": len(source_link_entries),
            "source_link_entries_total": len(all_source_link_entries),
            "source_link_entries_rejected_stale_queue": rejected_source_link_entries,
            "source_link_artifacts": source_link_artifacts,
            "matched_templates": 0,
            "chains_synthesized": 0,
            "status": "no-template-matches",
            "narratives": [],
        }
        report.update(_terminal_observability(
            workspace=workspace,
            input_fingerprints=input_fingerprints,
            current_queue_lead_ids=current_queue_lead_ids,
            current_queue_lead_invariant_ids=current_queue_lead_invariant_ids,
            all_source_link_entries=all_source_link_entries,
            source_link_entries=source_link_entries,
            rejected_source_link_entries=rejected_source_link_entries,
            source_link_artifacts=source_link_artifacts,
            broken_ids=broken_ids,
            max_chains=args.max_chains,
            require_hop_evidence=args.require_hop_evidence,
            dry_run=args.dry_run,
            template_match_status="no-template-matches",
            matched_templates=matched_templates,
        ))
        report_path = _write_chain_synthesis_report(workspace, report, dry_run=args.dry_run)
        if args.json:
            print(json.dumps(report, indent=2))
        elif not args.dry_run:
            print(f"matched_templates=0 chains_synthesized=0 status=no-template-matches report={report_path}")
        return 0

    # Step 2b: PR8a proof-seeking - decorate each template with per-hop evidence
    # and gate advancement. A chain only advances if every hop cites a broken
    # invariant, real evidence, and source-backed composition linkage.
    evidence_index = build_invariant_evidence_index(
        workspace, extra_entries=source_link_entries,
    )
    decorated = [
        decorate_template_with_hop_evidence(t, evidence_index)
        for t in matched_templates
    ]
    advancing = [d for d in decorated if d["advances"]]
    blocked = [d for d in decorated if not d["advances"]]
    print(f"[chain-synth-driver] evidence-indexed invariants: {len(evidence_index)} | "
          f"advancing chains: {len(advancing)} | blocked chains: {len(blocked)}",
          file=sys.stderr)

    # Map template_id -> template object so we only dispatch advancing ones.
    advancing_ids = {d["template_id"] for d in advancing}
    dispatch_templates = [
        t for t in matched_templates if _template_id(t) in advancing_ids
    ]

    # Step 2c: enqueue ONE multi-hop proof obligation per composed chain.
    # Advancing chains become harness work. Blocked multi-hop chains become
    # source-mining work unless they are explicitly non-applicable below.
    proof_obligations = [build_chain_proof_obligation(d, workspace) for d in advancing]
    obligations_path = None

    if args.require_hop_evidence and not dispatch_templates:
        non_applicable_no_source_links = _blocked_only_by_absent_source_links(
            blocked=blocked,
            all_source_link_entries=all_source_link_entries,
            source_link_artifacts=source_link_artifacts,
        )
        if not non_applicable_no_source_links:
            proof_obligations.extend(
                build_chain_proof_obligation(d, workspace)
                for d in blocked
                if _blocked_chain_needs_proof_obligation(d)
            )
        if proof_obligations:
            obligations_path = write_proof_obligations(workspace, proof_obligations)
            print(f"[chain-synth-driver] proof obligations written: {obligations_path} "
                  f"({len(proof_obligations)})", file=sys.stderr)
        report = {
            "schema": SCHEMA_ID,
            "generated_at": utc_now(),
            "workspace": str(workspace),
            "broken_invariant_ids": broken_ids,
            "seed_had_no_template": seed_had_no_template,
            "source_link_entries": len(source_link_entries),
            "source_link_entries_total": len(all_source_link_entries),
            "source_link_entries_rejected_stale_queue": rejected_source_link_entries,
            "source_link_artifacts": source_link_artifacts,
            "matched_templates": len(matched_templates),
            "advancing_chains": 0,
            "blocked_chains": [
                {"template_id": d["template_id"],
                 "missing_evidence_hops": d["missing_evidence_hops"],
                 "composition_supported": d["composition_supported"],
                 "composition_support": d["composition_support"]}
                for d in blocked
            ],
            "proof_obligations": len(proof_obligations),
            "proof_obligations_path": str(obligations_path) if obligations_path else None,
            "require_hop_evidence": args.require_hop_evidence,
            "chains_synthesized": 0,
            "status": "blocked-missing-hop-evidence",
        }
        if non_applicable_no_source_links:
            report.update({
                "applicability_verdict": "pass-not-applicable",
                "applicability_reason": (
                    "matched templates require source-backed composition links, "
                    "but no source-link artifact or source-link entries exist for this workspace"
                ),
            })
        report.update(_terminal_observability(
            workspace=workspace,
            input_fingerprints=input_fingerprints,
            current_queue_lead_ids=current_queue_lead_ids,
            current_queue_lead_invariant_ids=current_queue_lead_invariant_ids,
            all_source_link_entries=all_source_link_entries,
            source_link_entries=source_link_entries,
            rejected_source_link_entries=rejected_source_link_entries,
            source_link_artifacts=source_link_artifacts,
            broken_ids=broken_ids,
            max_chains=args.max_chains,
            require_hop_evidence=args.require_hop_evidence,
            dry_run=args.dry_run,
            template_match_status="matched",
            matched_templates=matched_templates,
            evidence_index=evidence_index,
            decorated=decorated,
            advancing=advancing,
            blocked=blocked,
            proof_obligations=proof_obligations,
            dispatch_templates=dispatch_templates,
        ))
        report_path = _write_chain_synthesis_report(workspace, report, dry_run=args.dry_run)
        print(f"[chain-synth-driver] report written: {report_path}", file=sys.stderr)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"matched_templates={len(matched_templates)} advancing=0 "
                  f"blocked={len(blocked)} status=blocked-missing-hop-evidence "
                  f"report={report_path}")
        return 0

    if proof_obligations:
        obligations_path = write_proof_obligations(workspace, proof_obligations)
        print(f"[chain-synth-driver] proof obligations written: {obligations_path} "
              f"({len(proof_obligations)})", file=sys.stderr)

    # Step 3: build batch JSONL (advancing chains only when gating is on)
    workspace_handle = workspace.name
    batch_dir = workspace / ".auditooor" / "tok_chain_batch"
    batch_dir.mkdir(parents=True, exist_ok=True)
    batch_file = build_batch_jsonl(
        repo_root, workspace_handle, dispatch_templates, batch_dir, dry_run=args.dry_run
    )
    if batch_file is None:
        print("[chain-synth-driver] batch generation failed", file=sys.stderr)
        report = {
            "schema": SCHEMA_ID,
            "generated_at": utc_now(),
            "workspace": str(workspace),
            "broken_invariant_ids": broken_ids,
            "seed_had_no_template": seed_had_no_template,
            "source_link_entries": len(source_link_entries),
            "source_link_entries_total": len(all_source_link_entries),
            "source_link_entries_rejected_stale_queue": rejected_source_link_entries,
            "source_link_artifacts": source_link_artifacts,
            "matched_templates": len(matched_templates),
            "advancing_chains": len(advancing),
            "blocked_chains": [
                {"template_id": d["template_id"],
                 "missing_evidence_hops": d["missing_evidence_hops"],
                 "composition_supported": d["composition_supported"],
                 "composition_support": d["composition_support"]}
                for d in blocked
            ],
            "proof_obligations": len(proof_obligations),
            "proof_obligations_path": str(obligations_path) if obligations_path else None,
            "require_hop_evidence": args.require_hop_evidence,
            "batch_jsonl": None,
            "chains_synthesized": 0,
            "dry_run": args.dry_run,
            "status": "batch-generation-failed",
            "dispatch_errors": 0,
            "dispatch_results": [],
            "narratives": [],
        }
        report.update(_terminal_observability(
            workspace=workspace,
            input_fingerprints=input_fingerprints,
            current_queue_lead_ids=current_queue_lead_ids,
            current_queue_lead_invariant_ids=current_queue_lead_invariant_ids,
            all_source_link_entries=all_source_link_entries,
            source_link_entries=source_link_entries,
            rejected_source_link_entries=rejected_source_link_entries,
            source_link_artifacts=source_link_artifacts,
            broken_ids=broken_ids,
            max_chains=args.max_chains,
            require_hop_evidence=args.require_hop_evidence,
            dry_run=args.dry_run,
            template_match_status="matched",
            matched_templates=matched_templates,
            evidence_index=evidence_index,
            decorated=decorated,
            advancing=advancing,
            blocked=blocked,
            proof_obligations=proof_obligations,
            dispatch_templates=dispatch_templates,
        ))
        report_path = _write_chain_synthesis_report(workspace, report, dry_run=False)
        print(f"[chain-synth-driver] report written: {report_path}", file=sys.stderr)
        if args.json:
            print(json.dumps(report, indent=2))
        return 1
    print(f"[chain-synth-driver] batch JSONL: {batch_file}", file=sys.stderr)

    # Step 4: dispatch + collect narratives
    dispatch_results = dispatch_batch(repo_root, batch_file, dry_run=args.dry_run)
    dispatch_errors = [
        row for row in dispatch_results
        if isinstance(row, dict) and row.get("error")
    ]
    narratives = [
        row for row in dispatch_results
        if _is_successful_chain_narrative(row)
    ]
    if args.dry_run:
        status = "dry-run"
    elif dispatch_results and not narratives:
        status = "dispatch-failed" if dispatch_errors else "dispatch-no-successful-narratives"
    elif dispatch_errors:
        status = "complete-with-dispatch-errors"
    else:
        status = "complete"

    # Write report
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_path = workspace / ".auditooor" / f"chain_synthesis_{date_str}.json"
    report = {
        "schema": SCHEMA_ID,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "broken_invariant_ids": broken_ids,
        "seed_had_no_template": seed_had_no_template,
        "source_link_entries": len(source_link_entries),
        "source_link_entries_total": len(all_source_link_entries),
        "source_link_entries_rejected_stale_queue": rejected_source_link_entries,
        "source_link_artifacts": source_link_artifacts,
        "matched_templates": len(matched_templates),
        "advancing_chains": len(advancing),
        "blocked_chains": [
            {"template_id": d["template_id"],
             "missing_evidence_hops": d["missing_evidence_hops"],
             "composition_supported": d["composition_supported"],
             "composition_support": d["composition_support"]}
            for d in blocked
        ],
        "proof_obligations": len(proof_obligations),
        "proof_obligations_path": str(obligations_path) if obligations_path else None,
        "require_hop_evidence": args.require_hop_evidence,
        "batch_jsonl": str(batch_file),
        "chains_synthesized": len(narratives),
        "dry_run": args.dry_run,
        "status": status,
        "dispatch_errors": len(dispatch_errors),
        "dispatch_results": dispatch_results,
        "narratives": narratives,
    }
    report.update(_terminal_observability(
        workspace=workspace,
        input_fingerprints=input_fingerprints,
        current_queue_lead_ids=current_queue_lead_ids,
        current_queue_lead_invariant_ids=current_queue_lead_invariant_ids,
        all_source_link_entries=all_source_link_entries,
        source_link_entries=source_link_entries,
        rejected_source_link_entries=rejected_source_link_entries,
        source_link_artifacts=source_link_artifacts,
        broken_ids=broken_ids,
        max_chains=args.max_chains,
        require_hop_evidence=args.require_hop_evidence,
        dry_run=args.dry_run,
        template_match_status="matched",
        matched_templates=matched_templates,
        evidence_index=evidence_index,
        decorated=decorated,
        advancing=advancing,
        blocked=blocked,
        proof_obligations=proof_obligations,
        dispatch_templates=dispatch_templates,
        batch_file=batch_file,
        dispatch_results=dispatch_results,
        dispatch_errors=dispatch_errors,
        narratives=narratives,
    ))
    report_path.write_text(json.dumps(report, indent=2))
    print(f"[chain-synth-driver] report written: {report_path}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"matched_templates={len(matched_templates)} "
              f"chains_synthesized={len(narratives)} "
              f"report={report_path}")
    return 1 if status in {"dispatch-failed", "dispatch-no-successful-narratives"} else 0


if __name__ == "__main__":
    sys.exit(main())
