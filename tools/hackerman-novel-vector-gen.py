#!/usr/bin/env python3
"""Generate bounded advisory novel-vector hypotheses from Hackerman corpus data.

Lane W6-5 / H5-4 first useful pass.

Model
-----
The generator is conservative and corpus-only:

* it reads validated Hackerman corpus records plus composable predicate state
  from `hackerman-predicate-compose.py`;
* it finds analogue records on structurally similar shapes
  (same language/domain, overlapping shape tags);
* for each target repo, it subtracts attack classes the repo already carries;
* the residual classes become advisory "untried but plausible" hypotheses.

Every emitted hypothesis cites the nearest analogue record, carries analogue
preconditions plus typed state-token preconditions, attempts to build a local
"possible chain" from target-repo producers whose `yields_state` satisfy the
analogue's `requires_state`, and emits bounded proof obligations.

Boundary
--------
This tool is NOT a submission-readiness surface. Output is advisory only and
intended to seed local audit worklists. It does not claim exploitability,
severity, or acceptance.

Usage
-----
    python3 tools/hackerman-novel-vector-gen.py --tag-dir audit/corpus_tags/tags
    python3 tools/hackerman-novel-vector-gen.py --tag-dir <dir> --json
    python3 tools/hackerman-novel-vector-gen.py --tag-dir <dir> --target-repo owner/repo --json
    python3 tools/hackerman-novel-vector-gen.py --tag-dir <dir> --target-repo owner/repo --same-class-variants --json
    python3 tools/hackerman-novel-vector-gen.py --tag-dir <dir> --out agent_outputs/novel_vectors.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_DERIVED_DIR = REPO_ROOT / "audit" / "corpus_tags" / "derived"
EXPLOIT_PREDICATES_SIDECAR = DEFAULT_DERIVED_DIR / "exploit_predicates.jsonl"
CHAIN_CANDIDATES_SIDECAR = DEFAULT_DERIVED_DIR / "chain_candidates.jsonl"
SCHEMA = "auditooor.hackerman_novel_vector_hypothesis.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_novel_vector_hypotheses.summary.v1"
MAX_LIMIT = 100
DEFAULT_MAX_TARGETS = 500
MAX_BRIDGES_PER_HYPOTHESIS = 2
MAX_PRECONDITIONS_PER_HYPOTHESIS = 6
MAX_PROOF_OBLIGATIONS = 8
MAX_TARGET_PREVIEW = 12


def _load_module(file_name: str, mod_name: str) -> Any:
    path = TOOLS_DIR / file_name
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {file_name}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_PREDS = _load_module("hackerman-exploit-predicates.py", "_w65_exploit_predicates")
_PRED_COMPOSE = _load_module("hackerman-predicate-compose.py", "_w65_predicate_compose")


def stable_hash(payload: Any, length: int = 16) -> str:
    data = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:length]


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _slug(value: Any) -> str:
    text = _as_text(value).lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")


def _severity_weight(value: str) -> float:
    return {
        "critical": 5.0,
        "high": 4.0,
        "medium": 2.5,
        "low": 1.0,
        "info": 0.25,
    }.get(_slug(value), 0.5)


def _component_name(component: str) -> str:
    tail = component.rsplit("/", 1)[-1]
    return tail.rsplit(".", 1)[-1]


def _shape_overlap(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _load_raw_records(tag_dir: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    validator = getattr(_PREDS, "_validate_record")
    recognised = set(getattr(_PREDS, "RECOGNISED_SCHEMA_VERSIONS"))
    yaml_load = getattr(_PREDS, "yaml_load")
    for path in sorted(list(tag_dir.glob("*.yaml")) + list(tag_dir.glob("*.yml"))):
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict) or doc.get("schema_version") not in recognised:
            continue
        if validator(doc):
            continue
        record_id = _as_text(doc.get("record_id"))
        if not record_id:
            continue
        records[record_id] = {"tag_path": path, "doc": doc}
    return records


def _iter_jsonl(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def _impact_class_from_structural(row: dict[str, Any]) -> str:
    impacts = row.get("impacts")
    if isinstance(impacts, list) and impacts and isinstance(impacts[0], dict):
        return _as_text(impacts[0].get("impact_class"))
    return ""


def _severity_from_structural(row: dict[str, Any]) -> str:
    impacts = row.get("impacts")
    if isinstance(impacts, list) and impacts and isinstance(impacts[0], dict):
        return _as_text(impacts[0].get("severity_at_finding"))
    return ""


def _shape_tags_from_sidecar(row: dict[str, Any], chain_row: dict[str, Any] | None) -> list[str]:
    tags: set[str] = set()
    if chain_row is not None:
        for pattern in chain_row.get("patterns") or []:
            value = _slug(pattern)
            if value:
                tags.add(value)
    for fallback in (
        row.get("target_component"),
        row.get("bug_class"),
        row.get("attack_class"),
    ):
        value = _slug(fallback)
        if value:
            tags.add(value)
    return sorted(tags)


def _catalog_record_from_structural(
    row: dict[str, Any],
    node: dict[str, Any],
    *,
    shape_tags: list[str],
) -> dict[str, Any]:
    return {
        "record_id": _as_text(row.get("record_id")),
        "source_audit_ref": _as_text(row.get("source_audit_ref")),
        "tag_file": _as_text(row.get("tag_file")),
        "target_repo": _as_text(row.get("target_repo")),
        "target_domain": _as_text(row.get("target_domain")),
        "target_language": _as_text(row.get("target_language")),
        "target_component": _as_text(row.get("target_component")),
        "component_name": _component_name(_as_text(row.get("target_component"))),
        "raw_signature": "",
        "shape_tags": shape_tags,
        "shape_tag_set": set(shape_tags),
        "bug_class": _as_text(row.get("bug_class")),
        "attack_class": _as_text(row.get("attack_class")),
        "attacker_role": _as_text(row.get("attacker_role")),
        "impact_class": _impact_class_from_structural(row),
        "severity_at_finding": _severity_from_structural(row),
        "required_preconditions": [
            _as_text(value)
            for value in (row.get("preconditions") or [])
            if _as_text(value)
        ],
        "actions": list(row.get("actions") or []),
        "requires_state": list(node.get("requires_state") or []),
        "yields_state": list(node.get("yields_state") or []),
        "composable": bool(node.get("composable")),
        "predicate_id": _as_text(node.get("predicate_id")),
    }


def _iter_sidecar_rows(monolith_path: Path) -> Any:
    """Yield record rows from a sidecar, preferring the sharded manifest.

    CAP-GAP-35-HACKER-MCP-USABILITY (2026-05-26): the original
    implementation read ONLY the monolithic JSONL. Once a sidecar grows
    past the 95MB size hard limit (R37 / hackerman size-cap discipline)
    the build pipeline switches to a sharded layout
    (``<stem>.manifest.json`` + ``<stem>.d/shard-*.jsonl``) and the
    monolith becomes stale. The novel-vector catalog then silently lost
    every record emitted after the cap was hit (including all records
    emitted by ``tools/hackerman-target-as-destination-ingest.py``).

    This helper reads from the sharded manifest when present (and reads
    every shard in manifest order), falling back to the monolith only
    when no manifest exists.
    """
    manifest_path = monolith_path.with_name(f"{monolith_path.stem}.manifest.json")
    shard_dir = monolith_path.with_name(f"{monolith_path.stem}.d")
    if manifest_path.is_file() and shard_dir.is_dir():
        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest_data = None
        shards = []
        if isinstance(manifest_data, dict):
            for shard in manifest_data.get("shards") or []:
                if not isinstance(shard, dict):
                    continue
                rel = shard.get("path")
                if not isinstance(rel, str) or not rel:
                    continue
                shards.append(shard_dir / rel)
        if not shards:
            shards = sorted(shard_dir.glob("shard-*.jsonl"))
        for shard_path in shards:
            if not shard_path.is_file():
                continue
            yield from _iter_jsonl(shard_path)
        return
    if monolith_path.is_file():
        yield from _iter_jsonl(monolith_path)


def _build_catalog_from_sidecars() -> list[dict[str, Any]]:
    if not EXPLOIT_PREDICATES_SIDECAR.is_file() or not CHAIN_CANDIDATES_SIDECAR.is_file():
        eps_manifest = EXPLOIT_PREDICATES_SIDECAR.with_name(
            f"{EXPLOIT_PREDICATES_SIDECAR.stem}.manifest.json"
        )
        ccs_manifest = CHAIN_CANDIDATES_SIDECAR.with_name(
            f"{CHAIN_CANDIDATES_SIDECAR.stem}.manifest.json"
        )
        if not (eps_manifest.is_file() and ccs_manifest.is_file()):
            return []
    structural_rows: dict[str, dict[str, Any]] = {}
    for row in _iter_sidecar_rows(EXPLOIT_PREDICATES_SIDECAR):
        record_id = _as_text(row.get("record_id"))
        if not record_id:
            continue
        structural_rows[record_id] = row
    chain_rows: dict[str, dict[str, Any]] = {}
    for row in _iter_sidecar_rows(CHAIN_CANDIDATES_SIDECAR):
        record_id = _as_text(row.get("record_id"))
        if not record_id:
            continue
        chain_rows[record_id] = row

    catalog: list[dict[str, Any]] = []
    for record_id in sorted(structural_rows):
        row = structural_rows[record_id]
        try:
            node = _PRED_COMPOSE.compose_record(row)
        except Exception:
            continue
        shape_tags = _shape_tags_from_sidecar(row, chain_rows.get(record_id))
        if not shape_tags:
            continue
        catalog.append(_catalog_record_from_structural(row, node, shape_tags=shape_tags))
    return catalog


def _build_catalog(tag_dir: Path) -> list[dict[str, Any]]:
    try:
        if tag_dir.resolve() == DEFAULT_TAG_DIR.resolve():
            sidecar_catalog = _build_catalog_from_sidecars()
            if sidecar_catalog:
                return sidecar_catalog
    except OSError:
        pass
    raw_records = _load_raw_records(tag_dir)

    catalog: list[dict[str, Any]] = []
    for record_id in sorted(raw_records):
        tag_path = raw_records[record_id]["tag_path"]
        raw = raw_records[record_id]["doc"]
        try:
            row = _PREDS.extract_record(tag_path, raw)
            node = _PRED_COMPOSE.compose_record(row)
        except Exception:
            continue
        function_shape = raw.get("function_shape") if isinstance(raw.get("function_shape"), dict) else {}
        shape_tags = sorted(
            {
                _slug(tag)
                for tag in (function_shape.get("shape_tags") or [])
                if _as_text(tag)
            }
        )
        record = {
            "record_id": record_id,
            "source_audit_ref": _as_text(raw.get("source_audit_ref")),
            "tag_file": _as_text(row.get("tag_file")),
            "target_repo": _as_text(raw.get("target_repo")),
            "target_domain": _as_text(raw.get("target_domain")),
            "target_language": _as_text(raw.get("target_language")),
            "target_component": _as_text(raw.get("target_component")),
            "component_name": _component_name(_as_text(raw.get("target_component"))),
            "raw_signature": _as_text(function_shape.get("raw_signature")),
            "shape_tags": shape_tags,
            "shape_tag_set": set(shape_tags),
            "bug_class": _as_text(raw.get("bug_class")),
            "attack_class": _as_text(raw.get("attack_class")),
            "attacker_role": _as_text(raw.get("attacker_role")),
            "impact_class": _as_text(raw.get("impact_class")),
            "severity_at_finding": _as_text(raw.get("severity_at_finding")),
            "required_preconditions": [
                _as_text(value)
                for value in (raw.get("required_preconditions") or [])
                if _as_text(value)
            ],
            "actions": list(row.get("actions") or []),
            "requires_state": list(node.get("requires_state") or []),
            "yields_state": list(node.get("yields_state") or []),
            "composable": bool(node.get("composable")),
            "predicate_id": _as_text(node.get("predicate_id")),
        }
        catalog.append(record)
    return catalog


def _candidate_sources(
    target: dict[str, Any],
    tag_index: dict[tuple[str, str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    lang = target["target_language"]
    domain = target["target_domain"]
    for tag in target["shape_tags"]:
        for record in tag_index.get((lang, domain, tag), []):
            if record["record_id"] == target["record_id"]:
                continue
            candidates[record["record_id"]] = record
    return sorted(candidates.values(), key=lambda row: row["record_id"])


def _local_bridges(
    target: dict[str, Any],
    source: dict[str, Any],
    by_repo: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    needs = set(source["requires_state"])
    if not needs:
        return []
    bridges: list[dict[str, Any]] = []
    for record in by_repo.get(target["target_repo"], []):
        if record["record_id"] == target["record_id"]:
            continue
        matched = sorted(set(record["yields_state"]) & needs)
        if not matched:
            continue
        bridges.append(
            {
                "record_id": record["record_id"],
                "attack_class": record["attack_class"],
                "bug_class": record["bug_class"],
                "target_component": record["target_component"],
                "matched_state": matched,
                "source_audit_ref": record["source_audit_ref"],
                "score": (
                    len(matched),
                    _severity_weight(record["severity_at_finding"]),
                    record["record_id"],
                ),
            }
        )
    bridges.sort(key=lambda item: (-item["score"][0], -item["score"][1], item["record_id"]))
    return bridges[:MAX_BRIDGES_PER_HYPOTHESIS]


def _build_preconditions(source: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for token in sorted(set(source["requires_state"])):
        out.append({"kind": "state_token", "value": token})
    for text in source["required_preconditions"]:
        out.append({"kind": "analogue_precondition", "value": text})
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in out:
        key = (entry["kind"], entry["value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
        if len(deduped) >= MAX_PRECONDITIONS_PER_HYPOTHESIS:
            break
    return deduped


def _build_possible_chain(
    target: dict[str, Any],
    source: dict[str, Any],
    bridges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for index, bridge in enumerate(bridges, start=1):
        chain.append(
            {
                "step_index": index,
                "step_type": "local_bridge",
                "record_id": bridge["record_id"],
                "attack_class": bridge["attack_class"],
                "bug_class": bridge["bug_class"],
                "target_component": bridge["target_component"],
                "matched_state": bridge["matched_state"],
                "narrative": (
                    f"Local record `{bridge['record_id']}` yields "
                    f"{', '.join(bridge['matched_state'])}, which can satisfy part of the "
                    f"analogue precondition set for `{source['attack_class']}`."
                ),
            }
        )
    chain.append(
        {
            "step_index": len(chain) + 1,
            "step_type": "hypothesis",
            "record_id": "",
            "attack_class": source["attack_class"],
            "bug_class": source["bug_class"],
            "target_component": target["target_component"],
            "matched_state": sorted(set(source["requires_state"])),
            "narrative": (
                f"Inspect `{target['target_component']}` in `{target['target_repo']}` for the "
                f"untried `{source['attack_class']}` vector, using `{source['record_id']}` "
                "as the nearest same-shape analogue."
            ),
        }
    )
    return chain


def _build_proof_obligations(
    target: dict[str, Any],
    source: dict[str, Any],
    bridges: list[dict[str, Any]],
) -> list[dict[str, str]]:
    obligations: list[dict[str, str]] = [
        {
            "kind": "shape_match",
            "obligation": (
                f"Confirm `{target['target_component']}` still matches analogue shape tags "
                f"{', '.join(source['shape_tags']) or '(none)'}` from `{source['record_id']}`."
            ),
            "evidence_hint": "function signature and shape-tag trace in target source",
        }
    ]
    for token in sorted(set(source["requires_state"])):
        obligations.append(
            {
                "kind": "state_precondition",
                "obligation": (
                    f"Prove target-local reachability of required state token `{token}` before "
                    f"the hypothesised `{source['attack_class']}` step."
                ),
                "evidence_hint": "caller/state trace or executable assertion",
            }
        )
    for text in source["required_preconditions"]:
        obligations.append(
            {
                "kind": "analogue_precondition",
                "obligation": (
                    f"Translate analogue precondition onto the target path: {text}"
                ),
                "evidence_hint": "target-specific source citation or harness setup",
            }
        )
    for bridge in bridges:
        obligations.append(
            {
                "kind": "chain_bridge",
                "obligation": (
                    f"Show `{bridge['record_id']}` can establish "
                    f"{', '.join(bridge['matched_state'])}` before the target path reaches "
                    f"`{target['target_component']}`."
                ),
                "evidence_hint": "ordered call/state sequence in the target repo",
            }
        )
    obligations.append(
        {
            "kind": "impact_path",
            "obligation": (
                f"Demonstrate that the target path can realize analogue impact class "
                f"`{source['impact_class'] or 'unknown'}` if the preconditions hold."
            ),
            "evidence_hint": "fund/accounting/state transition trace",
        }
    )
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in obligations:
        key = (item["kind"], item["obligation"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= MAX_PROOF_OBLIGATIONS:
            break
    return deduped


def _score_candidate(
    target: dict[str, Any],
    source: dict[str, Any],
    bridges: list[dict[str, Any]],
    overlap: float,
) -> dict[str, float]:
    bridge_tokens = len({token for bridge in bridges for token in bridge["matched_state"]})
    exact_component_bonus = 1.0 if target["component_name"] == source["component_name"] else 0.0
    score = round(
        overlap * 6.0
        + bridge_tokens * 1.5
        + min(len(source["requires_state"]), 3) * 0.35
        + _severity_weight(source["severity_at_finding"]) * 0.4
        + exact_component_bonus,
        3,
    )
    return {
        "score": score,
        "shape_overlap": round(overlap, 3),
        "bridge_token_count": float(bridge_tokens),
        "exact_component_bonus": exact_component_bonus,
        "analogue_severity_weight": _severity_weight(source["severity_at_finding"]),
    }


def _same_class_variant_assessment(
    target: dict[str, Any],
    source: dict[str, Any],
    by_repo: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    same_class = [
        record
        for record in by_repo.get(target["target_repo"], [])
        if record["attack_class"] == source["attack_class"]
    ]
    target_shape = set(target.get("shape_tag_set") or [])
    target_component = target.get("target_component")
    local_components = {record.get("target_component") for record in same_class}
    max_local_shape_overlap = 0.0
    for record in same_class:
        max_local_shape_overlap = max(
            max_local_shape_overlap,
            _shape_overlap(target_shape, set(record.get("shape_tag_set") or [])),
        )

    distinct_component = target_component not in local_components
    distinct_shape = bool(target_shape) and max_local_shape_overlap < 1.0
    enabled = bool(same_class) and (distinct_component or distinct_shape)
    signals: list[str] = []
    if distinct_component:
        signals.append("distinct_target_component")
    if distinct_shape:
        signals.append("distinct_function_shape")
    if source["target_component"] != target_component:
        signals.append("cross_repo_analogue_component")
    local_refs = [
        {
            "record_id": record["record_id"],
            "target_component": record["target_component"],
            "shape_tags": record["shape_tags"],
            "source_audit_ref": record["source_audit_ref"],
        }
        for record in same_class[:MAX_TARGET_PREVIEW]
    ]
    return {
        "enabled": enabled,
        "signals": signals,
        "distinct_component": distinct_component,
        "distinct_shape": distinct_shape,
        "max_local_shape_overlap": round(max_local_shape_overlap, 3),
        "local_same_class_count": len(same_class),
        "local_same_class_refs": local_refs,
    }


def _target_selection_score(
    record: dict[str, Any],
    tag_index: dict[tuple[str, str, str], list[dict[str, Any]]],
    repo_yields_union: dict[str, set[str]],
) -> dict[str, float]:
    """Heuristic used only for bounded scans (max_targets).

    When we only inspect N target records, prefer targets that are likely to
    surface analogues (shared shape tags) and have some repo-local "producer"
    coverage (yielded state tokens) for bridge building.
    """
    lang = record["target_language"]
    domain = record["target_domain"]
    analogue_pool = 0
    for tag in record["shape_tags"]:
        analogue_pool += max(0, len(tag_index.get((lang, domain, tag), [])) - 1)
    local_yields = len(repo_yields_union.get(record["target_repo"], set()))
    score = (
        analogue_pool * 1.0
        + len(record["shape_tags"]) * 0.75
        + min(local_yields, 25) * 0.15
        + _severity_weight(record.get("severity_at_finding") or "") * 0.1
    )
    return {
        "score": round(float(score), 3),
        "analogue_pool": float(analogue_pool),
        "shape_tag_count": float(len(record["shape_tags"])),
        "repo_yield_token_count": float(local_yields),
    }


def _empty_state_diagnostics(payload: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    next_steps: list[str] = []

    candidate_pairs_seen = int(payload.get("candidate_pairs_seen", 0) or 0)
    filtered_same_repo = int(payload.get("filtered_same_repo", 0) or 0)
    filtered_existing_class = int(payload.get("filtered_existing_class", 0) or 0)
    filtered_min_shape_overlap = int(payload.get("filtered_min_shape_overlap", 0) or 0)
    candidate_pairs_considered = int(payload.get("candidate_pairs_considered", 0) or 0)
    filtered_no_bridge = int(payload.get("filtered_no_bridge", 0) or 0)
    remote_pairs = max(0, candidate_pairs_seen - filtered_same_repo)
    remote_after_existing = max(0, remote_pairs - filtered_existing_class)

    if payload.get("total_target_candidates", 0) == 0:
        reasons.append("No target records matched the target-repo/language/domain filters.")
        next_steps.append("Broaden filters (omit --domain/--language) or loosen --target-repo substring.")
        next_steps.append("Confirm your target repo is present in the corpus tag set for the selected --tag-dir.")
        return {"status": "no_targets", "reasons": reasons, "next_steps": next_steps}

    if payload.get("targets_truncated"):
        next_steps.append("Increase --max-targets (e.g. 50-200) or use --all-targets for a full sweep.")

    if candidate_pairs_seen == 0:
        reasons.append("No same-language/domain analogue candidates were found for the considered targets.")
        next_steps.append("Lower --min-shape-overlap (e.g. 0.33) to admit looser shape matches.")
        next_steps.append("Broaden --domain (or omit it) to allow analogues from adjacent domains.")
        return {"status": "no_analogues", "reasons": reasons, "next_steps": next_steps}

    if remote_pairs == 0:
        reasons.append("All analogue candidates were from the same target repo (no cross-repo analogues for these tags).")
        next_steps.append("Broaden the target slice (omit --domain/--language) to pick up other domains/languages with more analogues.")

    if candidate_pairs_considered == 0 and filtered_min_shape_overlap > 0:
        reasons.append("No cross-repo candidates met --min-shape-overlap for hypothesis generation.")
        next_steps.append("Lower --min-shape-overlap (e.g. 0.33) to admit looser shape matches.")

    if remote_after_existing == 0 and remote_pairs > 0:
        reasons.append("All cross-repo analogue candidates were suppressed because their attack_class is already present in the target repo.")
        next_steps.append("Verify the target repo's attack_class coverage in the corpus is complete; missing records skew subtraction.")

    if filtered_no_bridge >= max(1, candidate_pairs_considered):
        reasons.append("No local bridge steps were found for the candidates that passed shape overlap.")
        next_steps.append("Increase --max-targets so more local 'producer' records can be discovered for bridge building.")
        next_steps.append("If using default tag dir, regenerate sidecars (exploit predicates / chain candidates) and retry.")

    if not reasons:
        reasons.append("No hypotheses met the conservative emission criteria.")
        next_steps.append("Increase --max-targets and lower --min-shape-overlap for exploratory advisory output.")

    return {"status": "empty", "reasons": reasons[:4], "next_steps": next_steps[:5]}


def build_payload(
    tag_dir: Path,
    *,
    limit: int = 20,
    target_repo: str = "",
    language: str = "",
    domain: str = "",
    min_shape_overlap: float = 0.5,
    max_targets: int | None = DEFAULT_MAX_TARGETS,
    same_class_variants: bool = False,
    exclude_target_repos: list[str] | None = None,
) -> dict[str, Any]:
    limit = max(1, min(int(limit), MAX_LIMIT))
    target_scan_limit = None if max_targets is None else max(1, int(max_targets))
    catalog = _build_catalog(tag_dir)
    tag_index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    by_repo: dict[str, list[dict[str, Any]]] = {}
    repo_classes: dict[str, set[str]] = {}
    for record in catalog:
        by_repo.setdefault(record["target_repo"], []).append(record)
        repo_classes.setdefault(record["target_repo"], set()).add(record["attack_class"])
        for tag in record["shape_tags"]:
            tag_index.setdefault(
                (record["target_language"], record["target_domain"], tag),
                [],
            ).append(record)

    repo_yields_union: dict[str, set[str]] = {}
    for repo, rows in by_repo.items():
        union: set[str] = set()
        for row in rows:
            union.update(row.get("yields_state") or [])
        repo_yields_union[repo] = union

    target_repo_norm = _as_text(target_repo).lower()
    language_norm = _as_text(language)
    domain_norm = _as_text(domain)
    # CAP-HACKER-MCP-SUITE-FIX-2026-05-26: filter out dominant repos (e.g.
    # cantina-audit/openvm with ~9k analogues per record) that would otherwise
    # monopolize the bounded scan. Substring match on lowercased target_repo.
    exclude_norm = [
        item.strip().lower()
        for item in (exclude_target_repos or [])
        if isinstance(item, str) and item.strip()
    ]

    filtered_target_repo = 0
    filtered_target_language = 0
    filtered_target_domain = 0
    filtered_target_missing_shape = 0
    filtered_target_excluded_repo = 0

    candidate_pairs_considered = 0
    candidate_pairs_seen = 0
    filtered_same_repo = 0
    filtered_min_shape_overlap = 0
    filtered_existing_class = 0
    same_class_variant_candidates = 0
    same_class_variants_emitted = 0
    filtered_no_bridge = 0
    hypotheses_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    target_candidates: list[dict[str, Any]] = []
    for record in catalog:
        if target_repo_norm and target_repo_norm not in _as_text(record.get("target_repo")).lower():
            filtered_target_repo += 1
            continue
        if exclude_norm:
            record_repo_lower = _as_text(record.get("target_repo")).lower()
            if any(pattern in record_repo_lower for pattern in exclude_norm):
                filtered_target_excluded_repo += 1
                continue
        if language_norm and language_norm != _as_text(record.get("target_language")):
            filtered_target_language += 1
            continue
        if domain_norm and domain_norm != _as_text(record.get("target_domain")):
            filtered_target_domain += 1
            continue
        if not record.get("shape_tags"):
            filtered_target_missing_shape += 1
            continue
        target_candidates.append(record)
    total_target_candidates = len(target_candidates)
    targets_truncated = False
    target_selection_preview: list[dict[str, Any]] = []
    if target_scan_limit is not None and len(target_candidates) > target_scan_limit:
        scored: list[tuple[float, str, dict[str, Any], dict[str, float]]] = []
        for record in target_candidates:
            breakdown = _target_selection_score(record, tag_index, repo_yields_union)
            scored.append((float(breakdown["score"]), record["record_id"], record, breakdown))
        scored.sort(key=lambda item: (-item[0], item[1]))
        target_candidates = [item[2] for item in scored[:target_scan_limit]]
        for _, _, record, breakdown in scored[: min(len(scored), MAX_TARGET_PREVIEW)]:
            target_selection_preview.append(
                {
                    "record_id": record["record_id"],
                    "target_repo": record["target_repo"],
                    "target_component": record["target_component"],
                    "target_language": record["target_language"],
                    "target_domain": record["target_domain"],
                    "selection_score": breakdown["score"],
                    "selection_breakdown": breakdown,
                }
            )
        targets_truncated = True
    targets_considered = len(target_candidates)
    if not target_selection_preview:
        for record in target_candidates[: min(len(target_candidates), MAX_TARGET_PREVIEW)]:
            breakdown = _target_selection_score(record, tag_index, repo_yields_union)
            target_selection_preview.append(
                {
                    "record_id": record["record_id"],
                    "target_repo": record["target_repo"],
                    "target_component": record["target_component"],
                    "target_language": record["target_language"],
                    "target_domain": record["target_domain"],
                    "selection_score": breakdown["score"],
                    "selection_breakdown": breakdown,
                }
            )

    for target in target_candidates:
        for source in _candidate_sources(target, tag_index):
            candidate_pairs_seen += 1
            if source["target_repo"] == target["target_repo"]:
                filtered_same_repo += 1
                continue
            overlap = _shape_overlap(target["shape_tag_set"], source["shape_tag_set"])
            if overlap < min_shape_overlap:
                filtered_min_shape_overlap += 1
                continue
            generation_mode = "residual_novel_class"
            variant_assessment: dict[str, Any] | None = None
            if source["attack_class"] in repo_classes.get(target["target_repo"], set()):
                filtered_existing_class += 1
                if not same_class_variants:
                    continue
                variant_assessment = _same_class_variant_assessment(target, source, by_repo)
                if not variant_assessment["enabled"]:
                    continue
                same_class_variant_candidates += 1
                generation_mode = "same_class_variant_advisory"
            candidate_pairs_considered += 1
            bridges = _local_bridges(target, source, by_repo)
            if not bridges:
                filtered_no_bridge += 1
                continue
            breakdown = _score_candidate(target, source, bridges, overlap)
            preconditions = _build_preconditions(source)
            possible_chain = _build_possible_chain(target, source, bridges)
            proof_obligations = _build_proof_obligations(target, source, bridges)
            hypothesis_id = "novelvec:" + stable_hash(
                {
                    "target_repo": target["target_repo"],
                    "target_component": target["target_component"],
                    "novel_attack_class": source["attack_class"],
                    "analogue_record_id": source["record_id"],
                    "generation_mode": generation_mode,
                },
                12,
            )
            hypothesis = {
                "schema": SCHEMA,
                "hypothesis_id": hypothesis_id,
                "generation_mode": generation_mode,
                "advisory_only": True,
                "target_repo": target["target_repo"],
                "target_domain": target["target_domain"],
                "target_language": target["target_language"],
                "target_component": target["target_component"],
                "target_signature": target["raw_signature"],
                "shape_tags": target["shape_tags"],
                "novel_attack_class": source["attack_class"],
                "novel_bug_class": source["bug_class"],
                "repo_attack_classes_seen": sorted(repo_classes.get(target["target_repo"], set())),
                "nearest_analogue": {
                    "record_id": source["record_id"],
                    "source_audit_ref": source["source_audit_ref"],
                    "target_repo": source["target_repo"],
                    "target_component": source["target_component"],
                    "target_signature": source["raw_signature"],
                    "bug_class": source["bug_class"],
                    "attack_class": source["attack_class"],
                    "impact_class": source["impact_class"],
                    "severity_at_finding": source["severity_at_finding"],
                    "shape_tags": source["shape_tags"],
                },
                "preconditions": preconditions,
                "possible_chain": possible_chain,
                "proof_obligations": proof_obligations,
                "score": breakdown["score"],
                "score_breakdown": breakdown,
                "novelty_rationale": (
                    f"`{source['attack_class']}` appears on a same-language/domain shape analogue "
                    f"but is absent from `{target['target_repo']}`. Inspect the target component "
                    f"`{target['target_component']}` as the closest local instance."
                ),
                "limitations": [
                    "Advisory hypothesis only; corpus similarity is not proof.",
                    "Possible chain shows token compatibility, not a validated exploit trace.",
                    "Nearest analogue may differ in implementation details that kill the vector locally.",
                ],
            }
            if generation_mode == "same_class_variant_advisory" and variant_assessment is not None:
                hypothesis["same_class_variant"] = {
                    "mode": "same_class_variant_advisory",
                    "reason": (
                        f"`{source['attack_class']}` already exists in `{target['target_repo']}`, "
                        "but this target has distinct same-class hunting-surface signals."
                    ),
                    "signals": variant_assessment["signals"],
                    "max_local_shape_overlap": variant_assessment["max_local_shape_overlap"],
                    "local_same_class_count": variant_assessment["local_same_class_count"],
                    "local_same_class_refs": variant_assessment["local_same_class_refs"],
                }
                hypothesis["novelty_rationale"] = (
                    f"`{source['attack_class']}` already exists in `{target['target_repo']}`, "
                    f"but `{target['target_component']}` has variant surface signals "
                    f"({', '.join(variant_assessment['signals'])}). Treat this as an advisory "
                    "same-class hunt, not a residual novel-class claim."
                )
            key = (
                hypothesis["target_repo"],
                hypothesis["target_component"],
                hypothesis["novel_attack_class"],
            )
            current = hypotheses_by_key.get(key)
            if current is None or hypothesis["score"] > current["score"]:
                hypotheses_by_key[key] = hypothesis

    hypotheses = sorted(
        hypotheses_by_key.values(),
        key=lambda row: (
            -float(row["score"]),
            row["target_repo"],
            row["target_component"],
            row["novel_attack_class"],
            row["hypothesis_id"],
        ),
    )[:limit]
    for rank, hypothesis in enumerate(hypotheses, start=1):
        hypothesis["rank"] = rank
    same_class_variants_emitted = sum(
        1
        for hypothesis in hypotheses
        if hypothesis.get("generation_mode") == "same_class_variant_advisory"
    )

    digest = stable_hash(
        {
            "schema": SUMMARY_SCHEMA,
            "tag_dir": str(tag_dir),
            "hypotheses": [row["hypothesis_id"] for row in hypotheses],
            "filters": {
                "target_repo": target_repo,
                "language": language,
                "domain": domain,
                "min_shape_overlap": round(min_shape_overlap, 3),
                "max_targets": target_scan_limit,
                "same_class_variants": same_class_variants,
                "exclude_target_repos": sorted(exclude_norm),
            },
        },
        64,
    )
    payload = {
        "schema": SUMMARY_SCHEMA,
        "context_pack_id": f"{SUMMARY_SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "advisory_only": True,
        "source_tag_dir": str(tag_dir),
        "total_records": len(catalog),
        "total_target_candidates": total_target_candidates,
        "targets_considered": targets_considered,
        "target_scan_limit": target_scan_limit,
        "targets_truncated": targets_truncated,
        "target_selection_preview": target_selection_preview,
        "filtered_target_repo": filtered_target_repo,
        "filtered_target_language": filtered_target_language,
        "filtered_target_domain": filtered_target_domain,
        "filtered_target_missing_shape": filtered_target_missing_shape,
        "filtered_target_excluded_repo": filtered_target_excluded_repo,
        "candidate_pairs_seen": candidate_pairs_seen,
        "candidate_pairs_considered": candidate_pairs_considered,
        "filtered_same_repo": filtered_same_repo,
        "filtered_min_shape_overlap": filtered_min_shape_overlap,
        "filtered_existing_class": filtered_existing_class,
        "same_class_variant_mode": same_class_variants,
        "same_class_variant_candidates": same_class_variant_candidates,
        "same_class_variants_emitted": same_class_variants_emitted,
        "filtered_no_bridge": filtered_no_bridge,
        "total_hypotheses": len(hypotheses),
        "filters": {
            "target_repo": target_repo,
            "language": language,
            "domain": domain,
            "min_shape_overlap": round(min_shape_overlap, 3),
            "limit": limit,
            "max_targets": target_scan_limit,
            "same_class_variants": same_class_variants,
            "exclude_target_repos": sorted(exclude_norm),
        },
        "diagnostics": {},
        "limitations": [
            "Residual class generation is based on corpus shape overlap and repo-local class subtraction.",
            "Advisory output does not claim exploitability, severity, or submission readiness.",
            "Local bridge steps show typed state compatibility only and require source-level validation.",
        ],
        "hypotheses": hypotheses,
    }
    if payload.get("total_hypotheses", 0) == 0:
        payload["diagnostics"]["empty_state"] = _empty_state_diagnostics(payload)
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    diagnostics = payload.get("diagnostics") or {}
    lines = [
        "# Hackerman Novel-Vector Hypotheses",
        "",
        f"- Schema: `{payload['schema']}`",
        f"- Source tag dir: `{payload['source_tag_dir']}`",
        f"- Advisory only: `{str(bool(payload.get('advisory_only'))).lower()}`",
        f"- Records scanned: {payload['total_records']}",
        f"- Target candidates: {payload.get('total_target_candidates', payload['targets_considered'])}",
        f"- Targets considered: {payload['targets_considered']}",
        f"- Targets truncated: {str(bool(payload.get('targets_truncated'))).lower()}",
        f"- Candidate pairs seen (same language/domain/tag): {payload.get('candidate_pairs_seen', payload['candidate_pairs_considered'])}",
        f"- Candidate pairs considered: {payload['candidate_pairs_considered']}",
        f"- Filtered because min-shape-overlap not met: {payload.get('filtered_min_shape_overlap', 0)}",
        f"- Filtered because class already exists in target repo: {payload['filtered_existing_class']}",
        f"- Same-class variant mode: {str(bool(payload.get('same_class_variant_mode'))).lower()}",
        f"- Same-class variant candidates: {payload.get('same_class_variant_candidates', 0)}",
        f"- Same-class variants emitted: {payload.get('same_class_variants_emitted', 0)}",
        f"- Filtered because no local bridge chain was found: {payload['filtered_no_bridge']}",
        f"- Hypotheses emitted: {payload['total_hypotheses']}",
        "",
    ]
    empty_state = diagnostics.get("empty_state")
    if payload.get("total_hypotheses", 0) == 0 and empty_state:
        lines.extend(["## Empty State Diagnostics", ""])
        lines.append(f"- Status: `{empty_state.get('status', 'empty')}`")
        for reason in empty_state.get("reasons") or []:
            lines.append(f"- Reason: {reason}")
        for step in empty_state.get("next_steps") or []:
            lines.append(f"- Next step: {step}")
        lines.append("")
    for hypothesis in payload.get("hypotheses", []):
        lines.extend(
            [
                f"## {hypothesis['rank']}. {hypothesis['novel_attack_class']} on {hypothesis['target_component']}",
                "",
                f"- Target repo: `{hypothesis['target_repo']}`",
                f"- Shape tags: `{', '.join(hypothesis['shape_tags'])}`",
                f"- Nearest analogue: `{hypothesis['nearest_analogue']['record_id']}` "
                f"({hypothesis['nearest_analogue']['target_repo']})",
                f"- Generation mode: `{hypothesis.get('generation_mode', 'residual_novel_class')}`",
                f"- Score: {hypothesis['score']}",
                f"- Novelty rationale: {hypothesis['novelty_rationale']}",
                "",
                "Preconditions:",
            ]
        )
        for item in hypothesis.get("preconditions", []):
            lines.append(f"- `{item['kind']}`: {item['value']}")
        lines.append("")
        lines.append("Possible chain:")
        for step in hypothesis.get("possible_chain", []):
            lines.append(
                f"- Step {step['step_index']} [{step['step_type']}]: {step['narrative']}"
            )
        lines.append("")
        lines.append("Proof obligations:")
        for item in hypothesis.get("proof_obligations", []):
            lines.append(f"- `{item['kind']}`: {item['obligation']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help="Directory of corpus tag YAML files")
    parser.add_argument("--limit", type=int, default=20, help=f"Maximum hypotheses to emit (1-{MAX_LIMIT})")
    parser.add_argument("--target-repo", default="", help="Optional substring filter for target repo")
    parser.add_argument("--language", default="", help="Optional exact target language filter")
    parser.add_argument("--domain", default="", help="Optional exact target domain filter")
    parser.add_argument(
        "--max-targets",
        type=int,
        default=DEFAULT_MAX_TARGETS,
        help=(
            "Maximum target records to inspect before emitting hypotheses. "
            "Use --all-targets for a complete, potentially expensive corpus sweep."
        ),
    )
    parser.add_argument(
        "--all-targets",
        action="store_true",
        help="Disable the default bounded target scan. Use only for offline/batch runs.",
    )
    parser.add_argument(
        "--min-shape-overlap",
        type=float,
        default=0.5,
        help="Minimum shape-tag Jaccard overlap between target and analogue (0-1)",
    )
    parser.add_argument(
        "--same-class-variants",
        action="store_true",
        help=(
            "Opt-in advisory mode: emit same-class variant hypotheses when repo-level "
            "class subtraction would suppress a distinct component/function-shape analogue."
        ),
    )
    parser.add_argument("--out", default=None, help="Write output to this path. Use '-' for stdout.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir)
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2
    payload = build_payload(
        tag_dir,
        limit=args.limit,
        target_repo=args.target_repo,
        language=args.language,
        domain=args.domain,
        min_shape_overlap=args.min_shape_overlap,
        max_targets=None if args.all_targets else args.max_targets,
        same_class_variants=args.same_class_variants,
    )
    if args.json:
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    elif args.out is not None:
        rendered = "".join(json.dumps(row, sort_keys=True) + "\n" for row in payload["hypotheses"])
    else:
        rendered = render_markdown(payload)

    if args.out is None or args.out == "-":
        sys.stdout.write(rendered)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
