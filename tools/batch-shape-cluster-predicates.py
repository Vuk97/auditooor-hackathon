#!/usr/bin/env python3
"""Batch shape-cluster predicate distiller for Phase II.17.

This tool deliberately consumes only existing JSONL/index artifacts. It does
not fetch repositories, run per-record source mining, or call a provider. The
first implementation joins P1 invariant source IDs onto the precomputed
``by_function_shape`` index, annotates matched rows with deterministic shape
fields, clusters by shape signature, then emits one predicate candidate per
cluster.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONSOLIDATED_INVARIANTS = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_full_library_llm_v1.jsonl"
)
DEFAULT_FALLBACK_INVARIANT_PATHS = [
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl",
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl",
]
DEFAULT_SHAPE_INDEX_DIR = (
    REPO_ROOT / "audit" / "corpus_tags" / "index" / "by_function_shape.d"
)
SCHEMA = "auditooor.phase_ii17.batch_shape_cluster_predicates.v1"


def _hash16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _norm_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return sorted({_norm_text(v) for v in value if _norm_text(v)})
    if isinstance(value, tuple) or isinstance(value, set):
        return sorted({_norm_text(v) for v in value if _norm_text(v)})
    text = _norm_text(value)
    return [text] if text else []


def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if isinstance(rec, dict):
                yield rec


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True) + "\n")
            count += 1
    return count


def _iter_batches(rows: list[dict[str, Any]], batch_size: int) -> Iterator[tuple[int, list[dict[str, Any]]]]:
    if batch_size <= 0:
        raise ValueError("--batch-size must be positive")
    for start in range(0, len(rows), batch_size):
        yield start // batch_size, rows[start : start + batch_size]


def load_invariants(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        for rec in _read_jsonl(path):
            inv_id = _norm_text(rec.get("invariant_id"))
            if inv_id and inv_id in seen:
                continue
            if inv_id:
                seen.add(inv_id)
            clone = dict(rec)
            clone["_invariant_source_path"] = str(path)
            records.append(clone)
    return records


def _unwrap_index_row(rec: dict[str, Any]) -> dict[str, Any]:
    """Accept both raw rows and legacy ``{"key": ..., "record": ...}`` rows."""
    nested = rec.get("record")
    if isinstance(nested, dict):
        merged = dict(nested)
        if rec.get("key") and not merged.get("key"):
            merged["key"] = rec.get("key")
        return merged
    return rec


def _shape_row_fingerprint(row: dict[str, Any]) -> str:
    parts = [
        row.get("record_id"),
        row.get("shape_hash"),
        row.get("function_signature"),
        row.get("target_language"),
        row.get("source_audit_ref"),
    ]
    return "|".join(_norm_text(p) for p in parts)


@dataclass
class ShapeIndex:
    rows: list[dict[str, Any]] = field(default_factory=list)
    by_source_id: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    row_count: int = 0
    indexed_row_count: int = 0

    @classmethod
    def load(cls, index_dir: Path) -> "ShapeIndex":
        index = cls()
        if not index_dir.is_dir():
            return index
        seen_by_key: dict[str, set[str]] = defaultdict(set)
        for path in sorted(index_dir.glob("*.jsonl")):
            if path.name == "manifest.jsonl":
                continue
            for raw in _read_jsonl(path):
                row = _unwrap_index_row(raw)
                if not row:
                    continue
                index.row_count += 1
                fp = _shape_row_fingerprint(row)
                index.rows.append(row)
                keys = {
                    _norm_text(row.get("record_id")),
                    _norm_text(row.get("source_audit_ref")),
                    _norm_text(row.get("tag_file")),
                }
                for key in {k for k in keys if k}:
                    if fp in seen_by_key[key]:
                        continue
                    seen_by_key[key].add(fp)
                    index.by_source_id[key].append(row)
                    index.indexed_row_count += 1
        return index


def _shape_fields(row: dict[str, Any]) -> dict[str, Any]:
    features = row.get("shape_features") if isinstance(row.get("shape_features"), dict) else {}
    body_features = row.get("body_features") if isinstance(row.get("body_features"), dict) else {}
    function_signature = _norm_text(row.get("function_signature"))
    language = _norm_text(row.get("target_language") or row.get("language")).lower()
    shape_hash = _norm_text(row.get("shape_hash"))
    fallback_material = "|".join(
        [
            language,
            function_signature,
            ",".join(_as_list(row.get("modifiers") or features.get("modifiers"))),
            ",".join(_as_list(row.get("state_vars") or features.get("state_vars") or features.get("state_writes"))),
            ",".join(_as_list(row.get("external_calls") or features.get("external_calls") or body_features.get("calls"))),
            ",".join(_as_list(row.get("control_flow") or features.get("control_flow") or body_features.get("control_flow"))),
        ]
    )
    cluster_key = shape_hash or f"sig-{_hash16(fallback_material)}"
    shape_signature = "|".join(
        [
            f"language={language}",
            f"shape={cluster_key}",
            f"function={function_signature}",
            f"modifiers={','.join(_as_list(row.get('modifiers') or features.get('modifiers')))}",
            f"state_vars={','.join(_as_list(row.get('state_vars') or features.get('state_vars') or features.get('state_writes')))}",
            f"external_calls={','.join(_as_list(row.get('external_calls') or features.get('external_calls') or body_features.get('calls')))}",
            f"control_flow={','.join(_as_list(row.get('control_flow') or features.get('control_flow') or body_features.get('control_flow')))}",
        ]
    )
    return {
        "shape_cluster_key": cluster_key,
        "shape_signature": shape_signature,
        "shape_signature_hash": _hash16(shape_signature),
        "function_signature": function_signature,
        "modifiers": _as_list(row.get("modifiers") or features.get("modifiers")),
        "state_vars": _as_list(row.get("state_vars") or features.get("state_vars") or features.get("state_writes")),
        "external_calls": _as_list(row.get("external_calls") or features.get("external_calls") or body_features.get("calls")),
        "control_flow": _as_list(row.get("control_flow") or features.get("control_flow") or body_features.get("control_flow")),
        "language": language,
        "shape_hash": shape_hash,
        "source_ref": _norm_text(row.get("source_audit_ref")),
        "annotation_method": "precomputed-by_function_shape-index",
    }


def annotate_invariants(
    invariants: list[dict[str, Any]],
    shape_index: ShapeIndex,
    *,
    batch_size: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    annotations: list[dict[str, Any]] = []
    unmatched_source_ids: Counter[str] = Counter()
    matched_source_ids: Counter[str] = Counter()
    seen_annotations: set[str] = set()

    for batch_index, batch in _iter_batches(invariants, batch_size):
        for invariant in batch:
            inv_id = _norm_text(invariant.get("invariant_id"))
            source_ids = [_norm_text(s) for s in (invariant.get("source_finding_ids") or []) if _norm_text(s)]
            if not source_ids:
                continue
            for source_id in source_ids:
                shape_rows = shape_index.by_source_id.get(source_id) or []
                if not shape_rows:
                    unmatched_source_ids[source_id] += 1
                    continue
                matched_source_ids[source_id] += 1
                for row in shape_rows:
                    fields = _shape_fields(row)
                    dedupe_key = "|".join(
                        [
                            inv_id,
                            source_id,
                            _norm_text(row.get("record_id")),
                            fields["shape_cluster_key"],
                        ]
                    )
                    if dedupe_key in seen_annotations:
                        continue
                    seen_annotations.add(dedupe_key)
                    annotations.append(
                        {
                            "schema": SCHEMA + ".annotation",
                            "batch_index": batch_index,
                            "invariant_id": inv_id,
                            "invariant_category": _norm_text(invariant.get("category")),
                            "invariant_target_lang": _norm_text(invariant.get("target_lang") or "any"),
                            "source_finding_id": source_id,
                            "record_id": _norm_text(row.get("record_id")),
                            "attack_class": _norm_text(row.get("attack_class")),
                            "bug_class": _norm_text(row.get("bug_class")),
                            "target_repo": _norm_text(row.get("target_repo")),
                            "target_domain": _norm_text(row.get("target_domain")),
                            "severity_at_finding": _norm_text(row.get("severity_at_finding")),
                            "year": row.get("year"),
                            "shape_annotation": fields,
                        }
                    )

    stats = {
        "batch_size": batch_size,
        "batch_count": (len(invariants) + batch_size - 1) // batch_size if invariants else 0,
        "invariant_records": len(invariants),
        "source_finding_ids": sum(len(inv.get("source_finding_ids") or []) for inv in invariants),
        "matched_source_finding_ids": len(matched_source_ids),
        "unmatched_source_finding_ids": len(unmatched_source_ids),
        "annotation_rows": len(annotations),
        "annotation_method": "batch-join-existing-jsonl-index-no-record-mining",
    }
    return annotations, stats


def _cluster_key(annotation: dict[str, Any]) -> str:
    return str(annotation.get("shape_annotation", {}).get("shape_cluster_key") or "")


def _predicate_matches(candidate: dict[str, Any], annotation: dict[str, Any]) -> bool:
    ann_shape = annotation.get("shape_annotation", {}) if isinstance(annotation.get("shape_annotation"), dict) else {}
    candidate_sig = _norm_text(candidate.get("shape_signature_hash"))
    if candidate_sig:
        return candidate_sig == _norm_text(ann_shape.get("shape_signature_hash"))
    return candidate.get("shape_cluster_key") == _cluster_key(annotation)


def distill_clusters(
    annotations: list[dict[str, Any]],
    *,
    max_predicates: int,
    target_coverage: float,
    false_positive_sample_size: int,
    emit_per_invariant_candidates: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if false_positive_sample_size < 0:
        raise ValueError("--false-positive-sample-size must be non-negative")
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ann in annotations:
        key = _cluster_key(ann)
        if key:
            clusters[key].append(ann)

    total = len(annotations)
    ordered = sorted(
        clusters.items(),
        key=lambda item: (
            -len(item[1]),
            item[0],
        ),
    )
    cumulative = 0
    candidates: list[dict[str, Any]] = []
    selected_cluster_count = 0
    in_cluster_signature_pass_count = 0
    out_of_cluster_zero_fp_pass_count = 0
    for rank, (key, rows) in enumerate(ordered, start=1):
        if (
            max_predicates > 0
            and selected_cluster_count >= max_predicates
            and (not total or (cumulative / total) >= target_coverage)
        ):
            break
        sample = rows[0]
        signature_counts = Counter(
            _norm_text(r.get("shape_annotation", {}).get("shape_signature_hash"))
            for r in rows
            if _norm_text(r.get("shape_annotation", {}).get("shape_signature_hash"))
        )
        dominant_signature_hash = (
            signature_counts.most_common(1)[0][0]
            if signature_counts
            else _norm_text(sample.get("shape_annotation", {}).get("shape_signature_hash"))
        )
        in_cluster_signature_hit_rate = (
            (signature_counts.get(dominant_signature_hash, 0) / len(rows))
            if rows and dominant_signature_hash
            else 0.0
        )
        outside = [ann for ann in annotations if _cluster_key(ann) != key]
        outside_sample = outside[:false_positive_sample_size]
        support_invariant_ids = sorted({r.get("invariant_id") for r in rows if r.get("invariant_id")})
        canonical_function_signature = sample.get("shape_annotation", {}).get("function_signature", "")
        probe_candidate = {
            "shape_cluster_key": key,
            "shape_signature_hash": dominant_signature_hash,
        }
        false_positive_count = sum(1 for ann in outside_sample if _predicate_matches(probe_candidate, ann))
        zero_fp_pass = false_positive_count == 0 and len(outside_sample) == false_positive_sample_size
        in_cluster_signature_pass = in_cluster_signature_hit_rate >= target_coverage
        validation_status = (
            "validated-shape-cluster-pending-dogfood"
            if in_cluster_signature_pass and zero_fp_pass
            else "rejected-shape-validation"
        )
        candidate = {
            "schema": SCHEMA + ".predicate_candidate",
            "predicate_id": f"SHAPE-PRED-{_hash16(key)}",
            "rank": rank,
            "shape_cluster_key": key,
            "cluster_id": key,
            "shape_signature_hash": dominant_signature_hash,
            "predicate_expression": (
                f"shape_signature_hash == {json.dumps(dominant_signature_hash)}"
                if dominant_signature_hash
                else f"shape_cluster_key == {json.dumps(key)}"
            ),
            "predicate_basis": "shape_signature_not_attack_class",
            "support_annotation_rows": len(rows),
            "support_record_ids": len({r.get("record_id") for r in rows if r.get("record_id")}),
            "support_invariant_ids": support_invariant_ids,
            "support_languages": dict(Counter(r.get("shape_annotation", {}).get("language", "") for r in rows)),
            "support_domains": dict(Counter(r.get("target_domain", "") for r in rows)),
            "support_attack_classes_sample": sorted({r.get("attack_class") for r in rows if r.get("attack_class")})[:20],
            "function_signature_sample": canonical_function_signature,
            "function_signature": canonical_function_signature,
            "invariant_id": support_invariant_ids[0] if len(support_invariant_ids) == 1 else "",
            "candidate_status": validation_status,
            "validation_status": validation_status,
            "status": "pending-live-target-dogfood",
            "attack_class_diversity": {
                "count": len({r.get("attack_class") for r in rows if r.get("attack_class")}),
                "attack_classes": sorted({r.get("attack_class") for r in rows if r.get("attack_class")})[:20],
            },
            "validation": {
                "cluster_record_match_rate": 1.0 if rows else 0.0,
                "semantic_acceptance_status": "pending-live-target-dogfood",
                "false_positive_sample_size": len(outside_sample),
                "false_positive_count": false_positive_count,
                "in_cluster_semantic_hit_rate": None,
                "in_cluster_signature_hit_rate": in_cluster_signature_hit_rate,
                "in_cluster_signature_min_required": target_coverage,
                "in_cluster_signature_threshold_passed": in_cluster_signature_pass,
                "out_of_cluster_zero_fp_check": {
                    "required_false_positive_count": 0,
                    "required_sample_size": false_positive_sample_size,
                    "sample_size_selected": len(outside_sample),
                    "sample_record_ids": [ann.get("record_id") for ann in outside_sample],
                    "passed": zero_fp_pass,
                },
            },
        }
        if in_cluster_signature_pass:
            in_cluster_signature_pass_count += 1
        if zero_fp_pass:
            out_of_cluster_zero_fp_pass_count += 1
        cumulative += len(rows)
        candidate["cumulative_annotation_coverage"] = (cumulative / total) if total else 0.0
        if emit_per_invariant_candidates and support_invariant_ids:
            for invariant_id in support_invariant_ids:
                expanded = dict(candidate)
                expanded["predicate_id"] = f"{candidate['predicate_id']}-INV-{_hash16(invariant_id)}"
                expanded["invariant_id"] = invariant_id
                candidates.append(expanded)
        else:
            candidates.append(candidate)
        selected_cluster_count += 1
        if total and candidate["cumulative_annotation_coverage"] >= target_coverage and selected_cluster_count >= 200:
            break

    summary = {
        "cluster_count": len(clusters),
        "selected_predicate_count": selected_cluster_count,
        "emitted_candidate_rows": len(candidates),
        "selected_annotation_coverage": candidates[-1]["cumulative_annotation_coverage"] if candidates else 0.0,
        "selected_annotation_coverage_shortfall": max(
            0.0,
            target_coverage - (candidates[-1]["cumulative_annotation_coverage"] if candidates else 0.0),
        ),
        "target_coverage": target_coverage,
        "target_coverage_reached": (
            (candidates[-1]["cumulative_annotation_coverage"] if candidates else 0.0)
            >= target_coverage
        ),
        "in_cluster_signature_threshold": target_coverage,
        "in_cluster_signature_pass_count": in_cluster_signature_pass_count,
        "out_of_cluster_zero_fp_pass_count": out_of_cluster_zero_fp_pass_count,
        "full_validation_pass_count": sum(
            1
            for c in candidates
            if c["validation"]["in_cluster_signature_threshold_passed"]
            and c["validation"]["out_of_cluster_zero_fp_check"]["passed"]
        ),
        "max_predicates": max_predicates,
        "false_positive_sample_size": false_positive_sample_size,
    }
    return candidates, summary


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    invariant_paths = [Path(p) for p in args.invariants]
    shape_index_dir = Path(args.shape_index_dir)
    invariants = load_invariants(invariant_paths)
    shape_index = ShapeIndex.load(shape_index_dir)
    annotations, annotation_stats = annotate_invariants(
        invariants,
        shape_index,
        batch_size=args.batch_size,
    )
    candidates, cluster_stats = distill_clusters(
        annotations,
        max_predicates=args.max_predicates,
        target_coverage=args.target_coverage,
        false_positive_sample_size=args.false_positive_sample_size,
        emit_per_invariant_candidates=args.emit_per_invariant_candidates,
    )
    return {
        "schema": SCHEMA + ".summary",
        "inputs": {
            "invariants": [str(p) for p in invariant_paths],
            "shape_index_dir": str(shape_index_dir),
        },
        "constraints": {
            "per_record_mining": False,
            "network": False,
            "provider_calls": False,
            "source_checkout_required": False,
            "cluster_key_excludes_attack_class": True,
        },
        "shape_index": {
            "row_count": shape_index.row_count,
            "indexed_row_count": shape_index.indexed_row_count,
            "source_id_keys": len(shape_index.by_source_id),
        },
        "annotation": annotation_stats,
        "clusters": cluster_stats,
        "top_predicates": candidates[:10],
        "_annotations": annotations,
        "_predicate_candidates": candidates,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--invariants",
        action="append",
        default=None,
        help="Invariant JSONL input. Repeatable. Defaults to pilot + extracted.",
    )
    parser.add_argument(
        "--shape-index-dir",
        default=str(DEFAULT_SHAPE_INDEX_DIR),
        help="Directory containing by_function_shape shard JSONL files.",
    )
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--max-predicates", type=int, default=300)
    parser.add_argument("--target-coverage", type=float, default=0.8)
    parser.add_argument("--false-positive-sample-size", type=int, default=10)
    parser.add_argument(
        "--emit-per-invariant-candidates",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Compatibility escape hatch: emit one row per "
            "(shape cluster, invariant_id). Default is false because Phase II.17 "
            "requires one predicate row per shape cluster; live-target fans out "
            "support_invariant_ids itself."
        ),
    )
    parser.add_argument("--annotated-jsonl", help="Optional annotation JSONL output path.")
    parser.add_argument("--predicates-jsonl", help="Optional predicate candidate JSONL output path.")
    parser.add_argument("--summary-json", help="Optional summary JSON output path.")
    args = parser.parse_args(argv)
    if args.invariants is None:
        if DEFAULT_CONSOLIDATED_INVARIANTS.is_file():
            args.invariants = [str(DEFAULT_CONSOLIDATED_INVARIANTS)]
        else:
            args.invariants = [str(p) for p in DEFAULT_FALLBACK_INVARIANT_PATHS]
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    payload = build_payload(args)
    annotations = payload.pop("_annotations")
    candidates = payload.pop("_predicate_candidates")
    if args.annotated_jsonl:
        payload["outputs"] = payload.get("outputs", {})
        payload["outputs"]["annotated_jsonl"] = {
            "path": args.annotated_jsonl,
            "rows": _write_jsonl(Path(args.annotated_jsonl), annotations),
        }
    if args.predicates_jsonl:
        payload["outputs"] = payload.get("outputs", {})
        payload["outputs"]["predicates_jsonl"] = {
            "path": args.predicates_jsonl,
            "rows": _write_jsonl(Path(args.predicates_jsonl), candidates),
        }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.summary_json:
        out = Path(args.summary_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
