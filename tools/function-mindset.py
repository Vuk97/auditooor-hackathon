#!/usr/bin/env python3
"""Return shape-indexed attack hypotheses for a function signature."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from hackerman_query_common import (
    DEFAULT_CROSS_LANGUAGE_ANALOGUES_SIDECAR,
    DEFAULT_INDEX_DIR,
    DEFAULT_PROOF_HARDENING_SIDECAR,
    DEFAULT_RECORD_QUALITY_SIDECAR,
    DEFAULT_TAGS_DIR,
    attach_cross_language_analogues,
    attach_proof_hardening,
    attach_record_quality,
    clamp_limit,
    compute_shape_from_signature,
    load_cross_language_analogue_index,
    load_record_quality_index,
    index_available,
    normalized_record,
    proof_hardening_match_weight,
    query_index,
    record_attack_classes,
    record_quality_float,
    record_quality_sort_key,
    record_tier_weight,
    load_proof_hardening_index,
    sidecar_status,
    stable_hash,
    utc_now,
)


SCHEMA = "auditooor.hackerman.function_mindset.v1"


def _dedupe_pairs_prefer_first(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    seen: set[str] = set()
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for row, record in pairs:
        key = str(
            record.get("record_id")
            or record.get("verdict_id")
            or row.get("record_id")
            or row.get("verdict_id")
            or row.get("tag_file")
            or ""
        )
        if not key:
            key = json.dumps(row, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append((row, record))
    return out


def _annotated_query(
    *,
    index_name: str,
    shape_hash: str,
    match_kind: str,
    index_dir: Path,
    tags_dir: Path,
    limit: int,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for row, record in query_index(
        index_name=index_name,
        key=shape_hash,
        index_dir=index_dir,
        tags_dir=tags_dir,
        limit=limit,
        fuzzy_slug=False,
    ):
        annotated = dict(row)
        annotated["_query_index_name"] = index_name
        annotated["_query_key"] = shape_hash
        annotated["_query_match_kind"] = match_kind
        out.append((annotated, record))
    return out


def _candidate_pairs(shape_hashes: list[str], index_dir: Path, tags_dir: Path, limit: int) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    candidate_limit = max(limit * 50, 50) if limit else 0
    if not candidate_limit:
        return []
    coarse = shape_hashes[0] if shape_hashes else ""
    fine = shape_hashes[1] if len(shape_hashes) > 1 else ""
    query_plan = [
        ("by_shape_hash", fine, "fine_exact"),
        ("by_shape_hash", coarse, "coarse_exact"),
        ("by_function_shape", fine, "function_shape_fine"),
        ("by_function_shape", coarse, "function_shape_coarse"),
    ]
    seen_plan: set[tuple[str, str]] = set()
    for index_name, shape_hash, match_kind in query_plan:
        if not shape_hash or (index_name, shape_hash) in seen_plan:
            continue
        seen_plan.add((index_name, shape_hash))
        if not index_available(index_dir, index_name):
            continue
        pairs.extend(
            _annotated_query(
                index_name=index_name,
                shape_hash=shape_hash,
                match_kind=match_kind,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=candidate_limit,
            )
        )
    return _dedupe_pairs_prefer_first(pairs)


def _norm_path(path: str) -> str:
    return str(path or "").strip().lstrip("./")


def _record_matches_target_file(record: dict[str, Any], target_file_path: str) -> bool:
    wanted = _norm_path(target_file_path)
    if not wanted:
        return False
    candidates = []
    for field in ("target_component", "file_path"):
        value = _norm_path(str(record.get(field) or ""))
        if value:
            candidates.append(value)
    sites = record.get("sites") if isinstance(record.get("sites"), list) else []
    for site in sites:
        if isinstance(site, dict):
            value = _norm_path(str(site.get("file_path") or ""))
            if value:
                candidates.append(value)
    for candidate in candidates:
        if candidate == wanted or candidate.endswith(wanted) or wanted.endswith(candidate):
            return True
    return False


def _match_precision_weight(row: dict[str, Any], norm: dict[str, Any], *, target_repo: str, file_path: str) -> float:
    match_kind = str(row.get("_query_match_kind") or "")
    weight = {
        "fine_exact": 1.0,
        "coarse_exact": 0.45,
        "function_shape_fine": 0.30,
        "function_shape_coarse": 0.12,
    }.get(match_kind, 0.10)
    if (
        target_repo
        and str(norm.get("target_repo") or "") == target_repo
        and file_path
        and not _record_matches_target_file(norm, file_path)
    ):
        weight *= 0.25
    return max(0.02, round(weight, 4))


def _rank_hypotheses(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    limit: int,
    quality_index: dict[str, dict[str, Any]],
    proof_index: dict[str, dict[str, Any]],
    analogue_index: dict[str, list[dict[str, Any]]],
    *,
    target_repo: str,
    file_path: str,
    target_language: str,
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for row, record in pairs:
        norm = attach_proof_hardening(
            attach_cross_language_analogues(
                attach_record_quality(normalized_record(record, row), quality_index),
                row,
                analogue_index,
                target_language=target_language,
                limit=3,
            ),
            proof_index,
        )
        match_weight = _match_precision_weight(row, norm, target_repo=target_repo, file_path=file_path)
        norm["match_kind"] = str(row.get("_query_match_kind") or "")
        norm["match_weight"] = match_weight
        classes = record_attack_classes(record) or ([norm["attack_class"]] if norm["attack_class"] else [])
        for attack_class in classes:
            bucket = buckets.setdefault(
                attack_class,
                {
                    "attack_class": attack_class,
                    "score": 0.0,
                    "confidence": 0.0,
                    "evidence": [],
                    "max_record_quality_score": 0.0,
                    "max_record_tier_weight": 0.0,
                    "max_match_weight": 0.0,
                },
            )
            bucket["score"] += proof_hardening_match_weight(norm) * match_weight
            bucket["max_record_quality_score"] = max(
                float(bucket["max_record_quality_score"]),
                record_quality_float(norm),
            )
            bucket["max_record_tier_weight"] = max(
                float(bucket["max_record_tier_weight"]),
                record_tier_weight(norm),
            )
            bucket["max_match_weight"] = max(float(bucket["max_match_weight"]), match_weight)
            bucket["evidence"].append(norm)
    for bucket in buckets.values():
        bucket["evidence"] = [
            record
            for _, record in sorted(
                enumerate(bucket["evidence"]),
                key=lambda item: (
                    *record_quality_sort_key(item[1], stable_index=item[0]),
                    item[1].get("record_id") or "",
                ),
            )
        ][:5]
    ranked = sorted(
        buckets.values(),
        key=lambda b: (
            -float(b["score"]),
            -float(b.get("max_match_weight") or 0.0),
            -float(b.get("max_record_tier_weight") or 0.0),
            -float(b.get("max_record_quality_score") or 0.0),
            str(b["attack_class"]),
        ),
    )
    for idx, item in enumerate(ranked, start=1):
        item["rank"] = idx
        item["confidence"] = min(0.99, round(0.45 + 0.1 * min(float(item["score"]), 5.0), 4))
    return ranked[:limit]


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    limit = clamp_limit(args.limit, default=5, maximum=50)
    ts = utc_now()
    if not args.shape_hash and not args.function_signature:
        digest = stable_hash({"schema": SCHEMA, "degraded": True, "ts": ts})
        return {
            "schema": SCHEMA,
            "context_pack_id": f"{SCHEMA}:{digest[:16]}",
            "context_pack_hash": digest,
            "degraded": True,
            "reason": "missing_shape_hash_or_function_signature",
            "target": {
                "repo": args.target_repo or "",
                "file_path": args.file_path or "",
                "function_signature": args.function_signature or "",
            },
            "ranked_attack_classes": [],
            "source_refs": [],
            "generated_at_utc": ts,
        }

    shape: dict[str, Any] = {}
    shape_hashes: list[str] = []
    if args.function_signature:
        shape = compute_shape_from_signature(args.function_signature, args.language)
        shape_hashes.extend([shape["shape_hash"], shape["shape_hash_fine"]])
    if args.shape_hash:
        shape_hashes.insert(0, args.shape_hash)
    shape_hashes = [h for idx, h in enumerate(shape_hashes) if h and h not in shape_hashes[:idx]]

    index_dir = Path(args.index_dir)
    tags_dir = Path(args.tags_dir)
    quality_index = load_record_quality_index(Path(args.quality_sidecar))
    proof_index = load_proof_hardening_index(Path(args.proof_hardening_sidecar))
    analogue_index = load_cross_language_analogue_index(Path(args.cross_language_sidecar))
    pairs = _candidate_pairs(shape_hashes, index_dir, tags_dir, max(limit, 1))
    if args.target_repo and args.same_repo_only:
        pairs = [(row, rec) for row, rec in pairs if str(rec.get("target_repo") or "") == args.target_repo]

    hypotheses = _rank_hypotheses(
        pairs,
        limit,
        quality_index,
        proof_index,
        analogue_index,
        target_repo=args.target_repo or "",
        file_path=args.file_path or "",
        target_language=shape.get("language") or args.language or "",
    )
    quality_sidecar_refs, sidecar_gaps = sidecar_status(
        Path(args.quality_sidecar),
        bool(quality_index),
        "record_quality",
    )
    proof_sidecar_refs, proof_sidecar_gaps = sidecar_status(
        Path(args.proof_hardening_sidecar),
        bool(proof_index),
        "proof_hardening",
    )
    cross_language_sidecar_refs, cross_language_sidecar_gaps = sidecar_status(
        Path(args.cross_language_sidecar),
        bool(analogue_index),
        "cross_language_analogues",
    )
    sidecar_gaps = sidecar_gaps + proof_sidecar_gaps + cross_language_sidecar_gaps
    digest = stable_hash(
        {
            "schema": SCHEMA,
            "target_repo": args.target_repo,
            "file_path": args.file_path,
            "shape_hashes": shape_hashes,
            "hypotheses": [(h["attack_class"], h["score"]) for h in hypotheses],
        }
    )
    return {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "degraded": False,
        "target": {
            "repo": args.target_repo or "",
            "file_path": args.file_path or "",
            "function_signature": args.function_signature or "",
            "language": shape.get("language") or args.language,
            "function_name": shape.get("function_name") or "",
            "receiver_type": shape.get("receiver_type"),
            "shape_hash": shape_hashes[0] if shape_hashes else "",
            "shape_hashes_queried": shape_hashes,
            "body_hash": args.body_hash or "",
        },
        "total_records_matched": len(pairs),
        "ranked_attack_classes": hypotheses,
        "source_refs": [
            str(index_dir / "by_function_shape.jsonl"),
            str(index_dir / "by_shape_hash.jsonl"),
            str(tags_dir),
            *quality_sidecar_refs,
            *proof_sidecar_refs,
            *cross_language_sidecar_refs,
        ],
        "sidecar_gaps": sidecar_gaps,
        "quality_sidecar_loaded": bool(quality_index),
        "quality_rows_loaded": len(
            {
                str(row.get("record_id") or "")
                for row in quality_index.values()
                if row.get("record_id")
            }
        ),
        "proof_hardening_sidecar_loaded": bool(proof_index),
        "proof_hardening_rows_loaded": len(
            {
                str(row.get("record_id") or "")
                for row in proof_index.values()
                if row.get("record_id")
            }
        ),
        "cross_language_sidecar_loaded": bool(analogue_index),
        "cross_language_sidecar_sources_loaded": len(analogue_index),
        "generated_at_utc": ts,
    }


def _emit_text(payload: dict[str, Any]) -> str:
    if payload.get("degraded"):
        return f"{payload['schema']}: {payload.get('reason', 'degraded')}"
    target = payload["target"]
    lines = [
        f"Function: {target.get('function_name') or target.get('function_signature') or target.get('shape_hash')}",
        f"Shape hashes: {', '.join(target.get('shape_hashes_queried') or [])}",
        f"Matched records: {payload['total_records_matched']}",
    ]
    for item in payload.get("ranked_attack_classes", []):
        lines.append(f"- #{item['rank']} {item['attack_class']} score={item['score']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function-signature", default="", help="Function signature to hash and query")
    parser.add_argument("--shape-hash", default="", help="Precomputed shape_hash to query")
    parser.add_argument("--body-hash", default="", help="Optional body hash echoed in the output envelope")
    parser.add_argument("--language", default="go", help="Signature language, default: go")
    parser.add_argument("--target-repo", default="", help="Target repo label")
    parser.add_argument("--file-path", default="", help="Target file path")
    parser.add_argument("--same-repo-only", action="store_true", help="Filter evidence to target_repo")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--quality-sidecar", default=str(DEFAULT_RECORD_QUALITY_SIDECAR))
    parser.add_argument("--proof-hardening-sidecar", default=str(DEFAULT_PROOF_HARDENING_SIDECAR))
    parser.add_argument("--cross-language-sidecar", default=str(DEFAULT_CROSS_LANGUAGE_ANALOGUES_SIDECAR))
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = build_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_emit_text(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
