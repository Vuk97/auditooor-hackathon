#!/usr/bin/env python3
"""Return corpus evidence for an attack class from corpus_tags indices."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from hackerman_query_common import (
    DEFAULT_INDEX_DIR,
    DEFAULT_PROOF_HARDENING_SIDECAR,
    DEFAULT_RECORD_QUALITY_SIDECAR,
    DEFAULT_TAGS_DIR,
    attach_proof_hardening,
    attach_record_quality,
    attack_class_query_terms,
    clamp_limit,
    dedupe_records,
    load_proof_hardening_index,
    load_record_quality_index,
    normalized_record,
    query_index,
    record_quality_sort_key,
    record_attack_classes,
    sidecar_status,
    slug,
    stable_hash,
    utc_now,
)


SCHEMA = "auditooor.hackerman.attack_class_evidence.v1"


def _outcome_key(record: dict[str, Any]) -> str:
    return str(record.get("triager_outcome") or record.get("verdict_class") or "UNKNOWN")


def _outcome_weight(record: dict[str, Any]) -> float:
    outcome = _outcome_key(record).upper()
    verdict = str(record.get("verdict_class") or "").upper()
    if outcome in {"ACCEPTED", "SUBMITTED", "FILED"} or verdict in {"FILED", "ACCEPTED"}:
        return 1.0
    if outcome in {"CANDIDATE", "STAGING"} or verdict == "CANDIDATE":
        return 0.5
    if outcome in {"DUPLICATE", "REJECTED", "NOT_A_BUG", "OOS", "DROPPED"}:
        return -0.5
    return 0.0


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    attack_class = args.attack_class or args.attack_class_opt or ""
    limit = clamp_limit(args.limit, default=10, maximum=100)
    ts = utc_now()
    if not attack_class:
        digest = stable_hash({"schema": SCHEMA, "degraded": True, "ts": ts})
        return {
            "schema": SCHEMA,
            "context_pack_id": f"{SCHEMA}:{digest[:16]}",
            "context_pack_hash": digest,
            "degraded": True,
            "reason": "missing_attack_class",
            "attack_class": "",
            "total_records_matched": 0,
            "total_verdicts_matched": 0,
            "records": [],
            "exemplar_verdicts": [],
            "source_refs": [],
            "generated_at_utc": ts,
        }

    index_dir = Path(args.index_dir)
    tags_dir = Path(args.tags_dir)
    quality_index = load_record_quality_index(Path(args.quality_sidecar))
    proof_index = load_proof_hardening_index(Path(args.proof_hardening_sidecar))
    terms = attack_class_query_terms(attack_class)
    candidate_limit = max(limit * 25, 50) if limit else 0
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for term in terms:
        pairs.extend(
            query_index(
                index_name="by_attack_class",
                key=term,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=candidate_limit,
            )
        )

    # Legacy indices can be stale or class names can differ by underscore vs
    # hyphen. Verify loaded records where possible and keep projected rows that
    # have no tag body.
    filtered: list[tuple[dict[str, Any], dict[str, Any]]] = []
    wanted_terms = {slug(term) for term in terms}
    for row, record in pairs:
        classes = record_attack_classes(record)
        if classes and not any(slug(cls) in wanted_terms for cls in classes):
            continue
        if args.target_repo and not args.sibling_repos_ok:
            if str(record.get("target_repo") or "") != args.target_repo:
                continue
        if _outcome_weight(record) < float(args.min_outcome_weight):
            continue
        filtered.append((row, record))

    enriched = [
        (
            row,
            attach_proof_hardening(
                attach_record_quality(normalized_record(record, row), quality_index),
                proof_index,
            ),
            _outcome_weight(record),
        )
        for row, record in dedupe_records(filtered)
    ]
    enriched.sort(
        key=lambda item: (
            -item[2],
            *record_quality_sort_key(
                item[1],
                target_repo=args.target_repo or "",
            ),
            item[1]["record_id"],
        )
    )
    filtered = [(row, record) for row, record, _ in enriched]
    sliced = filtered[:limit]
    records = [record | {"outcome_weight": weight} for _, record, weight in enriched[:limit]]
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
    sidecar_gaps = sidecar_gaps + proof_sidecar_gaps

    by_outcome: dict[str, int] = {}
    for _, record in dedupe_records(filtered):
        key = _outcome_key(record)
        by_outcome[key] = by_outcome.get(key, 0) + 1

    digest = stable_hash(
        {
            "schema": SCHEMA,
            "attack_class": attack_class,
            "query_terms": terms,
            "target_repo": args.target_repo,
            "total": len(filtered),
            "record_ids": [r["record_id"] for r in records],
        }
    )
    return {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "degraded": False,
        "attack_class": attack_class,
        "query_terms": terms,
        "target_repo": args.target_repo,
        "sibling_repos_ok": args.sibling_repos_ok,
        "total_records_matched": len(filtered),
        "total_verdicts_matched": len(filtered),
        "by_outcome": by_outcome,
        "records": records,
        "exemplar_verdicts": records,
        "source_refs": [
            str(index_dir / "by_attack_class.jsonl"),
            str(tags_dir),
            *quality_sidecar_refs,
            *proof_sidecar_refs,
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
        "generated_at_utc": ts,
    }


def _emit_text(payload: dict[str, Any]) -> str:
    if payload.get("degraded"):
        return f"{payload['schema']}: {payload.get('reason', 'degraded')}"
    lines = [
        f"Attack class: {payload['attack_class']}",
        f"Matched records: {payload['total_records_matched']}",
    ]
    for rec in payload.get("records", []):
        proof = rec.get("proof_hardening") if isinstance(rec.get("proof_hardening"), dict) else {}
        posture = ""
        if proof:
            posture = (
                f" posture={proof.get('submission_posture') or 'unknown'} "
                f"promotion_allowed={str(proof.get('promotion_allowed')).lower()}"
            )
        lines.append(
            f"- {rec.get('record_id')} [{rec.get('target_language') or 'unknown'}] "
            f"{rec.get('target_repo') or 'unknown'} :: {rec.get('bug_class') or rec.get('attack_class')}"
            f"{posture}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attack_class", nargs="?", help="Attack class to query, e.g. admin-bypass")
    parser.add_argument("--attack-class", dest="attack_class_opt", help="Attack class to query")
    parser.add_argument("--target-repo", default=None, help="Restrict to an exact target_repo when sibling repos are disabled")
    parser.add_argument("--sibling-repos-ok", dest="sibling_repos_ok", action="store_true", default=True)
    parser.add_argument("--no-sibling-repos-ok", dest="sibling_repos_ok", action="store_false")
    parser.add_argument("--min-outcome-weight", type=float, default=-1.0)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--quality-sidecar", default=str(DEFAULT_RECORD_QUALITY_SIDECAR))
    parser.add_argument("--proof-hardening-sidecar", default=str(DEFAULT_PROOF_HARDENING_SIDECAR))
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
