#!/usr/bin/env python3
"""predicate-domain-coverage-verifier.py - PHASE-II.5 predicate coverage helper.

Small standalone, hermetic verifier for predicate-domain coverage evidence. It
reads the existing `P1_INVARIANT_PREDICATES` registry from
`live-target-intelligence-report.py` and optionally parses a live-target JSON
report to summarize `SEMANTIC-MATCH` results by domain.

No provider/network calls. Stdlib only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.predicate_domain_coverage.v1"
TOOL_VERSION = "0.1.0"
INV_ID_RE = re.compile(r"^INV-([A-Z0-9]+)-")

REPO_ROOT = Path(__file__).resolve().parents[1]
LTIR_PATH = REPO_ROOT / "tools" / "live-target-intelligence-report.py"


def _load_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("_ltir_predicate_source", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_domain(inv_id: str) -> str:
    m = INV_ID_RE.match(inv_id)
    if not m:
        return "UNKNOWN"
    return m.group(1)


def _sorted_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _to_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _load_domains_from_predicates() -> dict[str, list[str]]:
    if not LTIR_PATH.is_file():
        raise FileNotFoundError(f"live-target-intelligence-report missing: {LTIR_PATH}")

    ltir = _load_module(LTIR_PATH)
    predicates = getattr(ltir, "P1_INVARIANT_PREDICATES", None)
    if not isinstance(predicates, dict):
        raise TypeError("P1_INVARIANT_PREDICATES not available in source module")

    by_domain: dict[str, list[str]] = {}
    for inv_id in predicates:
        if not isinstance(inv_id, str):
            continue
        by_domain.setdefault(_extract_domain(inv_id), []).append(inv_id)

    for domain in list(by_domain):
        by_domain[domain] = _sorted_unique(sorted(by_domain[domain]))
    return by_domain


def _entry_points(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    candidates = [
        payload.get("entry_points"),
        payload.get("prioritized_hunt_list"),
        payload.get("prioritized_entries"),
        payload.get("entries"),
        payload.get("rows"),
    ]

    for bucket in candidates:
        if isinstance(bucket, list):
            return [item for item in bucket if isinstance(item, dict)]

    return []


def _count_semantic_by_domain(
    rows: list[dict[str, Any]],
    domain_predicate_index: set[str],
) -> dict[str, dict[str, int]]:
    if not rows:
        return {}

    entry_counter: Counter[str] = Counter()
    invariant_counter: Counter[str] = Counter()
    seen_unknown: Counter[str] = Counter()

    for row in rows:
        if str(row.get("p1_match_tier") or "").upper() != "SEMANTIC-MATCH":
            continue

        semantic_ids = _to_list(
            row.get("semantic_p1_invariants")
            or row.get("semantic_invariants")
            or row.get("matched_p1_invariants")
            or row.get("p1_invariant_hits")
        )
        if not semantic_ids:
            continue

        # Count one entry per domain per row to avoid double-counting rows that match
        # multiple predicates in the same domain.
        row_domains: set[str] = set()
        for inv_id in semantic_ids:
            domain = _extract_domain(str(inv_id))
            if domain not in domain_predicate_index:
                seen_unknown[domain] += 1
                continue
            invariant_counter[domain] += 1
            row_domains.add(domain)
        for domain in row_domains:
            entry_counter[domain] += 1

    return {
        domain: {
            "entry_hits": entry_counter.get(domain, 0),
            "invariant_hits": invariant_counter.get(domain, 0),
        }
        for domain in sorted(set(entry_counter) | set(invariant_counter) | set(seen_unknown))
    }


def build_verifier_payload(
    *,
    live_target_json: Path | None = None,
) -> dict[str, Any]:
    by_domain_predicates = _load_domains_from_predicates()
    domain_predicate_ids = by_domain_predicates
    predicate_domain_ids = sorted(domain_predicate_ids)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "predicate_domain_ids": predicate_domain_ids,
        "predicate_by_domain": {
            domain: {"count": len(ids), "predicates": ids}
            for domain, ids in by_domain_predicates.items()
        },
        "predicate_total_count": sum(len(v) for v in by_domain_predicates.values()),
        "live_target_report": None,
        "semantic_match_counts": {
            domain: {"entry_hits": 0, "invariant_hits": 0}
            for domain in predicate_domain_ids
        },
    }

    if live_target_json is None:
        return payload

    if not live_target_json.is_file():
        payload["live_target_report"] = {
            "path": str(live_target_json),
            "status": "missing",
        }
        return payload

    try:
        report = json.loads(live_target_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        payload["live_target_report"] = {
            "path": str(live_target_json),
            "status": "invalid_json",
            "error": str(exc),
        }
        return payload

    rows = _entry_points(report)
    predicate_domain_index = set(predicate_domain_ids)
    counts = _count_semantic_by_domain(rows, predicate_domain_index)
    semantic_match_rows = 0
    for row in rows:
        if str(row.get("p1_match_tier") or "").upper() != "SEMANTIC-MATCH":
            continue
        semantic_ids = _to_list(
            row.get("semantic_p1_invariants")
            or row.get("semantic_invariants")
            or row.get("matched_p1_invariants")
            or row.get("p1_invariant_hits")
        )
        if any(_extract_domain(str(inv_id)) in predicate_domain_index for inv_id in semantic_ids):
            semantic_match_rows += 1

    domain_hits = dict(payload["semantic_match_counts"])
    for domain, count in counts.items():
        domain_hits.setdefault(domain, {"entry_hits": 0, "invariant_hits": 0})
        domain_hits[domain]["entry_hits"] += count["entry_hits"]
        domain_hits[domain]["invariant_hits"] += count["invariant_hits"]

    payload["live_target_report"] = {
        "path": str(live_target_json),
        "status": "ok",
        "matched_rows": len(rows),
        "semantic_match_rows": semantic_match_rows,
    }
    payload["semantic_match_counts"] = {
        domain: domain_hits[domain] for domain in sorted(domain_hits)
    }

    return payload


def _print_summary(payload: dict[str, Any]) -> None:
    domains = payload.get("predicate_domain_ids", [])
    print("predicate domains:", len(domains))
    for domain in domains:
        predicates = payload["predicate_by_domain"].get(domain, {}).get("count", 0)
        counts = payload.get("semantic_match_counts", {}).get(domain, {})
        print(
            f"  {domain}: predicates={predicates} "
            f"semantic_entry_hits={counts.get('entry_hits', 0)} "
            f"semantic_invariant_hits={counts.get('invariant_hits', 0)}"
        )
    report = payload.get("live_target_report")
    if isinstance(report, dict):
        print("live-target report:", report.get("status"), report.get("path"))
        if report.get("status") == "ok":
            print(
                "  matched rows:",
                report.get("matched_rows", 0),
                "semantic rows:",
                report.get("semantic_match_rows", 0),
            )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report per-domain P1 predicate IDs and, optionally, SEMANTIC-MATCH counts\n"
            "from a live-target report JSON. No provider/network calls."
        )
    )
    parser.add_argument(
        "--live-target-report",
        type=Path,
        default=None,
        help="Optional live-target-intelligence-report JSON path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON payload only.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional path to write the JSON payload as a CI artifact.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        payload = build_verifier_payload(live_target_json=args.live_target_report)
        if args.output_json is not None:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        _print_summary(payload)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[predicate-domain-coverage-verifier] FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
