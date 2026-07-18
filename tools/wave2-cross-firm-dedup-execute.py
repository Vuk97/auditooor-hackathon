#!/usr/bin/env python3
"""Wave-3 W3.9 cross-firm dedup execution.

The companion detector at tools/wave2-cross-firm-dedup-detector.py emits a
candidate cluster list under schema auditooor.wave2_cross_firm_dedup_detector.v1.
That detector is read-only by design (W2.6 detect-first / mutate-later
discipline). This executor consumes the same cluster output, applies a
canonical-pick + source-URL merge, and writes the resulting redirects to the
record files on disk.

Mutation policy (mirrors W2.6 cosmos-sdk dedup canonicalization at commit
8fa397589f):

* Records are NEVER deleted.
* Non-canonical members in a high-confidence cluster (Jaccard >= 0.8 by
  default) get a top-level ``redirected_to: <canonical-record-id>`` field
  appended to record.yaml. Schema updated to allow this property.
* Source URLs from every cluster member are merged into the canonical
  record's ``source_audit_ref`` field (list-typed, deduped, deterministic
  order) so the canonical record carries the full evidence trail.
* Clusters with Jaccard in [0.6, 0.8) are reported as ``deferred`` and not
  mutated; they require manual review.

Output:
* Per-execution migration log JSON at
  ``audit/migrations/wave3_w39_cross_firm_dedup_<UTC>.json``
  (schema: auditooor.wave3_w39_cross_firm_dedup_execute.v1).
* Stdout summary: pairs detected / executed / deferred.

CLI:
    python3 tools/wave2-cross-firm-dedup-execute.py \\
        --workspace . \\
        --execute-threshold 0.8 \\
        --defer-threshold 0.6 \\
        [--dry-run] [--json]

Discipline:
* Detect-first / mutate-later (W2.6 precedent at commit 8fa397589f).
* No record is deleted; mutations are append-only on existing records.
* ASCII hyphens only per CLAUDE.md formatting rules.
* Does NOT modify tools/calibration/llm_budget_log.jsonl.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import the sibling detector module so we share record-collection +
# cluster-build code paths exactly.
_DETECTOR_PATH = Path(__file__).resolve().parent / "wave2-cross-firm-dedup-detector.py"
_spec = importlib.util.spec_from_file_location(
    "_w2_cross_firm_dedup_detector", _DETECTOR_PATH
)
if _spec is None or _spec.loader is None:
    print(
        f"[wave2-cross-firm-dedup-execute] cannot load sibling detector at {_DETECTOR_PATH}",
        file=sys.stderr,
    )
    sys.exit(2)
_detector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_detector)

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover - env smoke
    print(
        f"[wave2-cross-firm-dedup-execute] PyYAML required: {exc}",
        file=sys.stderr,
    )
    sys.exit(2)


SCHEMA_ID = "auditooor.wave3_w39_cross_firm_dedup_execute.v1"
DEFAULT_EXECUTE_THRESHOLD = 0.8
DEFAULT_DEFER_THRESHOLD = 0.6


def _merge_source_audit_refs(
    canon_path: Path,
    non_canon_paths: List[Path],
) -> Tuple[List[str], List[str]]:
    """Return (merged_refs, refs_added) for the canonical record."""
    refs: List[str] = []
    seen: set = set()

    def _add(ref: Any) -> None:
        if ref is None:
            return
        if isinstance(ref, list):
            for r in ref:
                _add(r)
            return
        s = str(ref).strip()
        if not s or s in seen:
            return
        seen.add(s)
        refs.append(s)

    # Start with the canonical's existing refs (preserve order).
    with open(canon_path) as f:
        canon = yaml.safe_load(f) or {}
    canon_refs = canon.get("source_audit_ref")
    _add(canon_refs)
    # Also fold in record_source_url if set; it is a per-record evidence URL.
    canon_url = canon.get("record_source_url")
    if canon_url:
        _add(canon_url)

    pre_len = len(refs)
    # Then non-canonical refs.
    for p in non_canon_paths:
        with open(p) as f:
            r = yaml.safe_load(f) or {}
        _add(r.get("source_audit_ref"))
        url = r.get("record_source_url")
        if url:
            _add(url)
    added = refs[pre_len:]
    return refs, added


def _apply_redirect(
    record_path: Path,
    canonical_record_id: str,
    *,
    dry_run: bool,
) -> bool:
    """Append ``redirected_to`` to a record YAML in-place. Returns True if mutated."""
    with open(record_path) as f:
        rec = yaml.safe_load(f) or {}
    if not isinstance(rec, dict):
        return False
    if rec.get("redirected_to") == canonical_record_id:
        return False  # already redirected; idempotent no-op
    if dry_run:
        return True
    rec["redirected_to"] = canonical_record_id
    # Preserve YAML key ordering as best we can (PyYAML emits keys
    # alphabetically by default; consumers do not depend on key order).
    with open(record_path, "w") as f:
        yaml.safe_dump(rec, f, sort_keys=True, allow_unicode=True)
    return True


def _write_canonical_source_refs(
    canon_path: Path,
    merged_refs: List[str],
    *,
    dry_run: bool,
) -> bool:
    """Write merged source_audit_ref list onto canonical record."""
    with open(canon_path) as f:
        rec = yaml.safe_load(f) or {}
    existing = rec.get("source_audit_ref")
    # Determine if we actually need to mutate.
    if isinstance(existing, list):
        if existing == merged_refs:
            return False
    elif isinstance(existing, str):
        if [existing] == merged_refs:
            return False
    if dry_run:
        return True
    rec["source_audit_ref"] = merged_refs
    with open(canon_path, "w") as f:
        yaml.safe_dump(rec, f, sort_keys=True, allow_unicode=True)
    return True


def execute(
    workspace: Path,
    *,
    execute_threshold: float = DEFAULT_EXECUTE_THRESHOLD,
    defer_threshold: float = DEFAULT_DEFER_THRESHOLD,
    min_cluster_size: int = 2,
    firms_filter: Optional[set] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    tags_root = workspace / "audit" / "corpus_tags" / "tags"
    if not tags_root.is_dir():
        return {
            "schema": SCHEMA_ID,
            "workspace": str(workspace),
            "tags_root": str(tags_root),
            "status": "ERROR",
            "error": f"tags_root not found: {tags_root}",
        }

    records = _detector.collect_records(tags_root, firms_filter=firms_filter)
    # Build clusters at the defer threshold so we capture everything in
    # [defer, execute) for the deferred bucket.
    clusters = _detector.build_clusters(
        records,
        min_similarity=defer_threshold,
        min_cluster_size=min_cluster_size,
    )

    # Honesty diagnostic (W3.9 M14-trap discipline).
    #
    # The real audit_firm_public_reports corpus subtree holds one INDEX
    # record per published audit report (uniform attack_class
    # ``audit-firm-public-report``, no per-finding ``title``). Two reports
    # of the same protocol by two firms are distinct evidence, NOT the same
    # finding - collapsing them would fabricate an equivalence and lose a
    # distinct report URL. The detector therefore (correctly) produces 0
    # finding-level clusters on this subtree. When per-finding firm records
    # land later, the same code path will cluster them. ``corpus_profile``
    # makes the empty result legible rather than mistakable for a bug.
    titled = sum(1 for r in records if str(r.get("title") or "").strip())
    distinct_attack_classes = sorted(
        {r.get("attack_class", "") for r in records if r.get("attack_class")}
    )
    index_only = (
        bool(records)
        and titled == 0
        and distinct_attack_classes == ["audit-firm-public-report"]
    )
    corpus_profile = {
        "records_with_finding_title": titled,
        "distinct_attack_classes": distinct_attack_classes,
        "report_index_records_only": index_only,
        "note": (
            "NEGATIVE-EMPTY: subtree holds per-report index records, not "
            "per-finding records; cross-firm finding dedup has no signal "
            "to act on. This is a valid honest result, not a tool failure."
        )
        if index_only
        else "per-finding records present; dedup operates normally.",
    }

    executed: List[Dict[str, Any]] = []
    deferred: List[Dict[str, Any]] = []

    for c in clusters:
        sim = float(c.get("similarity_score") or 0.0)
        if sim < execute_threshold:
            deferred.append({
                "cluster_id": c["cluster_id"],
                "protocol_normalized": c["protocol_normalized"],
                "attack_class": c["attack_class"],
                "severity_normalized": c["severity_normalized"],
                "similarity_score": sim,
                "cluster_size": c["cluster_size"],
                "record_ids": list(c["record_ids"]),
                "firms_involved": list(c["firms_involved"]),
                "synthetic_fixture_only": c.get("synthetic_fixture_only", False),
                "reason": (
                    f"similarity_score={sim} in [{defer_threshold}, "
                    f"{execute_threshold}); manual review required"
                ),
            })
            continue

        # High-confidence cluster: execute.
        canon = c["recommended_canonical"]
        canon_id = canon["record_id"]
        canon_path = Path(canon["yaml_path"])
        non_canon_paths = [
            Path(p) for p in c["yaml_paths"] if Path(p) != canon_path
        ]

        merged_refs, refs_added = _merge_source_audit_refs(
            canon_path, non_canon_paths
        )
        canon_mutated = _write_canonical_source_refs(
            canon_path, merged_refs, dry_run=dry_run
        )

        redirects = []
        for p in non_canon_paths:
            mutated = _apply_redirect(p, canon_id, dry_run=dry_run)
            redirects.append({
                "record_path": str(p),
                "redirected_to": canon_id,
                "mutated": mutated,
            })

        executed.append({
            "cluster_id": c["cluster_id"],
            "protocol_normalized": c["protocol_normalized"],
            "attack_class": c["attack_class"],
            "severity_normalized": c["severity_normalized"],
            "similarity_score": sim,
            "cluster_size": c["cluster_size"],
            "canonical_record_id": canon_id,
            "canonical_record_path": str(canon_path),
            "firms_involved": list(c["firms_involved"]),
            "source_urls_after_merge": merged_refs,
            "source_urls_added_to_canonical": refs_added,
            "canonical_mutated": canon_mutated,
            "redirects_applied": redirects,
            "synthetic_fixture_only": c.get("synthetic_fixture_only", False),
        })

    return {
        "schema": SCHEMA_ID,
        "workspace": str(workspace),
        "tags_root": str(tags_root),
        "execute_threshold": execute_threshold,
        "defer_threshold": defer_threshold,
        "min_cluster_size": min_cluster_size,
        "firms_filter": sorted(firms_filter) if firms_filter else [],
        "total_firm_records_scanned": len(records),
        "firms_scanned": sorted({r["firm"] for r in records}),
        "corpus_profile": corpus_profile,
        "clusters_detected": len(clusters),
        "clusters_executed": len(executed),
        "clusters_deferred": len(deferred),
        "executed": executed,
        "deferred": deferred,
        "dry_run": dry_run,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def _utc_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def _migration_log_path(workspace: Path) -> Path:
    return (
        workspace
        / "audit"
        / "migrations"
        / "wave3_w39_cross_firm_dedup_2026-05-16.json"
    )


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Wave-3 W3.9 cross-firm dedup executor (apply redirects)."
    )
    p.add_argument("--workspace", default=".")
    p.add_argument(
        "--execute-threshold",
        type=float,
        default=DEFAULT_EXECUTE_THRESHOLD,
        help="Jaccard cutoff at which a cluster is auto-executed (default 0.8).",
    )
    p.add_argument(
        "--defer-threshold",
        type=float,
        default=DEFAULT_DEFER_THRESHOLD,
        help="Lower Jaccard cutoff for deferred clusters (default 0.6).",
    )
    p.add_argument("--min-cluster-size", type=int, default=2)
    p.add_argument(
        "--firms",
        default="",
        help="Comma-separated firm slugs to restrict the scan.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute candidate redirects without writing to disk.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the JSON payload to stdout in addition to the migration log.",
    )
    p.add_argument(
        "--migration-log",
        default="",
        help="Override the default migration log path.",
    )
    args = p.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    firms_filter = (
        {f.strip() for f in args.firms.split(",") if f.strip()}
        if args.firms
        else None
    )
    if args.defer_threshold > args.execute_threshold:
        print(
            "[wave2-cross-firm-dedup-execute] --defer-threshold must be "
            "<= --execute-threshold",
            file=sys.stderr,
        )
        return 2

    result = execute(
        workspace,
        execute_threshold=args.execute_threshold,
        defer_threshold=args.defer_threshold,
        min_cluster_size=args.min_cluster_size,
        firms_filter=firms_filter,
        dry_run=args.dry_run,
    )

    log_path = (
        Path(args.migration_log).resolve()
        if args.migration_log
        else _migration_log_path(workspace)
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"[wave2-cross-firm-dedup-execute] workspace={workspace} "
            f"scanned={result.get('total_firm_records_scanned', 0)} "
            f"detected={result.get('clusters_detected', 0)} "
            f"executed={result.get('clusters_executed', 0)} "
            f"deferred={result.get('clusters_deferred', 0)} "
            f"dry_run={result.get('dry_run', False)}"
        )
        print(
            f"[wave2-cross-firm-dedup-execute] migration log: {log_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
