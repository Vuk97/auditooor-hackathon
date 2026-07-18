#!/usr/bin/env python3
"""Wave-2 PR-A: dual-form record audit for the hackerman corpus.

Background
----------
The W2.5 tier-3 promotion verification agent (commit ``803c97f9e4``) surfaced
a WARNING against the live corpus: the additive
``audit/corpus_tags/index/by_verification_tier.jsonl`` index numerically
*undercounts* a handful of prefixes (bridge-incident, mev-exploits, movebit,
solana-svm, zkbugs, zkbugtracker) by a factor of 2x relative to a naive
file-walk count.

Root cause (per the W2.5 finding):
    The affected prefixes have records emitted in BOTH a ``record.yaml`` and
    a sibling ``record.json`` form. A naive file walker counts each form
    separately, but the indexer canonicalises by ``record_id`` so each record
    contributes exactly one row to the index. The corpus state is correct;
    the "undercount" is an artifact of dual-form duplication on disk.

This tool gives an explicit, mechanical, language-agnostic verdict on:

  1. Which records exist in dual form (both ``<stem>.yaml`` and
     ``<stem>.json``) on disk?
  2. Do the dual-form siblings agree on ``record_id``? Disagreement is a
     real corpus-integrity defect; agreement is benign duplication.
  3. Do the 5 Wave-2 additive indexes (``by_cve_id``, ``by_ghsa_id``,
     ``by_firm``, ``by_verification_tier``, ``by_incident_date``)
     contain the deduplicated, canonicalised row-count expected from
     the unique ``record_id`` set, or are they doubled / inflated?

Schema
------
Emits a JSON status pack ``auditooor.wave2_index_dual_form_audit.v1`` with:

    {
      "schema": "auditooor.wave2_index_dual_form_audit.v1",
      "workspace": <abs path>,
      "tags_root": <abs path>,
      "index_dir": <abs path>,
      "dual_form_record_count": <int>,
      "single_form_record_count": <int>,
      "total_unique_records": <int>,
      "prefix_breakdown": {
        "<prefix>": {
          "total_records": <int>,
          "dual_form_count": <int>,
          "single_form_count": <int>,
          "ratio": <float (dual / total)>,
          "inconsistent_record_ids": <int>
        }
      },
      "index_inflation_per_index": {
        "<index_name>": {
          "current_row_count": <int>,
          "unique_record_id_count": <int>,
          "inflated_by": <int>,        # current - unique
          "inflated": <bool>
        }
      },
      "affected_prefixes": [<prefix>, ...],
      "inconsistent_examples": [{<path_yaml>, <path_json>, <rid_yaml>, <rid_json>}, ...],
      "overall_status": "PASS" | "WARNING" | "FAIL",
      "summary": <str>
    }

CLI
---
    python3 tools/wave2-index-dual-form-audit.py \\
        --workspace . \\
        [--json] [--verbose] \\
        [--emit-corrected-indexes /tmp/corrected_indexes]

When ``--emit-corrected-indexes <dir>`` is passed, the tool writes a
deduplicated copy of each of the 5 additive indexes into ``<dir>`` for
operator review. The live ``audit/corpus_tags/index/`` is never mutated.

Exit codes
----------
    0   overall_status == PASS
    0   overall_status == WARNING (dual-form present but record_ids consistent)
    1   overall_status == FAIL (dual-form siblings disagree on record_id)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCHEMA = "auditooor.wave2_index_dual_form_audit.v1"

# The 5 Wave-2 additive indexes the tool audits.
ADDITIVE_INDEXES = (
    "by_cve_id",
    "by_ghsa_id",
    "by_firm",
    "by_verification_tier",
    "by_incident_date",
)

# Regex to pull record_id out of a YAML record without needing a YAML parser
# (the corpus uses a stable line-prefix shape ``record_id: <value>``).
YAML_RID_RE = re.compile(r"^record_id\s*:\s*([^\s#]+)", re.MULTILINE)

EXCLUDED_DIR_PREFIXES = ("_QUARANTINE", "_deprecated")


def _is_excluded(rel_parts: Tuple[str, ...]) -> bool:
    """Return True if any path segment names an excluded subtree."""
    for part in rel_parts:
        for ex in EXCLUDED_DIR_PREFIXES:
            if part.startswith(ex):
                return True
    return False


def _read_record_id(path: Path) -> Optional[str]:
    """Best-effort extraction of ``record_id`` from a record.yaml/.json file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if path.suffix == ".yaml":
        m = YAML_RID_RE.search(text)
        if m:
            val = m.group(1).strip().strip('"').strip("'")
            return val or None
        return None
    if path.suffix == ".json":
        try:
            obj = json.loads(text)
        except (ValueError, json.JSONDecodeError):
            return None
        if isinstance(obj, dict):
            rid = obj.get("record_id")
            if isinstance(rid, str):
                return rid.strip()
    return None


def _prefix_of(record_id: str) -> str:
    """Return the corpus-prefix (first segment before ``:``) of a record_id."""
    return record_id.split(":", 1)[0] if ":" in record_id else record_id


def _walk_records(tags_root: Path) -> Tuple[Dict[Tuple[Path, str], Set[str]], List[Path]]:
    """Walk the tags tree, grouping (dir, stem) -> {extension}.

    Returns:
        records:       dict mapping (dirpath, stem) -> set of {"yaml","json"}.
        skipped_dirs:  list of directories that were skipped (excluded subtrees).
    """
    records: Dict[Tuple[Path, str], Set[str]] = {}
    skipped: List[Path] = []
    if not tags_root.is_dir():
        return records, skipped
    for dirpath_str, dirnames, filenames in os.walk(tags_root):
        dirpath = Path(dirpath_str)
        rel = dirpath.relative_to(tags_root)
        rel_parts = tuple(p for p in rel.parts if p != ".")
        if _is_excluded(rel_parts):
            skipped.append(dirpath)
            # prune walk
            dirnames[:] = []
            continue
        # Also prune child quarantine/deprecated dirs before descending
        keep = []
        for d in dirnames:
            if any(d.startswith(ex) for ex in EXCLUDED_DIR_PREFIXES):
                skipped.append(dirpath / d)
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in filenames:
            if fn.endswith(".yaml"):
                stem = fn[:-5]
                records.setdefault((dirpath, stem), set()).add("yaml")
            elif fn.endswith(".json"):
                stem = fn[:-5]
                records.setdefault((dirpath, stem), set()).add("json")
    return records, skipped


def _scan_corpus(
    tags_root: Path,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Classify every record on disk and aggregate per-prefix stats."""
    records, skipped = _walk_records(tags_root)
    prefix_stats: Dict[str, Dict[str, int]] = {}
    inconsistent_examples: List[Dict[str, Any]] = []
    dual_form_count = 0
    single_form_count = 0
    unrid_count = 0
    for (dirpath, stem), exts in records.items():
        yaml_path = dirpath / (stem + ".yaml") if "yaml" in exts else None
        json_path = dirpath / (stem + ".json") if "json" in exts else None
        # Choose canonical: prefer yaml (matches index emitter)
        canonical_path = yaml_path or json_path
        rid = _read_record_id(canonical_path) if canonical_path else None
        if rid is None:
            unrid_count += 1
            continue
        pfx = _prefix_of(rid)
        st = prefix_stats.setdefault(
            pfx,
            {
                "total_records": 0,
                "dual_form_count": 0,
                "single_form_count": 0,
                "inconsistent_record_ids": 0,
            },
        )
        st["total_records"] += 1
        if "yaml" in exts and "json" in exts:
            st["dual_form_count"] += 1
            dual_form_count += 1
            # Verify both forms agree on record_id
            rid_y = _read_record_id(yaml_path)
            rid_j = _read_record_id(json_path)
            if rid_y and rid_j and rid_y != rid_j:
                st["inconsistent_record_ids"] += 1
                if len(inconsistent_examples) < 25:
                    inconsistent_examples.append(
                        {
                            "yaml_path": str(yaml_path),
                            "json_path": str(json_path),
                            "yaml_record_id": rid_y,
                            "json_record_id": rid_j,
                        }
                    )
        else:
            st["single_form_count"] += 1
            single_form_count += 1
    # finalise ratio
    prefix_breakdown: Dict[str, Dict[str, Any]] = {}
    for pfx, st in prefix_stats.items():
        total = st["total_records"]
        ratio = (st["dual_form_count"] / total) if total else 0.0
        prefix_breakdown[pfx] = {
            "total_records": total,
            "dual_form_count": st["dual_form_count"],
            "single_form_count": st["single_form_count"],
            "ratio": round(ratio, 4),
            "inconsistent_record_ids": st["inconsistent_record_ids"],
        }
    affected = sorted(p for p, st in prefix_breakdown.items() if st["dual_form_count"] > 0)
    return {
        "prefix_breakdown": prefix_breakdown,
        "affected_prefixes": affected,
        "dual_form_record_count": dual_form_count,
        "single_form_record_count": single_form_count,
        "total_unique_records": dual_form_count + single_form_count,
        "records_without_record_id": unrid_count,
        "skipped_subtrees": [str(p) for p in skipped],
        "inconsistent_examples": inconsistent_examples,
    }


def _audit_indexes(
    index_dir: Path,
    emit_corrected_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Count rows / unique record_ids per additive index.

    If ``emit_corrected_dir`` is given, write a deduplicated copy of each
    index to that directory (for operator review). The live index dir
    is never mutated.
    """
    out: Dict[str, Any] = {}
    if emit_corrected_dir is not None:
        emit_corrected_dir.mkdir(parents=True, exist_ok=True)
    for idx in ADDITIVE_INDEXES:
        path = index_dir / f"{idx}.jsonl"
        info: Dict[str, Any] = {
            "path": str(path),
            "exists": path.exists(),
            "current_row_count": 0,
            "unique_record_id_count": 0,
            "inflated_by": 0,
            "inflated": False,
        }
        if not path.exists():
            out[idx] = info
            continue
        seen: Dict[str, str] = {}  # record_id -> first raw line
        rows = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        continue
                    rows += 1
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rid = obj.get("record_id")
                    if isinstance(rid, str) and rid not in seen:
                        seen[rid] = line
        except OSError:
            pass
        info["current_row_count"] = rows
        info["unique_record_id_count"] = len(seen)
        info["inflated_by"] = rows - len(seen)
        info["inflated"] = rows > len(seen)
        out[idx] = info
        if emit_corrected_dir is not None:
            corrected_path = emit_corrected_dir / f"{idx}.jsonl"
            with corrected_path.open("w", encoding="utf-8") as cf:
                for line in seen.values():
                    cf.write(line if line.endswith("\n") else line + "\n")
    return out


def _build_verdict(corpus: Dict[str, Any], idx_audit: Dict[str, Any]) -> Tuple[str, str]:
    """Compute overall_status + summary."""
    total_inconsistent = sum(
        st["inconsistent_record_ids"]
        for st in corpus["prefix_breakdown"].values()
    )
    inflated_indexes = [k for k, v in idx_audit.items() if v.get("inflated")]
    if total_inconsistent > 0:
        status = "FAIL"
        summary = (
            f"FAIL: {total_inconsistent} dual-form record(s) have mismatched record_id "
            f"between their .yaml and .json forms (corpus-integrity defect)."
        )
        return status, summary
    if corpus["dual_form_record_count"] > 0 or inflated_indexes:
        status = "WARNING"
        bits = [
            f"{corpus['dual_form_record_count']} dual-form record(s) across "
            f"{len(corpus['affected_prefixes'])} prefix(es)"
        ]
        if inflated_indexes:
            bits.append(f"{len(inflated_indexes)} index(es) inflated: {','.join(inflated_indexes)}")
        else:
            bits.append("all 5 additive indexes deduplicated correctly")
        summary = "WARNING: " + "; ".join(bits) + "."
        return status, summary
    return "PASS", "PASS: no dual-form records on disk; all 5 additive indexes clean."


def audit(
    workspace: Path,
    *,
    emit_corrected_dir: Optional[Path] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    tags_root = workspace / "audit" / "corpus_tags" / "tags"
    index_dir = workspace / "audit" / "corpus_tags" / "index"
    corpus = _scan_corpus(tags_root, verbose=verbose)
    idx_audit = _audit_indexes(index_dir, emit_corrected_dir=emit_corrected_dir)
    status, summary = _build_verdict(corpus, idx_audit)
    return {
        "schema": SCHEMA,
        "workspace": str(workspace.resolve()),
        "tags_root": str(tags_root.resolve()),
        "index_dir": str(index_dir.resolve()),
        "additive_indexes": list(ADDITIVE_INDEXES),
        "dual_form_record_count": corpus["dual_form_record_count"],
        "single_form_record_count": corpus["single_form_record_count"],
        "total_unique_records": corpus["total_unique_records"],
        "records_without_record_id": corpus["records_without_record_id"],
        "prefix_breakdown": corpus["prefix_breakdown"],
        "affected_prefixes": corpus["affected_prefixes"],
        "skipped_subtrees": corpus["skipped_subtrees"],
        "inconsistent_examples": corpus["inconsistent_examples"],
        "index_inflation_per_index": idx_audit,
        "overall_status": status,
        "summary": summary,
    }


def _render_text(pack: Dict[str, Any]) -> str:
    """Human-readable rendering for ``--verbose`` / non-``--json`` mode."""
    lines: List[str] = []
    lines.append(f"schema={pack['schema']}")
    lines.append(f"workspace={pack['workspace']}")
    lines.append(f"overall_status={pack['overall_status']}")
    lines.append(f"summary={pack['summary']}")
    lines.append(
        f"dual_form_record_count={pack['dual_form_record_count']} "
        f"single_form_record_count={pack['single_form_record_count']} "
        f"total_unique_records={pack['total_unique_records']}"
    )
    if pack["affected_prefixes"]:
        lines.append("affected_prefixes:")
        for pfx in pack["affected_prefixes"]:
            st = pack["prefix_breakdown"][pfx]
            lines.append(
                f"  {pfx:30s} total={st['total_records']:6d} "
                f"dual={st['dual_form_count']:6d} single={st['single_form_count']:6d} "
                f"ratio={st['ratio']:.4f} inconsistent={st['inconsistent_record_ids']}"
            )
    lines.append("index_inflation_per_index:")
    for idx, info in pack["index_inflation_per_index"].items():
        lines.append(
            f"  {idx:24s} rows={info['current_row_count']:6d} "
            f"unique={info['unique_record_id_count']:6d} "
            f"inflated_by={info['inflated_by']:6d} inflated={info['inflated']}"
        )
    if pack["inconsistent_examples"]:
        lines.append("inconsistent_examples (first 25):")
        for ex in pack["inconsistent_examples"]:
            lines.append(
                f"  yaml_rid={ex['yaml_record_id']} json_rid={ex['json_record_id']}"
            )
            lines.append(f"    yaml_path={ex['yaml_path']}")
            lines.append(f"    json_path={ex['json_path']}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit hackerman corpus for dual-form record duplication "
        "and quantify the resulting (potential) index inflation.",
    )
    ap.add_argument(
        "--workspace",
        default=".",
        help="auditooor workspace root (default: cwd).",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="emit the JSON status pack on stdout.",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="also include human-readable rendering on stderr.",
    )
    ap.add_argument(
        "--emit-corrected-indexes",
        default=None,
        metavar="DIR",
        help="write deduplicated copies of the 5 additive indexes "
        "to DIR for operator review (live index dir is never mutated).",
    )
    args = ap.parse_args(argv)
    workspace = Path(args.workspace).resolve()
    emit_dir = Path(args.emit_corrected_indexes).resolve() if args.emit_corrected_indexes else None
    pack = audit(workspace, emit_corrected_dir=emit_dir, verbose=args.verbose)
    if args.json:
        sys.stdout.write(json.dumps(pack, indent=2, sort_keys=True))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(_render_text(pack))
        sys.stdout.write("\n")
    if args.verbose and args.json:
        sys.stderr.write(_render_text(pack))
        sys.stderr.write("\n")
    return 0 if pack["overall_status"] in ("PASS", "WARNING") else 1


if __name__ == "__main__":
    sys.exit(main())
