#!/usr/bin/env python3
"""L22 burndown-queue enhancer: apply rounds 1-10 cumulative blocker-class
taxonomy to the unconsumed rows, mark already-consumed rows, and rank by
yield-impact-effort.

This tool is purely additive: it reads the fresh inventory + base burndown
queue, performs read-only path probes for blocker-class detection, and writes
an enhanced queue JSON with consumption history preserved. It does NOT mutate
the inventory or base queue artifacts.

Inputs:
  --inventory  fresh truth-inventory JSON (rows + counts)
  --base-queue base burndown-queue JSON to enhance (rows + ranked actions)
  --consumed   JSON list of already-consumed row_ids (rounds 1-10)
  --blocker-classes  text file with one blocker-class string per line
                     (formal names from round docs)

Outputs:
  --json-out  enhanced queue JSON. Schema: auditooor.scanner_wiring_burndown_queue_l22.v1

The enhancer ranks by yield-impact-effort:
  - yield: number of un-consumed rows that share at least one blocker class
           assigned to this row (high yield = fixing this class unblocks many)
  - impact: detector path active in wave17 (live) and not graveyard
  - effort: low effort if smoke.json exists for the row and just needs
            promotion_allowed=true flip; high effort if no fixture pair
            visible in source_paths
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.scanner_wiring_burndown_queue_l22.v1"


# Heuristic blocker-class membership probes.
#
# Each entry is (class_name, probe_fn(row, repo_root) -> bool). The probes are
# conservative: only trigger on observable artifacts in row.source_paths or
# adjacent files on disk. Probes never reach beyond the workspace.
def _has_path(paths: list[str], substring: str) -> bool:
    return any(substring in p for p in paths)


def _has_path_re(paths: list[str], pattern: re.Pattern[str]) -> bool:
    return any(pattern.search(p) for p in paths)


def assign_blocker_classes(row: dict[str, Any], repo_root: Path) -> list[str]:
    """Return the cumulative-vocabulary blocker class names that apply.

    The membership rules are heuristics tuned against the per-row JSON
    `tightened_blocker` strings observed across rounds 1-10. Classes are
    canonical names derived from round docs (the per-round backtick names).
    """
    paths = [str(p) for p in row.get("source_paths", [])]
    row_id = str(row.get("row_id") or row.get("scanner_id") or row.get("pattern_id") or "")
    row_id_norm = row_id.lower()
    blockers = [str(b) for b in row.get("blockers", [])]
    proof = str(row.get("proof_status", ""))
    wiring = str(row.get("wiring_status", ""))
    classes: list[str] = []

    # Class 1: graveyard-only at wave_graveyard
    if _has_path(paths, "wave_graveyard/wave13_broken/"):
        classes.append("graveyard_only_at_canonical_slug_under_wave13_broken")
    if _has_path(paths, "wave_graveyard/wave14_broken/"):
        classes.append("graveyard_only_at_canonical_slug_under_wave14_broken")
    if _has_path(paths, "wave_graveyard/syntax_broken/"):
        classes.append("graveyard_sibling_under_syntax_broken_subdir")

    # Class 2: alias DSL namespaces
    if _has_path(paths, "patterns.dsl.r75_mined/c4_lending"):
        classes.append("alias_dsl_at_reference_patterns_dsl_r75_mined_c4_lending")
    if _has_path(paths, "patterns.dsl.r75_mined/c4_yield"):
        classes.append("alias_dsl_at_reference_patterns_dsl_r75_mined_c4_yield")
    if _has_path(paths, "patterns.dsl.r75_mined/c4_derivs"):
        classes.append("alias_dsl_at_reference_patterns_dsl_r75_mined_c4_derivs")
    if _has_path(paths, "patterns.dsl.r76_mined/rekt_postmortems"):
        classes.append("alias_dsl_at_r76_mined_rekt_postmortems")
    if _has_path(paths, "patterns.dsl.r76_mined/solodit_sherlock"):
        classes.append("alias_dsl_at_r76_mined_solodit_sherlock")
    if _has_path(paths, "patterns.dsl.r75_glider/") or _has_path(paths, "patterns.dsl.r76_glider/"):
        classes.append("alias_dsl_at_glider_subdir")
    if _has_path(paths, "_specs/drafts_glider/"):
        classes.append("drafts_glider_alias_DSL")
    if _has_path(paths, "_specs/drafts_audit_text/"):
        classes.append("drafts_audit_text_alias_DSL")

    # Class 3: hyphenated sister dirs
    fixture_paths = [p for p in paths if "/detectors/fixtures/" in p]
    underscore_dirs = {Path(p).parts[Path(p).parts.index("fixtures") + 1] for p in fixture_paths if "fixtures" in Path(p).parts}
    has_dash = any("-" in d for d in underscore_dirs)
    has_underscore = any("_" in d for d in underscore_dirs)
    if has_dash and has_underscore:
        classes.append("hyphenated_SISTER_fixture_dir_present_alongside_underscore_canonical_dir")

    # Class 4: smoke.json indicators
    smoke_paths = [p for p in paths if p.endswith("smoke.json")]
    if smoke_paths:
        # Read the first smoke to inspect canonical fields
        try:
            for sp in smoke_paths[:1]:
                full = repo_root / sp
                if not full.is_file():
                    continue
                with full.open("r", encoding="utf-8") as h:
                    smoke = json.load(h)
                if isinstance(smoke, dict):
                    if smoke.get("promotion_allowed") is False:
                        classes.append("smoke_promotion_allowed_false")
                    cmd = " ".join(
                        str(smoke.get(k, "")) for k in ("positive_command", "clean_command")
                    )
                    if "--include-graveyard" in cmd:
                        classes.append("smoke_command_requires_include_graveyard")
                    if "detector_path" in smoke and "wave_graveyard" in str(smoke["detector_path"]):
                        classes.append("smoke_detector_path_binding_to_graveyard")
                    if "detector_slug" not in smoke:
                        classes.append("smoke_LACKING_detector_slug_field")
                    if "schema" not in smoke:
                        classes.append("smoke_LACKING_schema_field")
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    # Class 5: legacy-shape filenames in fixtures
    if _has_path_re(paths, re.compile(r"_vulnerable\.sol$|_vulnerable\.move$|_vulnerable\.go$")):
        classes.append("canonical_fixture_root_uses_LEGACY_filename_shape_underscore_vulnerable")

    # Class 6: graveyard test_snippet
    if _has_path_re(paths, re.compile(r"\.test\.snippet$")) and _has_path(paths, "wave_graveyard"):
        classes.append("LIVE_wave17_OR_graveyard_test_dot_snippet_artifact")

    # Class 7: missing canonical DSL
    if not _has_path_re(paths, re.compile(r"reference/patterns\.dsl/[^/]+\.yaml$")):
        if _has_path(paths, "/detectors/"):
            classes.append("no_canonical_DSL_yaml_only_detector_present")

    # Class 8: missing canonical fixture root
    if not any("/detectors/fixtures/" in p for p in paths) and _has_path(paths, "/detectors/wave"):
        classes.append("missing_canonical_fixture_root")

    # Class 9: documentation-only
    if wiring == "documentation_only":
        classes.append("documentation_only_no_executable_detector")

    # Class 10: rust source-shape only
    if wiring == "rust_source_shape_only":
        classes.append("rust_source_shape_only_no_runtime_proof")

    # Class 11: in_dsl_fake_suspect
    if wiring == "in_dsl_fake_suspect":
        classes.append("dsl_fake_suspect_marker_present")

    # Class 12: quarantined fake
    if wiring == "quarantined_fake":
        classes.append("quarantined_fake_artifact")

    # Class 13: blocker-string echoes
    blocker_str = " ".join(blockers).lower()
    if "fixture_pair_missing" in blocker_str or "positive_or_vulnerable_fixture_missing" in blocker_str:
        classes.append("fixture_pair_missing")
    if "clean_or_negative_fixture_missing" in blocker_str:
        classes.append("clean_or_negative_fixture_missing")
    if "executor" in blocker_str:
        classes.append("backend_executor_route_unverified")

    # Class 14: explicit slug normalisation gap
    if "_x" in row_id_norm and "-x" in row_id_norm:
        classes.append("slug_normalisation_underscore_x_vs_dash_x")
    if "_x_" in row_id_norm:
        classes.append("slug_double_underscore_x_truncation")

    return sorted(set(classes))


def compute_yield(row: dict[str, Any], class_freq: dict[str, int]) -> int:
    """Yield = sum of frequencies of classes assigned to this row across the
    full unconsumed cohort. Higher = fixing this row's class set unblocks more
    siblings."""
    return sum(class_freq.get(c, 0) for c in row.get("blocker_classes_l22", []))


def compute_impact(row: dict[str, Any]) -> int:
    """Impact = wave17/wave_graveyard detector activity proxy."""
    paths = [str(p) for p in row.get("source_paths", [])]
    score = 0
    if any("wave17" in p for p in paths):
        score += 50
    if any("wave_graveyard" in p for p in paths):
        score += 25
    if any("/detectors/fixtures/" in p for p in paths):
        score += 25
    return score


def compute_effort(row: dict[str, Any]) -> int:
    """Effort = lower is easier-to-flip. We invert this for ranking later."""
    paths = [str(p) for p in row.get("source_paths", [])]
    has_smoke = any(p.endswith("smoke.json") for p in paths)
    has_dsl = any(re.search(r"reference/patterns\.dsl/[^/]+\.yaml$", p) for p in paths)
    has_fixtures = any("/detectors/fixtures/" in p for p in paths)
    classes = row.get("blocker_classes_l22", [])
    if has_smoke and "smoke_promotion_allowed_false" in classes and has_dsl and has_fixtures:
        return 10  # cheapest: just flip promotion_allowed=true after rubric proven
    if has_smoke and has_dsl:
        return 25
    if has_dsl or has_fixtures:
        return 50
    return 90


def compute_l22_score(row: dict[str, Any], class_freq: dict[str, int]) -> int:
    yld = compute_yield(row, class_freq)
    impact = compute_impact(row)
    effort = compute_effort(row)
    # Higher yield+impact, lower effort. Effort weighted to avoid drowning yield.
    return yld * 3 + impact * 2 - effort


def enhance(
    inventory: dict[str, Any],
    base_queue: dict[str, Any],
    consumed: set[str],
    repo_root: Path,
    blocker_class_names: list[str],
) -> dict[str, Any]:
    inv_rows = inventory.get("rows", [])
    rows_by_id: dict[str, dict[str, Any]] = {}
    for r in inv_rows:
        rid = str(r.get("scanner_id") or r.get("pattern_id") or "").strip()
        if not rid:
            continue
        # Prefer the highest-priority hit if multiple inventory rows share the id
        existing = rows_by_id.get(rid)
        if existing is None or r.get("memory_priority", 0) > existing.get("memory_priority", 0):
            rows_by_id[rid] = r

    # Apply blocker class taxonomy to ALL inventory rows (not just queue rows).
    enhanced_rows: list[dict[str, Any]] = []
    for rid, r in rows_by_id.items():
        out = dict(r)
        out["row_id"] = rid
        out["blocker_classes_l22"] = assign_blocker_classes(out, repo_root)
        out["consumed"] = rid in consumed
        enhanced_rows.append(out)

    # Compute class frequencies on the UN-consumed cohort only.
    class_freq: Counter[str] = Counter()
    for r in enhanced_rows:
        if r["consumed"]:
            continue
        for c in r["blocker_classes_l22"]:
            class_freq[c] += 1

    # Score each unconsumed row
    for r in enhanced_rows:
        r["l22_score"] = compute_l22_score(r, class_freq) if not r["consumed"] else 0
        r["l22_yield"] = compute_yield(r, class_freq)
        r["l22_impact"] = compute_impact(r)
        r["l22_effort"] = compute_effort(r)

    # Re-rank: only unconsumed rows, sorted by score desc, then row_id asc
    unconsumed = [r for r in enhanced_rows if not r["consumed"]]
    unconsumed.sort(key=lambda r: (-r["l22_score"], r["row_id"]))

    # Limit ranked queue to top 100 (vs 50 in original) to give L23+ headroom
    top_n = 100
    ranked = unconsumed[:top_n]
    for i, r in enumerate(ranked, start=1):
        r["l22_rank"] = i

    # Parallel low-effort lane: rows with effort <= 25 sorted by yield desc.
    # These are cheap-flip candidates (smoke + DSL + fixtures already on disk;
    # promotion_allowed=true flip is the typical remaining gate).
    low_effort = [r for r in unconsumed if r.get("l22_effort", 999) <= 25]
    low_effort.sort(key=lambda r: (-r["l22_yield"], r["row_id"]))
    low_effort_top = low_effort[:50]
    for i, r in enumerate(low_effort_top, start=1):
        r["l22_low_effort_rank"] = i

    consumed_rows = sorted(
        (r for r in enhanced_rows if r["consumed"]),
        key=lambda r: r["row_id"],
    )
    consumption_history = [
        {
            "row_id": r["row_id"],
            "wiring_status": r.get("wiring_status"),
            "blocker_classes_l22": r["blocker_classes_l22"],
        }
        for r in consumed_rows
    ]

    return {
        "schema": SCHEMA_VERSION,
        "source_inventory_schema": str(inventory.get("schema") or ""),
        "source_inventory_total_row_count": inventory.get("total_row_count"),
        "source_base_queue_schema": str(base_queue.get("schema") or ""),
        "source_base_queue_action_limit": base_queue.get("action_limit"),
        "consumed_count": len(consumed_rows),
        "unconsumed_count": len(unconsumed),
        "ranked_top_n": len(ranked),
        "blocker_class_vocabulary_size": len(blocker_class_names),
        "blocker_class_frequency_top_30": dict(class_freq.most_common(30)),
        "rows_with_at_least_one_blocker_class": sum(1 for r in enhanced_rows if r["blocker_classes_l22"]),
        "rows_flippable_low_effort": sum(1 for r in unconsumed if r.get("l22_effort", 999) <= 25),
        "ranked_queue": ranked,
        "low_effort_lane_top_n": len(low_effort_top),
        "low_effort_lane": low_effort_top,
        "consumption_history": consumption_history,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--base-queue", required=True, type=Path)
    parser.add_argument("--consumed", required=True, type=Path)
    parser.add_argument("--blocker-classes", required=True, type=Path)
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args(argv)

    with args.inventory.open("r", encoding="utf-8") as h:
        inventory = json.load(h)
    with args.base_queue.open("r", encoding="utf-8") as h:
        base_queue = json.load(h)
    with args.consumed.open("r", encoding="utf-8") as h:
        consumed_list = json.load(h)
    with args.blocker_classes.open("r", encoding="utf-8") as h:
        names = [line.strip() for line in h if line.strip()]

    payload = enhance(
        inventory,
        base_queue,
        consumed=set(consumed_list),
        repo_root=args.repo_root.resolve(),
        blocker_class_names=names,
    )

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"L22 enhanced queue written: rows_in={inventory.get('total_row_count')} "
        f"consumed={payload['consumed_count']} unconsumed={payload['unconsumed_count']} "
        f"ranked_top_n={payload['ranked_top_n']} "
        f"flippable_low_effort={payload['rows_flippable_low_effort']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
