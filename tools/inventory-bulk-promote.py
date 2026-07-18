#!/usr/bin/env python3
"""inventory-bulk-promote.py — Phase A registry update.

Reads inventory_smoke_promote_queue.json (output of inventory-smoke-test.py)
and bulk-updates _tier_registry.yaml: every passing detector becomes Tier-B
with verified=true + smoke-test metadata.

Idempotent: re-running with the same queue overwrites with the same data.

Safety:
  - Does NOT remove existing rows.
  - Does NOT downgrade existing Tier-A or Tier-S rows.
  - For existing rows at Tier-D / Tier-E / no-tier / Tier-PAPER, promote to B.
  - For existing rows already at Tier-B without `verified: true`, refresh
    with verified metadata.
  - For rows at Tier-A, skip (already higher than B).
  - For rows at Tier-S, skip (already higher than B).

Usage:
  python3 tools/inventory-bulk-promote.py \\
    --promote-queue /private/tmp/auditooor-inventory/inventory_smoke_promote_queue.json \\
    --summary-out /private/tmp/auditooor-inventory/inventory_bulk_promote_summary.json \\
    [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
DSL_DIR = REPO / "reference" / "patterns.dsl"


# Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
# Random-sample audit found "verified" detectors whose YAML used keys like
# `function.name_matches_regex` or `function.does_not_call_matching_regex` —
# none of which are in `_predicate_engine.py`'s SUPPORTED_FUNCTION_KEYS.
# The engine silently returned False for those keys, so the detector never fired,
# yet pattern-compile.py (without --strict-unsupported-keys) accepted the YAML
# and the wirers smoke-test produced 0 hits on both vuln+clean fixtures, which
# the smoke-pipeline then mis-reported as "passing" → bulk-promote → "verified: true".
# The gate below pre-validates `match.*` and `preconditions.*` predicate keys
# against pattern-compile.py's SUPPORTED_KEYS_BY_FIELD inventory and refuses to
# bulk-promote any entry whose YAML carries an unknown key.
_PATTERN_COMPILE_PY = REPO / "tools" / "pattern-compile.py"


def _load_supported_keys_by_field() -> dict[str, frozenset[str]]:
    """Import pattern-compile.py as a module and return its SUPPORTED_KEYS_BY_FIELD.

    pattern-compile.py uses a hyphen, so it can't be imported with `import`;
    use importlib.util.spec_from_file_location instead.
    """
    spec = importlib.util.spec_from_file_location(
        "_pattern_compile_for_promote_gate", _PATTERN_COMPILE_PY
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load spec for {_PATTERN_COMPILE_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SUPPORTED_KEYS_BY_FIELD


def _yaml_path_for_argument(argument: str) -> Path:
    return DSL_DIR / f"{argument}.yaml"


def _unknown_keys_in_yaml(
    yaml_path: Path, supported_by_field: dict[str, frozenset[str]]
) -> list[str]:
    """Return a list of `field.key` strings for any predicate key not in the
    supported-key set for that field. Empty list = all keys recognized.
    Returns ['__yaml_load_error__: <msg>'] if YAML cannot be parsed.
    """
    if not yaml_path.is_file():
        return [f"__missing_yaml__: {yaml_path}"]
    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"__yaml_load_error__: {exc}"]
    if not isinstance(doc, dict):
        return [f"__yaml_not_mapping__: {type(doc).__name__}"]

    bad: list[str] = []
    for field, supported in supported_by_field.items():
        items = doc.get(field)
        if items is None:
            continue
        if not isinstance(items, list):
            bad.append(f"{field}.__not_a_list__: {type(items).__name__}")
            continue
        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict) or len(item) != 1:
                # Shape error — let pattern-compile's --strict-yaml-shapes catch it;
                # we only flag unknown-key cases here.
                continue
            key = next(iter(item.keys()))
            if key not in supported:
                bad.append(f"{field}.{key}")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--promote-queue", required=True)
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--enforce-diversity", action="store_true",
                    help="Run wirer-output-diversity-check on the YAMLs of "
                         "rows about to be promoted; refuse the WHOLE BATCH "
                         "if any predicate cohort exceeds --max-share. "
                         "Defense-in-depth against the 2026-05-04 fp_repair_v2 "
                         "regex-trick incident.")
    ap.add_argument("--max-share", type=float, default=0.30)
    ap.add_argument("--min-cohort", type=int, default=5)
    ap.add_argument("--enforce-semantic-lint", action="store_true",
                    help="Run predicate-semantic-lint.py on each YAML about "
                         "to be promoted; refuse rows whose match: block "
                         "fails any hard rule (default rules 1, 2, 3). "
                         "Layer C of the harness hardening architecture "
                         "(see docs/HARNESS_HARDENING_2026-05-04.md). "
                         "Per-row, not whole-batch.")
    ap.add_argument("--semantic-lint-rule4-hard", action="store_true",
                    help="Promote Rule 4 (audit-context required) from "
                         "advisory to hard.")
    args = ap.parse_args()

    queue = json.loads(Path(args.promote_queue).read_text(encoding="utf-8"))
    if not isinstance(queue, list):
        print(f"queue is not a list", file=sys.stderr)
        return 2

    # Defense-in-depth (PR #607 followup): if --enforce-diversity, gate the
    # whole batch through wirer-output-diversity-check.py BEFORE any registry
    # mutation. A cohort > max_share signals the LLM regressed to a fixture-
    # shape-distinguishing trick (not a real bug-class predicate).
    if args.enforce_diversity:
        import subprocess
        yaml_paths = []
        for entry in queue:
            arg = entry.get("argument")
            if not arg:
                continue
            yp = REPO / "reference" / "patterns.dsl" / f"{arg}.yaml"
            if yp.exists():
                yaml_paths.append(str(yp))
        if yaml_paths:
            list_path = Path(args.summary_out).with_suffix(".diversity_yamls.txt")
            list_path.write_text("\n".join(yaml_paths))
            div_report = Path(args.summary_out).with_suffix(".diversity_report.json")
            rc = subprocess.run(
                ["python3", str(REPO / "tools" / "wirer-output-diversity-check.py"),
                 "--yaml-list", str(list_path),
                 "--max-share", str(args.max_share),
                 "--min-cohort", str(args.min_cohort),
                 "--json-out", str(div_report)],
                capture_output=False
            ).returncode
            if rc == 1:
                print(f"[bulk-promote] ❌ DIVERSITY VIOLATION — batch refused.")
                print(f"  see {div_report}")
                # Emit a summary so caller has something to read
                Path(args.summary_out).write_text(json.dumps({
                    "schema": "auditooor.inventory_bulk_promote.v1",
                    "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "promote_queue": args.promote_queue,
                    "tier_registry": str(TIER_REGISTRY),
                    "dry_run": args.dry_run,
                    "diversity_violation": True,
                    "diversity_report": str(div_report),
                    "promoted_count": 0,
                    "refused_diversity_violation_count": len(yaml_paths),
                }, indent=2))
                return 1
            elif rc == 2:
                print(f"[bulk-promote] diversity check error (rc=2); proceeding without gate", file=sys.stderr)

    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8"))
    tiers = reg.setdefault("tiers", {})

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
    supported_by_field = _load_supported_keys_by_field()

    promoted: list[dict] = []
    refreshed: list[dict] = []
    skipped_higher: list[dict] = []
    refused_unknown_keys: list[dict] = []
    refused_semantic_lint: list[dict] = []

    # Layer C (PR act7-harness-hardening): pre-compute the lint report once
    # for the whole queue — much cheaper than one subprocess per row.
    semantic_lint_failures: dict[str, list[dict]] = {}
    if args.enforce_semantic_lint:
        import subprocess
        list_path = Path(args.summary_out).with_suffix(".semantic_lint_yamls.txt")
        lint_report_path = Path(args.summary_out).with_suffix(".semantic_lint_report.json")
        yaml_paths_for_lint: list[str] = []
        for entry in queue:
            arg = entry.get("argument")
            if not arg:
                continue
            yp = REPO / "reference" / "patterns.dsl" / f"{arg}.yaml"
            if yp.exists():
                yaml_paths_for_lint.append(str(yp))
        if yaml_paths_for_lint:
            list_path.write_text("\n".join(yaml_paths_for_lint))
            cmd = ["python3", str(REPO / "tools" / "predicate-semantic-lint.py"),
                   "--yaml-list", str(list_path),
                   "--json-out", str(lint_report_path),
                   "--quiet",
                   "--warn-only"]
            if args.semantic_lint_rule4_hard:
                cmd.append("--rule4-hard")
            subprocess.run(cmd, capture_output=False)
            try:
                lint_data = json.loads(lint_report_path.read_text(encoding="utf-8"))
                for r in lint_data.get("reports", []):
                    if not r.get("passes", True):
                        stem = Path(r["yaml"]).stem
                        semantic_lint_failures[stem] = r.get("violations", [])
            except Exception as exc:
                print(f"[bulk-promote] semantic-lint report parse error: {exc}; "
                      f"proceeding without per-row gate", file=sys.stderr)

    for entry in queue:
        arg = entry["argument"]
        prior = tiers.get(arg, {})
        prior_tier = prior.get("tier", "")
        # Skip rows already higher than B
        if prior_tier in ("A", "S"):
            skipped_higher.append({
                "argument": arg,
                "prior_tier": prior_tier,
                "reason": "already higher than Tier-B",
            })
            continue
        # Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
        # Refuse to promote if the source YAML has any predicate key not in
        # pattern-compile's SUPPORTED_KEYS_BY_FIELD. Unknown keys cause the
        # predicate engine to silently return False, which produces a "passing"
        # smoke result (0 hits vuln + 0 hits clean) that is actually a no-op detector.
        yaml_path = _yaml_path_for_argument(arg)
        bad_keys = _unknown_keys_in_yaml(yaml_path, supported_by_field)
        if bad_keys:
            refused_unknown_keys.append({
                "argument": arg,
                "yaml_path": str(yaml_path.relative_to(REPO))
                              if yaml_path.is_relative_to(REPO) else str(yaml_path),
                "unknown_keys": bad_keys,
                "reason": "yaml has predicate keys not in SUPPORTED_KEYS_BY_FIELD",
            })
            continue
        # Layer C (PR act7-harness-hardening): semantic-lint refusal.
        if args.enforce_semantic_lint and arg in semantic_lint_failures:
            refused_semantic_lint.append({
                "argument": arg,
                "yaml_path": str(yaml_path.relative_to(REPO))
                              if yaml_path.is_relative_to(REPO) else str(yaml_path),
                "violations": semantic_lint_failures[arg],
                "reason": "predicate-semantic-lint hard rule violation (see "
                          "docs/HARNESS_HARDENING_2026-05-04.md Layer C)",
            })
            continue
        new_row = {
            "tier": "B",
            "reason": (
                f"phase-A inventory-smoke-test {today}: "
                f"clean_hits={entry['clean_hits']}, vuln_hits={entry['vuln_hits']}; "
                f"py={entry['py_path']}; vuln_fixture={entry['vuln_fixture']}"
            ),
            "waves": list(set(prior.get("waves", []) + ["phase-a-inventory"])),
            "first_added": prior.get("first_added", today),
            "last_promoted": today,
            "fixture_pair": prior.get("fixture_pair", entry["py_path"].replace("detectors/", "")),
            "engine": entry.get("engine", "slither"),
            "argument": arg,
            "verified": True,
            "verified_at": iso_now,
            "smoke_test_command": (
                "python3 detectors/run_custom.py --tier=ALL "
                f"{entry['vuln_fixture']} {arg}"
            ),
            "smoke_test_clean_hits": entry["clean_hits"],
            "smoke_test_vuln_hits": entry["vuln_hits"],
        }
        # Preserve any extra existing keys we don't manage here
        for k, v in prior.items():
            if k not in new_row:
                new_row[k] = v
        if prior_tier == "B":
            refreshed.append({
                "argument": arg,
                "prior_tier": "B",
                "added_verified_metadata": True,
            })
        else:
            promoted.append({
                "argument": arg,
                "prior_tier": prior_tier or "(none)",
                "new_tier": "B",
            })
        if not args.dry_run:
            tiers[arg] = new_row

    if not args.dry_run and (promoted or refreshed):
        tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(reg, default_flow_style=False, sort_keys=False), encoding="utf-8")
        tmp.replace(TIER_REGISTRY)

    summary = {
        "schema": "auditooor.inventory_bulk_promote.v1",
        "ran_at": iso_now,
        "promote_queue": args.promote_queue,
        "tier_registry": str(TIER_REGISTRY),
        "dry_run": args.dry_run,
        "promoted_count": len(promoted),
        "refreshed_count": len(refreshed),
        "skipped_higher_count": len(skipped_higher),
        # Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
        "refused_unknown_keys_count": len(refused_unknown_keys),
        # Layer C (PR act7-harness-hardening): semantic-lint refusals.
        "refused_semantic_lint_count": len(refused_semantic_lint),
        "enforced_semantic_lint": bool(args.enforce_semantic_lint),
        "promoted": promoted,
        "refreshed": refreshed,
        "skipped_higher": skipped_higher,
        "refused_unknown_keys": refused_unknown_keys,
        "refused_semantic_lint": refused_semantic_lint,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    print(f"[bulk-promote] dry_run={args.dry_run}")
    print(f"  promoted: {len(promoted)}")
    print(f"  refreshed (already Tier-B): {len(refreshed)}")
    print(f"  skipped (already higher): {len(skipped_higher)}")
    print(f"  refused (unknown predicate keys): {len(refused_unknown_keys)}")
    print(f"  refused (semantic-lint): {len(refused_semantic_lint)}")
    print(f"  summary -> {args.summary_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
