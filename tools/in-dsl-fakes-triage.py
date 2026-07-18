#!/usr/bin/env python3
"""in-dsl-fakes-triage.py — ACT-10 (2026-05-04).

Triage the in-DSL regex-trick fakes surfaced by
`tools/predicate-semantic-lint.py` against the live DSL corpus.

Background:
  PR #614 (ACT-7) added Layer-C predicate semantic linting. Running it
  against the full live `reference/patterns.dsl/*.yaml` corpus revealed
  a population of YAMLs that were synthesised BEFORE the diversity-check
  guard (PR #607) and the semantic-lint (PR #614) landed, and so escaped
  both gates.

  The lint Rule 2 is conservative: it fires only on the exact
  fp_repair_v2 fingerprint — a single textual regex, no semantic anchor,
  no unknown-key bypass, with a generic-shaped regex. That said, a small
  fraction of legitimate detectors might use a semantically-meaningful
  body_*_regex without a structural anchor. This tool classifies each
  flagged row as one of:

    fake-confirmed   — predicate is fixture-shape-encoding only.
                       Quarantine.
    lint-fp          — predicate IS bug-class meaningful (e.g. multiple
                       textual conjunctions encoding a real flow).
                       Keep + tag.
    borderline       — looks like a fake but the audit context suggests
                       the regex IS encoding the real bug. Mark for
                       operator review.

Classification heuristics:

  fake-confirmed if ALL of:
    - exactly 1 textual key, value is `require\\s*\\(` or near-variant
    - 0 semantic anchors
    - non-scope keys count == 1 (the textual one)
    - wiki_exploit_scenario is empty / boilerplate (<400 chars and
      starts with "Per audit finding:")
    - wave is "14" or empty (auto-mined cohort)

  lint-fp if ANY of:
    - predicate has a non-textual non-scope key the lint mis-classified
    - the textual regex carries a protocol-specific identifier even
      after Rule 2 was triggered (defensive — Rule 2 should already
      gate this; this is a belt-and-braces check)

  borderline otherwise.

Output:
  - reports/in_dsl_fakes_triage.json — per-row JSON
  - docs/IN_DSL_FAKES_TRIAGE_2026-05-04.md — markdown table

Usage:
  python3 tools/in-dsl-fakes-triage.py
  python3 tools/in-dsl-fakes-triage.py --lint-report reports/foo.json \
      --json-out reports/triage.json --md-out docs/triage.md

Exit codes:
  0 — triage produced; results written.
  2 — bad input.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

REPO = Path(__file__).resolve().parents[1]
DEFAULT_LINT_REPORT = REPO / "reports" / "live_dsl_predicate_lint.json"
DEFAULT_JSON_OUT = REPO / "reports" / "in_dsl_fakes_triage.json"
DEFAULT_MD_OUT = REPO / "docs" / "IN_DSL_FAKES_TRIAGE_2026-05-04.md"


SCOPE_ONLY_KEYS = {
    "function.name_matches", "function.name_equals", "function.kind",
    "function.visibility", "function.is_payable", "function.is_mutating",
    "function.is_constructor", "function.state_mutability",
    "function.not_slither_synthetic", "function.not_in_skip_list",
    "function.not_leaf_helper", "function.is_external",
    "function.is_public", "function.is_internal", "function.is_private",
    "function.has_param_of_type", "function.has_param_name_matching",
    "function.has_param_mapping", "function.has_param_struct_named",
    "contract.name_matches", "contract.name_equals", "file.path_matches",
}

TEXTUAL_REGEX_KEYS = {
    "function.body_contains_regex", "function.body_not_contains_regex",
    "function.not_body_contains_regex", "function.source_matches_regex",
    "function.not_source_matches_regex",
    "function.assembly_block_matches", "function.assembly_block_not_matches",
    "function.contract.source_matches_regex",
    "function.contract.not_source_matches_regex",
}

SEMANTIC_ANCHOR_KEYS = {
    "function.ast", "function.not_ast", "function.has_external_call",
    "function.external_call_count_gte", "function.has_high_level_call_named",
    "function.has_low_level_call", "function.calls_function_matching",
    "function.reaches_external", "function.has_external_call_without_guard",
    "function.post_external_call_mutates_state",
    "function.pre_external_call_mutates_state",
    "function.post_external_call_writes_gte",
    "function.is_self_scoped_mapping_write",
    "function.reads_storage_matching", "function.writes_storage_matching",
    "function.has_modifier", "function.has_require_mentioning",
    "function.emits_event_matching",
    "function.body_has_multi_dynamic_encodepacked",
    "function.computes_keccak", "function.taints_param_to",
    "function.reads_msg_sender", "function.reads_tx_origin",
    "function.reads_block_timestamp", "function.reads_block_number",
}

# Variants of the trick regex — anything that distinguishes "function
# does/doesn't have a require(" without semantic anchoring.
TRICK_REGEX_PATTERNS = [
    r"require\s*\\\(",
    r"require\\s\*\\\(",
    r"require\(",
]

BOILERPLATE_PHRASES = (
    "per audit finding",
    "see source audit report",
)


def _flatten_match(match_block: Any) -> List[tuple[str, Any]]:
    out: List[tuple[str, Any]] = []
    if not match_block:
        return out
    if isinstance(match_block, list):
        for entry in match_block:
            if isinstance(entry, dict):
                for k, v in entry.items():
                    out.append((str(k), v))
    elif isinstance(match_block, dict):
        for k, v in match_block.items():
            out.append((str(k), v))
    return out


def _classify_key(key: str) -> str:
    if key in SCOPE_ONLY_KEYS:
        return "scope"
    if key in TEXTUAL_REGEX_KEYS:
        return "textual"
    if key in SEMANTIC_ANCHOR_KEYS:
        return "semantic"
    return "unknown"


def _is_trick_regex(value: Any) -> bool:
    if value is None:
        return False
    s = str(value)
    # Strip outer YAML escaping — values like "require\\s*\\(" appear
    # both as raw and as parsed.
    norm = s.replace("\\\\", "\\")
    return bool(re.fullmatch(r"require\\s\*\\\(", norm)) or norm in (
        "require\\(",
        "require",
    )


def _scenario_is_boilerplate(scenario: Any) -> bool:
    if not scenario:
        return True
    s = str(scenario).strip()
    if len(s) < 80:
        return True
    s_lower = s.lower()
    # Auto-mined wave14 fakes start the scenario with "Per audit finding:"
    # and are typically <=400 chars.
    if s_lower.startswith("per audit finding") and len(s) < 400:
        return True
    return False


def _classify_yaml(yaml_path: Path) -> Dict[str, Any]:
    """Return triage record for a single YAML."""
    rec: Dict[str, Any] = {
        "yaml": str(yaml_path),
        "exists": yaml_path.exists(),
    }
    if not rec["exists"]:
        rec["classification"] = "missing"
        rec["rationale"] = "yaml file not found on disk"
        return rec

    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        rec["classification"] = "yaml-error"
        rec["rationale"] = f"yaml parse error: {exc}"
        return rec

    if not isinstance(doc, dict):
        rec["classification"] = "yaml-error"
        rec["rationale"] = "yaml is not a mapping"
        return rec

    pairs = _flatten_match(doc.get("match"))
    classified = [(k, v, _classify_key(k)) for (k, v) in pairs]
    summary = {"scope": 0, "textual": 0, "semantic": 0, "unknown": 0}
    for _, _, cls in classified:
        summary[cls] += 1

    n_non_scope = sum(1 for _, _, c in classified if c != "scope")
    n_semantic = summary["semantic"]
    n_textual = summary["textual"]
    n_unknown = summary["unknown"]

    textual_pairs = [(k, v) for (k, v, c) in classified if c == "textual"]
    has_trick_regex = any(_is_trick_regex(v) for _, v in textual_pairs)

    wave = str(doc.get("wave", "")).strip()
    scenario = doc.get("wiki_exploit_scenario", "")
    scenario_text = str(scenario or "").strip()
    scenario_len = len(scenario_text)
    boilerplate = _scenario_is_boilerplate(scenario)

    pattern_key = doc.get("pattern") or doc.get("name") or yaml_path.stem

    rec.update({
        "pattern_key": pattern_key,
        "wave": wave,
        "match_summary": summary,
        "n_non_scope_keys": n_non_scope,
        "has_trick_regex": has_trick_regex,
        "n_unknown_keys": n_unknown,
        "scenario_len": scenario_len,
        "scenario_boilerplate": boilerplate,
        "source": str(doc.get("source", ""))[:80],
        "severity": doc.get("severity"),
    })

    # === Triage rules ===

    # Rule LINT-FP: lint mis-classified an unknown key as "no semantic
    # anchor". A row with unknown keys is conservatively NOT a fake;
    # surface for review.
    if n_unknown > 0:
        rec["classification"] = "lint-fp"
        rec["rationale"] = (
            f"row has {n_unknown} unknown predicate key(s); lint Rule 2 "
            "should not have fired (defensive bypass). Manual review."
        )
        return rec

    # Rule LINT-FP: row has a semantic anchor (lint shouldn't have fired).
    if n_semantic > 0:
        rec["classification"] = "lint-fp"
        rec["rationale"] = (
            f"row has {n_semantic} semantic anchor(s); lint Rule 2 "
            "should not have fired (defensive bypass)."
        )
        return rec

    # Rule LINT-FP: textual regex is NOT the trick regex AND the regex
    # carries a protocol-specific identifier — Rule 2 should have spared
    # it via the protocol-identifier exception.
    if (
        n_textual == 1
        and not has_trick_regex
        and _has_protocol_identifier(textual_pairs[0][1])
    ):
        rec["classification"] = "lint-fp"
        rec["rationale"] = (
            "textual regex carries protocol-specific identifier(s) that "
            "Rule 2 should have spared. Defensive bypass. Manual review."
        )
        return rec

    # Rule FAKE-CONFIRMED: hits the fp_repair_v2 cohort fingerprint.
    if (
        has_trick_regex
        and n_non_scope == 1
        and n_textual == 1
        and n_semantic == 0
        and n_unknown == 0
        and wave in ("14", "")
        and boilerplate
    ):
        rec["classification"] = "fake-confirmed"
        rec["rationale"] = (
            "fp_repair_v2 cohort fingerprint: single trick regex "
            "(require\\s*\\(), 0 semantic anchors, scope-only filters, "
            f"wave={wave or '<empty>'}, boilerplate scenario "
            f"({scenario_len} chars)."
        )
        return rec

    # Borderline: caught by lint, but doesn't match the strict
    # fingerprint — operator should review.
    rec["classification"] = "borderline"
    pieces = []
    if not has_trick_regex:
        pieces.append("textual regex is NOT the require\\(-trick variant")
    if n_non_scope != 1:
        pieces.append(f"non-scope predicate count = {n_non_scope} (expected 1)")
    if wave not in ("14", ""):
        pieces.append(f"wave={wave} (not auto-mined cohort)")
    if not boilerplate:
        pieces.append(f"scenario rich ({scenario_len} chars, non-boilerplate)")
    rec["rationale"] = "borderline: " + "; ".join(pieces or ["mixed signals"])
    return rec


def _has_protocol_identifier(value: Any) -> bool:
    if value is None:
        return False
    s = str(value)
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", s)
    GENERIC = {
        "require", "assert", "revert", "function", "external",
        "public", "internal", "private", "view", "pure", "memory",
        "storage", "calldata", "returns",
    }
    return any(t.lower() not in GENERIC for t in tokens)


def _load_lint_report(path: Path) -> List[str]:
    data = json.loads(path.read_text())
    if data.get("schema") != "auditooor.predicate_semantic_lint.v1":
        raise ValueError(f"unexpected schema: {data.get('schema')}")
    return [r["yaml"] for r in data["reports"] if not r["passes"]]


def _emit_markdown(records: List[Dict[str, Any]], path: Path) -> None:
    counts: Dict[str, int] = {}
    for r in records:
        c = r.get("classification", "?")
        counts[c] = counts.get(c, 0) + 1

    lines: List[str] = []
    lines.append("# In-DSL Fakes Triage — 2026-05-04 (ACT-10)")
    lines.append("")
    lines.append("Triage of in-DSL regex-trick fakes surfaced by ACT-7's "
                 "`tools/predicate-semantic-lint.py` against the live DSL "
                 "corpus.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total flagged rows:** {len(records)}")
    for cls, ct in sorted(counts.items()):
        lines.append(f"- **{cls}:** {ct}")
    lines.append("")
    lines.append("## Classification rules")
    lines.append("")
    lines.append("- `fake-confirmed`: predicate matches fp_repair_v2 "
                 "cohort fingerprint (single trick regex `require\\s*\\(`, "
                 "0 semantic anchors, scope-only filters, wave 14 or "
                 "empty, boilerplate scenario). Quarantine.")
    lines.append("- `lint-fp`: row has semantic anchor or unknown key — "
                 "lint Rule 2 should not have fired. Keep + tag.")
    lines.append("- `borderline`: caught by lint but doesn't match the "
                 "strict fingerprint. Mark for operator review.")
    lines.append("")
    lines.append("## Per-row table")
    lines.append("")
    lines.append("| # | YAML | Class | Wave | Scenario len | Rationale |")
    lines.append("|---|------|-------|------|--------------|-----------|")
    for i, r in enumerate(records, 1):
        yaml_short = Path(r["yaml"]).name
        cls = r.get("classification", "?")
        wave = r.get("wave", "?") or "<empty>"
        sl = r.get("scenario_len", "?")
        rat = (r.get("rationale", "") or "")[:140]
        lines.append(
            f"| {i} | `{yaml_short}` | `{cls}` | `{wave}` | {sl} | {rat} |"
        )
    lines.append("")
    lines.append("## Spot-check (M14-trap discipline)")
    lines.append("")
    lines.append("Five fake-confirmed rows were inspected BY HAND before "
                 "the triage tool ran (seed=42, sampled from the live "
                 "lint failure list):")
    lines.append("")
    lines.append("| # | Path | Predicate shape | Verdict |")
    lines.append("|---|------|-----------------|---------|")
    lines.append(
        "| 1 | `handling-of-the-flatmatchingfee-in-the-function-previewborrow.yaml` "
        "| name=`^previewBorrow$` + 3 scope filters + `require\\s*\\(` "
        "trick | fake |"
    )
    lines.append(
        "| 2 | `cdpvault-sol-liquidatepositionbaddebt-should-not-set-profit--x.yaml` "
        "| name=`liquidatePositionBadDebt` + kind=external + 2 scope + "
        "trick | fake |"
    )
    lines.append(
        "| 3 | `function-assign-job-of-dvn-is-pausable.yaml` "
        "| name=`assignJob` + kind=external + 2 scope + trick | fake |"
    )
    lines.append(
        "| 4 | `dettachfrommanagednft-might-revert-and-temporarily-prevent-u-x.yaml` "
        "| name=`veNFT` + 2 scope + trick | fake |"
    )
    lines.append(
        "| 5 | `getsmnftpastvotes-incorrectly-checks-for-voting-power-leadin-x.yaml` "
        "| name=`getsmNFTPastVotes` + kind=external + 2 scope + trick "
        "| fake |"
    )
    lines.append("")
    lines.append("All five exhibit the same shape: single function-name "
                 "match + `body_not_contains_regex: \"require\\s*\\(\"` + "
                 "scope-only filters. ZERO semantic anchors. Scenario "
                 "field is `Per audit finding:` boilerplate (200-330 "
                 "chars). All five CONFIRMED fake. The triage tool's "
                 "rule reproduces this judgment automatically.")
    lines.append("")
    lines.append("## Methodology limitations")
    lines.append("")
    lines.append("- This triage relies on the lint having ALREADY flagged "
                 "the row. Detectors that are fakes by some other "
                 "mechanism are not surfaced here.")
    lines.append("- The `borderline` bucket is a guard-rail: rows that "
                 "look mostly like fakes but break one heuristic land "
                 "here for operator review rather than being "
                 "auto-quarantined.")
    lines.append("- The `lint-fp` bucket should be empty in the current "
                 "cohort (Rule 2 was tuned conservatively); a non-zero "
                 "count is a signal that lint Rule 2 needs widening.")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lint-report",
                    default=str(DEFAULT_LINT_REPORT),
                    help="path to predicate-semantic-lint JSON report")
    ap.add_argument("--json-out",
                    default=str(DEFAULT_JSON_OUT),
                    help="output JSON triage report")
    ap.add_argument("--md-out",
                    default=str(DEFAULT_MD_OUT),
                    help="output Markdown triage table")
    args = ap.parse_args()

    lint_path = Path(args.lint_report)
    if not lint_path.exists():
        print(f"[in-dsl-fakes-triage] lint report not found: {lint_path}",
              file=sys.stderr)
        return 2

    yamls = _load_lint_report(lint_path)
    print(f"[in-dsl-fakes-triage] {len(yamls)} flagged rows from "
          f"{lint_path}")

    records: List[Dict[str, Any]] = []
    for y in yamls:
        yp = Path(y)
        if not yp.is_absolute():
            yp = REPO / yp
        records.append(_classify_yaml(yp))

    counts: Dict[str, int] = {}
    for r in records:
        c = r.get("classification", "?")
        counts[c] = counts.get(c, 0) + 1

    print("[in-dsl-fakes-triage] classification:")
    for cls, ct in sorted(counts.items()):
        print(f"  {cls:18}: {ct}")

    summary = {
        "schema": "auditooor.in_dsl_fakes_triage.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "lint_report": str(lint_path),
        "totals": {"flagged": len(records), **counts},
        "records": records,
    }
    out_path = Path(args.json_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"[in-dsl-fakes-triage] JSON: {out_path}")

    md_path = Path(args.md_out)
    _emit_markdown(records, md_path)
    print(f"[in-dsl-fakes-triage] markdown: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
