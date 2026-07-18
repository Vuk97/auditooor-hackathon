#!/usr/bin/env python3
"""predicate-semantic-lint.py — refuse YAML detectors whose `match:` block
is structurally incapable of expressing a bug class.

Background (2026-05-04 fp_repair_v2 incident):
  The fp_repair_v2 wirer emitted 91 YAMLs whose `match:` block reduced to:

      match:
        - function.name_matches: "<single name>"
        - function.body_not_contains_regex: "require\\s*\\("
        - function.not_slither_synthetic: true
        - function.not_in_skip_list: true

  This pattern compiles, runs, and "passes" smoke (vuln=no-require fixture
  has 1 hit, clean=has-require fixture has 0 hits). But the predicate
  distinguishes the FIXTURE SHAPE, not the bug class. A predicate that
  only looks at "is this function externally observable AND lacks a
  require statement" is not a meaningful detector for any bug class.

  PR #607 added a wirer-output-diversity-check that catches this when MANY
  YAMLs collapse to the same shape. PR #608 wired it into bulk-promote.
  PR #609 added an upstream agent-dispatch-prompt-lint (Layer A).
  But diversity-check only catches the COHORT-COLLAPSE failure. A more
  diverse, but still-vacuous, output (each YAML using a different bare
  regex) would slip through the diversity gate.

  predicate-semantic-lint catches the failure at a different layer:
  it refuses any individual YAML whose `match:` block lacks a semantic
  bug-class signal, regardless of cohort.

Layered defense (see docs/HARNESS_HARDENING_2026-05-04.md):
  Layer A — prompt design (audit-context anchoring) — PR #609
  Layer B — output-shape audit (delimiter / structural) — partial
  Layer C — predicate semantic linting -- THIS TOOL
  Layer D — diversity check (cohort regression) — PR #607/608
  Layer E — cross-fixture leak (precision matrix) — ACT-1 G1
  Layer F — random-sample operator audit — codified
  Layer G — outcome calibration feedback — outcome-telemetry.py

Usage:
  # Lint a single YAML
  python3 tools/predicate-semantic-lint.py --yaml reference/patterns.dsl/foo.yaml

  # Lint a directory
  python3 tools/predicate-semantic-lint.py --dir reference/patterns.dsl/

  # Lint a list of YAMLs (one path per line)
  python3 tools/predicate-semantic-lint.py --yaml-list /tmp/yamls.txt

  # Strict mode: exit 1 on any violation (default behavior)
  # Lenient mode: --warn-only exits 0 even on violation; report still written
  python3 tools/predicate-semantic-lint.py --dir ... --warn-only

  # JSON report
  python3 tools/predicate-semantic-lint.py --dir ... --json-out reports/predicate_lint.json

Exit codes:
  0  all yamls pass
  1  one or more violations (unless --warn-only)
  2  bad input

Rules:
  Rule 1: no scope-only predicate
    If every key in `match:` is in SCOPE_ONLY_KEYS, refuse.
    Rationale: scope-only predicates can only filter WHAT functions are
    examined, not WHETHER they are buggy. A detector composed entirely
    of scope filters fires on every function in scope — i.e. is a no-op
    detector.

  Rule 2: no GENERIC bare regex without semantic anchor
    Fires only on the fp_repair_v2 trick signature:
      - exactly 1 textual regex predicate (body_*_regex / source_*_regex /
        assembly_*_regex)
      - 0 semantic anchors (calls, taint, storage, modifiers, etc.)
      - 0 unknown predicate keys (rust `crate.*` etc. bypass)
      - the textual regex is GENERIC: no `|` alternation AND
        (short <=20 chars OR no protocol-specific identifier)
    Rationale: a generic single textual regex cannot generalize beyond the
    fixture pair. Multi-textual conjunctions and anchored alternations are
    the legitimate DSL style and bypass this rule. Calibration against the
    1542-yaml DSL corpus shows ~115 production fakes match this signature
    in addition to the 91 quarantined; multi-textual conjunctions
    (1030 yamls) all pass.

  Rule 3: no over-broad name_matches
    If function.name_matches is "" or ".*" or a single literal that
    is too generic ("function", "execute", etc.), flag.

  Rule 4: audit-context required for low-arity predicates (advisory)
    If `match:` has only ONE key that is not a scope filter (low-arity
    detector — high false-positive risk), require the YAML to declare a
    non-empty `wiki_exploit_scenario` (not equal to the title or to
    boilerplate). Rationale: forces the operator who landed the YAML
    to articulate the bug class in prose, which makes the M14 trap
    explicit.

  (Rule 4 is advisory by default; promote to hard via --rule4-hard.)

Self-test:
  Running this tool on the quarantined fp_repair_v2 fakes:
    reference/patterns.dsl/_quarantine/fp_repair_v2_regex_trick/
  90/91 fail Rule 2; 1/91 (the multi-textual variant) passes Rule 2 and
  is caught by Layer D / cohort signature.

Limitations:
  - Cannot catch detectors where the predicate IS semantically anchored
    but happens to be wrong for the bug class. Layer E (cross-fixture
    leak) catches that.
  - Cannot catch detectors that piggyback on a semantic predicate that
    is itself fixture-only. Random-sample audit (Layer F) catches that.
  - Conservative by design: a legitimate detector might fail Rule 2
    if its real bug-class signal happens to be a body regex. Operators
    can override with `# semantic-lint: allow rule2 — <reason>` comment
    in the YAML.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml  # type: ignore
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO = Path(__file__).resolve().parents[1]


# Predicate keys that are scope-only — they filter WHICH functions to look at,
# not WHETHER any function is buggy. A `match:` composed only of these is a
# no-op detector.
SCOPE_ONLY_KEYS = frozenset({
    "function.name_matches",
    "function.name_equals",
    "function.kind",
    "function.visibility",
    "function.is_payable",
    "function.is_mutating",
    "function.is_constructor",
    "function.state_mutability",
    "function.not_slither_synthetic",
    "function.not_in_skip_list",
    "function.not_leaf_helper",
    "function.is_external",
    "function.is_public",
    "function.is_internal",
    "function.is_private",
    "function.has_param_of_type",
    "function.has_param_name_matching",
    "function.has_param_mapping",
    "function.has_param_struct_named",
    "contract.name_matches",
    "contract.name_equals",
    "file.path_matches",
})

# Predicate keys that are TEXTUAL (raw source / body / assembly regex). These
# are not, by themselves, semantic — they just look at substrings of the
# Solidity source. They CAN be a legitimate signal but only in combination
# with a semantic anchor or with multi-textual conjunctions over anchored
# protocol-specific identifiers.
TEXTUAL_REGEX_KEYS = frozenset({
    "function.body_contains_regex",
    "function.body_not_contains_regex",
    "function.not_body_contains_regex",
    "function.source_matches_regex",
    "function.not_source_matches_regex",
    "function.assembly_block_matches",
    "function.assembly_block_not_matches",
    "function.contract.source_matches_regex",
    "function.contract.not_source_matches_regex",
})

# Predicate keys that examine STRUCTURE / BEHAVIOR. Presence of any one of
# these counts as a "semantic anchor" satisfying Rule 2.
SEMANTIC_ANCHOR_KEYS = frozenset({
    # AST dispatch
    "function.ast",
    "function.not_ast",
    # Calls
    "function.has_external_call",
    "function.external_call_count_gte",
    "function.has_high_level_call_named",
    "function.has_low_level_call",
    "function.calls_function_matching",
    "function.reaches_external",
    "function.has_external_call_without_guard",
    # State-write ordering
    "function.post_external_call_mutates_state",
    "function.pre_external_call_mutates_state",
    "function.post_external_call_writes_gte",
    "function.is_self_scoped_mapping_write",
    # Storage
    "function.reads_storage_matching",
    "function.writes_storage_matching",
    # Modifiers / require / event
    "function.has_modifier",
    "function.has_require_mentioning",
    "function.emits_event_matching",
    # Encoding / hashing
    "function.body_has_multi_dynamic_encodepacked",
    "function.computes_keccak",
    # Taint
    "function.taints_param_to",
    # Globals
    "function.reads_msg_sender",
    "function.reads_tx_origin",
    "function.reads_block_timestamp",
    "function.reads_block_number",
})

# Patterns that are too generic to count as a meaningful name filter.
OVERBROAD_NAME_PATTERNS = frozenset({
    "",
    ".*",
    ".+",
    "(?:.*)",
    "function",
    "execute",
    "_",
})

# Boilerplate phrases that DO NOT count as a real wiki_exploit_scenario.
BOILERPLATE_PHRASES = (
    "see source audit report for recommended fix",
    "per audit finding",
    "n/a",
    "tbd",
    "todo",
)

# Generic regex tokens that do not count as protocol-specific identifiers.
GENERIC_TERMS = {
    "require", "assert", "revert", "function", "external",
    "public", "internal", "private", "view", "pure", "memory",
    "storage", "calldata", "returns",
}


def _flatten_match(match_block: Any) -> List[Tuple[str, Any]]:
    """Flatten a match: block into (key, value) pairs.

    DSL accepts multiple shapes — list of single-key dicts, list of multi-
    key dicts, or a bare dict. All collapse to a list of (key, value)
    tuples.
    """
    if not match_block:
        return []
    out: List[Tuple[str, Any]] = []
    if isinstance(match_block, list):
        for entry in match_block:
            if isinstance(entry, dict):
                for k, v in entry.items():
                    out.append((str(k), v))
            elif isinstance(entry, str):
                out.append(("__bare_str__", entry))
    elif isinstance(match_block, dict):
        for k, v in match_block.items():
            out.append((str(k), v))
    return out


def _classify_pair(key: str) -> str:
    """Return one of: scope, textual, semantic, unknown."""
    if key in SCOPE_ONLY_KEYS:
        return "scope"
    if key in TEXTUAL_REGEX_KEYS:
        return "textual"
    if key in SEMANTIC_ANCHOR_KEYS:
        return "semantic"
    return "unknown"


def _is_overbroad_name(value: Any) -> bool:
    if value is None:
        return True
    s = str(value).strip()
    if not s:
        return True
    if s in OVERBROAD_NAME_PATTERNS:
        return True
    if re.fullmatch(r"[\.\*\+\?\(\)\:]+", s):
        return True
    return False


def _has_boilerplate_scenario(doc: Dict[str, Any]) -> bool:
    """True if wiki_exploit_scenario is missing, empty, or boilerplate."""
    s = doc.get("wiki_exploit_scenario", "")
    if s is None:
        return True
    s = str(s).strip().lower()
    if not s:
        return True
    if len(s) < 40:
        return True
    title = str(doc.get("wiki_title", "")).strip().lower()
    if title and s == title:
        return True
    for phrase in BOILERPLATE_PHRASES:
        if phrase in s and len(s) < 100:
            return True
    return False


def _check_yaml(path: Path, args: argparse.Namespace) -> Dict[str, Any]:
    """Run all rules on a single YAML, return a per-yaml report dict."""
    rep: Dict[str, Any] = {
        "yaml": str(path),
        "violations": [],
        "match_summary": {"scope": 0, "textual": 0, "semantic": 0, "unknown": 0},
        "passes": True,
        "skipped": False,
    }

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        rep["skipped"] = True
        rep["skip_reason"] = f"yaml load error: {exc}"
        return rep

    if not isinstance(doc, dict):
        rep["skipped"] = True
        rep["skip_reason"] = "yaml is not a mapping"
        return rep

    # Honor inline allow comment: # semantic-lint: allow ruleN
    raw = path.read_text(encoding="utf-8")
    allowed_rules: set[int] = set()
    for m in re.finditer(r"# semantic-lint:\s*allow\s+rule(\d+)", raw):
        try:
            allowed_rules.add(int(m.group(1)))
        except ValueError:
            pass

    pairs = _flatten_match(doc.get("match"))
    classified = [(k, v, _classify_pair(k)) for (k, v) in pairs]
    summary = rep["match_summary"]
    for _, _, cls in classified:
        summary[cls] = summary.get(cls, 0) + 1

    has_semantic = any(c == "semantic" for (_, _, c) in classified)
    has_textual = any(c == "textual" for (_, _, c) in classified)
    non_scope_keys = [(k, v) for (k, v, c) in classified if c != "scope"]

    # Rule 1 — no scope-only predicate
    if 1 not in args.disable_rule and 1 not in allowed_rules:
        if pairs and not non_scope_keys:
            rep["violations"].append({
                "rule": 1,
                "name": "scope_only_predicate",
                "message": (
                    "match: contains only scope-filter keys "
                    f"({', '.join(sorted({k for k, _ in pairs}))}). "
                    "A scope-only predicate is a no-op detector — it filters "
                    "WHICH functions are examined, not WHETHER they are "
                    "buggy. Add at least one semantic anchor."
                ),
            })

    # Rule 2 — no generic bare regex without semantic anchor
    if 2 not in args.disable_rule and 2 not in allowed_rules:
        textual_pairs_full = [
            (k, v) for (k, v, c) in classified if c == "textual"
        ]
        n_textual = len(textual_pairs_full)
        n_unknown = sum(1 for (_, _, c) in classified if c == "unknown")
        if n_textual == 1 and not has_semantic and n_unknown == 0:
            tk, tv = textual_pairs_full[0]
            tv_str = str(tv) if tv is not None else ""
            has_alternation = "|" in tv_str
            generic_short = len(tv_str) <= 20
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", tv_str)
            has_protocol_identifier = any(
                t.lower() not in GENERIC_TERMS for t in tokens
            )
            looks_generic = (
                not has_alternation
                and (generic_short or not has_protocol_identifier)
            )
            if looks_generic:
                rep["violations"].append({
                    "rule": 2,
                    "name": "bare_regex_without_semantic_anchor",
                    "message": (
                        "match: a SINGLE generic textual regex with no "
                        "semantic anchor and no other textual conjunction. "
                        "This is the fp_repair_v2 fixture-shape-gaming "
                        f"signature: predicate {tk!r} = {tv_str[:80]!r}. "
                        "A generic textual regex (no alternation, no "
                        "protocol-specific identifier) cannot generalize "
                        "beyond the fixture pair."
                    ),
                })

    # Rule 3 — no over-broad name_matches
    if 3 not in args.disable_rule and 3 not in allowed_rules:
        for k, v in pairs:
            if k == "function.name_matches" and _is_overbroad_name(v):
                rep["violations"].append({
                    "rule": 3,
                    "name": "overbroad_name_matches",
                    "message": (
                        f"function.name_matches = {v!r} is too broad. "
                        "Wildcard or empty name matchers fire on every "
                        "function in scope."
                    ),
                })
                break

    # Rule 4 — audit-context required for low-arity predicates (advisory)
    if 4 not in args.disable_rule and 4 not in allowed_rules:
        non_scope_count = len(non_scope_keys)
        if non_scope_count <= 1 and pairs:
            if _has_boilerplate_scenario(doc):
                violation_obj = {
                    "rule": 4,
                    "name": "low_arity_without_audit_context",
                    "message": (
                        f"match: has only {non_scope_count} non-scope "
                        "predicate; wiki_exploit_scenario is empty / too "
                        "short / verbatim title / boilerplate. Add a >=40-char "
                        "wiki_exploit_scenario describing the precondition "
                        "+ trigger + impact."
                    ),
                }
                if args.rule4_hard:
                    rep["violations"].append(violation_obj)
                else:
                    rep.setdefault("advisories", []).append(violation_obj)

    if rep["violations"]:
        rep["passes"] = False
    return rep


def _collect_yamls(args: argparse.Namespace) -> List[Path]:
    out: List[Path] = []
    if args.yaml:
        out.append(Path(args.yaml))
    if args.dir:
        for p in Path(args.dir).rglob("*.yaml"):
            out.append(p)
    if args.yaml_list:
        with open(args.yaml_list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(Path(line))
    seen: set = set()
    uniq: List[Path] = []
    for p in out:
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        uniq.append(p)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yaml", help="single YAML to lint")
    ap.add_argument("--dir", help="directory of YAMLs to lint (rglob *.yaml)")
    ap.add_argument("--yaml-list", help="file with one YAML path per line")
    ap.add_argument("--json-out", help="write JSON report to this path")
    ap.add_argument("--warn-only", action="store_true",
                    help="exit 0 even on violations (still writes report)")
    ap.add_argument("--rule4-hard", action="store_true",
                    help="treat Rule 4 (audit-context) as hard, not advisory")
    ap.add_argument("--disable-rule", action="append", type=int, default=[],
                    help="disable a rule by number (repeatable)")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress per-yaml output; print summary only")
    args = ap.parse_args()

    yamls = _collect_yamls(args)
    if not yamls:
        print("[predicate-semantic-lint] no YAMLs to lint "
              "(use --yaml / --dir / --yaml-list)", file=sys.stderr)
        return 2

    reports: List[Dict[str, Any]] = []
    for yp in yamls:
        if not yp.exists():
            reports.append({
                "yaml": str(yp), "violations": [], "skipped": True,
                "skip_reason": "file does not exist", "passes": True,
                "match_summary": {},
            })
            continue
        reports.append(_check_yaml(yp, args))

    n_total = len(reports)
    n_skipped = sum(1 for r in reports if r.get("skipped"))
    n_failed = sum(1 for r in reports if not r["passes"])
    n_passed = n_total - n_skipped - n_failed

    rule_counts: Dict[int, int] = {}
    for r in reports:
        for v in r.get("violations", []):
            rule_counts[v["rule"]] = rule_counts.get(v["rule"], 0) + 1

    summary = {
        "schema": "auditooor.predicate_semantic_lint.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rules_disabled": sorted(set(args.disable_rule)),
        "rule4_hard": bool(args.rule4_hard),
        "totals": {
            "checked": n_total,
            "passed": n_passed,
            "failed": n_failed,
            "skipped": n_skipped,
        },
        "rule_violation_counts": rule_counts,
        "reports": reports,
    }

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2))

    if not args.quiet:
        for r in reports:
            if r.get("skipped"):
                print(f"  ?  SKIP  {r['yaml']} ({r.get('skip_reason')})")
                continue
            if r["passes"]:
                advisories = r.get("advisories") or []
                if advisories:
                    print(f"  ~  ADV   {r['yaml']}")
                    for a in advisories:
                        print(f"        rule {a['rule']} ({a['name']}): "
                              f"{a['message'][:120]}")
                continue
            print(f"  X  FAIL  {r['yaml']}")
            for v in r["violations"]:
                print(f"        rule {v['rule']} ({v['name']}): "
                      f"{v['message'][:200]}")

    print()
    print(f"[predicate-semantic-lint] checked={n_total} "
          f"passed={n_passed} failed={n_failed} skipped={n_skipped}")
    if rule_counts:
        for rule, ct in sorted(rule_counts.items()):
            print(f"  rule {rule}: {ct} violations")

    if n_failed > 0 and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
