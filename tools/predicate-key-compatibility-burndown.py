#!/usr/bin/env python3
"""Summarize unsupported predicate-key compatibility work.

Read-only companion to predicate-yaml-lint.py. It scans YAML predicate files,
groups lint findings by key, and annotates whether a key can be handled as a
low-risk alias to an already-supported predicate engine key.
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence


REPO = Path(__file__).resolve().parents[1]
LINT_PATH = REPO / "tools" / "predicate-yaml-lint.py"


@dataclasses.dataclass(frozen=True)
class AliasAssessment:
    status: str
    target: str
    note: str


SAFE_ALIASES: dict[str, AliasAssessment] = {
    "contract.has_func_matching": AliasAssessment(
        "safe_alias",
        "contract.has_function_matching",
        "Pure key spelling alias; both scan contract functions by name regex.",
    ),
    "contract.has_func_body_matching": AliasAssessment(
        "safe_alias",
        "contract.has_function_body_matching",
        "Pure key spelling alias; both scan any function body by regex.",
    ),
    "contract.has_func_body_matching_invert": AliasAssessment(
        "safe_alias",
        "contract.has_no_function_body_matching",
        "Pure inverse spelling alias to the existing negative body-regex predicate.",
    ),
    "contract.source_contains_regex": AliasAssessment(
        "safe_alias",
        "contract.source_matches_regex",
        "Regex source scan already exists under source_matches_regex.",
    ),
    "function.body_matches_regex": AliasAssessment(
        "safe_alias",
        "function.body_contains_regex",
        "Regex body scan already exists under body_contains_regex.",
    ),
    "function.not_body_matches_regex": AliasAssessment(
        "safe_alias",
        "function.body_not_contains_regex",
        "Negative regex body scan already exists under body_not_contains_regex.",
    ),
    "function.contract_has_source_matching": AliasAssessment(
        "safe_alias",
        "function.contract.source_matches_regex",
        "Function-level contract source scan already delegates to contract source regex.",
    ),
    "function.not_calls_function_matching": AliasAssessment(
        "safe_alias",
        "function.does_not_call_matching",
        "Negative call-name regex already exists under does_not_call_matching.",
    ),
    "function.not_in_slither_synthetic": AliasAssessment(
        "safe_alias",
        "function.not_slither_synthetic",
        "Pure key spelling alias; both mean drop Slither synthetic functions.",
    ),
}

VALUE_TRANSFORM_ALIASES: dict[str, AliasAssessment] = {
    "contract.source_contains": AliasAssessment(
        "value_transform",
        "contract.source_matches_regex",
        "Could be migrated by escaping literal text into a regex; not a runtime alias.",
    ),
    "contract.not_source_contains": AliasAssessment(
        "value_transform",
        "contract.not_source_matches_regex",
        "Could be migrated by escaping literal text into a regex; not a runtime alias.",
    ),
    "function.source_contains": AliasAssessment(
        "value_transform",
        "function.source_matches_regex",
        "Could be migrated by escaping literal text into a regex; not a runtime alias.",
    ),
    "function.source_not_contains": AliasAssessment(
        "value_transform",
        "function.not_source_matches_regex",
        "Could be migrated by escaping literal text into a regex; not a runtime alias.",
    ),
}


def _load_lint() -> Any:
    spec = importlib.util.spec_from_file_location("predicate_yaml_lint", LINT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {LINT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _assessment_for(key: str, warning_class: str, predicate_counts: Counter[str]) -> AliasAssessment:
    if (
        warning_class == "unsupported_function_key"
        and key.startswith("function.")
        and predicate_counts
        and all(str(predicate).startswith("preconditions") for predicate in predicate_counts)
    ):
        return AliasAssessment(
            "block_relocation",
            "match",
            "Key is supported only as a function match predicate; YAML put it in preconditions.",
        )
    if key in SAFE_ALIASES:
        return SAFE_ALIASES[key]
    if key in VALUE_TRANSFORM_ALIASES:
        return VALUE_TRANSFORM_ALIASES[key]
    if key.startswith("chain."):
        return AliasAssessment(
            "not_safe_alias",
            "",
            "Domain gate; Solidity Slither engine cannot prove this without explicit domain support.",
        )
    if key.startswith(("repo.", "crate.", "protocol.", "flow.", "semantic.", "cfg.")):
        return AliasAssessment(
            "not_safe_alias",
            "",
            "Non-Solidity or semantic namespace; needs a dedicated evaluator, not a spelling alias.",
        )
    return AliasAssessment(
        "manual_review",
        "",
        "No obvious one-to-one supported predicate with identical semantics.",
    )


def collect_findings(paths: Sequence[str], dirs: Sequence[str]) -> tuple[list[Any], int]:
    lint = _load_lint()
    scan_paths = lint.collect_paths(paths, dirs)
    findings: list[Any] = []
    for path in scan_paths:
        findings.extend(lint.lint_path(path))
    return findings, len(scan_paths)


def summarize(findings: Sequence[Any], checked: int, top: int = 20) -> dict[str, Any]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        key = str(finding.key)
        warning_class = str(finding.warning_class)
        group_key = (key, warning_class)
        row = by_key.setdefault(
            group_key,
            {
                "key": key,
                "warning_class": warning_class,
                "occurrences": 0,
                "affected_patterns": set(),
                "predicates": Counter(),
                "examples": [],
            },
        )
        row["occurrences"] += 1
        row["affected_patterns"].add(str(finding.yaml_path))
        row["predicates"][str(finding.predicate)] += 1
        if len(row["examples"]) < 5:
            row["examples"].append(str(finding.yaml_path))

    rows: list[dict[str, Any]] = []
    for (key, warning_class), row in by_key.items():
        assessment = _assessment_for(key, warning_class, row["predicates"])
        rows.append(
            {
                "key": key,
                "warning_class": warning_class,
                "occurrences": row["occurrences"],
                "affected_patterns": len(row["affected_patterns"]),
                "alias_status": assessment.status,
                "alias_target": assessment.target,
                "alias_note": assessment.note,
                "top_predicate_locations": [
                    {"predicate": pred, "count": count}
                    for pred, count in row["predicates"].most_common(5)
                ],
                "examples": row["examples"],
            }
        )

    rows.sort(key=lambda r: (-int(r["affected_patterns"]), -int(r["occurrences"]), str(r["key"])))
    status_counts = Counter(row["alias_status"] for row in rows)
    affected_total = len({str(f.yaml_path) for f in findings})
    return {
        "schema": "auditooor.predicate_key_compatibility_burndown.v1",
        "checked_yaml_count": checked,
        "finding_count": len(findings),
        "affected_pattern_count": affected_total,
        "unknown_key_count": len(rows),
        "alias_status_counts": dict(sorted(status_counts.items())),
        "top_unknown_keys": rows[:top],
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="YAML files or directories to scan")
    parser.add_argument("--dir", action="append", default=[], help="directory to scan recursively")
    parser.add_argument("--top", type=int, default=20, help="number of grouped keys to return")
    args = parser.parse_args(list(argv) if argv is not None else None)

    paths = args.paths or []
    dirs = args.dir or []
    if not paths and not dirs:
        dirs = [str(REPO / "reference" / "patterns.dsl")]
    findings, checked = collect_findings(paths, dirs)
    print(json.dumps(summarize(findings, checked, args.top), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
