#!/usr/bin/env python3
"""Dry-run report for supported function predicates misplaced in preconditions.

This scanner is intentionally read-only for DSL YAMLs. It mirrors the live
predicate-yaml-lint allowlist and emits migration candidates where a supported
`function.*` predicate is placed under `preconditions`, which the current lint
/ runtime model treats as an unsupported block for function predicates.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    import yaml  # type: ignore
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


REPO = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO / "reports" / "function_predicate_preconditions_migration_worker_br_2026-05-17.md"
LINT_TOOL = REPO / "tools" / "predicate-yaml-lint.py"


@dataclass(frozen=True)
class Candidate:
    yaml_path: str
    pattern: str
    current_block: str
    current_predicate: str
    key: str
    value: Any
    proposed_relocation: str
    confidence: str
    rationale: str

    def markdown_row(self) -> str:
        value_json = json.dumps(self.value, ensure_ascii=True)
        return (
            f"| `{self.yaml_path}` | `{self.pattern}` | `{self.current_predicate}` | "
            f"`{self.key}` | `{value_json}` | `{self.proposed_relocation}` | "
            f"`{self.confidence}` | {self.rationale} |"
        )


def _load_lint_module():
    spec = importlib.util.spec_from_file_location("predicate_yaml_lint", LINT_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load lint tool from {LINT_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_LINT = _load_lint_module()
FUNCTION_KEYS = frozenset(_LINT.FUNCTION_KEYS)
collect_paths = _LINT.collect_paths


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def _candidate_confidence(doc: dict[str, Any], key: str) -> tuple[str, str]:
    existing_match = doc.get("match")
    if not isinstance(existing_match, list) or not existing_match:
        return (
            "high",
            "Key is already supported in `match`, and the file has no existing `match` list to reconcile.",
        )

    existing_keys: list[str] = []
    for entry in existing_match:
        if isinstance(entry, dict):
            existing_keys.extend(str(k) for k in entry.keys())
    if key in existing_keys:
        return (
            "medium",
            "Key is supported in `match`, but the file already uses the same predicate there; relocation still needs dedupe review.",
        )
    return (
        "medium",
        "Key is supported in `match`, but moving it changes scope from contract gating to per-function matching and needs pattern review.",
    )


def scan_doc(path: Path, doc: Any) -> list[Candidate]:
    if not isinstance(doc, dict):
        return []
    preconditions = doc.get("preconditions")
    if not isinstance(preconditions, list):
        return []

    pattern = str(doc.get("pattern") or path.stem)
    shown = _display_path(path)
    out: list[Candidate] = []
    for idx, entry in enumerate(preconditions):
        if not isinstance(entry, dict):
            continue
        for raw_key, value in entry.items():
            key = str(raw_key)
            if not key.startswith("function."):
                continue
            if key not in FUNCTION_KEYS:
                continue
            confidence, rationale = _candidate_confidence(doc, key)
            out.append(
                Candidate(
                    yaml_path=shown,
                    pattern=pattern,
                    current_block="preconditions",
                    current_predicate=f"preconditions[{idx}]",
                    key=key,
                    value=value,
                    proposed_relocation="prepend to match",
                    confidence=confidence,
                    rationale=rationale,
                )
            )
    return out


def scan_path(path: Path) -> list[Candidate]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    return scan_doc(path, doc)


def write_report(report_path: Path, checked: int, candidates: Sequence[Candidate]) -> None:
    by_file: dict[str, int] = {}
    by_key: dict[str, int] = {}
    for candidate in candidates:
        by_file[candidate.yaml_path] = by_file.get(candidate.yaml_path, 0) + 1
        by_key[candidate.key] = by_key.get(candidate.key, 0) + 1

    lines = [
        "# Function Predicate Preconditions Migration Dry Run",
        "",
        f"- Date: {_dt.date.today().isoformat()}",
        f"- Checked YAMLs: {checked}",
        f"- Candidate misplaced supported `function.*` predicates: {len(candidates)}",
        f"- Distinct YAML paths affected: {len(by_file)}",
        "",
        "## Scope",
        "",
        "- This is a dry-run only. No YAML files were modified.",
        "- Candidates are limited to canonical keys already present in the live `FUNCTION_KEYS` allowlist from `tools/predicate-yaml-lint.py`.",
        "- Relocation target is `match` because the current lint/runtime model rejects supported `function.*` predicates in `preconditions`.",
        "",
        "## Summary By Key",
        "",
    ]
    if by_key:
        for key, count in sorted(by_key.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- `{key}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Candidate Files", ""])
    if by_file:
        for yaml_path, count in sorted(by_file.items()):
            lines.append(f"- `{yaml_path}`: {count} candidate entries")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Candidate Entries",
            "",
            "| YAML path | Pattern | Current block entry | Key | Value | Proposed relocation | Confidence | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    if candidates:
        for candidate in candidates:
            lines.append(candidate.markdown_row())
    else:
        lines.append("| none | none | none | none | none | none | none | no migration candidates found |")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="YAML files or directories to scan")
    parser.add_argument("--dir", action="append", default=[], help="directory to scan recursively")
    parser.add_argument("--report", default=str(DEFAULT_REPORT), help="markdown report path")
    args = parser.parse_args(list(argv) if argv is not None else None)

    paths = collect_paths(args.paths, args.dir)
    if not paths:
        print("[function-predicate-preconditions-migration] no YAML paths supplied", file=sys.stderr)
        return 2

    candidates: list[Candidate] = []
    for path in paths:
        if path.exists():
            candidates.extend(scan_path(path))

    candidates.sort(key=lambda item: (item.yaml_path, item.current_predicate, item.key))
    write_report(Path(args.report), len(paths), candidates)
    print(
        f"[function-predicate-preconditions-migration] checked={len(paths)} candidates={len(candidates)} report={args.report}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
