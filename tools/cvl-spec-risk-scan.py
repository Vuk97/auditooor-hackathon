#!/usr/bin/env python3
"""Inventory CVL/Certora proof-model risks in an audit workspace.

RELATED TOOLS:
- tools/audit-text-to-specs.py: generates specs from audit text; it does not
  inspect existing CVL semantics.
- tools/glider-ast-to-specs.py: converts AST/context into spec-like artifacts;
  it does not classify Certora proof assumptions.
- tools/hackerman-etl-from-solodit-specs.py: mines public spec records; it does
  not audit a workspace's local .spec/.conf files.

This tool is intentionally conservative. It does not decide whether a spec is
sound. It turns CVL modeling choices into explicit proof obligations so a
workspace cannot be closed by saying "Certora verified it" without reviewing the
semantics that made the proof pass.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.cvl_spec_risk_scan.v1"


@dataclass(frozen=True)
class Risk:
    kind: str
    path: str
    line: int
    severity: str
    text: str
    obligation: str


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def locate_certora_dir(path: Path) -> Path | None:
    candidates = [
        path,
        path / "certora",
        path / "src" / "certora",
    ]
    for candidate in candidates:
        if (candidate / "specs").is_dir() or (candidate / "confs").is_dir():
            return candidate
    matches = sorted(path.glob("**/certora"))
    for candidate in matches:
        if (candidate / "specs").is_dir() or (candidate / "confs").is_dir():
            return candidate
    return None


def _risk(
    risks: list[Risk],
    *,
    kind: str,
    path: Path,
    root: Path,
    line_no: int,
    severity: str,
    text: str,
    obligation: str,
) -> None:
    risks.append(
        Risk(
            kind=kind,
            path=_rel(path, root),
            line=line_no,
            severity=severity,
            text=text.strip()[:220],
            obligation=obligation,
        )
    )


def _iter_lines(path: Path) -> Iterable[tuple[int, str]]:
    for idx, line in enumerate(_read_text(path).splitlines(), start=1):
        yield idx, line


def _scan_rule_blocks(path: Path, root: Path, risks: list[Risk]) -> None:
    lines = _read_text(path).splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not re.search(r"\b(rule|invariant)\s+[A-Za-z_][A-Za-z0-9_]*", line):
            i += 1
            continue
        start = i
        brace_depth = line.count("{") - line.count("}")
        block = [line]
        i += 1
        while i < len(lines) and brace_depth > 0:
            block.append(lines[i])
            brace_depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        body = "\n".join(block)
        if re.search(r"\bsatisfy\b", body) and not re.search(r"\bassert\b", body):
            _risk(
                risks,
                kind="satisfy_without_assert",
                path=path,
                root=root,
                line_no=start + 1,
                severity="medium",
                text=lines[start],
                obligation="Rule has satisfy but no assert; treat as witness generation, not a universal safety proof.",
            )
        if re.search(r"\brequire\b", body) and not re.search(r"\bsatisfy\b", body):
            require_count = len(re.findall(r"\brequire\b", body))
            if require_count >= 8:
                _risk(
                    risks,
                    kind="high_require_density",
                    path=path,
                    root=root,
                    line_no=start + 1,
                    severity="review",
                    text=lines[start],
                    obligation="High require density can hide vacuity; pair with sanity or a witness rule.",
                )


def scan_spec(path: Path, root: Path, risks: list[Risk]) -> None:
    _scan_rule_blocks(path, root, risks)
    previous_window: list[str] = []
    for line_no, line in _iter_lines(path):
        stripped = line.strip()
        if re.search(r"\bpreserved\b", stripped):
            _risk(
                risks,
                kind="preserved_assumption",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Review preserved-block assumptions and prove them independently where load-bearing.",
            )
        if "requireInvariant" in stripped:
            _risk(
                risks,
                kind="require_invariant_dependency",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Confirm the required invariant is proven over the same method universe.",
            )
        if re.search(r"\bfiltered\b", stripped):
            _risk(
                risks,
                kind="filtered_parametric_methods",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="List excluded methods and verify they are not economically relevant to the property.",
            )
        if "lastReverted" in stripped:
            recent = "\n".join(previous_window[-8:])
            kind = "last_reverted_usage"
            severity = "review"
            obligation = "Confirm the immediately preceding call uses @withrevert; plain calls prune revert paths."
            if "@withrevert" not in recent:
                kind = "last_reverted_without_local_withrevert"
                severity = "medium"
            _risk(
                risks,
                kind=kind,
                path=path,
                root=root,
                line_no=line_no,
                severity=severity,
                text=line,
                obligation=obligation,
            )
        if re.search(r"\bpersistent\s+ghost\b", stripped):
            _risk(
                risks,
                kind="persistent_ghost",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Confirm persistence across external-call havoc is intended.",
            )
        elif re.search(r"^\s*ghost\b", line):
            _risk(
                risks,
                kind="nonpersistent_ghost",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Confirm unresolved external calls cannot havoc this ghost into a fake proof.",
            )
        if re.search(r"\b(init_state\s+)?axiom\b", stripped):
            kind = "init_state_axiom" if "init_state" in stripped else "global_ghost_axiom"
            severity = "review" if kind == "init_state_axiom" else "medium"
            _risk(
                risks,
                kind=kind,
                path=path,
                root=root,
                line_no=line_no,
                severity=severity,
                text=line,
                obligation="Check satisfiability and ensure the axiom constrains only intended ghost state.",
            )
        if "=> NONDET" in stripped:
            _risk(
                risks,
                kind="nondet_summary",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Verify NONDET is sound for this method; stateful methods need matching havoc or a real body.",
            )
        if re.search(r"=>\s+HAVOC_", stripped):
            kind = "havoc_all_delete" if "HAVOC_ALL DELETE" in stripped else "havoc_summary"
            _risk(
                risks,
                kind=kind,
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Review whether the havoc summary hides the real callee effect needed by the property.",
            )
        if "DISPATCHER(true)" in stripped:
            _risk(
                risks,
                kind="optimistic_dispatcher",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="DISPATCHER(true) assumes known implementations are complete; verify this matches deployment.",
            )
        if re.search(r"=>\s+CVL_[A-Za-z0-9_]+", stripped):
            _risk(
                risks,
                kind="cvl_function_summary",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Compare the CVL summary against the Solidity implementation or turn mismatch into a PoC obligation.",
            )
        if re.search(r"function\s+_\.", stripped):
            _risk(
                risks,
                kind="wildcard_external_summary",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Wildcard summaries may over-approximate external behavior; tie them back to the attack model.",
            )
        if "multicall" in stripped and "DELETE" in stripped:
            _risk(
                risks,
                kind="multicall_deleted",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Run bundled real-entrypoint tests for properties that may fail only across call sequences.",
            )
        previous_window.append(line)


def scan_conf(path: Path, root: Path, risks: list[Risk]) -> None:
    for line_no, line in _iter_lines(path):
        stripped = line.strip()
        if '"optimistic_loop"' in stripped and "true" in stripped:
            _risk(
                risks,
                kind="optimistic_loop",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Record loop bounds and fuzz real max-size collections near the configured bound.",
            )
        if '"optimistic_hashing"' in stripped or '"optimitic_hashing"' in stripped:
            _risk(
                risks,
                kind="optimistic_hashing",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Check whether hash injectivity or collision assumptions matter to authorization or accounting.",
            )
        if '"parametric_contracts"' in stripped:
            _risk(
                risks,
                kind="parametric_contracts_scope",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Confirm parametric rules range over every contract that can mutate the property.",
            )


def scan_readme(path: Path, root: Path, risks: list[Risk]) -> None:
    for line_no, line in _iter_lines(path):
        low = line.lower()
        if "erc20" in low and "well-behaved" in low:
            _risk(
                risks,
                kind="erc20_well_behaved_assumption",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Test fee-on-transfer, reverting, zero-return, non-standard, and callback-like token behavior if in scope.",
            )
        if "re-enter" in low or "reenter" in low:
            _risk(
                risks,
                kind="no_reentry_assumption",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Convert no-reentry modeling assumptions into callback and flashloan composition tests.",
            )
        if "multicall" in low and "removed" in low:
            _risk(
                risks,
                kind="readme_multicall_removed",
                path=path,
                root=root,
                line_no=line_no,
                severity="medium",
                text=line,
                obligation="Run real multicall/bundle tests for invariants proven only one entrypoint at a time.",
            )
        if "bounded" in low and "loop" in low:
            _risk(
                risks,
                kind="readme_bounded_loop_assumption",
                path=path,
                root=root,
                line_no=line_no,
                severity="review",
                text=line,
                obligation="Verify configured bounds cover production collection sizes or add boundary fuzzing.",
            )


def scan(path: Path) -> dict:
    certora_dir = locate_certora_dir(path.resolve())
    if certora_dir is None:
        return {
            "schema": SCHEMA,
            "input": str(path),
            "certora_dir": None,
            "verdict": "no-certora-dir",
            "spec_count": 0,
            "conf_count": 0,
            "risk_count": 0,
            "summary_by_kind": {},
            "risks": [],
        }

    root = certora_dir.parent
    spec_files = sorted((certora_dir / "specs").glob("**/*.spec")) if (certora_dir / "specs").is_dir() else []
    conf_files = sorted((certora_dir / "confs").glob("**/*.conf")) if (certora_dir / "confs").is_dir() else []
    readme = certora_dir / "README.md"

    risks: list[Risk] = []
    for spec in spec_files:
        scan_spec(spec, root, risks)
    for conf in conf_files:
        scan_conf(conf, root, risks)
    if readme.exists():
        scan_readme(readme, root, risks)

    counts = Counter(r.kind for r in risks)
    return {
        "schema": SCHEMA,
        "input": str(path),
        "certora_dir": str(certora_dir),
        "verdict": "review-obligations" if risks else "pass-no-obvious-cvl-risk-patterns",
        "spec_count": len(spec_files),
        "conf_count": len(conf_files),
        "risk_count": len(risks),
        "summary_by_kind": dict(sorted(counts.items())),
        "risks": [asdict(r) for r in risks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="workspace root or certora directory")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--out", type=Path, help="write JSON artifact")
    args = parser.parse_args()

    result = scan(args.path)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json or args.out is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[cvl-spec-risk-scan] wrote {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
