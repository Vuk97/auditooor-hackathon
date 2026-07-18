#!/usr/bin/env python3
"""Wave-2 PR-B firm-parser coverage-matrix aggregator.

Aggregates the W2.4 firm-specific PDF parsers (Trail of Bits, Sherlock,
Pashov, Zellic, Cyfrin, Spearbit, ChainSecurity, OpenZeppelin, ...) into a
single 2D coverage matrix so we can spot gaps where one firm has zero
fixtures for a given bug class or severity tier and battle-tested
strengths where a firm has >=3 fixtures for a class.

Real-source-only / M14-trap discipline:

* Tool auto-discovers parsers via
  ``glob.glob("tools/hackerman-etl-from-audit-firm-pdf-*.py")``. No
  hard-coded firm list. Tolerant of partial firm sets (e.g. when a new
  firm parser has not landed yet).
* Bug-class category mapping is derived from the parsers' shared
  ``_attack_class_from_title`` heuristic; we replay it locally rather
  than rerun each parser end-to-end (the parsers need a Wave-1 listings
  tree we do not want to fabricate here).
* Fixture PDFs are materialised by the parsers' own
  ``_<firm>_fixture_builder.ensure_fixtures()`` if missing.
* Synthetic test fixtures emit ``synthetic_fixture: true`` in YAML
  body. This tool is INFO only; it never gates anything.
* Does NOT modify ``tools/calibration/llm_budget_log.jsonl``.

CLI::

    python3 tools/wave2-firm-parser-coverage-matrix.py \\
        --workspace . --json
    python3 tools/wave2-firm-parser-coverage-matrix.py \\
        --workspace . --markdown
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA_VERSION = "auditooor.wave2_firm_parser_coverage_matrix.v1"

BUG_CLASS_COLUMNS: Tuple[str, ...] = (
    "reentrancy",
    "access-control",
    "arithmetic",
    "oracle-manip",
    "governance",
    "signature",
    "dos",
    "other",
)

SEVERITY_COLUMNS: Tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "gas",
    "undetermined",
)

# Maps the parser-internal attack_class label (the value returned by each
# parser's ``_attack_class_from_title`` heuristic) onto our column names.
ATTACK_CLASS_TO_COLUMN: Dict[str, str] = {
    "reentrancy": "reentrancy",
    "access-control": "access-control",
    "integer-overflow": "arithmetic",
    "arithmetic": "arithmetic",
    "rounding": "arithmetic",
    "oracle-manipulation": "oracle-manip",
    "price-manipulation": "oracle-manip",
    "governance": "governance",
    "voting": "governance",
    "signature-malleability": "signature",
    "replay-attack": "signature",
    "dos": "dos",
    "denial-of-service": "dos",
}

# Additional title keywords for bug-class categories the parsers' coarse
# heuristic does not yet attach. The fallback shape is: prefer the parser
# verdict; fall back to title keyword scan when the parser returned the
# generic "audit-firm-finding-other".
TITLE_KEYWORD_FALLBACK: Tuple[Tuple[str, str], ...] = (
    ("reentr", "reentrancy"),
    ("access control", "access-control"),
    ("access-control", "access-control"),
    ("authorization", "access-control"),
    ("missing access", "access-control"),
    ("overflow", "arithmetic"),
    ("underflow", "arithmetic"),
    ("rounding", "arithmetic"),
    ("integer", "arithmetic"),
    ("precision", "arithmetic"),
    ("oracle", "oracle-manip"),
    ("price manipulation", "oracle-manip"),
    ("twap", "oracle-manip"),
    ("governance", "governance"),
    ("voting", "governance"),
    ("proposal", "governance"),
    ("signature", "signature"),
    ("replay", "signature"),
    ("ecrecover", "signature"),
    ("denial of service", "dos"),
    ("dos ", "dos"),
    ("griefing", "dos"),
)

# Severity buckets we recognise; anything else (e.g. gas-only severity
# label) is normalised into the appropriate column or "other".
SEVERITY_NORMALISE: Dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "note": "informational",
    "gas": "gas",
    "gas optimization": "gas",
    "best practice": "informational",
    "undetermined": "undetermined",
}


# ---------------------------------------------------------------------------
# Discovery helpers.
# ---------------------------------------------------------------------------


def _repo_root_from_workspace(workspace: str) -> Path:
    return Path(workspace).resolve()


def discover_firm_parsers(workspace: Path) -> List[Dict[str, Any]]:
    """Auto-discover every ``hackerman-etl-from-audit-firm-pdf-*.py``."""
    tools_dir = workspace / "tools"
    pattern = str(tools_dir / "hackerman-etl-from-audit-firm-pdf-*.py")
    out: List[Dict[str, Any]] = []
    for path_str in sorted(glob.glob(pattern)):
        path = Path(path_str)
        slug = path.stem.replace("hackerman-etl-from-audit-firm-pdf-", "")
        info = _read_parser_metadata(path)
        out.append({
            "parser_filename_slug": slug,
            "parser_path": str(path),
            "firm_prefix": info.get("firm_prefix") or "",
            "parser_firm_variant": info.get("parser_firm_variant") or slug,
            "extract_fn_name": info.get("extract_fn_name") or "",
        })
    return out


def _read_parser_metadata(parser_path: Path) -> Dict[str, str]:
    text = parser_path.read_text(encoding="utf-8", errors="replace")
    out: Dict[str, str] = {}
    m = re.search(r'^FIRM_PREFIX\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m:
        out["firm_prefix"] = m.group(1)
    m = re.search(r'^PARSER_FIRM_VARIANT\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m:
        out["parser_firm_variant"] = m.group(1)
    m = re.search(r"pdf_finding_extractor\.extract_(\w+)_findings", text)
    if m:
        out["extract_fn_name"] = f"extract_{m.group(1)}_findings"
    return out


def discover_fixture_builders(workspace: Path) -> Dict[str, Path]:
    """Return mapping of firm-variant -> fixture builder path.

    The fixture builders live at
    ``tools/tests/fixtures/audit_firm_pdf_samples/_<variant>_fixture_builder.py``,
    plus the legacy ToB one at ``_fixture_builder.py`` (no variant prefix).
    """
    fixtures_dir = workspace / "tools" / "tests" / "fixtures" / "audit_firm_pdf_samples"
    out: Dict[str, Path] = {}
    for path_str in sorted(glob.glob(str(fixtures_dir / "_*_fixture_builder.py"))):
        path = Path(path_str)
        name = path.stem  # e.g. "_chainsecurity_fixture_builder"
        # Strip leading "_" and trailing "_fixture_builder"
        if name.startswith("_") and name.endswith("_fixture_builder"):
            variant = name[1:-len("_fixture_builder")]
            if not variant:
                # Legacy ToB builder (`_fixture_builder.py`) has no variant
                variant = "trailofbits"
            out[variant] = path
    return out


def discover_test_files(workspace: Path) -> Dict[str, Path]:
    """Return mapping of firm-variant -> test-file path."""
    tests_dir = workspace / "tools" / "tests"
    out: Dict[str, Path] = {}
    for path in sorted(tests_dir.glob("test_hackerman_etl_from_audit_firm_pdf_*.py")):
        name = path.stem
        variant = name.replace("test_hackerman_etl_from_audit_firm_pdf_", "")
        out[variant] = path
    return out


def parse_test_methods(test_path: Path) -> List[str]:
    """Return the list of ``def test_*`` methods inside a test file."""
    text = test_path.read_text(encoding="utf-8", errors="replace")
    return sorted(set(re.findall(r"^\s*def (test_[A-Za-z0-9_]+)\(", text, re.MULTILINE)))


def parse_fixture_methods(builder_path: Path) -> List[str]:
    """Return the list of ``def _sample_*`` methods inside a fixture builder."""
    text = builder_path.read_text(encoding="utf-8", errors="replace")
    return sorted(set(re.findall(r"^def (_sample_[A-Za-z0-9_]+)\(", text, re.MULTILINE)))


# ---------------------------------------------------------------------------
# Fixture materialisation + parser dry-run.
# ---------------------------------------------------------------------------


def _load_module_from_path(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def materialise_fixtures(builder_path: Path) -> Dict[str, Path]:
    """Call ``ensure_fixtures()`` and return its filename->path map."""
    # Builders live in a dir we make sure is on sys.path before import.
    parent = str(builder_path.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    mod = _load_module_from_path(f"_w2cm_builder_{builder_path.stem}", builder_path)
    if not hasattr(mod, "ensure_fixtures"):
        return {}
    out = mod.ensure_fixtures() or {}
    # Normalise to {filename: Path}
    return {str(k): Path(v) for k, v in out.items()}


def _load_extractor(workspace: Path):
    lib_path = workspace / "tools" / "lib" / "pdf_finding_extractor.py"
    lib_dir = str(lib_path.parent)
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    return _load_module_from_path("_w2cm_pdf_finding_extractor", lib_path)


def normalise_bug_class(parser_attack_class: str, title: str) -> str:
    """Map parser attack-class + title back onto our column-set."""
    column = ATTACK_CLASS_TO_COLUMN.get((parser_attack_class or "").lower())
    if column:
        return column
    # Fall back to title-keyword scan when the parser returned the generic
    # "audit-firm-finding-other" verdict.
    lowered = (title or "").lower()
    for needle, klass in TITLE_KEYWORD_FALLBACK:
        if needle in lowered:
            return klass
    return "other"


def normalise_severity(parser_severity: str) -> str:
    sev = (parser_severity or "").lower().strip()
    return SEVERITY_NORMALISE.get(sev, "undetermined")


def run_parser_on_fixtures(
    extractor,
    variant: str,
    fixture_paths: Iterable[Path],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Dry-run the matching ``extract_<variant>_findings`` against fixtures."""
    fn_name = f"extract_{variant}_findings"
    fn = getattr(extractor, fn_name, None)
    if fn is None:
        return [], [f"missing-extract-fn:{fn_name}"]
    out_records: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for fp in fixture_paths:
        if not fp.is_file():
            warnings.append(f"missing-fixture:{fp.name}")
            continue
        try:
            extraction = extractor.extract_structured_pages(fp)
            findings = fn(extraction) or []
        except Exception as exc:  # pragma: no cover - defensive
            warnings.append(f"extract-error:{fp.name}:{type(exc).__name__}:{exc}")
            continue
        for f in findings:
            title = getattr(f, "title", "") or ""
            severity = getattr(f, "severity", "") or ""
            parser_attack_class = _replay_attack_class_heuristic(title)
            bug_class_col = normalise_bug_class(parser_attack_class, title)
            severity_col = normalise_severity(severity)
            has_poc = bool(getattr(f, "code_snippet_pre_fix", "")) or bool(
                getattr(f, "lines_cited", [])
            )
            out_records.append({
                "fixture_filename": fp.name,
                "title": title,
                "severity": severity,
                "severity_column": severity_col,
                "bug_class_column": bug_class_col,
                "attack_class_heuristic": parser_attack_class,
                "has_poc": has_poc,
            })
    return out_records, warnings


# The parsers each ship their own copy of this heuristic; we replay it
# locally so the matrix logic is independent of the live driver bodies.
_ATTACK_CLASS_NEEDLES: Tuple[Tuple[str, str], ...] = (
    ("reentrancy", "reentrancy"),
    ("integer overflow", "integer-overflow"),
    ("overflow", "integer-overflow"),
    ("access control", "access-control"),
    ("authorization", "access-control"),
    ("uninitialized", "uninitialized-state"),
    ("denial of service", "dos"),
    ("dos", "dos"),
    ("oracle", "oracle-manipulation"),
    ("price manipulation", "oracle-manipulation"),
    ("slippage", "slippage"),
    ("rounding", "rounding"),
    ("front-running", "front-running"),
    ("frontrunning", "front-running"),
    ("signature", "signature-malleability"),
    ("replay", "replay-attack"),
    ("flash loan", "flash-loan"),
)


def _replay_attack_class_heuristic(title: str) -> str:
    lowered = (title or "").lower()
    for needle, klass in _ATTACK_CLASS_NEEDLES:
        if needle in lowered:
            return klass
    return "audit-firm-finding-other"


# ---------------------------------------------------------------------------
# Matrix assembly.
# ---------------------------------------------------------------------------


def _empty_row(columns: Iterable[str]) -> Dict[str, int]:
    return {c: 0 for c in columns}


def build_coverage_matrix(
    workspace: Path,
) -> Dict[str, Any]:
    parsers = discover_firm_parsers(workspace)
    fixture_builders = discover_fixture_builders(workspace)
    test_files = discover_test_files(workspace)

    # Map parser filename slug -> firm-variant (per-fixture-dir / PARSER_FIRM_VARIANT).
    # We prefer the parser's own PARSER_FIRM_VARIANT.
    firm_variants: List[str] = []
    parser_meta_by_variant: Dict[str, Dict[str, Any]] = {}
    for info in parsers:
        variant = info["parser_firm_variant"] or info["parser_filename_slug"]
        firm_variants.append(variant)
        parser_meta_by_variant[variant] = info

    firm_variants = sorted(set(firm_variants))

    extractor = _load_extractor(workspace)

    bug_class_matrix: Dict[str, Dict[str, int]] = {}
    severity_matrix: Dict[str, Dict[str, int]] = {}
    per_firm_detail: Dict[str, Dict[str, Any]] = {}
    total_fixtures = 0
    total_emitted = 0

    for variant in firm_variants:
        builder_path = fixture_builders.get(variant)
        # Variant name on the parser may not match the fixture-dir name
        # in legacy cases (e.g. parser variant "trailofbits" uses
        # ``_fixture_builder.py`` rather than `_trailofbits_fixture_builder.py`).
        if builder_path is None and variant == "trailofbits":
            legacy = workspace / "tools" / "tests" / "fixtures" / "audit_firm_pdf_samples" / "_fixture_builder.py"
            if legacy.is_file():
                builder_path = legacy

        fixture_paths_map: Dict[str, Path] = {}
        builder_warnings: List[str] = []
        fixture_methods: List[str] = []
        if builder_path is not None and builder_path.is_file():
            try:
                fixture_paths_map = materialise_fixtures(builder_path)
            except Exception as exc:  # pragma: no cover - defensive
                builder_warnings.append(f"materialise-error:{type(exc).__name__}:{exc}")
            try:
                fixture_methods = parse_fixture_methods(builder_path)
            except Exception:  # pragma: no cover - defensive
                pass

        # Test methods (one per coverage case) live alongside the test file.
        test_methods: List[str] = []
        # Test file name may use a different shortening (e.g. parser
        # filename slug `tob` -> test name `tob`). Try both keys.
        test_path = test_files.get(parser_meta_by_variant[variant]["parser_filename_slug"])
        if test_path is None:
            test_path = test_files.get(variant)
        if test_path is not None and test_path.is_file():
            test_methods = parse_test_methods(test_path)

        records, run_warnings = run_parser_on_fixtures(
            extractor,
            variant,
            sorted(fixture_paths_map.values()),
        )
        total_fixtures += len(fixture_paths_map)
        total_emitted += len(records)

        bug_row = _empty_row(BUG_CLASS_COLUMNS)
        sev_row = _empty_row(SEVERITY_COLUMNS)
        for rec in records:
            bc = rec["bug_class_column"]
            sv = rec["severity_column"]
            if bc in bug_row:
                bug_row[bc] += 1
            else:
                bug_row["other"] += 1
            if sv in sev_row:
                sev_row[sv] += 1
            else:
                sev_row["undetermined"] += 1

        bug_class_matrix[variant] = bug_row
        severity_matrix[variant] = sev_row
        per_firm_detail[variant] = {
            "parser_path": parser_meta_by_variant[variant]["parser_path"],
            "firm_prefix": parser_meta_by_variant[variant]["firm_prefix"],
            "extract_fn_name": parser_meta_by_variant[variant]["extract_fn_name"],
            "builder_path": str(builder_path) if builder_path else "",
            "test_path": str(test_path) if test_path else "",
            "fixture_count": len(fixture_paths_map),
            "emitted_record_count": len(records),
            "test_method_count": len(test_methods),
            "fixture_method_count": len(fixture_methods),
            "warnings": builder_warnings + run_warnings,
        }

    coverage_gaps: List[Tuple[str, str]] = []
    coverage_strengths: List[Tuple[str, str]] = []
    for firm, row in bug_class_matrix.items():
        for col, count in row.items():
            if count == 0:
                coverage_gaps.append((firm, col))
            if count >= 3:
                coverage_strengths.append((firm, col))

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "firms_discovered": firm_variants,
        "bug_class_columns": list(BUG_CLASS_COLUMNS),
        "severity_columns": list(SEVERITY_COLUMNS),
        "bug_class_matrix": bug_class_matrix,
        "severity_matrix": severity_matrix,
        "per_firm_detail": per_firm_detail,
        "total_fixtures": total_fixtures,
        "total_emitted_records": total_emitted,
        "coverage_gaps": [list(t) for t in coverage_gaps],
        "coverage_strengths": [list(t) for t in coverage_strengths],
        "overall_status": "INFO",
    }


# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------


def render_markdown(summary: Dict[str, Any]) -> str:
    firms = summary["firms_discovered"]
    bug_cols = summary["bug_class_columns"]
    sev_cols = summary["severity_columns"]
    bug_matrix = summary["bug_class_matrix"]
    sev_matrix = summary["severity_matrix"]

    lines: List[str] = []
    lines.append("# Wave-2 firm-parser coverage matrix")
    lines.append("")
    lines.append(f"_Generated: {summary['generated_at']}_")
    lines.append("")
    lines.append(f"- Firms discovered: **{len(firms)}** ({', '.join(firms)})")
    lines.append(f"- Total fixtures: **{summary['total_fixtures']}**")
    lines.append(f"- Total emitted records: **{summary['total_emitted_records']}**")
    lines.append(f"- Coverage gaps (count=0): **{len(summary['coverage_gaps'])}**")
    lines.append(f"- Battle-tested strengths (count>=3): **{len(summary['coverage_strengths'])}**")
    lines.append("")
    lines.append("## Bug-class matrix (firm x bug-class)")
    lines.append("")
    header = "| firm | " + " | ".join(bug_cols) + " |"
    sep = "|" + "---|" * (len(bug_cols) + 1)
    lines.append(header)
    lines.append(sep)
    for firm in firms:
        row = bug_matrix.get(firm, {})
        cells = [str(row.get(c, 0)) for c in bug_cols]
        lines.append(f"| {firm} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("## Severity matrix (firm x severity)")
    lines.append("")
    header2 = "| firm | " + " | ".join(sev_cols) + " |"
    sep2 = "|" + "---|" * (len(sev_cols) + 1)
    lines.append(header2)
    lines.append(sep2)
    for firm in firms:
        row = sev_matrix.get(firm, {})
        cells = [str(row.get(c, 0)) for c in sev_cols]
        lines.append(f"| {firm} | " + " | ".join(cells) + " |")
    lines.append("")
    if summary["coverage_gaps"]:
        lines.append("## Coverage gaps (firm, bug-class)")
        lines.append("")
        for firm, col in summary["coverage_gaps"][:50]:
            lines.append(f"- `{firm}` x `{col}`")
        if len(summary["coverage_gaps"]) > 50:
            lines.append(f"- ... and {len(summary['coverage_gaps']) - 50} more")
        lines.append("")
    if summary["coverage_strengths"]:
        lines.append("## Battle-tested strengths (firm, bug-class, count>=3)")
        lines.append("")
        for firm, col in summary["coverage_strengths"]:
            count = summary["bug_class_matrix"][firm][col]
            lines.append(f"- `{firm}` x `{col}` (n={count})")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Wave-2 PR-B firm-parser coverage-matrix aggregator.",
    )
    p.add_argument(
        "--workspace",
        default=".",
        help="Repo / workspace root containing the tools/ tree.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary to stdout (raw matrix output).",
    )
    p.add_argument(
        "--markdown",
        action="store_true",
        help="Emit a pretty Github-flavored markdown table to stdout.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-firm warnings and fixture-method details.",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    workspace = _repo_root_from_workspace(args.workspace)
    if not (workspace / "tools").is_dir():
        print(
            f"workspace {workspace} does not contain a tools/ directory",
            file=sys.stderr,
        )
        return 2
    summary = build_coverage_matrix(workspace)
    if args.json and not args.markdown:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif args.markdown and not args.json:
        print(render_markdown(summary))
    elif args.json and args.markdown:
        # Both: JSON first then a `---` divider then markdown.
        print(json.dumps(summary, indent=2, sort_keys=True))
        print("\n---\n")
        print(render_markdown(summary))
    else:
        # Default: render the markdown view (INFO summary).
        print(render_markdown(summary))
    if args.verbose:
        print("\n# verbose per-firm detail", file=sys.stderr)
        for firm, detail in summary["per_firm_detail"].items():
            print(f"- {firm}: {json.dumps(detail, sort_keys=True)}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
