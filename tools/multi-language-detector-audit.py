#!/usr/bin/env python3
"""multi-language-detector-audit.py — Phase H: multi-language detector landscape audit.

For each target language, reports:
  - detector count (Python modules in language-specific detector dirs)
  - fixture count (language-extension files in detectors/fixtures/ + detector test_fixtures/)
  - test count (test_* methods across relevant test files)
  - runner_wired (bool: dedicated runner tool exists)
  - solodit_pattern_count (YAML patterns in reference/patterns.dsl.r94_solodit_<lang>/ dirs)
  - gaps (list of identified gaps as strings)

Output modes:
  --format json  → stdout JSON (also written to reports/multi_language_detector_audit_<date>.json)
  --format md    → stdout Markdown table
  --lang <name>  → filter to single language

Usage:
  python3 tools/multi-language-detector-audit.py
  python3 tools/multi-language-detector-audit.py --format md
  python3 tools/multi-language-detector-audit.py --lang rust
  python3 tools/multi-language-detector-audit.py --format json --lang go
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from datetime import date
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo root relative to this file
# ---------------------------------------------------------------------------
REPO = Path(__file__).resolve().parent.parent
DETECTORS_DIR = REPO / "detectors"
TOOLS_DIR = REPO / "tools"
TESTS_DIR = REPO / "tools" / "tests"
REFERENCE_DIR = REPO / "reference"
REPORTS_DIR = REPO / "reports"

# ---------------------------------------------------------------------------
# Language definitions
# Each entry describes where to look for:
#   detector_dirs    — list of detector sub-dirs (relative to detectors/)
#   fixture_exts     — file extensions counted as fixtures
#   runner_tools     — tool filenames (relative to tools/) that constitute "wired"
#   test_files       — test file globs (relative to tools/tests/) for test count
#   solodit_suffixes — suffix strings that identify solodit YAML dirs for this language
# ---------------------------------------------------------------------------
LANGUAGE_SPECS: dict[str, dict] = {
    "solidity": {
        "detector_dirs": [
            "wave1", "wave3", "wave4", "wave5", "wave6", "wave7", "wave8",
            "wave9", "wave11", "wave12", "wave13", "wave14", "wave15",
            "wave16", "wave17", "wave18",
            "wave17_graveyard_reactivated", "wave_graveyard",
            "wave_overnight", "wave_overnight_quarantine",
        ],
        "fixture_exts": [".sol"],
        "runner_tools": ["run-detector.py", "run_regex_detectors.py", "forge-test-runner.py"],
        "test_files": ["test_run_detector.py", "test_run_regex_detectors.py",
                       "test_v4_detector_patterns.py",
                       "test_wrapper_zero_slippage_and_dual_direction_detectors.py"],
        "solodit_suffixes": [
            "amm", "amm2", "governance", "governance2", "reentrancy", "reentrancy2",
            "hooks", "flashloan", "proxy", "liquidation", "staking", "oracle",
            "oracle2", "mev", "nft", "token_standard", "tokenomics", "erc4626",
            "vault2", "vesting", "stablecoin", "restaking", "clob", "bridge",
            "perps", "aa", "accesscontrol", "sig", "sigreplay", "sigreplay2",
            "callback", "layerzero", "wrongmath", "func",
        ],
        "description": "Solidity (EVM smart contracts)",
    },
    "rust": {
        "detector_dirs": ["rust_wave1", "rust_wave2"],
        "fixture_exts": [".rs"],
        "runner_tools": ["rust-detector-runner.py", "reth-detector-runner.py",
                         "rust-scan-runner.sh"],
        "test_files": ["test_rust_detector_runner.py", "test_rust_wave2_detectors.py",
                       "test_rust_detector_coverage.py",
                       "test_zkbugs_bellperson_zero_detector.py",
                       "test_reth_detector_runner.sh"],
        "solodit_suffixes": ["rust"],
        "description": "Rust (reth, Solana programs, ZK backends)",
    },
    "go": {
        "detector_dirs": ["go_wave1"],
        "fixture_exts": [".go"],
        "runner_tools": ["go-detector-runner.py"],
        "test_files": ["test_go_detector_runner.py"],
        "solodit_suffixes": ["go"],
        "description": "Go (Cosmos/IBC chains, bridge services)",
    },
    "circom": {
        "detector_dirs": ["circom_wave1"],
        "fixture_exts": [".circom"],
        "runner_tools": ["circom-detect.py"],
        "test_files": ["test_zkbugs_circom_num2bits_detector.py",
                       "test_zkbugs_detectorization_map.py"],
        "solodit_suffixes": ["circom"],
        "description": "Circom (ZK circuit language)",
    },
    "vyper": {
        "detector_dirs": ["vyper_wave2"],
        "fixture_exts": [".vy", ".vyper"],
        "runner_tools": [],  # no dedicated runner yet
        "test_files": [],
        "solodit_suffixes": ["vyper"],
        "description": "Vyper (EVM smart contracts, alternative to Solidity)",
    },
    "move": {
        "detector_dirs": ["move_wave2"],
        "fixture_exts": [".move"],
        "runner_tools": [],  # no dedicated runner yet
        "test_files": [],
        "solodit_suffixes": ["move"],
        "description": "Move (Aptos / Sui smart contracts)",
    },
    "sway": {
        "detector_dirs": [],  # no dedicated dir yet
        "fixture_exts": [".sw", ".sway"],
        "runner_tools": [],
        "test_files": [],
        "solodit_suffixes": ["sway"],
        "description": "Sway (Fuel Network smart contracts)",
    },
    "cairo": {
        "detector_dirs": [],  # no dedicated dir yet
        "fixture_exts": [".cairo"],
        "runner_tools": [],
        "test_files": [],
        "solodit_suffixes": ["cairo"],
        "description": "Cairo (StarkNet smart contracts)",
    },
    "zk": {
        "detector_dirs": [],  # ZK detectors spread across rust_wave1 (zkbugs_*)
        "fixture_exts": [],
        "runner_tools": ["zkbugs-detectorization-map.py"],
        "test_files": ["test_zkbugs_detectorization_map.py",
                       "test_zkbugs_bellperson_zero_detector.py",
                       "test_zkbugs_circom_num2bits_detector.py"],
        "solodit_suffixes": ["zk", "crypto"],
        "description": "ZK / cryptographic circuits (generic, cross-language)",
    },
    "python": {
        "detector_dirs": ["python_wave1"],
        "fixture_exts": [".py"],  # fixture .py files — small count expected
        "runner_tools": [],  # no dedicated runner yet
        "test_files": [],
        "solodit_suffixes": [],
        "description": "Python (backend services, off-chain scripts)",
    },
    "anchor_solana": {
        "detector_dirs": [],  # Anchor detectors in rust_wave1 (anchor_*)
        "fixture_exts": [],
        "runner_tools": ["anchor-detector-runner.py"],
        "test_files": ["test_anchor_detector_runner.py"],
        "solodit_suffixes": [],
        "description": "Anchor / Solana (Rust-based Solana programs)",
    },
    "cosmos": {
        "detector_dirs": [],  # Cosmos detectors in go_wave1
        "fixture_exts": [],
        "runner_tools": ["cosmos-detector-runner.py"],
        "test_files": ["test_cosmos_detector_runner.py"],
        "solodit_suffixes": [],
        "description": "Cosmos SDK / IBC (CosmWasm + tendermint stack)",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_detector_files(dirs: list[str]) -> int:
    """Count non-dunder, non-test Python detector modules across detector dirs."""
    total = 0
    for d in dirs:
        p = DETECTORS_DIR / d
        if not p.exists():
            continue
        for f in p.rglob("*.py"):
            if f.name.startswith("__") or f.name.startswith("test_"):
                continue
            if f.name.startswith("_util") or f.name == "proof_of_life.py":
                continue
            total += 1
    return total


def _count_fixtures(dirs: list[str], exts: list[str]) -> int:
    """Count fixture files of the given extensions inside detector dirs."""
    if not exts:
        return 0
    total = 0
    search_dirs = [DETECTORS_DIR / d for d in dirs] if dirs else [DETECTORS_DIR]
    # Also search the flat fixtures/ dir
    search_dirs.append(DETECTORS_DIR / "fixtures")
    search_dirs.append(DETECTORS_DIR / "_fixtures")
    search_dirs.append(DETECTORS_DIR / "test_fixtures")
    seen: set[Path] = set()
    for sd in search_dirs:
        if not sd.exists():
            continue
        for ext in exts:
            for f in sd.rglob(f"*{ext}"):
                if f not in seen:
                    seen.add(f)
                    total += 1
    return total


def _count_test_methods(test_files: list[str]) -> int:
    """Count `def test_*` methods across named test files."""
    total = 0
    for fname in test_files:
        p = TESTS_DIR / fname
        if not p.exists():
            continue
        if fname.endswith(".sh"):
            # count 'test_' function definitions in shell scripts
            try:
                text = p.read_text(errors="replace")
                total += text.count("\ntest_") + text.count("\nfunction test_")
            except OSError:
                pass
            continue
        try:
            src = p.read_text(errors="replace")
            tree = ast.parse(src, filename=str(p))
        except SyntaxError:
            # Fallback: simple line scan
            try:
                lines = p.read_text(errors="replace").splitlines()
                total += sum(1 for l in lines if l.strip().startswith("def test_"))
            except OSError:
                pass
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                total += 1
    return total


def _runner_wired(runner_tools: list[str]) -> bool:
    """Return True if at least one runner tool exists on disk."""
    for rt in runner_tools:
        if (TOOLS_DIR / rt).exists():
            return True
    return False


def _count_solodit_patterns(suffixes: list[str]) -> int:
    """Count YAML patterns across all matching solodit DSL dirs."""
    total = 0
    if not REFERENCE_DIR.exists():
        return 0
    for suffix in suffixes:
        for d in REFERENCE_DIR.iterdir():
            if not d.is_dir():
                continue
            # Match dirs ending with _<suffix> or _<suffix>2 etc.
            dname = d.name
            if f"solodit_{suffix}" in dname or dname.endswith(f"_{suffix}"):
                for f in d.rglob("*.yaml"):
                    total += 1
                for f in d.rglob("*.yml"):
                    total += 1
    return total


def _identify_gaps(
    lang: str,
    spec: dict,
    detector_count: int,
    fixture_count: int,
    test_count: int,
    runner_wired: bool,
    solodit_pattern_count: int,
) -> list[str]:
    """Return a list of human-readable gap strings for the language."""
    gaps = []
    if not runner_wired and spec["runner_tools"]:
        gaps.append(f"runner tool(s) listed ({', '.join(spec['runner_tools'])}) but not found on disk")
    if not runner_wired and not spec["runner_tools"]:
        gaps.append("no dedicated runner tool exists — patterns cannot be executed automatically")
    if detector_count == 0:
        gaps.append("no detector modules found in language-specific dirs")
    elif detector_count < 3:
        gaps.append(f"very low detector count ({detector_count}) — coverage thin")
    if fixture_count == 0 and spec["fixture_exts"]:
        gaps.append(f"no fixture files ({', '.join(spec['fixture_exts'])}) found — smoke-testing blind")
    if test_count == 0:
        gaps.append("no unit-test methods found — detector correctness unverified")
    if solodit_pattern_count == 0 and spec["solodit_suffixes"]:
        gaps.append("solodit YAML patterns exist in reference/ but wired_count=0 (no runner consuming them)")
    if solodit_pattern_count > 10 and detector_count < solodit_pattern_count // 4:
        gaps.append(
            f"{solodit_pattern_count} solodit patterns documented but only {detector_count} "
            f"detector modules — many patterns not yet codified"
        )
    return gaps


# ---------------------------------------------------------------------------
# Core audit function
# ---------------------------------------------------------------------------

def audit_language(lang: str, spec: dict) -> dict:
    detector_count = _count_detector_files(spec["detector_dirs"])
    fixture_count = _count_fixtures(spec["detector_dirs"], spec["fixture_exts"])
    test_count = _count_test_methods(spec["test_files"])
    wired = _runner_wired(spec["runner_tools"])
    solodit_count = _count_solodit_patterns(spec["solodit_suffixes"])
    gaps = _identify_gaps(
        lang, spec, detector_count, fixture_count, test_count, wired, solodit_count
    )
    return {
        "language": lang,
        "description": spec.get("description", ""),
        "detector_count": detector_count,
        "fixture_count": fixture_count,
        "test_count": test_count,
        "runner_wired": wired,
        "solodit_pattern_count": solodit_count,
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def run_audit(lang_filter: str | None = None) -> dict:
    results = []
    specs = LANGUAGE_SPECS
    if lang_filter:
        lf = lang_filter.lower()
        specs = {k: v for k, v in LANGUAGE_SPECS.items() if k == lf}
        if not specs:
            raise ValueError(f"Unknown language '{lang_filter}'. Known: {sorted(LANGUAGE_SPECS)}")
    for lang, spec in sorted(specs.items()):
        results.append(audit_language(lang, spec))

    total_gaps = sum(r["gap_count"] for r in results)
    langs_no_runner = [r["language"] for r in results if not r["runner_wired"]]
    langs_no_tests = [r["language"] for r in results if r["test_count"] == 0]
    top3_gaps = sorted(results, key=lambda r: r["gap_count"], reverse=True)[:3]

    return {
        "schema": "auditooor.multi_language_detector_audit.v1",
        "generated": str(date.today()),
        "languages_audited": len(results),
        "total_gap_count": total_gaps,
        "languages_without_runner": langs_no_runner,
        "languages_without_tests": langs_no_tests,
        "top3_gap_languages": [r["language"] for r in top3_gaps],
        "prioritized_gaps": [
            {
                "rank": i + 1,
                "language": r["language"],
                "gap_count": r["gap_count"],
                "top_gap": r["gaps"][0] if r["gaps"] else None,
            }
            for i, r in enumerate(top3_gaps)
        ],
        "per_language": results,
    }


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_md(report: dict) -> str:
    lines = [
        "# Multi-Language Detector Audit",
        f"Generated: {report['generated']}  ",
        f"Languages audited: {report['languages_audited']}  ",
        f"Total gaps: {report['total_gap_count']}",
        "",
        "## Summary Table",
        "",
        "| Language | Detectors | Fixtures | Tests | Runner | Solodit patterns | Gaps |",
        "|----------|-----------|----------|-------|--------|-----------------|------|",
    ]
    for r in report["per_language"]:
        runner_str = "yes" if r["runner_wired"] else "**NO**"
        lines.append(
            f"| {r['language']} | {r['detector_count']} | {r['fixture_count']} "
            f"| {r['test_count']} | {runner_str} | {r['solodit_pattern_count']} "
            f"| {r['gap_count']} |"
        )
    lines += [
        "",
        "## Top-3 Gaps by Language",
        "",
    ]
    for p in report["prioritized_gaps"]:
        lines.append(f"**{p['rank']}. {p['language']}** ({p['gap_count']} gaps)")
        if p["top_gap"]:
            lines.append(f"  - {p['top_gap']}")
        lines.append("")
    lines += [
        "## Languages Without a Runner",
        ", ".join(report["languages_without_runner"]) or "none",
        "",
        "## Languages Without Tests",
        ", ".join(report["languages_without_tests"]) or "none",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-language detector landscape audit (Phase H)"
    )
    parser.add_argument("--lang", default=None, help="Filter to a single language")
    parser.add_argument(
        "--format",
        choices=["json", "md"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Skip writing the JSON report to reports/",
    )
    args = parser.parse_args()

    report = run_audit(lang_filter=args.lang)

    if args.format == "md":
        print(format_md(report))
    else:
        print(json.dumps(report, indent=2))

    # Write JSON report to reports/ regardless of --format (unless --no-write)
    if not args.no_write and not args.lang:
        REPORTS_DIR.mkdir(exist_ok=True)
        out_path = REPORTS_DIR / f"multi_language_detector_audit_{report['generated']}.json"
        out_path.write_text(json.dumps(report, indent=2))
        print(f"\n[audit] Report written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
