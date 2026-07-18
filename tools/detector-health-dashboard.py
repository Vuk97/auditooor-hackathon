#!/usr/bin/env python3
"""detector-health-dashboard.py — single-shot observability tool.

Prints the current state of the detector library in a terse, fixed-width,
≤80-col plain-text report. No colours, no charts, no full test-suite run —
this is the "is everything OK right now?" pulse-check.

Usage:
    python3 tools/detector-health-dashboard.py

Exits 1 if VERDICT is BROKEN (parity < 100%, fixture suite known-bad, etc.).
Phase 10 of PR #84.
"""
from __future__ import annotations

import datetime as _dt
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTORS = ROOT / "detectors"
PATTERNS_DSL = ROOT / "reference" / "patterns.dsl"
PARITY_REPORT = ROOT / "docs" / "R94_PARITY_REPORT.md"
TOOLS_INVENTORY = ROOT / "docs" / "TOOLS_INVENTORY.md"
SKILL_ISSUES = ROOT / "SKILL_ISSUES.md"
PARITY_TOOL = ROOT / "tools" / "parity-report.py"
ROLLUP_TOOL = ROOT / "tools" / "skill-issues-rollup.py"
TEST_SCRIPT = ROOT / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh"


# ─── helpers ────────────────────────────────────────────────────────────────

def _git(*args: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True, text=True, check=False, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _count_glob(d: Path, pat: str) -> int:
    if not d.exists():
        return 0
    return sum(1 for _ in d.glob(pat))


def _dir_size_kb(d: Path) -> int:
    if not d.exists():
        return 0
    total = 0
    for p in d.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total // 1024


def _mtime(p: Path) -> str:
    if not p.exists():
        return "(missing)"
    ts = _dt.datetime.fromtimestamp(p.stat().st_mtime)
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _import_parity():
    spec = importlib.util.spec_from_file_location("parity_report", PARITY_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _import_rollup():
    spec = importlib.util.spec_from_file_location("skill_issues_rollup", ROLLUP_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ─── section builders ───────────────────────────────────────────────────────

def section_header() -> list[str]:
    sha = _git("rev-parse", "--short", "HEAD") or "(no-git)"
    branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "(detached)"
    ts = _dt.datetime.now().isoformat(timespec="seconds")
    return [
        "AUDITOOOR DETECTOR HEALTH DASHBOARD",
        f"generated: {ts}",
        f"commit:    {sha}  (branch: {branch})",
        "",
    ]


def section_inventory() -> tuple[list[str], dict]:
    rust_dir = DETECTORS / "rust_wave1"
    rust_count = sum(
        1 for p in rust_dir.glob("*.py")
        if not p.name.startswith("_") and p.name not in ("run_custom.py",)
    ) if rust_dir.exists() else 0
    rust_kb = _dir_size_kb(rust_dir)

    fix_dir = rust_dir / "test_fixtures"
    pos = _count_glob(fix_dir, "*_positive.rs")
    neg = _count_glob(fix_dir, "*_negative.rs")

    sol17 = _count_glob(DETECTORS / "wave17", "*.py")
    sol14 = _count_glob(DETECTORS / "wave14", "*.py")
    yaml_n = _count_glob(PATTERNS_DSL, "*.yaml")
    grave = _count_glob(DETECTORS / "wave17_graveyard_reactivated", "*.py")

    lines = [
        "## DETECTOR INVENTORY",
        f"Rust wave1:       {rust_count:<4} detectors     {rust_kb} KB",
        f"Rust wave1:       {pos+neg:<4} fixtures      ({pos} positive + {neg} negative)",
        f"Solidity wave17:  {sol17:<4} detectors",
        f"Solidity wave14:  {sol14:<4} detectors",
        f"YAML patterns:    {yaml_n:<4} in reference/patterns.dsl/",
        f"Graveyard:        {grave:<4} in wave17_graveyard_reactivated/",
        "",
    ]
    data = {
        "rust": rust_count, "fix_pos": pos, "fix_neg": neg,
        "sol17": sol17, "sol14": sol14, "yaml": yaml_n, "grave": grave,
    }
    return lines, data


def section_parity() -> tuple[list[str], dict]:
    try:
        mod = _import_parity()
        bc = mod.BUG_CLASSES
        total = len(bc)
        both = sum(1 for v in bc.values() if v.get("applies_to") == "both")
        sol_only = sum(1 for v in bc.values() if v.get("applies_to") == "solidity_only")
        rust_only = sum(1 for v in bc.values() if v.get("applies_to") == "rust_only")
    except Exception as e:
        return [
            "## PARITY",
            f"(failed to import parity-report.py: {e})",
            "",
        ], {"ok": False, "pct": 0.0}

    pct, pct_str = 0.0, "(unknown)"
    if PARITY_REPORT.exists():
        body = PARITY_REPORT.read_text(errors="ignore")
        m = re.search(r"Bidirectional parity:\*\*\s*\*\*([0-9.]+)%", body)
        if m:
            pct = float(m.group(1))
            pct_str = f"{pct}%"
    is_100 = abs(pct - 100.0) < 0.01

    lines = [
        "## PARITY",
        f"Classes registered:  {total:<8} (tools/parity-report.py::BUG_CLASSES)",
        f"Applies to both:     {both}",
        f"Rust-only:           {rust_only}",
        f"Solidity-only:       {sol_only}",
        f"100% class coverage: {'YES' if is_100 else 'NO'}       "
        f"(latest R94_PARITY_REPORT.md: {pct_str})",
        "",
    ]
    return lines, {
        "ok": is_100, "pct": pct, "total": total,
        "both": both, "sol_only": sol_only, "rust_only": rust_only,
    }


def section_tests() -> tuple[list[str], dict]:
    # We don't run the suite — too slow. Use the parity-report mtime as a
    # proxy for "last full health pass" (parity is the first thing that
    # follows a green test run in `make all`).
    last_run = _mtime(PARITY_REPORT)
    # Optional: parse a tail-of-test-detectors log if present.
    log = DETECTORS / "rust_wave1" / "test_fixtures" / "audit" / "rust-detect.log"
    pass_n: int | str = "?"
    fail_n: int | str = "?"
    if log.exists():
        body = log.read_text(errors="ignore")
        mp = re.search(r"(\d+)\s*/\s*\d+\s+passed", body)
        if mp:
            pass_n = int(mp.group(1))
        mf = re.search(r"Failures:\s*\n((?:\s*-.*\n)+)", body)
        fail_n = len(mf.group(1).strip().splitlines()) if mf else 0

    lines = [
        "## TESTS",
        f"Last fixture suite run: {last_run}  (mtime of R94_PARITY_REPORT.md)",
        f"  - pass count: {pass_n}",
        f"  - fail count: {fail_n}",
        "",
    ]
    return lines, {"fail": fail_n if isinstance(fail_n, int) else 0}


def section_git() -> list[str]:
    head = _git("log", "-1", "--pretty=format:%h %s") or "(no-git)"
    # Truncate to keep "Latest commit:    " + head ≤ 80 cols.
    if len(head) > 60:
        head = head[:59] + "..."
    porcelain = _git("status", "--porcelain")
    if porcelain:
        lines = porcelain.splitlines()
        untracked = sum(1 for l in lines if l.startswith("??"))
        modified = len(lines) - untracked
    else:
        untracked = modified = 0
    return [
        "## GIT",
        f"Latest commit:    {head}",
        f"Modified tracked: {modified}",
        f"Untracked:        {untracked}",
        "",
    ]


def section_skill_issues() -> tuple[list[str], dict]:
    try:
        mod = _import_rollup()
        text = SKILL_ISSUES.read_text(encoding="utf-8")
        issues = mod.parse_issues(text)
        total = len(issues)
        buckets = {"OPEN": 0, "DONE": 0, "UNKNOWN": 0}
        for iss in issues:
            buckets[mod.classify_issue(iss)] += 1
        done, opn, unk = buckets["DONE"], buckets["OPEN"], buckets["UNKNOWN"]
    except Exception as e:
        return [
            "## SKILL_ISSUES",
            f"(failed to parse {SKILL_ISSUES.name}: {e})",
            "",
        ], {"done": 0, "open": 0, "unknown": 0, "total": 0}

    def pct(n: int) -> str:
        return f"{(100 * n / total):.0f}%" if total else "0%"

    lines = [
        "## SKILL_ISSUES",
        f"Total:    {total:>4}",
        f"DONE:     {done:>4}  ({pct(done)})",
        f"OPEN:     {opn:>4}  ({pct(opn)})",
        f"UNKNOWN:  {unk:>4}",
        "(numbers come from SKILL_ISSUES.md via tools/skill-issues-rollup.py)",
        "",
    ]
    return lines, {"done": done, "open": opn, "unknown": unk, "total": total}


def section_tools() -> list[str]:
    n = "?"
    if TOOLS_INVENTORY.exists():
        body = TOOLS_INVENTORY.read_text(errors="ignore")
        m = re.search(r"\*\*Total tools:\*\*\s*(\d+)", body)
        if m:
            n = m.group(1)
    return [
        "## TOOLS",
        f"Registered:      {n}  (in docs/TOOLS_INVENTORY.md)",
        f"Last regenerated: {_mtime(TOOLS_INVENTORY)}",
        "",
    ]


def section_verdict(parity: dict, tests: dict, inv: dict) -> tuple[list[str], str]:
    reasons: list[str] = []
    if not parity.get("ok"):
        reasons.append(f"parity not 100% ({parity.get('pct', 0)}%)")
    if tests.get("fail", 0):
        reasons.append(f"{tests['fail']} fixture failures in last run")
    if inv["fix_pos"] != inv["rust"] or inv["fix_neg"] != inv["rust"]:
        reasons.append(
            f"fixture/detector mismatch (rust={inv['rust']}, "
            f"pos={inv['fix_pos']}, neg={inv['fix_neg']})"
        )

    verdict = "HEALTHY" if not reasons else "BROKEN"
    lines = ["## VERDICT", f"Overall: {verdict}"]
    if reasons:
        lines.append("Reasons:")
        for r in reasons:
            lines.append(f"  - {r}")
    lines.append("")
    return lines, verdict


# ─── main ──────────────────────────────────────────────────────────────────

def main() -> int:
    out: list[str] = []
    out += section_header()
    inv_lines, inv = section_inventory(); out += inv_lines
    par_lines, parity = section_parity(); out += par_lines
    test_lines, tests = section_tests(); out += test_lines
    out += section_git()
    si_lines, si = section_skill_issues(); out += si_lines
    out += section_tools()
    verdict_lines, verdict = section_verdict(parity, tests, inv); out += verdict_lines

    # One-line summary on stderr for shell scripting.
    print("\n".join(out))
    summary = (
        f"VERDICT: {verdict}, {inv['rust']} rust, "
        f"{parity.get('total', 0)} classes, "
        f"{parity.get('pct', 0)}% parity, "
        f"{si['done']}/{si['open']} issues"
    )
    print(summary, file=sys.stderr)

    return 1 if verdict == "BROKEN" else 0


if __name__ == "__main__":
    raise SystemExit(main())
