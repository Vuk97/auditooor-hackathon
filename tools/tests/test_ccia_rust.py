#!/usr/bin/env python3
"""Offline tests for tools/ccia-rust.py (iter10 T1).

Scope:
  - Isolated tmpfile fixtures for auth / rounding / empty cases.
  - Global hard-negative: no finding may carry `confidence: "high"`.
  - Smoke test against the real ~/audits/k2/src/ tree (read-only). Iter9
    T1 hand-surveyed 7 angles; this tool uses pure heuristics and is
    expected to surface a non-trivial fraction — floor ≥5 across the
    full tree. The hand-surveyed 7 were flagged DROP per FM-016 (dup
    vs prior audits); the tool does not re-litigate that decision,
    only confirms the surfaces are mechanically reachable.

All tests are stdlib-only and exit-0 on missing optional smoke source
(the k2 smoke test is skipped rather than failed when the workspace is
unavailable, to keep the suite portable).
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "ccia-rust.py"
K2_SRC = Path(os.path.expanduser("~/audits/k2/src"))


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _make_fixture(root: Path, relpath: str, content: str) -> Path:
    full = root / relpath
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return full


class TestCciaRust(unittest.TestCase):

    # ---- (1) A-AUTH surfacing on privileged-looking fn without require_auth
    def test_detects_unauthorized_admin_function(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_fixture(ws, "src/lib.rs", (
                "use soroban_sdk::{Env, Address};\n"
                "\n"
                "pub fn admin_only(env: Env, new_val: u64) {\n"
                "    // no require_auth here — should be flagged A-AUTH\n"
                "    env.storage().instance().set(&1u32, &new_val);\n"
                "}\n"
            ))
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            auth = [a for a in report["angles"] if a["angle"] == "A-AUTH"]
            self.assertTrue(auth, f"expected A-AUTH finding; got {report['angles']}")
            # Should cite the admin_only fn name in reason at medium confidence
            med = [a for a in auth if a["confidence"] == "medium"]
            self.assertTrue(med, "expected at least one medium A-AUTH finding")
            self.assertTrue(
                any("admin_only" in a["reason"] for a in med),
                f"expected reason to cite admin_only; got {[a['reason'] for a in med]}"
            )

    # ---- (2) A-ROUNDING surfacing on `let x = a / b;`
    def test_detects_integer_division(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_fixture(ws, "src/math.rs", (
                "pub fn compute_amount(amount: u64, shares: u64) -> u64 {\n"
                "    let x = amount / shares;\n"
                "    x\n"
                "}\n"
            ))
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            rounding = [a for a in report["angles"] if a["angle"] == "A-ROUNDING"]
            self.assertTrue(rounding, f"expected A-ROUNDING finding; got {report['angles']}")
            # all at `low` since raw `/` not `checked_div`
            for a in rounding:
                self.assertEqual(a["confidence"], "low")
            # file relpath cites src/math.rs
            self.assertTrue(any("math.rs" in a["file"] for a in rounding))

    # ---- (3) Empty workspace (no .rs) returns `angles: []` + exit 0
    def test_empty_workspace_returns_empty_angles(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            # create a non-.rs file so dir is non-empty
            (ws / "src" / "README.md").write_text("# not rust\n", encoding="utf-8")
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["angles"], [])
            self.assertEqual(report["total_files_scanned"], 0)
            self.assertEqual(report.get("note"), "no Rust source")

    # ---- (4) Hard-negative: no `high` confidence in any emitted finding
    def test_confidence_never_high(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Mix fixtures that exercise multiple angles
            _make_fixture(ws, "src/a.rs", (
                "pub fn admin_only(env: Env, x: u64) {\n"
                "    env.storage().instance().set(&1u32, &x);\n"
                "}\n"
                "\n"
                "pub fn get_price(env: Env) -> u64 {\n"
                "    // oracle/price accessor\n"
                "    let reflector = env.storage().instance().get(&2u32).unwrap();\n"
                "    reflector\n"
                "}\n"
                "\n"
                "pub fn compute_fee(amount: u64, rate: u64) -> u64 {\n"
                "    let fee = amount * rate / 10_000;\n"
                "    fee\n"
                "}\n"
            ))
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertTrue(report["angles"], "expected at least one finding")
            for a in report["angles"]:
                self.assertIn(
                    a["confidence"], ("low", "medium"),
                    f"non-allowed confidence: {a}"
                )
                self.assertNotEqual(
                    a["confidence"], "high",
                    "tool must never emit high confidence (heuristic)"
                )

    # ---- (5) Smoke test against real ~/audits/k2/src/ — iter9 T1 angle set
    def test_scan_of_k2_real_source_surfaces_at_least_N_angles(self):
        if not K2_SRC.exists():
            self.skipTest(f"k2 source not available at {K2_SRC}")
        # Scan the workspace root (tool finds `src/` automatically)
        proc = _run(["--workspace", str(K2_SRC.parent)])
        self.assertEqual(proc.returncode, 0, proc.stderr[:500])
        report = json.loads(proc.stdout)
        self.assertGreaterEqual(
            report["total_files_scanned"], 50,
            f"expected ≥50 .rs files; got {report['total_files_scanned']}"
        )
        # Floor: iter9 T1 hand-survey found 7 angles (all dup-dropped per
        # FM-016). This tool is heuristic; we assert it surfaces ≥5
        # findings at low/medium. The real smoke-run at plan time produced
        # >1000; floor held low to accept heuristic churn without letting
        # a regression silently pass (drop to near-zero would fail).
        self.assertGreaterEqual(
            len(report["angles"]), 5,
            f"expected ≥5 k2 angles; got {len(report['angles'])}"
        )
        # No high confidence
        for a in report["angles"]:
            self.assertIn(a["confidence"], ("low", "medium"))
        # Angle types include at least A-AUTH or A-ORACLE (k2 is a
        # Soroban lending protocol — it *must* have these surfaces)
        types = {a["angle"] for a in report["angles"]}
        self.assertTrue(
            {"A-AUTH", "A-ORACLE"} & types,
            f"expected A-AUTH or A-ORACLE in k2 types; got {types}"
        )


if __name__ == "__main__":
    unittest.main()
