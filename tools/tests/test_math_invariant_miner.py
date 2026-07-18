#!/usr/bin/env python3
"""V4 P2 — tests for tools/math-invariant-miner.py (Tier B / advisory).

Covers:
  - End-to-end: workspace with the diverging-supply fixture produces
    MATH_SPEC.md + math_spec.json with a conservation law and a one-sided
    mutation flagged on mint().
  - Clean fixture produces the conservation law but NO violations
    (transfer's two-sided mapping mutation is not flagged).
  - JSON schema shape (required keys, schema_version, tier="B").
  - Multi-contract workspace: each contract gets its own analysis section.
  - Heuristics: monotonicity hint on `mint`, role inference for
    `oracle`/`admin` named state vars, user-input extraction.
  - Determinism: two runs over the same input produce byte-identical JSON
    (sorted keys + stable iteration).
  - CLI surface: --help exits 0, missing workspace exits 2, custom
    --contracts glob honoured.
  - audit-deep.sh DEEP_PROFILE=math handler dry-run notes the planned
    invocation; live run produces artifacts.

All offline. Stdlib only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "math-invariant-miner.py"
AUDIT_DEEP = ROOT / "tools" / "audit-deep.sh"
FIXTURE_DIR = ROOT / "tools" / "tests" / "fixtures" / "math_invariant_miner"
FIXTURE_VULN = FIXTURE_DIR / "diverging_supply_vulnerable.sol"
FIXTURE_CLEAN = FIXTURE_DIR / "convergent_supply_clean.sol"


def _make_ws(tmpdir: Path, fixture: Path) -> Path:
    ws = tmpdir / "ws"
    (ws / "src").mkdir(parents=True)
    shutil.copy(fixture, ws / "src" / fixture.name)
    return ws


def _run_miner(ws: Path, *extra_args: str) -> subprocess.CompletedProcess:
    out_dir = ws / "math_invariants"
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--workspace",
            str(ws),
            "--output-dir",
            str(out_dir),
            *extra_args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


class MathInvariantMinerTests(unittest.TestCase):
    def test_tool_exists_and_help(self) -> None:
        self.assertTrue(TOOL.exists(), f"missing {TOOL}")
        cp = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("--workspace", cp.stdout)
        self.assertIn("--output-dir", cp.stdout)

    def test_missing_workspace_exits_2(self) -> None:
        cp = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                "/this/path/should/not/exist/p2-smoke",
                "--output-dir",
                "/tmp/p2-doesnt-matter",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 2)

    def test_vulnerable_fixture_emits_artifacts_and_violation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), FIXTURE_VULN)
            cp = _run_miner(ws)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            md = ws / "math_invariants" / "MATH_SPEC.md"
            js = ws / "math_invariants" / "math_spec.json"
            self.assertTrue(md.exists())
            self.assertTrue(js.exists())

            md_text = md.read_text()
            self.assertIn("DivergingMath", md_text)
            self.assertIn("conservation-of-totalsupply", md_text)
            self.assertIn("totalSupply == sum(balanceOf)", md_text)
            # mint() is the only function that should be flagged
            self.assertIn("`mint`", md_text)

            spec = json.loads(js.read_text())
            self.assertEqual(spec["schema_version"], "1.0")
            self.assertEqual(spec["tier"], "B")
            self.assertIn("DivergingMath", spec["contracts"])
            c = spec["contracts"]["DivergingMath"]
            self.assertTrue(c["conservation_laws"])
            self.assertEqual(c["conservation_laws"][0]["formula"], "totalSupply == sum(balanceOf)")
            mint_violations = [v for v in c["violations"] if v["function"] == "mint"]
            self.assertEqual(len(mint_violations), 1, c["violations"])
            self.assertEqual(mint_violations[0]["kind"], "scalar-moved-mapping-untouched")
            self.assertEqual(mint_violations[0]["severity"], "HIGH")

    def test_clean_fixture_emits_no_violations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), FIXTURE_CLEAN)
            cp = _run_miner(ws)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            c = spec["contracts"]["ConvergentMath"]
            # Clean: mint touches both totalSupply AND balanceOf -> not flagged.
            self.assertEqual(c["violations"], [], c["violations"])
            # Conservation law still emitted (variables match the heuristic).
            self.assertTrue(c["conservation_laws"])

    def test_json_schema_required_keys(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), FIXTURE_VULN)
            _run_miner(ws)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            for k in (
                "schema_version",
                "workspace",
                "generated_at",
                "tier",
                "tool",
                "contracts",
            ):
                self.assertIn(k, spec)
            c = spec["contracts"]["DivergingMath"]
            for k in (
                "state_variables",
                "functions",
                "conservation_laws",
                "monotonicity",
                "rounding",
                "regime_boundaries",
                "user_inputs",
                "oracle_config_dependencies",
                "candidates",
                "violations",
            ):
                self.assertIn(k, c, f"missing key {k}")

    def test_monotonicity_hint_on_mint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), FIXTURE_VULN)
            _run_miner(ws)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            c = spec["contracts"]["DivergingMath"]
            mono = c["monotonicity"]
            self.assertTrue(any(m["variable"] == "totalSupply" and m["direction"] == "non-decreasing" for m in mono))

    def test_user_inputs_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), FIXTURE_VULN)
            _run_miner(ws)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            c = spec["contracts"]["DivergingMath"]
            self.assertIn("amount", c["user_inputs"])
            self.assertIn("to", c["user_inputs"])

    def test_oracle_role_inferred(self) -> None:
        # Synthesise a contract with an oracle-named variable and confirm the
        # role heuristic fires.
        sol = """
        // SPDX-License-Identifier: UNLICENSED
        pragma solidity ^0.8.20;
        contract Configurable {
            address public priceOracle;
            uint256 public adminFactor;
            uint256 public totalSupply;
            mapping(address => uint256) public balanceOf;
        }
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Configurable.sol").write_text(sol)
            cp = _run_miner(ws)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            c = spec["contracts"]["Configurable"]
            roles = {v["name"]: v.get("role") for v in c["state_variables"]}
            self.assertEqual(roles.get("priceOracle"), "oracle")
            self.assertEqual(roles.get("adminFactor"), "config")
            deps = {d["config"] for d in c["oracle_config_dependencies"]}
            self.assertIn("priceOracle", deps)
            self.assertIn("adminFactor", deps)

    def test_multiple_contracts_each_analysed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            shutil.copy(FIXTURE_VULN, ws / "src" / FIXTURE_VULN.name)
            shutil.copy(FIXTURE_CLEAN, ws / "src" / FIXTURE_CLEAN.name)
            cp = _run_miner(ws)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            self.assertIn("DivergingMath", spec["contracts"])
            self.assertIn("ConvergentMath", spec["contracts"])

    def test_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), FIXTURE_VULN)
            _run_miner(ws)
            first = (ws / "math_invariants" / "math_spec.json").read_text()
            shutil.rmtree(ws / "math_invariants")
            _run_miner(ws)
            second = (ws / "math_invariants" / "math_spec.json").read_text()
            # `generated_at` is a timestamp; strip that single line before
            # comparing the rest of the structure.
            def _strip_ts(text: str) -> str:
                return "\n".join(
                    line for line in text.splitlines() if "generated_at" not in line
                )
            self.assertEqual(_strip_ts(first), _strip_ts(second))

    def test_custom_contracts_glob_honoured(self) -> None:
        # Place a contract OUTSIDE the default src/ glob and prove --contracts
        # picks it up.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "lib").mkdir(parents=True)
            shutil.copy(FIXTURE_VULN, ws / "lib" / "OffPath.sol")
            cp = _run_miner(ws, "--contracts", "lib/**/*.sol")
            self.assertEqual(cp.returncode, 0, cp.stderr)
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            self.assertIn("DivergingMath", spec["contracts"])

    def test_audit_deep_profile_math_dry_run(self) -> None:
        # In dry-run mode the math step should be PLANNED, not executed —
        # so no math_invariants/ artifact is emitted.
        if not AUDIT_DEEP.exists():
            self.skipTest("audit-deep.sh missing")
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            shutil.copy(FIXTURE_VULN, ws / "src" / FIXTURE_VULN.name)
            env = os.environ.copy()
            env["DEEP_PROFILE"] = "math"
            env["AUDIT_DEEP_DRY_RUN"] = "1"
            cp = subprocess.run(
                ["bash", str(AUDIT_DEEP), "--dry-run", str(ws)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            report = ws / ".audit_logs" / "audit_deep_report.md"
            self.assertTrue(report.exists())
            txt = report.read_text()
            self.assertIn("Step 5", txt)
            self.assertIn("DEEP_PROFILE=math", txt)
            self.assertIn("planned:", txt)
            # Dry-run must NOT actually emit the spec.
            self.assertFalse((ws / "math_invariants" / "MATH_SPEC.md").exists())

    def test_audit_deep_profile_math_live_run_emits_artifacts(self) -> None:
        if not AUDIT_DEEP.exists():
            self.skipTest("audit-deep.sh missing")
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            shutil.copy(FIXTURE_VULN, ws / "src" / FIXTURE_VULN.name)
            env = os.environ.copy()
            env["DEEP_PROFILE"] = "math"
            # Disable optional tools by sterilising PATH (still needs python3,
            # bash, mkdir, date, cp). Keep /usr/bin + /bin + the dir hosting
            # python3 so the script can find the interpreter.
            keep_dirs = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
            keep_dirs.add(str(Path(sys.executable).parent))
            env["PATH"] = ":".join(sorted(keep_dirs))
            cp = subprocess.run(
                ["bash", str(AUDIT_DEEP), str(ws)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertTrue((ws / "math_invariants" / "MATH_SPEC.md").exists())
            self.assertTrue((ws / "math_invariants" / "math_spec.json").exists())
            spec = json.loads((ws / "math_invariants" / "math_spec.json").read_text())
            self.assertIn("DivergingMath", spec["contracts"])

    def test_audit_deep_default_profile_skips_math(self) -> None:
        # Under the V4 P4 --profile NAME dispatch (PR #240), math is its own
        # profile — when neither --profile math nor DEEP_PROFILE=math is set,
        # the math-invariant miner is simply not invoked. The default chain
        # (halmos/medusa/echidna/slither) runs without any reference to
        # math-invariant mining or MATH_SPEC artifacts.
        if not AUDIT_DEEP.exists():
            self.skipTest("audit-deep.sh missing")
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            shutil.copy(FIXTURE_VULN, ws / "src" / FIXTURE_VULN.name)
            env = os.environ.copy()
            env.pop("DEEP_PROFILE", None)
            env["AUDIT_DEEP_DRY_RUN"] = "1"
            cp = subprocess.run(
                ["bash", str(AUDIT_DEEP), "--dry-run", str(ws)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            txt = (ws / ".audit_logs" / "audit_deep_report.md").read_text()
            # Default report must NOT include the math-profile sections and
            # must NOT have produced MATH_SPEC artifacts.
            self.assertNotIn("MATH_SPEC", txt)
            self.assertNotIn("math-invariant-miner", txt)
            self.assertNotIn("math-profile", txt)
            # Default chain still ran.
            self.assertIn("Step 1 — Halmos symbolic execution", txt)
            self.assertFalse((ws / "math_invariants" / "MATH_SPEC.md").exists())

    def test_fixtures_have_no_bug_comments(self) -> None:
        # Foot-gun #2: comment-leakage. Strip Minimax's `// BUG:` markers;
        # this test is the canary that ensures we don't reintroduce them.
        for fixture in (FIXTURE_VULN, FIXTURE_CLEAN):
            self.assertTrue(fixture.exists(), f"missing {fixture}")
            text = fixture.read_text()
            self.assertNotIn("BUG:", text, f"{fixture} contains 'BUG:' marker")
            self.assertNotIn("VULN:", text, f"{fixture} contains 'VULN:' marker")
            self.assertNotIn("EXPLOIT:", text, f"{fixture} contains 'EXPLOIT:' marker")


if __name__ == "__main__":
    unittest.main()
