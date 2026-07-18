"""
tools/tests/test_invariant_auto_synth.py

Guard tests for tools/invariant-auto-synth.py.

Bug covered: test-file-included-as-production
  - .t.sol files placed OUTSIDE test/ (e.g. src/) were NOT excluded by the
    old path-directory filter, causing synthesized invariants to be derived
    from Foundry test contracts rather than production code.
  - .s.sol deploy-script files placed OUTSIDE script/ similarly passed through.
  - /script/ directory was not in the skip list at all.

All tests drive the tool via subprocess to avoid Python 3.14 import issues
with modules using top-level @dataclass decorators.

Lane: bugfix-inventory-claude-20260610
R36: rebuttal marker present in invariant-auto-synth.py near the edit.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOL = _REPO_ROOT / "tools" / "invariant-auto-synth.py"

# Minimal Solidity that will generate at least one invariant candidate
_PRODUCTION_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""

# Foundry test contract (should NEVER be included in invariant synthesis)
_TEST_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
contract TokenTest is Test {
    function testTransfer(address to, uint256 amount) external {
        // This is a test function - not a production invariant source
    }
}
"""

# Foundry deploy script (should NEVER be included in invariant synthesis)
_SCRIPT_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Script.sol";
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
    }
}
"""


def _run_synth(ws: Path, output: Path) -> tuple[int, str, str]:
    """Run invariant-auto-synth.py and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, str(_TOOL),
         "--workspace", str(ws),
         "--output", str(output),
         "--json"],
        capture_output=True, text=True
    )
    return result.returncode, result.stdout, result.stderr


def _read_records(output: Path) -> list[dict]:
    if not output.exists():
        return []
    records = []
    for line in output.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


class TestTestFileSuffixExclusion(unittest.TestCase):
    """
    Primary guard: .t.sol files in src/ must NOT appear in output.

    Before the fix: the directory filter (/test/, /tests/, ...) did NOT match
    a path like /workspace/src/MyToken.t.sol, so the file was included.
    After the fix: the .t.sol suffix filter excludes it regardless of directory.
    """

    def test_t_sol_outside_test_dir_is_excluded(self):
        """src/MyToken.t.sol must not produce any output records."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            src = ws / "src"
            src.mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"

            # Place a .t.sol test contract INSIDE src/ (non-standard but valid)
            (src / "MyToken.t.sol").write_text(_TEST_SOL, encoding="utf-8")

            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"Tool exited with {rc}; stderr={stderr}")

            records = _read_records(out)
            included_files = {r["file"] for r in records}
            matching = [f for f in included_files if "MyToken.t.sol" in f]
            self.assertEqual(
                matching, [],
                f"src/MyToken.t.sol appeared in output records: {matching}. "
                f"Test contracts must be excluded regardless of directory."
            )

    def test_cosmos_simulation_dir_is_excluded(self):
        """src/vault/simulation/*.go (Cosmos sim harness, OOS) must produce no records,
        while a sibling production keeper/*.go file IS included. NUVA 2026-06-30:
        134/844 ranked hunt questions leaked onto src/vault/simulation + simapp."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            sim = ws / "src" / "vault" / "simulation"
            keeper = ws / "src" / "vault" / "keeper"
            sim.mkdir(parents=True)
            keeper.mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"
            (sim / "vault.go").write_text(
                "package simulation\nfunc (k Keeper) CalculateNAV(ctx sdk.Context) {}\n")
            (keeper / "valuation_engine.go").write_text(
                "package keeper\nfunc (k Keeper) CalculateNAV(ctx sdk.Context) {}\n")
            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"stderr={stderr}")
            files = {r["file"] for r in _read_records(out)}
            self.assertFalse([f for f in files if "/simulation/" in f],
                             f"simulation/ harness must be excluded; got {files}")
            self.assertTrue([f for f in files if "valuation_engine.go" in f],
                            "production keeper/ must still be included")

    def test_simapp_dir_is_excluded(self):
        """src/vault/simapp/*.go (Cosmos SimApp wiring, OOS) must produce no records."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            simapp = ws / "src" / "vault" / "simapp"
            simapp.mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"
            (simapp / "app.go").write_text(
                "package simapp\nfunc (k Keeper) ProcessPayout(ctx sdk.Context) {}\n")
            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"stderr={stderr}")
            files = {r["file"] for r in _read_records(out)}
            self.assertFalse([f for f in files if "/simapp/" in f],
                             f"simapp/ must be excluded; got {files}")

    def test_s_sol_outside_script_dir_is_excluded(self):
        """src/Deploy.s.sol must not produce any output records."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            src = ws / "src"
            src.mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"

            # Place a .s.sol deploy script INSIDE src/
            (src / "Deploy.s.sol").write_text(_SCRIPT_SOL, encoding="utf-8")

            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"Tool exited with {rc}; stderr={stderr}")

            records = _read_records(out)
            included_files = {r["file"] for r in records}
            matching = [f for f in included_files if "Deploy.s.sol" in f]
            self.assertEqual(
                matching, [],
                f"src/Deploy.s.sol appeared in output records: {matching}. "
                f"Deploy scripts must be excluded regardless of directory."
            )

    def test_s_sol_inside_script_dir_is_excluded(self):
        """script/Deploy.s.sol must also be excluded (script/ dir now in skip list)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            script_dir = ws / "script"
            script_dir.mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"

            (script_dir / "Deploy.s.sol").write_text(_SCRIPT_SOL, encoding="utf-8")

            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"Tool exited with {rc}; stderr={stderr}")

            records = _read_records(out)
            included_files = {r["file"] for r in records}
            matching = [f for f in included_files if "Deploy.s.sol" in f]
            self.assertEqual(
                matching, [],
                f"script/Deploy.s.sol appeared in output records: {matching}. "
                f"/script/ dir must be excluded."
            )


class TestProductionSolIncluded(unittest.TestCase):
    """
    Regression guard: production .sol files must still be included after the fix.
    We don't want to over-exclude.
    """

    def test_production_sol_in_src_is_included(self):
        """src/MyToken.sol must still generate invariant candidates."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            src = ws / "src"
            src.mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"

            (src / "MyToken.sol").write_text(_PRODUCTION_SOL, encoding="utf-8")

            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"Tool exited with {rc}; stderr={stderr}")

            records = _read_records(out)
            included_files = {r["file"] for r in records}
            matching = [f for f in included_files if "MyToken.sol" in f]
            self.assertGreater(
                len(matching), 0,
                f"src/MyToken.sol did NOT appear in output records. "
                f"Production contracts must still be processed. All files: {included_files}"
            )


class TestMixedWorkspace(unittest.TestCase):
    """
    Combined scenario: production file included, test and script files excluded.
    This is the canonical regression test for the fix.
    """

    def test_mixed_workspace_only_production_included(self):
        """
        Workspace with src/Token.sol, src/Token.t.sol, src/Deploy.s.sol,
        script/Deploy.s.sol, and test/Token.t.sol.

        Only src/Token.sol should produce output records.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            (ws / "src").mkdir(parents=True)
            (ws / "script").mkdir(parents=True)
            (ws / "test").mkdir(parents=True)
            out = Path(tmp) / "out.jsonl"

            (ws / "src" / "Token.sol").write_text(_PRODUCTION_SOL, encoding="utf-8")
            (ws / "src" / "Token.t.sol").write_text(_TEST_SOL, encoding="utf-8")
            (ws / "src" / "Deploy.s.sol").write_text(_SCRIPT_SOL, encoding="utf-8")
            (ws / "script" / "Deploy.s.sol").write_text(_SCRIPT_SOL, encoding="utf-8")
            (ws / "test" / "Token.t.sol").write_text(_TEST_SOL, encoding="utf-8")

            rc, stdout, stderr = _run_synth(ws, out)
            self.assertEqual(rc, 0, f"Tool exited with {rc}; stderr={stderr}")

            records = _read_records(out)
            included_files = {r["file"] for r in records}

            # Production file must be included
            prod_matches = [f for f in included_files if "Token.sol" in f
                            and ".t.sol" not in f and ".s.sol" not in f]
            self.assertGreater(
                len(prod_matches), 0,
                f"src/Token.sol missing from output. included_files={included_files}"
            )

            # Test/script files must be excluded
            bad = [f for f in included_files
                   if f.endswith(".t.sol") or f.endswith(".s.sol")]
            self.assertEqual(
                bad, [],
                f"Test/script files leaked into output: {bad}"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
