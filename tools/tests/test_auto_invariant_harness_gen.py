"""Guard tests for tools/auto-invariant-harness-gen.py

Asserts:
  1. Emitter produces a manifest (JSON with expected schema key).
  2. Emitted .t.sol contains REAL assert-style invariant bodies (not assert(true)).
  3. UNIV-CONSERVATION and UNIV-NO-FREE-MINT invariants are present.
  4. A scaffold is self-marked UNWIRED when no fork-url and no deploy fixture.
  5. Never emits assert(true) or x == x self-equality in an invariant body.
  6. Manifest is_real_contract=False for scaffold tier.

Run:
    python3 -m unittest tools.tests.test_auto_invariant_harness_gen
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOLS = _HERE.parent


def _load_module():
    tool = _TOOLS / "auto-invariant-harness-gen.py"
    spec = importlib.util.spec_from_file_location("auto_invariant_harness_gen", str(tool))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["auto_invariant_harness_gen"] = mod
    spec.loader.exec_module(mod)
    return mod


_mod = _load_module()


# ---------------------------------------------------------------------------
# Minimal fixture Solidity contracts.
# ---------------------------------------------------------------------------

_SIMPLE_ERC20_SOL = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract SimpleVault {
        mapping(address => uint256) public balanceOf;
        uint256 public totalSupply;
        address public asset;

        function deposit(uint256 amount, address receiver) external returns (uint256 shares) {
            totalSupply += amount;
            balanceOf[receiver] += amount;
            shares = amount;
        }

        function withdraw(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
            require(balanceOf[owner] >= shares, "insufficient");
            balanceOf[owner] -= shares;
            totalSupply -= shares;
            assets = shares;
        }

        function transfer(address to, uint256 amount) external returns (bool) {
            require(balanceOf[msg.sender] >= amount, "insufficient");
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            return true;
        }
    }
""")

_PAUSABLE_SOL = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract PausableToken {
        bool public paused;
        mapping(address => uint256) public balanceOf;
        uint256 public totalSupply;

        modifier whenNotPaused() { require(!paused); _; }

        function pause() external { paused = true; }
        function unpause() external { paused = false; }

        function mint(address to, uint256 amount) external whenNotPaused {
            totalSupply += amount;
            balanceOf[to] += amount;
        }
    }
""")

_EMPTY_INTERFACE_SOL = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    interface IEmpty {
        function foo() external view returns (uint256);
    }
""")


def _make_ws(sol_content: str, sol_name: str = "SimpleVault") -> Path:
    """Create a temp workspace with a single Solidity file in src/."""
    tmp = tempfile.mkdtemp(prefix="aihg_test_")
    src = Path(tmp) / "src"
    src.mkdir()
    (src / f"{sol_name}.sol").write_text(sol_content, encoding="utf-8")
    (Path(tmp) / ".auditooor").mkdir()
    return Path(tmp)


class TestManifestProduced(unittest.TestCase):
    """Emitter produces a manifest with the expected schema key."""

    def test_manifest_file_exists_after_main(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        try:
            _mod.main([str(ws)])
        except SystemExit as e:
            if e.code not in (0, None):
                self.fail(f"main() exited with code {e.code}")
        manifest_path = ws / ".auditooor" / "auto_invariant_harness_gen_manifest.json"
        self.assertTrue(manifest_path.exists(), "manifest file should exist after main()")
        data = json.loads(manifest_path.read_text())
        self.assertEqual(data["schema"], "auditooor.auto_invariant_harness_gen.v1")
        self.assertIn("results", data)

    def test_result_has_emitted_status(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertEqual(r["status"], "emitted", f"expected emitted, got: {r}")

    def test_result_schema_key(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertEqual(r["schema"], "auditooor.auto_invariant_harness_gen.v1")


class TestRealInvariantBodies(unittest.TestCase):
    """Emitted .t.sol contains real assertion expressions - not assert(true)."""

    def _get_sol(self, ws: Path, contract: str) -> str:
        sol_path = (ws / "poc-tests" / f"{contract}-universal-invariants" / "test"
                    / f"{contract}_Conservation_RoundTrip_xfn.t.sol")
        self.assertTrue(sol_path.exists(), f".t.sol not found at {sol_path}")
        return sol_path.read_text()

    def test_no_assert_true(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        self.assertNotIn("assert(true)", sol,
                         "assert(true) must never appear in emitted harness")

    def test_no_x_equals_x_self_equality_in_assertions(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        trivial_matches = []
        for line in sol.splitlines():
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            # Look for patterns like x == x where x is a non-trivial identifier
            m = re.findall(r"\b([A-Za-z_]\w*)\s*==\s*\1\b", stripped)
            for tok in m:
                if tok not in ("true", "false", "null"):
                    trivial_matches.append(f"'{tok} == {tok}' in: {stripped}")
        self.assertEqual(trivial_matches, [],
                         f"Self-equality detected: {trivial_matches}")

    def test_has_real_comparison_calls(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        has_real_assert = any(kw in sol for kw in
                              ("assertGe(", "assertLe(", "assertEq(", "assertFalse(",
                               "assertTrue("))
        self.assertTrue(has_real_assert,
                        "emitted harness must contain at least one assert*/assertGe/Le call")

    def test_invariant_functions_declared(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        fns = re.findall(r"function invariant_(\w+)\(\)", sol)
        self.assertGreater(len(fns), 0, "at least one invariant_* function must be emitted")


class TestConservationAndNoFreeMint(unittest.TestCase):
    """UNIV-CONSERVATION and UNIV-NO-FREE-MINT invariants are present for ERC20-like target."""

    def _get_sol(self, ws: Path, contract: str) -> str:
        sol_path = (ws / "poc-tests" / f"{contract}-universal-invariants" / "test"
                    / f"{contract}_Conservation_RoundTrip_xfn.t.sol")
        return sol_path.read_text()

    def test_conservation_present_in_manifest(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertIn("UNIV-CONSERVATION", r["emitted_invariants"],
                      "UNIV-CONSERVATION must be in emitted_invariants for vault-like contract")

    def test_conservation_present_in_sol(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        self.assertIn("UNIV_CONSERVATION", sol.replace("-", "_"),
                      "UNIV-CONSERVATION invariant function must appear in .t.sol")

    def test_no_free_mint_present_in_manifest(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertIn("UNIV-NO-FREE-MINT", r["emitted_invariants"],
                      "UNIV-NO-FREE-MINT must be emitted for ERC20-like surface")

    def test_no_free_mint_present_in_sol(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        self.assertIn("UNIV_NO_FREE_MINT", sol.replace("-", "_"),
                      "UNIV-NO-FREE-MINT invariant function must appear in .t.sol")

    def test_multiple_invariants_emitted(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertGreaterEqual(len(r["emitted_invariants"]), 2,
                                "at least 2 universal invariants expected for vault-like contract")


class TestScaffoldSelfMarked(unittest.TestCase):
    """Scaffold (tier c) is self-marked UNWIRED and is_real_contract=False."""

    def _get_sol(self, ws: Path, contract: str) -> str:
        sol_path = (ws / "poc-tests" / f"{contract}-universal-invariants" / "test"
                    / f"{contract}_Conservation_RoundTrip_xfn.t.sol")
        self.assertTrue(sol_path.exists(), f".t.sol not found at {sol_path}")
        return sol_path.read_text()

    def test_scaffold_wiring_tier_is_unwired(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertEqual(r["wiring_tier"], "chimera-manual-UNWIRED",
                         "without fork-url or deploy fixture, tier must be chimera-manual-UNWIRED")

    def test_scaffold_is_real_contract_false(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertFalse(r["is_real_contract"],
                         "scaffold tier must set is_real_contract=False")

    def test_scaffold_banner_contains_unwired(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        self.assertIn("chimera-manual-UNWIRED", sol,
                      "scaffold .t.sol must contain WIRING-TIER: chimera-manual-UNWIRED")

    def test_scaffold_todo_present(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol = self._get_sol(ws, "SimpleVault")
        self.assertIn("TODO(operator)", sol,
                      "scaffold .t.sol must contain TODO(operator) setup instruction")

    def test_fork_tier_activates_with_fork_url(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(
            ws, ws / "src" / "SimpleVault.sol",
            fork_rpc="https://example.rpc/", fork_block=0,
        )
        self.assertEqual(r["wiring_tier"], "fork",
                         "fork_rpc provided -> tier must be fork")
        self.assertTrue(r["is_real_contract"],
                        "fork tier must set is_real_contract=True")

    def test_fork_sol_contains_create_select_fork(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(
            ws, ws / "src" / "SimpleVault.sol",
            fork_rpc="https://example.rpc/", fork_block=12345678,
        )
        sol_path = (ws / "poc-tests" / "SimpleVault-universal-invariants" / "test"
                    / "SimpleVault_Conservation_RoundTrip_xfn.t.sol")
        sol = sol_path.read_text()
        self.assertIn("vm.createSelectFork", sol,
                      "fork-mode harness must call vm.createSelectFork")
        self.assertIn("AUDITOOOR_TARGET_ADDR", sol,
                      "fork-mode harness must read AUDITOOOR_TARGET_ADDR from env")


class TestCrossFunction(unittest.TestCase):
    """Harness file naming enables cross-function-harness-producer discovery."""

    def test_harness_file_name_contains_xfn_hints(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol_files = [f for f in r["emitted_files"] if f.endswith(".t.sol")]
        self.assertTrue(sol_files, "at least one .t.sol must be emitted")
        fname = Path(sol_files[0]).name
        self.assertIn("Conservation", fname,
                      "filename must contain 'Conservation' for producer discovery")
        self.assertIn("xfn", fname,
                      "filename must contain 'xfn' for producer discovery")

    def test_candidate_not_proof_flag(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertTrue(r["candidate_not_proof"],
                        "candidate_not_proof must be True in manifest")

    def test_manifest_has_proof_pending_via(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        r = _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        self.assertIn("cross-function-harness-producer", r["proof_pending_via"])


class TestPauseGateInvariant(unittest.TestCase):
    """UNIV-PAUSE-GATE is emitted for pausable contracts."""

    def test_pause_gate_emitted(self):
        ws = _make_ws(_PAUSABLE_SOL, "PausableToken")
        r = _mod.generate_for_contract(ws, ws / "src" / "PausableToken.sol", None, 0)
        self.assertIn("UNIV-PAUSE-GATE", r["emitted_invariants"],
                      "UNIV-PAUSE-GATE must be emitted for contract with pause modifier")


class TestMedusaConfig(unittest.TestCase):
    """medusa.json is emitted with correct structure."""

    def test_medusa_json_exists(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        medusa_path = (ws / "poc-tests" / "SimpleVault-universal-invariants" / "medusa.json")
        self.assertTrue(medusa_path.exists(), "medusa.json must be emitted")
        cfg = json.loads(medusa_path.read_text())
        self.assertIn("fuzzing", cfg)
        self.assertIn("testPrefixes", cfg["fuzzing"]["propertyTesting"])
        self.assertIn("invariant_", cfg["fuzzing"]["propertyTesting"]["testPrefixes"])

    def test_medusa_target_contract_name_contains_handler(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        medusa_path = (ws / "poc-tests" / "SimpleVault-universal-invariants" / "medusa.json")
        cfg = json.loads(medusa_path.read_text())
        targets = cfg["fuzzing"]["targetContracts"]
        self.assertTrue(
            any("Handler" in t for t in targets),
            "medusa.json targetContracts must reference the Handler contract",
        )


class TestRefusalOnNoApplicableInvariant(unittest.TestCase):
    """Tool refuses when no universal invariant applies."""

    def test_interface_only_no_emit(self):
        ws = _make_ws(_EMPTY_INTERFACE_SOL, "IEmpty")
        r = _mod.generate_for_contract(ws, ws / "src" / "IEmpty.sol", None, 0)
        self.assertNotEqual(r.get("status"), "emitted",
                            "interface-only file must not produce emitted status")


class TestHarnessNotProofBanner(unittest.TestCase):
    """CANDIDATE HARNESS - NOT PROOF banner appears in all emitted .t.sol files."""

    def test_banner_in_sol(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        sol_path = (ws / "poc-tests" / "SimpleVault-universal-invariants" / "test"
                    / "SimpleVault_Conservation_RoundTrip_xfn.t.sol")
        sol = sol_path.read_text()
        self.assertIn("CANDIDATE HARNESS - NOT PROOF", sol,
                      "CANDIDATE HARNESS - NOT PROOF banner must appear in .t.sol")


class TestEmittedSolidityDefectsFixed(unittest.TestCase):
    # r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
    """Locks the 3 adversarial-verify defect fixes: no within-contract duplicate
    state-var declarations (compiler-fatal), non-vacuous conservation (real
    balance-snapshot, not 0==0), and no inverted-polarity unconditional revert."""

    def _emit(self):
        ws = _make_ws(_SIMPLE_ERC20_SOL)
        _mod.generate_for_contract(ws, ws / "src" / "SimpleVault.sol", None, 0)
        return (ws / "poc-tests" / "SimpleVault-universal-invariants" / "test"
                / "SimpleVault_Conservation_RoundTrip_xfn.t.sol").read_text()

    def test_no_duplicate_state_vars_within_a_contract(self):
        import re
        sol = self._emit()
        for m in re.finditer(r"contract\s+\w[\w]*[^{]*\{(.*?)\n\}", sol, re.S):
            names = re.findall(r"\bpublic\s+([A-Za-z_]\w*)\s*;", m.group(1))
            dups = sorted({n for n in names if names.count(n) > 1})
            self.assertEqual(dups, [], f"duplicate state vars within one contract: {dups}")

    def test_conservation_is_non_vacuous(self):
        sol = self._emit()
        self.assertIn("IERC20Min(ghost_tracked_tokens", sol,
                      "conservation must do a real balance-snapshot, not a 0==0 ghost compare")
        self.assertNotIn("ghost_totalIn", sol, "old vacuous ghost_totalIn ledger must be gone")
        self.assertIn("INERT until wired", sol,
                      "conservation must early-return (honest inert) until wired, not silently pass 0==0")

    def test_no_unconditional_revert_in_invariants(self):
        sol = self._emit()
        self.assertNotIn("revert(", sol,
                         "emitted invariants must not unconditionally revert (inverted polarity)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
