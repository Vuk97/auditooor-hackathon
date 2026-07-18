"""Regression tests for tools/audit/invariant-harness-generator.py (W4.6)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "invariant-harness-generator.py"
FIXTURE = ROOT / "tools" / "tests" / "fixtures" / "fuzz_wrappers" / "vulnerable"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "invariant_harness_generator", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _load_tool()


VAULT_SRC = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

TOKEN_SRC = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Token {
    uint256 public totalSupply;
    uint256 public mintNonce;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amt) external {
        totalSupply += amt;
        balanceOf[to] += amt;
        mintNonce += 1;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function balanceLookup(address a) external view returns (uint256) {
        return balanceOf[a];
    }
}
"""


def _make_ws(tmp: Path, source: str, filename: str = "src/Vault.sol") -> Path:
    ws = tmp / "ws"
    src = ws / filename
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(source)
    return ws


class TestEnumeration(unittest.TestCase):
    def test_iter_solidity_sources_skips_test_and_lib(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "lib").mkdir()
            (ws / "test").mkdir()
            (ws / "src" / "A.sol").write_text("contract A {}")
            (ws / "lib" / "Dep.sol").write_text("contract Dep {}")
            (ws / "test" / "A.t.sol").write_text("contract AT {}")
            (ws / "src" / "B.t.sol").write_text("contract BT {}")
            found = {p.name for p in GEN.iter_solidity_sources(ws)}
            self.assertEqual(found, {"A.sol"})

    def test_monotone_var_detection(self):
        svars = [("uint256", "totalMinted"), ("uint256", "mintNonce"),
                 ("uint256", "price"), ("address", "owner")]
        self.assertEqual(
            set(GEN.monotone_vars(svars)), {"totalMinted", "mintNonce"})


class TestGenerateVault(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = _make_ws(Path(self._td.name), VAULT_SRC)
        self.manifest = GEN.generate(self.ws)

    def tearDown(self):
        self._td.cleanup()

    def test_status_ok(self):
        self.assertEqual(self.manifest["status"], "ok")
        self.assertEqual(self.manifest["target_contract"], "Vault")

    def test_emits_four_artifacts(self):
        for rel in ("fuzz/VaultInvariantHarness.t.sol", "fuzz/medusa.json",
                    "fuzz/echidna.yaml", "fuzz/harness_manifest.json"):
            self.assertTrue((self.ws / rel).is_file(), rel)

    def test_wrappers_for_mutating_functions(self):
        harness = (self.ws / "fuzz" / "VaultInvariantHarness.t.sol").read_text()
        self.assertIn("function fuzz_deposit()", harness)
        self.assertIn("function fuzz_withdraw(uint256 a0)", harness)
        self.assertIn("try target.deposit{value: msg.value}()", harness)

    def test_generic_invariants_present(self):
        harness = (self.ws / "fuzz" / "VaultInvariantHarness.t.sol").read_text()
        for inv in ("echidna_no_unbacked_supply", "echidna_target_solvent",
                    "echidna_accounting_monotonic"):
            self.assertIn(f"function {inv}()", harness)
        self.assertIn("assertBaselineInvariants", harness)

    def test_todo_section_present(self):
        harness = (self.ws / "fuzz" / "VaultInvariantHarness.t.sol").read_text()
        self.assertIn("TODO: protocol-specific invariants", harness)
        self.assertIn("echidna_protocol_invariant_1", harness)

    def test_medusa_config_targets_harness(self):
        cfg = json.loads((self.ws / "fuzz" / "medusa.json").read_text())
        self.assertIn("VaultInvariantHarness", cfg["targets"])
        self.assertIn("VaultInvariantHarness",
                      cfg["fuzzing"]["targetContracts"])
        self.assertTrue(cfg["fuzzing"]["assertionTesting"]["enabled"])

    def test_echidna_config_assertion_mode(self):
        cfg = (self.ws / "fuzz" / "echidna.yaml").read_text()
        self.assertIn("testMode: assertion", cfg)
        self.assertIn("VaultInvariantHarness", cfg)

    def test_idempotent(self):
        first = (self.ws / "fuzz" / "VaultInvariantHarness.t.sol").read_text()
        GEN.generate(self.ws, force=True)
        second = (self.ws / "fuzz" / "VaultInvariantHarness.t.sol").read_text()
        self.assertEqual(first, second)


class TestGenerateToken(unittest.TestCase):
    """Token has totalSupply + a monotone counter — exercises those paths."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = _make_ws(Path(self._td.name), TOKEN_SRC,
                           filename="src/Token.sol")
        self.manifest = GEN.generate(self.ws)

    def tearDown(self):
        self._td.cleanup()

    def test_total_supply_wires_real_invariant(self):
        self.assertTrue(self.manifest["has_total_supply"])
        harness = (self.ws / "fuzz" / "TokenInvariantHarness.t.sol").read_text()
        self.assertIn("target.totalSupply() <= ghostObservedSupply", harness)

    def test_monotone_candidate_detected(self):
        self.assertIn("mintNonce", self.manifest["monotone_candidates"])
        harness = (self.ws / "fuzz" / "TokenInvariantHarness.t.sol").read_text()
        self.assertIn("ghostLast_mintNonce", harness)

    def test_interface_declares_total_supply(self):
        harness = (self.ws / "fuzz" / "TokenInvariantHarness.t.sol").read_text()
        self.assertIn("function totalSupply() external view", harness)


class TestGuards(unittest.TestCase):
    def test_blocks_on_handwritten_harness(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), VAULT_SRC)
            (ws / "fuzz").mkdir()
            (ws / "fuzz" / "MyHarness.t.sol").write_text(
                "// hand written\ncontract MyHarness {}")
            manifest = GEN.generate(ws)
            self.assertEqual(manifest["status"], "blocked")
            self.assertIn("hand-written", manifest["reason"])

    def test_force_overrides_handwritten_harness(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), VAULT_SRC)
            (ws / "fuzz").mkdir()
            (ws / "fuzz" / "MyHarness.t.sol").write_text(
                "// hand written\ncontract MyHarness {}")
            manifest = GEN.generate(ws, force=True)
            self.assertEqual(manifest["status"], "ok")

    def test_blocks_on_empty_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty"
            ws.mkdir()
            manifest = GEN.generate(ws)
            self.assertEqual(manifest["status"], "blocked")

    def test_explicit_contract_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), VAULT_SRC)
            manifest = GEN.generate(ws, contract="DoesNotExist")
            self.assertEqual(manifest["status"], "blocked")


class TestCLI(unittest.TestCase):
    def test_cli_runs_against_repo_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            shutil.copytree(FIXTURE, ws)
            proc = subprocess.run(
                ["python3", str(TOOL), str(ws)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(proc.stdout)
            self.assertEqual(manifest["status"], "ok")
            self.assertEqual(manifest["target_contract"], "Vault")


@unittest.skipUnless(shutil.which("solc"),
                     "solc not on PATH; compile-shape check skipped")
class TestCompileShape(unittest.TestCase):
    """When solc is available, prove the generated harness compiles."""

    def _compile(self, source: str, filename: str) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), source, filename=filename)
            manifest = GEN.generate(ws)
            self.assertEqual(manifest["status"], "ok")
            harness = ws / manifest["generated"][0]
            proc = subprocess.run(
                ["solc", "--bin", str(harness)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0,
                             f"solc failed:\n{proc.stderr}")
            self.assertIn("Binary:", proc.stdout)

    def test_vault_harness_compiles(self):
        self._compile(VAULT_SRC, "src/Vault.sol")

    def test_token_harness_compiles(self):
        self._compile(TOKEN_SRC, "src/Token.sol")


if __name__ == "__main__":
    unittest.main()
