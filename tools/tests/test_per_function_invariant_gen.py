import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "per-function-invariant-gen.py"


class PerFunctionInvariantGenTest(unittest.TestCase):
    def test_matching_engine_harness_root_receives_generated_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function deposit(uint256 amount) external {} }\n",
                encoding="utf-8",
            )
            engine_root = ws / "poc-tests" / "Vault-engine-harness"
            (engine_root / "test").mkdir(parents=True)
            (engine_root / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\ntest = 'test'\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["functions"][0]
            harness_path = Path(row["harness_path"])
            self.assertEqual(harness_path, (engine_root / "test" / harness_path.name).resolve())
            self.assertTrue(harness_path.exists())
            self.assertEqual(row["halmos_root"], str(engine_root.resolve()))
            self.assertEqual(row["halmos_invocation"]["working_directory"], str(engine_root.resolve()))
            self.assertEqual(row["import_path"], "../src/Vault.sol")
            self.assertTrue((engine_root / "src").is_symlink())
            self.assertIn('import "../src/Vault.sol";', harness_path.read_text(encoding="utf-8"))

    def test_scaffold_harness_uses_foundry_configured_test_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            project = ws / "src" / "project"
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\ntest = 'tests'\n",
                encoding="utf-8",
            )
            (project / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function deposit(uint256 amount) external {} }\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            row = json.loads(proc.stdout)["functions"][0]
            self.assertEqual(Path(row["harness_path"]).parent, (project / "tests").resolve())
            self.assertTrue((project / "tests" / Path(row["harness_path"]).name).exists())

    def test_missing_engine_root_is_bootstrapped_from_donor(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Other.sol").write_text(
                "pragma solidity ^0.8.20; contract Other { function set(uint256 value) external {} }\n",
                encoding="utf-8",
            )
            donor = ws / "poc-tests" / "Donor-engine-harness"
            (donor / "lib" / "forge-std" / "src").mkdir(parents=True)
            (donor / "test").mkdir()
            (donor / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            row = json.loads(proc.stdout)["functions"][0]
            root = ws / "poc-tests" / "Other-engine-harness"
            self.assertEqual(row["halmos_root"], str(root.resolve()))
            self.assertTrue((root / "foundry.toml").exists())
            self.assertTrue((root / "lib").is_symlink())
            self.assertTrue(Path(row["harness_path"]).exists())

    def test_generates_only_state_writing_public_harnesses(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    uint256 public total;

    function deposit(uint256 amount) external {
        total += amount;
    }

    function totalAssets() external view returns (uint256) {
        return total;
    }

    function _settle() internal {
        total = 1;
    }
}
""",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.per_function_invariant_gen.v1")
            self.assertEqual(payload["function_count"], 1)
            row = payload["functions"][0]
            self.assertEqual(row["selector"], "Vault.deposit")
            self.assertIn("halmos_invocations", payload)
            self.assertEqual(payload["halmos_invocations"][0]["match_contract"], "Halmos_Vault_deposit")
            harness = Path(row["harness_path"])
            self.assertTrue(harness.exists())
            harness_text = harness.read_text(encoding="utf-8")
            self.assertIn('import "../../src/Vault.sol";', harness_text)
            self.assertIn("contract Halmos_Vault_deposit", harness_text)
            self.assertEqual(row["halmos_invocation"]["args"], ["--match-contract", "Halmos_Vault_deposit"])
            self.assertTrue((ws / "poc-tests" / "per_function_invariants" / "manifest.json").exists())
            # DUAL-PREFIX (SSV loop fix 2026-06-23): the scaffold must carry BOTH a
            # halmos `check_` entry AND a forge `test_` entry. `forge test` (the
            # genuine-coverage mutation-verify runner) discovers only test*/invariant*;
            # a check_-only scaffold ran 0 forge tests -> "no-execution" -> the harness
            # could never be classified/credited on a forge-engine workspace.
            self.assertIn("function check_deposit_does_not_break_core_invariant", harness_text)
            self.assertIn("function test_deposit_does_not_break_core_invariant", harness_text)
            # un-filled scaffold is still a sentinel (both bodies assert(true))
            self.assertTrue(row["is_sentinel"], "un-filled dual-prefix scaffold must stay sentinel")

    def test_harness_links_matching_preflight_pack_invariants(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Vault {
    function withdraw(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )
            pack_dir = ws / ".auditooor" / "pre_flight_packs"
            pack_dir.mkdir(parents=True)
            (pack_dir / "pre_flight_pack_Vault_withdraw.json").write_text(
                json.dumps(
                    {
                        "contract": "Vault",
                        "function": "withdraw",
                        "invariants_touched": {"invariant_ids": ["INV-WITHDRAW-001"]},
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["functions"][0]
            self.assertEqual(row["invariants_touched"], ["INV-WITHDRAW-001"])
            harness_text = Path(row["harness_path"]).read_text(encoding="utf-8")
            self.assertIn("Candidate invariant: INV-WITHDRAW-001", harness_text)

    def test_dry_run_does_not_write_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "contracts"
            src.mkdir()
            (src / "Token.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Token {
    function mint(address to, uint256 amount) public {}
}
""",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--dry-run", "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["function_count"], 1)
            self.assertEqual(payload["functions"][0]["status"], "would-write")
            self.assertFalse(Path(payload["functions"][0]["harness_path"]).exists())
            self.assertFalse((ws / "poc-tests" / "per_function_invariants").exists())

    def test_include_read_only_allows_targeted_view_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Ratifier.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Ratifier {
    function isRatified(bytes32 root) external view returns (bool) {
        return root != bytes32(0);
    }
}
""",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--function",
                    "isRatified",
                    "--include-read-only",
                    "--dry-run",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["function_count"], 1)
            self.assertEqual(payload["functions"][0]["selector"], "Ratifier.isRatified")

    def test_excludes_auditooor_poc_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Vault {
    function deposit(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )
            poc_dir = ws / ".auditooor" / "poc"
            poc_dir.mkdir(parents=True)
            (poc_dir / "AuditOnlyPoC.sol").write_text(
                """
pragma solidity ^0.8.20;
contract AuditOnlyPoC {
    function helper(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            selectors = {row["selector"] for row in payload["functions"]}
            self.assertEqual(selectors, {"Vault.deposit"})

    def test_overwrite_removes_stale_generated_harnesses_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Vault {
    function deposit(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )
            out = ws / "poc-tests" / "per_function_invariants"
            out.mkdir(parents=True)
            stale_generated = out / "Halmos_Stale_helper.t.sol"
            stale_generated.write_text(
                """
// Auto-generated by tools/per-function-invariant-gen.py.
contract Halmos_Stale_helper {}
""",
                encoding="utf-8",
            )
            manual = out / "Halmos_Manual_helper.t.sol"
            manual.write_text("contract Halmos_Manual_helper {}\n", encoding="utf-8")

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--overwrite", "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["function_count"], 1)
            self.assertFalse(stale_generated.exists())
            self.assertTrue(manual.exists())
            self.assertTrue(Path(payload["functions"][0]["harness_path"]).exists())
            self.assertEqual(payload["removed_stale_harnesses"], [str(stale_generated.resolve())])


    def test_overwrite_preserves_existing_real_harness(self):
        """P1-b no-clobber (taxonomy mode 13): a regeneration must NEVER overwrite
        a worker-filled REAL (non-sentinel) harness, even under --overwrite. The
        row status is 'preserved-existing-real-harness' and the file is unchanged.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                """
pragma solidity ^0.8.20;
contract Vault {
    function deposit(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )
            # First pass: emit the sentinel scaffold so we know its path.
            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            harness_path = Path(payload["functions"][0]["harness_path"])
            self.assertTrue(harness_path.exists())

            # Fill it with a REAL (non-sentinel) property, simulating a worker.
            real_body = """// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.0;
import "../../src/Vault.sol";
contract Halmos_Vault_deposit {
    function test_deposit_does_not_break_core_invariant() public {
        Vault v = new Vault();
        v.deposit(5);
        assert(address(v) != address(0));
    }
}
"""
            harness_path.write_text(real_body, encoding="utf-8")

            # Regenerate WITH --overwrite: the real harness MUST be preserved.
            proc2 = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--overwrite", "--json"],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc2.returncode, 0, proc2.stderr)
            payload2 = json.loads(proc2.stdout)
            row = payload2["functions"][0]
            self.assertEqual(
                row["status"], "preserved-existing-real-harness",
                "real harness must be preserved, not clobbered, under --overwrite",
            )
            self.assertFalse(row["is_sentinel"], "preserved real harness is not sentinel")
            # File content is byte-for-byte unchanged.
            self.assertEqual(
                harness_path.read_text(encoding="utf-8"), real_body,
                "real harness file must be unchanged after --overwrite regeneration",
            )

    def test_oos_deployed_zip_paths_yield_no_harness(self):
        """P1-e / taxonomy mode 19: a CUT under reference/instascope_deployed_zip
        is an OOS mirror; no harness must be emitted for those paths even though
        an in-scope src/ contract is harnessed normally."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "InScope.sol").write_text(
                """
pragma solidity ^0.8.20;
contract InScope {
    function deposit(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )
            oos = ws / "reference" / "instascope_deployed_zip" / "src"
            oos.mkdir(parents=True)
            (oos / "L2MigrationFacet.sol").write_text(
                """
pragma solidity ^0.8.20;
contract L2MigrationFacet {
    function migrate(uint256 amount) external {}
}
""",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            selectors = {row["selector"] for row in payload["functions"]}
            self.assertIn("InScope.deposit", selectors)
            self.assertNotIn("L2MigrationFacet.migrate", selectors,
                             "OOS deployed-zip CUT must not be harnessed")
            # No harness_path points into the deployed-zip tree.
            for row in payload["functions"]:
                self.assertNotIn("instascope_deployed_zip", row["source"])


if __name__ == "__main__":
    unittest.main()
