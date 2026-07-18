"""Regression tests for tools/chimera-scaffold.py."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "chimera-scaffold.py"


def _make_workspace(tmp: Path, source: str) -> Path:
    ws = tmp / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir()
    (ws / "src" / "Vault.sol").write_text(source)
    ledger = {
        "schema": "auditooor.invariant_ledger.v1",
        "rows": [
            {
                "id": "ROW-1",
                "title": "Vault balance cannot be drained",
                "source_citations": ["src/Vault.sol:1"],
                "production_path": "src/Vault.sol: Vault.withdraw",
            }
        ],
    }
    (ws / ".auditooor" / "invariant_ledger.json").write_text(json.dumps(ledger))
    _write_impact_contract(ws, row_id="ROW-1")
    return ws


def _write_impact_contract(ws: Path, *, row_id: str, proven: bool = True) -> None:
    (ws / ".auditooor" / "impact_contracts.json").write_text(
        json.dumps(
            {
                "contracts": [
                    {
                        "row_id": row_id,
                        "impact_contract_id": "impact-contract-vault-loss",
                        "selected_impact": "Direct theft of user funds from the vault",
                        "severity": "high",
                        "exact_impact_row": True,
                        "listed_impact_proven": proven,
                    }
                ]
            }
        )
    )


def _install_forge_std(ws: Path) -> None:
    forge_std = ws / "lib" / "forge-std" / "src"
    forge_std.mkdir(parents=True)
    (forge_std / "Test.sol").write_text("contract Test {}\n")


class ChimeraScaffoldTests(unittest.TestCase):
    def test_scaffold_writes_manifest_and_advisory_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(
                Path(td),
                "contract Vault { function deposit() external {} function withdraw(uint256) external {} }",
            )
            out = ws / "chimera_harnesses" / "ROW-1"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--out",
                    str(out),
                    "--require-concrete-binding",
                    "--strict-handlers",
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertEqual(payload["schema"], "auditooor.chimera_harness.v1")
            self.assertEqual(payload["evidence_class"], "scaffolded_unverified")
            self.assertTrue(payload["ledger_hash"])
            self.assertEqual(payload["ledger_hash"], payload["ledger_provenance_hash"])
            self.assertTrue(payload["commands_display_only"])
            self.assertEqual(payload["concrete_bindings"][0]["contract"], "Vault")
            self.assertTrue((out / "test/recon/CryticTester.sol").exists())
            manifest = json.loads((out / "auditooor_chimera_manifest.json").read_text())
            self.assertEqual(manifest["status"], "scaffolded_unverified")
            self.assertIn("ADVISORY", (out / "README.md").read_text())
            self.assertIn("target_withdraw", (out / "test/recon/TargetFunctions.sol").read_text())

    def test_workspace_forge_std_writes_relative_remapping(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(
                Path(td),
                "contract Vault { function deposit() external {} function withdraw(uint256) external {} }",
            )
            _install_forge_std(ws)
            out = ws / "chimera_harnesses" / "ROW-1"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--out",
                    str(out),
                    "--require-concrete-binding",
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(result.stdout)
            resolution = payload["forge_std_resolution"]
            self.assertEqual(resolution["status"], "remapping_written")
            self.assertEqual(resolution["remapping"], "forge-std/=../../lib/forge-std/src/")
            self.assertEqual(
                (out / "remappings.txt").read_text(),
                "forge-std/=../../lib/forge-std/src/\n",
            )
            self.assertIn("forge-std/=../../lib/forge-std/src/", (out / "README.md").read_text())
            self.assertIn('import "forge-std/Test.sol";', (out / "test/recon/CryticToFoundry.sol").read_text())

    def test_dry_run_does_not_write_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "contract Vault { function withdraw() external {} }")
            out = ws / "chimera_harnesses" / "ROW-1"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--out",
                    str(out),
                    "--dry-run",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("auditooor.chimera_harness.v1", result.stdout)
            self.assertFalse(out.exists())

    def test_missing_impact_contract_blocks_without_harness_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "contract Vault { function withdraw() external {} }")
            (ws / ".auditooor" / "impact_contracts.json").unlink()
            out = ws / "chimera_harnesses" / "ROW-1"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--out",
                    str(out),
                    "--print-json",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "blocked_missing_impact_contract")
            self.assertFalse((out / "test/recon/CryticTester.sol").exists())
            self.assertTrue((out / "auditooor_chimera_manifest.json").exists())
            self.assertIn("blocked_missing_impact_contract", (out / "README.md").read_text())

    def test_unproven_impact_contract_blocks_without_harness_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "contract Vault { function withdraw() external {} }")
            _write_impact_contract(ws, row_id="ROW-1", proven=False)
            out = ws / "chimera_harnesses" / "ROW-1"
            result = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--row-id", "ROW-1", "--out", str(out)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertFalse((out / "test/recon/TargetFunctions.sol").exists())
            manifest = json.loads((out / "auditooor_chimera_manifest.json").read_text())
            self.assertEqual(manifest["status"], "blocked_missing_impact_contract")
            self.assertIn("listed_impact_proven=true", manifest["missing_preconditions"])

    def test_require_concrete_binding_fails_for_interface_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "interface Vault { function withdraw() external; }")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--require-concrete-binding",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("no concrete contract binding", result.stderr)

    def test_require_concrete_binding_fails_for_abstract_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "abstract contract Vault { function withdraw() external virtual; }")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--require-concrete-binding",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("no concrete contract binding", result.stderr)

    def test_malformed_row_id_is_rejected_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "contract Vault { function withdraw() external {} }")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW$(id)",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid row id", result.stderr)

    def test_out_dir_must_stay_inside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = _make_workspace(root, "contract Vault { function withdraw() external {} }")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--row-id",
                    "ROW-1",
                    "--out",
                    str(root / "outside"),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("out directory must be inside", result.stderr)

    def test_property_comment_injection_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td), "contract Vault { function withdraw() external {} }")
            ledger_path = ws / ".auditooor" / "invariant_ledger.json"
            ledger = json.loads(ledger_path.read_text())
            ledger["rows"][0]["title"] = "safe */ injected /*\nsecond line"
            ledger_path.write_text(json.dumps(ledger))
            out = ws / "chimera_harnesses" / "ROW-1"
            subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--row-id", "ROW-1", "--out", str(out)],
                text=True,
                capture_output=True,
                check=True,
            )
            props = (out / "test/recon/Properties.sol").read_text()
            self.assertNotIn("*/", props)
            self.assertNotIn("/*", props)
            self.assertIn("safe * / injected / * second line", props)


if __name__ == "__main__":
    unittest.main()
