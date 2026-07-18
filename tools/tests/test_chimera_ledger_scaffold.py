"""Regression tests for tools/chimera-ledger-scaffold.py."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "chimera-ledger-scaffold.py"


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


class ChimeraLedgerScaffoldTests(unittest.TestCase):
    def test_batch_scaffold_writes_manifest_and_skips_non_solidity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
            ledger = {
                "schema": "auditooor.invariant_ledger.v1",
                "rows": [
                    {"id": "SOL-I01", "title": "vault", "source_citations": ["src/Vault.sol:1"]},
                    {"id": "RUST-I01", "title": "rust", "source_citations": ["crates/node/src/lib.rs:1"]},
                ],
            }
            (ws / ".auditooor" / "invariant_ledger.json").write_text(json.dumps(ledger))
            _write_impact_contract(ws, row_id="SOL-I01")
            manifest = ws / ".audit_logs" / "chimera_scaffold_manifest.json"
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--manifest",
                    str(manifest),
                    "--require-concrete-binding",
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertEqual(payload["schema"], "auditooor.chimera_ledger_scaffold.v1")
            self.assertEqual(payload["status_counts"]["scaffolded"], 1)
            self.assertEqual(payload["status_counts"]["skipped_non_solidity"], 1)
            self.assertEqual(payload["entries"][0]["row_id"], "SOL-I01")
            self.assertTrue((ws / "chimera_harnesses" / "SOL-I01" / "auditooor_chimera_manifest.json").exists())
            self.assertTrue(manifest.exists())

    def test_dry_run_does_not_create_harness_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps({"rows": [{"id": "SOL-I01", "source_citations": ["src/Vault.sol:1"]}]})
            )
            _write_impact_contract(ws, row_id="SOL-I01")
            subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--dry-run", "--require-concrete-binding"],
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertFalse((ws / "chimera_harnesses" / "SOL-I01").exists())
            manifest = json.loads((ws / ".audit_logs" / "chimera_scaffold_manifest.json").read_text())
            self.assertEqual(manifest["status_counts"]["planned"], 1)

    def test_strict_handler_collision_skips_row_without_batch_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(
                "contract Vault { function withdraw(uint256 amount) external {} }\n"
                "contract Router { function withdraw(uint256 amount) external {} }\n"
            )
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "id": "SOL-I01",
                                "source_citations": ["src/Vault.sol:1", "src/Vault.sol:2"],
                            }
                        ]
                    }
                )
            )
            _write_impact_contract(ws, row_id="SOL-I01")
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--dry-run",
                    "--require-concrete-binding",
                    "--strict-handlers",
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["status_counts"]["skipped_ambiguous"], 1)
            self.assertIn("handler collision", manifest["entries"][0]["reason"])
            self.assertFalse((ws / "chimera_harnesses" / "SOL-I01").exists())

    def test_missing_impact_contract_blocks_row_without_harness_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
            (ws / ".auditooor" / "invariant_ledger.json").write_text(
                json.dumps({"rows": [{"id": "SOL-I01", "source_citations": ["src/Vault.sol:1"]}]})
            )
            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--require-concrete-binding",
                    "--print-json",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["status_counts"]["blocked_missing_impact_contract"], 1)
            self.assertEqual(manifest["entries"][0]["status"], "blocked_missing_impact_contract")
            self.assertFalse((ws / "chimera_harnesses" / "SOL-I01" / "test/recon/CryticTester.sol").exists())
            self.assertTrue((ws / "chimera_harnesses" / "SOL-I01" / "auditooor_chimera_manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
