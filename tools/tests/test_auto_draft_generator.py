#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "auto-draft-generator.py"


class AutoDraftGeneratorImpactContractTests(unittest.TestCase):
    def make_ws(self, tmp: Path) -> Path:
        ws = tmp / "ws"
        ws.mkdir()
        (ws / ".auditooor").mkdir()
        (ws / "ccia_report.json").write_text(
            json.dumps(
                {
                    "attack_angles": [
                        {
                            "id": "A-AUTH",
                            "severity": "High",
                            "title": "Unauthorized vault withdrawal",
                            "contracts": ["Vault"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return ws

    def write_impact_contracts(self, ws: Path, *, proven: bool = True) -> None:
        (ws / "poc-tests").mkdir(exist_ok=True)
        (ws / "poc-tests" / "vault_theft_proof.txt").write_text(
            "proved listed impact\n",
            encoding="utf-8",
        )
        (ws / ".auditooor" / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-vault-theft",
                            "contract": "Vault",
                            "angle_id": "A-AUTH",
                            "selected_impact": "Direct theft of user funds",
                            "severity": "High",
                            "exact_impact_row": True,
                            "listed_impact_proven": proven,
                            "proof_artifact": "poc-tests/vault_theft_proof.txt",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

    def run_generator(self, ws: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(ws),
                "--angle-id",
                "A-AUTH",
                "--contract",
                "Vault",
                *args,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def run_generator_raw(self, ws: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(ws),
                *args,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_missing_impact_contract_id_blocks_before_writes_or_poc(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self.make_ws(Path(td))
            out = ws / "submissions" / "staging" / "draft.md"

            result = self.run_generator(ws, "--with-poc", "--out", str(out))

            self.assertEqual(result.returncode, 2)
            self.assertIn("blocked_missing_impact_contract", result.stdout)
            self.assertFalse(out.exists())
            self.assertFalse((ws / "poc-tests").exists())

    def test_unproven_impact_contract_blocks_before_staging_write(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self.make_ws(Path(td))
            self.write_impact_contracts(ws, proven=False)
            out = ws / "submissions" / "staging" / "draft.md"

            result = self.run_generator(
                ws,
                "--impact-contract-id",
                "impact-contract-vault-theft",
                "--out",
                str(out),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("listed_impact_proven=true", result.stdout)
            self.assertFalse(out.exists())

    def test_locked_impact_contract_allows_staging_draft(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self.make_ws(Path(td))
            self.write_impact_contracts(ws)
            out = ws / "submissions" / "staging" / "draft.md"

            result = self.run_generator(
                ws,
                "--impact-contract-id",
                "impact-contract-vault-theft",
                "--out",
                str(out),
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = out.read_text(encoding="utf-8")
            self.assertIn("**Impact contract:** `impact-contract-vault-theft`", text)
            self.assertIn("**Locked impact:** Direct theft of user funds", text)
            self.assertIn("**Proof artifact:** `poc-tests/vault_theft_proof.txt`", text)

    def test_pick_fails_closed_when_non_interactive(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self.make_ws(Path(td))

            result = self.run_generator_raw(ws, "--pick", "--contract", "Vault")

            self.assertEqual(result.returncode, 2)
            self.assertIn("blocked_interactive_pick_requires_tty", result.stdout)
            self.assertIn("--pick-index", result.stdout)

    def test_pick_index_selects_without_interactive_prompt(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self.make_ws(Path(td))
            self.write_impact_contracts(ws)
            out = ws / "submissions" / "staging" / "draft.md"

            result = self.run_generator_raw(
                ws,
                "--pick-index",
                "1",
                "--contract",
                "Vault",
                "--impact-contract-id",
                "impact-contract-vault-theft",
                "--out",
                str(out),
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = out.read_text(encoding="utf-8")
            self.assertIn("Unauthorized vault withdrawal", text)
            self.assertIn("**Impact contract:** `impact-contract-vault-theft`", text)

    def test_missing_proof_artifact_blocks_before_staging_write(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self.make_ws(Path(td))
            self.write_impact_contracts(ws)
            (ws / "poc-tests" / "vault_theft_proof.txt").unlink()
            out = ws / "submissions" / "staging" / "draft.md"

            result = self.run_generator(
                ws,
                "--impact-contract-id",
                "impact-contract-vault-theft",
                "--out",
                str(out),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("proof_artifact=file_exists", result.stdout)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
