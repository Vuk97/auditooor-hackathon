from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "target-saturation-score.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("target_saturation_score", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["target_saturation_score"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _row(payload: dict, module: str) -> dict:
    rows = {row["module"]: row for row in payload["modules"]}
    return rows[module]


class TargetSaturationScoreTests(unittest.TestCase):
    def test_high_saturation_core_module_gets_state_divergence_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "morpho"
            (ws / "prior_audits").mkdir(parents=True)
            (ws / "scope.json").write_text(
                json.dumps({"in_scope_paths": ["src/core/MorphoBlue.sol"]}),
                encoding="utf-8",
            )
            (ws / "prior_audits" / "certora_morpho_blue.md").write_text(
                "Certora security review of MorphoBlue.\n"
                "MorphoBlue accounting, MorphoBlue liquidation, MorphoBlue shares.\n",
                encoding="utf-8",
            )
            (ws / "prior_audits" / "chainsecurity_morpho_blue.md").write_text(
                "ChainSecurity audit: MorphoBlue market core. MorphoBlue was reviewed.\n",
                encoding="utf-8",
            )

            payload = tool.build_payload(ws)
            row = _row(payload, "MorphoBlue")

            self.assertGreaterEqual(row["saturation_score"], 70)
            self.assertEqual(row["firm_count"], 2)
            self.assertEqual(row["recommended_action"], "state_divergence_only")
            self.assertEqual(payload["summary"]["high_saturation_modules"], 1)

    def test_low_saturation_active_module_gets_cold_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "nuva"
            (ws / "prior_audits").mkdir(parents=True)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n- Contract: EdgeAdapter\n- Contract: CoreVault\n",
                encoding="utf-8",
            )
            (ws / "prior_audits" / "zellic_core.md").write_text(
                "Zellic audit covered CoreVault and accounting.\n",
                encoding="utf-8",
            )

            payload = tool.build_payload(ws)
            edge = _row(payload, "EdgeAdapter")

            self.assertEqual(edge["audit_mentions"], 0)
            self.assertEqual(edge["saturation_score"], 0)
            self.assertEqual(edge["recommended_action"], "cold_read")

    def test_contract_name_collision_does_not_count_substring_mentions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "collision"
            (ws / "prior_audits").mkdir(parents=True)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n- Contract: Vault\n- Contract: MegaVault\n",
                encoding="utf-8",
            )
            (ws / "prior_audits" / "halborn_megavault.md").write_text(
                "Halborn audit focused on MegaVault. MegaVault withdrawal logic was covered.\n",
                encoding="utf-8",
            )

            payload = tool.build_payload(ws)
            vault = _row(payload, "Vault")
            mega = _row(payload, "MegaVault")

            self.assertEqual(vault["audit_mentions"], 0)
            self.assertEqual(vault["recommended_action"], "cold_read")
            self.assertGreaterEqual(mega["audit_mentions"], 2)
            self.assertTrue(mega["evidence_paths"])

    def test_missing_prior_audits_writes_artifact_with_insufficient_data(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fresh"
            ws.mkdir(parents=True)
            (ws / "README.md").write_text(
                "Fresh target. In scope: `FreshFactory.sol` and `FreshAdapter.sol`.\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            out = ws / ".auditooor" / "target_saturation.json"
            self.assertTrue(out.is_file())
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertFalse(payload["summary"]["prior_audits_present"])
            self.assertGreaterEqual(payload["summary"]["module_count"], 2)
            self.assertEqual(
                {row["recommended_action"] for row in payload["modules"]},
                {"insufficient_data"},
            )


if __name__ == "__main__":
    unittest.main()
