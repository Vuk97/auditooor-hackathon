#!/usr/bin/env python3
"""Promotion-gate regressions for brief candidate impact-contract preflight."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "agent-output-synthesizer.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("agent_output_synthesizer", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SYNTH = _load_module()


def _brief(include_impact_contract: bool) -> str:
    lines = [
        "# Agent Brief - sample - Vault",
        "**Contract:** Vault",
        "**Matched mining brief:** `swarm/mining_briefs/vault_A-RACE.md`",
        "",
        "### A-RACE \u2014 HIGH",
        "**Title:** Settlement race on delayed accounting",
        "",
        "## Exploit Goal",
        "Replay `settle()` before `checkpoint()` updates balances.",
        "",
        "## Live Check Evidence",
        "- `pass` row shows storage drift at pinned block",
        "",
        "## Expected Paired Live Proof",
        "- `ROW-1` (Vault) \u2014 pinned pass",
        "",
    ]
    if include_impact_contract:
        lines.extend(
            [
                "## Impact Contract",
                "- Victim: Vault LPs",
                "- Source proof: src/Vault.sol:120-166",
                "- Harness scaffold: poc-tests/VaultRacePlan.t.sol",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


class AgentOutputSynthesizerImpactContractTests(unittest.TestCase):
    def test_missing_contract_demotes_candidate_to_poc_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            brief = Path(tmp) / "brief_a.md"
            brief.write_text(_brief(include_impact_contract=False), encoding="utf-8")
            candidates = SYNTH.extract_candidate_plans_from_brief(brief)
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertEqual(candidate["kind"], "poc_plan")
            self.assertEqual(
                candidate["impact_contract"]["decision"]["code"],
                "impact-contract-missing",
            )
            self.assertIn("Impact Contract", candidate["recommended_next_step"])
            self.assertEqual(candidate["evidence_class"], "generated_hypothesis")

    def test_explicit_contract_promotes_candidate_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            brief = Path(tmp) / "brief_b.md"
            brief.write_text(_brief(include_impact_contract=True), encoding="utf-8")
            candidates = SYNTH.extract_candidate_plans_from_brief(brief)
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertEqual(candidate["kind"], "candidate_finding")
            self.assertTrue(candidate["impact_contract"]["impact_contract"]["explicit"])
            self.assertEqual(
                candidate["impact_contract"]["decision"]["code"],
                "impact-contract-explicit",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
