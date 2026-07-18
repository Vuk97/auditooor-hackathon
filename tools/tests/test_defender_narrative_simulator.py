from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "defender-narrative-simulator.py"

_spec = importlib.util.spec_from_file_location("defender_narrative_simulator", TOOL)
_sim = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec.loader is not None
sys.modules[_spec.name] = _sim
_spec.loader.exec_module(_sim)


class DefenderNarrativeSimulatorSchemaTest(unittest.TestCase):
    def _simulate_json(self, payload: dict, *, generated_at: str = "2026-05-24T00:00:00Z") -> dict:
        loaded = _sim._load_from_text(json.dumps(payload), "packet.json", 50_000, force_json=True)
        return _sim.build_simulation(loaded, generated_at=generated_at)

    def test_schema_contains_required_archetypes_and_fields(self) -> None:
        packet = self._simulate_json(
            {
                "title": "Oracle adapter accepts stale external price",
                "severity": "High",
                "description": (
                    "The finding mentions admin pause, by design wording, user error, "
                    "no fund loss, duplicate prior art, and no PoC yet."
                ),
                "impact": "External dependency oracle behavior reaches src/OracleAdapter.sol:42.",
                "source_refs": ["src/OracleAdapter.sol:42", "test/OracleAdapter.t.sol:91"],
            }
        )

        self.assertEqual(packet["schema"], "auditooor.defender_narrative_simulator.v1")
        self.assertEqual(packet["mode"], "deterministic_local_rules")
        self.assertTrue(packet["advisory_only"])
        self.assertFalse(packet["provider_backed"])
        self.assertFalse(packet["submission_clearance"])
        narratives = packet["defender_narratives"]
        self.assertLessEqual(len(narratives), 7)
        self.assertEqual(
            {row["archetype"] for row in narratives},
            {
                "intended-design",
                "user-error",
                "trusted-admin",
                "insufficient-impact",
                "duplicate/prior-art",
                "external dependency",
                "missing PoC",
            },
        )
        for row in narratives:
            for key in (
                "likely_objection",
                "evidence_gap",
                "rebuttal_strategy",
                "kill_condition",
                "source_refs",
            ):
                self.assertIn(key, row)
                self.assertTrue(row[key])
            self.assertIsInstance(row["rebuttal_checklist"], list)
            self.assertLessEqual(len(row["rebuttal_checklist"]), 4)
            self.assertLessEqual(len(row["source_refs"]), 8)

    def test_deterministic_ranking_is_stable(self) -> None:
        text = """# User supplied txid mismatch

Severity: High

The defender may call this user error because the receiver must verify a
caller supplied txid and the victim should verify the counterparty state.
"""
        loaded = _sim._load_from_text(text, "draft.md", 50_000)
        first = _sim.build_simulation(loaded, generated_at="2026-05-24T00:00:00Z")
        second = _sim.build_simulation(loaded, generated_at="2026-05-24T00:00:00Z")

        self.assertEqual(first, second)
        self.assertEqual(first["defender_narratives"][0]["archetype"], "user-error")
        scores = [row["score"] for row in first["defender_narratives"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_advisory_only_language_does_not_claim_verdict_or_clearance(self) -> None:
        packet = self._simulate_json(
            {
                "title": "Missing validation",
                "severity": "Critical",
                "description": "No PoC yet; proof pending for a missing check.",
            }
        )

        boundary = packet["language_boundary"].lower()
        summary = packet["summary"].lower()
        self.assertIn("advisory", boundary)
        self.assertIn("not a triager verdict", boundary)
        self.assertIn("not submission clearance", boundary)
        self.assertIn("not a verdict", summary)
        self.assertIsNone(packet["predicted_triager_verdict"])
        for row in packet["defender_narratives"]:
            self.assertIn("may argue", row["likely_objection"].lower())
            self.assertNotIn("will reject", row["likely_objection"].lower())


class DefenderNarrativeSimulatorCliTest(unittest.TestCase):
    def test_cli_accepts_text_file_and_emits_bounded_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                "# Finding\n\nSeverity: High\n\nNo PoC yet; external oracle dependency.",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--max-narratives", "3"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["schema"], "auditooor.defender_narrative_simulator.v1")
        self.assertEqual(packet["input"]["format"], "text")
        self.assertEqual(len(packet["defender_narratives"]), 3)
        self.assertEqual(packet["bounds"]["max_narratives"], 3)


if __name__ == "__main__":
    unittest.main()
