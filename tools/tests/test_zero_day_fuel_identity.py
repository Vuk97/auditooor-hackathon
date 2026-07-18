"""Focused tests for explicit, receipt-bound zero-day fuel linkage."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CORPUS = load("corpus_driven_hunt_fuel_test", "corpus-driven-hunt.py")
NOVELTY = load("novelty_gate_fuel_test", "novelty-gate-flywheel.py")
FREEZE = load("zero_day_freeze_fuel_test", "zero-day-freeze-compiler.py")


class ZeroDayFuelIdentityTest(unittest.TestCase):
    def identity_map(self, directory: Path, *keys: str) -> Path:
        path = directory / "identity-map.jsonl"
        rows = [
            {
                "identity_key": key,
                "obligation_id": "zdo_" + ("a" * 64),
                "revision_id": "zdr_" + (chr(ord("b") + index) * 64),
                "source_refs": ["src/Vault.sol:9"],
                "asset_invariant": "assets conserved",
                "impact_class": "loss of funds",
            }
            for index, key in enumerate(keys)
        ]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def test_corpus_emits_canonical_explicitly_linked_fuel(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            key = "corpus_hypothesis:INV-1:withdraw"
            identity_map = self.identity_map(directory, key)
            rows = CORPUS.emit_zero_day_fuel({
                "hypotheses": [{"invariant_id": "INV-1", "function": "withdraw", "hypothesis": "missing debit"}],
                "hacker_questions": [],
            }, identity_map, strict=True)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["schema"], FREEZE.FUEL_SCHEMA)
            self.assertEqual(row["obligation_id"], "zdo_" + ("a" * 64))
            self.assertEqual(row["revision_id"], "zdr_" + ("b" * 64))
            self.assertEqual(row["fuel_id"], "zdf_" + FREEZE.digest({k: v for k, v in row.items() if k != "fuel_id"}))
            linked, all_rows = FREEZE.link_fuel_rows({
                "step-4c": [{**row, "_expected_fuel_kind": "corpus_hypothesis"}],
            }, [{
                "obligation_id": row["obligation_id"],
                "revision_id": row["revision_id"],
                "source_refs": ["src/Vault.sol:9"],
                "logical": {
                    "asset_invariant": "assets conserved",
                    "impact_class": "loss of funds",
                },
            }])
            self.assertEqual(len(all_rows), 1)
            self.assertEqual(linked[(row["obligation_id"], row["revision_id"])][0]["fuel_id"], row["fuel_id"])

    def test_unlinked_applicable_rows_fail_strict_for_both_producers(self):
        with self.assertRaisesRegex(ValueError, "missing_identity_map_for_applicable_fuel"):
            CORPUS.emit_zero_day_fuel({
                "hypotheses": [{"invariant_id": "INV-1", "function": "withdraw", "hypothesis": "missing debit"}],
                "hacker_questions": [],
            }, None, strict=True)
        with self.assertRaisesRegex(ValueError, "missing_identity_map_for_applicable_fuel"):
            NOVELTY.emit_zero_day_fuel(
                [{"invariant_id": "VCIS-1", "statement": "balance mismatch"}],
                [{"label": "NOVEL"}], None, strict=True)

    def test_novelty_skips_unmapped_rows_only_outside_strict_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            rows = NOVELTY.emit_zero_day_fuel(
                [{"invariant_id": "VCIS-1", "statement": "balance mismatch"}],
                [{"label": "NOVEL"}],
                self.identity_map(directory, "novelty_flywheel:OTHER"), strict=False)
            self.assertEqual(rows, [])
            with self.assertRaisesRegex(ValueError, "unlinked_applicable_fuel:novelty_flywheel:VCIS-1"):
                NOVELTY.emit_zero_day_fuel(
                    [{"invariant_id": "VCIS-1", "statement": "balance mismatch"}],
                    [{"label": "NOVEL"}],
                    self.identity_map(directory, "novelty_flywheel:OTHER"), strict=True)


if __name__ == "__main__":
    unittest.main()
