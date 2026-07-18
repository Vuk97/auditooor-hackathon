#!/usr/bin/env python3
"""Tests for the advisory corpus-detectorization engage stage."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
ENGAGE = ROOT / "tools" / "engage.py"


def _load_engage():
    tools_dir = str(ENGAGE.parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage_corpus_detectorization_test_subject", ENGAGE)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _args():
    return SimpleNamespace(quiet=True)


class CorpusDetectorizationStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_stage_registered_between_closeout_and_campaign(self) -> None:
        self.assertIn("corpus-detectorization", self.mod.STAGES)
        names = [name for name, _desc, _art in self.mod.STAGE_TABLE]
        self.assertIn("corpus-detectorization", names)
        self.assertLess(
            names.index("post-audit-review"),
            names.index("corpus-detectorization"),
        )
        self.assertLess(
            names.index("corpus-detectorization"),
            names.index("campaign-source-mine"),
        )
        self.assertIn("corpus-detectorization", self.mod.SUMMARY_ARTIFACT_PATTERNS)

    def test_stage_writes_impact_neutral_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            swival_dir = ws / "critical_hunt" / "wave6_swival_mining"
            swival_dir.mkdir(parents=True)
            (swival_dir / "swival_findings_normalized.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "id": "SWIVAL-STDLIB-001",
                                "title": "snappy decompress_vec decode bomb",
                                "source_path": "library/std/src/codec/snappy.rs",
                                "family": "unbounded decompress",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            status = self.mod.stage_corpus_detectorization(ws, _args())
            self.assertEqual(status, "SUCCESS")
            inventory = ws / ".auditooor" / "corpus_detectorization_inventory.json"
            self.assertTrue(inventory.is_file())
            payload = json.loads(inventory.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["row_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["corpus"], "swival_rust")
            self.assertEqual(row["terminal_state"], "detectorized")
            self.assertEqual(row["detector_or_lane"], "rust-decode-bomb-scan")
            self.assertEqual(row["selected_impact"], "")
            self.assertEqual(row["severity"], "none")
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(row["submit_status"], "NOT_SUBMIT_READY")
            self.assertTrue(row["impact_contract_required"])


if __name__ == "__main__":
    unittest.main()
