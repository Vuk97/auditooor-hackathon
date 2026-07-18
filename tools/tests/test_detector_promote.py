#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-promote.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("detector_promote_under_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["detector_promote_under_test"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class DetectorPromoteImpactGateTests(unittest.TestCase):
    def test_workspace_inventory_adds_impact_gate_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "corpus_detectorization_inventory.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "detector_or_lane": "impact-gated-detector",
                                "impact_contract_summary": {
                                    "required": True,
                                    "status": "missing_contract",
                                    "selected_impact": "",
                                },
                            },
                            {
                                "detector_or_lane": "impact-gated-detector",
                                "impact_contract_summary": {
                                    "required": True,
                                    "status": "mapped",
                                    "selected_impact": "Temporary freezing of user funds",
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            rendered = MOD.render(
                [
                    {
                        "name": "impact-gated-detector",
                        "tp": 5,
                        "fp": 0,
                        "engagements": 1,
                        "fixture": True,
                        "impact_gate": MOD._load_detectorization_gate_summary(ws)["impact-gated-detector"],
                    }
                ],
                [],
                [],
                ws,
            )

            self.assertIn("Impact-contract gate workspace", rendered)
            self.assertIn("blocked 1/2", rendered)


if __name__ == "__main__":
    unittest.main()
