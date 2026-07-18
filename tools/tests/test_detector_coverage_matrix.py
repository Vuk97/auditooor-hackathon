#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-coverage-matrix.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("detector_coverage_matrix_under_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["detector_coverage_matrix_under_test"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class DetectorCoverageMatrixImpactGateTests(unittest.TestCase):
    def test_workspace_gate_summary_renders_blocked_and_mapped_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "corpus_detectorization_inventory.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "detector_or_lane": "base-rust-swival-shape-scan",
                                "impact_contract_summary": {
                                    "required": True,
                                    "status": "mapped",
                                    "selected_impact": "Temporary freezing of user funds",
                                },
                            },
                            {
                                "detector_or_lane": "base-rust-swival-shape-scan",
                                "impact_contract_summary": {
                                    "required": True,
                                    "status": "missing_contract",
                                    "selected_impact": "",
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (ws / "scanner_promotion_advisories.json").write_text(
                json.dumps(
                    {
                        "advisories": [
                            {
                                "id": "scanner-promo-1",
                                "impact_contract_summary": {
                                    "required": True,
                                    "status": "missing_contract",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            rendered = MOD.render(
                [("auth", ["auth"])],
                {"auth": 1},
                {"auth": 1},
                {"auth": {"keywords": ["auth"], "applies_to": "both"}},
                {},
                MOD.load_detectorization_gate_summary(ws),
            )

            self.assertIn("## Detectorization Gate Summary", rendered)
            self.assertIn("Scanner promotion advisories: `1`", rendered)
            self.assertIn("`base-rust-swival-shape-scan` | 2 | 1 | 1", rendered)


if __name__ == "__main__":
    unittest.main()
