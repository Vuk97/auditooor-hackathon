#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "solodit-taxonomy-triage.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("solodit_taxonomy_triage_under_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class SoloditTaxonomyTriageTests(unittest.TestCase):
    def test_build_worklist_keeps_only_uncategorized_blindspots(self) -> None:
        rows = [
            {
                "finding_id": "F-1",
                "title": "Unknown accounting edge case",
                "severity": "HIGH",
                "bug_class": "uncategorized",
                "status": "analyzed",
                "is_blindspot": True,
                "analysis_mode": "keyword-based",
                "signals": ["accounting", "rounding"],
                "github_ref": {
                    "repo": "org/project",
                    "commit": "1234567890abcdef",
                    "filepath": "src/Vault.sol",
                },
                "solodit_url": "https://solodit.example/issues/F-1",
            },
            {
                "finding_id": "F-2",
                "title": "Already categorized",
                "bug_class": "access-control",
                "status": "analyzed",
                "is_blindspot": True,
            },
            {
                "finding_id": "F-3",
                "title": "Uncategorized but not a blindspot row",
                "bug_class": "uncategorized",
                "status": "analyzed",
                "is_blindspot": False,
            },
            {
                "finding_id": "F-4",
                "title": "Skipped language row",
                "bug_class": "uncategorized",
                "status": "skipped_language",
                "is_blindspot": True,
            },
        ]

        payload = MOD.build_worklist(rows, Path("reports/detector_gap.json"))

        self.assertTrue(payload["advisory_only"])
        self.assertFalse(payload["promotion_authority"])
        self.assertIn("Does not assess detector coverage.", payload["limits"])
        self.assertIn("Does not assess submission readiness.", payload["limits"])
        self.assertEqual(payload["input_row_count"], 4)
        self.assertEqual(payload["uncategorized_count"], 1)
        self.assertEqual(payload["rows"][0]["finding_id"], "F-1")
        self.assertEqual(payload["rows"][0]["title"], "Unknown accounting edge case")
        self.assertIn("accounting", payload["rows"][0]["signals"])
        self.assertIn("severity: HIGH", payload["rows"][0]["signals"])
        self.assertIn(
            "github_ref: org/project/src/Vault.sol@12345678",
            payload["rows"][0]["signals"],
        )
        self.assertEqual(
            payload["rows"][0]["next_action"],
            "assign_concrete_bug_class_before_detector_work",
        )

    def test_load_accepts_object_with_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "gap.json"
            source.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "id": "65131",
                                "name": "Synthetic title",
                                "classification": "uncategorized",
                                "is_blindspot": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_gap_rows(source)
            payload = MOD.build_worklist(rows, source)

        self.assertEqual(payload["uncategorized_count"], 1)
        self.assertEqual(payload["rows"][0]["finding_id"], "65131")
        self.assertEqual(payload["rows"][0]["title"], "Synthetic title")

    def test_markdown_render_includes_disclaimers_and_escapes_pipes(self) -> None:
        payload = {
            "source": "reports/detector_gap.json",
            "uncategorized_count": 1,
            "rows": [
                {
                    "finding_id": "F-1",
                    "title": "Price | share mismatch",
                    "signals": ["severity: HIGH", "token | vault"],
                    "next_action": "assign_concrete_bug_class_before_detector_work",
                }
            ],
        }

        rendered = MOD.render_markdown(payload)

        self.assertIn("Does not assess detector coverage.", rendered)
        self.assertIn("Does not assess submission readiness.", rendered)
        self.assertIn("Price \\| share mismatch", rendered)
        self.assertIn("token \\| vault", rendered)

    def test_main_fails_closed_on_missing_or_malformed_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.json"
            out = root / "out.json"
            self.assertEqual(MOD.main([str(missing), "--output", str(out)]), 2)
            self.assertFalse(out.exists())

            malformed = root / "bad.json"
            malformed.write_text('{"not_rows": []}', encoding="utf-8")
            self.assertEqual(MOD.main([str(malformed), "--output", str(out)]), 2)
            self.assertFalse(out.exists())

    def test_main_writes_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "gap.json"
            out = root / "triage.json"
            source.write_text(
                json.dumps(
                    [
                        {
                            "finding_id": "F-1",
                            "title": "Needs taxonomy",
                            "bug_class": "uncategorized",
                            "status": "analyzed",
                            "is_blindspot": True,
                        }
                    ]
                ),
                encoding="utf-8",
            )

            rc = MOD.main([str(source), "--output", str(out)])

            self.assertEqual(rc, 0)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["schema"], MOD.SCHEMA)
            self.assertEqual(saved["uncategorized_count"], 1)
            self.assertEqual(saved["rows"][0]["finding_id"], "F-1")


if __name__ == "__main__":
    unittest.main()
