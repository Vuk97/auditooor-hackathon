#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-65-CALIBRATION declared in .auditooor/agent_pathspec.json
"""Sanity check: every initial R65 rubric file exists and parses.

The 5 initial rubrics seed the tier-1 catalog tasks. Each must:
- Exist at reference/deepseek_rubrics/<name>.md
- Have a title line starting with `# Rubric`
- Have a `## Scoring Dimensions` section with >=5 dimensions
- Have a `## Paired-Comparison Prompt Template` section for the verifier
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_THIS = Path(__file__).resolve().parent
_REPO = _THIS.parent.parent
_RUBRIC_DIR = _REPO / "reference" / "deepseek_rubrics"
_CALIB_TOOL = _REPO / "tools" / "deepseek-calibrate.py"

# Import calibrator for rubric parsing helper.
_spec = importlib.util.spec_from_file_location("calib_mod", _CALIB_TOOL)
calib_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(calib_mod)

EXPECTED_RUBRICS = [
    ("tok-a-exp.md", "TOK-A", "rationale-mining"),
    ("tok-b-cl.md", "TOK-B-CL", "cross-language-invariant-lift"),
    ("tok-c-ws.md", "TOK-C-WS", "per-workspace-hypothesis-gen"),
    ("tok-d.md", "TOK-D", "adversarial-triager-persona"),
    ("tok-t.md", "TOK-T", "triager-pattern-mining"),
]


class TestRubricsPresent(unittest.TestCase):
    def test_rubric_dir_exists(self):
        self.assertTrue(_RUBRIC_DIR.exists(),
                        f"rubric dir missing: {_RUBRIC_DIR}")

    def test_all_initial_rubrics_exist(self):
        for fname, _, _ in EXPECTED_RUBRICS:
            path = _RUBRIC_DIR / fname
            self.assertTrue(path.exists(), f"missing rubric: {path}")

    def test_all_rubrics_parse_with_dimensions(self):
        for fname, _, _ in EXPECTED_RUBRICS:
            path = _RUBRIC_DIR / fname
            rubric = calib_mod.load_rubric(path)
            self.assertNotIn("_error", rubric,
                             f"rubric parse error for {fname}")
            self.assertGreaterEqual(
                len(rubric["dimensions"]), 5,
                f"rubric {fname} has only {len(rubric['dimensions'])} dimensions "
                f"(expected >=5)",
            )

    def test_all_rubrics_have_paired_comparison_template(self):
        for fname, _, _ in EXPECTED_RUBRICS:
            path = _RUBRIC_DIR / fname
            raw = path.read_text(encoding="utf-8")
            self.assertIn("Paired-Comparison Prompt Template", raw,
                          f"rubric {fname} missing prompt template")
            self.assertIn("flash_scores:", raw,
                          f"rubric {fname} missing flash_scores line")
            self.assertIn("pro_scores:", raw,
                          f"rubric {fname} missing pro_scores line")

    def test_all_task_ids_resolve_to_rubric(self):
        for fname, task_id, task_class in EXPECTED_RUBRICS:
            cls = calib_mod.resolve_task_class(task_id)
            self.assertEqual(cls["rubric"], fname,
                             f"task {task_id} -> rubric {cls['rubric']} != {fname}")
            self.assertEqual(cls["class"], task_class)


if __name__ == "__main__":
    unittest.main()
