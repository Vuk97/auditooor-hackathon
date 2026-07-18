#!/usr/bin/env python3
"""Regression: global-chain-template-library-build refuses to overwrite a non-trivial
existing library with <50% as many templates (safety guard), and --max-incidents 0 means
NO cap (not an empty load).

2026-07-07: the chain-template rebuild is currently broken because invariants_pilot_audited
.jsonl was re-materialized as RAW per-fn hunt fuel (source_finding_ids, no causal-linkage
schema), so every row is source-unbacked -> 0 composable tuples. Before this guard, a rebuild
SILENTLY WIPED the 2,653-template library to 0. The guard makes that a hard refuse."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "global-chain-template-library-build.py"


class T(unittest.TestCase):
    def test_refuses_to_shrink_existing_library(self):
        # a pre-existing library with 200 templates
        out = Path(tempfile.mkdtemp()) / "lib.jsonl"
        out.write_text("\n".join('{"chain_template_id":"x%d"}' % i for i in range(200)) + "\n")
        # the real corpus currently composes to 0 (raw fuel input) -> guard must refuse
        r = subprocess.run(
            [sys.executable, str(_TOOL), "--output", str(out), "--max-incidents", "0"],
            capture_output=True, text=True, cwd=str(_TOOL.parent.parent), timeout=300)
        self.assertEqual(r.returncode, 2, f"expected refuse rc=2, got {r.returncode}: {r.stderr[-400:]}")
        self.assertIn("REFUSING", r.stderr)
        # library must be UNTOUCHED (still 200 lines, not wiped)
        self.assertEqual(sum(1 for l in out.read_text().splitlines() if l.strip()), 200)

    def test_allow_shrink_overrides(self):
        out = Path(tempfile.mkdtemp()) / "lib.jsonl"
        out.write_text("\n".join('{"chain_template_id":"x%d"}' % i for i in range(200)) + "\n")
        r = subprocess.run(
            [sys.executable, str(_TOOL), "--output", str(out), "--max-incidents", "0",
             "--allow-shrink"],
            capture_output=True, text=True, cwd=str(_TOOL.parent.parent), timeout=300)
        # with the override it proceeds (writes the 0/low set); rc != 2 (not the refuse path)
        self.assertNotEqual(r.returncode, 2, f"allow-shrink must bypass refuse: {r.stderr[-300:]}")


if __name__ == "__main__":
    unittest.main()
