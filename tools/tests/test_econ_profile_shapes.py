#!/usr/bin/env python3
"""V5-P0-10 / Gap 20 regression tests for the econ-profile path-shape contract.

`tools/audit-deep.sh --profile econ` must accept three input shapes for
the hypotheses file:

  1. ``<ws>/economic_hypotheses/<basename>.md``  (directory + glob)
  2. ``<ws>/economic_hypotheses.md``             (singular file)
  3. (missing)                                   -> INDETERMINATE report.

This test exercises the wrapper end-to-end so we are also covering the
audit-deep.sh shell logic that selects the input path.

Hermetic, stdlib-only.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools" / "audit-deep.sh"


SAMPLE_HYPOS = """\
# Economic Hypotheses for sample.sol

## 1. Oracle calls (1 hit(s))

### Hypotheses
- [ ] Repeats in cycle?
- [ ] Loop on the same block?
"""


def _run(ws: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["AUDIT_DEEP_DRY_RUN"] = "0"
    return subprocess.run(
        ["bash", str(WRAPPER), "--profile", "econ", str(ws)],
        capture_output=True,
        text=True,
        env=env,
    )


class EconProfileShapesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="econ_shape_test_"))
        if not shutil.which("bash"):
            self.skipTest("bash not on PATH")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- shape 1: directory + glob -----------------------------------------
    def test_directory_shape_accepted(self) -> None:
        d = self.tmp / "economic_hypotheses"
        d.mkdir()
        (d / "sample.md").write_text(SAMPLE_HYPOS, encoding="utf-8")

        proc = _run(self.tmp)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        canonical = self.tmp / ".audit_logs" / "audit_deep_report.md"
        self.assertTrue(canonical.exists())
        body = canonical.read_text(encoding="utf-8")
        self.assertIn("input shape: directory", body)
        # Modeler artifacts present.
        self.assertTrue((self.tmp / ".audit_logs" / "actors.json").exists())
        self.assertTrue((self.tmp / ".audit_logs" / "econ_deep_report.md").exists())

    # --- shape 2: singular file ---------------------------------------------
    def test_singular_file_shape_accepted(self) -> None:
        (self.tmp / "economic_hypotheses.md").write_text(SAMPLE_HYPOS, encoding="utf-8")

        proc = _run(self.tmp)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        canonical = self.tmp / ".audit_logs" / "audit_deep_report.md"
        body = canonical.read_text(encoding="utf-8")
        self.assertIn("input shape: singular_file", body)
        # Modeler still emits artifacts.
        self.assertTrue((self.tmp / ".audit_logs" / "actors.json").exists())
        self.assertTrue((self.tmp / ".audit_logs" / "econ_deep_report.md").exists())

    # --- shape 3: missing ---------------------------------------------------
    def test_missing_shape_does_not_hard_fail(self) -> None:
        proc = _run(self.tmp)
        # Wrapper still exits 0 — modeler emits an INDETERMINATE report.
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        # Wrapper warns on stderr so the operator sees the missing input.
        self.assertIn("no hypotheses input found", proc.stderr)
        canonical = self.tmp / ".audit_logs" / "audit_deep_report.md"
        body = canonical.read_text(encoding="utf-8")
        self.assertIn("input shape: missing", body)
        # The modeler-level INDETERMINATE flows through to the econ_deep_report.
        econ_report = self.tmp / ".audit_logs" / "econ_deep_report.md"
        self.assertTrue(econ_report.exists())
        self.assertIn("INDETERMINATE", econ_report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
