#!/usr/bin/env python3
"""V5-P0-08 / Gap 18 regression tests for `tools/extract-oos.sh`.

Asserts the curated-content-preservation contract introduced for V5-P0-08:

  1. Re-running extract-oos preserves operator-curated content sitting
     ABOVE the AUDITOOOR_AUTO_OOS block.
  2. Re-running extract-oos preserves operator-curated content sitting
     BELOW the AUDITOOOR_AUTO_OOS block.
  3. Running extract-oos against a legacy file (no markers) preserves
     the existing content and appends a fresh auto block at the end.
  4. SEVERITY_CAPS.md gets the same begin/end marker treatment.
  5. The auto block content actually updates between runs (so the
     preserve logic doesn't accidentally freeze the auto bullets).

Hermetic, stdlib-only. No network. Uses subprocess to invoke the bash
script so we exercise the real file end-to-end.
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
SCRIPT = ROOT / "tools" / "extract-oos.sh"


SCOPE_RUN1 = """\
# Test scope

## Out of scope
- Issue A in vendor lib
- Issue B in mock contracts

## Severity caps
- Any issue is at most medium
"""

SCOPE_RUN2 = """\
# Test scope

## Out of scope
- Issue A in vendor lib
- Issue B in mock contracts
- Issue C added later

## Severity caps
- Any issue is at most medium
"""


class ExtractOosPreserveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="extract_oos_test_"))
        if not shutil.which("bash"):
            self.skipTest("bash not on PATH")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self) -> int:
        # Use the worktree's python so PATH stays intact.
        env = os.environ.copy()
        proc = subprocess.run(
            ["bash", str(SCRIPT), str(self.tmp)],
            capture_output=True,
            text=True,
            env=env,
        )
        return proc.returncode

    # --- 1 + 2 ---------------------------------------------------------------
    def test_curated_content_above_and_below_preserved(self) -> None:
        scope = self.tmp / "SCOPE.md"
        scope.write_text(SCOPE_RUN1, encoding="utf-8")

        rc = self._run()
        self.assertEqual(rc, 0)

        oos_path = self.tmp / "OOS_CHECKLIST.md"
        self.assertTrue(oos_path.exists())

        # Insert curated content above and below the auto block.
        body = oos_path.read_text(encoding="utf-8")
        self.assertIn("<!-- AUDITOOOR_AUTO_OOS_BEGIN -->", body)
        self.assertIn("<!-- AUDITOOOR_AUTO_OOS_END -->", body)
        body = body.replace(
            "<!-- AUDITOOOR_AUTO_OOS_BEGIN -->",
            "## Operator notes (curated)\n- Manual entry above\n\n<!-- AUDITOOOR_AUTO_OOS_BEGIN -->",
        )
        body = body.replace(
            "<!-- AUDITOOOR_AUTO_OOS_END -->",
            "<!-- AUDITOOOR_AUTO_OOS_END -->\n\n## Below-block operator notes\n- Manual entry below\n",
        )
        oos_path.write_text(body, encoding="utf-8")

        # Re-run with an updated SCOPE.
        scope.write_text(SCOPE_RUN2, encoding="utf-8")
        rc = self._run()
        self.assertEqual(rc, 0)

        final = oos_path.read_text(encoding="utf-8")
        # Curated content above and below survived.
        self.assertIn("Manual entry above", final)
        self.assertIn("Manual entry below", final)
        # Auto block updated to include the new bullet.
        self.assertIn("Issue C added later", final)

    # --- 3 ------------------------------------------------------------------
    def test_legacy_file_preserved_and_marker_appended(self) -> None:
        scope = self.tmp / "SCOPE.md"
        scope.write_text(SCOPE_RUN1, encoding="utf-8")

        # Pre-create a legacy OOS_CHECKLIST.md with no markers.
        legacy = self.tmp / "OOS_CHECKLIST.md"
        legacy.write_text(
            "# Out-of-scope checklist — auto-extracted from SCOPE.md\n\n"
            "Legacy curated note from before V5-P0-08.\n\n"
            "- [ ] **OOS-1:** Manual entry from old run\n",
            encoding="utf-8",
        )

        rc = self._run()
        self.assertEqual(rc, 0)

        body = legacy.read_text(encoding="utf-8")
        # Legacy content preserved verbatim.
        self.assertIn("Legacy curated note from before V5-P0-08.", body)
        self.assertIn("Manual entry from old run", body)
        # Markers are now present at the end so a second run is safe.
        self.assertIn("<!-- AUDITOOOR_AUTO_OOS_BEGIN -->", body)
        self.assertIn("<!-- AUDITOOOR_AUTO_OOS_END -->", body)

        # Round-trip: a second run on the now-marked file does NOT touch
        # the legacy curated content.
        rc = self._run()
        self.assertEqual(rc, 0)
        round_trip = legacy.read_text(encoding="utf-8")
        self.assertIn("Legacy curated note from before V5-P0-08.", round_trip)
        self.assertIn("Manual entry from old run", round_trip)

    # --- 4 ------------------------------------------------------------------
    def test_severity_caps_uses_same_marker_treatment(self) -> None:
        scope = self.tmp / "SCOPE.md"
        scope.write_text(SCOPE_RUN1, encoding="utf-8")
        rc = self._run()
        self.assertEqual(rc, 0)

        caps = (self.tmp / "SEVERITY_CAPS.md").read_text(encoding="utf-8")
        self.assertIn("<!-- AUDITOOOR_AUTO_CAPS_BEGIN -->", caps)
        self.assertIn("<!-- AUDITOOOR_AUTO_CAPS_END -->", caps)
        self.assertIn("CAP-1:", caps)

    # --- 5 ------------------------------------------------------------------
    def test_auto_block_actually_updates_between_runs(self) -> None:
        scope = self.tmp / "SCOPE.md"
        scope.write_text(SCOPE_RUN1, encoding="utf-8")
        self.assertEqual(self._run(), 0)
        oos1 = (self.tmp / "OOS_CHECKLIST.md").read_text(encoding="utf-8")

        scope.write_text(SCOPE_RUN2, encoding="utf-8")
        self.assertEqual(self._run(), 0)
        oos2 = (self.tmp / "OOS_CHECKLIST.md").read_text(encoding="utf-8")

        self.assertNotIn("Issue C added later", oos1)
        self.assertIn("Issue C added later", oos2)


if __name__ == "__main__":
    unittest.main()
