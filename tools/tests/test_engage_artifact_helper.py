from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ENGAGE = REPO / "tools" / "engage.py"


class EngageArtifactHelperTest(unittest.TestCase):
    def test_shared_scan_paths_have_artifact_helper(self) -> None:
        src = ENGAGE.read_text()
        self.assertIn("def _artifact_for(", src)
        self.assertRegex(src, r"_artifact_for\(\"scan\"\)")
        self.assertNotRegex(
            src,
            r"NameError: name '_artifact_for'",
            "test fixture should not encode the runtime failure text",
        )

    def test_artifact_helper_delegates_to_summary_resolver(self) -> None:
        src = ENGAGE.read_text()
        helper = re.search(
            r"def _artifact_for\(name: str\).*?return _summary_artifact_for\(name, \"SUCCESS\"\)",
            src,
            re.S,
        )
        self.assertIsNotNone(helper)


if __name__ == "__main__":
    unittest.main()
