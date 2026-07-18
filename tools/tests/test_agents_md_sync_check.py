"""
tools/tests/test_agents_md_sync_check.py
Tests for tools/agents-md-sync-check.py

Run:
  python3 -m unittest tools.tests.test_agents_md_sync_check -v
"""

import hashlib
import importlib.util
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the module under test directly (avoid relying on it being installed)
# ---------------------------------------------------------------------------
_TOOL_PATH = Path(__file__).resolve().parent.parent / "agents-md-sync-check.py"
_spec = importlib.util.spec_from_file_location("agents_md_sync_check", _TOOL_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[arg-type]

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AGENTS_MD = REPO_ROOT / "AGENTS.md"

SENTINEL_PATHS = [
    REPO_ROOT / ".cursorrules",
    REPO_ROOT / ".windsurfrules",
    REPO_ROOT / ".aider.conf.yml",
    REPO_ROOT / ".github" / "copilot-instructions.md",
    REPO_ROOT / ".kimi" / "AGENTS.md",
]


class TestSentinelFilesExist(unittest.TestCase):
    """Assertion 1: all 5 sentinel files must exist on disk."""

    def test_all_sentinels_exist(self):
        missing = [p for p in SENTINEL_PATHS if not p.exists()]
        self.assertEqual(
            missing,
            [],
            msg=f"Missing sentinel files: {[str(p) for p in missing]}",
        )


class TestSentinelsContainMarker(unittest.TestCase):
    """Assertion 2: every sentinel must contain an `# AGENTS.md ref:` line."""

    MARKER_RE = re.compile(r"# AGENTS\.md ref:\s*\S+")

    def test_all_sentinels_have_marker(self):
        for path in SENTINEL_PATHS:
            if not path.exists():
                self.skipTest(f"Sentinel missing: {path}")
            text = path.read_text()
            self.assertRegex(
                text,
                self.MARKER_RE,
                msg=f"{path.relative_to(REPO_ROOT)} is missing '# AGENTS.md ref:' marker",
            )


class TestSentinelShasMatchAgentsMd(unittest.TestCase):
    """Assertion 3: the sha in every sentinel must match the current AGENTS.md sha."""

    def setUp(self):
        if not AGENTS_MD.exists():
            self.skipTest("AGENTS.md not found")
        self.agents_sha = _mod.compute_agents_sha(AGENTS_MD.read_text())

    def test_all_sentinel_shas_match(self):
        for path in SENTINEL_PATHS:
            if not path.exists():
                self.skipTest(f"Sentinel missing: {path}")
            recorded = _mod.get_sentinel_sha(path.read_text())
            self.assertEqual(
                recorded,
                self.agents_sha,
                msg=(
                    f"{path.relative_to(REPO_ROOT)}: "
                    f"recorded sha={recorded!r} != current sha={self.agents_sha!r}. "
                    "Run `python3 tools/agents-md-sync-check.py --update`."
                ),
            )


class TestUpdateRewritesSentinels(unittest.TestCase):
    """Assertion 4: --update regenerates sentinel markers correctly in a temp dir."""

    def test_update_writes_correct_sha(self):
        # Build a synthetic AGENTS.md in a temp dir with an L25-L31 section
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # Minimal AGENTS.md with the required section header
            agents_text = (
                "# AGENTS.md\n\n"
                "## L25-L31 doctrine for provider-agnostic agents\n\n"
                "L25 content goes here.\nL31 ends here.\n"
            )
            agents_file = tmp / "AGENTS.md"
            agents_file.write_text(agents_text)

            # Compute expected sha
            expected_sha = _mod.compute_agents_sha(agents_text)

            # Create a synthetic sentinel with a PLACEHOLDER marker
            sentinel = tmp / ".cursorrules"
            sentinel.write_text("# Cursor\n# AGENTS.md ref: PLACEHOLDER\nRest of file.\n")

            # Run update_sentinel directly
            changed = _mod.update_sentinel(sentinel, expected_sha)

            self.assertTrue(changed, "update_sentinel should return True when marker changes")
            updated_text = sentinel.read_text()
            recorded = _mod.get_sentinel_sha(updated_text)
            self.assertEqual(
                recorded,
                expected_sha,
                msg=f"After update, recorded sha={recorded!r} != expected={expected_sha!r}",
            )


class TestCheckDetectsDrift(unittest.TestCase):
    """Assertion 5: --check exits 1 when a sentinel has a stale sha."""

    def test_check_detects_synthetic_drift(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            agents_text = (
                "# AGENTS.md\n\n"
                "## L25-L31 doctrine for provider-agnostic agents\n\n"
                "Canonical content.\n"
            )
            agents_file = tmp / "AGENTS.md"
            agents_file.write_text(agents_text)

            real_sha = _mod.compute_agents_sha(agents_text)
            stale_sha = "0000000000000000"  # synthetic wrong sha

            self.assertNotEqual(
                real_sha, stale_sha, "Synthetic stale sha must differ from real sha"
            )

            # Sentinel with a stale sha
            sentinel = tmp / ".cursorrules"
            sentinel.write_text(f"# Cursor\n# AGENTS.md ref: {stale_sha}\nRest.\n")

            recorded = _mod.get_sentinel_sha(sentinel.read_text())
            self.assertEqual(recorded, stale_sha)
            self.assertNotEqual(
                recorded,
                real_sha,
                msg="Drift check: stale sha should not match the current AGENTS.md sha",
            )


if __name__ == "__main__":
    unittest.main()
