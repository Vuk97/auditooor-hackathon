"""
Tests for the erc-2771-msgSender-forgery detector fix (wave-14 FP fix).

Root cause of FP: old pattern '_msgSender\\s*\\(|trustedForwarder|ERC2771' fired on
any contract calling _msgSender(), including plain-Context contracts where
_msgSender() is just msg.sender (no trusted-forwarder calldata-suffix decode).

Fix: pattern changed to 'ERC2771Context|isTrustedForwarder\\s*\\(|is\\s+ERC2771'
which requires the ERC2771Context inheritance or isTrustedForwarder presence
as a precondition, eliminating plain-Context FPs.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APPLY_QUERIES = ROOT / "tools" / "apply-queries.sh"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "erc-2771-msgSender-forgery"
POSITIVE_FIXTURE = FIXTURE_DIR / "positive.sol"
CLEAN_FIXTURE = FIXTURE_DIR / "clean.sol"

# The discriminating pattern from the fixed detector
FIXED_PATTERN = re.compile(r"ERC2771Context|isTrustedForwarder\s*\(|is\s+ERC2771")


class Erc2771MsgSenderForgeryPatternTests(unittest.TestCase):
    """Unit tests using regex directly - no shell dependency, always runnable."""

    def test_positive_fixture_matches_pattern(self) -> None:
        """ERC2771Context-inheriting contract must match the fixed pattern."""
        content = POSITIVE_FIXTURE.read_text()
        matches = FIXED_PATTERN.findall(content)
        self.assertGreater(
            len(matches),
            0,
            "positive.sol (ERC2771Context contract) must match the discriminating pattern",
        )

    def test_clean_fixture_no_match(self) -> None:
        """Plain-Context contract must NOT match the fixed pattern."""
        content = CLEAN_FIXTURE.read_text()
        matches = FIXED_PATTERN.findall(content)
        self.assertEqual(
            matches,
            [],
            f"clean.sol (plain Context, no ERC2771) must NOT match the discriminating "
            f"pattern - got: {matches}",
        )

    def test_old_broken_pattern_would_have_fired_on_clean(self) -> None:
        """Confirm the OLD pattern (pre-fix) would have fired on the clean fixture."""
        old_pattern = re.compile(r"_msgSender\s*\(|trustedForwarder|ERC2771")
        content = CLEAN_FIXTURE.read_text()
        # The clean fixture DOES call _msgSender() - the old pattern would have caught it.
        self.assertIsNotNone(
            old_pattern.search(content),
            "Test sanity: the old broken pattern must match the clean fixture (showing the FP).",
        )

    def test_apply_queries_uses_fixed_pattern(self) -> None:
        """Confirm apply-queries.sh actually contains the fixed pattern."""
        apply_queries_text = APPLY_QUERIES.read_text()
        # Old inheritance-blind trigger must be gone from the active detector line
        # (it may still appear in comments)
        active_line_pattern = re.compile(
            r'check_pattern\s+"erc-2771-msgSender-forgery"[^\n]*'
        )
        m = active_line_pattern.search(apply_queries_text)
        self.assertIsNotNone(m, "apply-queries.sh must contain the erc-2771-msgSender-forgery check_pattern line")
        active_line = m.group(0)
        # The fixed line must NOT use the old standalone _msgSender trigger as the primary pattern
        self.assertNotIn(
            "_msgSender",
            active_line,
            "Fixed pattern must not use _msgSender as a primary standalone trigger (inheritance-blind)",
        )
        # The fixed line must require ERC2771Context or isTrustedForwarder as discriminator
        self.assertTrue(
            "ERC2771Context" in active_line or "isTrustedForwarder" in active_line,
            "Fixed pattern must use ERC2771Context or isTrustedForwarder as discriminating signal",
        )

    def test_fixture_files_exist(self) -> None:
        """Both fixture files must be present."""
        self.assertTrue(POSITIVE_FIXTURE.exists(), "positive.sol fixture must exist")
        self.assertTrue(CLEAN_FIXTURE.exists(), "clean.sol fixture must exist")


class Erc2771MsgSenderForgeryShellTests(unittest.TestCase):
    """Integration tests via apply-queries.sh (require rg on PATH)."""

    @classmethod
    def setUpClass(cls) -> None:
        import shutil
        cls._rg_available = shutil.which("rg") is not None

    def _run_detector_on(self, fixture_path: Path) -> str:
        if not self._rg_available:
            self.skipTest("ripgrep (rg) not available")
        result = subprocess.run(
            ["bash", str(APPLY_QUERIES), str(fixture_path.parent), "erc-2771-msg-sender-address-forgery"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout + result.stderr

    def test_positive_fixture_fires(self) -> None:
        """Detector must report HITS on the ERC2771Context vuln fixture."""
        out = self._run_detector_on(POSITIVE_FIXTURE)
        self.assertIn(
            "[HITS]",
            out,
            "Detector must fire (HITS) on positive.sol which contains ERC2771Context",
        )

    def test_clean_fixture_alone_no_fire(self) -> None:
        """Detector must report CLEAN on a directory containing only the clean fixture."""
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(CLEAN_FIXTURE, Path(tmp) / "clean.sol")
            result = subprocess.run(
                ["bash", str(APPLY_QUERIES), tmp, "erc-2771-msg-sender-address-forgery"],
                capture_output=True,
                text=True,
                check=False,
            )
            out = result.stdout + result.stderr
            self.assertIn(
                "[CLEAN]",
                out,
                "Detector must be CLEAN on plain-Context contract (no ERC2771Context inheritance)",
            )
            self.assertNotIn(
                "[HITS]",
                out,
                "Detector must NOT fire on plain-Context contract",
            )


if __name__ == "__main__":
    unittest.main()
