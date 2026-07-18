#!/usr/bin/env python3
"""Regression: extract-oos.sh must FOLD wrapped continuation lines into the current
OOS bullet, not drop them. Bug caught on Obyte 2026-07-09 - a SCOPE.md bullet

    - Basic economic attacks (e.g. 51% attack). Lack-of-liquidity impacts.
      Sybil attacks. Centralization risks.

silently lost the wrapped "Sybil attacks. Centralization risks." clause from
OOS_CHECKLIST.md, so the automated OOS pre-check nearly let a Sybil-farming
finding through as fileable (a false-negative-OOS / integrity risk)."""
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_SCRIPT = _REPO / "tools" / "extract-oos.sh"


class TestExtractOosWrappedBullet(unittest.TestCase):
    def _run(self, scope_md: str) -> str:
        d = tempfile.mkdtemp()
        (Path(d) / ".auditooor").mkdir(exist_ok=True)
        (Path(d) / "SCOPE.md").write_text(scope_md)
        subprocess.run(["bash", str(_SCRIPT), d], capture_output=True, text=True, check=False)
        return (Path(d) / "OOS_CHECKLIST.md").read_text()

    def test_wrapped_continuation_clause_folded(self):
        oos = self._run(textwrap.dedent("""
            # SCOPE
            ## Out of scope
            - Basic economic attacks (e.g. 51% attack). Lack-of-liquidity impacts.
              Sybil attacks. Centralization risks.
            - Phishing / social engineering.
        """))
        # the wrapped clause must survive
        self.assertIn("Sybil attacks", oos, "wrapped Sybil clause dropped")
        self.assertIn("Centralization risks", oos, "wrapped Centralization clause dropped")
        # and it must be folded into the SAME bullet as its opener, not orphaned
        self.assertIn("Lack-of-liquidity impacts. Sybil attacks", oos)
        # normal (non-wrapped) bullets are unaffected
        self.assertIn("Phishing", oos)

    def test_blank_line_ends_continuation(self):
        # a blank line between a bullet and later prose must NOT fold that prose in
        oos = self._run(textwrap.dedent("""
            # SCOPE
            ## Out of scope
            - First OOS class here.

            Some unrelated prose paragraph that is not a bullet.
            ## Next section
            - not oos
        """))
        self.assertIn("First OOS class here", oos)
        self.assertNotIn("unrelated prose", oos)


if __name__ == "__main__":
    unittest.main()
