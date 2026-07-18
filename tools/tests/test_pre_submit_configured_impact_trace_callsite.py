"""Pre-submit call-site regression for configured-impact trace gates."""
from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


class TestPreSubmitConfiguredImpactTraceCallsite(unittest.TestCase):
    def test_check88_cli_severity_reaches_numbered_check(self) -> None:
        """A no-header draft must hit Check 88 through CLI severity."""
        with tempfile.TemporaryDirectory() as td:
            draft = Path(td) / "bridge-config-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bridge route accepts malformed messages

                    The bridge relayer can submit a malformed cross-chain
                    message that causes downstream accounting state corruption.
                    The draft intentionally omits configuration/deployment
                    preconditions and the downstream consumer trace.
                    """
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Medium"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
            )

        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("88. CONFIG-DOWNSTREAM-TRACE blocked", proc.stdout)
        self.assertIn("severity=medium", proc.stdout)

    def test_r42_cli_severity_reaches_numbered_check(self) -> None:
        """A draft with no severity header must still hit Check 89 via CLI severity."""
        with tempfile.TemporaryDirectory() as td:
            draft = Path(td) / "configured-impact-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Registered consensus client accepts forged root and drains funds

                    A registered consensus client accepts an unfinalized state root.
                    The report claims loss of funds from a downstream bridge reserve,
                    but intentionally omits a Configured-Impact Trace section.
                    """
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Medium"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
            )

        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("89. R42-CONFIGURED-IMPACT-TRACE blocked", proc.stdout)
        self.assertIn("severity=medium", proc.stdout)


if __name__ == "__main__":
    unittest.main()
