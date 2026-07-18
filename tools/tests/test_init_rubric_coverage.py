from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "init-rubric-coverage.sh"


class InitRubricCoverageTest(unittest.TestCase):
    def test_rejects_placeholder_severity_instead_of_generating_fake_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text(
                "# Severity Rubric\n\n"
                "**TODO:** paste the bounty program's severity matrix here.\n"
            )

            result = subprocess.run(
                ["bash", str(TOOL), str(ws), "--force"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertFalse((ws / "RUBRIC_COVERAGE.md").exists())
            self.assertIn("no populated severity rubric source", result.stdout)

    def test_generates_from_split_smart_contract_and_blockchain_dlt_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n"
                "- Smart contract funds can be stolen\n\n"
                "# High\n"
                "- Contract funds can be permanently frozen\n"
            )
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text(
                "# Critical\n"
                "- Consensus safety can be violated\n\n"
                "# Medium\n"
                "- DLT liveness can be temporarily degraded\n"
            )

            result = subprocess.run(
                ["bash", str(TOOL), str(ws), "--force"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            coverage = (ws / "RUBRIC_COVERAGE.md").read_text()
            self.assertIn("SEVERITY_SMART_CONTRACTS.md", coverage)
            self.assertIn("SEVERITY_BLOCKCHAIN_DLT.md", coverage)
            self.assertIn("Smart contract funds can be stolen", coverage)
            self.assertIn("Consensus safety can be violated", coverage)

    def test_parses_markdown_table_severity_rubric(self):
        # Many programs (incl. the Immunefi standard rubric) express the
        # severity-to-impact mapping as a markdown TABLE, not tier-header +
        # bullets. The parser must read table rows and must NOT pick up the
        # column header, the |---| separator, or Impact x Probability matrix rows.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text(
                "# Severity\n\n"
                "| Severity | Impact |\n"
                "|----------|--------|\n"
                "| Critical | Direct theft of user funds |\n"
                "| High | Temporary freezing of funds |\n"
                "| Medium | Smart contract unable to operate |\n"
                "| Low | Contract fails to deliver returns |\n\n"
                "## Probability matrix\n"
                "| | Low | High |\n"
                "|---|---|---|\n"
                "| **High Probability** | MEDIUM | CRITICAL |\n"
            )
            result = subprocess.run(
                ["bash", str(TOOL), str(ws), "--force"],
                cwd=REPO, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            coverage = (ws / "RUBRIC_COVERAGE.md").read_text()
            self.assertIn("Direct theft of user funds", coverage)
            self.assertIn("Temporary freezing of funds", coverage)
            self.assertIn("Smart contract unable to operate", coverage)
            # The probability-matrix row's first cell is a probability label,
            # not a bare tier, so it must NOT create a spurious example row.
            self.assertNotIn("High Probability", coverage)


if __name__ == "__main__":
    unittest.main()
