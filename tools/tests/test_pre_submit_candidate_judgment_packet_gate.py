#!/usr/bin/env python3
"""Subprocess regression for pre-submit-check.sh Check 82."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _run_pre_submit(draft: Path, workspace: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["WS"] = str(workspace)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


class CandidateJudgmentPacketGateTests(unittest.TestCase):
    def test_high_draft_blocks_when_matching_packet_has_scope_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            draft_dir = workspace / "submissions" / "staging"
            auditooor_dir = workspace / ".auditooor"
            draft_dir.mkdir(parents=True)
            auditooor_dir.mkdir()

            (workspace / "SCOPE.md").write_text(
                "# Scope\n\nIn scope: synthetic protocol source.\n\nOut of scope: candidate-82.\n",
                encoding="utf-8",
            )
            draft = draft_dir / "candidate-82.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Candidate 82 scope blocked draft

                    **Severity:** High

                    ## Impact

                    Candidate ID: candidate-82

                    This draft is intentionally minimal; Check 82 should block
                    because the matching candidate judgment packet is scope-blocked.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            (auditooor_dir / "candidate_judgment_packet.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.candidate_judgment_packet.v1",
                        "summary": {
                            "strict_poc_planning_allowed": False,
                            "blocked_before_poc_count": 1,
                        },
                        "strict_blockers": [
                            {
                                "candidate_id": "candidate-82",
                                "packet_state": "blocked_by_scope",
                            }
                        ],
                        "packets": [
                            {
                                "candidate_id": "candidate-82",
                                "title": "Candidate 82 scope blocked draft",
                                "packet_state": "blocked_by_scope",
                                "verdict": "blocked_before_poc",
                                "promotion_blockers": ["blocked_by_scope"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft, workspace)

            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("82. CANDIDATE-JUDGMENT-PACKET blocked", proc.stdout)
            self.assertIn("strict_poc_planning_allowed=false", proc.stdout)
            self.assertIn("blocked_by_scope", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
