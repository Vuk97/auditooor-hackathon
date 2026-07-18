"""test_prebriefing_impact_mechanism_plane.py

Regression: the CANONICAL hunt brief (dispatch-agent-with-prebriefing.py, used by
`make hunt-scoped`) must carry Section 0.8 - the impact x mechanism completeness
plane + the agent_mechanism_verdicts write-instruction. The plane lived only in
agent-prompt-hacker-augmenter.py, which the hunt-scoped dispatch does NOT call, so
the closed-loop cell-clearing capability was orphaned for the real per-fn hunt
(operator-caught: 'is this the proper flow?'). This test pins the wiring.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load():
    spec = importlib.util.spec_from_file_location("dispatch_pb_plane", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_pb_plane"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


D = _load()


def _ws_with_mech(td: str) -> pathlib.Path:
    ws = pathlib.Path(td)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        json.dumps({"function": "deposit", "file": "src/Vault.sol"}) + "\n",
        encoding="utf-8",
    )
    return ws


class TestPrebriefingPlane(unittest.TestCase):
    def test_plane_block_renders(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_mech(td)
            blk = D.build_impact_mechanism_plane_block(ws)
            self.assertIn("Section 0.8", blk)
            self.assertIn("agent_mechanism_verdicts", blk)
            self.assertIn("auditooor.agent_mechanism_verdict.v1", blk)

    def test_enriched_prompt_carries_the_plane(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_mech(td)
            enriched, _meta = D.build_enriched_prompt(
                prompt_text="hunt this workspace for bugs",
                lane_type="hunt", severity="HIGH", workspace_path=ws,
            )
            self.assertIn("Section 0.8", enriched)
            self.assertIn("auditooor.agent_mechanism_verdict.v1", enriched)

    def test_no_workspace_degrades_gracefully(self):
        self.assertEqual(D.build_impact_mechanism_plane_block(None), "")

    def test_plane_survives_skeleton_only_truncation(self):
        """THE real regression: the hunt-scoped fanout path calls
        --skeleton-only, which TRUNCATES at the END marker. The plane MUST be
        emitted by format_skeleton_as_markdown BEFORE that marker, or every
        batch brief loses it (the exact bug: 0/32 batches carried it)."""
        with tempfile.TemporaryDirectory() as td:
            ws = _ws_with_mech(td)
            skel = D.format_skeleton_as_markdown(
                None, lane_type="hunt", severity="HIGH", workspace_path=ws,
            )
            end = "<!-- END dispatch-agent-with-prebriefing META-1 block -->"
            self.assertIn("Section 0.8", skel)
            self.assertIn(end, skel)
            # the plane must appear BEFORE the END marker (else --skeleton-only cuts it)
            self.assertLess(skel.index("Section 0.8"), skel.index(end),
                            "Section 0.8 must precede the END marker to survive --skeleton-only")


if __name__ == "__main__":
    unittest.main()
