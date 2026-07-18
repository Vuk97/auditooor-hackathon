#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""Tests for tools/hunt-cluster-brief-emit.py (L36 step 5)."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hunt-cluster-brief-emit.py"
_spec = importlib.util.spec_from_file_location("hunt_cluster_brief_emit", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["hunt_cluster_brief_emit"] = mod
_spec.loader.exec_module(mod)


class TestClusterBriefEmit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_scope_no_briefs(self):
        result = mod.run(self.ws)
        self.assertEqual(result["verdict"], "pass-no-clusters")
        self.assertEqual(result["briefs"], [])

    def test_briefs_emitted_per_cluster(self):
        (self.ws / "SCOPE.md").write_text("- x/clob\n- x/prices\n- matching engine\n")
        result = mod.run(self.ws)
        self.assertEqual(result["verdict"], "pass-briefs-emitted")
        self.assertEqual(len(result["briefs"]), 3)
        for b in result["briefs"]:
            self.assertTrue(Path(b).is_file())

    def test_scope_parser_ignores_target_and_oos_sections(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# Example - Audit Scope",
                "",
                "## Target",
                "- Repo: https://example.test/protocol",
                "- Platform: Cantina",
                "",
                "## Asset classes",
                "- Smart Contract: all `src/**/*.sol`",
                "",
                "## In scope (src/ only)",
                "- `src/Core.sol` - core protocol",
                "- `src/periphery/` - helper contracts",
                "",
                "## Out of scope",
                "- test/, certora/, lib/",
                "- Trusted-role assumptions",
                "",
                "## Token safety assumptions",
                "- Token must not re-enter.",
            ]) + "\n"
        )

        result = mod.run(self.ws)

        self.assertEqual(result["verdict"], "pass-briefs-emitted")
        slugs = {Path(p).stem for p in result["briefs"]}
        self.assertEqual(slugs, {
            "smart-contract-all-src-sol",
            "src-core-sol",
            "src-periphery",
        })

    def test_title_scope_heading_does_not_hide_bullets(self):
        (self.ws / "SCOPE.md").write_text("# Audit Scope\n- src/Core.sol\n- src/periphery/\n")

        result = mod.run(self.ws)

        self.assertEqual(result["verdict"], "pass-briefs-emitted")
        self.assertEqual({Path(p).stem for p in result["briefs"]}, {"src-core-sol", "src-periphery"})

    def test_brief_embeds_canonical_hunt_definition(self):
        (self.ws / "SCOPE.md").write_text("- x/clob\n")
        result = mod.run(self.ws)
        body = Path(result["briefs"][0]).read_text()
        self.assertIn("Canonical hunt definition", body)
        self.assertIn("FULL pipeline", body)
        self.assertIn("rejected by hunt-completeness-check", body)

    def test_brief_embeds_skip_set_digest(self):
        (self.ws / "SCOPE.md").write_text("- x/clob\n")
        (self.ws / ".auditooor" / "hunt_skip_set.json").write_text(json.dumps({
            "schema": "auditooor.l36_hunt_skip_set.v1",
            "source_counts": {"total_after_dedup": 2},
            "entries": [
                {"slug": "prior-finding-a", "verdict": "filed", "file_line": "a.go:1", "root_cause": "rc"},
                {"slug": "dead-end-b", "verdict": "killed", "file_line": "", "root_cause": "no impact"},
            ],
        }))
        result = mod.run(self.ws)
        body = Path(result["briefs"][0]).read_text()
        self.assertIn("DEDUP-FIRST directive", body)
        self.assertIn("prior-finding-a", body)
        self.assertIn("dead-end-b", body)
        self.assertEqual(result["skip_set_entries"], 2)

    def test_empty_skip_set_digest_message(self):
        (self.ws / "SCOPE.md").write_text("- x/clob\n")
        result = mod.run(self.ws)
        body = Path(result["briefs"][0]).read_text()
        self.assertIn("skip-set empty", body)

    def test_slugify_handles_special_chars(self):
        self.assertEqual(mod._slugify("x/clob (matching)"), "x-clob-matching")
        self.assertEqual(mod._slugify(""), "cluster")


if __name__ == "__main__":
    unittest.main()
