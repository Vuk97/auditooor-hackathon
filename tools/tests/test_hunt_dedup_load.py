#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""Unit tests for tools/hunt-dedup-load.py (L36 dedup-first step 0)."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hunt-dedup-load.py"
_spec = importlib.util.spec_from_file_location("hunt_dedup_load", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class TestHuntDedupLoad(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, use_mcp=False):
        return mod.run(self.ws, use_mcp=use_mcp, mcp_server=None, repo_root=self.ws)

    def test_fresh_workspace_writes_empty_skip_set(self):
        result, verdict = self._run()
        self.assertEqual(verdict, "pass-dedup-loaded-empty")
        out = self.ws / ".auditooor" / "hunt_skip_set.json"
        self.assertTrue(out.is_file())
        data = json.loads(out.read_text())
        self.assertEqual(data["schema"], "auditooor.l36_hunt_skip_set.v1")
        self.assertEqual(data["source_counts"]["total_after_dedup"], 0)

    def test_submissions_collected_across_status_dirs(self):
        for status in ("filed", "_killed", "paste_ready", "staging", "superseded"):
            d = self.ws / "submissions" / status
            d.mkdir(parents=True)
            (d / f"my-{status}-finding.md").write_text(
                f"# {status} title\nFoo.sol:42 root cause\n"
            )
        result, verdict = self._run()
        self.assertEqual(verdict, "pass-dedup-loaded")
        self.assertEqual(result["source_counts"]["submissions"], 5)

    def test_per_finding_slug_folder_layout(self):
        slug = "deep-finding-slug"
        d = self.ws / "submissions" / "filed" / slug
        d.mkdir(parents=True)
        # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered
        (d / f"{slug}.md").write_text("# Title\nx/clob.go:10\n")
        data = self._read_skip_set()
        entry = next(e for e in data["entries"] if e["source"] == "submissions")
        self.assertEqual(entry["slug"], slug)
        self.assertEqual(entry["file_line"], "x/clob.go:10")

    def test_tracker_md_excluded(self):
        d = self.ws / "submissions" / "filed"
        d.mkdir(parents=True)
        (d / "SUBMISSIONS.md").write_text("# tracker\n")
        (d / "README.md").write_text("# readme\n")
        (d / "real-finding.md").write_text("# real\n")
        result, _ = self._run()
        self.assertEqual(result["source_counts"]["submissions"], 1)

    def test_workspace_known_dead_ends_collected(self):
        rep = self.ws / "reports"
        rep.mkdir()
        kde = rep / "known_dead_ends.jsonl"
        kde.write_text(
            json.dumps({"record_id": "DE-1", "root_cause": "no impact", "verdict": "KILLED"}) + "\n"
            + json.dumps({"slug": "DE-2", "reason": "OOS"}) + "\n"
        )
        result, _ = self._run()
        self.assertEqual(result["source_counts"]["known_dead_ends"], 2)

    def test_global_dead_ends_filtered_to_workspace(self):
        # repo-global KDE: one record for this ws name, one for another ws.
        repo = Path(self._tmp.name) / "repo"
        (repo / "reports").mkdir(parents=True)
        ws_name = self.ws.name
        (repo / "reports" / "known_dead_ends.jsonl").write_text(
            json.dumps({"record_id": "G-MINE", "workspace": ws_name, "verdict": "KILLED"}) + "\n"
            + json.dumps({"record_id": "G-OTHER", "workspace": "some-other-project", "verdict": "KILLED"}) + "\n"
            + json.dumps({"record_id": "G-GLOBAL", "verdict": "KILLED"}) + "\n"  # no ws => kept
        )
        # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered
        result, verdict = mod.run(self.ws, use_mcp=False, mcp_server=None, repo_root=repo)
        # G-MINE + G-GLOBAL kept; G-OTHER filtered out. Read the skip-set this
        # run wrote (do NOT re-run with the default repo_root).
        data = json.loads((self.ws / ".auditooor" / "hunt_skip_set.json").read_text())
        slugs = {e["slug"] for e in data["entries"]}
        self.assertIn("G-MINE", slugs)
        self.assertIn("G-GLOBAL", slugs)
        self.assertNotIn("G-OTHER", slugs)

    def test_sidecars_collected_including_fp(self):
        sc = self.ws / ".auditooor" / "hunt_findings_sidecars"
        sc.mkdir(parents=True)
        (sc / "cand-1.json").write_text(json.dumps({"slug": "cand-1", "verdict": "CONFIRMED"}))
        (sc / "cand-2-FP.json").write_text(json.dumps({"slug": "cand-2"}))
        result, _ = self._run()
        self.assertEqual(result["source_counts"]["sidecars"], 2)
        verdicts = {e["verdict"] for e in self._read_skip_set()["entries"] if e["source"] == "sidecar"}
        self.assertIn("fp", verdicts)

    def test_loose_sidecar_md_under_auditooor(self):
        a = self.ws / ".auditooor"
        a.mkdir()
        (a / "dydx_loop1_foo_sidecar.md").write_text("# loose sidecar\nbar.go:5\n")
        result, _ = self._run()
        self.assertEqual(result["source_counts"]["sidecars"], 1)

    def test_dedup_collapses_identical_entries(self):
        d = self.ws / "submissions" / "filed"
        d.mkdir(parents=True)
        (d / "x.md").write_text("# X\nA.sol:1\n")
        rep = self.ws / "reports"
        rep.mkdir()
        # A dead-end with same slug+file_line+verdict would dedup; use distinct.
        rep_kde = rep / "known_dead_ends.jsonl"
        rep_kde.write_text(json.dumps({"slug": "x", "file_line": "A.sol:1", "verdict": "filed"}) + "\n")
        data = self._read_skip_set()
        # 'x' filed from submissions; the KDE row has verdict 'filed' too => same key => deduped.
        xs = [e for e in data["entries"] if e["slug"] == "x"]
        self.assertEqual(len(xs), 1)

    def test_cannot_write_is_hard_fail(self):
        # Make .auditooor a file so mkdir/write fails.
        (self.ws / ".auditooor").write_text("not a dir")
        result, verdict = self._run()
        self.assertEqual(verdict, "fail-cannot-write")

    def test_cli_exit_codes(self):
        # missing workspace => 2
        rc = mod.main([str(self.ws / "nope"), "--no-mcp"])
        self.assertEqual(rc, 2)
        # fresh ws => 0
        rc = mod.main([str(self.ws), "--no-mcp", "--repo-root", str(self.ws)])
        self.assertEqual(rc, 0)

    def _read_skip_set(self):
        self._run()
        return json.loads((self.ws / ".auditooor" / "hunt_skip_set.json").read_text())


if __name__ == "__main__":
    unittest.main()
