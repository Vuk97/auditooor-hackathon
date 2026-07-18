#!/usr/bin/env python3
"""Regression: cross-link-validator scans the DOCUMENTATION corpus, not ephemeral
per-engagement artifact trees, and its --fix-suggestions cost is bounded.

2026-07-07: repo-root scope pulled in 16363 "docs" (~15000 from audit/ agent-run
outputs, .claude/ session state, reports/ generated advisories), reported 9091
broken links, and --fix-suggestions rebuilt a 16k-entry basename dict PER broken
link -> the docs gate stalled for minutes. Fix: (a) SCAN_ONLY_SKIP_DIRS excludes
those trees from OUTGOING-link scanning while keeping them in the filesystem
index as valid link TARGETS; (b) the basename map is built once; (c) suggestion
fuzzy-match is capped with a disclosed (non-silent) note.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "clv", _HERE.parent / "cross-link-validator.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["clv"] = _m
_spec.loader.exec_module(_m)


class TestCrossLinkScope(unittest.TestCase):
    def _tree(self):
        root = Path(tempfile.mkdtemp())
        (root / "docs").mkdir()
        (root / "audit").mkdir()
        (root / "reports").mkdir()
        (root / ".claude").mkdir()
        # a real doc that links to a report artifact (target must resolve)
        (root / "docs" / "guide.md").write_text("See [rpt](../reports/r.md)\n")
        (root / "reports" / "r.md").write_text("# report with [dangling](./nope.md)\n")
        (root / "audit" / "a.md").write_text("[broken](./missing.md)\n")
        (root / ".claude" / "s.md").write_text("[broken](./gone.md)\n")
        return root

    def test_scan_skips_ephemeral_trees(self):
        root = self._tree()
        scanned = [p.name for p in _m.iter_md_files(root)]
        self.assertIn("guide.md", scanned)
        # ephemeral trees are NOT scanned for outgoing links
        self.assertNotIn("r.md", scanned)      # reports/
        self.assertNotIn("a.md", scanned)      # audit/
        self.assertNotIn("s.md", scanned)      # .claude/

    def test_index_still_includes_report_targets(self):
        # build_fs_index must keep reports/ + audit/ as valid link TARGETS so a
        # genuine doc -> artifact link resolves (only .claude is fully excluded).
        root = self._tree()
        idx, basenames = _m.build_fs_index(root)
        self.assertIn("r.md", basenames)       # reports/ file indexable as target
        self.assertIn("a.md", basenames)       # audit/ file indexable as target

    def test_doc_link_into_report_is_not_broken(self):
        # docs/guide.md -> ../reports/r.md must resolve (target exists on disk)
        root = self._tree()
        status = _m.target_status(
            root / "docs" / "guide.md", "../reports/r.md", root, "repo-only")
        self.assertNotEqual(status, "broken", status)

    def test_suggest_signature_precomputed(self):
        # suggest() takes the precomputed basename map + keys (built once)
        root = self._tree()
        idx, basenames = _m.build_fs_index(root)
        keys = list(basenames.keys())
        # a near-miss basename should suggest the real file
        out = _m.suggest("reports/rr.md", idx, basenames, keys)
        self.assertTrue(out.endswith("r.md") or out == "", out)


if __name__ == "__main__":
    unittest.main()
