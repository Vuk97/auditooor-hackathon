from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "iter-rollup.py"


def _load_tool():
    # Register the module in sys.modules BEFORE exec_module so that
    # @dataclass (which inspects cls.__module__ via sys.modules) works
    # under Python 3.14 strict-mode semantics.
    mod_name = "_iter_rollup_tool"
    spec = importlib.util.spec_from_file_location(mod_name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


class IterRollupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.reports = self.tmp_path / "reports"
        self.reports.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ----- fixture helpers --------------------------------------------------

    def _make_lane(
        self,
        iter_name: str,
        lane: str,
        body: str,
    ) -> Path:
        iter_dir = self.reports / iter_name
        iter_dir.mkdir(exist_ok=True)
        lane_dir = iter_dir / f"lane_{lane}"
        lane_dir.mkdir(exist_ok=True)
        results = lane_dir / "results.md"
        results.write_text(body, encoding="utf-8")
        return results

    # ----- iter folder parsing ---------------------------------------------

    def test_parses_canonical_iter_folder(self):
        self.assertEqual(self.tool._parse_iter_folder("v3_iter_2026-05-25"), ("2026-05-25", ""))

    def test_parses_iter_suffix(self):
        self.assertEqual(
            self.tool._parse_iter_folder("v3_iter_2026-05-23_iter12"),
            ("2026-05-23", "iter12"),
        )

    def test_parses_phase_suffix(self):
        self.assertEqual(
            self.tool._parse_iter_folder("v3_iter_2026-05-23_phase_a"),
            ("2026-05-23", "phase_a"),
        )

    def test_rejects_non_iter_folder(self):
        self.assertIsNone(self.tool._parse_iter_folder("random_dir"))
        self.assertIsNone(self.tool._parse_iter_folder("v3_iter_invalid"))

    # ----- verdict extraction ----------------------------------------------

    def test_extracts_verdict_inline(self):
        body = "# foo\n\n## VERDICT: DROP - mechanic structurally sound\n\nbody"
        self.assertEqual(
            self.tool._extract_verdict(body), "DROP - mechanic structurally sound"
        )

    def test_extracts_verdict_kv_form(self):
        body = "- verdict: AUDIT-DEEP-MOSTLY-NOMINAL\n"
        self.assertEqual(self.tool._extract_verdict(body), "AUDIT-DEEP-MOSTLY-NOMINAL")

    def test_extracts_verdict_header_body(self):
        body = "## Lane verdict\n\nPOSITIVE: shows U256 truncation\n\nbody"
        self.assertIn("POSITIVE", self.tool._extract_verdict(body))

    def test_no_verdict_returns_empty(self):
        body = "# title\n\nrandom prose, no verdict."
        self.assertEqual(self.tool._extract_verdict(body), "")

    # ----- verdict classification ------------------------------------------

    def test_classifies_positive(self):
        self.assertEqual(self.tool._classify_verdict("POSITIVE: novel fileable"), "POSITIVE")

    def test_classifies_drop(self):
        self.assertEqual(self.tool._classify_verdict("DROP - no novel surface"), "DROP")
        self.assertEqual(self.tool._classify_verdict("NO-NOVEL"), "DROP")

    def test_classifies_neutral_on_unknown(self):
        self.assertEqual(self.tool._classify_verdict("AUDIT-DEEP-MOSTLY-NOMINAL"), "NEUTRAL")

    def test_classifies_unknown_when_empty(self):
        self.assertEqual(self.tool._classify_verdict(""), "UNKNOWN")

    # ----- workspace extraction --------------------------------------------

    def test_extracts_workspace_decl(self):
        body = "- Workspace: /Users/wolf/audits/hyperbridge\n"
        self.assertIn("hyperbridge", self.tool._extract_workspace(body))

    def test_extracts_workspace_from_path(self):
        body = "PoC path: /Users/wolf/audits/morpho/poc-tests/foo.sol"
        self.assertEqual(self.tool._extract_workspace(body), "audits/morpho")

    def test_workspace_default_when_missing(self):
        self.assertEqual(self.tool._extract_workspace("no hints here", default="x"), "x")

    # ----- draft path extraction -------------------------------------------

    def test_extracts_draft_path_per_finding_layout(self):
        body = (
            "## Submission draft\n\nPer-finding folder at "
            "`/Users/wolf/audits/hyperbridge/submissions/staging/foo/foo.md`\n"
        )
        paths = self.tool._extract_fileable_drafts(body)
        self.assertEqual(paths, ["submissions/staging/foo/foo.md"])

    def test_extracts_draft_path_flat_legacy(self):
        body = "Submission at submissions/paste_ready/bar.md"
        self.assertEqual(self.tool._extract_fileable_drafts(body), ["submissions/paste_ready/bar.md"])

    def test_dedup_draft_paths(self):
        body = (
            "submissions/staging/foo/foo.md mentioned once\n"
            "submissions/staging/foo/foo.md again\n"
            "submissions/filed/bar.md\n"
        )
        paths = self.tool._extract_fileable_drafts(body)
        self.assertEqual(paths, ["submissions/staging/foo/foo.md", "submissions/filed/bar.md"])

    def test_no_draft_paths_when_absent(self):
        self.assertEqual(self.tool._extract_fileable_drafts("nothing here"), [])

    # ----- commit sha extraction -------------------------------------------

    def test_extracts_commit_inline(self):
        body = "- commit: abcdef1234567890\n"
        self.assertEqual(self.tool._extract_commit_sha(body), "abcdef123456")

    def test_no_commit_returns_empty(self):
        self.assertEqual(self.tool._extract_commit_sha("nothing"), "")

    # ----- end-to-end discovery --------------------------------------------

    def test_discovers_three_lanes_across_two_iters(self):
        self._make_lane(
            "v3_iter_2026-05-25",
            "DRILL_POS",
            "# Lane DRILL_POS\n\n## Lane verdict\n\nPOSITIVE: fired\n\n"
            "- Workspace: /Users/wolf/audits/hyperbridge\n"
            "Submission draft at submissions/staging/foo/foo.md\n",
        )
        self._make_lane(
            "v3_iter_2026-05-25",
            "DRILL_DROP",
            "# Lane DRILL_DROP\n\n## VERDICT: DROP - structurally sound\n\nbody\n",
        )
        self._make_lane(
            "v3_iter_2026-05-24",
            "AUDIT_DEEP",
            "- verdict: AUDIT-DEEP-MOSTLY-NOMINAL\n",
        )
        records = self.tool.discover_lanes(self.reports, since_days=0, git_lookup=False)
        self.assertEqual(len(records), 3)
        names = {r.lane_name for r in records}
        self.assertEqual(names, {"DRILL_POS", "DRILL_DROP", "AUDIT_DEEP"})

    def test_skips_empty_iter_dir_gracefully(self):
        (self.reports / "v3_iter_2026-05-25").mkdir()  # empty
        self._make_lane(
            "v3_iter_2026-05-24",
            "ONE",
            "## VERDICT: DROP\n",
        )
        records = self.tool.discover_lanes(self.reports, since_days=0, git_lookup=False)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].lane_name, "ONE")

    def test_summarize_by_iter_orders_recent_first(self):
        self._make_lane(
            "v3_iter_2026-05-24", "OLD", "## VERDICT: DROP\n"
        )
        self._make_lane(
            "v3_iter_2026-05-25", "NEW", "## VERDICT: DROP\n"
        )
        records = self.tool.discover_lanes(self.reports, since_days=0, git_lookup=False)
        summaries = self.tool.summarize_by_iter(records)
        self.assertEqual(len(summaries), 2)
        self.assertEqual(summaries[0].iter_folder, "v3_iter_2026-05-25")

    def test_fileable_finding_requires_positive_and_draft(self):
        # POSITIVE without draft path == not fileable
        self._make_lane(
            "v3_iter_2026-05-25",
            "POS_NO_DRAFT",
            "## Lane verdict\n\nPOSITIVE: but no draft\n",
        )
        # POSITIVE with draft path == fileable
        self._make_lane(
            "v3_iter_2026-05-25",
            "POS_WITH_DRAFT",
            "## Lane verdict\n\nPOSITIVE\n\nDraft at submissions/staging/p/p.md\n",
        )
        # DROP with draft path mention == not fileable (must be POSITIVE class)
        self._make_lane(
            "v3_iter_2026-05-25",
            "DROP_WITH_PATH",
            "## VERDICT: DROP\n\nrefers to submissions/superseded/x/x.md\n",
        )
        records = self.tool.discover_lanes(self.reports, since_days=0, git_lookup=False)
        fileable = [r for r in records if r.is_fileable]
        self.assertEqual(len(fileable), 1)
        self.assertEqual(fileable[0].lane_name, "POS_WITH_DRAFT")

    # ----- render output ---------------------------------------------------

    def test_render_markdown_has_top_section_and_per_lane_table(self):
        self._make_lane(
            "v3_iter_2026-05-25",
            "DRILL_POS",
            "## Lane verdict\n\nPOSITIVE\n\nDraft submissions/staging/foo/foo.md\n",
        )
        records = self.tool.discover_lanes(self.reports, since_days=0, git_lookup=False)
        summaries = self.tool.summarize_by_iter(records)
        md = self.tool.render_markdown(
            summaries, since_days=60, workspace_filter="", generated_at="2026-05-25T00:00:00Z"
        )
        self.assertIn("# Cross-iter hunt index", md)
        self.assertIn("## Per-iter overview", md)
        self.assertIn("## Per-lane detail", md)
        self.assertIn("## Fileable findings across iters", md)
        self.assertIn("DRILL_POS", md)
        self.assertIn("submissions/staging/foo/foo.md", md)

    def test_render_json_has_schema_and_iters(self):
        self._make_lane(
            "v3_iter_2026-05-25", "ONE", "## VERDICT: DROP\n"
        )
        records = self.tool.discover_lanes(self.reports, since_days=0, git_lookup=False)
        summaries = self.tool.summarize_by_iter(records)
        out = self.tool.render_json(
            summaries, since_days=60, workspace_filter="", generated_at="2026-05-25T00:00:00Z"
        )
        payload = json.loads(out)
        self.assertEqual(payload["schema"], self.tool.SCHEMA_VERSION)
        self.assertEqual(payload["totals"]["lanes"], 1)
        self.assertEqual(payload["iters"][0]["lanes"][0]["lane_name"], "ONE")

    # ----- workspace filter -------------------------------------------------

    def test_workspace_filter_excludes_other_workspaces(self):
        self._make_lane(
            "v3_iter_2026-05-25",
            "HB",
            "- Workspace: /Users/wolf/audits/hyperbridge\n## VERDICT: DROP\n",
        )
        self._make_lane(
            "v3_iter_2026-05-25",
            "DYDX",
            "- Workspace: /Users/wolf/audits/dydx\n## VERDICT: DROP\n",
        )
        records = self.tool.discover_lanes(
            self.reports, since_days=0, workspace_filter="dydx", git_lookup=False
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].lane_name, "DYDX")

    # ----- since-window filter ---------------------------------------------

    def test_since_parser_accepts_d_suffix(self):
        self.assertEqual(self.tool._parse_since("30d"), 30)
        self.assertEqual(self.tool._parse_since("60d"), 60)
        self.assertEqual(self.tool._parse_since("0"), 0)
        self.assertEqual(self.tool._parse_since("7"), 7)

    # ----- real-repo dogfood (anchor case) ---------------------------------

    def test_real_repo_emits_index(self):
        """Dogfood on the real repo's reports/v3_iter_2026-05-25 tree.

        Confirms (a) the tool runs without error against live data,
        (b) DRILL-6 (a known POSITIVE fileable from this iter) shows up
        in the fileable set when present.
        """
        live_reports = REPO_ROOT / "reports"
        if not (live_reports / "v3_iter_2026-05-25").is_dir():
            self.skipTest("real reports/v3_iter_2026-05-25 not present")
        records = self.tool.discover_lanes(
            live_reports, since_days=60, git_lookup=False
        )
        self.assertGreater(len(records), 0, "should discover at least one lane on live tree")
        # DRILL-6 has a POSITIVE verdict + per-finding folder. If it is present
        # in the tree, it should appear in the fileable set.
        drill6 = [r for r in records if "HYPERBRIDGE_DRILL_6" in r.lane_name]
        if drill6:
            self.assertEqual(drill6[0].verdict_class, "POSITIVE")
            self.assertTrue(drill6[0].fileable_draft_paths)


if __name__ == "__main__":
    unittest.main()
