#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/tests/test_prior_lane_scan.py - CAPABILITY-GAP-2 (2026-05-25)."""

from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import textwrap
import unittest

_TOOLS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))
from lib import prior_lane_scan  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HYPERBRIDGE_CHAIN3_FIXTURE = textwrap.dedent(
    """\
    # hb_loop9_chained_cross_component

    Some preamble that does not match.

    ## Chain 1 - unrelated

    Some unrelated text.

    ### Verdict - Chain 1: DOES NOT CLOSE

    NEGATIVE-sound.

    ## Chain 3 - timeout x delivery partial-landing across two contracts

    A request whose timeout-refund path and whose delivery path interact
    across two contracts so that BOTH effects partly land. The handler
    deletes the commitment before its callback, and the refund cannot
    fire while the destination shows the message delivered. This is a
    double refund scenario across two handler callsites.

    ### Verdict - Chain 3: DOES NOT CLOSE

    Timeout and delivery cannot both partly land. NEGATIVE-sound.

    ## Chain 4 - fee-escrow re-dispatch

    Unrelated, no overlap with our hypothesis keywords.
    """
)

REPO_RESULTS_FIXTURE = textwrap.dedent(
    """\
    # Lane LOOP10-T1: timeout refund hunt

    - Iter: v3_iter_2026-05-24_iter1
    - Lane: lane-LOOP10-T1
    - Workspace: /Users/wolf/audits/hyperbridge

    ## TL;DR

    Investigated double refund via handler timeout in cross-component
    delivery. Verdict: DROP.

    ## Verdict

    DROP-verdict, NEGATIVE-NO-FINDING.
    """
)


class PriorLaneScanTokenizerTests(unittest.TestCase):
    def test_basic_tokenize(self) -> None:
        toks = prior_lane_scan._tokenize_keywords("double refund handler timeout")
        self.assertEqual(toks, ["double", "refund", "handler", "timeout"])

    def test_comma_and_dedupe(self) -> None:
        toks = prior_lane_scan._tokenize_keywords(
            "double,refund,double,refund timeout"
        )
        self.assertEqual(toks, ["double", "refund", "timeout"])

    def test_stopwords_dropped(self) -> None:
        toks = prior_lane_scan._tokenize_keywords(
            "the refund and the handler"
        )
        self.assertEqual(toks, ["refund", "handler"])

    def test_tiny_tokens_dropped(self) -> None:
        toks = prior_lane_scan._tokenize_keywords("a is no x42 refund")
        # "x42" is len 3 = kept; "a", "is", "no" stripped.
        self.assertIn("refund", toks)
        self.assertNotIn("a", toks)
        self.assertNotIn("is", toks)

    def test_empty(self) -> None:
        self.assertEqual(prior_lane_scan._tokenize_keywords(""), [])
        self.assertEqual(prior_lane_scan._tokenize_keywords("   "), [])


class PriorLaneScanSectionizerTests(unittest.TestCase):
    def test_split_into_sections(self) -> None:
        sections = prior_lane_scan._split_into_sections(HYPERBRIDGE_CHAIN3_FIXTURE)
        headings = [s[0] for s in sections]
        self.assertIn("hb_loop9_chained_cross_component", headings)
        self.assertIn("Chain 1 - unrelated", headings)
        self.assertIn(
            "Chain 3 - timeout x delivery partial-landing across two contracts",
            headings,
        )
        self.assertIn("Chain 4 - fee-escrow re-dispatch", headings)

    def test_score_section_overlap(self) -> None:
        sections = prior_lane_scan._split_into_sections(HYPERBRIDGE_CHAIN3_FIXTURE)
        chain3 = [s for s in sections if s[0].startswith("Chain 3")][0]
        score, matched = prior_lane_scan._score_section(
            chain3[2], ["double", "refund", "handler", "timeout"]
        )
        # All 4 should match in the chain-3 section body.
        self.assertEqual(score, 4)
        self.assertEqual(set(matched), {"double", "refund", "handler", "timeout"})

    def test_score_section_no_overlap(self) -> None:
        sections = prior_lane_scan._split_into_sections(HYPERBRIDGE_CHAIN3_FIXTURE)
        chain4 = [s for s in sections if s[0].startswith("Chain 4")][0]
        score, _ = prior_lane_scan._score_section(
            chain4[2], ["double", "refund", "handler", "timeout"]
        )
        self.assertEqual(score, 0)

    def test_find_verdict_marker(self) -> None:
        v = prior_lane_scan._find_verdict_marker(
            "blah\nNEGATIVE-sound\nmore\n"
        )
        self.assertIsNotNone(v)
        assert v is not None
        self.assertTrue(v[0].upper().startswith("NEGATIVE"))

    def test_find_verdict_marker_drop(self) -> None:
        v = prior_lane_scan._find_verdict_marker("DROP-verdict here")
        self.assertIsNotNone(v)

    def test_find_verdict_marker_none(self) -> None:
        v = prior_lane_scan._find_verdict_marker("no verdict here, just text")
        self.assertIsNone(v)


class PriorLaneScanWorkspaceScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="pls_test_ws_"))
        self.workspace = self.tmpdir / "fake_ws"
        (self.workspace / ".auditooor").mkdir(parents=True)
        self.repo_root = self.tmpdir / "fake_repo"
        (self.repo_root / "reports").mkdir(parents=True)
        # No .git: _git_sha_for_file should gracefully return "untracked".

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_loop9(self) -> pathlib.Path:
        p = self.workspace / ".auditooor" / "hb_loop9_chained_cross_component.md"
        p.write_text(HYPERBRIDGE_CHAIN3_FIXTURE, encoding="utf-8")
        return p

    def test_hyperbridge_chain3_match(self) -> None:
        self._write_loop9()
        result = prior_lane_scan.scan_prior_lanes(
            workspace=self.workspace,
            lane_id="TEST-COMP-5",
            keyword_tokens=["double", "refund", "handler", "timeout"],
            repo_root=self.repo_root,
            enable_mcp=False,
        )
        chains = result["prior_negative_chains"]
        titles = [r["title"] for r in chains]
        self.assertTrue(
            any("Chain 3" in t for t in titles),
            f"Expected Chain 3 in titles; got: {titles}",
        )
        chain3 = [r for r in chains if r["title"].startswith("Chain 3")][0]
        # Verdict marker text or MCP fallback verdict.
        self.assertTrue(
            "NEGATIVE" in chain3["verdict"].upper()
            or "DOES NOT CLOSE" in chain3["verdict"].upper(),
            f"Unexpected verdict: {chain3['verdict']}",
        )
        self.assertIn("hb_loop9", chain3["source"])

    def test_empty_workspace_returns_empty(self) -> None:
        result = prior_lane_scan.scan_prior_lanes(
            workspace=self.workspace,
            lane_id="EMPTY",
            keyword_tokens=["double", "refund"],
            repo_root=self.repo_root,
            enable_mcp=False,
        )
        self.assertEqual(result["prior_negative_chains"], [])
        self.assertEqual(result["scan_summary"]["matches_returned"], 0)

    def test_missing_auditooor_dir_is_warn_only(self) -> None:
        # Remove the .auditooor dir.
        shutil.rmtree(self.workspace / ".auditooor")
        result = prior_lane_scan.scan_prior_lanes(
            workspace=self.workspace,
            lane_id="NO-AUDITOOOR",
            keyword_tokens=["timeout"],
            repo_root=self.repo_root,
            enable_mcp=False,
        )
        self.assertEqual(result["prior_negative_chains"], [])
        warnings = result["scan_summary"]["warnings"]
        self.assertTrue(any("missing-.auditooor" in w for w in warnings))

    def test_no_overlap_returns_empty(self) -> None:
        self._write_loop9()
        result = prior_lane_scan.scan_prior_lanes(
            workspace=self.workspace,
            lane_id="NO-OVERLAP",
            keyword_tokens=["pinata", "wombat", "xyzzy"],
            repo_root=self.repo_root,
            enable_mcp=False,
        )
        self.assertEqual(result["prior_negative_chains"], [])

    def test_repo_lane_results_scanned(self) -> None:
        iter_dir = self.repo_root / "reports" / "v3_iter_2026-05-24_iter1"
        lane_dir = iter_dir / "lane_LOOP10_T1"
        lane_dir.mkdir(parents=True)
        results_md = lane_dir / "results.md"
        results_md.write_text(REPO_RESULTS_FIXTURE, encoding="utf-8")
        result = prior_lane_scan.scan_prior_lanes(
            workspace=self.workspace,
            lane_id="TEST",
            keyword_tokens=["double", "refund", "handler", "timeout"],
            repo_root=self.repo_root,
            enable_mcp=False,
        )
        titles = [r["title"] for r in result["prior_negative_chains"]]
        self.assertTrue(
            any("LOOP10" in t or "TL;DR" in t or "Verdict" in t
                or "timeout" in t.lower() for t in titles),
            f"Expected a results.md hit; got: {titles}",
        )


class PriorLaneScanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="pls_test_cli_"))
        self.workspace = self.tmpdir / "ws"
        (self.workspace / ".auditooor").mkdir(parents=True)
        (
            self.workspace / ".auditooor" / "hb_loop9_chained_cross_component.md"
        ).write_text(HYPERBRIDGE_CHAIN3_FIXTURE, encoding="utf-8")
        self.repo_root = self.tmpdir / "repo"
        (self.repo_root / "reports").mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cli_json_emits_schema(self) -> None:
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            rc = prior_lane_scan.main([
                "--workspace", str(self.workspace),
                "--lane-id", "CLI-TEST",
                "--hypothesis-keywords", "double refund handler timeout",
                "--repo-root", str(self.repo_root),
                "--no-mcp",
            ])
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["schema"], "auditooor.prior_lane_scan.v1")
        titles = [r["title"] for r in payload["prior_negative_chains"]]
        self.assertTrue(any("Chain 3" in t for t in titles))

    def test_cli_render_brief_emits_markdown(self) -> None:
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            rc = prior_lane_scan.main([
                "--workspace", str(self.workspace),
                "--lane-id", "CLI-TEST",
                "--hypothesis-keywords", "double refund handler timeout",
                "--repo-root", str(self.repo_root),
                "--no-mcp",
                "--render-brief",
            ])
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        self.assertIn("<!-- BEGIN prior-lane-scan", out)
        self.assertIn("<!-- END prior-lane-scan", out)
        self.assertIn("STEP 1.5", out)
        self.assertIn("prior_negative_chains_acknowledged", out)
        self.assertIn("Chain 3", out)

    def test_cli_missing_workspace_graceful(self) -> None:
        from io import StringIO
        bogus = self.tmpdir / "does_not_exist"
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            rc = prior_lane_scan.main([
                "--workspace", str(bogus),
                "--lane-id", "MISSING",
                "--hypothesis-keywords", "timeout",
                "--repo-root", str(self.repo_root),
                "--no-mcp",
            ])
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["prior_negative_chains"], [])
        self.assertTrue(
            any("not-found" in w for w in payload["scan_summary"]["warnings"])
        )


class PriorLaneScanRenderBriefTests(unittest.TestCase):
    def test_empty_result_renders_acknowledgement_stub(self) -> None:
        result = {
            "schema": "auditooor.prior_lane_scan.v1",
            "scan_summary": {
                "workspace": "/fake",
                "lane_id": "TEST",
                "keyword_tokens": ["timeout"],
                "sources_scanned": {
                    "mcp_known_dead_ends_enabled": True,
                    "mcp_limit": 10,
                    "local_loop_md_cap": 60,
                    "reports_lookback_days": 60,
                    "reports_file_cap": 120,
                },
                "candidates_considered": 0,
                "matches_returned": 0,
                "warnings": [],
                "match_limit": 8,
            },
            "prior_negative_chains": [],
        }
        out = prior_lane_scan.render_brief_section(result)
        self.assertIn("STEP 1.5", out)
        self.assertIn("prior_negative_chains_acknowledged: []", out)

    def test_non_empty_result_lists_chains(self) -> None:
        result = {
            "schema": "auditooor.prior_lane_scan.v1",
            "scan_summary": {
                "workspace": "/fake",
                "lane_id": "TEST",
                "keyword_tokens": ["timeout"],
                "sources_scanned": {
                    "mcp_known_dead_ends_enabled": False,
                    "mcp_limit": 10,
                    "local_loop_md_cap": 60,
                    "reports_lookback_days": 60,
                    "reports_file_cap": 120,
                },
                "candidates_considered": 1,
                "matches_returned": 1,
                "warnings": [],
                "match_limit": 8,
            },
            "prior_negative_chains": [
                {
                    "title": "Chain 3 - timeout x delivery",
                    "verdict": "NEGATIVE-sound",
                    "source": "/x/y/hb_loop9.md",
                    "sha": "abc1234",
                    "overlap_summary": "keywords matched: timeout (1/1)",
                }
            ],
        }
        out = prior_lane_scan.render_brief_section(result)
        self.assertIn("Chain 3 - timeout x delivery", out)
        self.assertIn("NEGATIVE-sound", out)
        self.assertIn("abc1234", out)
        self.assertIn("prior_negative_chains_acknowledged:", out)


# ---------------------------------------------------------------------------
# K3-deadend-injection: file_line match mode + PRIOR DEAD-ENDS brief block.
# ---------------------------------------------------------------------------

class PriorLaneScanFileLineModeTests(unittest.TestCase):
    def _ws_with_store(self, rows, store_name="known_dead_ends.jsonl"):
        ws = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, ws, ignore_errors=True)
        aud = ws / ".auditooor"
        aud.mkdir()
        (aud / store_name).write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
        )
        return ws

    def test_normalize_file_line_variants(self):
        self.assertEqual(
            prior_lane_scan._normalize_file_line("src/A.sol:86"), ("src/a.sol", 86)
        )
        self.assertEqual(
            prior_lane_scan._normalize_file_line("src/A.sol"), ("src/a.sol", None)
        )
        self.assertEqual(
            prior_lane_scan._normalize_file_line("src/A.sol#L12"), ("src/a.sol", 12)
        )

    def test_coalesce_kde_row_variant_fields(self):
        # ledger-style row: evidence_file_line / kill_reason / record_id /
        # kill_verdict must coalesce to the uniform fields.
        row = {
            "record_id": "REC-1",
            "evidence_file_line": "src/B.sol:10",
            "kill_reason": "balance check holds",
            "kill_verdict": "FP",
            "pin": "abc123",
        }
        c = prior_lane_scan._coalesce_kde_row(row)
        self.assertEqual(c["dead_end_id"], "REC-1")
        self.assertEqual(c["file_line"], "src/B.sol:10")
        self.assertEqual(c["norm_path"], "src/b.sol")
        self.assertEqual(c["line"], 10)
        self.assertEqual(c["drop_class"], "FP")
        self.assertEqual(c["reason"], "balance check holds")
        self.assertEqual(c["pin"], "abc123")

    def test_pin_match_completeness_safe(self):
        # unknown pin on either side -> keep; short-sha prefix match both ways.
        self.assertTrue(prior_lane_scan._pin_matches("", "deadbeef"))
        self.assertTrue(prior_lane_scan._pin_matches("deadbeef", ""))
        self.assertTrue(prior_lane_scan._pin_matches("deadbeef0011", "deadbeef"))
        self.assertTrue(prior_lane_scan._pin_matches("deadbeef", "deadbeef0011"))
        self.assertFalse(prior_lane_scan._pin_matches("deadbeef", "cafebabe"))

    def test_file_line_match_exact_and_path_level(self):
        ws = self._ws_with_store([
            {"dead_end_id": "KDE-1", "file_line": "src/A.sol:86",
             "reason": "no overflow", "drop_class": "DROP"},
        ])
        # exact line match
        hits = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/A.sol:86"], target_pin="", repo_root=ws,
        )
        self.assertEqual([h["dead_end_id"] for h in hits], ["KDE-1"])
        # path-level match when target gives no line
        hits2 = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/A.sol"], target_pin="", repo_root=ws,
        )
        self.assertEqual([h["dead_end_id"] for h in hits2], ["KDE-1"])
        # different line in same file -> no match (both carry a line)
        hits3 = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/A.sol:99"], target_pin="", repo_root=ws,
        )
        self.assertEqual(hits3, [])
        # different file -> no match
        hits4 = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/Other.sol:86"], target_pin="", repo_root=ws,
        )
        self.assertEqual(hits4, [])

    def test_file_line_pin_filter(self):
        ws = self._ws_with_store([
            {"dead_end_id": "KDE-PIN", "file_line": "src/A.sol:5",
             "reason": "stale pin row", "audit_pin": "cafebabe"},
        ])
        # KDE row pinned to a DIFFERENT pin -> filtered out.
        miss = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/A.sol:5"], target_pin="deadbeef", repo_root=ws,
        )
        self.assertEqual(miss, [])
        # same pin -> matches.
        hit = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/A.sol:5"], target_pin="cafebabe", repo_root=ws,
        )
        self.assertEqual([h["dead_end_id"] for h in hit], ["KDE-PIN"])

    def test_empty_store_no_dead_ends(self):
        ws = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, ws, ignore_errors=True)
        (ws / ".auditooor").mkdir()
        hits = prior_lane_scan.scan_file_line_dead_ends(
            ws, ["src/A.sol:1"], target_pin="", repo_root=ws,
        )
        self.assertEqual(hits, [])

    def test_render_brief_contains_prior_dead_ends_block(self):
        result = {
            "schema": prior_lane_scan.SCHEMA,
            "scan_summary": {
                "keyword_tokens": ["overflow"],
                "sources_scanned": {},
                "candidates_considered": 0,
                "matches_returned": 0,
                "dead_ends_returned": 1,
                "warnings": [],
            },
            "prior_dead_ends": [
                {"dead_end_id": "KDE-9", "file_line": "src/A.sol:42",
                 "drop_class": "DROP", "reason": "overflow impossible"},
            ],
            "prior_negative_chains": [],
        }
        out = prior_lane_scan.render_brief_section(result)
        self.assertIn("## PRIOR DEAD-ENDS", out)
        self.assertIn("do not re-derive; cite dead_end_id", out)
        self.assertIn("src/A.sol:42", out)
        self.assertIn("KDE-9", out)

    def test_render_brief_no_block_when_no_dead_ends(self):
        result = {
            "schema": prior_lane_scan.SCHEMA,
            "scan_summary": {"keyword_tokens": [], "sources_scanned": {},
                             "candidates_considered": 0, "matches_returned": 0,
                             "warnings": []},
            "prior_dead_ends": [],
            "prior_negative_chains": [],
        }
        out = prior_lane_scan.render_brief_section(result)
        self.assertNotIn("PRIOR DEAD-ENDS", out)

    def test_scan_prior_lanes_surfaces_dead_ends(self):
        ws = self._ws_with_store([
            {"dead_end_id": "KDE-INT", "file_line": "src/A.sol:42",
             "reason": "drilled", "drop_class": "NEGATIVE"},
        ])
        res = prior_lane_scan.scan_prior_lanes(
            ws, "HUNT-1", ["overflow"], repo_root=ws, enable_mcp=False,
            target_file_lines=["src/A.sol:42"], target_pin="",
        )
        self.assertEqual(res["scan_summary"]["dead_ends_returned"], 1)
        self.assertEqual(
            [d["dead_end_id"] for d in res["prior_dead_ends"]], ["KDE-INT"]
        )


if __name__ == "__main__":
    unittest.main()
