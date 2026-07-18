#!/usr/bin/env python3
# r36-rebuttal: lane-gap37b-salvage-negation registered via tools/agent-pathspec-register.py.
"""Tests for tools/salvage-negation-verdict-check.py (Gap #37b).

Companion gate to Gap #37 (Check #109). Covers:
- Trigger-surface routing (in/out of scope).
- pass-no-verdict-language when body lacks verdict phrasing.
- pass-negation-framing-complete when all three elements present.
- ok-rebuttal for each fail mode.
- fail-no-negation-token, fail-no-negation-evidence-list, fail-no-flip-clause.
- Three real anchors:
    A. DRILL-2 R60-bounded "drop" without framing.
    B. Wave 3 dedup "exhausted" without framing.
    C. iter-1 dropped-items resurrection "0/16 salvageable" without framing.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _REPO_ROOT / "tools" / "salvage-negation-verdict-check.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("salvage_negation_verdict_check", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


GATE = _import_tool()


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _in_scope_lane_path(root: Path) -> Path:
    """Build a path that matches the trigger surface."""
    p = root / "reports" / "v3_iter_2026-05-26_iter1" / "lane_TEST" / "results.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _in_scope_agent_path(root: Path) -> Path:
    p = root / "agent_outputs" / "some_lane" / "results.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _in_scope_killed_path(root: Path) -> Path:
    p = root / "submissions" / "spark" / "_killed" / "leadXX" / "report.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _full_framing_body() -> str:
    return (
        "# Lane results\n\n"
        "## Verdict\n\n"
        "DROP-CONFIRMED after exhaustive enumeration; finding is not salvageable.\n\n"
        "## Negation evidence\n\n"
        "- Halmos: timeout at depth 7 after 30 min\n"
        "- Foundry 1M fuzz: 0 counterexamples in 1,000,000 runs\n"
        "- Differential vs reference impl: bit-equal across 50K inputs\n"
        "- Mythril: PASS no SWC-101 detected\n\n"
        "## What would flip this\n\n"
        "A new callsite of `_transferTokensFromTrap` reachable by an unauthorised\n"
        "caller would re-open the verdict. Specifically, any callsite that bypasses\n"
        "the `onlyOwner` modifier at OracleManager.sol:142 invalidates the negation.\n"
    )


# ---------------------------------------------------------------------------
# Case 1: out-of-scope path.
# ---------------------------------------------------------------------------
class TestOutOfScope(unittest.TestCase):
    def test_random_path_passes_oos(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "docs" / "random.md"
        _write(p, "DROP-CONFIRMED with full negation evidence.\n")
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_OOS)


# ---------------------------------------------------------------------------
# Case 2 / 3: in-scope no verdict-language.
# ---------------------------------------------------------------------------
class TestNoVerdictLanguage(unittest.TestCase):
    def test_lane_results_no_verdict_language(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        _write(p, "## Findings\nThe finding is HIGH-confirmed; PoC builds clean.\n")
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_NO_VERDICT)

    def test_killed_subtree_no_verdict_language(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_killed_path(tmp)
        # Body must avoid every trigger phrase; the file lives under the
        # _killed/ subtree (in-scope) but its prose makes no verdict claim.
        _write(
            p,
            "# Lead notes\n"
            "Original hypothesis: re-entrancy on _claim(). Source review showed\n"
            "guards in place. Done.\n",
        )
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_NO_VERDICT)


# ---------------------------------------------------------------------------
# Case 4 / 5 / 6: complete framing passes.
# ---------------------------------------------------------------------------
class TestCompleteFramingPasses(unittest.TestCase):
    def test_full_framing_lane_results(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        _write(p, _full_framing_body())
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_COMPLETE)
        self.assertEqual(r["evidence"]["negation_token"], "DROP-CONFIRMED")
        self.assertGreaterEqual(r["evidence"]["negation_evidence_row_count"], 3)
        self.assertTrue(r["evidence"]["has_flip_clause"])

    def test_full_framing_agent_outputs(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_agent_path(tmp)
        _write(p, _full_framing_body())
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_COMPLETE)

    def test_full_framing_killed_subtree(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_killed_path(tmp)
        body = _full_framing_body().replace("DROP-CONFIRMED", "KILLED-CONFIRMED")
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_COMPLETE)
        self.assertEqual(r["evidence"]["negation_token"], "KILLED-CONFIRMED")


# ---------------------------------------------------------------------------
# Case 7 / 8 / 9: each fail mode.
# ---------------------------------------------------------------------------
class TestFailModes(unittest.TestCase):
    def test_fail_no_negation_token(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "## Verdict\n\n"
            "The drilled-down finding is exhausted. Nothing further to investigate.\n"
            "## Negation evidence\n"
            "- Halmos: timeout at depth 7\n"
            "- Foundry 1M fuzz: 0 counterexamples\n"
            "- differential vs reference impl: bit-equal\n"
            "## What would flip this\n"
            "A new unauthorised callsite of _claim().\n"
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_TOKEN)

    def test_fail_no_negation_evidence_list(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "## Verdict\n\n"
            "EXHAUSTION-CONFIRMED.\n\n"
            "## Negation evidence\n\n"
            "- Halmos: timeout at depth 7\n"
            "- Foundry 1M fuzz: 0 counterexamples\n\n"
            "## What would flip this\n\n"
            "A new callsite.\n"
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_EVIDENCE)
        self.assertEqual(r["evidence"]["negation_evidence_row_count"], 2)

    def test_fail_no_flip_clause(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "## Verdict\n\n"
            "NOT-SALVAGEABLE-CONFIRMED across 3 angles.\n\n"
            "## Negation evidence\n\n"
            "- Halmos: timeout at depth 7\n"
            "- Foundry 1M fuzz: 0 counterexamples\n"
            "- Differential vs ref impl: bit-equal across 50K inputs\n"
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_FLIP)


# ---------------------------------------------------------------------------
# Case 10 / 11 / 12: rebuttal accepted for each fail mode.
# ---------------------------------------------------------------------------
class TestRebuttalAcceptedForEachFailMode(unittest.TestCase):
    REBUTTAL_HTML = "<!-- gap37b-rebuttal: operator approved drop pending fresh anchors -->\n"
    REBUTTAL_VISIBLE = "gap37b-rebuttal: operator-approved exception per iter-12 SKILL.md\n"

    def test_rebuttal_html_comment_overrides_no_token(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "Verdict: dropped after review.\n"
            + self.REBUTTAL_HTML
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_OK_REBUTTAL)
        self.assertIn("operator approved drop", r["reason"])

    def test_rebuttal_visible_line_overrides_no_evidence(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "## Verdict\nEXHAUSTION-CONFIRMED.\n"
            "## Negation evidence\n- Halmos: timeout\n"
            "## What would flip this\nNew callsite.\n"
            + self.REBUTTAL_VISIBLE
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_OK_REBUTTAL)

    def test_rebuttal_html_overrides_no_flip(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "## Verdict\nDROP-CONFIRMED.\n"
            "## Negation evidence\n"
            "- Halmos: timeout at depth 7\n"
            "- Foundry 1M fuzz: 0 counterexamples\n"
            "- Differential vs ref impl: bit-equal\n"
            + self.REBUTTAL_HTML
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_OK_REBUTTAL)


# ---------------------------------------------------------------------------
# Case 13: oversized rebuttal ignored.
# ---------------------------------------------------------------------------
class TestRebuttalLimits(unittest.TestCase):
    def test_oversized_rebuttal_ignored(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        long_reason = "x" * 300
        body = (
            "Verdict: dropped.\n"
            f"<!-- gap37b-rebuttal: {long_reason} -->\n"
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        # Oversized rebuttal is ignored => original fail verdict stands
        # (no token in body => fail-no-negation-token).
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_TOKEN)

    def test_empty_rebuttal_ignored(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = (
            "Verdict: dropped.\n"
            "<!-- gap37b-rebuttal:  -->\n"
        )
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_TOKEN)


# ---------------------------------------------------------------------------
# Case 14 / 15: missing file + JSON CLI round-trip.
# ---------------------------------------------------------------------------
class TestErrorAndCli(unittest.TestCase):
    def test_missing_file_error(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "reports" / "v3_iter_2026-05-26_iter1" / "lane_X" / "missing.md"
        # Don't create p; we still want trigger-surface match.
        r = GATE.evaluate(p, strict=False)
        # NB: trigger surface only applies if the path matches; for a
        # missing file with an in-surface path, evaluate() short-circuits
        # on existence first.
        self.assertEqual(r["verdict"], GATE.V_ERROR)

    def test_main_json_cli_passes(self):
        import io
        import contextlib

        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        _write(p, _full_framing_body())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = GATE.main([str(p), "--json"])
        self.assertEqual(rc, 0)
        import json as _json
        payload = _json.loads(buf.getvalue())
        self.assertEqual(payload["verdict"], GATE.V_PASS_COMPLETE)
        self.assertEqual(payload["schema"], GATE.SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# Real anchor A: DRILL-2 R60-bounded "drop" without framing.
# ---------------------------------------------------------------------------
class TestAnchorA_Drill2R60(unittest.TestCase):
    """Anchor A: HYPERBRIDGE-DRILL-2 R60-bounded results.md declared
    "drop" without an explicit negation-framing token, evidence rows, or
    flip clause. The gate must catch this and emit fail-no-negation-token.
    """

    def test_drill2_drop_without_framing_fails_no_token(self):
        tmp = Path(tempfile.mkdtemp())
        p = (
            tmp / "reports" / "v3_iter_2026-05-26_iter1"
            / "lane_HYPERBRIDGE-DRILL-2" / "results.md"
        )
        _write(
            p,
            "# HYPERBRIDGE-DRILL-2 results\n\n"
            "## Verdict\n\n"
            "R60-bounded; drop after 3-angle source-anchored enumeration.\n"
            "Lane DROPPED. Move on.\n",
        )
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_TOKEN)


# ---------------------------------------------------------------------------
# Real anchor B: Wave 3 dedup "exhausted" without framing.
# ---------------------------------------------------------------------------
class TestAnchorB_Wave3Dedup(unittest.TestCase):
    """Anchor B: Wave-3 dedup lane wrote "exhausted" without explicit
    framing token or evidence list. Gate must emit fail-no-negation-token.
    """

    def test_wave3_dedup_exhausted_without_framing_fails(self):
        tmp = Path(tempfile.mkdtemp())
        p = (
            tmp / "agent_outputs" / "wave3_dedup_lane" / "results.md"
        )
        _write(
            p,
            "# Wave 3 dedup outcomes\n\n"
            "After running the dedup pass we believe the candidate set is\n"
            "exhausted; no further dedup work is warranted.\n",
        )
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_TOKEN)


# ---------------------------------------------------------------------------
# Real anchor C: iter-1 dropped-items resurrection "0/16 salvageable".
# ---------------------------------------------------------------------------
class TestAnchorC_Iter1DroppedItemsResurrection(unittest.TestCase):
    """Anchor C: iter-1 dropped-items resurrection lane declared
    "0/16 salvageable" without any framing or evidence rows. Gate must
    catch this as fail-no-negation-token.
    """

    def test_iter1_resurrection_0_of_16_salvageable_fails(self):
        tmp = Path(tempfile.mkdtemp())
        p = (
            tmp / "reports" / "v3_iter_2026-05-23_iter1"
            / "lane_DROPPED-ITEMS-RESURRECTION" / "results.md"
        )
        _write(
            p,
            "# Dropped-items resurrection (iter-1)\n\n"
            "## Verdict\n\n"
            "0/16 salvageable. Closing the resurrection lane.\n",
        )
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_FAIL_NO_TOKEN)


# ---------------------------------------------------------------------------
# Extra Case: token present but rebuttal also present => pass-complete wins
# (rebuttal only applies when framing is missing).
# ---------------------------------------------------------------------------
class TestTokenWinsOverRebuttal(unittest.TestCase):
    def test_complete_framing_short_circuits_rebuttal(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        body = _full_framing_body() + "\n<!-- gap37b-rebuttal: extra -->\n"
        _write(p, body)
        r = GATE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], GATE.V_PASS_COMPLETE)


if __name__ == "__main__":
    unittest.main()
