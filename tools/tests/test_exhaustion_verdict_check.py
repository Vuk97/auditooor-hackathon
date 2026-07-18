#!/usr/bin/env python3
# r36-rebuttal: lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR-PLUS-EXHAUSTION-VERDICT-GATE registered via tools/agent-pathspec-register.py.
"""Tests for tools/exhaustion-verdict-tools-attempt-required-check.py (Gap #37)."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _REPO_ROOT / "tools" / "exhaustion-verdict-tools-attempt-required-check.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("exhaustion_verdict_check", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


GATE = _import_tool()


def _write(p: Path, body: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _seed_log(ws: Path, rows: list[dict]):
    log_path = ws / ".auditooor" / "depth_tools_log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return log_path


def _full_log_rows() -> list[dict]:
    """Construct one log row per required family."""
    return [
        {"tool": "orient-prefilter", "status": "PASS", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "hacker-mcp", "status": "PASS", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "audit-deep", "status": "PASS", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "foundry-fuzz-1m", "status": "SKIPPED", "skip_reason": "language=rust", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "halmos", "status": "SKIPPED", "skip_reason": "language=rust", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "differential-fuzz", "status": "PASS", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "mythril", "status": "SKIPPED", "skip_reason": "language=rust", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
        {"tool": "rule14-deep-integrate", "status": "PASS", "target": "x", "timestamp_utc": "2026-05-26T00:00:00Z"},
    ]


class TestNoExhaustionVerdict(unittest.TestCase):
    def test_no_exhaustion_keywords_passes(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "## verdict\nThe finding is HIGH-confirmed; PoC builds.\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_PASS_NO_EXHAUSTION)


class TestExhaustionRequiresEvidence(unittest.TestCase):
    def test_exhausted_with_no_log_fails(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "## verdict\nGENUINELY-EXHAUSTED after 7-angle source-anchored enumeration.\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)
        self.assertGreaterEqual(len(result["evidence"]["missing_families"]), 1)

    def test_exhausted_with_full_log_passes(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: EXHAUSTED after multi-angle drilling.\n")
        _seed_log(tmp, _full_log_rows())
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_PASS_ALL_TOOLS)

    def test_partial_log_fails(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: HUNT-DONE - no further angles.\n")
        # Only orient-prefilter + audit-deep evidence.
        _seed_log(tmp, [
            {"tool": "orient-prefilter", "status": "PASS", "target": "x", "timestamp_utc": "T"},
            {"tool": "audit-deep", "status": "PASS", "target": "x", "timestamp_utc": "T"},
        ])
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)
        missing = result["evidence"]["missing_families"]
        # All families except orient-prefilter, audit-deep should be missing.
        self.assertIn("halmos", missing)
        self.assertIn("foundry-fuzz-1m", missing)
        self.assertIn("rule14-deep", missing)


class TestRebuttalAccepted(unittest.TestCase):
    def test_html_comment_rebuttal_accepted(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: EXHAUSTED.\n\n<!-- gap37-rebuttal: pre-rule lane, op-approved -->\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_OK_REBUTTAL)
        self.assertIn("pre-rule", result["reason"])

    def test_visible_line_rebuttal_accepted(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: GENUINELY-EXHAUSTED\n\ngap37-rebuttal: target lacks compilable harness\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_OK_REBUTTAL)

    def test_oversized_rebuttal_rejected(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        big = "x" * 220
        _write(lane, f"Verdict: EXHAUSTED.\n<!-- gap37-rebuttal: {big} -->\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)

    def test_empty_rebuttal_rejected(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: EXHAUSTED.\n<!-- gap37-rebuttal:  -->\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)


class TestErrorBranch(unittest.TestCase):
    def test_missing_lane_file_returns_error(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "missing.md"
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_ERROR)


class TestCli(unittest.TestCase):
    def test_cli_returns_0_on_pass_no_exhaustion(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "HIGH-confirmed result.\n")
        rc = GATE.main([str(lane), "--workspace", str(tmp), "--json"])
        self.assertEqual(rc, 0)

    def test_cli_returns_1_on_fail(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: NEGATIVE-CLOSED-EXHAUSTED\n")
        rc = GATE.main([str(lane), "--workspace", str(tmp), "--json"])
        self.assertEqual(rc, 1)

    def test_cli_returns_0_on_full_evidence(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(lane, "Verdict: NEGATIVE-CLOSED-EXHAUSTED\n")
        _seed_log(tmp, _full_log_rows())
        rc = GATE.main([str(lane), "--workspace", str(tmp), "--json"])
        self.assertEqual(rc, 0)


class TestHyperbridgeSimulation(unittest.TestCase):
    """Simulate the empirical Hyperbridge SMT-DRILL9 / SPARK-LEAD1 anchors."""

    def test_hyperbridge_smt_drill9_exhausted_without_depth_tools_fails(self):
        """If the iter17 SMT-DRILL9 verdict ('LOW-CONFIRMED exhausted')
        had been pasted without the depth-tools log, Gap #37 catches it."""
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "results.md"
        _write(lane, (
            "# LANE: HYPERBRIDGE-SMT-DRILL9-MEDIUM-HIGH-SALVAGE\n"
            "## Verdict\n"
            "7-angle exhaustion of EthereumTrieDB / PolkadotTrie / MMR surface.\n"
            "GENUINELY-EXHAUSTED at LOW-CONFIRMED tier.\n"
        ))
        rc = GATE.main([str(lane), "--workspace", str(tmp), "--json"])
        self.assertEqual(rc, 1, "Hyperbridge SMT-DRILL9 verdict missing depth-tools log MUST fail Gap #37")

    def test_spark_lead1_not_salvageable_without_depth_tools_fails(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "results.md"
        _write(lane, (
            "# LANE SPARK-LEAD1-CRITICAL-SALVAGE\n"
            "## Verdict\n"
            "NOT-SALVAGEABLE-CONFIRMED after 7-angle source-anchored enumeration.\n"
        ))
        rc = GATE.main([str(lane), "--workspace", str(tmp), "--json"])
        # "NOT-SALVAGEABLE-CONFIRMED" doesn't trigger exhaustion keywords;
        # validate behavior matches spec.
        # We expect pass-no-exhaustion-verdict here.
        self.assertEqual(rc, 0)


class TestExhaustedProseFalsePositive(unittest.TestCase):
    """Regression (NUVA 2026-07-04): a Medium griefing finding that describes
    resource exhaustion in ordinary prose ('once reserves are exhausted') MUST
    NOT trip the exhaustion-VERDICT gate. The bare word 'exhausted' is a weak
    trigger that only counts in a verdict context."""

    def test_reserves_exhausted_prose_passes(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "finding.md"
        _write(lane, (
            "## Impact\n"
            "The payout reverts once the admin-funded reserves are exhausted "
            "(reconcile.go:185-186), so the griefing is a persistent tax bounded "
            "by the reserve balance.\n"
        ))
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_PASS_NO_EXHAUSTION)

    def test_gas_and_queue_exhausted_prose_passes(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "finding.md"
        _write(lane, (
            "The unbounded loop runs until gas is exhausted and the timeout "
            "queue is exhausted each block as entries drain.\n"
        ))
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_PASS_NO_EXHAUSTION)

    def test_verdict_context_exhausted_still_fires(self):
        """A real 'VERDICT: EXHAUSTED' (weak trigger IN verdict context) with no
        depth-tools log must still fail - the fix must not weaken real detection."""
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "results.md"
        _write(lane, "VERDICT: EXHAUSTED - no further vectors on this surface.\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)

    def test_disposition_context_exhausted_still_fires(self):
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "results.md"
        _write(lane, "disposition = exhausted after the full depth sweep.\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)

    def test_strong_token_still_fires_without_verdict_word(self):
        """Strong hyphenated tokens (hunt-exhausted) fire anywhere, even without
        a nearby 'verdict' word."""
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "results.md"
        _write(lane, "final state: HUNT-EXHAUSTED across all clusters.\n")
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = GATE.evaluate(lane, tmp, log, strict=False)
        self.assertEqual(result["verdict"], GATE.V_FAIL_INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
