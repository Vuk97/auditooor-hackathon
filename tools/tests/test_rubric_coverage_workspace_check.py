# <!-- r36-rebuttal: lane-L37-RUBRIC-COVERAGE registered in .auditooor/agent_pathspec.json -->
"""Tests for tools/rubric-coverage-workspace-check.py (WORKSPACE rubric coverage).

The SECOND coverage axis (complement of finite-A's SURFACE coverage):
"for the program SEVERITY.md, did the workspace produce >=1 candidate for each
impact/severity ROW?".

Coverage:
  (a) some-but-not-all rows -> correct uncovered-row set.
  (b) uncovered rows appear in the L37 audit-completeness gate verdict
      (surfaced, not hidden).
  (c) honest-match: a candidate whose impact does NOT match a row does NOT
      mark it covered.
  (d) generic: no target/program literal hard-coded in the tool's behavior.
  plus: no SEVERITY.md -> fail; no rows -> fail; --write-report artifact;
        full-coverage pass; malformed report at gate.

Deterministic, stdlib-only, offline.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
TOOL = TOOLS / "rubric-coverage-workspace-check.py"
L37_TOOL = TOOLS / "audit-completeness-check.py"


# Load the tool as a module for direct unit calls (hyphenated filename).
def _load_module():
    spec = importlib.util.spec_from_file_location(
        "_rubric_coverage_ws_check", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_rubric_coverage_ws_check"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


# A GENERIC 3-row rubric (NO real target/program literal). The rows span three
# distinct impact classes so we can test partial coverage and honest match.
_GENERIC_SEVERITY_MD = """\
# Severity rubric

### Critical

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| CRIT-1 | Direct loss of funds | high |
| CRIT-2 | Permanent freezing of funds | mid |

### High

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| HIGH-1 | Governance takeover | low |
"""


def _run(ws: Path, *extra):
    proc = subprocess.run(
        [sys.executable, str(TOOL), str(ws), "--json", *extra],
        capture_output=True, text=True,
    )
    return proc.returncode, json.loads(proc.stdout)


def _run_l37(ws: Path):
    proc = subprocess.run(
        [sys.executable, str(L37_TOOL), str(ws), "--json"],
        capture_output=True, text=True,
    )
    return proc.returncode, json.loads(proc.stdout)


class RubricCoverageWorkspaceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.ws = self._tmp / "ws"
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    # ---- (a) some-but-not-all rows: correct uncovered-row set ----
    def test_partial_coverage_uncovered_row_set(self):
        _write(self.ws / "SEVERITY.md", _GENERIC_SEVERITY_MD)
        # Two candidates: one covers CRIT-1 (loss of funds), one covers HIGH-1
        # (governance takeover). NOBODY attempts CRIT-2 (freeze).
        _write_json(self.ws / ".auditooor" / "exploit_queue.json", {
            "queue": [
                {"title": "Attacker drains the vault - direct loss of funds for users"},
                {"title": "Malicious proposer takes over governance via vote forgery"},
            ],
        })
        rc, out = _run(self.ws)
        self.assertEqual(rc, 0)
        self.assertEqual(out["verdict"], "pass-rubric-coverage-report")
        self.assertEqual(out["total_rows"], 3)
        self.assertEqual(out["rows_with_candidate"], 2)
        self.assertEqual(out["rows_uncovered"], 1)
        # The uncovered row MUST be exactly CRIT-2 (permanent freezing).
        unc_ids = {r["rubric_id"] for r in out["uncovered_rows"]}
        self.assertEqual(unc_ids, {"CRIT-2"})
        self.assertIn("freezing", out["uncovered_rows"][0]["sentence"].lower())
        # And the covered rows are exactly CRIT-1 + HIGH-1.
        cov_ids = {r["rubric_id"] for r in out["covered_rows"]}
        self.assertEqual(cov_ids, {"CRIT-1", "HIGH-1"})

    # ---- (b) uncovered rows surfaced in the L37 gate verdict ----
    def test_uncovered_rows_surfaced_in_l37_verdict(self):
        # Build a partial rubric_coverage_report.json directly and assert L37's
        # rubric-coverage signal surfaces the uncovered rows (not hidden).
        _write_json(self.ws / ".auditooor" / "rubric_coverage_report.json", {
            "schema": "auditooor.workspace_rubric_coverage.v1",
            "workspace": "ws", "total_rows": 3, "rows_with_candidate": 1,
            "rows_uncovered": 2, "rubric_coverage_fraction": 0.333333,
            "candidates_scanned": 1,
            "uncovered_rows": [
                {"tier": "critical", "rubric_id": "CRIT-2",
                 "sentence": "Permanent freezing of funds"},
                {"tier": "high", "rubric_id": "HIGH-1",
                 "sentence": "Governance takeover"},
            ],
            "covered_rows": [], "rows": [],
        })
        rc, out = _run_l37(self.ws)
        sig = [s for s in out["signals"] if s["signal"] == "rubric-coverage"][0]
        # Signal PASSES (presence is the requirement; low coverage is a WARN).
        self.assertTrue(sig["ok"], sig)
        # But the uncovered impact classes MUST be surfaced.
        self.assertIn("UNATTEMPTED", sig["reason"])
        self.assertIn("CRIT-2", sig["reason"])
        # The top-level result carries the loud warn + uncovered rows.
        self.assertIsNotNone(out.get("rubric_coverage_warn"))
        self.assertTrue(any("CRIT-2" in lbl for lbl in out["rubric_uncovered_rows"]))
        self.assertTrue(any("HIGH-1" in lbl for lbl in out["rubric_uncovered_rows"]))

    def test_l37_fails_closed_when_no_rubric_coverage_report(self):
        # No report at all -> the signal fails closed (mirrors coverage-map).
        rc, out = _run_l37(self.ws)
        sig = [s for s in out["signals"] if s["signal"] == "rubric-coverage"][0]
        self.assertFalse(sig["ok"], sig)
        self.assertEqual(sig["verdict"], "fail-no-rubric-coverage")

    def test_l37_fails_closed_on_malformed_report(self):
        _write_json(self.ws / ".auditooor" / "rubric_coverage_report.json", {
            "schema": "auditooor.workspace_rubric_coverage.v1",
            # missing total_rows / rows_uncovered / rubric_coverage_fraction
        })
        rc, out = _run_l37(self.ws)
        sig = [s for s in out["signals"] if s["signal"] == "rubric-coverage"][0]
        self.assertFalse(sig["ok"], sig)
        self.assertEqual(sig["verdict"], "fail-no-rubric-coverage")
        self.assertIn("malformed", sig["reason"].lower())

    # ---- (c) honest-match: non-matching candidate does NOT mark a row covered ----
    def test_honest_match_vague_candidate_does_not_cover(self):
        _write(self.ws / "SEVERITY.md", _GENERIC_SEVERITY_MD)
        # A candidate whose impact wording is UNRELATED to any rubric row. It
        # must NOT inflate coverage of ANY row.
        _write_json(self.ws / ".auditooor" / "exploit_queue.json", {
            "queue": [
                {"title": "Event is emitted with a slightly stale timestamp value"},
                {"title": "Gas usage is marginally higher than optimal in a view"},
            ],
        })
        rc, out = _run(self.ws)
        self.assertEqual(out["rows_with_candidate"], 0)
        self.assertEqual(out["rows_uncovered"], 3)
        self.assertEqual(out["rubric_coverage_fraction"], 0.0)

    def test_honest_match_unit_level_direct(self):
        # Direct unit assertion on the honest-match helper: a freeze-row is only
        # covered by a candidate that genuinely mentions a freeze noun.
        self.assertTrue(MOD._candidate_covers_row(
            "user funds are permanently frozen and locked forever",
            "Permanent freezing of funds"))
        self.assertFalse(MOD._candidate_covers_row(
            "the contract emits a duplicate event on re-entry",
            "Permanent freezing of funds"))
        # A loss-row is not covered by a freeze candidate (class separation).
        self.assertFalse(MOD._candidate_covers_row(
            "funds are frozen but recoverable later",
            "Direct loss of funds"))
        self.assertTrue(MOD._candidate_covers_row(
            "attacker drains the pool, direct theft of user funds",
            "Direct loss of funds"))

    # ---- (d) generic: no target/program literal; full coverage pass ----
    def test_full_coverage_pass(self):
        _write(self.ws / "SEVERITY.md", _GENERIC_SEVERITY_MD)
        _write_json(self.ws / ".auditooor" / "exploit_queue.json", {
            "queue": [
                {"title": "Attacker drains the vault, direct loss of funds"},
                {"title": "Permanent freezing of funds locks user balances forever"},
                {"title": "Governance takeover via forged votes seizes control"},
            ],
        })
        rc, out = _run(self.ws)
        self.assertEqual(out["rows_with_candidate"], 3)
        self.assertEqual(out["rows_uncovered"], 0)
        self.assertEqual(out["rubric_coverage_fraction"], 1.0)
        self.assertFalse(out["low_coverage_warn"])

    def test_candidates_from_submissions_drafts(self):
        # Candidates are also enumerated from submission drafts, not just the
        # exploit queue.
        _write(self.ws / "SEVERITY.md", _GENERIC_SEVERITY_MD)
        draft = self.ws / "submissions" / "staging" / "freeze-bug" / "freeze-bug.md"
        _write(draft,
               "# Permanent freezing of funds in the escrow path\n\n"
               "## Impact\n\nUser funds become permanently frozen and "
               "irrecoverable.\n")
        # SUBMISSIONS.md bookkeeping must NOT be scored as a candidate.
        _write(self.ws / "submissions" / "SUBMISSIONS.md",
               "# tracker\n\n- direct loss of funds in some draft\n")
        rc, out = _run(self.ws)
        cov_ids = {r["rubric_id"] for r in out["covered_rows"]}
        self.assertIn("CRIT-2", cov_ids)  # the freeze draft covers CRIT-2
        # The tracker file's "direct loss of funds" line must NOT have covered
        # CRIT-1 (it is bookkeeping, skipped).
        self.assertNotIn("CRIT-1", cov_ids)

    # ---- fail branches ----
    def test_fail_no_severity_md(self):
        _write_json(self.ws / ".auditooor" / "exploit_queue.json",
                    {"queue": [{"title": "loss of funds"}]})
        rc, out = _run(self.ws)
        self.assertEqual(rc, 1)
        self.assertEqual(out["verdict"], "fail-no-severity-md")

    def test_fail_no_rubric_rows(self):
        # SEVERITY.md present but with no parseable tier rows.
        _write(self.ws / "SEVERITY.md", "# Severity\n\nNo tiers here at all.\n")
        rc, out = _run(self.ws)
        self.assertEqual(rc, 1)
        self.assertEqual(out["verdict"], "fail-no-rubric-rows")

    # ---- --write-report artifact ----
    def test_write_report_artifact(self):
        _write(self.ws / "SEVERITY.md", _GENERIC_SEVERITY_MD)
        _write_json(self.ws / ".auditooor" / "exploit_queue.json",
                    {"queue": [{"title": "direct loss of funds drain"}]})
        rc, out = _run(self.ws, "--write-report")
        self.assertEqual(rc, 0)
        report = self.ws / ".auditooor" / "rubric_coverage_report.json"
        self.assertTrue(report.is_file())
        obj = json.loads(report.read_text())
        self.assertEqual(obj["schema"], "auditooor.workspace_rubric_coverage.v1")
        self.assertEqual(obj["total_rows"], 3)

    def test_error_on_missing_workspace(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(self._tmp / "nope"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        out = json.loads(proc.stdout)
        self.assertEqual(out["verdict"], "error")


if __name__ == "__main__":
    unittest.main()
