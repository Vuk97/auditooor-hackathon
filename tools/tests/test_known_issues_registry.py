"""Guard: RANK-2 known-issues registry wiring.

The structured per-workspace registry .auditooor/known_issues.json (schema
auditooor.known_issues.v1) was read ONLY by falsification-triage. This guard
covers the new shared lib (tools/lib/known_issues_registry.py) AND proves that a
registered acknowledged-OOS keyword is now surfaced by at least one downstream
consumer:

  - the hunt-dispatch ranker hard-zeros a matching question with the distinct
    verdict 'skip-known-issue-registry' (was: ranked + fanned out to a paid
    agent), and
  - the R47 paste-ready acknowledged-wont-fix gate surfaces the registry-declared
    acknowledgement in its workspace ack scan.

All additive: an EMPTY/ABSENT registry leaves every consumer's behavior
unchanged, and an in-scope ('open') issue is NOT suppressed.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_PATH = REPO_ROOT / "tools" / "lib" / "known_issues_registry.py"
RANKER_PATH = REPO_ROOT / "tools" / "per-fn-question-ranker.py"
ACK_PATH = REPO_ROOT / "tools" / "acknowledged-wont-fix-check.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


registry = _load_module("known_issues_registry_test", LIB_PATH)
ranker = _load_module("per_fn_question_ranker_test", RANKER_PATH)
ack_check = _load_module("acknowledged_wont_fix_check_test", ACK_PATH)


def _write_registry(ws: Path, issues: list) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "known_issues.json").write_text(
        json.dumps({"schema": "auditooor.known_issues.v1", "issues": issues}),
        encoding="utf-8",
    )


ACK_ISSUE = {
    "id": "KI-01",
    "title": "delayed liquidation bad debt is acknowledged",
    "status": "acknowledged-oos",
    "keywords": ["delayed", "liquidation", "baddebt"],
    "invariant_hints": ["solvency"],
    "source": "prior_audits/quantstamp.txt#e",
}
OPEN_ISSUE = {
    "id": "KI-99",
    "title": "live in-scope reentrancy",
    "status": "open",
    "keywords": ["reentrancy", "withdraw", "callback"],
}


class TestKnownIssuesRegistryLib(unittest.TestCase):
    def test_loads_only_oos_statuses(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_registry(ws, [ACK_ISSUE, OPEN_ISSUE])
            oos = registry.load_known_oos(ws)
            ids = {i["id"] for i in oos}
            self.assertIn("KI-01", ids)
            self.assertNotIn("KI-99", ids, "open issue must NOT be returned as OOS")
            row = next(i for i in oos if i["id"] == "KI-01")
            self.assertEqual(row["status"], "acknowledged-oos")
            self.assertIn("liquidation", row["keywords"])
            self.assertIn("solvency", row["invariant_hints"])

    def test_absent_registry_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(registry.load_known_oos(Path(td)), [])

    def test_malformed_registry_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".auditooor" / "known_issues.json").write_text("{not json", encoding="utf-8")
            self.assertEqual(registry.load_known_oos(ws), [])

    def test_keyword_terms_helper(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_registry(ws, [ACK_ISSUE])
            terms = registry.oos_keyword_terms(ws)
            self.assertEqual(len(terms), 1)
            issue_id, term_list = terms[0]
            self.assertEqual(issue_id, "KI-01")
            self.assertIn("solvency", term_list)


class TestRankerConsumer(unittest.TestCase):
    """A question matching a registered acknowledged-OOS issue must hard-zero with
    the distinct 'skip-known-issue-registry' verdict (was ranked + dispatched)."""

    def _score(self, ws: Path, question_text: str):
        oos_patterns = ranker.load_bug_bounty_oos(ws)
        q = {"question": question_text, "function": "fn", "file": "src/X.sol",
             "unit_id": "src/X.sol::fn"}
        return ranker.score_question(
            q, oos_patterns, [], {}, {}, {}, {"idx": {}, "file_idx": {}})

    def test_registered_oos_keyword_is_surfaced_as_hard_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_registry(ws, [ACK_ISSUE])
            res = self._score(
                ws, "Can a delayed liquidation create baddebt breaking solvency?")
            self.assertEqual(res["verdict"], "skip-known-issue-registry")
            self.assertEqual(res["score"], 0.0)

    def test_unrelated_question_not_suppressed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_registry(ws, [ACK_ISSUE])
            res = self._score(ws, "Does setOwner lack an access-control check?")
            self.assertNotEqual(res["verdict"], "skip-known-issue-registry")

    def test_open_issue_does_not_suppress(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_registry(ws, [OPEN_ISSUE])
            res = self._score(
                ws, "Is there a reentrancy in withdraw via the callback?")
            self.assertNotEqual(res["verdict"], "skip-known-issue-registry")


class TestAckCheckConsumer(unittest.TestCase):
    """The R47 workspace ack scan must surface a registry-declared acknowledgement
    even when no prose .md/.txt doc mentions it."""

    def test_registry_ack_surfaced_in_scan(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_registry(ws, [ACK_ISSUE])
            hits = ack_check._registry_ack_hits(ws)
            self.assertTrue(hits, "registry acknowledgement must produce a hit")
            self.assertTrue(any("KI-01" in (h.get("text") or "") for h in hits))
            self.assertTrue(all(
                h["source_file"].endswith("known_issues.json") for h in hits))

    def test_absent_registry_no_hits(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(ack_check._registry_ack_hits(Path(td)), [])


if __name__ == "__main__":
    unittest.main()
