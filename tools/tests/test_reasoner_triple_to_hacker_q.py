"""Guard: reasoner-triple-to-hacker-q lifts each _REASONER_LEDGERS reasoner's
docstring LOGIC TRIPLE / REASONING QUERY into the flat hacker-question library as
an OPEN question, append-only + dedup-safe, routing-integrity-safe, no em-dashes.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "reasoner-triple-to-hacker-q.py"
CHECK = ROOT / "tools" / "logic-obligation-resolution-check.py"
TOOLS = ROOT / "tools"


def _load():
    spec = importlib.util.spec_from_file_location("reasoner_triple_hq", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestReasonerTripleToHackerQ(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_parses_every_ledger_and_builds_one_row_each(self):
        ledgers = self.m.iter_reasoner_ledgers(CHECK)
        self.assertGreaterEqual(len(ledgers), 30, "expected ~40 reasoner ledgers")
        rows, skipped = self.m.build_all_rows(CHECK, TOOLS)
        # Every ledger tool exists + has a docstring in a healthy tree.
        self.assertEqual(skipped, [], f"unexpected skips: {skipped}")
        self.assertEqual(len(rows), len(ledgers))

    def test_rows_are_open_questions_sourced_and_dash_clean(self):
        rows, _ = self.m.build_all_rows(CHECK, TOOLS)
        ids = set()
        for r in rows:
            self.assertTrue(r["question_text"].endswith("?"),
                            f"not an open question: {r['reasoner_tool']}")
            self.assertTrue(r["source"].startswith("reasoner-triple:"),
                            f"missing reasoner-triple source: {r}")
            self.assertNotIn("—", r["question_text"], "em-dash leaked from source")
            self.assertNotIn("–", r["question_text"], "en-dash leaked from source")
            self.assertNotIn(".py", r["question_text"], "filename echo in question")
            self.assertGreater(len(r["question_text"]), 60, "question too thin")
            # question_id must be unique across reasoners
            self.assertNotIn(r["question_id"], ids)
            ids.add(r["question_id"])
            # routing-safe: stored target_languages cover the derived natives
            nat = set(r.get("native_target_languages") or [])
            stored = set(r.get("target_languages") or [])
            self.assertTrue(nat <= stored,
                            f"routing mismatch {r['reasoner_tool']}: {nat} !<= {stored}")

    def test_append_is_dedup_safe_and_grows_only_by_new(self):
        with tempfile.TemporaryDirectory() as td:
            lib = Path(td) / "hacker_questions_library.jsonl"
            # seed one pre-existing unrelated row
            lib.write_text(json.dumps({"question_id": "HQ-EXISTING-1",
                                       "question_text": "pre?",
                                       "source": "case-study:x"}) + "\n",
                           encoding="utf-8")
            argv = ["--library", str(lib), "--check-path", str(CHECK),
                    "--tools-dir", str(TOOLS)]
            import sys
            old = sys.argv
            try:
                sys.argv = ["reasoner-triple-to-hacker-q.py"] + argv
                rc1 = self.m.main()
            finally:
                sys.argv = old
            self.assertEqual(rc1, 0)
            lines1 = [l for l in lib.read_text().splitlines() if l.strip()]
            new1 = [json.loads(l) for l in lines1
                    if json.loads(l).get("source", "").startswith("reasoner-triple:")]
            self.assertGreaterEqual(len(new1), 30, "library did not grow by reasoner rows")
            self.assertEqual(len(lines1), 1 + len(new1), "seed row must be preserved")

            # second run must be a no-op (append-only + dedup by source/question_id)
            try:
                sys.argv = ["reasoner-triple-to-hacker-q.py"] + argv
                rc2 = self.m.main()
            finally:
                sys.argv = old
            self.assertEqual(rc2, 0)
            lines2 = [l for l in lib.read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines2), len(lines1), "re-run must not duplicate rows")

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            lib = Path(td) / "lib.jsonl"
            lib.write_text("", encoding="utf-8")
            import sys
            old = sys.argv
            try:
                sys.argv = ["reasoner-triple-to-hacker-q.py", "--dry-run",
                            "--library", str(lib), "--check-path", str(CHECK),
                            "--tools-dir", str(TOOLS)]
                rc = self.m.main()
            finally:
                sys.argv = old
            self.assertEqual(rc, 0)
            self.assertEqual(lib.read_text().strip(), "", "dry-run must not write")

    def test_extract_and_render_negates_assumption_into_open_question(self):
        ds = (
            "sample-reasoner.py - LOGIC CAPABILITY (demo class).\n\n"
            "THE LOGIC TRIPLE (extracted from the demo class):\n"
            "  ASSUMPTION (protocol trusts): the withdrawn amount never exceeds the\n"
            "    caller's recorded balance.\n"
            "  INVARIANT: WITHDRAW is a SUBSET of BALANCE_CHECKED.\n"
            "  FINDING = every entrypoint in WITHDRAW \\ BALANCE_CHECKED debits without\n"
            "    a balance assertion.\n\n"
            "WHY THIS IS LOGIC\n  unrelated tail.\n"
        )
        parts = self.m.extract_logic(ds, "sample")
        self.assertIn("recorded balance", parts["assumption"])
        q = self.m.render_question(parts)
        self.assertTrue(q.endswith("?"))
        self.assertIn("the protocol assumes", q)
        self.assertNotIn("unrelated tail", q, "must not bleed past the triple block")

    def test_async_lifecycle_substrate_routes_to_rust_advisory_question(self):
        rows, skipped = self.m.build_all_rows(CHECK, TOOLS)
        self.assertNotIn(("async-cancel-coupled-state-screen.py", "missing-file"), skipped)
        row = next(r for r in rows
                   if r["reasoner_tool"] == "async-cancel-coupled-state-screen.py")
        self.assertEqual(row["reasoner_ledger"],
                         "async_cancel_coupled_state_hypotheses.jsonl")
        self.assertIn("rust", row["target_languages"])
        self.assertIn("async-cancel", row["question_text"].lower())
        self.assertIn("coupled-state", row["question_text"].lower())
        self.assertTrue(row["question_text"].endswith("?"))


if __name__ == "__main__":
    unittest.main()
