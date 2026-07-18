#!/usr/bin/env python3
"""Guard test for tools/ensure-per-fn-questions.py - the generic fix that materializes
<ws>/.auditooor/per_fn_hacker_questions.jsonl (the scoped per-fn hunt worklist) so
hunt-scoped runs SCOPED instead of silently dropping to blunt N=2007 corpus mode.

Pinned gap (NUVA 2026-06-30): the producer chain (invariant-auto-synth ->
per-function-hacker-questions) was orphaned + wrote to reports/ not .auditooor/, so the
scoped-hunt step-integrity gate stayed SKIPPED forever. The wrapper must be idempotent,
land the file at the canonical path, and write a LOUD defect marker (not silently degrade)
when it genuinely cannot produce.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "ensure-per-fn-questions.py"


def _load():
    spec = importlib.util.spec_from_file_location("ensure_per_fn_questions", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _load()
CANON = Path(".auditooor") / "per_fn_hacker_questions.jsonl"
RANKED = Path(".auditooor") / "per_fn_hacker_questions.jsonl.ranked.jsonl"
DEFECT = Path(".auditooor") / "per_fn_questions_generation_defect.json"


class EnsurePerFnQuestionsTest(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="ensure_perfn_"))
        (self.ws / ".auditooor").mkdir()
        self._orig_run = M._run

    def tearDown(self):
        M._run = self._orig_run

    def _write_canon(self, n):
        (self.ws / CANON).write_text("\n".join(json.dumps({"q": i}) for i in range(n)) + "\n")

    def _rank_writer(self, n):
        """A _run fake that, for the ranker stage, writes n ranked rows."""
        def _fake(cmd, prefix):
            if prefix == "per-fn-question-ranker":
                Path(cmd[cmd.index("--output") + 1]).write_text(
                    "\n".join(json.dumps({"r": i}) for i in range(n)) + "\n")
            return 0, ""
        return _fake

    # 1. Idempotent base: pre-existing rows -> "exists", GEN chain NOT invoked, but
    #    the ranked worklist is still materialized (ranker may run).
    def test_exists_short_circuits_gen_but_ensures_ranked(self):
        self._write_canon(3)
        def _fake(cmd, prefix):
            if prefix in ("invariant-auto-synth", "per-function-hacker-questions"):
                raise AssertionError("generation chain must not run when base populated")
            if prefix == "per-fn-question-ranker":
                Path(cmd[cmd.index("--output") + 1]).write_text('{"r":1}\n{"r":2}\n')
            return 0, ""
        M._run = _fake
        rc, payload = M.ensure(self.ws, force=False, max_files=1000)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "exists")
        self.assertEqual(payload["rows"], 3)
        self.assertEqual(payload["ranked_rows"], 2)
        self.assertTrue((self.ws / RANKED).is_file())

    # 1b. Ranked already present -> ranker NOT re-run.
    def test_ranked_exists_short_circuits(self):
        self._write_canon(3)
        (self.ws / RANKED).write_text('{"r":1}\n')
        def _boom(cmd, prefix):
            raise AssertionError("nothing should run when base+ranked both present")
        M._run = _boom
        rc, payload = M.ensure(self.ws, force=False, max_files=1000)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "exists")

    # 2. Generation: empty -> run chain (simulated) -> lands canonical file.
    def test_generation_lands_canonical_file(self):
        calls = []
        def _fake_run(cmd, prefix):
            calls.append(prefix)
            if prefix == "invariant-auto-synth":
                # write the invariants tmp file the wrapper passes as --output
                outp = Path(cmd[cmd.index("--output") + 1])
                outp.write_text('{"inv": 1}\n{"inv": 2}\n')
            elif prefix == "per-function-hacker-questions":
                outp = Path(cmd[cmd.index("--output") + 1])
                outp.write_text('{"q": 1}\n{"q": 2}\n{"q": 3}\n')
            elif prefix == "per-fn-question-ranker":
                Path(cmd[cmd.index("--output") + 1]).write_text('{"r": 1}\n{"r": 2}\n')
            return 0, ""
        M._run = _fake_run
        rc, payload = M.ensure(self.ws, force=False, max_files=1000)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "generated")
        self.assertEqual(payload["rows"], 3)
        self.assertTrue((self.ws / CANON).is_file())
        self.assertIn("invariant-auto-synth", calls)
        self.assertIn("per-function-hacker-questions", calls)
        # ranking stage ran + landed the ranked worklist hunt-scoped prefers
        self.assertIn("per-fn-question-ranker", calls)
        self.assertEqual(payload["ranked_rows"], 2)
        self.assertTrue((self.ws / RANKED).is_file())
        # max-files raised so large workspaces are not truncated
        # (the wrapper default is 1000; assert it is passed through)

    # 3. Defect: stage-1 yields 0 invariants -> loud defect marker, rc 1.
    def test_defect_when_no_invariants(self):
        def _fake_run(cmd, prefix):
            return 0, ""  # produce nothing
        M._run = _fake_run
        rc, payload = M.ensure(self.ws, force=False, max_files=1000)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "defect")
        self.assertTrue((self.ws / DEFECT).is_file(), "defect marker must be written")
        marker = json.loads((self.ws / DEFECT).read_text())
        self.assertEqual(marker["verdict"], "defect-cannot-generate-per-fn-questions")

    # 4. Defect: invariants ok but questions yield 0 -> defect at stage 2.
    def test_defect_when_no_questions(self):
        def _fake_run(cmd, prefix):
            if prefix == "invariant-auto-synth":
                Path(cmd[cmd.index("--output") + 1]).write_text('{"inv": 1}\n')
            return 0, ""  # stage 2 writes nothing
        M._run = _fake_run
        rc, payload = M.ensure(self.ws, force=False, max_files=1000)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "defect")
        self.assertTrue((self.ws / DEFECT).is_file())

    # 5. --force regenerates even when the file exists.
    def test_force_regenerates(self):
        self._write_canon(2)
        ran = []
        def _fake_run(cmd, prefix):
            ran.append(prefix)
            outp = Path(cmd[cmd.index("--output") + 1])
            outp.write_text('{"x": 1}\n')
            return 0, ""
        M._run = _fake_run
        rc, payload = M.ensure(self.ws, force=True, max_files=1000)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "generated")
        self.assertTrue(ran, "force must run the chain even when file exists")

    # 6. Bad workspace via main -> rc 2.
    def test_main_bad_workspace(self):
        rc = M.main(["--workspace", "/no/such/ws/here", "--json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
