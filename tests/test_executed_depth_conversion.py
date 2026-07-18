"""executed-depth-conversion lane (2026-07-14): the missing bridge from a
needs-llm-depth coverage_unit_verdict to an EXECUTED poc_execution_record the
executed-refutation-negative-gate credits.

Covers:
  1. selection - a needs-llm-depth verdict is picked; a mechanical-no-finding one is not.
  2. obligation emission - one obligation JSON per selected unit.
  3. record bridge (anti-fabrication) - REFUSES a non-executed / non-killed result.
  4. end-to-end JOIN - a valid executed result writes a manifest the negative-gate
     credits as HONEST for the value-mover NEGATIVE on the same source file.
"""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CONV_TOOL = _ROOT / "tools" / "executed-depth-conversion.py"
_GATE_TOOL = _ROOT / "tools" / "executed-refutation-negative-gate.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_conv = _load("_exec_depth_conv", _CONV_TOOL)
_gate = _load("_exec_refut_gate_t", _GATE_TOOL)


def _write_verdict(ws, slug, unit_id, verdict, source_path, reason="", questions=None):
    d = pathlib.Path(ws) / ".auditooor" / "coverage_unit_verdicts"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{slug}.json").write_text(json.dumps({
        "schema": "auditooor.coverage_unit_verdict.v1",
        "workspace": pathlib.Path(ws).name,
        "unit_id": unit_id,
        "source_path": source_path,
        "verdict": verdict,
        "reason": reason,
        "adversarial_questions": questions or [],
    }))


class ExecutedDepthConversion(unittest.TestCase):
    def test_selection_only_depth_units(self):
        with tempfile.TemporaryDirectory() as ws:
            _write_verdict(ws, "poll-go--Vote", "poll.go::Vote",
                           "needs-llm-depth", "x/vote/keeper/poll.go",
                           reason="no impact proven mechanically")
            _write_verdict(ws, "safe-go--Foo", "safe.go::Foo",
                           "mechanical-hunt-no-finding", "x/safe/safe.go",
                           reason="cleared mechanically")
            # include_flagged_negatives=False -> pure population-A selection
            units = _conv.select_units(pathlib.Path(ws), include_flagged_negatives=False)
            ids = {u["unit_id"] for u in units}
            self.assertIn("poll.go::Vote", ids)
            self.assertNotIn("safe.go::Foo", ids,
                             "a mechanical-no-finding verdict is NOT a depth unit")

    def test_crypto_arm_selected(self):
        with tempfile.TemporaryDirectory() as ws:
            _write_verdict(ws, "rng-rs--seed", "rng.rs::seed",
                           "mechanical-hunt-no-finding", "src/tofn/rng.rs",
                           questions=["Does it reuse an ecdsa nonce/k-value across signatures?"])
            units = _conv.select_units(pathlib.Path(ws), include_flagged_negatives=False)
            self.assertIn("rng.rs::seed", {u["unit_id"] for u in units},
                          "a crypto/nonce-shaped verdict is a depth unit even if not needs-llm-depth")

    def test_emit_obligations(self):
        with tempfile.TemporaryDirectory() as ws:
            _write_verdict(ws, "poll-go--Vote", "poll.go::Vote",
                           "needs-llm-depth", "x/vote/keeper/poll.go")
            res = _conv.emit_obligations(pathlib.Path(ws))
            self.assertGreaterEqual(res["obligations_written"], 1)
            opath = (pathlib.Path(ws) / ".auditooor" / "executed_depth_obligations"
                     / "poll-go--Vote.json")
            self.assertTrue(opath.is_file())
            ob = json.loads(opath.read_text())
            self.assertEqual(ob["status"], "pending")
            self.assertEqual(ob["schema"], "auditooor.executed_depth_obligation.v1")

    def test_record_refuses_non_executed(self):
        with tempfile.TemporaryDirectory() as ws:
            bad = pathlib.Path(ws) / "bad.json"
            bad.write_text(json.dumps({
                "function": "Vote",
                "source_refs": ["x/vote/keeper/poll.go:120"],
                "baseline": {"cmd": "grep -n HasVoted poll.go", "exit_code": 0},  # grep-only-ish but exit 0
                "mutant": {"description": "guard removed", "exit_code": 0},  # NOT killed
                "cut_restored_byte_clean": True,
            }))
            res = _conv.record(pathlib.Path(ws), "poll.go::Vote", str(bad))
            self.assertFalse(res["ok"], "a mutant that was NOT killed must be refused")
            self.assertTrue(any("not killed" in r.lower() for r in res.get("reasons", [])))
            # no manifest written
            self.assertFalse((pathlib.Path(ws) / ".auditooor" / "poc_execution").exists())

    def test_record_refuses_baseline_fail(self):
        with tempfile.TemporaryDirectory() as ws:
            bad = pathlib.Path(ws) / "bad.json"
            bad.write_text(json.dumps({
                "function": "Vote",
                "source_refs": ["x/vote/keeper/poll.go:120"],
                "baseline": {"cmd": "go test ./...", "exit_code": 1},  # baseline did NOT pass
                "mutant": {"description": "guard removed", "exit_code": 1},
                "cut_restored_byte_clean": True,
            }))
            res = _conv.record(pathlib.Path(ws), "poll.go::Vote", str(bad))
            self.assertFalse(res["ok"])

    def test_end_to_end_gate_credits(self):
        with tempfile.TemporaryDirectory() as ws:
            wsp = pathlib.Path(ws)
            # a value-mover NEGATIVE (refuted double-vote) citing poll.go - grep-only,
            # so the gate flags it NON-HONEST BEFORE any poc record exists.
            mvd = wsp / ".auditooor" / "agent_mechanism_verdicts"
            mvd.mkdir(parents=True, exist_ok=True)
            (mvd / "poll_double_vote.json").write_text(json.dumps({
                "verdict": "refuted",
                "impact": "double vote / tally weight inflation",
                "mechanism": "poll-id+voter double-vote replay",
                "source_refs": ["x/vote/keeper/poll.go:120"],
                "local_verification_cmd": "grep -n HasVoted x/vote/keeper/poll.go",
            }))
            before = _gate.scan(wsp)
            self.assertEqual(len(before["honest"]), 0)
            self.assertGreaterEqual(len(before["flagged"]), 1)

            # a GENUINE executed result: baseline PASS + mutant KILL, tree byte-clean.
            good = wsp / "good.json"
            good.write_text(json.dumps({
                "function": "Vote",
                "source_refs": ["x/vote/keeper/poll.go:120"],
                "cut": "x/vote/keeper/poll.go:118",
                "invariant": "a voter cannot vote twice; second Vote errors and tally does not double",
                "baseline": {"cmd": "go test -run TestExecutedDepth_PollVote ./x/vote/keeper/",
                             "exit_code": 0, "output_excerpt": "ok  ...  PASS"},
                "mutant": {"description": "poll.go HasVoted double-vote guard neutralized (forced false)",
                           "cmd": "go test -run TestExecutedDepth_PollVote ./x/vote/keeper/",
                           "exit_code": 1,
                           "output_excerpt": "FAIL: second vote accepted; tally weight doubled"},
                "cut_restored_byte_clean": True,
            }))
            res = _conv.record(wsp, "poll.go::Vote", str(good))
            self.assertTrue(res["ok"], res)

            after = _gate.scan(wsp)
            self.assertEqual(len(after["flagged"]), 0,
                             "the poll.go NEGATIVE must now be HONEST (executed+guard-neutralized)")
            self.assertGreaterEqual(len(after["honest"]), 1)


if __name__ == "__main__":
    unittest.main()
