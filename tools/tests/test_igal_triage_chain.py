#!/usr/bin/env python3
"""Guard tests for the IGAL canonical triage chain (emit -> dispatch -> disposition).

Makes the incomplete-guard-ack discovery -> disposition flow a CANONICAL runbook step on
every workspace (was previously hand-rolled). Covers: emit batches HIGH-only by default,
disposition policy (benign + verified-not-fileable -> not-fileable; fileable -> open lead,
NO disposition so the gate stays red), and R76 drop of a fabricated excerpt.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent.parent / fname)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


emit = _load("igal_emit", "igal-triage-emit.py")
ingest = _load("igal_ingest", "igal-disposition-ingest.py")

_SRC = """\
pragma solidity 0.8.25;
contract OPCM {
    function upgrade(bytes memory data) public {
        // TODO(#20084): remove this permitted-instruction allowance before mainnet
        if (_isPermittedInstruction(key)) return true;
    }
}
"""


def _ws_with_hyps(rows):
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "OPCM.sol").write_text(_SRC, encoding="utf-8")
    with (ws / ".auditooor" / "incomplete_guard_ack_hypotheses.jsonl").open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return ws


class EmitTest(unittest.TestCase):
    def test_high_only_by_default(self):
        ws = _ws_with_hyps([
            {"file": "src/OPCM.sol", "ack_line": 4, "rank_bucket": "high", "ack_token": "TODO",
             "ack_text": "TODO remove", "sink_line": 5, "sink_text": "return true;",
             "sink_kind": "early-skip-return", "function": "upgrade", "language": "sol"},
            {"file": "src/OPCM.sol", "ack_line": 4, "rank_bucket": "med", "ack_token": "TODO",
             "ack_text": "x", "sink_line": 5, "sink_text": "y", "function": "f", "language": "sol"},
        ])
        res = emit.emit(ws, batch_size=12, include_med=False)
        self.assertEqual(res["hypotheses"], 1, "MED bucket leaked into a HIGH-only emit")
        self.assertGreaterEqual(res["batches"], 1)
        plan = ws / "src"  # sanity: prompt dir created under .auditooor
        self.assertTrue((ws / ".auditooor" / "igal_triage" / "_agent_plan" / "batch_000.md").is_file())

    def test_include_med_adds_them(self):
        ws = _ws_with_hyps([
            {"file": "src/OPCM.sol", "ack_line": 4, "rank_bucket": "high", "ack_text": "a",
             "sink_line": 5, "sink_text": "b", "function": "u", "language": "sol"},
            {"file": "src/OPCM.sol", "ack_line": 4, "rank_bucket": "med", "ack_text": "c",
             "sink_line": 5, "sink_text": "d", "function": "f", "language": "sol"},
        ])
        res = emit.emit(ws, batch_size=12, include_med=True)
        self.assertEqual(res["hypotheses"], 2)


class DispositionTest(unittest.TestCase):
    def _run(self, verdicts):
        ws = _ws_with_hyps([])
        td = ws / ".auditooor" / "igal_triage"
        td.mkdir(parents=True, exist_ok=True)
        (td / "batch_000.jsonl").write_text(json.dumps(verdicts), encoding="utf-8")
        res = ingest.ingest(ws)
        dispo = [json.loads(l) for l in (ws / ".auditooor" / "incomplete_guard_ack_dispositions.jsonl").read_text().splitlines() if l.strip()]
        leads = [json.loads(l) for l in (ws / ".auditooor" / "igal_open_leads.jsonl").read_text().splitlines() if l.strip()]
        return res, dispo, leads

    def test_benign_and_verified_not_fileable_dispositioned(self):
        res, dispo, leads = self._run([
            {"file_line": "src/OPCM.sol:5", "ack_line": 5, "classification": "benign",
             "fileable": None, "reason": "dev comment", "code_excerpt": "if (_isPermittedInstruction(key)) return true;"},
            {"file_line": "src/OPCM.sol:4", "ack_line": 4, "classification": "finding-candidate",
             "fileable": False, "blocking_gate": "reachability-trusted", "reason": "governance only",
             "code_excerpt": "function upgrade(bytes memory data) public {"},
        ])
        self.assertEqual(len(dispo), 2)
        self.assertTrue(all(d["disposition"] == "not-fileable" for d in dispo))
        self.assertEqual(len(leads), 0)

    def test_fileable_left_undisposed_as_open_lead(self):
        res, dispo, leads = self._run([
            {"file_line": "src/OPCM.sol:4", "ack_line": 4, "classification": "finding-candidate",
             "fileable": True, "severity": "Medium", "reason": "honest reach + external exploit",
             "code_excerpt": "function upgrade(bytes memory data) public {"},
        ])
        self.assertEqual(len(dispo), 0, "a FILEABLE lead must NOT be auto-dispositioned")
        self.assertEqual(len(leads), 1)
        self.assertEqual(res["open_fileable_leads"], 1)

    def test_fabricated_excerpt_r76_dropped(self):
        res, dispo, leads = self._run([
            {"file_line": "src/OPCM.sol:4", "ack_line": 4, "classification": "benign",
             "fileable": None, "reason": "x",
             "code_excerpt": "function stealAllFunds(address attacker) selfdestruct(attacker)"},
        ])
        self.assertEqual(len(dispo), 0, "fabricated excerpt must be R76-dropped, not dispositioned")
        self.assertEqual(res["r76_dropped"], 1)


if __name__ == "__main__":
    unittest.main()
