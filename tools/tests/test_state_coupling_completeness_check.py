#!/usr/bin/env python3
"""Regression for tools/state-coupling-completeness-check.py (P4 audit-complete signal).
Gates ONLY on promotable semantic-ssa edges; syntactic/non-promotable stay advisory.
2026-07-08 (SCC framework, box P4)."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    import sys
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


scs = _load("state_coupling_schema", "state_coupling_schema.py")
chk = _load("scc_check", "state-coupling-completeness-check.py")


def _mk(edges):
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    scs.write_edges(ws, edges)
    return ws


def _promotable_edge(eid="e1", probed=False):
    e = scs.new_edge(eid, "solidity", "conserved-with", "a", "b",
                     ["fa"], ["fb"], [{"fn": "fb", "file": "V.sol", "line": 1,
                                       "mutates": ["b"], "omits": ["a"]}],
                     confidence="semantic-ssa")
    e["evidence"]["promotable"] = True
    if probed:
        e["evidence"]["probe_verdict"] = "NEGATIVE-guarded"
    return e


def _advisory_edge(eid="e2"):
    e = scs.new_edge(eid, "go", "derived-from", "x", "y", [], [], [],
                     confidence="syntactic")
    e["evidence"]["promotable"] = False
    return e


class T(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_open_promotable_warns_rc0_no_marker(self):
        ws = _mk([_promotable_edge()])
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 0)  # advisory WARN
        self.assertFalse((ws / ".auditooor" /
                          "state_coupling_completeness_pass.marker").is_file())
        r = json.loads((ws / ".auditooor" / "state_coupling_completeness.json").read_text())
        self.assertEqual(r["open_edges"], 1)
        self.assertEqual(r["verdict"], "warn-state-coupling-open")

    def test_open_promotable_strict_rc1(self):
        ws = _mk([_promotable_edge()])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 1)

    def test_explicit_strict_fails_starved_zero(self):
        ws = _mk([])
        rc = chk.main(["--workspace", str(ws), "--no-emit", "--strict"])
        self.assertEqual(rc, 1)
        result = json.loads((ws / ".auditooor" /
                             "state_coupling_completeness.json").read_text())
        self.assertTrue(any("substrate" in issue for issue in result["strict_failures"]))

    def test_explicit_strict_fails_syntactic_only_input(self):
        ws = _mk([_advisory_edge("syntactic-only")])
        rc = chk.main(["--workspace", str(ws), "--no-emit", "--strict"])
        self.assertEqual(rc, 1)
        result = json.loads((ws / ".auditooor" /
                             "state_coupling_completeness.json").read_text())
        self.assertTrue(any("syntactic-only" in issue for issue in result["strict_failures"]))

    def test_explicit_strict_passes_cited_semantic_terminal_closure(self):
        ws = _mk([_promotable_edge("terminal")])
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "terminal", "verdict": "safe",
                        "source_refs": ["src/Vault.sol:1"],
                        "rationale": "writer preserves both coupled cells"}) + "\n")
        rc = chk.main(["--workspace", str(ws), "--no-emit", "--strict"])
        self.assertEqual(rc, 0)
        result = json.loads((ws / ".auditooor" /
                             "state_coupling_completeness.json").read_text())
        self.assertEqual(result["strict_failures"], [])

    def test_explicit_strict_accepts_typed_cited_empty_closure(self):
        ws = _mk([])
        (ws / ".auditooor" / "state_coupling_conserved_accounting.json").write_text(
            json.dumps({"status": "cited-empty", "source_refs": ["src/Vault.sol"],
                        "rationale": "semantic slice examined all in-scope writers"}))
        self.assertEqual(chk.main([
            "--workspace", str(ws), "--no-emit", "--strict"]), 0)

    def test_explicit_strict_rejects_uncited_probe_verdict(self):
        ws = _mk([_promotable_edge("uncited")])
        edge = scs.read_edges(ws)[0]
        edge["evidence"]["probe_verdict"] = "safe"
        scs.write_edges(ws, [edge])
        self.assertEqual(chk.main([
            "--workspace", str(ws), "--no-emit", "--strict"]), 1)

    def test_advisory_edges_never_gate(self):
        # a non-promotable (syntactic) edge is advisory - it must NOT be open, so the
        # marker is written even under strict.
        ws = _mk([_advisory_edge()])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 0)
        self.assertTrue((ws / ".auditooor" /
                         "state_coupling_completeness_pass.marker").is_file())

    def test_probed_promotable_passes(self):
        # evidence.probe_verdict set -> not open -> pass marker.
        ws = _mk([_promotable_edge(probed=True)])
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 0)
        self.assertTrue((ws / ".auditooor" /
                         "state_coupling_completeness_pass.marker").is_file())

    def test_probes_sidecar_marks_probed(self):
        ws = _mk([_promotable_edge("eX")])
        # a legitimate probe carries a RATIONALE (note/evidence/source_cites)
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "eX", "verdict": "REAL-desync",
                        "note": "guarded @ V.sol:1"}) + "\n")
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 0)
        self.assertTrue((ws / ".auditooor" /
                         "state_coupling_completeness_pass.marker").is_file())

    def test_rationale_less_verdict_does_not_hand_green(self):
        # a bare {edge_id, verdict} with NO rationale must NOT close a promotable lead
        # (hand-greening = the #1 sin). Edge stays OPEN -> STRICT hard-fails rc1.
        ws = _mk([_promotable_edge("eBare")])
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "eBare", "verdict": "ok"}) + "\n")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 1, "rationale-less verdict must not green a promotable edge")
        res = json.loads((ws / ".auditooor" / "state_coupling_completeness.json").read_text())
        self.assertEqual(res["open_edges"], 1)

    def test_no_edges_vacuous_pass(self):
        ws = _mk([])
        rc = chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc, 0)
        self.assertTrue((ws / ".auditooor" /
                         "state_coupling_completeness_pass.marker").is_file())

    def test_stale_marker_removed_when_open(self):
        ws = _mk([_promotable_edge()])
        m = ws / ".auditooor" / "state_coupling_completeness_pass.marker"
        m.write_text("stale\n")
        chk.main(["--workspace", str(ws), "--no-emit"])
        self.assertFalse(m.is_file(), "stale pass marker must be removed when open")


class TExploitQueueGather(unittest.TestCase):
    def setUp(self):
        self.eq = _load("eq", "exploit-queue.py")

    def test_gather_promotes_only_promotable_semantic(self):
        ws = _mk([
            _promotable_edge("real"),                       # promotable + semantic-ssa
            _advisory_edge("adv"),                          # non-promotable syntactic
        ])
        # a promotable edge but probed-NEGATIVE must NOT be a candidate
        neg = _promotable_edge("neg")
        neg["evidence"]["probe_verdict"] = "NEGATIVE-guarded"
        scs.write_edges(ws, [_promotable_edge("real"), _advisory_edge("adv"), neg])
        rows = self.eq._gather_from_state_coupling(ws)
        ids = [r["lead_id"] for r in rows]
        self.assertTrue(any("real" in i for i in ids), f"promotable semantic must promote: {ids}")
        self.assertFalse(any("adv" in i for i in ids), "advisory edge must NOT promote")
        self.assertFalse(any("neg" in i for i in ids), "probed-NEGATIVE must NOT promote")
        real = next(r for r in rows if "real" in r["lead_id"])
        self.assertEqual(real["attack_class"], "value-conservation-break")

    def test_gather_empty_when_no_edges_file(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        self.assertEqual(self.eq._gather_from_state_coupling(ws), [])


if __name__ == "__main__":
    unittest.main()
