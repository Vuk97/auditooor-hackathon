#!/usr/bin/env python3
"""Tests for tools/assumption-negation-reachability.py (3rd NOVELTY engine).

Covers:
  1. survivor: entrypoint-reachable value-move path with no bound guard -> a
     value-bounded negation survivor is emitted, grounded to file:line.
  2. NON-VACUOUS MUTATION PAIR: add a guard enforcing the bound on that same
     path -> the survivor DISAPPEARS (proves the reachability join is real, not
     a token grep over the assumption text).
  3. cited_empty: substrate present + entrypoint paths exist but every impact
     path enforces A -> honest 0 (status cited_empty), no survivors.
  4. substrate_vacuous: no entrypoint paths -> status substrate_vacuous +
     --fail-closed exits non-zero.
  5. needs_source advisory: assumption present but no entrypoint-reachable impact
     path for that unit -> advisory needs_source row (never a survivor).
  6. real substrate: runs over /Users/wolf/audits/nuva if present (honest:
     survivors OR cited_empty), schema + grounding asserted.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_TOOLS = pathlib.Path(__file__).resolve().parent.parent
_TOOL = _TOOLS / "assumption-negation-reachability.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("assumption_negation", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ANR = _load_tool()

_FILE = "src/prime/RedemptionProxy.sol"
_ABS = "/ws/src/prime/RedemptionProxy.sol"


def _write_backends(ws: pathlib.Path, guard_exprs, *, reachable=True,
                    sink_kind="safeTransferFrom", transfer=True):
    """Build a minimal .auditooor substrate: one value-moving entrypoint fn with
    a single dataflow path to a value-move sink carrying `guard_exprs`."""
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    (a / "value_moving_functions.json").write_text(json.dumps({
        "functions": [{
            "file": _FILE, "function": "triggerRedeem", "language": "sol",
            "transfer_hit": transfer, "ledger_write_hit": False,
            "authz_write_hit": False, "guarded_callee_hit": False,
        }]
    }))
    (a / "guard_completeness.jsonl").write_text(json.dumps({
        "file": _FILE, "function": "triggerRedeem", "language": "sol",
        "guarded": False, "guard_evidence": "", "disposition": "",
    }) + "\n")
    path = {
        "schema": "dataflow_path.v1", "path_id": "dfp-0001", "language": "solidity",
        "source": {"kind": "param-entrypoint" if reachable else "local",
                   "fn": "RedemptionProxy.triggerRedeem(uint256,uint256)",
                   "var": "amount", "file": _ABS, "line": 113},
        "sink": {"kind": sink_kind, "callee": sink_kind, "fn": "triggerRedeem",
                 "file": _ABS, "line": 128},
        "hops": [],
        "guard_nodes": [{"file": _ABS, "line": 120, "expr": e} for e in guard_exprs],
    }
    (a / "dataflow_paths.jsonl").write_text(json.dumps(path) + "\n")


class TestSurvivor(unittest.TestCase):
    def test_survivor_value_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            # only a non-zero guard, NO bound/balance comparison
            _write_backends(ws, ["amount == 0"])
            rep = ANR.run(ws)
            self.assertEqual(rep["status"], "survivors")
            vb = [s for s in rep["survivors"] if s["assumption"] == "value-bounded"]
            self.assertEqual(len(vb), 1)
            s = vb[0]
            # grounded to a real file:line entrypoint + sink
            self.assertEqual(s["reachable_path"]["entrypoint"]["line"], 113)
            self.assertEqual(s["impact_sink"]["line"], 128)
            self.assertEqual(s["impact_class"], "value-move")
            self.assertIsNone(s.get("corpus_class", None))  # class-agnostic


class TestProducerFreshness(unittest.TestCase):
    def test_autorun_skips_fresh_substrates(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "inscope_units.jsonl").write_text("{}\n")
            (aud / "value_moving_functions.json").write_text("{}\n")
            (aud / "guard_completeness.jsonl").write_text("{}\n")
            for name in (
                "dataflow_paths.jsonl",
                "assumption_falsification_obligations.jsonl",
            ):
                (aud / name).write_text("{}\n")
            fresh = os.path.getmtime(aud / "dataflow_paths.jsonl") + 10
            os.utime(aud / "dataflow_paths.jsonl", (fresh, fresh))
            fresh = os.path.getmtime(aud / "assumption_falsification_obligations.jsonl") + 10
            os.utime(aud / "assumption_falsification_obligations.jsonl", (fresh, fresh))

            with mock.patch.object(ANR.subprocess, "run") as run:
                log = ANR._autorun_producers(ws)

            self.assertEqual([row["status"] for row in log], ["skipped-fresh", "skipped-fresh"])
            run.assert_not_called()


class TestNonVacuousMutationPair(unittest.TestCase):
    """THE non-vacuity proof: adding a guard that enforces A on the path must
    make the survivor vanish. A token grep over the assumption text could not
    tell these two substrates apart."""

    def test_add_bound_guard_removes_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            # BEFORE: no bound guard -> survivor
            _write_backends(ws, ["amount == 0"])
            before = ANR.run(ws)
            vb_before = [s for s in before["survivors"]
                         if s["assumption"] == "value-bounded"]
            self.assertEqual(len(vb_before), 1, "expected a value-bounded survivor pre-mutation")

            # AFTER: add a bound guard enforcing value-bounded ON THE SAME PATH
            _write_backends(ws, ["amount == 0", "amount <= balance"])
            after = ANR.run(ws)
            vb_after = [s for s in after["survivors"]
                        if s["assumption"] == "value-bounded"]
            self.assertEqual(len(vb_after), 0,
                             "bound guard on the path must kill the value-bounded survivor")


class TestCitedEmpty(unittest.TestCase):
    def test_all_paths_guarded_is_cited_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            # every relevant assumption enforced on the path
            _write_backends(ws, ["amount == 0", "amount <= balance",
                                 "require(msg.sender == owner)"])
            rep = ANR.run(ws)
            self.assertFalse(rep["substrate"]["vacuous"])
            self.assertEqual(rep["survivor_count"], 0)
            self.assertEqual(rep["status"], "cited_empty")


class TestSubstrateVacuous(unittest.TestCase):
    def test_no_entrypoint_paths_is_vacuous(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            _write_backends(ws, ["amount == 0"], reachable=False)  # not param-entrypoint
            rep = ANR.run(ws)
            self.assertEqual(rep["status"], "substrate_vacuous")
            self.assertTrue(rep["substrate"]["vacuous"])

    def test_fail_closed_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            _write_backends(ws, ["amount == 0"], reachable=False)
            r = subprocess.run(
                [sys.executable, str(_TOOL), "--workspace", str(ws), "--fail-closed"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 3, r.stderr)


class TestNeedsSourceAdvisory(unittest.TestCase):
    def test_present_but_no_impact_path_is_needs_source(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            # value-mover present in value_moving_functions but the dataflow path
            # reaches a NON-impact sink kind -> reachability cannot be confirmed.
            _write_backends(ws, ["amount == 0"], sink_kind="log")
            rep = ANR.run(ws)
            # not vacuous (there IS an entrypoint path), but no impact sink
            self.assertFalse(rep["substrate"]["vacuous"])
            self.assertGreaterEqual(rep["needs_source_count"], 1)
            self.assertEqual(rep["survivor_count"], 0)
            ns = rep["needs_source"]
            self.assertTrue(all("no entrypoint-reachable" in n["reason"] for n in ns))


class TestAutorunProducers(unittest.TestCase):
    """--autorun-producers must run the dataflow backend before the join and must
    NOT fabricate a survivor when the substrate never materializes (the build
    agent's proof-run fabricated a nuva firing; on an empty ws the honest verdict
    is substrate_vacuous, and --fail-closed exits non-zero)."""

    def test_autorun_on_empty_ws_is_substrate_vacuous_not_fabricated(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            # empty ws: no source, no dataflow_paths.jsonl. Autorun runs the
            # producers; they emit nothing groundable -> honest substrate_vacuous,
            # never a fabricated survivor. --fail-closed => rc 3.
            r = subprocess.run(
                [sys.executable, str(_TOOL), "--workspace", str(ws),
                 "--autorun-producers", "--fail-closed"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn("substrate", r.stderr.lower())
            outp = ws / ".auditooor" / "assumption_negation_obligations.jsonl"
            if outp.exists():
                surv = [ln for ln in outp.read_text().splitlines()
                        if ln.strip() and json.loads(ln).get("verdict") == "survivor"]
                self.assertEqual(surv, [], "no survivor may be fabricated on empty ws")

    def test_assumption_producer_uses_its_positional_cli(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            self.assertEqual(ANR._producer_commands(ws)[-1][1], [str(ws)])

    def test_autorun_flag_records_producer_log(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            r = subprocess.run(
                [sys.executable, str(_TOOL), "--workspace", str(ws),
                 "--autorun-producers", "--json"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            rep = json.loads(r.stdout)
            self.assertIn("autorun_producers", rep)
            self.assertTrue(any(p["producer"] in ("dataflow.py", "dataflow-slice.py")
                                for p in rep["autorun_producers"]))


class TestRealSubstrate(unittest.TestCase):
    def test_nuva_real_substrate(self):
        ws = pathlib.Path("/Users/wolf/audits/nuva")
        if not (ws / ".auditooor" / "dataflow_paths.jsonl").exists():
            self.skipTest("nuva substrate not present")
        rep = ANR.run(ws)
        self.assertEqual(rep["schema"], "auditooor.assumption_negation.v1")
        # honest: either survivors or cited_empty, never a crash / silent drop
        self.assertIn(rep["status"], ("survivors", "cited_empty", "substrate_vacuous"))
        for s in rep["survivors"]:
            # every survivor grounded to a real file:line
            self.assertTrue(s["reachable_path"]["entrypoint"]["file"])
            self.assertTrue(s["impact_sink"]["file"])
            self.assertTrue(s["negation"])  # class-agnostic negation text present


if __name__ == "__main__":
    unittest.main(verbosity=2)
