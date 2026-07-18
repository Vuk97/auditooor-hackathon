"""Bounded unit tests for tools/reasoner-regen-pass.py (2026-07-14).

Verifies the obligation-substrate REGEN-ORDERING pass:
  - the pure staleness classifier (synthetic mtimes, no disk),
  - substrate-dependency + re-run-command parsing from runbook text,
  - the on-disk plan using REAL files with os.utime-forced synthetic mtimes,
  - the apply path with an INJECTED fake runner (never spawns a real reasoner).

Fully bounded: no subprocess, no real reasoner batch, no full-workspace walk.
"""
import importlib.util
import os
import pathlib
import tempfile
import time
import unittest

_TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"


def _load_mod():
    p = _TOOLS / "reasoner-regen-pass.py"
    spec = importlib.util.spec_from_file_location("reasoner_regen_pass", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_mod()


class ClassifierTest(unittest.TestCase):
    def test_no_substrate(self):
        self.assertEqual(M.classify_staleness(True, 100.0, []), "no-substrate")
        self.assertEqual(M.classify_staleness(False, None, []), "no-substrate")

    def test_missing_ledger_with_substrate(self):
        self.assertEqual(M.classify_staleness(False, None, [100.0]), "missing")

    def test_stale_ledger_predates_substrate(self):
        # ledger @50, substrate @100 -> STALE
        self.assertEqual(M.classify_staleness(True, 50.0, [100.0, 80.0]), "stale")

    def test_fresh_ledger_at_or_after_substrate(self):
        self.assertEqual(M.classify_staleness(True, 100.0, [100.0]), "fresh")
        self.assertEqual(M.classify_staleness(True, 150.0, [100.0, 90.0]), "fresh")

    def test_newest_substrate_governs(self):
        # ledger @90 is newer than one substrate (80) but older than newest (120)
        self.assertEqual(M.classify_staleness(True, 90.0, [80.0, 120.0]), "stale")


class SubstrateParseTest(unittest.TestCase):
    def test_detects_exact_and_scoped(self):
        deps = M.substrate_deps_from_text(
            "READS: dataflow_paths.jsonl (+ scoped sidecars)",
            "consumes state_coupling_edges.jsonl and dataflow_paths_solidity.jsonl",
        )
        self.assertIn("dataflow_paths.jsonl", deps)
        self.assertIn("state_coupling_edges.jsonl", deps)
        self.assertIn("dataflow_paths_solidity.jsonl", deps)

    def test_no_substrate_text(self):
        self.assertEqual(M.substrate_deps_from_text("emits foo_obligations.jsonl only"), [])

    def test_matches_substrate_prefixes(self):
        self.assertTrue(M.matches_substrate("dataflow_paths.jsonl"))
        self.assertTrue(M.matches_substrate(".auditooor/state_coupling_edges.jsonl"))
        self.assertFalse(M.matches_substrate("oracle_spot_price_obligations.jsonl"))


class CommandExtractTest(unittest.TestCase):
    def test_backtick_command_preferred(self):
        wmbd = "Run `python3 tools/oracle-spot-price-manipulation-reasoner.py --workspace <ws>`. FEEDS: ..."
        cmd = M.extract_rerun_command(wmbd, "oracle-spot-price-manipulation-reasoner.py")
        self.assertEqual(cmd, "python3 tools/oracle-spot-price-manipulation-reasoner.py --workspace <ws>")

    def test_fallback_canonical(self):
        cmd = M.extract_rerun_command("no command here", "conservation-haircut-realization-check.py")
        self.assertEqual(cmd, "python3 tools/conservation-haircut-realization-check.py --workspace <ws>")

    def test_resolve_argv_substitutes_ws(self):
        argv = M.resolve_command_argv("python3 tools/x.py --workspace <ws>", "nuva")
        self.assertEqual(argv, ["python3", "tools/x.py", "--workspace", "nuva"])


class PlanOnDiskTest(unittest.TestCase):
    def _mk(self):
        ws = pathlib.Path(tempfile.mkdtemp())
        ad = ws / ".auditooor"
        ad.mkdir()
        return ws, ad

    def _write(self, ad, name, mtime):
        p = ad / name
        p.write_text("{}\n")
        os.utime(p, (mtime, mtime))
        return p

    def test_stale_and_fresh_and_missing(self):
        ws, ad = self._mk()
        base = time.time()
        # substrate is newest
        self._write(ad, "dataflow_paths.jsonl", base + 100)
        # stale ledger (older than substrate)
        self._write(ad, "oracle_spot_price_obligations.jsonl", base + 10)
        # fresh ledger (newer than substrate)
        self._write(ad, "conservation_haircut_obligations.jsonl", base + 200)
        # (numeric_boundary ledger absent -> missing)

        specs = [
            {"ledger": "oracle_spot_price_obligations.jsonl", "tool": "oracle-spot-price-manipulation-reasoner.py",
             "lang": "any", "substrates": ["dataflow_paths.jsonl"], "command": "python3 tools/x.py --workspace <ws>", "step_id": "s1"},
            {"ledger": "conservation_haircut_obligations.jsonl", "tool": "conservation-haircut-realization-check.py",
             "lang": "any", "substrates": ["dataflow_paths.jsonl"], "command": "python3 tools/y.py --workspace <ws>", "step_id": "s2"},
            {"ledger": "numeric_boundary_obligations.jsonl", "tool": "adversarial-numeric-boundary-seeder.py",
             "lang": "any", "substrates": ["dataflow_paths.jsonl"], "command": "python3 tools/z.py --workspace <ws>", "step_id": "s3"},
        ]
        plan = M.compute_regen_plan(specs, ad, include_missing=False)
        by = {p["ledger"]: p for p in plan}
        self.assertEqual(by["oracle_spot_price_obligations.jsonl"]["verdict"], "stale")
        self.assertTrue(by["oracle_spot_price_obligations.jsonl"]["will_rerun"])
        self.assertEqual(by["conservation_haircut_obligations.jsonl"]["verdict"], "fresh")
        self.assertFalse(by["conservation_haircut_obligations.jsonl"]["will_rerun"])
        self.assertEqual(by["numeric_boundary_obligations.jsonl"]["verdict"], "missing")
        # missing NOT re-run by default
        self.assertFalse(by["numeric_boundary_obligations.jsonl"]["will_rerun"])

        # include_missing flips the missing one to will_rerun
        plan2 = M.compute_regen_plan(specs, ad, include_missing=True)
        by2 = {p["ledger"]: p for p in plan2}
        self.assertTrue(by2["numeric_boundary_obligations.jsonl"]["will_rerun"])

    def test_no_substrate_present_skips(self):
        ws, ad = self._mk()
        base = time.time()
        # only a ledger, no substrate file at all
        self._write(ad, "oracle_spot_price_obligations.jsonl", base)
        specs = [
            {"ledger": "oracle_spot_price_obligations.jsonl", "tool": "t.py", "lang": "any",
             "substrates": ["dataflow_paths.jsonl"], "command": "python3 tools/x.py --workspace <ws>", "step_id": "s1"},
        ]
        plan = M.compute_regen_plan(specs, ad)
        self.assertEqual(plan[0]["verdict"], "no-substrate")
        self.assertFalse(plan[0]["will_rerun"])


class ApplyWithFakeRunnerTest(unittest.TestCase):
    def test_only_stale_reran_and_receipts(self):
        calls = []

        def fake_runner(argv, cwd, timeout):
            calls.append(argv)
            return {"rc": 0, "timed_out": False, "duration_s": 0.01, "stderr_tail": ""}

        plan = [
            {"ledger": "a_obligations.jsonl", "tool": "a.py", "step_id": "sa", "verdict": "stale",
             "will_rerun": True, "command": "python3 tools/a.py --workspace <ws>"},
            {"ledger": "b_obligations.jsonl", "tool": "b.py", "step_id": "sb", "verdict": "fresh",
             "will_rerun": False, "command": "python3 tools/b.py --workspace <ws>"},
        ]
        receipts = M.apply_regen(plan, "nuva", pathlib.Path("/repo"), 30, runner=fake_runner)
        # only the stale one ran
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], ["python3", "tools/a.py", "--workspace", "nuva"])
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["ledger"], "a_obligations.jsonl")
        self.assertEqual(receipts[0]["reason"], "stale")
        self.assertEqual(receipts[0]["rc"], 0)

    def test_missing_command_recorded_no_crash(self):
        def fake_runner(argv, cwd, timeout):
            raise AssertionError("should not run when command is empty")

        plan = [{"ledger": "a_obligations.jsonl", "tool": "a.py", "step_id": "sa",
                 "verdict": "stale", "will_rerun": True, "command": ""}]
        receipts = M.apply_regen(plan, "nuva", pathlib.Path("/repo"), 30, runner=fake_runner)
        self.assertEqual(receipts[0]["error"], "no-command")


class RunbookJoinTest(unittest.TestCase):
    """Join the imported reasoner set to the REAL runbook (bounded: pure parse)."""

    def test_specs_have_substrate_and_command(self):
        import json
        rb = json.loads((_TOOLS / "readme_runbook_steps.json").read_text())
        ledgers = M.load_reasoner_ledgers()
        self.assertTrue(len(ledgers) > 0, "reasoner ledger set must be importable")
        specs = M.build_reasoner_specs(rb, ledgers)
        # at least the known substrate-backed reasoners must be present
        by = {s["ledger"]: s for s in specs}
        self.assertIn("oracle_spot_price_obligations.jsonl", by)
        self.assertIn("conservation_haircut_obligations.jsonl", by)
        spec = by["oracle_spot_price_obligations.jsonl"]
        self.assertIn("dataflow_paths.jsonl", spec["substrates"])
        self.assertTrue(spec["command"] and "oracle-spot-price-manipulation-reasoner.py" in spec["command"])


class MapCoverageTest(unittest.TestCase):
    """BUG 2: the regen map must cover EVERY firing-tracked reasoner (no silent drop)."""

    def test_every_tracked_reasoner_is_mapped(self):
        import json
        rb = json.loads((_TOOLS / "readme_runbook_steps.json").read_text())
        ledgers = M.load_reasoner_ledgers()
        specs = M.build_reasoner_specs(rb, ledgers)
        # single source of truth: one spec per tracked reasoner, none excluded.
        self.assertEqual(len(specs), len(ledgers))
        mapped = {s["ledger"] for s in specs}
        for ledger, _tool, _lang in ledgers:
            self.assertIn(M._basename(ledger), mapped)

    def test_no_substrate_dep_falls_back_to_global(self):
        # a reasoner whose runbook text names NO substrate is keyed on the global ref.
        rb = {"steps": [{"emit_artifact": ".auditooor/foo_hypotheses.jsonl",
                         "step_id": "s-foo", "reads": "some leads",
                         "what_must_be_done": "run `python3 tools/foo-screen.py --workspace <ws> --emit`"}]}
        specs = M.build_reasoner_specs(rb, (("foo_hypotheses.jsonl", "foo-screen.py", "any"),))
        self.assertEqual(len(specs), 1)
        self.assertTrue(specs[0]["uses_global_substrate"])
        self.assertTrue(specs[0]["command"] and "foo-screen.py" in specs[0]["command"])


class GlobalSubstratePlanTest(unittest.TestCase):
    def _mk(self):
        ws = pathlib.Path(tempfile.mkdtemp())
        ad = ws / ".auditooor"
        ad.mkdir()
        return ws, ad

    def _write(self, ad, name, mtime, body="{}\n"):
        p = ad / name
        p.write_text(body)
        os.utime(p, (mtime, mtime))
        return p

    def test_global_reasoner_stale_and_missing_against_dataflow(self):
        ws, ad = self._mk()
        base = time.time()
        self._write(ad, "dataflow_paths.jsonl", base + 100)
        # a global-keyed reasoner with an OLD ledger -> stale vs the global substrate
        self._write(ad, "zk_constraint_coverage_obligations.jsonl", base + 10)
        specs = [
            {"ledger": "zk_constraint_coverage_obligations.jsonl", "tool": "zk-constraint-coverage.py",
             "lang": "zk", "substrates": [], "uses_global_substrate": True,
             "command": "python3 tools/zk-constraint-coverage.py --workspace <ws> --emit", "step_id": "s1"},
            {"ledger": "oracle_reachability_hypotheses.jsonl", "tool": "oracle-reachability-lane.py",
             "lang": "any", "substrates": [], "uses_global_substrate": True,
             "command": "python3 tools/oracle-reachability-lane.py --workspace <ws>", "step_id": "s2"},
        ]
        plan = M.compute_regen_plan(specs, ad, include_missing=True)
        by = {p["ledger"]: p for p in plan}
        self.assertEqual(by["zk_constraint_coverage_obligations.jsonl"]["verdict"], "stale")
        self.assertTrue(by["zk_constraint_coverage_obligations.jsonl"]["will_rerun"])
        # missing ledger + fresh global substrate -> missing (re-run under include_missing)
        self.assertEqual(by["oracle_reachability_hypotheses.jsonl"]["verdict"], "missing")
        self.assertTrue(by["oracle_reachability_hypotheses.jsonl"]["will_rerun"])

    def test_empty_dataflow_shard_is_no_substrate(self):
        ws, ad = self._mk()
        base = time.time()
        self._write(ad, "dataflow_paths.jsonl", base + 100, body="\n  \n")  # 0 real rows
        self._write(ad, "zk_constraint_coverage_obligations.jsonl", base + 10)
        specs = [{"ledger": "zk_constraint_coverage_obligations.jsonl", "tool": "t.py", "lang": "zk",
                  "substrates": [], "uses_global_substrate": True,
                  "command": "python3 tools/t.py --workspace <ws>", "step_id": "s1"}]
        plan = M.compute_regen_plan(specs, ad, include_missing=True)
        self.assertEqual(plan[0]["verdict"], "no-substrate")
        self.assertFalse(plan[0]["will_rerun"])


class ProducerOrderingTest(unittest.TestCase):
    """BUG 1: a producer re-bump must NOT leave a re-run consumer ordering-stale."""

    def test_producer_first_then_frozen_consumer_no_restale(self):
        ws = pathlib.Path(tempfile.mkdtemp())
        ad = ws / ".auditooor"
        ad.mkdir()
        base = time.time()

        def w(name, mt, body="{}\n"):
            p = ad / name
            p.write_text(body)
            os.utime(p, (mt, mt))
            return p

        # substrate + a consumer + a producer, ALL initially stale-ish.
        w("dataflow_paths.jsonl", base + 100)
        w("state_coupling_edges.jsonl", base + 100)
        w("consumer_obligations.jsonl", base + 10)   # consumer stale vs substrate
        w("composition_novelty_obligations.jsonl", base + 5)  # producer stale

        specs = [
            {"ledger": "consumer_obligations.jsonl", "tool": "cons.py", "lang": "any",
             "substrates": ["dataflow_paths.jsonl"], "uses_global_substrate": False,
             "command": "python3 tools/cons.py --workspace <ws>", "step_id": "sc"},
            {"ledger": "composition_novelty_obligations.jsonl", "tool": "composition-novelty-search.py",
             "lang": "any", "substrates": ["state_coupling_edges.jsonl"], "uses_global_substrate": False,
             "command": "python3 tools/composition-novelty-search.py --workspace <ws> --emit --autorun-producers",
             "step_id": "sp"},
        ]
        # PLAN order deliberately puts the CONSUMER first - the pre-fix bug ran it before
        # the producer bumped the substrate, snapping it back to stale.
        plan = M.compute_regen_plan(specs, ad, include_missing=True)

        clock = [base + 200]  # strictly increasing synthetic mtime source
        order = []

        def fake_runner(argv, cwd, timeout):
            joined = " ".join(argv)
            clock[0] += 10
            if "--autorun-producers" in argv:
                order.append("producer")
                # producer REGENERATES both substrate shards (bump), then writes its ledger.
                for sub in ("dataflow_paths.jsonl", "state_coupling_edges.jsonl"):
                    os.utime(ad / sub, (clock[0], clock[0]))
                clock[0] += 10
                p = ad / "composition_novelty_obligations.jsonl"
                p.write_text("{}\n")
                os.utime(p, (clock[0], clock[0]))
            else:
                order.append("consumer")
                self.assertNotIn("--autorun-producers", argv, "consumer pass must be FROZEN")
                p = ad / "consumer_obligations.jsonl"
                p.write_text("{}\n")
                os.utime(p, (clock[0], clock[0]))
            return {"rc": 0, "timed_out": False, "duration_s": 0.0, "stderr_tail": ""}

        receipts = M.apply_regen(plan, str(ws), pathlib.Path("/repo"), 30,
                                 runner=fake_runner, specs=specs, auditooor_dir=ad,
                                 include_missing=True)
        self.assertTrue(receipts)
        # producer ran BEFORE any consumer.
        self.assertEqual(order[0], "producer")
        self.assertIn("consumer", order)
        self.assertLess(order.index("producer"), order.index("consumer"))

        # INVARIANT: after the pass NO reasoner is ordering-stale (ledger > substrate).
        final = M.compute_regen_plan(specs, ad, include_missing=True)
        for p in final:
            self.assertNotEqual(p["verdict"], "stale",
                                f"{p['ledger']} left ordering-stale after regen pass")
            self.assertNotEqual(p["verdict"], "missing",
                                f"{p['ledger']} still missing after regen pass")

    def test_producer_detection_and_freeze(self):
        c = "python3 tools/x.py --workspace <ws> --emit --autorun-producers --fail-closed"
        self.assertTrue(M.is_producer(c))
        self.assertFalse(M.is_producer("python3 tools/y.py --workspace <ws>"))
        self.assertEqual(M.freeze_command(c),
                         "python3 tools/x.py --workspace <ws> --emit --fail-closed")


if __name__ == "__main__":
    unittest.main()
