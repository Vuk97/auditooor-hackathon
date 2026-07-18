#!/usr/bin/env python3
"""Tests for tools/dataflow-invariant-seed.py + the path-relevant mutant mode of
tools/mutation-verify-coverage.py (data-flow-aware harness/fuzz/invariant layer).

Hermetic: no forge / halmos / cargo / slither. The DefUsePath jsonl is built by
hand via tools/dataflow_schema.py (the same producer schema the live engine
emits), and the mutation-kill is proven with a tiny Python-stub `--harness`
(mirroring test_mutation_verify_coverage.py) so the mutate->run->restore loop is
exercised end-to-end against the REAL fixture source without a Solidity toolchain.

Covered:
  - the seeder emits a CONSERVATION harness for an UNGUARDED multi-hop value flow,
    tagged flow_seeded / dataflow_seeded / dataflow_path_id, non-sentinel;
  - a GUARDED variant of the same flow yields NO unguarded-flow invariant;
  - DEFAULT-OFF: absent dataflow_paths.jsonl -> empty manifest, nothing written;
  - MUTATION-VERIFIED: the path-relevant mode mutates the value-moving SINK and
    the conservation harness FAILS on the value-creation mutant (verdict
    non-vacuous), proving the seeded harness is non-vacuous.
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

ROOT = Path(__file__).resolve().parents[2]
SEED_TOOL = ROOT / "tools" / "dataflow-invariant-seed.py"
MVC_TOOL = ROOT / "tools" / "mutation-verify-coverage.py"
FIXTURES = ROOT / "tests" / "fixtures" / "dataflow"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ds = _load(ROOT / "tools" / "dataflow_schema.py", "dataflow_schema")
_mvc = _load(MVC_TOOL, "mutation_verify_coverage")


def _unguarded_path(src_rel: str) -> dict:
    """An UNGUARDED forward value-flow path into the value-moving sink _send,
    matching value_creation_sink.sol's hop structure."""
    return _ds.new_path(
        path_id="vcs-payout-transfer-0",
        language="solidity", direction="forward", engine="slither-ssa",
        source={"kind": "param", "fn": "payout", "var": "amount",
                "file": src_rel, "line": 25},
        sink={"kind": "transfer", "callee": "transfer", "arg_pos": 0,
              "fn": "_send", "file": src_rel, "line": 36},
        hops=[
            {"from_var": "amount", "to_var": "amt", "fn": "_route",
             "via": "internal_call", "file": src_rel, "line": 30, "ir": "", "guarded": False},
            {"from_var": "amt", "to_var": "a", "fn": "_send",
             "via": "internal_call", "file": src_rel, "line": 35, "ir": "", "guarded": False},
        ],
        guard_nodes=[], confidence="semantic-ssa",
    )


def _guarded_path(src_rel: str) -> dict:
    return _ds.new_path(
        path_id="clean-withdraw-transferFrom-0",
        language="solidity", direction="forward", engine="slither-ssa",
        source={"kind": "param", "fn": "withdraw", "var": "amount",
                "file": src_rel, "line": 28},
        sink={"kind": "transferFrom", "callee": "transferFrom", "arg_pos": 2,
              "fn": "_pay", "file": src_rel, "line": 40},
        hops=[
            {"from_var": "amount", "to_var": "amt", "fn": "_route",
             "via": "internal_call", "file": src_rel, "line": 33, "ir": "", "guarded": True},
        ],
        guard_nodes=[{"file": src_rel, "line": 34, "expr": "require(amt <= cap)"}],
        confidence="semantic-ssa",
    )


# A conservation-property STUB harness. It reads the (possibly-mutated) sink
# source and PASSES iff `_send` sends the FULL authorized amount `a`
# (`transfer(a)`); it FAILS when the value-creation mutant halves the send
# (`transfer((a) / 2)`). This is the conservation invariant the seeded harness
# encodes, expressed as a toolchain-free oracle so the mutate->run->restore loop
# is exercised against the real fixture source.
_STUB = (
    "import sys, re, pathlib\n"
    "src = pathlib.Path(sys.argv[1]).read_text()\n"
    "# the sink must move the WHOLE authorized amount: transfer(a) with no /2.\n"
    "m = re.search(r'\\.transfer\\(([^;]*)\\);', src)\n"
    "arg = (m.group(1).strip() if m else '')\n"
    "ok = (arg == 'a')  # value conserved iff the full var is sent\n"
    "print('[PASS]' if ok else '[FAIL] counterexample: value not conserved at sink')\n"
    "sys.exit(0 if ok else 3)\n"
)


class TestDataflowInvariantSeed(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="df_inv_seed_"))
        self.ws = self.tmp / "ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / ".auditooor").mkdir(parents=True)
        shutil.copy(FIXTURES / "value_creation_sink.sol", self.ws / "src" / "value_creation_sink.sol")
        shutil.copy(FIXTURES / "clean.sol", self.ws / "src" / "clean.sol")
        self.paths = self.ws / ".auditooor" / "dataflow_paths.jsonl"
        self.stub = self.tmp / "stub.py"
        self.stub.write_text(_STUB, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_paths(self, recs):
        _ds.write_jsonl(str(self.paths), recs)

    def _run_seed(self, *extra):
        proc = subprocess.run(
            ["python3", str(SEED_TOOL), "--workspace", str(self.ws), "--json", *extra],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    # ---- 1. seeder emits a conservation harness for the unguarded flow ----
    def test_seeds_conservation_harness_for_unguarded_flow(self):
        self._write_paths([_unguarded_path("src/value_creation_sink.sol")])
        m = self._run_seed()
        self.assertEqual(m["seeded_count"], 1)
        self.assertFalse(m["default_off"])
        row = m["flow_seeded_harnesses"][0]
        # CREDIT TAGS present.
        self.assertTrue(row["flow_seeded"])
        self.assertTrue(row["dataflow_seeded"])
        self.assertEqual(row["dataflow_path_id"], "vcs-payout-transfer-0")
        self.assertEqual(row["call_depth"], 2)
        self.assertIn(row["invariant_class"], ("value-flow-bounds", "accounting-conservation"))
        # NON-SENTINEL: a real relational conservation assertion was emitted.
        self.assertIs(row["is_sentinel"], False)
        body = Path(row["harness_path"]).read_text(encoding="utf-8")
        self.assertIn("postSink <= preSink + authorized", body)
        # MULTI-HOP: the full call sequence is documented, not a single fn.
        self.assertIn("payout", body)
        self.assertIn("_route", body)
        self.assertIn("_send", body)

    # ---- 2. guarded variant -> NO unguarded-flow invariant ----
    def test_guarded_flow_is_not_seeded(self):
        self._write_paths([_guarded_path("src/clean.sol")])
        m = self._run_seed()
        self.assertEqual(m["seeded_count"], 0)
        self.assertTrue(m["default_off"])
        reasons = {s["reason"] for s in m["skipped"]}
        self.assertIn("guarded-flow", reasons)

    # ---- 3. DEFAULT-OFF: no dataflow_paths.jsonl -> nothing written ----
    def test_default_off_when_no_paths_file(self):
        # No paths file written at all.
        self.assertFalse(self.paths.exists())
        m = self._run_seed()
        self.assertEqual(m["seeded_count"], 0)
        self.assertEqual(m["total_paths_read"], 0)
        self.assertTrue(m["default_off"])
        self.assertFalse(m["paths_file_present"])
        # The per-function output tree is NOT created by the seeder.
        self.assertFalse((self.ws / "poc-tests" / "dataflow_invariants").exists())

    # ---- 4. MUTATION-VERIFIED: conservation harness kills the value mutant ----
    def test_path_relevant_mutant_kills_value_creation_mutant(self):
        self._write_paths([_unguarded_path("src/value_creation_sink.sol")])
        # Drive the path-relevant mode directly against the REAL fixture source via
        # the conservation stub harness. Unguarded path -> mutate the value sink.
        src = self.ws / "src" / "value_creation_sink.sol"
        rec = _mvc.verify_dataflow_path(
            workspace=self.ws,
            rec=_unguarded_path("src/value_creation_sink.sol"),
            harness=f"{sys.executable} {self.stub} {src}",
            timeout=120,
        )
        # The sink _send has exactly one value_mutation mutant (transfer((a)/2)).
        self.assertEqual(rec["verdict"], "non-vacuous", json.dumps(rec, indent=2)[:2000])
        self.assertEqual(rec["path_relevant_mode"], "sink-value")
        self.assertEqual(rec["dataflow_path_id"], "vcs-payout-transfer-0")
        self.assertTrue(rec["flow_seeded"])
        self.assertGreaterEqual(rec["killed_count"], 1)
        # Source restored byte-identical after the loop (the sink LINE is intact,
        # i.e. no transient mutant left on disk).
        restored = (self.ws / "src" / "value_creation_sink.sol").read_text(encoding="utf-8")
        self.assertEqual(
            restored, (FIXTURES / "value_creation_sink.sol").read_text(encoding="utf-8")
        )

    # ---- 5. guard-on-path mode targets the guard for the mutant ----
    def test_guard_on_path_mode_targets_guard(self):
        # A guarded path resolves to guard-removal of the path's dominating guard.
        guarded = _guarded_path("src/clean.sol")
        target = _mvc._resolve_path_relevant_target(guarded, self.ws)
        self.assertIsNotNone(target)
        self.assertEqual(target["mode"], "guard-on-path")
        self.assertIn("guard_removal", target["classes"])
        self.assertEqual(target["source_file"].name, "clean.sol")
        # The function arg is the guard's file:line.
        self.assertTrue(str(target["function"]).endswith(":34"))


if __name__ == "__main__":
    unittest.main()
