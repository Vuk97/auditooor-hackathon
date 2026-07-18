"""G4 - go.consensus.nondeterministic_time_float_rand (advisory, env-gated).

A keeper/abci/module fn that reads a nondeterministic source (time.Now /
unseeded math/rand / float arith) AND writes consensus state in the SAME body
is an AppHash-divergence / chain-halt candidate.

Non-vacuous: the positive fixtures MUST fire, the negative (no store-write)
and benign (telemetry latency / gauge) fixtures MUST NOT. Three extra guards
prove the predicate is load-bearing:
  * blanking _G4_STORE_WRITE makes the positive stop firing (store-write gate
    is real, not decorative);
  * injecting a store-write into the negative fixture makes it fire (the
    store-write requirement is the mutation-kill witness);
  * blanking _G4_TELEMETRY + _G4_LATENCY_IDIOM makes the benign fixture fire
    (the telemetry FP-guard is real).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER_PATH = HERE.parent / "go-detector-runner.py"
FIX = HERE / "fixtures" / "G4"
PID = "go.consensus.nondeterministic_time_float_rand"


def _load_runner():
    spec = importlib.util.spec_from_file_location("go_detector_runner_g4", RUNNER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_detector_runner_g4"] = mod
    spec.loader.exec_module(mod)
    return mod


class G4NondetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _funcs_for(self, src_path: Path):
        # place under a keeper/ path so the context gate is exercisable via
        # path as well as the sdk.Context param.
        src = src_path.read_text(encoding="utf-8")
        return self.mod._extract_functions(src, Path("x/mymod/keeper") / src_path.name)

    def _hits(self, src_path: Path):
        return self.mod._detect_nondeterministic_time_float_rand(self._funcs_for(src_path))

    def test_positive_time_now_fires(self):
        hits = self._hits(FIX / "positive" / "time_now_store.go")
        self.assertEqual(len(hits), 1, [h.to_json() for h in hits])
        self.assertEqual(hits[0].extra["function"], "EndBlock")
        self.assertEqual(hits[0].extra["arm"], "time_now")

    def test_positive_rand_fires(self):
        hits = self._hits(FIX / "positive" / "rand_store.go")
        self.assertEqual(len(hits), 1, [h.to_json() for h in hits])
        self.assertEqual(hits[0].extra["function"], "HandlePick")
        self.assertEqual(hits[0].extra["arm"], "math_rand")

    def test_negative_no_store_clean(self):
        hits = self._hits(FIX / "negative" / "no_store.go")
        self.assertEqual(len(hits), 0, f"no-store fixture fired: {[h.to_json() for h in hits]}")

    def test_benign_telemetry_clean(self):
        hits = self._hits(FIX / "benign" / "telemetry_latency.go")
        self.assertEqual(len(hits), 0, f"telemetry fixture fired: {[h.to_json() for h in hits]}")

    def test_store_write_gate_is_load_bearing(self):
        """Blank _G4_STORE_WRITE -> the positive stops firing (gate is real)."""
        funcs = self._funcs_for(FIX / "positive" / "time_now_store.go")
        orig = self.mod._G4_STORE_WRITE
        try:
            self.mod._G4_STORE_WRITE = re.compile(r"(?!x)x")  # never matches
            hits = self.mod._detect_nondeterministic_time_float_rand(funcs)
            self.assertEqual(len(hits), 0, "store-write gate is vacuous")
        finally:
            self.mod._G4_STORE_WRITE = orig
        self.assertEqual(len(self.mod._detect_nondeterministic_time_float_rand(funcs)), 1)

    def test_negative_becomes_positive_with_store_write(self):
        """Mutation-kill witness: add a store-write to the no-store fixture
        and it fires (the float source now feeds consensus state)."""
        src = (FIX / "negative" / "no_store.go").read_text()
        mutated = src.replace(
            "return uint64(math.Ceil(float64(delayPeriod) / float64(expected)))",
            "bd := uint64(math.Ceil(float64(delayPeriod) / float64(expected)))\n"
            "\tk.SetBlockDelay(ctx, bd)\n\treturn bd",
        )
        self.assertNotEqual(src, mutated, "mutation did not apply")
        funcs = self.mod._extract_functions(mutated, Path("x/mymod/keeper/m.go"))
        hits = self.mod._detect_nondeterministic_time_float_rand(funcs)
        self.assertEqual(len(hits), 1, "adding the store-write did not un-suppress")
        self.assertEqual(hits[0].extra["arm"], "float")

    def test_telemetry_guard_is_load_bearing(self):
        """Blank the telemetry + latency guards -> the benign fixture fires."""
        funcs = self._funcs_for(FIX / "benign" / "telemetry_latency.go")
        tel, lat = self.mod._G4_TELEMETRY, self.mod._G4_LATENCY_IDIOM
        try:
            self.mod._G4_TELEMETRY = re.compile(r"(?!x)x")
            self.mod._G4_LATENCY_IDIOM = re.compile(r"(?!x)x")
            hits = self.mod._detect_nondeterministic_time_float_rand(funcs)
            self.assertGreaterEqual(len(hits), 1, "telemetry FP-guard is vacuous")
        finally:
            self.mod._G4_TELEMETRY, self.mod._G4_LATENCY_IDIOM = tel, lat
        self.assertEqual(len(self.mod._detect_nondeterministic_time_float_rand(funcs)), 0)

    def test_dedup_against_map_iteration_detector(self):
        """A1 dedup boundary: a (file,line) already emitted by the
        map-iteration determinism detector is dropped from the G4 lane."""
        funcs = self._funcs_for(FIX / "positive" / "time_now_store.go")
        g4 = self.mod._detect_nondeterministic_time_float_rand(funcs)
        self.assertEqual(len(g4), 1)
        collide = self.mod.Hit(file=g4[0].file, line=g4[0].line, snippet="x")
        with tempfile.TemporaryDirectory() as ws:
            recs, _ = self.mod._emit_nondeterministic_time_float_rand_hypotheses(
                Path(ws), funcs, [collide], out_path=Path(ws) / "out.jsonl",
            )
            self.assertEqual(recs, [], "collision not de-duplicated")

    def test_env_gated_emission(self):
        """scan_workspace emits the jsonl only when the env flag is set, with
        verdict=needs-fuzz + the apphash-divergence exploit class."""
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            dst = wsp / "x" / "mymod" / "keeper"
            dst.mkdir(parents=True)
            shutil.copy(FIX / "positive" / "time_now_store.go", dst / "k.go")
            out = wsp / ".auditooor" / self.mod.G4_NONDET_OUT
            env = self.mod.G4_NONDET_ENV

            os.environ.pop(env, None)
            self.mod.scan_workspace(wsp, tuple(self.mod._DEFAULT_GUARDS))
            self.assertFalse(out.exists(), "jsonl emitted while env OFF")

            os.environ[env] = "1"
            try:
                self.mod.scan_workspace(wsp, tuple(self.mod._DEFAULT_GUARDS))
            finally:
                os.environ.pop(env, None)
            self.assertTrue(out.exists(), "jsonl not emitted while env ON")
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["verdict"], "needs-fuzz")
            self.assertEqual(rows[0]["pattern_id"], PID)
            self.assertEqual(rows[0]["exploit_class"], "apphash-divergence")
            self.assertEqual(rows[0]["lane"], "G4")


if __name__ == "__main__":
    unittest.main()
