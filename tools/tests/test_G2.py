"""G2 - go.cosmos.attacker_divisor_zero_unchecked (advisory, env-gated).

Non-vacuous: the positive fixture MUST fire and the negative/gas-price
fixtures MUST NOT. Two extra guards prove the predicate is load-bearing:
  * patching _ADV_TAINT_SEGMENTS to empty makes the positive stop firing
    (the taint gate is real, not decorative);
  * dropping the IsPositive guard from the negative fixture makes it fire
    (the zero-guard suppressor is real).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER_PATH = HERE.parent / "go-detector-runner.py"
FIX = HERE / "fixtures" / "G2"
PID = "go.cosmos.attacker_divisor_zero_unchecked"


def _load_runner():
    spec = importlib.util.spec_from_file_location("go_detector_runner_g2", RUNNER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_detector_runner_g2"] = mod
    spec.loader.exec_module(mod)
    return mod


class G2AttackerDivisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _funcs_for(self, src_path: Path):
        # place under an x/<mod>/ path so the cosmos-context gate is also
        # exercisable via path (belt-and-suspenders with the sdk.Context param).
        src = src_path.read_text(encoding="utf-8")
        return self.mod._extract_functions(src, Path("x/oracle/keeper") / src_path.name)

    def test_positive_fires(self):
        funcs = self._funcs_for(FIX / "positive" / "attacker_divisor_unguarded.go")
        hits = self.mod._detect_attacker_divisor_zero_unchecked(funcs)
        self.assertEqual(len(hits), 1, f"expected 1 hit, got {[h.to_json() for h in hits]}")
        self.assertEqual(hits[0].extra["function"], "TallyExchangeRate")
        self.assertEqual(hits[0].extra["divisor"], "msg.ExchangeRate")

    def test_negative_guarded_clean(self):
        funcs = self._funcs_for(FIX / "negative" / "attacker_divisor_guarded.go")
        hits = self.mod._detect_attacker_divisor_zero_unchecked(funcs)
        self.assertEqual(len(hits), 0, f"guarded fixture fired: {[h.to_json() for h in hits]}")

    def test_gasprice_divisor_deduped(self):
        funcs = self._funcs_for(FIX / "negative" / "gasprice_divisor.go")
        hits = self.mod._detect_attacker_divisor_zero_unchecked(funcs)
        self.assertEqual(len(hits), 0, f"gas-price divisor leaked into G2: {[h.to_json() for h in hits]}")

    def test_predicate_is_load_bearing_taint(self):
        """Mutate the predicate: empty the taint set -> positive stops firing."""
        funcs = self._funcs_for(FIX / "positive" / "attacker_divisor_unguarded.go")
        orig = self.mod._ADV_TAINT_SEGMENTS
        try:
            self.mod._ADV_TAINT_SEGMENTS = frozenset()
            hits = self.mod._detect_attacker_divisor_zero_unchecked(funcs)
            self.assertEqual(len(hits), 0, "taint gate is vacuous")
        finally:
            self.mod._ADV_TAINT_SEGMENTS = orig
        # restore-check: it fires again with the real predicate.
        self.assertEqual(len(self.mod._detect_attacker_divisor_zero_unchecked(funcs)), 1)

    def test_zero_guard_is_load_bearing(self):
        """Drop the IsPositive guard from the negative fixture -> it fires."""
        src = (FIX / "negative" / "attacker_divisor_guarded.go").read_text()
        mutated = src.replace("if msg.ExchangeRate.IsPositive() {", "if true {")
        self.assertNotEqual(src, mutated, "mutation did not apply")
        funcs = self.mod._extract_functions(mutated, Path("x/oracle/keeper/m.go"))
        hits = self.mod._detect_attacker_divisor_zero_unchecked(funcs)
        self.assertEqual(len(hits), 1, "removing the guard did not un-suppress")

    def test_env_gated_emission(self):
        """scan_workspace emits the jsonl only when the env flag is set."""
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            dst = wsp / "x" / "oracle" / "keeper"
            dst.mkdir(parents=True)
            shutil.copy(FIX / "positive" / "attacker_divisor_unguarded.go", dst / "k.go")
            out = wsp / ".auditooor" / self.mod.G2_ATTACKER_DIVISOR_OUT
            env = self.mod.G2_ATTACKER_DIVISOR_ENV

            # OFF: no jsonl.
            os.environ.pop(env, None)
            self.mod.scan_workspace(wsp, tuple(self.mod._DEFAULT_GUARDS))
            self.assertFalse(out.exists(), "jsonl emitted while env OFF")

            # ON: jsonl with a needs-fuzz record.
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
            self.assertEqual(rows[0]["source"], "G2")


if __name__ == "__main__":
    unittest.main()
