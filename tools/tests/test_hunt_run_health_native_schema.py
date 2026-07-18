"""
test_hunt_run_health_native_schema.py
-------------------------------------
Regression tests for the native per-fn mechanism-verdict sidecar schema in
hunt-run-health-check.py (classify_record + _unit_key).

PROBLEM this guards (operator-observed 2026-07-06, SEI hunt-trust gate):
SEI's hunt_findings_sidecars / agent_mechanism_verdicts records carry
{unit, file, lines, verdict, cited_excerpt} at the TOP LEVEL with NO nested
`result` wrapper. classify_record keyed on rec["result"] and _unit_key keyed on
rec["function_anchor"], so ~70% of SEI's hunt records (3305/4949) were:
  - misclassified "empty" (should be "engaged": a NEGATIVE verdict + real file =
    the model mechanically engaged the function and cleanly declined), AND
  - dropped from the per-unit trust rollup entirely (no unit key resolved).
Both collapsed units_engaged -> unit_engaged_fraction 0.46 (< 0.50 healthy) ->
verdict "degraded" -> the hunt-trust STRICT gate false-red. This is the same
serving-join class as the unhunted-surface-adjudicate.py file_line fix.
"""

import importlib.util
import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_TOOL = os.path.join(REPO_ROOT, "tools", "hunt-run-health-check.py")
_spec = importlib.util.spec_from_file_location("_hh_native", _TOOL)
hh = importlib.util.module_from_spec(_spec)
sys.modules["_hh_native"] = hh
_spec.loader.exec_module(hh)


# A real in-scope-looking path so _real_anchor accepts it.
_FILE = "/Users/wolf/audits/sei/src/sei-chain/x/evm/types/ethtx/associate_tx.go"


def _native(verdict="NEGATIVE", unit="Fee", file=_FILE):
    """A native mechanism-verdict sidecar record: NO `result`, NO `function_anchor`."""
    return {
        "unit": unit,
        "file": file,
        "lines": "53",
        "verdict": verdict,
        "reasoning": "Unreachable stub, doubly guarded (no caller + no ante path).",
        "cited_excerpt": "func (tx *AssociateTx) Fee() *big.Int { panic(...) }",
        "severity_if_finding": None,
    }


class TestNativeSchemaClassify(unittest.TestCase):

    def test_negative_verdict_with_file_is_engaged_not_empty(self):
        klass, ref = hh.classify_record(_native(verdict="NEGATIVE"))
        self.assertEqual(klass, "engaged",
                         f"native NEGATIVE+file record must be engaged-clean, got {klass}")
        self.assertTrue(ref)

    def test_finding_verdict_with_file_is_success(self):
        for v in ("CONFIRMED", "positive", "exploitable", "vulnerable"):
            klass, _ = hh.classify_record(_native(verdict=v))
            self.assertEqual(klass, "success",
                             f"native finding verdict {v!r} must be success, got {klass}")

    def test_native_record_without_real_file_stays_empty(self):
        # No usable anchor -> genuinely empty (never-ran / garbage).
        klass, _ = hh.classify_record(_native(verdict="NEGATIVE", file="?"))
        self.assertEqual(klass, "empty")

    def test_no_verdict_no_result_stays_empty(self):
        rec = {"unit": "X", "file": _FILE}  # no verdict at all
        klass, _ = hh.classify_record(rec)
        self.assertEqual(klass, "empty")

    def test_unit_key_resolves_native_schema(self):
        key = hh._unit_key(_native(unit="Fee", file=_FILE))
        self.assertIsNotNone(key, "unit key must resolve from native unit+file")
        self.assertEqual(key, "associate_tx.go::Fee")

    def test_nested_result_schema_still_works(self):
        # The legacy nested-result schema must be unaffected by the fallback.
        rec = {"status": "ok", "result": '{"applies_to_target": "no"}'}
        klass, _ = hh.classify_record(rec)
        self.assertEqual(klass, "engaged")

    def test_degraded_to_healthy_flip_on_native_records(self):
        # A surface of native NEGATIVE records that ALL engage must read healthy-
        # clean per-unit, never degraded (the SEI false-red).
        recs = [_native(verdict="NEGATIVE", unit=f"Fn{i}",
                        file=f"/ws/src/pkg/f{i}.go") for i in range(40)]
        unit_best = {}
        for r in recs:
            u = hh._unit_key(r)
            k, _ = hh.classify_record(r)
            self.assertEqual(k, "engaged")
            self.assertIsNotNone(u)
            unit_best[u] = k
        du = len(unit_best)
        ue = sum(1 for k in unit_best.values() if k in ("success", "engaged"))
        verdict = hh.verdict_for(len(recs), 0, ue, distinct_units=du,
                                 units_engaged=ue, units_success=0)
        self.assertEqual(verdict, "healthy-clean",
                         f"all-engaged native surface must be healthy-clean, got {verdict}")


if __name__ == "__main__":
    unittest.main()
