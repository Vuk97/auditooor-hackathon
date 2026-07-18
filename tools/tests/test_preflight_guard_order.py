"""Guard-triage ordering for per-function-preflight-orchestrator.

RANK-5 additive fix: before the --max-functions cap / total-budget truncation, the
orchestrator stable-sorts discovered functions by a guard-risk score loaded from
``.auditooor/guard_triage.json`` (risk_units score / hunt_priority_order). Guard-risky
functions are preflighted first; unranked functions keep their existing relative order.
Missing guard_triage.json -> no reordering (alphabetical discovery order preserved).

Mirrors tools/per-function-attack-worklist.py:_guard_risk_scores.
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "per-function-preflight-orchestrator.py"


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "per_function_preflight_orchestrator", TOOL
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class _FakeFn:
    function_name: str
    relative_file: str = "src/X.sol"


def _sort_like_orchestrator(functions, guard_risk):
    """Replicate the orchestrator's pre-cap stable sort (additive fix site)."""
    if guard_risk and functions:
        return sorted(
            functions,
            key=lambda fn: -guard_risk.get(fn.function_name.lower(), 0),
        )
    return functions


class GuardRiskScoresTest(unittest.TestCase):
    def test_missing_triage_returns_empty(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self.assertEqual(tool._guard_risk_scores(ws), {})

    def test_risk_units_score_parsed(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "guard_triage.json").write_text(
                json.dumps(
                    {
                        "risk_units": [
                            {"unit": "src/Vault.sol:42:withdraw", "score": 9},
                            {"unit": "src/Vault.sol:10:deposit", "score": 3},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            scores = tool._guard_risk_scores(ws)
            self.assertEqual(scores.get("withdraw"), 9)
            self.assertEqual(scores.get("deposit"), 3)

    def test_hunt_priority_order_gets_positive_rank(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "guard_triage.json").write_text(
                json.dumps({"hunt_priority_order": ["src/Vault.sol:7:liquidate"]}),
                encoding="utf-8",
            )
            scores = tool._guard_risk_scores(ws)
            self.assertGreater(scores.get("liquidate", 0), 0)

    def test_corrupt_triage_returns_empty(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "guard_triage.json").write_text(
                "{not json", encoding="utf-8"
            )
            self.assertEqual(tool._guard_risk_scores(ws), {})


class GuardOrderSortTest(unittest.TestCase):
    def test_high_risk_fn_sorts_before_no_risk_fn_when_present(self):
        # Alphabetical discovery order: aaa_safe < zzz_risky.
        functions = [_FakeFn("aaa_safe"), _FakeFn("zzz_risky")]
        guard_risk = {"zzz_risky": 9}
        ordered = _sort_like_orchestrator(functions, guard_risk)
        self.assertEqual(
            [f.function_name for f in ordered], ["zzz_risky", "aaa_safe"]
        )

    def test_order_unchanged_when_triage_absent(self):
        # Empty guard_risk map => no reordering, discovery (alphabetical) order kept.
        functions = [_FakeFn("aaa_safe"), _FakeFn("zzz_risky")]
        ordered = _sort_like_orchestrator(functions, {})
        self.assertEqual(
            [f.function_name for f in ordered], ["aaa_safe", "zzz_risky"]
        )

    def test_unranked_fns_keep_relative_order_after_ranked(self):
        # Two unranked (b, c) keep their relative order; ranked (d) goes first.
        functions = [_FakeFn("b_un"), _FakeFn("c_un"), _FakeFn("d_risky")]
        guard_risk = {"d_risky": 5}
        ordered = _sort_like_orchestrator(functions, guard_risk)
        self.assertEqual(
            [f.function_name for f in ordered], ["d_risky", "b_un", "c_un"]
        )

    def test_end_to_end_load_then_sort(self):
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "guard_triage.json").write_text(
                json.dumps(
                    {"risk_units": [{"unit": "src/V.sol:1:zzz_risky", "score": 8}]}
                ),
                encoding="utf-8",
            )
            functions = [_FakeFn("aaa_safe"), _FakeFn("zzz_risky")]
            guard_risk = tool._guard_risk_scores(ws)
            ordered = _sort_like_orchestrator(functions, guard_risk)
            self.assertEqual(ordered[0].function_name, "zzz_risky")


if __name__ == "__main__":
    unittest.main()
