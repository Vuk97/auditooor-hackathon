"""test_mechanism_axis_agent_verdicts.py

Regression tests for the agent-REASONED per-cell verdict path in
completeness-matrix-build.py (_load_agent_mechanism_verdicts + its wiring into
_build_mechanism_axis). This closes the loop so a hunter clears an UNSCANNED
(no-detector) impact x mechanism cell by SOURCE-READING, not only a detector.

Load-bearing anti-false-negative property under test: closing a cell is a claim
of ABSENCE and must be as hard as a finding - a 'cleared' verdict credits the
cell ONLY with >=1 source citation + substantive reasoning; a bare 'cleared'
string is IGNORED (fail-closed, cell stays unscanned).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "completeness-matrix-build.py"


def _load():
    spec = importlib.util.spec_from_file_location("cmb_agent_verdicts", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cmb_agent_verdicts"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


cmb = _load()

# A go/all-language cell with detector=null in the seed (unscanned by default).
IMPACT = "chain-halt"
MECH = "consensus-path-arithmetic-panic"


def _ws(td: str) -> pathlib.Path:
    ws = pathlib.Path(td)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        json.dumps({"function": "BeginBlocker", "file": "src/vault/keeper/abci.go"}) + "\n",
        encoding="utf-8",
    )
    return ws


def _write_verdicts(ws: pathlib.Path, rows: list[dict]) -> None:
    d = ws / ".auditooor" / "agent_mechanism_verdicts"
    d.mkdir(parents=True, exist_ok=True)
    (d / "v.json").write_text(json.dumps(rows), encoding="utf-8")


def _cell(ws: pathlib.Path):
    inscope = cmb._load_inscope(ws)
    axis = cmb._build_mechanism_axis(ws, inscope, set())
    for c in axis["cells"]:
        if c["impact"] == IMPACT and c["mechanism"] == MECH:
            return c, axis
    raise AssertionError(f"cell {IMPACT}/{MECH} not in axis")


class TestAgentVerdicts(unittest.TestCase):
    def test_baseline_cell_is_unscanned(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            c, _ = _cell(ws)
            self.assertEqual(c["status"], "not-enumerated-unscanned")

    def test_cleared_with_evidence_closes_cell(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            _write_verdicts(ws, [{
                "schema": "auditooor.agent_mechanism_verdict.v1",
                "impact": IMPACT, "mechanism": MECH, "verdict": "cleared",
                "source_refs": ["src/vault/keeper/valuation_engine.go:120"],
                "reasoning": "All Mul/Quo in the valuation path are guarded by bounded "
                             "checks; no unguarded 256-bit arithmetic reaches consensus.",
            }])
            c, axis = _cell(ws)
            self.assertEqual(c["status"], "enumerated-agent-cleared")
            # counts as enumerated, not as an unscanned gap
            self.assertTrue(c["status"].startswith("enumerated"))

    def test_bare_cleared_without_citation_is_ignored_failclosed(self):
        """The core anti-false-negative rule: a cleared verdict with NO source
        citation must NOT close the cell (closing is as hard as finding)."""
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            _write_verdicts(ws, [{
                "impact": IMPACT, "mechanism": MECH, "verdict": "cleared",
                "source_refs": [], "reasoning": "looks fine",
            }])
            c, _ = _cell(ws)
            self.assertEqual(c["status"], "not-enumerated-unscanned")

    def test_cleared_with_trivial_reasoning_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            _write_verdicts(ws, [{
                "impact": IMPACT, "mechanism": MECH, "verdict": "cleared",
                "source_refs": ["src/x.go:1"], "reasoning": "ok",
            }])
            c, _ = _cell(ws)
            self.assertEqual(c["status"], "not-enumerated-unscanned")

    def test_agent_finding_opens_cell(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            _write_verdicts(ws, [{
                "impact": IMPACT, "mechanism": MECH, "verdict": "finding",
                "source_refs": ["src/vault/keeper/reconcile.go:474"],
                "reasoning": "Unbounded WalkDue with no batch cap on the consensus hook.",
            }])
            c, axis = _cell(ws)
            self.assertEqual(c["status"], "not-enumerated-open-finding")
            self.assertGreaterEqual(axis["not_enumerated_open"], 1)

    def test_agent_finding_dispositioned_is_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            _write_verdicts(ws, [{
                "impact": IMPACT, "mechanism": MECH, "verdict": "finding",
                "source_refs": ["src/vault/keeper/reconcile.go:474"],
                "reasoning": "Unbounded WalkDue.",
            }])
            # a disposition row keyed mechanism::file::line closes it
            (ws / ".auditooor" / "mechanism_dispositions.jsonl").write_text(
                json.dumps({"mechanism": MECH, "file": "src/vault/keeper/reconcile.go",
                            "line": "474", "verdict": "refuted-known-issue"}) + "\n",
                encoding="utf-8",
            )
            c, _ = _cell(ws)
            self.assertNotEqual(c["status"], "not-enumerated-open-finding")

    def test_loader_direct(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            _write_verdicts(ws, [
                {"impact": IMPACT, "mechanism": MECH, "verdict": "cleared",
                 "source_refs": ["a.go:1"], "reasoning": "x" * 50},
                {"impact": "insolvency", "mechanism": "accounting-conservation-break",
                 "verdict": "finding", "source_refs": ["b.go:2"], "reasoning": "y"},
            ])
            cleared, findings = cmb._load_agent_mechanism_verdicts(ws)
            self.assertIn((IMPACT, MECH), cleared)
            self.assertIn(("insolvency", "accounting-conservation-break"), findings)


if __name__ == "__main__":
    unittest.main()
