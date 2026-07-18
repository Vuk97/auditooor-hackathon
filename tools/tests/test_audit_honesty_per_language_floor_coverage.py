#!/usr/bin/env python3
# <!-- r36-rebuttal: lane AHC-PER-LANG-FLOOR-COVERAGE registered in .auditooor/agent_pathspec.json -->
"""NUVA 2026-06-30: the per-language value-moving FLOOR compared corroborated
harness-RECORD count vs value-moving FUNCTION count, so a single mutation-verified
conservation harness covering N functions counted as 1 record and could never meet
the floor. Fix: reduce each language's NEED by the value-moving functions whose FILE
is the CUT of a mutation-verified harness (coverage-based credit).

NEVER-FALSE-PASS: only a mutation_verified harness with a real on-disk CUT credits;
a vacuous sidecar or a value-moving fn with no harness stays a deficit.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "audit-honesty-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("ahc_floor", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ahc_floor"] = m
    spec.loader.exec_module(m)
    return m


ahc = _load()


def _mk(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="ahc_floor_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class PerLanguageFloorCoverageTest(unittest.TestCase):
    def _vmf(self, *fns):
        return {"function_count": len(fns),
                "functions": [{"file": f, "function": n, "language": l} for (f, n, l) in fns]}

    def test_mutation_verified_cut_file_covers_its_value_movers(self):
        ws = _mk({
            "src/v.go": "package v\nfunc SwapIn(){}\nfunc SwapOut(){}\n",
            ".auditooor/mvc_sidecar/go.json": json.dumps({
                "schema": "auditooor.mutation_verify_coverage.v1",
                "mutation_verified": True, "mutants_killed": 1,
                "source_file": "src/v.go", "harness_path": "src/v_test.go",
            }),
        })
        vmf = self._vmf(("src/v.go", "SwapIn", "go"), ("src/v.go", "SwapOut", "go"))
        self.assertEqual(ahc._per_language_floor_unmet(ws, vmf), [],
                         "both go value-movers in a mutation-verified CUT file must be covered")

    def test_uncovered_value_mover_stays_deficit(self):
        ws = _mk({
            "src/v.go": "package v\nfunc SwapIn(){}\n",
            "src/other.go": "package v\nfunc Deposit(){}\n",
            ".auditooor/mvc_sidecar/go.json": json.dumps({
                "mutation_verified": True, "mutants_killed": 1, "source_file": "src/v.go",
            }),
        })
        # Deposit@other.go has NO harness -> go floor unmet (never-false-pass)
        vmf = self._vmf(("src/v.go", "SwapIn", "go"), ("src/other.go", "Deposit", "go"))
        self.assertIn("go", ahc._per_language_floor_unmet(ws, vmf))

    def test_vacuous_sidecar_does_not_credit(self):
        ws = _mk({
            "src/v.go": "package v\nfunc SwapIn(){}\n",
            ".auditooor/mvc_sidecar/go.json": json.dumps({
                "mutation_verified": False, "verdict": "vacuous", "source_file": "src/v.go",
            }),
        })
        self.assertEqual(ahc._mutation_verified_cut_files(ws), set(),
                         "vacuous sidecar must not be a mutation-verified CUT")
        vmf = self._vmf(("src/v.go", "SwapIn", "go"))
        self.assertIn("go", ahc._per_language_floor_unmet(ws, vmf))


if __name__ == "__main__":
    unittest.main(verbosity=2)
