#!/usr/bin/env python3
# <!-- r36-rebuttal: lane ENGINE-HARNESS-DRIFTED-DIAGNOSTIC registered in .auditooor/agent_pathspec.json -->
"""NUVA 2026-06-30: when a cross-function/closeout agent additively edits a baseline
invariant handler that carries a mutation-verified mvc_sidecar, the sidecar DRIFTS
(harness_source_sha256 no longer matches) and the engine-harness-proof gate flagged
the file as a "fake/tautological stub" - a misdiagnosis that sends the operator to
re-author a harness when the real fix is a RE-VERIFY.

This test pins the diagnostic-only split: a non-vacuous-but-drifted sidecar's campaign
files surface in `drifted_unproven`, NEVER in `proven`. The verdict is unchanged (a
drifted sidecar stays uncredited), so the reclassification cannot create a false-green.
"""
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "engine-harness-proof-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("ehp_drift", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ehp_drift"] = m
    spec.loader.exec_module(m)
    return m


ehp = _load()


def _mk(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="ehp_drift_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class DriftedDiagnosticTest(unittest.TestCase):
    def _sidecar(self, harness_rel: str, recorded_sha: str) -> str:
        return json.dumps({
            "schema": "auditooor.mutation_verify_coverage.v1",
            "mode": "manual-mutant-harness", "manual_registration": True,
            "verdict": "non-vacuous", "mutation_verified": True, "mutants_killed": 1,
            "harness_path": harness_rel,
            "harness_source_sha256": recorded_sha,
        })

    def test_drifted_campaign_files_detects_stale_nonvacuous_sidecar(self):
        # baseline handler edited AFTER the sidecar recorded its hash -> drift.
        ws = _mk({
            "chimera_harnesses/Foo/test/FooHandler.sol":
                "// edited after sidecar recorded\ncontract FooHandler {}\n",
            "chimera_harnesses/Foo/test/Foo_Invariant.t.sol":
                "contract Foo_Invariant {}\n",
        })
        stale = hashlib.sha256(b"the ORIGINAL pre-edit bytes").hexdigest()
        (ws / ".auditooor/mvc_sidecar").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor/mvc_sidecar/foo.json").write_text(
            self._sidecar("chimera_harnesses/Foo/test/FooHandler.sol", stale),
            encoding="utf-8")
        drifted = ehp._drifted_campaign_files(ws)
        inv = str((ws / "chimera_harnesses/Foo/test/Foo_Invariant.t.sol").resolve())
        hnd = str((ws / "chimera_harnesses/Foo/test/FooHandler.sol").resolve())
        # the WHOLE campaign bundle is flagged drifted (siblings credited together)
        self.assertIn(inv, drifted)
        self.assertIn(hnd, drifted)

    def test_fresh_sidecar_is_not_drifted(self):
        ws = _mk({
            "chimera_harnesses/Foo/test/FooHandler.sol": "contract FooHandler {}\n",
        })
        cur = hashlib.sha256(
            (ws / "chimera_harnesses/Foo/test/FooHandler.sol").read_bytes()).hexdigest()
        (ws / ".auditooor/mvc_sidecar").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor/mvc_sidecar/foo.json").write_text(
            self._sidecar("chimera_harnesses/Foo/test/FooHandler.sol", cur),
            encoding="utf-8")
        self.assertEqual(ehp._drifted_campaign_files(ws), set(),
                         "a current (non-drifted) sidecar must not be flagged drifted")

    def test_vacuous_drifted_sidecar_not_credited_as_drifted(self):
        # a VACUOUS sidecar that also drifted is NOT a real-but-stale proof; it must
        # stay a genuine stub (not reclassified to the softer drifted bucket).
        ws = _mk({
            "chimera_harnesses/Foo/test/FooHandler.sol": "contract FooHandler {}\n",
        })
        (ws / ".auditooor/mvc_sidecar").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor/mvc_sidecar/foo.json").write_text(json.dumps({
            "mutation_verified": False, "verdict": "vacuous",
            "harness_path": "chimera_harnesses/Foo/test/FooHandler.sol",
            "harness_source_sha256": hashlib.sha256(b"old").hexdigest(),
        }), encoding="utf-8")
        self.assertEqual(ehp._drifted_campaign_files(ws), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
