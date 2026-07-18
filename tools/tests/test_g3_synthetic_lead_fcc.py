#!/usr/bin/env python3
"""test_g3_synthetic_lead_fcc.py - G3: function-coverage must not credit synthetic-lead sidecars.

A synthetic-lead hunt sidecar CLAIMS a per-fn hunt (carries a file_line) but was
never dispatched (duration_s<=0 & started==ended, no spawn_worker receipt) - the
NUVA-437 false-green the E4 gate kills on the hunt-coverage plane. function-coverage
credited real-attack on ANY bridged sidecar with a file_line, ignoring provenance,
so a fabricated sidecar manufactured per-function coverage. G3 filters synthetic-lead
paths at the single evidence-path source (_pass1_evidence_paths).

Empirically self-validating: each test FIRST asserts the REAL E4 classifier tags the
fixtures as expected (synthetic-lead vs authentic), THEN asserts fcc excludes only the
synthetic one. Cases:
  - precondition: real classify_sidecar_provenance => synthetic fixture=synthetic-lead,
    authentic fixture (duration_s>0)=authentic.
  - _synthetic_lead_sidecar_paths(ws) contains the synthetic path, NOT the authentic.
  - _pass1_evidence_paths(ws) YIELDS the authentic sidecar, EXCLUDES the synthetic.
  - fail-open: classifier unavailable => empty set => BOTH paths yielded (byte-identical
    to pre-G3; absence never demotes).

Stdlib-only; uses the REAL classifier (no mocking of the provenance decision).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FCC_PATH = REPO / "tools" / "function-coverage-completeness.py"
PROV_PATH = REPO / "tools" / "hunt-dispatch-provenance-check.py"


def _load(mod_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # dataclass field() 3.14
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _sidecar(synthetic: bool) -> dict:
    # claims a real hunt (file_line) => subject to the provenance guard.
    sc = {
        "schema": "auditooor.hunt_finding_sidecar.v1",
        "function": "swapOut",
        "file_line": "src/vault/keeper/vault.go:412",
        "function_anchor": "swapOut@src/vault/keeper/vault.go",
        "provider": "via-agent",
        "verification_tier": "tier-3-synthetic",
        "status": "no-finding",
        "verdict": "ruled-out",
        "verdict_detail": "swapOut ruled out: file_line src/vault/keeper/vault.go:412",
    }
    if synthetic:
        # inline-authoring signature: duration_s<=0 & started==ended, no receipt.
        sc.update({"duration_s": 0, "started": "2026-07-11T00:00:00Z",
                   "ended": "2026-07-11T00:00:00Z"})
    else:
        # real, non-degenerate duration => genuinely dispatched => authentic.
        sc.update({"duration_s": 42.0, "started": "2026-07-11T00:00:00Z",
                   "ended": "2026-07-11T00:00:42Z"})
    return sc


class G3SyntheticLeadFccTest(unittest.TestCase):
    def setUp(self):
        self.fcc = _load("_fcc_g3_test", FCC_PATH)
        self.prov = _load("_prov_g3_test", PROV_PATH)
        self.fcc._SYNTH_LEAD_PATHS_CACHE.clear()

    def _make_ws(self, td: str):
        ws = Path(td)
        scdir = ws / ".auditooor" / "hunt_findings_sidecars"
        scdir.mkdir(parents=True, exist_ok=True)
        synth = scdir / "synthetic.json"
        auth = scdir / "authentic.json"
        synth.write_text(json.dumps(_sidecar(True)), encoding="utf-8")
        auth.write_text(json.dumps(_sidecar(False)), encoding="utf-8")
        return ws, synth, auth

    def test_precondition_real_classifier_tags_fixtures(self):
        # validate the fixtures against the REAL E4 classifier before testing fcc.
        c_syn = self.prov.classify_sidecar_provenance(
            Path("synthetic.json"), _sidecar(True), set(), [])
        c_auth = self.prov.classify_sidecar_provenance(
            Path("authentic.json"), _sidecar(False), set(), [])
        self.assertEqual(c_syn.get("status"), "synthetic-lead",
                         f"synthetic fixture must classify synthetic-lead: {c_syn}")
        self.assertEqual(c_auth.get("status"), "authentic",
                         f"authentic fixture must classify authentic: {c_auth}")

    def test_synth_lead_paths_selects_only_synthetic(self):
        with tempfile.TemporaryDirectory() as td:
            ws, synth, auth = self._make_ws(td)
            got = self.fcc._synthetic_lead_sidecar_paths(ws)
            self.assertIn(str(synth), got, "synthetic sidecar must be flagged")
            self.assertNotIn(str(auth), got, "authentic sidecar must NOT be flagged")

    def test_pass1_evidence_excludes_synthetic_only(self):
        with tempfile.TemporaryDirectory() as td:
            ws, synth, auth = self._make_ws(td)
            paths = {str(p) for p in self.fcc._pass1_evidence_paths(ws)}
            self.assertIn(str(auth), paths,
                          "authentic hunt sidecar must remain a credit source")
            self.assertNotIn(str(synth), paths,
                             "synthetic-lead sidecar must be excluded from credit sources (G3)")

    def test_nested_synthetic_sidecar_is_flagged(self):
        # rglob fix: a synthetic-lead sidecar in a SUBDIR of hunt_findings_sidecars
        # (nested placement is explicitly supported by the recursive credit globs)
        # must still be in the exclusion set.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            nested = ws / ".auditooor" / "hunt_findings_sidecars" / "batch7"
            nested.mkdir(parents=True, exist_ok=True)
            nsynth = nested / "nested_synth.json"
            nsynth.write_text(json.dumps(_sidecar(True)), encoding="utf-8")
            got = self.fcc._synthetic_lead_sidecar_paths(ws)
            self.assertIn(str(nsynth), got,
                          "a NESTED synthetic-lead sidecar must be flagged (rglob)")

    def test_fail_open_when_classifier_absent(self):
        with tempfile.TemporaryDirectory() as td:
            ws, synth, auth = self._make_ws(td)
            orig = self.fcc._load_provenance_module
            self.fcc._load_provenance_module = lambda: None  # type: ignore[assignment]
            self.fcc._SYNTH_LEAD_PATHS_CACHE.clear()
            try:
                got = self.fcc._synthetic_lead_sidecar_paths(ws)
                self.assertEqual(got, set(), "classifier-absent must yield empty set (fail-open)")
                paths = {str(p) for p in self.fcc._pass1_evidence_paths(ws)}
                self.assertIn(str(synth), paths, "fail-open must yield the synthetic path (no demotion)")
                self.assertIn(str(auth), paths, "fail-open must yield the authentic path")
            finally:
                self.fcc._load_provenance_module = orig  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
