#!/usr/bin/env python3
"""test_needs_llm_depth_only_demotion.py - needs-llm-depth coverage false-green fix.

Regression coverage for the NUVA 2026-07-11 false-green: auto-coverage-closer writes
a per-unit ``coverage_unit_verdict`` of ``needs-llm-depth`` when its bounded
mechanical arsenal emits >=1 adversarial hypothesis but proves NO impact - an
EXPLICIT hunt OBLIGATION deferred to an LLM-depth lane. Crediting that verdict as
coverage let the hunt-coverage residual drain to empty, residual-scope-per-fn write
``residual-empty-no-hunt-required``, and make audit-complete STRICT pass WITHOUT the
deferred LLM hunt ever running.

The fix (mirroring the E4 synthetic-lead demotion) demotes a coverage token whose
ONLY provenance is a needs-llm-depth verdict, fail-closed under strict, advisory-WARN
(byte-identical) by default, and NEVER demotes a unit ALSO covered by a genuine
dispatched hunt sidecar or a mechanical-hunt-no-finding verdict.

Cases:
  (1) needs-llm-depth-ONLY unit demotes under strict (env=1) - re-enters residual.
  (2) needs-llm-depth unit ALSO covered by a GENUINE (E4-authentic, duration_s>0)
      hunt sidecar STAYS covered (never-false-demote).
  (3) a mechanical-hunt-no-finding unit is NEVER demoted (it is genuine coverage).
  (4) NON-STRICT (no env) is byte-identical: demoted set empty; residual credits.
  (5) a SYNTHETIC-LEAD hunt sidecar (duration_s==0 & started==ended) does NOT
      protect - a needs-llm-depth unit backed only by it still demotes under strict.

Stdlib-only. Loads the real tools by path and also runs the residual scoper as a
subprocess end-to-end so the emitted obligation status is asserted.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HCG_PATH = REPO / "tools" / "hunt-coverage-gate.py"
RSP_PATH = REPO / "tools" / "residual-scope-per-fn.py"

_STRICT_ENV = "AUDITOOOR_NEEDS_LLM_DEPTH_STRICT"
_VERDICT_SCHEMA = "auditooor.coverage_unit_verdict.v1"


def _load(mod_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _slug(unit: str) -> str:
    return unit.replace("/", "-").replace("::", "--").replace(".", "-")


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _verdict(ws: Path, unit_id: str, source_path: str, verdict: str) -> None:
    """Write a coverage_unit_verdicts/<slug>.json (as auto-coverage-closer would)."""
    p = ws / ".auditooor" / "coverage_unit_verdicts" / (_slug(unit_id) + ".json")
    _write_json(
        p,
        {
            "schema": _VERDICT_SCHEMA,
            "workspace": ws.name,
            "unit_id": unit_id,
            "source_path": source_path,
            "verdict": verdict,
            "coverage_credit": "mechanical-source-cited",
            "is_r80_poc": False,
        },
    )


def _hunt_sidecar(ws: Path, name: str, file: str, fn: str, *, authentic: bool) -> None:
    """Write a hunt_findings_sidecars/<name>.json. authentic=True => duration_s>0
    (E4 'real-duration' -> authentic); authentic=False => inline-authored synthetic
    (duration_s==0 & started==ended -> synthetic-lead)."""
    sc = {
        "task_id": name,
        "workspace": ws.name,
        "workspace_path": str(ws),
        "function_anchor": {"file": file, "function": fn},
        "file_line": f"{file}:1-2",
        "code_excerpt": f"func {fn}() {{}}",
        "verdict": "killed",
        "applies_to_target": "no",
        "verification_tier": "tier-1-agent-source-read",
    }
    if authentic:
        sc["duration_s"] = 7.5
        sc["started_at_utc"] = "2026-07-11T00:00:00Z"
        sc["ended_at_utc"] = "2026-07-11T00:00:07Z"
    else:
        sc["duration_s"] = 0
        sc["started_at_utc"] = "2026-07-11T00:00:00Z"
        sc["ended_at_utc"] = "2026-07-11T00:00:00Z"
        sc["verification_tier"] = "tier-3-synthetic-taxonomy-anchored"
    _write_json(ws / ".auditooor" / "hunt_findings_sidecars" / (name + ".json"), sc)


def _residual_queue(ws: Path, units: list[tuple[str, str]]) -> None:
    items = [
        {"kind": "surface-unit", "unit_id": f"{src}::{fn}", "source_path": src}
        for src, fn in units
    ]
    _write_json(
        ws / ".auditooor" / "coverage_residual_worker_queue.json",
        {"schema": "auditooor.coverage_residual_worker_queue.v1", "items": items},
    )


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.hcg = _load("hcg_under_test", HCG_PATH)
        self.rsp = _load("rsp_under_test", RSP_PATH)
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        # make sure no ambient strict env leaks in
        self._saved_env = os.environ.pop(_STRICT_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(_STRICT_ENV, None)
        if self._saved_env is not None:
            os.environ[_STRICT_ENV] = self._saved_env
        self._tmp.cleanup()

    def _strict(self, on: bool) -> None:
        if on:
            os.environ[_STRICT_ENV] = "1"
        else:
            os.environ.pop(_STRICT_ENV, None)
        # rsp caches the hcg module, but the strict predicate reads os.environ live.

    def _obligation_via_cli(self, strict: bool) -> dict:
        out = self.ws / ".auditooor" / "obligation.json"
        env = dict(os.environ)
        if strict:
            env[_STRICT_ENV] = "1"
        else:
            env.pop(_STRICT_ENV, None)
        subprocess.run(
            [sys.executable, str(RSP_PATH), "--workspace", str(self.ws),
             "--emit-obligation", str(out)],
            check=True, capture_output=True, env=env,
        )
        return json.loads(out.read_text(encoding="utf-8"))


class NeedsLlmDepthDemotion(_Base):
    def test_1_needs_llm_depth_only_demotes_under_strict(self) -> None:
        _verdict(self.ws, "Foo.sol::bar", "Foo.sol", "needs-llm-depth")
        # advisory (no env): nothing demoted, byte-identical to pre-fix.
        self._strict(False)
        self.assertEqual(self.hcg.needs_llm_depth_only_units(self.ws), set())
        # strict: the unit demotes (its only provenance is the needs-llm-depth verdict).
        self._strict(True)
        self.assertEqual(
            self.hcg.needs_llm_depth_only_units(self.ws), {"Foo.sol::bar"}
        )
        toks, trace = self.hcg._needs_llm_depth_only_scanned_tokens(self.ws)
        self.assertIn("Foo.sol::bar", toks)
        self.assertEqual(trace["needs_llm_depth_only_units"], ["Foo.sol::bar"])

    def test_2_genuine_hunt_protects(self) -> None:
        _verdict(self.ws, "Foo.sol::bar", "Foo.sol", "needs-llm-depth")
        _hunt_sidecar(self.ws, "hunt__Foo__bar", "Foo.sol", "bar", authentic=True)
        self._strict(True)
        # E4-authentic hunt sidecar covers the same token -> NEVER demoted.
        self.assertEqual(self.hcg.needs_llm_depth_only_units(self.ws), set())
        toks, trace = self.hcg._needs_llm_depth_only_scanned_tokens(self.ws)
        self.assertNotIn("Foo.sol::bar", toks)
        self.assertGreaterEqual(trace["authentic_hunt_protected_token_count"], 1)

    def test_3_mechanical_no_finding_never_demoted(self) -> None:
        _verdict(self.ws, "Foo.sol::baz", "Foo.sol", "mechanical-hunt-no-finding")
        self._strict(True)
        self.assertEqual(self.hcg.needs_llm_depth_only_units(self.ws), set())

    def test_4_non_strict_is_byte_identical(self) -> None:
        _verdict(self.ws, "Foo.sol::bar", "Foo.sol", "needs-llm-depth")
        self._strict(False)
        self.assertFalse(self.hcg._needs_llm_depth_strict_enabled_for_coverage())
        self.assertEqual(self.hcg.needs_llm_depth_only_units(self.ws), set())

    def test_5_synthetic_lead_hunt_does_not_protect(self) -> None:
        _verdict(self.ws, "Foo.sol::bar", "Foo.sol", "needs-llm-depth")
        # a synthetic-lead sidecar (inline-authored, duration_s==0) is NOT genuine
        # provenance, so it must NOT protect the needs-llm-depth unit.
        _hunt_sidecar(self.ws, "hunt__Foo__bar_syn", "Foo.sol", "bar", authentic=False)
        self._strict(True)
        self.assertEqual(
            self.hcg.needs_llm_depth_only_units(self.ws), {"Foo.sol::bar"}
        )


class ResidualReopen(_Base):
    def test_residual_reopens_under_strict_only(self) -> None:
        _verdict(self.ws, "src/x.go::Bar", "src/x.go", "needs-llm-depth")
        _residual_queue(self.ws, [("src/x.go", "Bar")])

        # BEFORE (advisory): the needs-llm-depth verdict drains the residual (the
        # reproduced false-green) -> residual-empty-no-hunt-required.
        before = self._obligation_via_cli(strict=False)
        self.assertEqual(before["status"], "residual-empty-no-hunt-required")
        self.assertEqual(before["residual_surface_units"], 0)

        # AFTER (strict): the unit re-enters the residual -> a hunt obligation.
        after = self._obligation_via_cli(strict=True)
        self.assertEqual(after["status"], "residual-hunt-required")
        self.assertGreaterEqual(after["residual_surface_units"], 1)

    def test_residual_genuine_hunt_stays_covered_under_strict(self) -> None:
        _verdict(self.ws, "src/x.go::Bar", "src/x.go", "needs-llm-depth")
        _hunt_sidecar(self.ws, "hunt__x__Bar", "src/x.go", "Bar", authentic=True)
        _residual_queue(self.ws, [("src/x.go", "Bar")])
        # genuine hunt present -> even under strict the unit stays covered (drained).
        after = self._obligation_via_cli(strict=True)
        self.assertEqual(after["status"], "residual-empty-no-hunt-required")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
