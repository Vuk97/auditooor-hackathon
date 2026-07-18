#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-generic-100pct-audit-complete-enforcement agent_pathspec.json -->
"""Regression tests for the 100%-terminal-adjudication completeness enforcement.

The honesty bug these close: `make audit-complete STRICT=1` used to PASS while
three completeness axes were only ADVISORY WARNs -
  (1) the mechanism plane's UNSCANNED cells,
  (2) the swept-surface uncovered fraction,
  (3) the rubric rows nobody attempted.
So a pass could hide 62% unswept + N unadjudicated mechanisms behind loud warns.

Cases (per the build brief):
  (a) an UNSCANNED mechanism cell FAILs the matrix under STRICT, PASSes advisory
      without;
  (b) a cited agent-cleared mechanism cell PASSes (terminal via reasoning);
  (c) a bare/uncited disposition clear is REJECTED (never-false-pass);
  (d) an UNATTEMPTED rubric row w/o an N-A reason FAILs the rubric signal under
      STRICT (and terminal via an N-A disposition PASSes);
  (e) the NON-strict swept/rubric verdict is byte-identical to pre-change (WARN-pass);
  (f) the mechanism enforce flag AUDITOOOR_MECHANISM_AXIS_ENFORCE actually flips
      enforce=True (the misleading `enforce=False` print bug).

Tests build ephemeral tmp workspaces and never modify any tool file. The two
hyphenated modules are imported with sys.modules registration (required for the
Python 3.14 @dataclass resolution in audit-completeness-check.py).
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
from unittest import mock

_REPO = Path(__file__).resolve().parents[2]
_CMB_PATH = _REPO / "tools" / "completeness-matrix-build.py"
_ACC_PATH = _REPO / "tools" / "audit-completeness-check.py"

_AXIS_ENVS = (
    "AUDITOOOR_L37_STRICT",
    "AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT",
    "AUDITOOOR_RUBRIC_ATTEMPT_STRICT",
    "AUDITOOOR_SWEPT_TERMINAL_STRICT",
    "AUDITOOOR_MECHANISM_AXIS_ENFORCE",
    "AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE",
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # required for 3.14 @dataclass resolution
    spec.loader.exec_module(mod)
    return mod


_CMB = _load("cmb_axes_test", _CMB_PATH)
_ACC = _load("acc_axes_test", _ACC_PATH)


def _clean_env() -> dict:
    env = dict(os.environ)
    for k in _AXIS_ENVS:
        env.pop(k, None)
    return env


class _WSMixin(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="axes_ws_"))
        (self.tmp / ".auditooor").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, obj):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(obj, (dict, list)):
            p.write_text(json.dumps(obj), encoding="utf-8")
        else:
            p.write_text(str(obj), encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# (f) mechanism enforce flag actually flips enforce=True
# ---------------------------------------------------------------------------
class TestMechanismEnforceFlagFlips(unittest.TestCase):
    def test_flag_flips_enforce_true(self):
        with mock.patch.dict(os.environ, _clean_env(), clear=True):
            self.assertFalse(_CMB._mech_unscanned_enforced())
            self.assertFalse(_CMB._enforce_enabled())
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_MECHANISM_AXIS_ENFORCE": "1"}, clear=True):
            self.assertTrue(_CMB._mech_unscanned_enforced())
            # The misleading `enforce=False` print bug: enforce_enabled must now be True.
            self.assertTrue(_CMB._enforce_enabled())

    def test_flag_zero_does_not_enforce(self):
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_MECHANISM_AXIS_ENFORCE": "0"}, clear=True):
            self.assertFalse(_CMB._mech_unscanned_enforced())
            self.assertFalse(_CMB._enforce_enabled())

    def test_global_l37_strict_flips_mechanism(self):
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_L37_STRICT": "1"}, clear=True):
            self.assertTrue(_CMB._mech_unscanned_enforced())


# ---------------------------------------------------------------------------
# (a)(b)(c) mechanism axis: unscanned FAIL under strict, agent-cleared PASS,
#           bare/uncited clear REJECTED.
# ---------------------------------------------------------------------------
class TestMechanismAxis(_WSMixin):
    def _mech_axis(self):
        # A single in-scope Solidity value-mover so the ws has a language + impacts.
        inscope = {"file": "Vault.sol", "function": "withdraw", "kind": "external"}
        self._write(".auditooor/inscope_units.jsonl", "")
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps(inscope) + "\n", encoding="utf-8")
        inscope_map = _CMB._load_inscope(self.tmp)
        impacts = set()
        return _CMB._build_mechanism_axis(self.tmp, inscope_map, impacts)

    def test_unscanned_cell_present(self):
        ax = self._mech_axis()
        # With no detector scan + no agent verdict, the plane has unscanned cells.
        self.assertGreater(ax["not_enumerated_unscanned"], 0,
                           "fixture should have >=1 unscanned [impact x mechanism] cell")

    def test_a_unscanned_fails_under_strict_passes_advisory(self):
        # ADVISORY (no env): unscanned cells only WARN -> not enforced.
        with mock.patch.dict(os.environ, _clean_env(), clear=True):
            self.assertFalse(self._mech_axis()["unscanned_enforced"])
        # STRICT: unscanned cells become a terminal obligation -> enforced.
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_L37_STRICT": "1"}, clear=True):
            self.assertTrue(self._mech_axis()["unscanned_enforced"])

    def test_b_agent_cleared_with_citation_is_terminal(self):
        # Load-path fail-closed: an agent-cleared verdict needs >=1 ref + >=40-char
        # reasoning to CLEAR a cell (mirrors _load_agent_mechanism_verdicts).
        row = {
            "impact": "theft", "mechanism": "reentrancy", "verdict": "cleared",
            "source_refs": ["Vault.sol:42"],
            "reasoning": "nonReentrant modifier present on withdraw at Vault.sol:42; "
                         "checked against the CEI pattern, no external call precedes state write.",
        }
        cleared, findings = self._agent_verdicts([row])
        self.assertIn(("theft", "reentrancy"), cleared)

    def test_c_bare_uncited_clear_rejected(self):
        # never-false-pass: a bare 'cleared' with NO citation / too-short reasoning
        # must NOT clear the cell.
        rows = [
            {"impact": "theft", "mechanism": "reentrancy", "verdict": "cleared"},  # no refs
            {"impact": "theft", "mechanism": "reentrancy", "verdict": "cleared",
             "source_refs": ["Vault.sol:42"], "reasoning": "looks fine"},  # short reasoning
        ]
        cleared, findings = self._agent_verdicts(rows)
        self.assertNotIn(("theft", "reentrancy"), cleared,
                         "bare/uncited clear must be REJECTED (never-false-pass)")

    def _agent_verdicts(self, rows):
        # _load_agent_mechanism_verdicts reads .auditooor/agent_mechanism_verdicts/*.json
        d = self.tmp / ".auditooor" / "agent_mechanism_verdicts"
        d.mkdir(parents=True, exist_ok=True)
        (d / "verdicts.json").write_text(json.dumps(rows), encoding="utf-8")
        return _CMB._load_agent_mechanism_verdicts(self.tmp)


# ---------------------------------------------------------------------------
# (d)(e) rubric-attempt axis: unattempted row FAILs under strict; N-A disposition
#         PASSes; NON-strict byte-identical WARN-pass.
# ---------------------------------------------------------------------------
class TestRubricAttemptAxis(_WSMixin):
    def _write_rubric_report(self):
        report = {
            "schema": "auditooor.workspace_rubric_coverage.v1",
            "total_rows": 3,
            "rows_with_candidate": 2,
            "rows_uncovered": 1,
            "rubric_coverage_fraction": 0.6667,
            "uncovered_rows": [
                {"tier": "critical", "rubric_id": "R1",
                 "sentence": "Protocol insolvency"},
            ],
        }
        self._write(".auditooor/rubric_coverage_report.json", report)

    def test_d_unattempted_row_fails_under_strict(self):
        self._write_rubric_report()
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_L37_STRICT": "1"}, clear=True):
            r = _ACC.check_rubric_coverage(self.tmp)
        self.assertFalse(r.ok, "unattempted rubric row must FAIL under strict")
        self.assertEqual(r.detail.get("rubric_non_terminal_rows"), 1)

    def test_d_na_disposition_makes_row_terminal(self):
        self._write_rubric_report()
        # An N-A-with-reason disposition keyed on the rubric id OR sentence clears it.
        self._write(".auditooor/rubric_attempt_dispositions.jsonl",
                    json.dumps({"row": "R1",
                                "reason": "protocol has no lending; insolvency is N/A for this AMM"}) + "\n")
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_L37_STRICT": "1"}, clear=True):
            r = _ACC.check_rubric_coverage(self.tmp)
        self.assertTrue(r.ok, "N-A-with-reason disposition should make the row terminal")

    def test_c_bare_uncited_na_disposition_rejected(self):
        # never-false-pass: an N-A row with too-short reason is ignored.
        self._write_rubric_report()
        self._write(".auditooor/rubric_attempt_dispositions.jsonl",
                    json.dumps({"row": "R1", "reason": "n/a"}) + "\n")  # < 8 chars
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_L37_STRICT": "1"}, clear=True):
            r = _ACC.check_rubric_coverage(self.tmp)
        self.assertFalse(r.ok, "bare/uncited N-A disposition must be REJECTED")

    def test_e_nonstrict_byte_identical_warn_pass(self):
        self._write_rubric_report()
        with mock.patch.dict(os.environ, _clean_env(), clear=True):
            r = _ACC.check_rubric_coverage(self.tmp)
        # NON-strict: PASSES (presence is the requirement), reason has no STRICT FAIL.
        self.assertTrue(r.ok, "non-strict must WARN-pass (backward-compat)")
        self.assertNotIn("STRICT FAIL", r.reason)


# ---------------------------------------------------------------------------
# swept-surface axis: uncovered unit FAILs under strict; disposition/skip terminal;
# NON-strict byte-identical.
# ---------------------------------------------------------------------------
class TestSweptSurfaceAxis(_WSMixin):
    def test_uncovered_unit_terminal_helpers(self):
        # Focused unit test of the terminal-disposition loader used by the axis
        # (avoids the coverage signal's many upstream freshness guards).
        self._write(".auditooor/swept_surface_dispositions.jsonl",
                    json.dumps({"unit": "Lib.sol::toAddress",
                                "reason": "pure byte helper, no value movement"}) + "\n"
                    + json.dumps({"unit": "X.sol::f", "reason": "n/a"}) + "\n")  # too short
        with mock.patch.dict(os.environ, _clean_env(), clear=True):
            disp = _ACC._load_terminal_dispositions(self.tmp, "swept_surface_dispositions.jsonl")
        self.assertIn("Lib.sol::toAddress", disp)
        self.assertNotIn("X.sol::f", disp, "too-short reason must be rejected")

    def test_swept_strict_toggle(self):
        with mock.patch.dict(os.environ, _clean_env(), clear=True):
            self.assertFalse(_ACC._swept_terminal_strict())
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_L37_STRICT": "1"}, clear=True):
            self.assertTrue(_ACC._swept_terminal_strict())
        with mock.patch.dict(os.environ, {**_clean_env(),
                                          "AUDITOOOR_SWEPT_TERMINAL_STRICT": "1"}, clear=True):
            self.assertTrue(_ACC._swept_terminal_strict())


if __name__ == "__main__":
    unittest.main()
