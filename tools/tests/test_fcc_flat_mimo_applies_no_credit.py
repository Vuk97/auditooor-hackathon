#!/usr/bin/env python3
"""Guard: function-coverage-completeness must credit a per-fn MIMO hunt sidecar
carried in the FLAT schema - a TOP-LEVEL ``applies_to_target: "no"`` + a
source-cited ``file_line`` but NO nested ``function_anchor`` dict and NO explicit
``verdict``/``disposition`` field.

Root cause (axelar-dlt 2026-07-12): the per-fn mimo hunt emitted a genuine R76
source-cited KILL for ``validatedProtoMarshaler.ValidateBasic`` (a trivial
delegation wrapper) as a flat sidecar. structured_status='' (no verdict field),
function_anchor absent -> the nested-anchor path (which DOES credit applies=no +
source-cite) missed it AND the Pass-1 file_line path saw no structured clean
terminal status, so the fn fell to ``hollow`` -> a permanent
fail-function-coverage-incomplete false-red (260/261). Fix: Pass-1 mirrors the
nested-anchor policy for the flat schema (applies=no + same-file source cite +
fn-name-in-record, not R76-flagged, not a DROP -> real-attack).

NEVER-FALSE-PASS: a bare-prose "no" WITHOUT applies_to_target=no, and an
R76-flagged applies=no, both stay HOLLOW.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "fcc_flat", str(_TOOLS / "function-coverage-completeness.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["fcc_flat"] = m
    spec.loader.exec_module(m)
    return m


class TestFlatMimoAppliesNoCredit(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, tmp: Path, *, applies_no: bool, r76_fail: bool):
        ad = tmp / ".auditooor" / "hunt_findings_sidecars"
        ad.mkdir(parents=True, exist_ok=True)
        src = tmp / "src" / "utils"
        src.mkdir(parents=True, exist_ok=True)
        f = src / "validate.go"
        f.write_text(
            "package utils\n"
            "func (v vpm) ValidateBasic() error {\n"
            "\treturn v.validate()\n}\n", encoding="utf-8")
        sc = {
            "obligation_id": "perfn_1",
            "file": "src/utils/validate.go",
            "fn": "vpm.ValidateBasic",
            "applies_to_target": "no" if applies_no else "maybe",
            "candidate_finding": "NA",
            "file_line": "src/utils/validate.go:2-3",
            "code_excerpt": "func (v vpm) ValidateBasic() error { return v.validate() }",
            "severity_estimate": "NA",
            "falsification_attempt": "generic delegation wrapper, no reachable impact",
        }
        if r76_fail:
            sc["r76_source_existence_fail"] = True
        (ad / "hunt__validate.go__abc__I-generic.json").write_text(
            json.dumps(sc), encoding="utf-8")
        return f

    def _fn(self):
        return self.m.Fn(name="ValidateBasic", file="src/utils/validate.go",
                         line=2, lang="go", end_line=3)

    def test_flat_applies_no_credits_real_attack(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._ws(tmp, applies_no=True, r76_fail=False)
            fns = [self._fn()]
            self.m._classify(tmp, fns)
            self.assertEqual(fns[0].classification, "real-attack",
                             f"flat applies=no + source-cite must credit: {fns[0].evidence}")

    def test_bare_maybe_stays_hollow(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._ws(tmp, applies_no=False, r76_fail=False)
            fns = [self._fn()]
            self.m._classify(tmp, fns)
            self.assertNotEqual(fns[0].classification, "real-attack",
                                "applies=maybe (not no) must NOT get flat credit")

    def test_flat_credit_survives_mutation_verify(self):
        # A source-cited FP-defended rule-out cannot be mutation-verified (no
        # attack/harness to inject a mutant into); it must survive the
        # mutation_verify over-credit downgrade, same as finding-fp-defended-anchor.
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._ws(tmp, applies_no=True, r76_fail=False)
            fns = [self._fn()]
            self.m._classify(tmp, fns, mutation_verify=True, strict=True)
            self.assertEqual(fns[0].classification, "real-attack",
                             f"flat rule-out must survive mutation_verify: {fns[0].evidence}")

    def test_r76_flagged_applies_no_stays_hollow(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._ws(tmp, applies_no=True, r76_fail=True)
            fns = [self._fn()]
            self.m._classify(tmp, fns)
            self.assertNotEqual(fns[0].classification, "real-attack",
                                "R76-flagged (hallucinated cite) applies=no must stay hollow")


if __name__ == "__main__":
    unittest.main()
