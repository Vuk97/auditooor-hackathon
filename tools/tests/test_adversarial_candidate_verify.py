#!/usr/bin/env python3
"""Tests for tools/adversarial-candidate-verify.py (multi-perspective panel)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "adversarial-candidate-verify.py"

_spec = importlib.util.spec_from_file_location("acv", TOOL)
acv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acv)


def _eval(text: str, severity: str | None = "high", strict: bool = False):
    sev = None if severity is None else severity.lower()
    src = "test" if sev else "missing"
    return acv.evaluate(text, sev, src, strict)


class TestSeverityScope(unittest.TestCase):
    def test_low_is_out_of_scope(self):
        p = _eval("anything", severity="low")
        self.assertEqual(p["panel_verdict"], "pass-out-of-scope")

    def test_missing_severity_out_of_scope(self):
        p = _eval("anything", severity=None)
        self.assertEqual(p["panel_verdict"], "pass-out-of-scope")

    def test_medium_fires_panel(self):
        p = _eval("nothing useful here", severity="medium")
        self.assertNotEqual(p["panel_verdict"], "pass-out-of-scope")


class TestRefutedIfUncertain(unittest.TestCase):
    def test_bare_candidate_all_three_refuted_killed(self):
        p = _eval("the contract has a bug somewhere", severity="high")
        self.assertEqual(p["refutation_count"], 3)
        self.assertEqual(p["panel_verdict"], "fail-killed-by-panel")

    def test_each_lens_defaults_refuted(self):
        p = _eval("no evidence at all", severity="medium")
        for entry in p["lenses"]:
            self.assertEqual(entry["vote"], "refuted")
            self.assertEqual(entry["effective"], "refuted")


class TestPerLensEvidence(unittest.TestCase):
    def test_correctness_survives_on_file_line(self):
        p = _eval("root cause at Token.sol:88 is the missing check", severity="high")
        corr = next(l for l in p["lenses"] if l["lens"] == acv.LENS_CORRECTNESS)
        self.assertEqual(corr["vote"], "survives")

    def test_reachability_survives_on_real_entrypoint(self):
        p = _eval("the path is reachable from a real entrypoint", severity="high")
        reach = next(l for l in p["lenses"] if l["lens"] == acv.LENS_REACHABILITY)
        self.assertEqual(reach["vote"], "survives")

    def test_defense_survives_on_traversal(self):
        p = _eval("defense-in-depth traversal verified end to end", severity="high")
        d = next(l for l in p["lenses"] if l["lens"] == acv.LENS_DEFENSE)
        self.assertEqual(d["vote"], "survives")

    def test_defense_survives_on_honest_ceiling(self):
        p = _eval("we hit a defense-in-depth ceiling and walk back honestly", severity="high")
        d = next(l for l in p["lenses"] if l["lens"] == acv.LENS_DEFENSE)
        self.assertEqual(d["vote"], "survives")


class TestMajorityKill(unittest.TestCase):
    def test_two_refuted_one_survive_killed(self):
        # only correctness has evidence; reachability + defense refuted -> 2 refute
        p = _eval("root cause at A.sol:1", severity="high")
        self.assertEqual(p["refutation_count"], 2)
        self.assertEqual(p["panel_verdict"], "fail-killed-by-panel")

    def test_one_refuted_two_survive_passes(self):
        text = ("root cause at A.sol:1 reachable from a real entrypoint; "
                "no extra evidence for defense")
        p = _eval(text, severity="high")
        # correctness + reachability survive, defense refuted -> 1 refute
        self.assertEqual(p["refutation_count"], 1)
        self.assertEqual(p["panel_verdict"], "pass-survived-panel")

    def test_zero_refuted_passes(self):
        text = ("root cause at A.sol:1 reachable from a real entrypoint via "
                "external caller; payload survives every defense layer reaching "
                "the impact")
        p = _eval(text, severity="critical")
        self.assertEqual(p["refutation_count"], 0)
        self.assertEqual(p["panel_verdict"], "pass-survived-panel")


class TestRebuttalRuleOut(unittest.TestCase):
    def test_rebuttal_rules_out_one_lens(self):
        # correctness has evidence; reachability + defense refuted; rebut both
        text = ("root cause at A.sol:1\n"
                "acv-rebuttal-reachability: deployed-config confirms reachable\n"
                "acv-rebuttal-defense: single-defense protocol, no other layers\n")
        p = _eval(text, severity="high")
        self.assertEqual(p["refutation_count"], 2)
        self.assertEqual(p["refutations_ruled_out"], 2)
        self.assertEqual(p["panel_verdict"], "pass-refutations-ruled-out")

    def test_rebuttal_html_comment_form(self):
        text = ("root cause at A.sol:1\n"
                "<!-- acv-rebuttal-reachability: see analytics for population -->\n"
                "<!-- acv-rebuttal-defense: ceiling documented -->\n")
        p = _eval(text, severity="high")
        self.assertEqual(p["panel_verdict"], "pass-refutations-ruled-out")

    def test_only_one_rebuttal_still_killed(self):
        # 3 refuted, only 1 ruled out -> 2 unresolved -> kill
        text = "vague claim\nacv-rebuttal-correctness: trusted prior audit\n"
        p = _eval(text, severity="high")
        self.assertEqual(p["refutation_count"], 3)
        self.assertEqual(p["refutations_ruled_out"], 1)
        self.assertEqual(p["panel_verdict"], "fail-killed-by-panel")

    def test_oversized_rebuttal_ignored(self):
        big = "x" * 250
        text = (f"root cause at A.sol:1\n"
                f"acv-rebuttal-reachability: {big}\n"
                f"acv-rebuttal-defense: short ok\n")
        p = _eval(text, severity="high")
        # reachability rebuttal ignored (>200) -> still 1 unresolved (<2) passes
        reach = next(l for l in p["lenses"] if l["lens"] == acv.LENS_REACHABILITY)
        self.assertIsNone(reach["rebuttal"])

    def test_empty_rebuttal_ignored(self):
        text = "root cause at A.sol:1\nacv-rebuttal-defense:   \n"
        p = _eval(text, severity="high")
        d = next(l for l in p["lenses"] if l["lens"] == acv.LENS_DEFENSE)
        self.assertIsNone(d["rebuttal"])

    def test_rebuttal_does_not_silence_sibling_lens(self):
        # correctness rebuttal must not rule out reachability/defense
        text = "vague\nacv-rebuttal-correctness: ok reason\n"
        p = _eval(text, severity="high")
        reach = next(l for l in p["lenses"] if l["lens"] == acv.LENS_REACHABILITY)
        self.assertEqual(reach["effective"], "refuted")


class TestStrictMode(unittest.TestCase):
    def test_strict_kills_on_single_unresolved(self):
        text = ("root cause at A.sol:1 reachable from a real entrypoint via "
                "external caller")  # defense refuted (1 unresolved)
        p = _eval(text, severity="high", strict=True)
        self.assertEqual(p["refutation_count"], 1)
        self.assertEqual(p["panel_verdict"], "fail-killed-by-panel")

    def test_strict_passes_when_all_survive(self):
        text = ("root cause at A.sol:1 reachable from a real entrypoint via "
                "external caller; payload survives every defense layer reaching "
                "the impact")
        p = _eval(text, severity="high", strict=True)
        self.assertEqual(p["panel_verdict"], "pass-survived-panel")

    def test_strict_passes_when_unresolved_ruled_out(self):
        # correctness + reachability survive; defense refuted but ruled out ->
        # 0 unresolved -> strict passes (single refutation, ruled out)
        text = ("root cause at A.sol:1 reachable from a real entrypoint via "
                "external caller\n"
                "acv-rebuttal-defense: single-defense protocol\n")
        p = _eval(text, severity="high", strict=True)
        self.assertIn(p["panel_verdict"],
                      ("pass-survived-panel", "pass-refutations-ruled-out"))
        self.assertEqual(p["refutation_count"] - p["refutations_ruled_out"], 0)


class TestJsonCandidate(unittest.TestCase):
    def test_json_severity_field(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cand.json"
            p.write_text(json.dumps({
                "severity": "High",
                "root_cause": "missing check at Vault.sol:42",
                "notes": "reachable from a real entrypoint via external caller",
                "defense": "survives every defense layer to the impact",
            }))
            text, obj = acv._load_candidate(p)
            sev, src = acv._severity(text, p, "auto", obj)
            self.assertEqual(sev, "high")
            res = acv.evaluate(text, sev, src, False)
            self.assertEqual(res["panel_verdict"], "pass-survived-panel")

    def test_json_flatten_finds_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({"severity": "medium", "blob": "nothing"}))
            text, obj = acv._load_candidate(p)
            sev, src = acv._severity(text, p, "auto", obj)
            res = acv.evaluate(text, sev, src, False)
            self.assertEqual(res["panel_verdict"], "fail-killed-by-panel")


class TestSchemaAndCLI(unittest.TestCase):
    def test_schema_id(self):
        p = _eval("x", severity="medium")
        self.assertEqual(p["schema_id"], "auditooor.adversarial_candidate_verify.v1")

    def test_cli_json_runs(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "cand.md"
            f.write_text("Severity: Medium\nvague claim\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), str(f), "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0)
            out = json.loads(r.stdout)
            self.assertEqual(out["panel_verdict"], "fail-killed-by-panel")

    def test_cli_missing_file_errors(self):
        r = subprocess.run(
            [sys.executable, str(TOOL), "/nonexistent/x.md", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)

    def test_cli_severity_override(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "cand.md"
            f.write_text("vague claim with no severity\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), str(f), "--severity", "Low", "--json"],
                capture_output=True, text=True,
            )
            out = json.loads(r.stdout)
            self.assertEqual(out["panel_verdict"], "pass-out-of-scope")


if __name__ == "__main__":
    unittest.main()
