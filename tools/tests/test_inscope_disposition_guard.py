"""Tests for inscope-disposition-guard.py + scope_authority.py - the generic,
language-agnostic backstop that fails closed when a disposition marks an
IN-SCOPE unit out-of-scope (strata 2026-07-01 class)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


G = _load("inscope_disposition_guard", "inscope-disposition-guard.py")
SA = _load("scope_authority", "scope_authority.py")


def _ws(inscope_records, disposition=None, disp_name="unhunted_terminal_verdicts.json"):
    ws = Path(tempfile.mkdtemp())
    a = ws / ".auditooor"
    a.mkdir()
    (a / "inscope_units.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in inscope_records), encoding="utf-8")
    if disposition is not None:
        (a / disp_name).write_text(json.dumps(disposition), encoding="utf-8")
    SA.clear_cache()
    return ws


class TestScopeAuthority(unittest.TestCase):
    def test_inscope_file_by_relpath_and_basename(self):
        ws = _ws([{"file": "src/gov/AccessControlManager.sol", "function": "grantCall"}])
        self.assertTrue(SA.is_inscope_file(ws, "src/gov/AccessControlManager.sol"))
        self.assertTrue(SA.is_inscope_file(ws, "AccessControlManager.sol"))
        self.assertTrue(SA.is_inscope_file(ws, "src/gov/AccessControlManager.sol:67"))
        self.assertFalse(SA.is_inscope_file(ws, "src/other/Unrelated.sol"))

    def test_exact_path_wins_over_duplicate_basename(self):
        ws = _ws([{"file": "src/live/ImportAssistant.sol", "function": "swap"}])
        self.assertTrue(SA.is_inscope_file(ws, "src/live/ImportAssistant.sol", exact=True))
        self.assertFalse(SA.is_inscope_file(ws, "src/legacy/ImportAssistant.sol", exact=True))
        self.assertFalse(SA.is_inscope_file(
            ws, str(ws / "src" / "legacy" / "ImportAssistant.sol"), exact=True))

    def test_absent_manifest_asserts_nothing(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        SA.clear_cache()
        self.assertFalse(SA.is_inscope_file(ws, "anything.sol"))

    def test_oos_family_tokens(self):
        for t in ("vendored-trusted-library", "out-of-scope", "trusted-infra",
                  "oos-curator-config", "not-in-scope"):
            self.assertTrue(SA.is_oos_family(t), t)
        for t in ("covered-in-scope", "hunt-source-refuted", "interface-declaration", "finding"):
            self.assertFalse(SA.is_oos_family(t), t)

    def test_language_agnostic_go_rust(self):
        ws = _ws([{"file": "x/keeper/msg_server.go", "function": "MsgTransfer"},
                  {"file": "src/vault/lib.rs", "function": "withdraw"}])
        self.assertTrue(SA.is_inscope_file(ws, "x/keeper/msg_server.go"))
        self.assertTrue(SA.is_inscope_file(ws, "lib.rs"))


class TestGuard(unittest.TestCase):
    def test_pass_when_no_inscope_oos(self):
        ws = _ws([{"file": "src/A.sol", "function": "f"}],
                 disposition={"verdicts": [
                     {"evidence_class": "hunt-source-refuted", "evidence_ref": "src/A.sol"},
                     {"evidence_class": "vendored-trusted-library", "evidence_ref": "lib/oz/Math.sol"}]})
        self.assertEqual(G.evaluate(str(ws))["verdict"], "pass-no-inscope-oos")

    def test_fail_when_inscope_marked_vendored(self):
        ws = _ws([{"file": "src/gov/AccessControlManager.sol", "function": "grantCall"}],
                 disposition={"verdicts": [
                     {"evidence_class": "vendored-trusted-library",
                      "evidence_ref": "src/gov/AccessControlManager.sol", "title": "wrong"}]})
        r = G.evaluate(str(ws))
        self.assertEqual(r["verdict"], "fail-inscope-marked-oos")
        self.assertEqual(len(r["violations"]), 1)

    def test_fail_catches_any_oos_family_and_language(self):
        # a Go in-scope unit wrongly closed "trusted-infra" in a different artifact
        ws = _ws([{"file": "x/keeper/keeper.go", "function": "Withdraw"}],
                 disposition={"classes": [
                     {"status": "trusted-infra", "evidence_ref": "x/keeper/keeper.go"}]},
                 disp_name="exploit_class_coverage.json")
        self.assertEqual(G.evaluate(str(ws))["verdict"], "fail-inscope-marked-oos")

    def test_pass_no_manifest_is_advisory_not_false_green(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        SA.clear_cache()
        self.assertEqual(G.evaluate(str(ws))["verdict"], "pass-no-manifest")

    def test_skip_names_not_flagged(self):
        # the OOS index itself legitimately holds OOS tokens - must be skipped
        ws = _ws([{"file": "src/A.sol", "function": "f"}],
                 disposition={"entries": [{"class": "out-of-scope", "file": "src/A.sol"}]},
                 disp_name="bug_bounty_oos_index.json")
        self.assertEqual(G.evaluate(str(ws))["verdict"], "pass-no-inscope-oos")

    def test_not_fileable_verdict_mentioning_oos_in_prose_is_not_flagged(self):
        # strata Tranche.sol 2026-07-02 false-red: a NOT-FILEABLE in-scope closure
        # whose verdict NARRATIVE explains an OOS-mock selector collision must NOT
        # be mis-flagged as an OOS closure. The authoritative class is
        # disposition_type='not-fileable' (in-scope); "OUT-OF-SCOPE" appears only
        # inside a prose explanation. A class token is a slug; prose is not.
        narrative = (
            "CONFIRMED AT SOURCE (R76) + runnable PoC PASS, but NOT-FILEABLE "
            "(bounded-dust permanent freeze). The ~1.0-share revert is NOT the "
            "in-scope Tranche guard - it is a different, identically-named error "
            "emitted by the OUT-OF-SCOPE mock Ethena vault test/ethena/StakedUSDe.sol "
            "MinSharesViolation(); the prior PoC matched the wrong contract's selector.")
        ws = _ws([{"file": "src/contracts/tranches/Tranche.sol", "function": "withdraw"}],
                 disposition={"records": [
                     {"disposition_type": "not-fileable", "verdict": narrative,
                      "file": "tranches/Tranche.sol", "line": "20,452-455"}]},
                 disp_name="mechanism_dispositions.jsonl")
        self.assertEqual(G.evaluate(str(ws))["verdict"], "pass-no-inscope-oos")

    def test_real_oos_slug_in_disposition_type_is_still_caught(self):
        # completeness (anti-false-negative): a genuine OOS class SLUG living in
        # the disposition_type field of an in-scope unit is still a violation.
        ws = _ws([{"file": "src/contracts/tranches/Tranche.sol", "function": "withdraw"}],
                 disposition={"records": [
                     {"disposition_type": "oos-curator-config",
                      "verdict": "closed as out of scope",
                      "file": "tranches/Tranche.sol"}]},
                 disp_name="mechanism_dispositions.jsonl")
        self.assertEqual(G.evaluate(str(ws))["verdict"], "fail-inscope-marked-oos")


class TestOosFamilyProseGuard(unittest.TestCase):
    def test_prose_narrative_never_oos_family(self):
        prose = ("reached from the OUT-OF-SCOPE mock vault; this is vendored in the "
                 "test harness only and not-in-scope for the finding")
        self.assertFalse(SA.is_oos_family(prose))

    def test_slug_class_tokens_still_match(self):
        for slug in ("vendored", "out-of-scope-test-only", "oos-curator-config",
                     "trusted-infra-compromise", "not-in-scope"):
            self.assertTrue(SA.is_oos_family(slug), slug)

    def test_inscope_disposition_type_slug_not_oos(self):
        for slug in ("not-fileable", "refuted", "finding", "covered-by-fuzz"):
            self.assertFalse(SA.is_oos_family(slug), slug)

    def test_fcc_filtered_coverage_status_not_oos(self):
        # 2026-07-02 coverage_plane.jsonl false-red: "out-of-scope-fcc-filtered"
        # classifies a FUNCTION as non-callable-attack-surface (coverage
        # bookkeeping), not a program-scope disposition - must never match.
        for slug in ("out-of-scope-fcc-filtered", "out_of_scope_fcc_filtered"):
            self.assertFalse(SA.is_oos_family(slug), slug)


class TestCoveragePlaneNotFalseRed(unittest.TestCase):
    def test_fcc_filtered_flat_jsonl_row_does_not_trip_guard(self):
        # coverage_plane.jsonl exposes `status` as a flat top-level field per row
        # (unlike completeness_matrix.json's nested assets[].functions[]), so it
        # is directly visible to _iter_records - this is the real strata shape
        # that produced the false-red.
        ws = _ws([{"file": "src/contracts/tranches/Accounting.sol", "function": "totalReserve"}],
                 disposition={"status": "out-of-scope-fcc-filtered",
                              "file": "src/contracts/tranches/Accounting.sol",
                              "unit": "src/contracts/tranches/Accounting.sol::totalReserve"},
                 disp_name="coverage_plane.jsonl")
        self.assertEqual(G.evaluate(str(ws))["verdict"], "pass-no-inscope-oos")


if __name__ == "__main__":
    unittest.main()
