"""Unit tests for ``tools/compiler-feature-screen.py`` (E2 screen).

Non-vacuous: they exercise the version-BOUNDARY discrimination, not just the
keyword scan. A synthetic transient-storage advisory with window
[0.8.28, 0.8.34) is injected so the test does not couple to corpus drift; a
matching real-corpus run is covered by the tool's own mutation-verify.

* FLAG       at pinned 0.8.28 (introduced <= pinned < fixed).
* CLEAR      at pinned 0.8.34 (pinned == fixed -> outside window).
* UNSCREENED when a used feature has NO matching-feature advisory.
* Mutating the window-match (shift the advisory window) BREAKS the FLAG test.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "compiler-feature-screen.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


CFS = _load(TOOL, "compiler_feature_screen")


# window [0.8.28, 0.8.34) on the transient-storage subsystem.
TRANSIENT_ADV = {
    "uid": "test:transient:1",
    "introduced": "0.8.28",
    "fixed": "0.8.34",
    "subsystem": "transient-storage",
}


class ScreenPairTest(unittest.TestCase):
    def test_flag_at_0828(self):
        v = CFS.screen_pair("0.8.28", "transient-storage", [TRANSIENT_ADV])
        self.assertEqual(v["verdict"], "FLAG")
        self.assertEqual(v["matched_advisory_uid"], "test:transient:1")
        self.assertEqual(v["introduced"], "0.8.28")
        self.assertEqual(v["fixed"], "0.8.34")

    def test_clear_at_0834(self):
        # pinned == fixed -> at/after the fix -> outside every window.
        v = CFS.screen_pair("0.8.34", "transient-storage", [TRANSIENT_ADV])
        self.assertEqual(v["verdict"], "CLEAR")
        self.assertIsNone(v["matched_advisory_uid"])

    def test_clear_below_window(self):
        v = CFS.screen_pair("0.8.20", "transient-storage", [TRANSIENT_ADV])
        self.assertEqual(v["verdict"], "CLEAR")

    def test_unscreened_no_matching_advisory(self):
        # feature used but NO matching-feature advisory computed -> fail-closed.
        v = CFS.screen_pair("0.8.28", "transient-storage", [])
        self.assertEqual(v["verdict"], "UNSCREENED")

    def test_unscreened_unparseable_version(self):
        v = CFS.screen_pair(None, "transient-storage", [TRANSIENT_ADV])
        self.assertEqual(v["verdict"], "UNSCREENED")

    def test_window_mutation_breaks_flag(self):
        # Shift the window past 0.8.28 -> the SAME pinned version must NOT flag.
        shifted = dict(TRANSIENT_ADV, introduced="0.8.30", fixed="0.8.34")
        v = CFS.screen_pair("0.8.28", "transient-storage", [shifted])
        self.assertNotEqual(v["verdict"], "FLAG")
        self.assertEqual(v["verdict"], "CLEAR")


class ParseWindowTest(unittest.TestCase):
    def test_raw_signature_window(self):
        rec = {"record_id": "x", "function_shape": {
            "raw_signature": ("// solc bug SOL-2026-1 subsystem=transient-storage "
                              "introduced<=0.8.28 fixed_in=0.8.34"),
            "shape_tags": []}}
        w = CFS.parse_window(rec)
        self.assertEqual(w["subsystem"], "transient-storage")
        self.assertEqual(w["introduced"], "0.8.28")
        self.assertEqual(w["fixed"], "0.8.34")

    def test_no_window_returns_none(self):
        rec = {"record_id": "x", "function_shape": {
            "raw_signature": "def asset() -> address", "shape_tags": []}}
        self.assertIsNone(CFS.parse_window(rec))

    def test_pre_version_introduced(self):
        rec = {"record_id": "x", "function_shape": {
            "raw_signature": ("subsystem=transient-storage introduced<=pre-0.1.0 "
                              "fixed_in=0.3.1"),
            "shape_tags": []}}
        w = CFS.parse_window(rec)
        self.assertEqual(w["introduced"], "pre-0.1.0")
        # pre-X maps to (0,0,0) so any 0.2.x is inside [pre, 0.3.1).
        v = CFS.screen_pair("0.2.0", "transient-storage", [w])
        self.assertEqual(v["verdict"], "FLAG")


class FeatureDetectTest(unittest.TestCase):
    def test_transient_tload(self):
        self.assertIn("transient-storage",
                      CFS.detect_features("function f() { tload(msg.sender); }"))

    def test_e2b_widened_features_are_detected(self):
        # E2b WIDEN: inline-asm / immutable / udvt / abi-nested-dynamic are now detected
        # (they were deferred in increment-1). They are ADVISORY - detected + queued but
        # NEVER gate (see the gate-eligibility tests below).
        self.assertIn("inline-asm", CFS.detect_features("assembly { sstore(0, 1) }"))
        self.assertIn("inline-asm",
                      CFS.detect_features('assembly ("memory-safe") { let x := 1 }'))
        self.assertIn("immutable", CFS.detect_features("uint immutable x;"))
        self.assertIn("udvt", CFS.detect_features("type Price is uint256;"))
        self.assertIn("udvt", CFS.detect_features("Price.wrap(1); Price.unwrap(p);"))
        self.assertIn("abi-nested-dynamic", CFS.detect_features("abi.encode(a, b);"))
        self.assertIn("abi-nested-dynamic", CFS.detect_features("abi.decode(d, (uint));"))

    def test_no_feature(self):
        self.assertEqual(CFS.detect_features("uint x = 1;"), set())

    # ---- R10 comment-aware regression (latent fleet-RED FP kill) -------------
    def test_transient_in_line_comment_is_true_negative(self):
        # A `// transient ...` comment must NOT flag transient-storage (it was the
        # latent fleet-RED at solc 0.8.28-0.8.33).
        self.assertNotIn("transient-storage",
                         CFS.detect_features("uint x; // uses transient storage here\n"))
        self.assertNotIn("transient-storage",
                         CFS.detect_features("uint x; // transient reentrancy guard\n"))

    def test_transient_in_block_comment_is_true_negative(self):
        self.assertNotIn(
            "transient-storage",
            CFS.detect_features("/* the contract uses transient storage */\nuint x;"))

    def test_transient_in_natspec_comment_is_true_negative(self):
        # morpho's `/// @dev The contract uses transient storage.` alone (no state var)
        # must be a true-negative.
        self.assertNotIn(
            "transient-storage",
            CFS.detect_features("/// @dev The contract uses transient storage.\nuint x;"))

    def test_transient_in_string_literal_is_true_negative(self):
        self.assertNotIn(
            "transient-storage",
            CFS.detect_features('string e = "transient failure";'))
        self.assertNotIn(
            "transient-storage",
            CFS.detect_features("string e = 'transient failure';"))

    def test_real_transient_state_var_still_flags(self):
        # A GENUINE violation must STILL fire (the FP fix must not silence it).
        self.assertIn("transient-storage",
                      CFS.detect_features("address public transient initiator;"))
        self.assertIn("transient-storage",
                      CFS.detect_features("uint256 public transient firstTotalAssets;"))

    def test_real_transient_beside_a_comment_still_flags(self):
        # morpho shape: a `/// @dev ... transient storage.` comment redundant with a real
        # `transient` state var -> the real var must still flag despite comment-stripping.
        src = ("/// @dev The contract uses transient storage.\n"
               "uint256 public transient firstTotalAssets;\n")
        self.assertIn("transient-storage", CFS.detect_features(src))

    def test_slash_slash_inside_string_not_treated_as_comment(self):
        # ordering-hazard guard: a `//` inside a string must not swallow real code that
        # follows on the same line (single-pass scanner, not a regex chain).
        src = 'string u = "http://x"; uint immutable y;'
        self.assertIn("immutable", CFS.detect_features(src))

    def test_quote_inside_comment_not_treated_as_string(self):
        # ordering-hazard guard: a quote inside a `//` comment must not open a string that
        # then swallows real code on the next line.
        src = '// a "transient" mention\nuint immutable y;'
        feats = CFS.detect_features(src)
        self.assertIn("immutable", feats)
        self.assertNotIn("transient-storage", feats)

    def test_tstore_inside_assembly_still_flags(self):
        # comment-stripping must not touch assembly bodies.
        self.assertIn("transient-storage",
                      CFS.detect_features("assembly { tstore(0, 1) }"))


# feature_tagged transient window (graduated) vs an untagged widened window.
TRANSIENT_ADV_TAGGED = dict(TRANSIENT_ADV, feature_tagged=True)
ABI_ADV_TAGGED = {
    "uid": "test:abi:1", "introduced": "0.5.8", "fixed": "0.8.16",
    "subsystem": "abi-nested-dynamic", "feature_tagged": True,
}


class GateEligibilityTest(unittest.TestCase):
    """NON-VACUOUS: the gate-eligible property FIRES on a transient in-window FLAG and is
    SILENT on (a) an advisory widened-feature FLAG, (b) an out-of-window CLEAR, (c) an
    untagged transient window. Mutating any of these silences the gate."""

    def test_gate_eligible_true_on_transient_flag(self):
        v = CFS.screen_pair("0.8.28", "transient-storage", [TRANSIENT_ADV_TAGGED])
        self.assertEqual(v["verdict"], "FLAG")
        self.assertTrue(v["gate_eligible"])

    def test_gate_eligible_false_on_abi_flag(self):
        # abi-nested-dynamic FLAGs (even feature_tagged) are ADVISORY - not in
        # GATE_ELIGIBLE_FEATURES, so they never gate.
        v = CFS.screen_pair("0.8.15", "abi-nested-dynamic", [ABI_ADV_TAGGED])
        self.assertEqual(v["verdict"], "FLAG")
        self.assertFalse(v["gate_eligible"])

    def test_gate_eligible_false_on_inline_asm(self):
        # inline-asm has NO windowed advisory -> UNSCREENED -> never gate-eligible.
        v = CFS.screen_pair("0.8.15", "inline-asm", [])
        self.assertEqual(v["verdict"], "UNSCREENED")
        self.assertFalse(v["gate_eligible"])

    def test_gate_eligible_false_when_transient_out_of_window(self):
        # SILENT when the property is guarded: bump the pin past the fix -> CLEAR.
        v = CFS.screen_pair("0.8.34", "transient-storage", [TRANSIENT_ADV_TAGGED])
        self.assertEqual(v["verdict"], "CLEAR")
        self.assertFalse(v["gate_eligible"])

    def test_gate_eligible_false_on_untagged_transient_window(self):
        # A transient FLAG matched against an advisory WITHOUT feature_tagged does not
        # graduate to the gate (the >=3-ws / per-advisory-tag admission is required).
        v = CFS.screen_pair("0.8.28", "transient-storage", [TRANSIENT_ADV])
        self.assertEqual(v["verdict"], "FLAG")
        self.assertFalse(v["gate_eligible"])


class PinnedVersionTest(unittest.TestCase):
    def test_solc_exact(self):
        self.assertEqual(CFS.pinned_solc("pragma solidity 0.8.28;"), "0.8.28")

    def test_solc_caret(self):
        self.assertEqual(CFS.pinned_solc("pragma solidity ^0.8.20;"), "0.8.20")

    def test_vyper_version(self):
        self.assertEqual(CFS.pinned_vyper("# @version 0.3.7\n"), "0.3.7")

    def test_vyper_pragma_version(self):
        self.assertEqual(CFS.pinned_vyper("# pragma version 0.3.10\n"), "0.3.10")


class RunEndToEndTest(unittest.TestCase):
    def _ws(self, tmp: Path, pragma: str) -> Path:
        ws = tmp
        (ws / "C.sol").write_text(
            f"pragma solidity {pragma};\n"
            "contract C { function f() external { tload(msg.sender); } }\n")
        return ws

    def test_flag_then_clear_and_counts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._ws(ws, "0.8.28")
            res = CFS.run(ws, [str(REPO_ROOT / "audit" / "corpus_tags" /
                                   "tags" / "solc_compiler_bugs")])
            self.assertTrue(res["substrate_present"])
            trow = [r for r in res["rows"]
                    if r["feature"] == "transient-storage"][0]
            self.assertEqual(trow["verdict"], "FLAG")
            # the curated KNOWN_BAD_WINDOWS carries feature_tagged, so a transient
            # in-window FLAG is gate-eligible (the sole graduated feature).
            self.assertTrue(trow["gate_eligible"])
            self.assertFalse(trow["advisory"])
            self.assertGreaterEqual(res["counts"]["flagged"], 1)
            self.assertGreaterEqual(res["counts"]["gate_eligible_flagged"], 1)

    def test_transient_out_of_window_gate_count_zero(self):
        # NON-VACUOUS at the run level: bump the pin past the fix -> CLEAR -> the gate
        # count drops to 0 (the property is now guarded, gate stays SILENT).
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._ws(ws, "0.8.34")
            res = CFS.run(ws)
            trow = [r for r in res["rows"]
                    if r["feature"] == "transient-storage"][0]
            self.assertEqual(trow["verdict"], "CLEAR")
            self.assertEqual(res["counts"]["gate_eligible_flagged"], 0)

    def test_widened_abi_flag_is_advisory_not_gate(self):
        # An abi-nested-dynamic FLAG (pin inside the wide window) is emitted but ADVISORY:
        # it does NOT increment gate_eligible_flagged, so it cannot fleet-RED a green ws.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "A.sol").write_text(
                "pragma solidity 0.8.15;\n"
                "contract A { function f() external pure returns (bytes memory) "
                "{ return abi.encode(uint256(1)); } }\n")
            res = CFS.run(ws)
            arows = [r for r in res["rows"] if r["feature"] == "abi-nested-dynamic"]
            self.assertTrue(arows)
            self.assertEqual(arows[0]["verdict"], "FLAG")
            self.assertFalse(arows[0]["gate_eligible"])
            self.assertTrue(arows[0]["advisory"])
            self.assertEqual(res["counts"]["gate_eligible_flagged"], 0)

    def test_comment_only_transient_in_window_gate_count_zero(self):
        # R10 comment-aware: a `// transient` comment (NO real transient) at solc 0.8.30
        # (inside the [0.8.28, 0.8.34) window) must NOT fleet-RED a genuinely-green ws:
        # 0 gate-eligible flags, and no transient-storage row at all.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "G.sol").write_text(
                "pragma solidity 0.8.30;\n"
                "/// @dev the contract uses transient storage internally\n"
                'contract G { string e = "transient failure"; }\n')
            res = CFS.run(ws)
            self.assertEqual(res["counts"]["gate_eligible_flagged"], 0)
            self.assertFalse([r for r in res["rows"]
                              if r["feature"] == "transient-storage"])

    def test_real_transient_state_var_flags_gate(self):
        # The genuine violation (morpho shape) STILL fires: real `transient` state var at the
        # inclusive 0.8.28 boundary -> FLAG + gate_eligible.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "R.sol").write_text(
                "pragma solidity 0.8.28;\n"
                "/// @dev The contract uses transient storage.\n"
                "contract R { uint256 public transient firstTotalAssets; }\n")
            res = CFS.run(ws)
            trow = [r for r in res["rows"]
                    if r["feature"] == "transient-storage"][0]
            self.assertEqual(trow["verdict"], "FLAG")
            self.assertTrue(trow["gate_eligible"])
            self.assertGreaterEqual(res["counts"]["gate_eligible_flagged"], 1)

    def test_fail_open_empty_ws(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            res = CFS.run(Path(d))
            self.assertFalse(res["substrate_present"])
            self.assertEqual(res["counts"]["screened_pairs"], 0)

    def test_strict_flag_requires_exact_evidence_backed_disposition(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._ws(ws, "0.8.28")
            first = CFS.run(ws, strict=True)
            row = [r for r in first["rows"] if r["feature"] == "transient-storage"][0]
            self.assertEqual(first["strict_verdict"], "fail-compiler-feature-screen")
            self.assertTrue(first["strict_open_rows"])

            disp = ws / ".auditooor" / "compiler_feature_screen_dispositions.jsonl"
            disp.parent.mkdir(parents=True, exist_ok=True)
            disp.write_text(json.dumps({
                "stable_id": row["stable_id"],
                "disposition_type": "covered",
                "reason": "bytecode review closes the applicable compiler obligation",
                "evidence_ref": "tests/compiler-feature-screen/bytecode-review.txt",
            }) + "\n")
            closed = CFS.run(ws, strict=True)
            self.assertEqual(closed["strict_verdict"], "pass-compiler-feature-screen")
            self.assertEqual(closed["strict_open_rows"], [])
            self.assertEqual(closed["strict_dispositioned"], 1)

    def test_strict_rejects_ambiguous_version_without_disposition(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "Ambiguous.sol").write_text(
                "pragma solidity 0.8.28;\n"
                "pragma solidity 0.8.30;\n"
                "contract C { function f() external { tload(msg.sender); } }\n"
            )
            res = CFS.run(ws, strict=True)
            self.assertEqual(res["rows"][0]["verdict"], "AMBIGUOUS")
            self.assertIn("open-rows:", " ".join(res["strict_blockers"]))

    def test_strict_clean_scan_has_evidence_backed_accounting(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "Clean.sol").write_text(
                "pragma solidity 0.8.34;\ncontract C { uint256 public value; }\n"
            )
            res = CFS.run(ws, strict=True)
            self.assertEqual(res["strict_verdict"], "pass-compiler-feature-screen")
            self.assertTrue(res["accounting"]["evidence_backed"])

    def test_strict_n_a_is_explicitly_accounted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            res = CFS.run(Path(d), strict=True)
            self.assertEqual(res["strict_verdict"], "pass-not-applicable")
            self.assertTrue(res["accounting"]["evidence_backed"])

    def test_cli_strict_returns_nonzero_for_open_flag(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._ws(ws, "0.8.28")
            rc = CFS.main([str(ws), "--strict"])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
