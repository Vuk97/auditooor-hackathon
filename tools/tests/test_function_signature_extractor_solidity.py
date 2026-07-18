"""Tests for tools/function-signature-extractor.py — Solidity path (Wave-9).

Verifies:
  1. Tree-sitter extracts function name + visibility + params + return types
     correctly for a standard external function.
  2. visibility field is "external" for external functions.
  3. Modifier onlyOwner is extracted into the modifiers list.
  4. Multi-modifier functions (nonReentrant + whenNotPaused + onlyOwner)
     produce all three modifiers.
  5. Return types are extracted for view functions.
  6. is_constructor flag works for constructor_definition nodes.
  7. is_receive / is_fallback flags work.
  8. Regex fallback still works when tree-sitter is unavailable (mocked).
  9. guards_detected intersects modifiers correctly (authority-check from
     onlyOwner; reentrancy-guard from nonReentrant; pause-guard from
     whenNotPaused).
 10. params list carries both name and type for each parameter.
"""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "function-signature-extractor.py"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "fn_sig_extractor_sol"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_fse_sol", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class SolidityExtractorTreeSitterTests(unittest.TestCase):
    """Tests that require tree-sitter-solidity to be installed."""

    @classmethod
    def setUpClass(cls):
        cls.tool = _load_tool()
        if not cls.tool._TREE_SITTER_SOLIDITY_AVAILABLE:
            raise unittest.SkipTest("tree-sitter-solidity not installed; skipping tree-sitter tests")

    def _extract(self, fixture_name: str):
        path = FIXTURE_DIR / fixture_name
        text = path.read_text(encoding="utf-8")
        return self.tool.extract_solidity_functions(text, fixture_name)

    def _by_name(self, recs):
        return {r["function_name"]: r for r in recs}

    # --- Test 1: basic extraction of function name ---

    def test_extracts_setOwner_function_name(self):
        recs = self._extract("standard_fn.sol")
        names = {r["function_name"] for r in recs}
        self.assertIn("setOwner", names)

    # --- Test 2: visibility is "external" for external functions ---

    def test_visibility_external(self):
        recs = self._extract("standard_fn.sol")
        by_name = self._by_name(recs)
        self.assertIn("setOwner", by_name)
        self.assertEqual(by_name["setOwner"]["visibility"], "external",
                         f"got {by_name['setOwner']['visibility']!r}")

    # --- Test 3: onlyOwner extracted into modifiers ---

    def test_modifier_onlyOwner_in_modifiers(self):
        recs = self._extract("standard_fn.sol")
        by_name = self._by_name(recs)
        self.assertIn("setOwner", by_name)
        mods = by_name["setOwner"]["modifiers"]
        self.assertIn("onlyOwner", mods,
                      f"expected onlyOwner in modifiers, got {mods}")

    # --- Test 4: multi-modifier function carries all three modifiers ---

    def test_multi_modifier_all_present(self):
        recs = self._extract("standard_fn.sol")
        by_name = self._by_name(recs)
        self.assertIn("multiGuarded", by_name)
        mods = by_name["multiGuarded"]["modifiers"]
        for expected in ("nonReentrant", "whenNotPaused", "onlyOwner"):
            self.assertIn(expected, mods,
                          f"expected {expected} in modifiers, got {mods}")

    # --- Test 5: return types extracted for view function ---

    def test_return_types_view_function(self):
        recs = self._extract("view_pure_payable.sol")
        by_name = self._by_name(recs)
        self.assertIn("getStored", by_name)
        ret = by_name["getStored"]["return_types"]
        self.assertTrue(len(ret) >= 1, f"expected return types, got {ret}")
        self.assertTrue(any("uint256" in t for t in ret),
                        f"expected uint256 in return_types, got {ret}")

    # --- Test 6: is_constructor flag ---

    def test_is_constructor_flag(self):
        recs = self._extract("constructor_fallback.sol")
        constructors = [r for r in recs if r.get("is_constructor")]
        self.assertTrue(len(constructors) >= 1,
                        f"expected at least one constructor, got {[r['function_name'] for r in recs]}")

    # --- Test 7: is_receive and is_fallback flags ---

    def test_is_receive_and_fallback_flags(self):
        recs = self._extract("constructor_fallback.sol")
        receives = [r for r in recs if r.get("is_receive")]
        fallbacks = [r for r in recs if r.get("is_fallback")]
        self.assertTrue(len(receives) >= 1,
                        f"expected is_receive flag, got {[r['function_name'] for r in recs]}")
        self.assertTrue(len(fallbacks) >= 1,
                        f"expected is_fallback flag, got {[r['function_name'] for r in recs]}")

    # --- Test 9: guards_detected from modifiers ---

    def test_guards_detected_from_modifiers(self):
        recs = self._extract("standard_fn.sol")
        by_name = self._by_name(recs)
        # setOwner has onlyOwner -> authority-check
        self.assertIn("authority-check", by_name["setOwner"]["guards_detected"],
                      f"got {by_name['setOwner']['guards_detected']}")
        # multiGuarded has nonReentrant + whenNotPaused + onlyOwner
        mg = by_name["multiGuarded"]
        for g in ("authority-check", "reentrancy-guard", "pause-guard"):
            self.assertIn(g, mg["guards_detected"],
                          f"expected {g} in guards_detected, got {mg['guards_detected']}")

    # --- Test 10: params carry name and type ---

    def test_params_name_and_type(self):
        recs = self._extract("standard_fn.sol")
        by_name = self._by_name(recs)
        self.assertIn("setOwner", by_name)
        params = by_name["setOwner"]["params"]
        self.assertTrue(len(params) >= 1, f"expected params, got {params}")
        p = params[0]
        self.assertIn("type", p)
        self.assertIn("name", p)
        # type should be "address"
        self.assertEqual(p["type"], "address",
                         f"expected address type, got {p['type']!r}")
        self.assertEqual(p["name"], "newOwner",
                         f"expected newOwner name, got {p['name']!r}")

    # --- Multi-return types ---

    def test_multi_return_types(self):
        recs = self._extract("view_pure_payable.sol")
        by_name = self._by_name(recs)
        self.assertIn("multiReturn", by_name)
        ret = by_name["multiReturn"]["return_types"]
        self.assertEqual(len(ret), 3,
                         f"expected 3 return types, got {ret}")


class SolidityShapeFeaturesTests(unittest.TestCase):
    """Wave-11: tests for the _solidity_shape_features() body-derived
    feature dict that powers shape_hash_fine."""

    @classmethod
    def setUpClass(cls):
        cls.tool = _load_tool()
        if not cls.tool._TREE_SITTER_SOLIDITY_AVAILABLE:
            raise unittest.SkipTest("tree-sitter-solidity not installed")

    def _extract(self, fixture_name):
        path = FIXTURE_DIR / fixture_name
        text = path.read_text(encoding="utf-8")
        return self.tool.extract_solidity_functions(text, fixture_name)

    def _by_name(self, recs):
        return {r["function_name"]: r for r in recs}

    def test_shape_features_present_on_every_record(self):
        recs = self._extract("shape_features.sol")
        for r in recs:
            self.assertIn(
                "shape_features", r,
                f"shape_features missing on {r.get('function_name')}",
            )
            sf = r["shape_features"]
            for k in (
                "visibility", "state_mutability", "param_count",
                "return_count", "modifiers_sorted",
                "has_authority_modifier", "has_reentrancy_modifier",
                "storage_write_count", "external_call_count",
                "has_require_or_revert", "has_assembly_block",
            ):
                self.assertIn(k, sf, f"feature {k!r} missing")

    def test_visibility_captured_in_features(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        self.assertEqual(by_name["multiWrite"]["shape_features"]["visibility"], "external")
        self.assertEqual(by_name["readCounter"]["shape_features"]["state_mutability"], "view")
        self.assertEqual(by_name["asmEcho"]["shape_features"]["state_mutability"], "pure")

    def test_modifiers_sorted_capture(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        gw = by_name["guardedWrite"]["shape_features"]
        # Sorted list — alphabetical.
        self.assertEqual(
            gw["modifiers_sorted"], sorted(["nonReentrant", "onlyOwner"]),
            f"got {gw['modifiers_sorted']}",
        )
        # Plain view has no modifiers.
        self.assertEqual(by_name["readCounter"]["shape_features"]["modifiers_sorted"], [])

    def test_authority_and_reentrancy_modifier_flags(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        gw = by_name["guardedWrite"]["shape_features"]
        self.assertEqual(gw["has_authority_modifier"], 1)
        self.assertEqual(gw["has_reentrancy_modifier"], 1)
        # multiWrite has no guard modifiers
        mw = by_name["multiWrite"]["shape_features"]
        self.assertEqual(mw["has_authority_modifier"], 0)
        self.assertEqual(mw["has_reentrancy_modifier"], 0)

    def test_external_call_count(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        mec = by_name["multiExternalCall"]["shape_features"]
        # poke() is an interface call (no .call/.transfer/.send) so it
        # doesn't count; we should detect the .call("") and .transfer(0) → 2.
        self.assertGreaterEqual(
            mec["external_call_count"], 2,
            f"expected >=2 external-call sites, got {mec['external_call_count']}",
        )
        # multiWrite makes no external calls.
        self.assertEqual(by_name["multiWrite"]["shape_features"]["external_call_count"], 0)

    def test_storage_write_count(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        mw = by_name["multiWrite"]["shape_features"]
        # 3 top-level assignments: counter=a, balances[..]=b, owner=msg.sender
        self.assertGreaterEqual(
            mw["storage_write_count"], 3,
            f"expected >=3 storage writes, got {mw['storage_write_count']}",
        )
        # View function has no writes (== inside return doesn't count).
        self.assertEqual(by_name["readCounter"]["shape_features"]["storage_write_count"], 0)

    def test_has_require_or_revert(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        self.assertEqual(
            by_name["multiExternalCall"]["shape_features"]["has_require_or_revert"], 1,
        )
        self.assertEqual(
            by_name["guardedWrite"]["shape_features"]["has_require_or_revert"], 1,
        )
        self.assertEqual(
            by_name["readCounter"]["shape_features"]["has_require_or_revert"], 0,
        )

    def test_has_assembly_block(self):
        recs = self._extract("shape_features.sol")
        by_name = self._by_name(recs)
        self.assertEqual(by_name["asmEcho"]["shape_features"]["has_assembly_block"], 1)
        self.assertEqual(by_name["multiWrite"]["shape_features"]["has_assembly_block"], 0)

    def test_shape_hash_fine_distinguishes_functions(self):
        """End-to-end: pipe records through tools/shape-hash.py and verify
        shape_hash_fine has higher uniqueness than coarse shape_hash for
        Solidity functions that share visibility+mutability but differ in
        body shape."""
        import importlib.util
        sh_spec = importlib.util.spec_from_file_location(
            "_sh_mod", str(REPO_ROOT / "tools" / "shape-hash.py"),
        )
        sh_mod = importlib.util.module_from_spec(sh_spec)
        sh_spec.loader.exec_module(sh_mod)

        recs = self._extract("shape_features.sol")
        # All `external` functions in this fixture share visibility +
        # similar param/return arity — coarse hash collapses many of them.
        for r in recs:
            sh_mod.add_shape_hashes_to_record(r)
        coarse = {r["shape_hash"] for r in recs}
        fine = {r["shape_hash_fine"] for r in recs}
        # Fine must be at least as discriminative as coarse.
        self.assertGreaterEqual(
            len(fine), len(coarse),
            f"shape_hash_fine LESS discriminative than coarse "
            f"(fine={len(fine)} coarse={len(coarse)}) — regression",
        )
        # And fine must distinguish multiWrite from multiExternalCall
        # even though they share visibility+mutability+param_count.
        by_name = self._by_name(recs)
        self.assertNotEqual(
            by_name["multiWrite"]["shape_hash_fine"],
            by_name["multiExternalCall"]["shape_hash_fine"],
            "shape_hash_fine should distinguish write-heavy from "
            "external-call-heavy functions",
        )

    def test_coarse_shape_hash_unchanged_by_features(self):
        """The coarse shape_hash MUST be invariant under shape_features —
        only shape_hash_fine consumes it. Guard against accidental coupling."""
        import importlib.util
        sh_spec = importlib.util.spec_from_file_location(
            "_sh_mod2", str(REPO_ROOT / "tools" / "shape-hash.py"),
        )
        sh_mod = importlib.util.module_from_spec(sh_spec)
        sh_spec.loader.exec_module(sh_mod)

        # Two identical records that differ ONLY in shape_features content.
        base_rec = {
            "language": "solidity",
            "visibility": "external",
            "params": [{"name": "x", "type": "uint256"}],
            "return_types": [],
            "guards_detected": [],
            "receiver_type": None,
        }
        rec_a = dict(base_rec, shape_features={
            "visibility": "external", "state_mutability": "nonpayable",
            "param_count": 1, "return_count": 0, "modifiers_sorted": [],
            "has_authority_modifier": 0, "has_reentrancy_modifier": 0,
            "storage_write_count": 1, "external_call_count": 0,
            "has_require_or_revert": 0, "has_assembly_block": 0,
        })
        rec_b = dict(base_rec, shape_features={
            "visibility": "external", "state_mutability": "nonpayable",
            "param_count": 1, "return_count": 0, "modifiers_sorted": ["onlyOwner"],
            "has_authority_modifier": 1, "has_reentrancy_modifier": 0,
            "storage_write_count": 5, "external_call_count": 3,
            "has_require_or_revert": 1, "has_assembly_block": 1,
        })
        sh_mod.add_shape_hashes_to_record(rec_a)
        sh_mod.add_shape_hashes_to_record(rec_b)
        self.assertEqual(
            rec_a["shape_hash"], rec_b["shape_hash"],
            "coarse shape_hash leaked shape_features — regression",
        )
        self.assertNotEqual(
            rec_a["shape_hash_fine"], rec_b["shape_hash_fine"],
            "fine shape_hash failed to incorporate shape_features",
        )


class SolidityExtractorRegexFallbackTests(unittest.TestCase):
    """Tests the regex fallback path (works regardless of tree-sitter availability)."""

    @classmethod
    def setUpClass(cls):
        cls.tool = _load_tool()

    def test_regex_fallback_extracts_function_names(self):
        """Regex fallback should still return function name records."""
        text = (FIXTURE_DIR / "standard_fn.sol").read_text()
        recs = self.tool._extract_solidity_regex_fallback(text, "standard_fn.sol")
        names = {r["function_name"] for r in recs}
        self.assertIn("setOwner", names)
        self.assertIn("transfer", names)
        self.assertIn("viewBalance", names)

    def test_regex_fallback_record_shape(self):
        """Regex fallback records must have expected fields (empty for non-name fields)."""
        text = (FIXTURE_DIR / "standard_fn.sol").read_text()
        recs = self.tool._extract_solidity_regex_fallback(text, "standard_fn.sol")
        self.assertTrue(len(recs) > 0)
        r = recs[0]
        for field in ("function_name", "visibility", "modifiers", "params",
                      "return_types", "guards_detected", "line_start"):
            self.assertIn(field, r, f"missing field {field!r}")
        # Regex path produces empty lists for enriched fields
        self.assertEqual(r["modifiers"], [])
        self.assertEqual(r["params"], [])
        self.assertEqual(r["return_types"], [])

    def test_extract_solidity_functions_with_mocked_ts_unavailable(self):
        """When tree-sitter import flag is patched to False, extract_solidity_functions
        falls through to regex fallback."""
        tool = _load_tool()
        original = tool._TREE_SITTER_SOLIDITY_AVAILABLE
        try:
            tool._TREE_SITTER_SOLIDITY_AVAILABLE = False
            text = (FIXTURE_DIR / "standard_fn.sol").read_text()
            recs = tool.extract_solidity_functions(text, "standard_fn.sol")
            names = {r["function_name"] for r in recs}
            self.assertIn("setOwner", names)
            # In fallback mode, modifiers should be empty
            by_name = {r["function_name"]: r for r in recs}
            self.assertEqual(by_name["setOwner"]["modifiers"], [])
        finally:
            tool._TREE_SITTER_SOLIDITY_AVAILABLE = original


if __name__ == "__main__":
    unittest.main()
