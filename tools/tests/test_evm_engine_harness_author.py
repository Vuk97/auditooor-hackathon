"""Tests for tools/evm-engine-harness-author.py."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "evm-engine-harness-author.py"
_spec = importlib.util.spec_from_file_location("evm_engine_harness_author", MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
import sys as _sys
_sys.modules["evm_engine_harness_author"] = mod
_spec.loader.exec_module(mod)

# Load the engine-harness proof gate so the authored output can be asserted to
# pass it (the load-bearing contract for this tool: harnesses it authors MUST
# pass tools/engine-harness-proof-gate.py with pass-real-property-executed).
_GATE_PATH = REPO_ROOT / "tools" / "engine-harness-proof-gate.py"
_gspec = importlib.util.spec_from_file_location("engine_harness_proof_gate", _GATE_PATH)
gate = importlib.util.module_from_spec(_gspec)
_sys.modules["engine_harness_proof_gate"] = gate
_gspec.loader.exec_module(gate)

SAMPLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault is IVault, Ownable {
    uint256 public immutable CAP;
    address internal immutable ASSET;
    mapping(address => uint256) internal balances;

    event Deposit(address indexed who, uint256 amount);
    error NotOwner();

    modifier onlyOwner() { _; }

    function deposit(uint256 amount) external returns (uint256) {}
    function withdraw(uint256 amount) public {}
    function previewRedeem(uint256 shares) external view returns (uint256) {}
    function onCallback(bytes calldata d) external {}
}
"""


class TestParse(unittest.TestCase):
    def _surf(self, src=SAMPLE, want=None):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        return mod.parse_contract(p, want)

    def test_contract_name_and_kind(self):
        s = self._surf()
        self.assertEqual(s.name, "Vault")
        self.assertEqual(s.kind, "contract")
        self.assertIn("Ownable", s.bases)

    def test_mutating_external_excludes_view(self):
        s = self._surf()
        names = [f.name for f in s.mutating_external]
        self.assertIn("deposit", names)
        self.assertIn("withdraw", names)
        self.assertIn("onCallback", names)
        self.assertNotIn("previewRedeem", names)  # view

    def test_surface_members(self):
        s = self._surf()
        self.assertIn("Deposit", s.events)
        self.assertIn("NotOwner", s.errors)
        self.assertIn("onlyOwner", s.modifiers)
        self.assertIn("CAP", s.immutables)
        self.assertIn("ASSET", s.immutables)

    def test_no_contract_raises(self):
        with self.assertRaises(ValueError):
            self._surf(src="pragma solidity ^0.8.0;\n// nothing here\n")

    def test_want_not_found_raises(self):
        with self.assertRaises(ValueError):
            self._surf(want="DoesNotExist")


class TestMatch(unittest.TestCase):
    def test_derive_categories_from_names(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, None)
        cats = mod.derive_wanted_categories(surf)
        # deposit -> conservation/custody/bounds; withdraw -> +authorization;
        # onCallback -> atomicity; modifier present -> authorization
        self.assertIn("conservation", cats)
        self.assertIn("authorization", cats)
        self.assertIn("atomicity", cats)

    def test_match_returns_real_corpus_ids(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, None)
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        self.assertTrue(corpus, "corpus index should be non-empty")
        matched = mod.match_invariants(surf, corpus)
        self.assertTrue(matched)
        # every emitted id must exist in the corpus we loaded
        valid = {r["invariant_id"] for r in corpus}
        for cat, recs in matched.items():
            for r in recs:
                self.assertIn(r["invariant_id"], valid)


class TestEmit(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            self.contract = Path(f.name)
        self.ws = Path(tempfile.mkdtemp())

    def test_author_emits_all_engine_files(self):
        manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        self.assertTrue((out / "test" / "Vault_HalmosSpec.t.sol").exists())
        self.assertTrue((out / "test" / "Vault_FuzzProps.sol").exists())
        self.assertTrue((out / "test" / "Vault_Invariant.t.sol").exists())
        # Specs are self-contained; no property-free HarnessUnderTest.sol model
        # file is emitted (it would sink the directory-level proof gate).
        self.assertFalse((out / "test" / "HarnessUnderTest.sol").exists())
        self.assertFalse((out / "src" / "HarnessUnderTest.sol").exists())
        self.assertTrue((out / "medusa.json").exists())
        self.assertTrue((out / "echidna.yaml").exists())
        self.assertTrue((out / "foundry.toml").exists())
        self.assertTrue((out / "attempt_manifest.json").exists())

    def test_manifest_schema_and_grounding(self):
        manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        self.assertEqual(manifest["schema_version"], mod.SCHEMA)
        self.assertTrue(manifest["candidate_not_proof"])
        self.assertTrue(manifest["rule_58_grounded"])
        self.assertIn("halmos", manifest["engines"])
        self.assertIn("foundry_invariant", manifest["engines"])

    def test_specs_carry_not_proof_banner(self):
        manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        halmos = (out / "test" / "Vault_HalmosSpec.t.sol").read_text()
        self.assertIn("CANDIDATE HARNESS - NOT PROOF", halmos)
        self.assertIn("check_", halmos)
        fuzz = (out / "test" / "Vault_FuzzProps.sol").read_text()
        self.assertIn("echidna_", fuzz)
        self.assertIn("fuzz_", fuzz)
        inv = (out / "test" / "Vault_Invariant.t.sol").read_text()
        self.assertIn("invariant_", inv)
        self.assertIn("targetContract", inv)

    def test_medusa_config_valid_json(self):
        manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        cfg = json.loads((out / "medusa.json").read_text())
        self.assertIn("fuzzing", cfg)
        self.assertEqual(cfg["fuzzing"]["targetContracts"], ["Vault_FuzzProps"])


class TestProofGate(unittest.TestCase):
    """The authored harnesses MUST pass tools/engine-harness-proof-gate.py."""

    def setUp(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            self.contract = Path(f.name)
        self.ws = Path(tempfile.mkdtemp())
        self.manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        self.out = Path(self.manifest["out_dir"])

    def test_each_spec_file_passes_proof_gate(self):
        for fname in (
            "Vault_HalmosSpec.t.sol",
            "Vault_FuzzProps.sol",
            "Vault_Invariant.t.sol",
        ):
            p = self.out / "test" / fname
            res = gate.classify_path(p)
            self.assertEqual(
                res["verdict"], gate.PASS_REAL,
                f"{fname}: expected pass-real-property-executed, got "
                f"{res['verdict']} ({res.get('reason')})",
            )
            self.assertGreaterEqual(res["real_property_count"], 1)
            self.assertEqual(res.get("stub_properties", []), [])

    def test_output_dir_passes_proof_gate(self):
        # directory verdict takes the WORST across all .sol files: no emitted
        # file may be a property-free model that sinks the tree.
        res = gate.classify_path(self.out)
        self.assertEqual(
            res["verdict"], gate.PASS_REAL,
            f"dir: expected pass-real-property-executed, got "
            f"{res['verdict']} ({res.get('reason')})",
        )

    def test_output_dir_passes_proof_gate_strict(self):
        # --strict promotes any stub-alongside-real to fail; the authored
        # output has zero stub properties, so it passes strict too.
        res = gate.classify_path(self.out)
        if res["verdict"] == gate.PASS_REAL and res.get("stub_properties"):
            res = dict(res, verdict=gate.FAIL_STUB)
        self.assertEqual(res["verdict"], gate.PASS_REAL)

    def test_no_stub_or_ghost_verdict_anywhere(self):
        # NEVER fail-stub-or-ghost: no assert(true), no `% 1`, no x==x ghost.
        res = gate.classify_path(self.out)
        self.assertNotEqual(res["verdict"], gate.FAIL_STUB)
        for fr in res.get("files", []):
            self.assertNotEqual(fr["verdict"], gate.FAIL_STUB, fr.get("file"))

    def test_property_bodies_carry_real_comparison(self):
        # Each property body must contain a genuine comparison operator (the
        # invariant relation), never a tautology.
        import re
        fuzz = (self.out / "test" / "Vault_FuzzProps.sol").read_text()
        for cat in self.manifest["matched_invariants"]:
            m = re.search(
                rf"function echidna_{cat}\(\) public(?: view)? returns \(bool\) \{{(?P<body>.*?)\n    \}}",
                fuzz,
                re.DOTALL,
            )
            self.assertIsNotNone(m, f"echidna_{cat} not found")
            body = m.group("body")
            self.assertIn("beforeState", body)
            self.assertIn("afterState", body)
            self.assertIn("negative_control_cleanPath", body)
            self.assertRegex(body, r"target\.[A-Za-z_][A-Za-z0-9_]*\(")
            return_m = re.search(r"return \(([^;]+)\);", body, re.DOTALL)
            self.assertIsNotNone(return_m, f"echidna_{cat} return not found")
            expr = return_m.group(1)
            self.assertRegex(expr, r"(==|!=|<=|>=|<|>|&&|\|\|)")
            # not a self-equality / literal-true tautology
            self.assertNotRegex(expr.strip(), r"^true$")

    def test_refuses_when_no_category_matched(self):
        # A contract with no mutating external surface has no real property to
        # author; the tool must refuse rather than emit a property-free harness
        # that would fail the proof gate.
        src = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Empty { uint256 public x; }\n"
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        with self.assertRaises(ValueError):
            mod.author(
                Path(tempfile.mkdtemp()), p, None,
                mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
            )

    def test_no_neutered_mod_by_one_in_property_bodies(self):
        # the gate's MOD_BY_ONE pattern (`% 1` not followed by a digit) must
        # not appear in any emitted spec file.
        import re
        neutered = re.compile(r"%\s*1\b(?!\d)")
        for fname in (
            "Vault_HalmosSpec.t.sol",
            "Vault_FuzzProps.sol",
            "Vault_Invariant.t.sol",
        ):
            txt = (self.out / "test" / fname).read_text()
            self.assertIsNone(
                neutered.search(txt), f"{fname} contains a neutered `% 1`"
            )

    def test_atomicity_determinism_not_tautology(self):
        """Guard test: atomicity and determinism must NOT be emitted as
        always-true tautologies. The fix: both categories carry typed_skip=True
        so they are excluded from matched_invariants and do NOT appear as
        echidna_*/fuzz_*/invariant_*/check_* functions in the emitted specs.
        Instead they appear in typed_skip_categories in the manifest.

        Invariant the test enforces:
          - Neither 'atomicity' nor 'determinism' is in manifest['matched_invariants']
            (they were filtered out as typed-skip, not emitted as properties).
          - Both categories appear in manifest['typed_skip_categories'].
          - The emitted fuzz file does NOT contain 'echidna_atomicity' or
            'echidna_determinism' (no vacuous property emitted).
          - The emitted fuzz file does NOT contain the self-equality expression
            that was the previous tautology:
              callDepth == 0 && !locked  (atomicity tautology)
              lastOutput == (lastInput % 1e18) * 3 + 7  (determinism substitution tautology)
        """
        import re as _re

        fuzz_txt = (self.out / "test" / "Vault_FuzzProps.sol").read_text()
        matched = self.manifest.get("matched_invariants", {})
        typed_skip = self.manifest.get("typed_skip_categories", [])

        # Part 1: atomicity must NOT be in matched_invariants (typed-skip filtered it).
        self.assertNotIn(
            "atomicity", matched,
            "atomicity was emitted as a real property - it is a tautology and "
            "must be typed-skip; found in matched_invariants: " + str(list(matched.keys())),
        )

        # Part 2: determinism must NOT be in matched_invariants (typed-skip filtered it).
        self.assertNotIn(
            "determinism", matched,
            "determinism was emitted as a real property - it is a substitution "
            "tautology and must be typed-skip; found in matched_invariants: "
            + str(list(matched.keys())),
        )

        # Part 3: both are recorded in typed_skip_categories if they were wanted.
        # The SAMPLE contract triggers atomicity (onCallback) but not determinism.
        # atomicity MUST be in typed_skip_categories.
        self.assertIn(
            "atomicity", typed_skip,
            "atomicity was in wanted categories but missing from typed_skip_categories; "
            "it must be recorded there so the audit author knows CUT-specific wiring "
            "is required. typed_skip_categories=" + str(typed_skip),
        )

        # Part 4: no vacuous echidna_atomicity / echidna_determinism function in
        # the emitted fuzz file.
        self.assertNotIn(
            "echidna_atomicity", fuzz_txt,
            "echidna_atomicity must not be emitted (typed-skip category); "
            "a generic reentrancy harness is an always-true tautology.",
        )
        self.assertNotIn(
            "echidna_determinism", fuzz_txt,
            "echidna_determinism must not be emitted (typed-skip category); "
            "the substitution tautology (lastOutput == (lastInput%1e18)*3+7) "
            "is always true.",
        )

        # Part 5: the OLD tautology expressions must not appear anywhere in the
        # emitted files (regression guard against re-introduction).
        for fname in ("Vault_HalmosSpec.t.sol", "Vault_FuzzProps.sol", "Vault_Invariant.t.sol"):
            txt = (self.out / "test" / fname).read_text()
            # atomicity tautology: callDepth += 1; callDepth -= 1; locked = false; ... check callDepth==0
            self.assertNotIn(
                "callDepth -= 1",
                txt,
                f"{fname}: old atomicity tautology mutate body (callDepth -= 1) found; "
                "this always nets callDepth to 0 making the check vacuous.",
            )
            # determinism substitution tautology: (lastInput % 1e18) * 3 + 7
            self.assertNotIn(
                "(lastInput % 1e18) * 3 + 7",
                txt,
                f"{fname}: old determinism tautology check expr found; "
                "lastOutput == (lastInput % 1e18) * 3 + 7 is a substitution "
                "tautology (lastOutput was set to that same expression).",
            )

        # Part 6: for every category that IS in matched_invariants, the echidna_*
        # return expression must not be of the form `expr == expr` (same LHS/RHS).
        # This guards against future tautology regressions in other categories.
        for cat in matched:
            m = _re.search(
                rf"function echidna_{cat}\(\) public(?: view)? returns \(bool\) \{{(?P<body>.*?)\n    \}}",
                fuzz_txt,
                _re.DOTALL,
            )
            if m is None:
                continue
            ret = _re.search(r"return \(([^;]+)\);", m.group("body"), _re.DOTALL)
            if ret is None:
                continue
            expr = ret.group(1).strip()
            # Check: LHS == RHS where LHS and RHS are literally identical tokens
            # e.g. `x == x` or `(a+b) == (a+b)` - a tautological self-equality.
            # Simple heuristic: split on `==` and check if stripped sides are equal.
            parts = expr.split("==")
            if len(parts) == 2:
                lhs = parts[0].strip()
                rhs = parts[1].strip()
                self.assertNotEqual(
                    lhs, rhs,
                    f"echidna_{cat}: return expression `{expr}` is a "
                    "self-equality tautology (LHS == RHS with identical operands); "
                    "the check must compare two genuinely distinct quantities.",
                )


TICKLIB = """// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

library TickLib {
    int24 internal constant MIN_TICK = -887272;
    int24 internal constant MAX_TICK = 887272;
    uint160 internal constant MIN_SQRT_PRICE = 4295128739;

    error TickOutOfRange(int24 tick);

    function tickToSqrtPrice(int24 tick) internal pure returns (uint160 sqrtPriceX96) {
        if (tick < MIN_TICK || tick > MAX_TICK) revert TickOutOfRange(tick);
        uint256 shifted = uint256(int256(tick) - int256(MIN_TICK));
        sqrtPriceX96 = uint160(uint256(MIN_SQRT_PRICE) + shifted);
    }

    function sqrtPriceToTick(uint160 sqrtPriceX96) internal pure returns (int24 tick) {
        uint256 shifted = uint256(sqrtPriceX96) - uint256(MIN_SQRT_PRICE);
        tick = int24(int256(shifted) + int256(MIN_TICK));
    }
}
"""


class TestTickMathAuthoring(unittest.TestCase):
    """The pure tick<->price conversion library authoring path: a TickMath /
    TickLib has no mutating external surface, so the category path refuses; the
    tick-math path authors the tick<->price-monotonic + no-truncation-to-zero
    invariants against the REAL library and the output must pass the proof gate.
    """

    def _ticklib(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(TICKLIB)
            return Path(f.name)

    def test_detect_tick_math(self):
        surf = mod.parse_contract(self._ticklib(), "TickLib")
        tm = mod.detect_tick_math(surf)
        self.assertIsNotNone(tm)
        self.assertEqual(tm.name, "TickLib")
        self.assertEqual(tm.kind, "library")
        self.assertEqual(tm.tick_to_price_fn.name, "tickToSqrtPrice")
        self.assertEqual(tm.price_to_tick_fn.name, "sqrtPriceToTick")
        self.assertTrue(tm.tick_param_type.startswith("int"))

    def test_non_tick_contract_not_detected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, None)
        self.assertIsNone(mod.detect_tick_math(surf))

    def test_author_emits_tick_files_and_manifest(self):
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(
            ws, self._ticklib(), "TickLib",
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        self.assertEqual(manifest["authoring_path"], "tick-math-pure-library")
        self.assertIn("tick<->price monotonic", manifest["tick_invariants"])
        self.assertIn("no-truncation-to-zero", manifest["tick_invariants"])
        out = Path(manifest["out_dir"])
        for f in (
            "TickLib_HalmosSpec.t.sol",
            "TickLib_FuzzProps.sol",
            "TickLib_Invariant.t.sol",
        ):
            self.assertTrue((out / "test" / f).exists(), f)
        # corpus-grounded: monotonicity + bounds invariant IDs must be present
        # and must exist in the loaded corpus.
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        valid = {r["invariant_id"] for r in corpus}
        self.assertIn("monotonicity", manifest["matched_invariants"])
        self.assertIn("bounds", manifest["matched_invariants"])
        for cat, ids in manifest["matched_invariants"].items():
            for inv_id in ids:
                self.assertIn(inv_id, valid)

    def test_authored_specs_call_real_library(self):
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(
            ws, self._ticklib(), "TickLib",
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        for f in ("TickLib_HalmosSpec.t.sol", "TickLib_FuzzProps.sol",
                  "TickLib_Invariant.t.sol"):
            txt = (out / "test" / f).read_text()
            # imports + calls the REAL library, not a self-contained model.
            self.assertIn("import {TickLib}", txt)
            self.assertIn("TickLib.tickToSqrtPrice(", txt)

    def test_tick_specs_pass_proof_gate(self):
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(
            ws, self._ticklib(), "TickLib",
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        res = gate.classify_path(out / "test")
        self.assertEqual(
            res["verdict"], gate.PASS_REAL,
            f"expected pass-real-property-executed, got {res['verdict']} "
            f"({res.get('reason')})",
        )
        for fr in res.get("files", []):
            self.assertEqual(fr["verdict"], gate.PASS_REAL, fr.get("file"))
            self.assertEqual(fr.get("stub_properties", []), [])

    def test_tick_specs_no_neutered_mod_by_one(self):
        import re
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(
            ws, self._ticklib(), "TickLib",
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        neutered = re.compile(r"%\s*1\b(?!\d)")
        for f in ("TickLib_HalmosSpec.t.sol", "TickLib_FuzzProps.sol",
                  "TickLib_Invariant.t.sol"):
            txt = (out / "test" / f).read_text()
            self.assertIsNone(neutered.search(txt), f)
            self.assertNotIn("assert(true)", txt)

    def test_named_invariants_present(self):
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(
            ws, self._ticklib(), "TickLib",
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        out = Path(manifest["out_dir"])
        halmos = (out / "test" / "TickLib_HalmosSpec.t.sol").read_text()
        # the two named invariants are each a real comparison over real output.
        self.assertIn("check_tickPriceMonotonic", halmos)
        self.assertIn("check_tickPriceNonZero", halmos)
        self.assertIn("TickLib.tickToSqrtPrice(", halmos)
        self.assertIn("beforeState", halmos)
        self.assertIn("afterState", halmos)
        self.assertIn("negative_control_cleanPath", halmos)
        self.assertIn("beforeState < afterState", halmos)
        self.assertIn("afterState != 0", halmos)


# ---------------------------------------------------------------------------
# Bug-guarding tests added by bugfix-inventory-claude-20260610
# ---------------------------------------------------------------------------

# Governance contract: only propose/cancel/execute, with a modifier (triggers
# authorization category via derive_wanted_categories), but NONE of the
# function names match the authorization hints (set/owner/upgrade/admin/transfer).
# Before fix: _pick_target_function fell back to propose() for authorization,
# embedding the wrong target in the harness and recording rule_58_grounded=True.
GOVERNANCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Governance {
    uint256 public quorum;

    modifier onlyQuorum() { _; }

    function propose(uint256 id, bytes calldata data) external returns (uint256) {}
    function cancel(uint256 id) external onlyQuorum {}
    function execute(uint256 id) external onlyQuorum {}
}
"""


class TestPickTargetFunctionNoFallback(unittest.TestCase):
    """Bug 1: _pick_target_function must return None (not surf.mutating_external[0])
    when no hint token matches the category. Before the fix it returned propose()
    for the authorization category on GOVERNANCE, embedding a semantically wrong
    target call and yielding a false-green rule_58_grounded=True."""

    def _surf(self, src=None):
        if src is None:
            src = GOVERNANCE
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        return mod.parse_contract(p, None)

    def test_authorization_pick_is_none_for_governance(self):
        # The governance contract has a modifier (-> authorization in wanted),
        # but no function name contains set/owner/upgrade/admin/transfer.
        # After the fix _pick_target_function must return None for authorization.
        surf = self._surf()
        result = mod._pick_target_function(surf, "authorization")
        self.assertIsNone(
            result,
            "_pick_target_function must return None when no hint token matches "
            "(fallback to mutating_external[0] is a false-green); got: " + repr(result),
        )

    def test_ordering_pick_is_not_none_for_governance(self):
        # execute matches the ordering hints, so ordering should still resolve.
        surf = self._surf()
        result = mod._pick_target_function(surf, "ordering")
        self.assertIsNotNone(result, "ordering should match execute")
        self.assertEqual(result.name, "execute")

    def test_match_invariants_excludes_authorization_for_governance(self):
        # match_invariants must NOT include authorization in by_cat for GOVERNANCE
        # because _pick_target_function returns None for that category.
        surf = self._surf()
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        matched = mod.match_invariants(surf, corpus)
        self.assertNotIn(
            "authorization", matched,
            "match_invariants must filter out categories where "
            "_pick_target_function returns None; "
            "authorization was wrongly included for GOVERNANCE",
        )

    def test_no_wrong_target_call_in_emitted_halmos(self):
        # If authorization is (correctly) excluded, no check_authorization body
        # calling propose() should appear.  If it is present (pre-fix path), it
        # must NOT call target.propose() for a semantically mismatched category.
        import re
        surf = self._surf()
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        matched = mod.match_invariants(surf, corpus)
        if not matched:
            return  # nothing to author - also a valid outcome
        halmos_src = mod.emit_halmos(surf, matched)
        auth_fn = re.search(
            r"function check_authorization\([^)]*\)[^{]*\{(?P<body>.*?)\n    \}",
            halmos_src,
            re.DOTALL,
        )
        if auth_fn:
            body = auth_fn.group("body")
            self.assertNotIn(
                "target.propose(",
                body,
                "check_authorization must not call propose() - wrong semantic target",
            )

    def test_all_matched_categories_have_real_target(self):
        # Every category returned by match_invariants must have a semantically
        # appropriate _pick_target_function result (not None).
        src = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract OnlyModifier {\n"
            "    modifier onlyRole() { _; }\n"
            "    function foo(uint256 x) external onlyRole {}\n"
            "    function bar(uint256 x) external onlyRole {}\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        surf = mod.parse_contract(p, None)
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        matched = mod.match_invariants(surf, corpus)
        for cat in matched:
            target = mod._pick_target_function(surf, cat)
            self.assertIsNotNone(
                target,
                "matched category {!r} has no semantic target - "
                "match_invariants should have filtered it out".format(cat),
            )


class TestLibraryGuardInAuthor(unittest.TestCase):
    """Bug 2: author() must reject library and interface declarations (excluding
    the tick-math library exception). Before the fix, a file containing only a
    library declaration would succeed and emit a harness that instantiated the
    library with invalid call semantics, recording rule_58_grounded=True."""

    def test_library_raises_value_error(self):
        src = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "library SafeTransferLib {\n"
            "    function safeTransfer("
            "address token, address to, uint256 amount) external {}\n"
            "    function safeTransferFrom("
            "address token, address from, address to, uint256 amount) external {}\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        ws = Path(tempfile.mkdtemp())
        with self.assertRaises(ValueError) as ctx:
            mod.author(ws, p, None, mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None)
        msg = str(ctx.exception)
        self.assertIn("library", msg.lower())
        self.assertTrue(
            "concrete contract" in msg.lower() or "not a concrete" in msg.lower(),
            "Error message should mention concrete contract requirement; got: " + repr(msg),
        )

    def test_library_author_does_not_emit_harness_directory(self):
        # No poc-tests/SafeTransferLib-engine-harness/ directory must be created.
        src = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "library SafeTransferLib {\n"
            "    function safeTransfer("
            "address token, address to, uint256 amount) external {}\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        ws = Path(tempfile.mkdtemp())
        try:
            mod.author(ws, p, None, mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None)
        except ValueError:
            pass
        harness_dir = ws / "poc-tests" / "SafeTransferLib-engine-harness"
        self.assertFalse(
            harness_dir.exists(),
            "No harness directory should be created for a library: " + str(harness_dir),
        )

    def test_interface_raises_value_error(self):
        src = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "interface IVault {\n"
            "    function deposit(uint256 amount) external returns (uint256);\n"
            "    function withdraw(uint256 amount) external;\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(src)
            p = Path(f.name)
        ws = Path(tempfile.mkdtemp())
        with self.assertRaises(ValueError) as ctx:
            mod.author(ws, p, None, mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None)
        msg = str(ctx.exception)
        self.assertIn("interface", msg.lower())

    def test_concrete_contract_still_works(self):
        # The guard must not block a normal concrete contract: SAMPLE (Vault)
        # must still produce a valid manifest.
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(ws, p, None, mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None)
        self.assertEqual(manifest["contract_kind"], "contract")
        self.assertTrue(manifest["rule_58_grounded"])

    def test_tick_math_library_still_works(self):
        # The tick-math library exception must survive: TickLib is a library but
        # goes through the tick-math path before the library guard fires.
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(TICKLIB)
            p = Path(f.name)
        ws = Path(tempfile.mkdtemp())
        manifest = mod.author(
            ws, p, "TickLib", mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None
        )
        self.assertEqual(manifest["authoring_path"], "tick-math-pure-library")


class TestSharedActorPool(unittest.TestCase):
    """The generated medusa/echidna configs must expose a shared address pool
    so the fuzzer may assign the SAME address to two roles (payer==receiver,
    from==to, liquidator==borrower) without a per-bug hint.  This is the
    generic input-space fix that would have reached the morpho self-settled-take.
    """

    def setUp(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            self.contract = Path(f.name)
        self.ws = Path(tempfile.mkdtemp())
        self.manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        self.out = Path(self.manifest["out_dir"])

    def _medusa_cfg(self):
        return json.loads((self.out / "medusa.json").read_text())

    def _echidna_cfg_text(self):
        return (self.out / "echidna.yaml").read_text()

    def test_medusa_sender_addresses_present(self):
        cfg = self._medusa_cfg()
        self.assertIn(
            "senderAddresses", cfg["fuzzing"],
            "medusa.json fuzzing.senderAddresses must be present for shared-pool coverage",
        )

    def test_medusa_sender_addresses_non_empty(self):
        senders = self._medusa_cfg()["fuzzing"]["senderAddresses"]
        self.assertGreater(
            len(senders), 0,
            "senderAddresses must be non-empty",
        )

    def test_medusa_sender_addresses_allow_collapse(self):
        # A shared pool means the SAME address can appear as multiple roles.
        # The pool must contain at least two distinct entries so the fuzzer has
        # *both* collapse-capable (same address) AND distinct-address sequences.
        # One entry => always same actor, two+ entries => can go either way.
        senders = self._medusa_cfg()["fuzzing"]["senderAddresses"]
        self.assertGreaterEqual(
            len(senders), 2,
            "At least 2 sender addresses needed so the fuzzer can explore both "
            "same-actor (collapse) and distinct-actor paths without hints; "
            "got: " + repr(senders),
        )

    def test_medusa_sender_addresses_are_valid_hex(self):
        import re
        senders = self._medusa_cfg()["fuzzing"]["senderAddresses"]
        hex_re = re.compile(r"^0x[0-9a-fA-F]+$")
        for addr in senders:
            self.assertRegex(
                addr, hex_re,
                "Each senderAddress must be a 0x-prefixed hex string; got: " + repr(addr),
            )

    def test_echidna_senders_present(self):
        text = self._echidna_cfg_text()
        self.assertIn(
            "senders:",
            text,
            "echidna.yaml must contain a senders: block for shared-pool coverage",
        )

    def test_echidna_senders_non_empty(self):
        import re
        text = self._echidna_cfg_text()
        # find all "  - ..." lines after the senders: key
        m = re.search(r"senders:\n((?:  - [^\n]+\n?)+)", text)
        self.assertIsNotNone(m, "senders: block must have at least one address entry")
        entries = re.findall(r'  - "?([^"\n]+)"?', m.group(1))
        self.assertGreater(len(entries), 0, "senders entries must be non-empty")

    def test_echidna_senders_allow_collapse(self):
        import re
        text = self._echidna_cfg_text()
        m = re.search(r"senders:\n((?:  - [^\n]+\n?)+)", text)
        self.assertIsNotNone(m, "senders: block not found")
        entries = re.findall(r'  - "?([^"\n]+)"?', m.group(1))
        self.assertGreaterEqual(
            len(entries), 2,
            "At least 2 senders needed so the fuzzer can explore both "
            "same-actor (collapse) and distinct-actor paths; got: " + repr(entries),
        )

    def test_medusa_and_echidna_sender_sets_consistent(self):
        # The two configs should advertise the same address pool so behavior
        # is predictable across both fuzzers.
        import re
        medusa_senders = set(self._medusa_cfg()["fuzzing"]["senderAddresses"])
        text = self._echidna_cfg_text()
        m = re.search(r"senders:\n((?:  - [^\n]+\n?)+)", text)
        self.assertIsNotNone(m, "echidna senders: block not found")
        echidna_senders = set(re.findall(r'  - "?([^"\n]+)"?', m.group(1)))
        self.assertEqual(
            medusa_senders, echidna_senders,
            "medusa senderAddresses and echidna senders must be identical; "
            "medusa=" + repr(medusa_senders) + " echidna=" + repr(echidna_senders),
        )

    def test_existing_medusa_config_fields_preserved(self):
        # Adding senderAddresses must not displace any pre-existing required fields.
        cfg = self._medusa_cfg()
        fuzz = cfg["fuzzing"]
        for key in ("workers", "testLimit", "callSequenceLength",
                    "targetContracts", "corpusDirectory",
                    "assertionTesting", "propertyTesting"):
            self.assertIn(key, fuzz, "required medusa field missing: " + key)


# ---------------------------------------------------------------------------
# Bug-guarding tests for library-qualified type import resolution (2026-06-13)
# ---------------------------------------------------------------------------

# A contract whose public surface uses a library-qualified enum type.
# Before fix: the interface block contained `LibTransfer.To` and `LibTransfer.From`
# but no import - solc would fail with "Identifier not found or not unique".
# After fix: the tool resolves the library file in the workspace and emits an
# `import {LibTransfer} from "<rel_path>";` before the interface block.
_CLAIM_FACET_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibTransfer} from "contracts/libraries/Token/LibTransfer.sol";

contract ClaimFacet {
    function claimPlenty(address well, LibTransfer.To toMode) external payable {}
    function claimAllPlenty(LibTransfer.To toMode) external payable {}
    function mow(address account, address token) external {}
}
"""

_LIB_TRANSFER_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library LibTransfer {
    enum To { EXTERNAL, INTERNAL }
    enum From { EXTERNAL, INTERNAL }
    function sendToken(address token, uint256 amount, address recipient, To toMode) internal {}
}
"""


class TestQualifiedTypeImportResolution(unittest.TestCase):
    """Library-qualified type references (e.g. LibTransfer.To) in function
    signatures must cause the harness author to emit a corresponding import
    statement so the generated .sol compiles.  Functions whose library types
    cannot be resolved must be omitted (TYPED-SKIP) rather than emitted as
    non-compiling signatures."""

    def setUp(self):
        # Build a fake workspace: contracts/libraries/Token/LibTransfer.sol
        self.ws = Path(tempfile.mkdtemp())
        lib_dir = self.ws / "contracts" / "libraries" / "Token"
        lib_dir.mkdir(parents=True)
        (lib_dir / "LibTransfer.sol").write_text(_LIB_TRANSFER_SRC)

        # Write the ClaimFacet source at the workspace root.
        self.facet_path = self.ws / "ClaimFacet.sol"
        self.facet_path.write_text(_CLAIM_FACET_SRC)

    def _surf(self):
        return mod.parse_contract(self.facet_path, "ClaimFacet")

    def _test_dir(self):
        # Mirrors what author() creates: poc-tests/<Name>-engine-harness/test/
        return self.ws / "poc-tests" / "ClaimFacet-engine-harness" / "test"

    def test_resolve_library_import_finds_libtransfer(self):
        """_resolve_library_import must return a non-None relative path for
        LibTransfer when the workspace contains the library definition."""
        test_dir = self._test_dir()
        test_dir.mkdir(parents=True, exist_ok=True)
        result = mod._resolve_library_import("LibTransfer", self.ws, test_dir)
        self.assertIsNotNone(
            result,
            "_resolve_library_import returned None - should have found LibTransfer.sol",
        )
        # The result must be a relative path string, not absolute.
        self.assertFalse(
            result.startswith("/"),
            "import path should be relative, not absolute; got: " + repr(result),
        )
        # It must end with LibTransfer.sol.
        self.assertTrue(
            result.endswith("LibTransfer.sol"),
            "import path must end with LibTransfer.sol; got: " + repr(result),
        )

    def test_collect_qualified_imports_identifies_libtransfer(self):
        """_collect_qualified_imports must identify LibTransfer as a needed
        import and resolve it to a non-None path."""
        surf = self._surf()
        test_dir = self._test_dir()
        test_dir.mkdir(parents=True, exist_ok=True)
        imports, unresolved = mod._collect_qualified_imports(
            surf.mutating_external, self.ws, test_dir
        )
        self.assertIn(
            "LibTransfer", imports,
            "LibTransfer must appear in resolved imports; got imports=" + repr(imports),
        )
        self.assertNotIn(
            "LibTransfer", unresolved,
            "LibTransfer must NOT appear in unresolved set",
        )

    def test_render_target_interface_emits_import_for_libtransfer(self):
        """_render_target_interface must prefix the interface block with an
        import statement for LibTransfer when the workspace contains the lib."""
        surf = self._surf()
        test_dir = self._test_dir()
        test_dir.mkdir(parents=True, exist_ok=True)
        result = mod._render_target_interface(surf, workspace=self.ws, test_dir=test_dir)
        self.assertIn(
            "import {LibTransfer}", result,
            "The generated interface block must include an import for LibTransfer; got:\n" + result,
        )
        # The import must precede the interface declaration.
        import_pos = result.find("import {LibTransfer}")
        iface_pos = result.find("interface IAuditooor")
        self.assertLess(
            import_pos, iface_pos,
            "import must appear before the interface declaration",
        )

    def test_render_target_interface_signatures_preserved_after_import(self):
        """After adding the import, the function signatures must still be
        present verbatim in the interface - they must not be stripped."""
        surf = self._surf()
        test_dir = self._test_dir()
        test_dir.mkdir(parents=True, exist_ok=True)
        result = mod._render_target_interface(surf, workspace=self.ws, test_dir=test_dir)
        self.assertIn("claimPlenty", result)
        self.assertIn("LibTransfer.To", result)

    def test_author_emits_import_in_fuzzprops(self):
        """Full author() run: the generated _FuzzProps.sol must contain the
        LibTransfer import so it would compile without "Identifier not found"."""
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        # Build a minimal corpus stub if the real index is absent (CI safety).
        if not corpus:
            self.skipTest("corpus index unavailable - skipping integration test")
        try:
            manifest = mod.author(
                self.ws, self.facet_path, "ClaimFacet",
                mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
            )
        except ValueError as exc:
            # If no category matched the surface, that's acceptable - skip.
            if "no mutating external surface matched" in str(exc):
                self.skipTest("no corpus match for minimal ClaimFacet - skip")
            raise
        out = Path(manifest["out_dir"])
        fuzz = (out / "test" / "ClaimFacet_FuzzProps.sol").read_text()
        self.assertIn(
            "import {LibTransfer}", fuzz,
            "_FuzzProps.sol must contain LibTransfer import; got file:\n" + fuzz[:1200],
        )

    def test_unresolvable_type_produces_typed_skip_not_compile_error(self):
        """When a library type cannot be resolved in the workspace, the function
        must be replaced with a TYPED-SKIP comment rather than emitting an
        un-importable reference that would break solc."""
        # Write a contract that references a non-existent library.
        src = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WidgetFacet {
    function process(address user, LibGhostXYZ.Mode mode) external {}
    function transfer(address to, uint256 amount) external {}
}
"""
        p = self.ws / "WidgetFacet.sol"
        p.write_text(src)
        surf = mod.parse_contract(p, "WidgetFacet")
        test_dir = self._test_dir()
        test_dir.mkdir(parents=True, exist_ok=True)
        result = mod._render_target_interface(surf, workspace=self.ws, test_dir=test_dir)
        # The non-resolvable function must appear as a TYPED-SKIP comment.
        self.assertIn(
            "TYPED-SKIP", result,
            "Unresolvable library type must produce a TYPED-SKIP comment; got:\n" + result,
        )
        # The unresolvable raw type must NOT appear as a live function signature.
        # It may appear in the TYPED-SKIP comment itself, but NOT in a
        # `function process(...)` line.
        import re as _re
        fn_lines = [l for l in result.splitlines() if _re.search(r"^\s+function\s+process\(", l)]
        self.assertEqual(
            fn_lines, [],
            "process() with unresolvable LibGhostXYZ.Mode must NOT appear as "
            "a live function signature; got lines: " + repr(fn_lines),
        )
        # The resolvable function (transfer) must still be present.
        self.assertIn("function transfer(", result)

    def test_no_import_emitted_when_no_qualified_types(self):
        """When no library-qualified types appear in signatures, no import is
        emitted - backward-compatible for contracts using only primitive types."""
        surf = mod.parse_contract(
            self.facet_path.parent.parent / "ClaimFacet.sol" if False else self.facet_path,
            "ClaimFacet",
        )
        # Build a surface with only primitive-type functions.
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)  # Vault contract - no library-qualified types
            p = Path(f.name)
        surf_plain = mod.parse_contract(p, "Vault")
        test_dir = self._test_dir()
        test_dir.mkdir(parents=True, exist_ok=True)
        result = mod._render_target_interface(
            surf_plain, workspace=self.ws, test_dir=test_dir
        )
        self.assertNotIn(
            "import {", result,
            "No import should be emitted when no qualified types appear; got:\n" + result,
        )
        # But the interface itself should be present as normal.
        self.assertIn("interface IAuditooorVaultTarget", result)


# ---------------------------------------------------------------------------
# Bug-guarding tests for bare-custom-type typed-skip + array-element-type
# argument construction (2026-06-13).
#
# Beanstalk regression: PipelineConvertFacet's pipelineConvert takes an
# `AdvancedPipeCall[] memory` param (a bare struct type, NOT a Lib.Member
# qualified ref) and the gauge functions take `int96[]`. Before the fix:
#   - the bare struct leaked verbatim into the target interface -> solc
#     Error (7920): Identifier not found or not unique -> the WHOLE harness
#     failed to compile -> 0 engine coverage (engine-error, real_execution=False).
#   - int96[] args were emitted as `new int256[](0)` -> Error: invalid implicit
#     conversion from int[] to int96[].
# After the fix: struct-param functions are TYPED-SKIPPED (harness compiles,
# engines run on the resolvable functions), and array args use the real
# element type.
# ---------------------------------------------------------------------------


class TestBareCustomTypeTypedSkip(unittest.TestCase):
    """A function whose params reference a bare custom (non-elementary) type
    such as a struct name must be TYPED-SKIPPED rather than emitted into the
    interface (which would not compile)."""

    _SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PipeFacet {
    function pipelineConvert(address inputToken, int96[] calldata stems, uint256[] calldata amounts, address outputToken, AdvancedPipeCall[] memory advancedPipeCalls) external returns (int256) {}
    function transfer(address to, uint256 amount) external {}
}
"""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        self.p = self.ws / "PipeFacet.sol"
        self.p.write_text(self._SRC)
        self.test_dir = self.ws / "poc-tests" / "PipeFacet-engine-harness" / "test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def test_is_elementary_param_type(self):
        for good in ("address", "uint256", "int96", "bool", "bytes32", "string",
                     "uint256[]", "int96[]", "bytes", "address[]"):
            self.assertTrue(mod._is_elementary_param_type(good), good)
        for bad in ("AdvancedPipeCall", "AdvancedPipeCall[]", "LibTransfer.To",
                    "MyStruct", "IERC20"):
            self.assertFalse(mod._is_elementary_param_type(bad), bad)

    def test_unsupported_param_types_flags_struct_keeps_elementary(self):
        params = ("address inputToken, int96[] calldata stems, uint256[] calldata amounts, "
                  "address outputToken, AdvancedPipeCall[] memory advancedPipeCalls")
        bad = mod._unsupported_param_types(params, set())
        self.assertEqual(bad, ["AdvancedPipeCall[]"], bad)
        # A purely-elementary signature flags nothing.
        self.assertEqual(mod._unsupported_param_types("address to, uint256 amount", set()), [])

    def test_resolved_qualified_type_is_supported(self):
        # A qualified Lib.Member type whose library is in resolved_libs is NOT
        # flagged (it gets an import line) - preserves the c3184e2a8e behaviour.
        self.assertEqual(
            mod._unsupported_param_types("address well, LibTransfer.To toMode", {"LibTransfer"}),
            [],
        )
        # But unresolved qualified is flagged.
        self.assertEqual(
            mod._unsupported_param_types("LibGhost.Mode m", set()),
            ["LibGhost.Mode"],
        )

    def test_struct_param_function_typed_skipped_in_interface(self):
        surf = mod.parse_contract(self.p, "PipeFacet")
        result = mod._render_target_interface(surf, workspace=self.ws, test_dir=self.test_dir)
        # The struct-param function must be TYPED-SKIPPED, not a live signature.
        self.assertIn("TYPED-SKIP", result)
        import re as _re
        live_pipeline = [l for l in result.splitlines()
                         if _re.search(r"^\s+function\s+pipelineConvert\(", l)]
        self.assertEqual(live_pipeline, [],
                         "pipelineConvert (struct param) must NOT be a live signature; got: "
                         + repr(live_pipeline))
        # The bare struct type must never appear as a live interface type.
        self.assertNotIn("AdvancedPipeCall[] memory advancedPipeCalls) external", result)
        # The purely-elementary function must survive.
        self.assertIn("function transfer(", result)


class TestArrayArgRealElementType(unittest.TestCase):
    """_solidity_arg_for_type must construct array literals with the real
    element type, not a hardcoded int256[]/uint256[]."""

    def test_int_array_uses_real_element_type(self):
        self.assertEqual(mod._solidity_arg_for_type("int96[]", 0), "new int96[](0)")
        self.assertEqual(mod._solidity_arg_for_type("int128[]", 1), "new int128[](0)")

    def test_uint_array_uses_real_element_type(self):
        self.assertEqual(mod._solidity_arg_for_type("uint128[]", 0), "new uint128[](0)")
        self.assertEqual(mod._solidity_arg_for_type("uint256[]", 0), "new uint256[](0)")

    def test_scalar_int_uint_unchanged(self):
        self.assertEqual(mod._solidity_arg_for_type("int96", 0), "int96(int256(x))")
        self.assertEqual(mod._solidity_arg_for_type("uint128", 0), "uint128(x)")


# ---------------------------------------------------------------------------
# Guard test: forge invariant harness setUp binds a target OR is typed-skip
#
# The diagnosed vacuity: emit_forge_invariant authored _Invariant.t.sol
# harnesses where setUp() never called bindTarget(), so target remained
# address(0) at runtime. Every real-protocol call was guarded by
# `if (address(target) != address(0))`, silently skipped, and only the
# synthetic mutate*/drive* model state ran. Every mutant passed because the
# real CUT was never invoked -> oracle_verdict=vacuous, 0 kills. The proof gate
# still returned PASS_REAL because the invariant check expressions contained
# real comparisons over model state, but the model state had no connection to
# the real contract -> FALSE COVERAGE.
#
# The fix (option b - honest typed-skip, per task spec): since the CUT cannot
# be generically instantiated without knowing constructor args, emit the
# _Invariant.t.sol with a HARNESS-TYPED-SKIP sentinel that is unambiguously
# NOT genuine coverage, and record setUp_binds_target="typed-skip" in the
# manifest. This prevents the vacuous green from propagating to downstream
# consumers (audit-complete, oracle_verdict). The audit author must supply
# CUT-specific setUp wiring to promote to genuine coverage.
#
# Guard invariant (FAILS before fix, PASSES after):
#   For every authored _Invariant.t.sol:
#     setUp() body contains `bindTarget(`        <- genuine wiring
#     OR the file contains `HARNESS-TYPED-SKIP`  <- honest typed-skip
#   AND manifest setUp_binds_target != False      <- no silent false-green
# ---------------------------------------------------------------------------

class TestForgeInvariantTypedSkipNotVacuous(unittest.TestCase):
    """Guard test: the emitted _Invariant.t.sol must EITHER call bindTarget()
    in setUp (genuine CUT wiring) OR carry an explicit HARNESS-TYPED-SKIP
    sentinel (honest typed-skip). A model-only harness that silently skips all
    real-protocol calls via `if (address(target) != address(0))` guards without
    any typed-skip marking is the vacuity this test rejects."""

    def setUp(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            self.contract = Path(f.name)
        self.ws = Path(tempfile.mkdtemp())
        self.manifest = mod.author(
            self.ws, self.contract, None,
            mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
        )
        self.out = Path(self.manifest["out_dir"])
        self.inv_src = (self.out / "test" / "Vault_Invariant.t.sol").read_text()

    def _setUp_calls_bindTarget(self):
        """Return True if the emitted setUp() function body contains an actual
        (non-comment) bindTarget( call. Comments like `// bindTarget(...)` are
        NOT counted - only a live call is a genuine binding."""
        import re as _re
        # Extract the setUp function body between { and its matching }.
        m = _re.search(
            r"function setUp\(\) public \{(.*?)\n    \}",
            self.inv_src,
            _re.DOTALL,
        )
        if m is None:
            return False
        body = m.group(1)
        # Strip single-line comments before checking for live call.
        stripped = _re.sub(r"//[^\n]*", "", body)
        return "bindTarget(" in stripped

    def test_setUp_binds_target_not_false(self):
        """Manifest setUp_binds_target must NOT be False.
        False means the harness is model-only with no explicit typed-skip
        recording -> a downstream consumer sees genuine coverage where there is
        none. Accepted values: True (genuine setUp wiring) or 'typed-skip'."""
        val = self.manifest.get("setUp_binds_target")
        self.assertNotEqual(
            val, False,
            "manifest setUp_binds_target must not be False; False means a "
            "model-only harness is presented as genuine coverage "
            "(oracle_verdict=vacuous, 0 kills). "
            "Set to True when setUp calls bindTarget(), or 'typed-skip' when "
            "the CUT cannot be generically instantiated. Got: " + repr(val),
        )

    def test_invariant_file_binds_target_or_typed_skip(self):
        """The emitted _Invariant.t.sol must either call bindTarget() in setUp
        (genuine CUT wiring) or carry a HARNESS-TYPED-SKIP sentinel (honest
        typed-skip). A model-only body with neither is FALSE COVERAGE."""
        has_bind = self._setUp_calls_bindTarget()
        has_skip = "HARNESS-TYPED-SKIP" in self.inv_src
        self.assertTrue(
            has_bind or has_skip,
            "Vault_Invariant.t.sol is a model-only harness: setUp() does not "
            "call bindTarget() (live, non-comment) AND the file lacks a "
            "HARNESS-TYPED-SKIP marker. "
            "This produces oracle_verdict=vacuous (all mutants pass, 0 kills) "
            "because target == address(0) causes every real-protocol call to "
            "be silently skipped. Fix: either deploy + bindTarget the real CUT "
            "in setUp(), or emit the file with a HARNESS-TYPED-SKIP sentinel "
            "and record setUp_binds_target='typed-skip' in the manifest.",
        )

    def test_no_silent_model_only_body(self):
        """The old BIND-TARGET-NEEDED comment is NOT sufficient - it documents
        the problem but does not prevent the vacuous green. After the fix, a
        genuine typed-skip sentinel (HARNESS-TYPED-SKIP) must be present, or
        setUp must call bindTarget(). BIND-TARGET-NEEDED alone fails."""
        has_bind = self._setUp_calls_bindTarget()
        has_typed_skip = "HARNESS-TYPED-SKIP" in self.inv_src
        # A file that has the old BIND-TARGET-NEEDED comment but not the new
        # HARNESS-TYPED-SKIP sentinel and does not call bindTarget() is the
        # failure mode we guard against.
        if not has_bind and not has_typed_skip:
            self.fail(
                "Vault_Invariant.t.sol has BIND-TARGET-NEEDED but no "
                "HARNESS-TYPED-SKIP and no live bindTarget() call in setUp. "
                "BIND-TARGET-NEEDED is documentation, not a guard: the proof "
                "gate still scores the file PASS_REAL via the model invariant "
                "checks, propagating a vacuous green upstream. "
                "Upgrade to HARNESS-TYPED-SKIP sentinel so downstream "
                "consumers know this file requires CUT-specific wiring.",
            )

    def test_setUp_binds_target_value_is_typed_skip_when_no_generic_ctor(self):
        """When the CUT cannot be generically instantiated (no constructor
        args known at authoring time), setUp_binds_target must be 'typed-skip',
        not False. 'typed-skip' lets callers distinguish intentional from
        accidental model-only harnesses."""
        val = self.manifest.get("setUp_binds_target")
        if self._setUp_calls_bindTarget():
            self.assertEqual(
                val, True,
                "setUp calls bindTarget() (live) so setUp_binds_target must be True; "
                "got: " + repr(val),
            )
        else:
            # No live bindTarget call in setUp -> must be 'typed-skip', not False.
            self.assertEqual(
                val, "typed-skip",
                "setUp does not call bindTarget() (live), so setUp_binds_target "
                "must be 'typed-skip' (not False). False silently presents a "
                "model-only harness as genuine coverage. Got: " + repr(val),
            )

    def test_halmos_and_fuzz_not_affected_by_typed_skip(self):
        """The HARNESS-TYPED-SKIP designation applies only to the forge
        invariant harness (which needs setUp/bindTarget wiring). The halmos
        symbolic specs and echidna/medusa fuzz properties are self-contained
        and must NOT carry the HARNESS-TYPED-SKIP sentinel (they are real)."""
        halmos_src = (self.out / "test" / "Vault_HalmosSpec.t.sol").read_text()
        fuzz_src = (self.out / "test" / "Vault_FuzzProps.sol").read_text()
        self.assertNotIn(
            "HARNESS-TYPED-SKIP", halmos_src,
            "HARNESS-TYPED-SKIP must NOT appear in _HalmosSpec.t.sol: "
            "halmos specs are self-contained and are genuine coverage.",
        )
        self.assertNotIn(
            "HARNESS-TYPED-SKIP", fuzz_src,
            "HARNESS-TYPED-SKIP must NOT appear in _FuzzProps.sol: "
            "echidna/medusa fuzz properties are self-contained and are genuine.",
        )

    def test_typed_skip_inv_file_contains_wiring_instructions(self):
        """A HARNESS-TYPED-SKIP _Invariant.t.sol must still tell the audit
        author what wiring is needed (what contract to deploy + bind). The
        instructions must reference the real contract name and bindTarget."""
        if self._setUp_calls_bindTarget():
            return  # genuine wiring path - skip
        # Typed-skip path: must have actionable wiring instructions.
        self.assertIn(
            "HARNESS-TYPED-SKIP", self.inv_src,
            "Typed-skip path must contain HARNESS-TYPED-SKIP",
        )
        # Must reference bindTarget so the author knows what to do.
        self.assertIn(
            "bindTarget", self.inv_src,
            "HARNESS-TYPED-SKIP file must reference bindTarget in its "
            "instructions so the audit author knows what wiring to add.",
        )
        # Must reference the real contract name.
        self.assertIn(
            "Vault", self.inv_src,
            "HARNESS-TYPED-SKIP file must reference the CUT name (Vault) "
            "in its wiring instructions.",
        )


# ---------------------------------------------------------------------------
# Guard test: transitive-dep-remapping (lane transitive-dep-remapping)
#
# Root cause (Error 6275 / Source not found): emit_foundry_toml emitted a
# static foundry.toml with libs=["lib"] and no remappings.  When the generated
# harness imported a real workspace library (e.g. LibTransfer) whose own
# transitive imports used remapped prefixes (@openzeppelin/, contracts/...),
# those prefixes were absent from the generated foundry.toml, causing solc
# Error 6275 (Source not found) on every transitive import.
#
# Fix: _workspace_foundry_settings() reads the workspace's remappings.txt
# (and inline foundry.toml remappings) and expands relative targets to
# absolute paths; emit_foundry_toml() merges them in.  The generated
# foundry.toml now resolves any transitive import that the workspace itself
# can resolve.
#
# Guard invariant (FAILS before fix, PASSES after):
#   When the workspace has a remappings.txt, the generated foundry.toml MUST
#   contain those remappings with absolute-path targets (so they resolve from
#   any out-dir location), AND the libs array MUST include the workspace's
#   absolute lib paths.
# ---------------------------------------------------------------------------


class TestTransitiveDepRemapping(unittest.TestCase):
    """emit_foundry_toml must inherit workspace remappings + lib paths so
    transitive imports from workspace libraries resolve from the generated
    harness out-dir. Regression guard for Error 6275 (Source not found)."""

    def _make_workspace(self):
        """Build a minimal fake workspace with:
          - remappings.txt referencing @openzeppelin/ and forge-std/
          - a lib/ directory (for forge-std)
          - a node_modules/ directory (for @openzeppelin)
          - foundry.toml with libs = ['node_modules', 'lib']
          - contracts/libraries/Token/LibTransfer.sol
        """
        ws = Path(tempfile.mkdtemp())
        # Create the lib directories.
        (ws / "lib" / "forge-std" / "src").mkdir(parents=True)
        (ws / "node_modules" / "@openzeppelin" / "contracts").mkdir(parents=True)
        # Write remappings.txt (relative targets).
        (ws / "remappings.txt").write_text(
            "forge-std/=lib/forge-std/src/\n"
            "@openzeppelin/=node_modules/@openzeppelin/\n"
            "contracts/=contracts/\n",
            encoding="utf-8",
        )
        # Write foundry.toml with libs array.
        (ws / "foundry.toml").write_text(
            "[profile.default]\n"
            "src = 'contracts'\n"
            "test = 'test'\n"
            "out = 'out'\n"
            "libs = ['node_modules', 'lib']\n",
            encoding="utf-8",
        )
        # Write a real library file.
        lib_dir = ws / "contracts" / "libraries" / "Token"
        lib_dir.mkdir(parents=True)
        (lib_dir / "LibTransfer.sol").write_text(_LIB_TRANSFER_SRC, encoding="utf-8")
        return ws

    def test_workspace_foundry_settings_reads_remappings(self):
        """_workspace_foundry_settings must return the remappings from
        remappings.txt with targets expanded to absolute paths."""
        ws = self._make_workspace()
        remappings, abs_libs = mod._workspace_foundry_settings(ws)
        # Must find all three remapping prefixes from remappings.txt.
        prefixes = [r.split("=")[0] for r in remappings]
        self.assertIn(
            "forge-std/", prefixes,
            "_workspace_foundry_settings must include forge-std/ from remappings.txt; "
            "got prefixes=" + repr(prefixes),
        )
        self.assertIn(
            "@openzeppelin/", prefixes,
            "_workspace_foundry_settings must include @openzeppelin/ from remappings.txt; "
            "got prefixes=" + repr(prefixes),
        )

    def test_workspace_foundry_settings_expands_to_absolute(self):
        """Remapping targets must be absolute paths (not relative) so they
        resolve from any out-dir location, not just the workspace root."""
        ws = self._make_workspace()
        remappings, _ = mod._workspace_foundry_settings(ws)
        for r in remappings:
            _, _, target = r.partition("=")
            # target may be empty string for prefix-only remappings; skip those.
            if not target:
                continue
            self.assertTrue(
                target.startswith("/"),
                "Remapping target must be an absolute path so it resolves "
                "from any out-dir; got: " + repr(r),
            )

    def test_workspace_foundry_settings_reads_lib_dirs(self):
        """_workspace_foundry_settings must return the absolute paths of
        the lib directories declared in foundry.toml's libs array."""
        ws = self._make_workspace()
        _, abs_libs = mod._workspace_foundry_settings(ws)
        abs_lib_strs = " ".join(abs_libs)
        # Both node_modules and lib must appear as absolute paths.
        self.assertTrue(
            any("node_modules" in p for p in abs_libs),
            "node_modules must appear in abs_libs; got: " + repr(abs_libs),
        )
        self.assertTrue(
            any("/lib" in p for p in abs_libs),
            "lib/ must appear in abs_libs; got: " + repr(abs_libs),
        )

    def test_emit_foundry_toml_inherits_workspace_remappings(self):
        """emit_foundry_toml(workspace=ws) must include all workspace
        remappings with absolute targets in the generated foundry.toml."""
        ws = self._make_workspace()
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, "Vault")
        out = Path(tempfile.mkdtemp())
        toml_text = mod.emit_foundry_toml(surf, workspace=ws, out_dir=out)
        # The generated foundry.toml must contain a remappings block.
        self.assertIn(
            "remappings", toml_text,
            "emit_foundry_toml must include a remappings block when workspace "
            "has remappings.txt; got:\n" + toml_text,
        )
        # Must include forge-std/ remapping.
        self.assertIn(
            "forge-std/", toml_text,
            "Generated foundry.toml must include forge-std/ remapping; got:\n" + toml_text,
        )
        # Must include @openzeppelin/ remapping.
        self.assertIn(
            "@openzeppelin/", toml_text,
            "Generated foundry.toml must include @openzeppelin/ remapping; got:\n" + toml_text,
        )

    def test_emit_foundry_toml_targets_are_absolute(self):
        """Remapping targets in the generated foundry.toml must be absolute
        paths so they resolve correctly from the harness out-dir."""
        import re as _re
        ws = self._make_workspace()
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, "Vault")
        out = Path(tempfile.mkdtemp())
        toml_text = mod.emit_foundry_toml(surf, workspace=ws, out_dir=out)
        # Extract all "prefix=target" lines inside the remappings block.
        remap_lines = _re.findall(r'"([^"]+/=[^"]+)"', toml_text)
        for r in remap_lines:
            _, _, target = r.partition("=")
            if not target:
                continue
            self.assertTrue(
                target.startswith("/"),
                "Remapping target must be absolute in generated foundry.toml; "
                "got: " + repr(r),
            )

    def test_emit_foundry_toml_libs_includes_workspace_abs_paths(self):
        """The libs array in the generated foundry.toml must include the
        absolute paths of the workspace's lib directories."""
        ws = self._make_workspace()
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, "Vault")
        out = Path(tempfile.mkdtemp())
        toml_text = mod.emit_foundry_toml(surf, workspace=ws, out_dir=out)
        # libs line must exist and include at least one absolute path.
        self.assertIn(
            "libs =", toml_text,
            "Generated foundry.toml must have a libs = [...] line; got:\n" + toml_text,
        )
        # At least one absolute path must appear in the libs array.
        self.assertRegex(
            toml_text,
            r'libs\s*=\s*\[(?:[^]]*"/[^"]*"[^]]*)\]',
            "libs array must contain at least one absolute path; got:\n" + toml_text,
        )

    def test_emit_foundry_toml_without_workspace_still_valid(self):
        """emit_foundry_toml(workspace=None) must still produce a valid
        foundry.toml (backward-compatible: no remappings block, basic libs)."""
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as f:
            f.write(SAMPLE)
            p = Path(f.name)
        surf = mod.parse_contract(p, "Vault")
        toml_text = mod.emit_foundry_toml(surf, workspace=None)
        self.assertIn("[profile.default]", toml_text)
        self.assertIn('src = "src"', toml_text)
        # No remappings block expected when workspace=None.
        self.assertNotIn(
            "remappings", toml_text,
            "No remappings block expected when workspace=None; got:\n" + toml_text,
        )

    def test_author_generated_foundry_toml_inherits_workspace_remappings(self):
        """Full author() integration: the foundry.toml written by author() to
        the harness out-dir must include the workspace remappings so transitive
        imports (e.g. @openzeppelin/) resolve when forge build is run."""
        ws = self._make_workspace()
        # Write the target contract inside the workspace.
        contract_path = ws / "ClaimFacet.sol"
        contract_path.write_text(_CLAIM_FACET_SRC, encoding="utf-8")
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        if not corpus:
            self.skipTest("corpus index unavailable - skip integration test")
        try:
            manifest = mod.author(
                ws, contract_path, "ClaimFacet",
                mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
            )
        except ValueError as exc:
            if "no mutating external surface matched" in str(exc):
                self.skipTest("no corpus match - skip")
            raise
        out = Path(manifest["out_dir"])
        toml_text = (out / "foundry.toml").read_text(encoding="utf-8")
        self.assertIn(
            "@openzeppelin/", toml_text,
            "Generated foundry.toml must inherit @openzeppelin/ remapping from "
            "workspace; got:\n" + toml_text,
        )
        self.assertIn(
            "forge-std/", toml_text,
            "Generated foundry.toml must inherit forge-std/ remapping; got:\n" + toml_text,
        )


# ---------------------------------------------------------------------------
# Guard test: int-array-residual - all _target_call_stmt emission paths must
# use the real int element type (not hardcoded int256[]) for int96[] params.
#
# d5aa842b78 fixed _solidity_arg_for_type to emit new <real_elem>[](0).
# This test guards the RESIDUAL paths: the _target_call_stmt call-arg
# substitution variants (halmos default x='x', echidna/fuzz x='uint256(0)',
# forge invariant actor='address(this)') must also produce the real element
# type end-to-end.
#
# Guard invariant (FAILS before d5aa842b78, PASSES after):
#   For every _target_call_stmt call variant and for author() end-to-end:
#     generated call args for int96[] params must contain new int96[](0)
#     NOT new int256[](0) (which triggers Error 9553: invalid implicit
#     conversion from int256[] memory to int96[] memory).
# ---------------------------------------------------------------------------

class TestIntArrayResidualEmissionPath(unittest.TestCase):
    """Guard test: all _target_call_stmt call-arg paths must emit the real
    array element type. Regression guard for Error 9553 (int256[] -> int96[])."""

    _SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SiloWithdraw {
    function withdrawDeposits(
        address token,
        int96[] calldata stems,
        uint256[] calldata amounts
    ) external payable {
    }
}
"""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        self.p = self.ws / "SiloWithdraw.sol"
        self.p.write_text(self._SRC)

    def _surf(self):
        return mod.parse_contract(self.p, "SiloWithdraw")

    def test_target_call_stmt_default_x_no_int256_array(self):
        """_target_call_stmt with default x='x' (halmos check_ path) must not
        emit new int256[](0) for an int96[] parameter."""
        surf = self._surf()
        stmt = mod._target_call_stmt(surf, "conservation")
        self.assertNotIn(
            "new int256[](0)", stmt,
            "Default-x path emitted new int256[](0) for int96[] param; "
            "Error 9553 regression.",
        )
        self.assertIn(
            "new int96[](0)", stmt,
            "Default-x path must emit new int96[](0) for int96[] param.",
        )

    def test_target_call_stmt_zero_x_no_int256_array(self):
        """_target_call_stmt with x='uint256(0)' (echidna_/fuzz_/invariant_
        zero-arg path) must not emit new int256[](0) for an int96[] parameter."""
        surf = self._surf()
        stmt = mod._target_call_stmt(
            surf, "conservation",
            x="uint256(0)", y="uint256(0)", actor="msg.sender",
        )
        self.assertNotIn(
            "new int256[](0)", stmt,
            "Zero-x path emitted new int256[](0) for int96[] param; "
            "Error 9553 regression.",
        )
        self.assertIn(
            "new int96[](0)", stmt,
            "Zero-x path must emit new int96[](0) for int96[] param.",
        )

    def test_target_call_stmt_address_this_actor_no_int256_array(self):
        """_target_call_stmt with actor='address(this)' (forge invariant_
        path) must not emit new int256[](0) for an int96[] parameter."""
        surf = self._surf()
        stmt = mod._target_call_stmt(
            surf, "conservation",
            x="uint256(0)", y="uint256(0)", actor="address(this)",
        )
        self.assertNotIn(
            "new int256[](0)", stmt,
            "address(this)-actor path emitted new int256[](0) for int96[] param; "
            "Error 9553 regression.",
        )
        self.assertIn(
            "new int96[](0)", stmt,
            "address(this)-actor path must emit new int96[](0) for int96[] param.",
        )

    def test_full_author_no_int256_array_in_generated_sol(self):
        """Full author() must not produce any .sol file containing new int256[](0)
        when the target function takes int96[] parameters."""
        corpus = mod.load_corpus_invariants(mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT)
        if not corpus:
            self.skipTest("corpus index unavailable - skip integration test")
        try:
            manifest = mod.author(
                self.ws, self.p, "SiloWithdraw",
                mod.DEFAULT_EXTRACTED, mod.DEFAULT_PILOT, None,
            )
        except ValueError as exc:
            if "no mutating external surface matched" in str(exc):
                self.skipTest("no corpus match - skip")
            raise
        out = Path(manifest["out_dir"])
        for sol_file in sorted(out.rglob("*.sol")):
            content = sol_file.read_text(encoding="utf-8")
            self.assertNotIn(
                "new int256[](0)", content,
                f"{sol_file.name}: new int256[](0) must not appear for int96[] params; "
                "Error 9553 regression (invalid implicit conversion int256[]->int96[]).",
            )

    def test_solidity_arg_for_type_all_int_widths(self):
        """_solidity_arg_for_type must use the REAL element type for every
        standard int width, not a hardcoded int256[]."""
        for width in ("", "8", "16", "32", "64", "96", "128", "160", "256"):
            typ = f"int{width}[]"
            result = mod._solidity_arg_for_type(typ, 0)
            expected = f"new int{width}[](0)"
            self.assertEqual(
                result, expected,
                f"_solidity_arg_for_type('{typ}') must return '{expected}' "
                f"(real element type); got '{result}'. Error 9553 regression.",
            )


if __name__ == "__main__":
    unittest.main()


class TestFixedBytesArgSynth(unittest.TestCase):
    """Regression: _solidity_arg_for_type must synthesize a FIXED-width value for a
    bytesN param, not a dynamic bytes-memory abi.encodePacked. 'bytes32'.startswith
    ('bytes') is True, so the dynamic branch would emit abi.encodePacked(...) which does
    NOT convert to bytes32 (Error 9553) and build-breaks the whole harness tree (NUVA
    2026-07-06: CrossChainManager deposit(uint256,bytes32))."""

    def test_bytes32_gets_fixed_width_value(self):
        for t in ("bytes32", "bytes4", "bytes1", "bytes16"):
            got = mod._solidity_arg_for_type(t, 0)
            self.assertTrue(got.startswith(t + "(keccak256("),
                            t + " must be a fixed-width cast, got " + got)
            self.assertNotEqual(got, "abi.encodePacked(x, y, actor)")

    def test_dynamic_bytes_unchanged(self):
        self.assertEqual(mod._solidity_arg_for_type("bytes", 0), "abi.encodePacked(x, y, actor)")

    def test_bytes_arrays_unchanged(self):
        self.assertEqual(mod._solidity_arg_for_type("bytes32[]", 0), "new bytes32[](0)")
        self.assertEqual(mod._solidity_arg_for_type("bytes[]", 0), "new bytes[](0)")
