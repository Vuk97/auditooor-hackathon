#!/usr/bin/env python3
"""Recursive call-graph CLOSURE primitive — regression + mutation tests.

Pins the Glider callee/caller_functions_recursive + modifier-fold + override
resolution analog added to ``tools/slither_predicates.py``:

  - ``callee_closure`` / ``caller_closure`` — cycle-guarded, UNBOUNDED-depth.
  - ``has_guard_in_closure`` — folds modifier BODIES; fixes both the
    guard-in-callee FALSE-POSITIVE and the header-only / hollow-modifier
    FALSE-NEGATIVE.
  - ``unguarded_paths_to_sink`` — backward caller closure tagging each
    entrypoint guarded/unguarded.
  - ``resolve_concrete_impl`` — base-guard-dropped-by-override dispatch.

Honesty (R80): these tests require a real Slither compile of the in-tree
fixtures. If Slither is not importable the suite SKIPs (it does not fake a
pass). The DEGRADE path (non-navigable input) is tested without Slither.

Mutation evidence: ``test_mutation_remove_require_flips_guard`` removes the
``require`` in the helper of ``guard_in_helper.sol`` and asserts the predicate
flips True -> False, proving non-vacuity.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "callgraph_closure"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_sp():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates", TOOLS / "slither_predicates.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load_sp()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(), "slither-analyzer not importable; closure tests need a real compile"
)


def _compile(path: pathlib.Path):
    from slither import Slither

    return Slither(str(path))


def _get_fn(sl, cname, fname):
    for c in sl.contracts:
        if c.name == cname:
            for f in c.functions:
                if f.name == fname:
                    return c, f
    return None, None


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class DegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_callee_closure_degrades(self):
        self.assertTrue(sp.is_degraded(sp.callee_closure(self._Dummy())))

    def test_caller_closure_degrades(self):
        self.assertTrue(sp.is_degraded(sp.caller_closure(self._Dummy())))

    def test_has_guard_in_closure_degrades(self):
        self.assertTrue(sp.is_degraded(sp.has_guard_in_closure(self._Dummy())))

    def test_unguarded_paths_to_sink_degrades(self):
        self.assertTrue(sp.is_degraded(sp.unguarded_paths_to_sink(self._Dummy(), [])))

    def test_resolve_concrete_impl_degrades(self):
        self.assertTrue(sp.is_degraded(sp.resolve_concrete_impl(self._Dummy(), "x()")))

    def test_degraded_is_falsy_but_distinct(self):
        # Falsy so `if has_guard_in_closure(...)` does not silently treat it as
        # "guard present", but `is_degraded()` distinguishes it from real False.
        self.assertFalse(bool(sp.DEGRADED))
        self.assertTrue(sp.is_degraded(sp.DEGRADED))
        self.assertFalse(sp.is_degraded(False))


# ─── Semantic path (real Slither compile of fixtures) ────────────────────────


@SKIP_NO_SLITHER
class GuardInClosureTest(unittest.TestCase):
    def test_a_guard_in_helper_is_found(self):
        # (a) header-less fn whose helper (2 hops) has the require -> True.
        sl = _compile(FX / "guard_in_helper.sol")
        _, entry = _get_fn(sl, "GuardInHelper", "entry")
        self.assertIsNotNone(entry)
        self.assertIs(sp.has_guard_in_closure(entry), True)

    def test_b_no_real_guard_in_closure_is_false(self):
        # (b) numeric bound is NOT a caller-identity guard -> False.
        sl = _compile(FX / "no_guard_in_closure.sol")
        _, entry = _get_fn(sl, "NoGuardInClosure", "entry")
        self.assertIs(sp.has_guard_in_closure(entry), False)

    def test_c_hollow_inherited_modifier_is_false(self):
        # (c) modifier header present, BODY hollow -> folds body -> False.
        sl = _compile(FX / "hollow_modifier.sol")
        _, priv = _get_fn(sl, "Child", "privileged")
        self.assertIs(sp.has_guard_in_closure(priv), False)


@SKIP_NO_SLITHER
class OzOnlyOwnerIndirectionTest(unittest.TestCase):
    """#49/#53: OZ onlyOwner -> _checkOwner() -> owner()-revert indirection.

    Pre-refinement the default guard predicate keyed on a DIRECT msg.sender read
    inside a require, so an owner-gated fn whose modifier body is just
    `_checkOwner();` (caller read indirectly via Context._msgSender()) was
    FALSE-flagged unguarded. The refined default recognises (a) a call to a
    known authz helper and (b) an owner()/_msgSender() accessor-compare in a
    require, so the fn is now correctly guarded — WITHOUT widening to value-bound
    requires.
    """

    FX_OZ = FX / "oz_only_owner_indirection.sol"

    def test_g_oz_onlyowner_indirection_is_guarded(self):
        # POSITIVE: rescueERC20 owner-gated via OZ indirection -> guarded.
        sl = _compile(self.FX_OZ)
        _, fn = _get_fn(sl, "OzGuardedVault", "rescueERC20")
        self.assertIsNotNone(fn)
        self.assertIs(sp.has_guard_in_closure(fn), True)

    def test_g_value_bound_require_not_access_guard(self):
        # NEGATIVE: a numeric-bound require is NOT caller-identity authz.
        sl = _compile(self.FX_OZ)
        _, fn = _get_fn(sl, "OzGuardedVault", "valueBoundOnly")
        self.assertIs(sp.has_guard_in_closure(fn), False)

    def test_g_permissionless_stays_unguarded(self):
        # NEGATIVE: genuinely-open fn stays unguarded.
        sl = _compile(self.FX_OZ)
        _, fn = _get_fn(sl, "OzGuardedVault", "permissionless")
        self.assertIs(sp.has_guard_in_closure(fn), False)

    def test_g_checkowner_body_is_a_guard(self):
        # The _checkOwner body itself (owner() == _msgSender() require) is a
        # caller-identity guard even though it reads no literal msg.sender.
        sl = _compile(self.FX_OZ)
        _, fn = _get_fn(sl, "Ownable", "_checkOwner")
        self.assertIs(sp.has_guard_in_closure(fn), True)

    def test_g_mutation_remove_checkowner_require_flips_guard(self):
        # Non-vacuity: deleting the require in _checkOwner must flip
        # rescueERC20 True -> False.
        src = self.FX_OZ.read_text(encoding="utf-8")
        sl = _compile(self.FX_OZ)
        _, fn = _get_fn(sl, "OzGuardedVault", "rescueERC20")
        self.assertIs(sp.has_guard_in_closure(fn), True)

        mutated = src.replace(
            'require(owner() == _msgSender(), "Ownable: caller is not the owner"); // AUTH-TARGET',
            "// require removed by mutation",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "oz_only_owner_indirection.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "OzGuardedVault", "rescueERC20")
            self.assertIs(
                sp.has_guard_in_closure(mfn),
                False,
                "predicate did not flip True->False under mutation (vacuous!)",
            )


@SKIP_NO_SLITHER
class CycleTerminationTest(unittest.TestCase):
    def test_d_recursive_cycle_terminates(self):
        # (d) mutual + self recursion must terminate via visited-set.
        sl = _compile(FX / "recursive_cycle.sol")
        _, ent = _get_fn(sl, "RecursiveCycle", "entryRec")
        closure = sp.callee_closure(ent)
        self.assertFalse(sp.is_degraded(closure))
        names = sorted(getattr(x, "name", "?") for x in closure)
        # a, b (mutually recursive) and loop (self-recursive) all reached once.
        self.assertEqual(names, ["a", "b", "loop"])
        # The root must not be in its own closure.
        self.assertNotIn(ent, closure)


@SKIP_NO_SLITHER
class UnguardedSinkTest(unittest.TestCase):
    def test_e_ungated_mint_path_found_and_tagged(self):
        # (e) privileged _mint reachable from an UNGATED public entrypoint.
        sl = _compile(FX / "ungated_mint.sol")
        scope = [f for c in sl.contracts for f in c.functions]
        _, mint = _get_fn(sl, "UngatedMint", "_mint")
        paths = sp.unguarded_paths_to_sink(mint, scope)
        self.assertFalse(sp.is_degraded(paths))
        by_name = {p["name"]: p for p in paths}
        # Both reachers are enumerated and correctly tagged.
        self.assertIn("openMint", by_name)
        self.assertIn("adminMint", by_name)
        self.assertFalse(by_name["openMint"]["guarded"])  # the bug
        self.assertTrue(by_name["adminMint"]["guarded"])
        # A public fn that does NOT reach the sink must not appear.
        self.assertNotIn("unrelated", by_name)

    def test_e_caller_closure_via_scope(self):
        sl = _compile(FX / "ungated_mint.sol")
        scope = [f for c in sl.contracts for f in c.functions]
        _, mint = _get_fn(sl, "UngatedMint", "_mint")
        callers = sp.caller_closure(mint, scope=scope)
        self.assertFalse(sp.is_degraded(callers))
        names = sorted(getattr(x, "name", "?") for x in callers)
        self.assertEqual(names, ["adminMint", "openMint"])


@SKIP_NO_SLITHER
class OverrideResolutionTest(unittest.TestCase):
    def test_f_base_guard_dropped_by_override(self):
        # (f) child override drops the base onlyOwner.
        sl = _compile(FX / "override_drops_guard.sol")
        derived = next(c for c in sl.contracts if c.name == "Derived")
        base = next(c for c in sl.contracts if c.name == "BaseGuarded")

        impl = sp.resolve_concrete_impl(derived, "setConfig(uint256)")
        self.assertIsNotNone(impl)
        self.assertFalse(sp.is_degraded(impl))
        # The concrete dispatch target on Derived is the CHILD body.
        self.assertEqual(impl.contract.name, "Derived")
        # ... and that body is UNGUARDED (the dropped-guard bug).
        self.assertIs(sp.has_guard_in_closure(impl), False)

        # On the base contract the same selector resolves to the guarded body.
        base_impl = sp.resolve_concrete_impl(base, "setConfig(uint256)")
        self.assertIs(sp.has_guard_in_closure(base_impl), True)

    def test_f_resolve_by_bare_name(self):
        sl = _compile(FX / "override_drops_guard.sol")
        derived = next(c for c in sl.contracts if c.name == "Derived")
        impl = sp.resolve_concrete_impl(derived, "setConfig")
        self.assertIsNotNone(impl)
        self.assertEqual(impl.contract.name, "Derived")

    def test_f_unknown_selector_returns_none(self):
        sl = _compile(FX / "override_drops_guard.sol")
        derived = next(c for c in sl.contracts if c.name == "Derived")
        self.assertIsNone(sp.resolve_concrete_impl(derived, "doesNotExist()"))


@SKIP_NO_SLITHER
class MutationVerificationTest(unittest.TestCase):
    """Non-vacuity: removing the helper's require must flip the predicate."""

    def test_mutation_remove_require_flips_guard(self):
        src = (FX / "guard_in_helper.sol").read_text(encoding="utf-8")
        # Baseline: guard present.
        sl = _compile(FX / "guard_in_helper.sol")
        _, entry = _get_fn(sl, "GuardInHelper", "entry")
        self.assertIs(sp.has_guard_in_closure(entry), True)

        # Mutant: delete the require line in the helper.
        mutated = src.replace(
            'require(msg.sender == owner, "not owner"); // MUTATION-TARGET',
            "// require removed by mutation",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "guard_in_helper.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mentry = _get_fn(msl, "GuardInHelper", "entry")
            self.assertIs(
                sp.has_guard_in_closure(mentry),
                False,
                "predicate did not flip True->False under mutation (vacuous!)",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)


class AccessManagedRestrictedTest(unittest.TestCase):
    """Polygon-surfaced: OZ AccessManaged `restricted` modifier body calls
    _checkCanCall(...) (which delegates to the authority's canCall /
    AuthorityUtils.canCallWithDelay). The closure folds the modifier body; that
    node's call to _checkCanCall must be recognized as a caller-identity authz
    guard, else a `restricted` fn (e.g. PolBridger.rescue -> safeTransfer) is
    FALSE-flagged unguarded. Mock-node unit test (no live Slither needed)."""
    from types import SimpleNamespace as _NS

    def _node(self, callee_names, expression="", ntype=""):
        NS = self._NS
        return NS(
            internal_calls=[NS(name=n) for n in callee_names],
            high_level_calls=[], solidity_calls=[],
            expression=expression, type=ntype,
        )

    def test_checkcancall_is_authz_guard(self):
        # bare `_checkCanCall(...)` statement (no require) -> guard
        node = self._node(["_checkCanCall"])
        self.assertIs(sp._node_default_guard(node), True)

    def test_checkcancall_trusted_even_when_body_resolved(self):
        # THE FIX (real PolBridger.rescue case): foundry compile RESOLVES the
        # AccessManaged body, so _checkcancall is NOT in unresolved_helpers_only;
        # an in-body helper would defer, but an external-authority-enforced
        # primitive stays trusted (real check is an external authority call the
        # closure cannot see).
        node = self._node(["_checkCanCall", "_msgSender", "_msgData"])
        self.assertIs(sp._node_default_guard(node, unresolved_helpers_only=set()), True)

    def test_inbody_helper_still_defers_when_resolved(self):
        # NEVER-FALSE-PASS preserved: an in-body-enforced helper (_checkOwner) is
        # NOT name-trusted when its body is resolved (the body's real check decides;
        # keeps mutation-sensitivity intact).
        node = self._node(["_checkOwner"])
        self.assertIs(sp._node_default_guard(node, unresolved_helpers_only=set()), False)

    def test_cancall_chain_is_authz_guard(self):
        for nm in ("canCall", "canCallWithDelay"):
            self.assertIs(sp._node_default_guard(self._node([nm])), True, nm)

    def test_value_check_not_authz_guard(self):
        # NEVER-FALSE-PASS: a non-authz callee in a require is not caller-identity authz
        node = self._node(["someBoundsCheck"], expression="require(amt <= cap)")
        self.assertIs(sp._node_default_guard(node), False)

    def test_helper_names_registered(self):
        for h in ("_checkcancall", "cancall", "cancallwithdelay"):
            self.assertIn(h, sp._AUTHZ_HELPER_NAMES)


if __name__ == "__main__":
    unittest.main()


class LegacyOzIsOwnerTest(unittest.TestCase):
    """Polygon pos-contracts uses legacy openzeppelin-solidity Ownable:
    `modifier onlyOwner() { require(isOwner()); }` where isOwner() reads
    `msg.sender == _owner`. `require(isOwner())` must be recognized as a
    caller-identity guard (signal 3, accessor in revert context). Mock-node
    unit test (no live Slither)."""
    from types import SimpleNamespace as _NS

    def _node(self, callees, expression, ntype=""):
        NS = self._NS
        return NS(internal_calls=[NS(name=n) for n in callees], high_level_calls=[],
                  solidity_calls=[], expression=expression, type=ntype)

    def test_require_isowner_is_guard(self):
        node = self._node(["isOwner"], "require(isOwner())")
        self.assertIs(sp._node_default_guard(node), True)

    def test_require_isadmin_is_guard(self):
        node = self._node(["isAdmin"], "require(isAdmin())")
        self.assertIs(sp._node_default_guard(node), True)

    def test_isowner_outside_revert_ctx_not_guard(self):
        # an isOwner() call NOT in a require/if is not a guard (e.g. a view return)
        node = self._node(["isOwner"], "return isOwner()")
        self.assertIs(sp._node_default_guard(node), False)


@SKIP_NO_SLITHER
class StorageMappingCallerGuardTest(unittest.TestCase):
    """SSV-surfaced: a per-validator owner gate compares msg.sender against a
    value READ FROM A STORAGE MAPPING / STRUCT FIELD, e.g.
        require(validators[validatorId].contractAddress == msg.sender);
    inside a modifier (or fn body). The storage lvalue is an IR ReferenceVariable
    the node-level read-set does not surface as a caller guard, so signal (4)
    (caller-vs-storage-read comparator) must recognise it. Conservative: an
    arbitrary equality / value-bound / caller-vs-non-storage compare must NOT
    be credited.
    """

    FX_SM = FX / "storage_mapping_caller_guard.sol"

    def test_h_storage_mapping_modifier_guard_is_found(self):
        # POSITIVE: per-validator owner gate via modifier -> guarded.
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "removeValidator")
        self.assertIsNotNone(fn)
        self.assertIs(sp.has_guard_in_closure(fn), True)

    def test_h_storage_mapping_inline_guard_is_found(self):
        # POSITIVE: same gate inline in the fn body -> guarded.
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "removeValidatorInline")
        self.assertIs(sp.has_guard_in_closure(fn), True)

    def test_h_no_caller_compare_stays_unguarded(self):
        # NEGATIVE: identical storage write, no caller-identity compare -> unguarded.
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "unguardedRemove")
        self.assertIs(sp.has_guard_in_closure(fn), False)

    def test_h_value_bound_on_storage_not_access_guard(self):
        # NEGATIVE: a numeric-bound require reading a storage VALUE (not compared
        # against the caller) is NOT a caller-identity guard.
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "valueBoundOnly")
        self.assertIs(sp.has_guard_in_closure(fn), False)

    def test_h_mutation_remove_storage_require_flips_guard(self):
        # Non-vacuity: deleting the storage-compare require in the modifier must
        # flip removeValidator True -> False (proves the modifier guard is real).
        src = self.FX_SM.read_text(encoding="utf-8")
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "removeValidator")
        self.assertIs(sp.has_guard_in_closure(fn), True)

        mutated = src.replace(
            'require(validators[validatorId].contractAddress == msg.sender, "not owner"); // AUTH-TARGET',
            "// require removed by mutation",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "storage_mapping_caller_guard.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "StorageMappingCallerGuard", "removeValidator")
            self.assertIs(
                sp.has_guard_in_closure(mfn),
                False,
                "predicate did not flip True->False under mutation (vacuous!)",
            )

    def test_h_cached_caller_is_found(self):
        # POSITIVE: caller cached from _msgSender() on a prior line, compared
        # against the storage field. ONLY signal (4) can fire (no literal
        # msg.sender / accessor on the require node) -> guarded=True.
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "removeValidatorCachedCaller")
        self.assertIsNotNone(fn)
        self.assertIs(sp.has_guard_in_closure(fn), True)

    def test_h_cached_non_caller_stays_unguarded(self):
        # NEGATIVE: a cached LOCAL that is NOT the caller (a fn param) vs storage
        # must NOT be credited (the alias set seeds only from msg.sender/_msgSender).
        sl = _compile(self.FX_SM)
        _, fn = _get_fn(sl, "StorageMappingCallerGuard", "cachedNonCaller")
        self.assertIs(sp.has_guard_in_closure(fn), False)

    def test_h_signal4_is_load_bearing_not_dead_code(self):
        # THE NON-VACUITY PROOF the reviewer required: disabling ONLY signal (4)'s
        # call site (simulating its removal) must flip the cached-caller fn
        # True -> False. This proves signal (4) closes a gap signals (1)/(3) leave
        # open - i.e. it is load-bearing, not dead code carried by signal (1).
        # The same disable must NOT change the literal-msg.sender fns (they are
        # carried by signal (1)), confirming the test isolates signal (4).
        import unittest.mock as _mock

        sl = _compile(self.FX_SM)
        _, cached = _get_fn(sl, "StorageMappingCallerGuard", "removeValidatorCachedCaller")
        _, literal = _get_fn(sl, "StorageMappingCallerGuard", "removeValidatorInline")

        # baseline: both guarded
        self.assertIs(sp.has_guard_in_closure(cached), True)
        self.assertIs(sp.has_guard_in_closure(literal), True)

        # disable signal (4) only
        with _mock.patch.object(
            sp, "_node_caller_vs_storage_read_compare", lambda node: False
        ):
            self.assertIs(
                sp.has_guard_in_closure(cached),
                False,
                "cached-caller fn did NOT flip True->False when signal (4) was "
                "disabled - signal (4) is dead code (vacuous integration test!)",
            )
            # the literal-msg.sender fn is carried by signal (1), so it must STAY
            # guarded even with signal (4) off (the test really isolates signal 4).
            self.assertIs(
                sp.has_guard_in_closure(literal),
                True,
                "literal-msg.sender fn must stay guarded via signal (1) - the "
                "test would otherwise not be isolating signal (4)",
            )

    def test_h_caller_alias_resolution(self):
        # Unit-level: the function-scope caller-alias resolver picks up a local
        # cached from _msgSender() and rejects a non-caller local.
        sl = _compile(self.FX_SM)
        _, cached = _get_fn(sl, "StorageMappingCallerGuard", "removeValidatorCachedCaller")
        _, noncaller = _get_fn(sl, "StorageMappingCallerGuard", "cachedNonCaller")
        self.assertIn("who", sp._caller_alias_vars(cached))
        self.assertNotIn("who", sp._caller_alias_vars(noncaller))


class StorageMappingCallerGuardUnitTest(unittest.TestCase):
    """Predicate-level unit tests for signal (4) operand classification — these
    do NOT need a live Slither compile (they assert the never-over-credit
    contract on the operand helpers directly via mock IR)."""

    from types import SimpleNamespace as _NS

    def _ref(self, name, origin_cls="StateVariable", origin_name="validators"):
        # A ReferenceVariable whose points_to_origin roots in a StateVariable.
        NS = self._NS
        origin = type(origin_cls, (), {"name": origin_name})()
        return type("ReferenceVariable", (), {"name": name, "points_to_origin": origin})()

    def _local_ref(self, name):
        NS = self._NS
        origin = type("LocalVariable", (), {"name": name, "is_storage": False})()
        return type("ReferenceVariable", (), {"name": name, "points_to_origin": origin})()

    def _caller(self, name="msg.sender"):
        return type("SolidityVariableComposed", (), {"name": name})()

    def test_caller_operand_recognised(self):
        self.assertTrue(sp._ir_operand_is_caller(self._caller("msg.sender")))
        self.assertTrue(sp._ir_operand_is_caller(self._caller("tx.origin")))

    def test_non_caller_operand_rejected(self):
        # a local named "owner" is NOT the caller (conservative).
        self.assertFalse(sp._ir_operand_is_caller(self._local_ref("owner")))

    def test_storage_read_recognised(self):
        self.assertTrue(sp._ir_operand_is_storage_read(self._ref("REF_8")))

    def test_local_ref_not_storage_read(self):
        # a memory/local reference must NOT count as a storage read (never-over-credit).
        self.assertFalse(sp._ir_operand_is_storage_read(self._local_ref("tmp")))

    def test_plain_caller_not_storage_read(self):
        self.assertFalse(sp._ir_operand_is_storage_read(self._caller("msg.sender")))
