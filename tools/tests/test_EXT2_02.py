#!/usr/bin/env python3
"""EXT2-02 object-graph cross-reference consistency screen - non-vacuous regression.

Pins tools/object-graph-xref-consistency-screen.py: for an entrypoint that
co-passes >=2 RELATED stateful handles (config+state, pool+registry, whitelist+
owner, market+position, parent+child, principal+reserves ...), it enumerates the
co-passed set and flags a MISSING relational assertion = the pairing (that the
handles belong together) is never checked, so a type-valid but FOREIGN second
handle can be substituted (the MoveBit launchpad-whitelist class; corpus
INV-XLANG-GO-0040 `aToken.POOL()==pool`). Every row is advisory verdict=needs-fuzz.

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - a pool/registry entrypoint with NO membership
      binding, and a Go parent/child entrypoint with no back-reference check.
  (2) COVERED / benign NEGATIVE silent  - the SAME entrypoint WITH the relational
      assertion (`registry.contains(pool)`, `child.parent == parent`) does not
      fire; and two UNRELATED handles (token+recipient) are never enumerated.
  (3) NEUTRALIZE the core predicate - monkeypatch `has_pair_binding` to constant
      True (the pairing is "always asserted"); the planted positive must then STOP
      firing. Proves the binding predicate is load-bearing, not decoration.
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_TOOL = ROOT / "tools" / "object-graph-xref-consistency-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext2_02_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


XR = _load()


def _rows(src: str, rel: str = "T.sol"):
    return XR.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# A pool+registry entrypoint. `pool` and `registry` are related (container<->member
# / lexicon pair). The registry is dereferenced but NEVER asserts that `pool`
# belongs to it -> an attacker passes a foreign, well-formed pool -> FIRES.
SOL_POSITIVE = """
contract Router {
    function harvest(IPool pool, IRegistry registry, uint256 amount) external {
        uint256 bal = pool.balanceOf(address(this));
        registry.recordHarvest(pool, amount);   // uses both, but NO membership check
    }
}
"""

# Same entrypoint, but now it asserts the pool is registered in that registry
# (a membership binding) -> the pairing is checked -> SILENT.
SOL_GUARDED = """
contract Router {
    function harvest(IPool pool, IRegistry registry, uint256 amount) external {
        require(registry.contains(pool), "foreign pool");
        uint256 bal = pool.balanceOf(address(this));
        registry.recordHarvest(pool, amount);
    }
}
"""

# Two UNRELATED handle-ish params: a token and a recipient. There is no
# must-move-together invariant between them -> must NOT be enumerated (no FP).
SOL_UNRELATED = """
contract Router {
    function sweep(IERC20 token, address recipient) external {
        token.transfer(recipient, token.balanceOf(address(this)));
    }
}
"""

# Go parent/child: `child` must belong to `parent`. Positive omits the back-ref.
GO_POSITIVE = """
package graph
func (k Keeper) Attach(parent *Vault, child *Strategy) error {
    parent.total += child.assets
    child.linked = true
    return nil
}
"""

# Go parent/child WITH the back-reference assertion -> SILENT.
GO_GUARDED = """
package graph
func (k Keeper) Attach(parent *Vault, child *Strategy) error {
    if child.parent != parent.id {
        return errForeignChild
    }
    parent.total += child.assets
    child.linked = true
    return nil
}
"""

# A shared-identity-field pairing (two coins that must share a denom). Positive
# reads both `.Denom` but never compares them -> FIRES on the shared field.
GO_SHARED_FIELD_POSITIVE = """
package bank
func Pay(principal sdk.Coin, reserves sdk.Coin) error {
    if principal.Denom == "" {
        return errBadDenom
    }
    _ = reserves.Denom
    return nil
}
"""


class TestPositiveFires(unittest.TestCase):
    def test_pool_registry_unchecked_fires(self):
        fired = _fired(_rows(SOL_POSITIVE))
        self.assertTrue(fired, "an unchecked pool/registry pairing must fire")
        pair = {(r["handle_a"]["name"], r["handle_b"]["name"]) for r in fired}
        self.assertTrue(
            ("pool", "registry") in pair or ("registry", "pool") in pair,
            f"expected the pool<->registry pair to fire, got {pair}")

    def test_go_parent_child_unchecked_fires(self):
        fired = _fired(_rows(GO_POSITIVE, rel="graph.go"))
        self.assertTrue(
            any({r["handle_a"]["name"], r["handle_b"]["name"]} == {"parent", "child"}
                for r in fired),
            "an unchecked parent/child pairing must fire")

    def test_shared_field_unchecked_fires(self):
        fired = _fired(_rows(GO_SHARED_FIELD_POSITIVE, rel="bank.go"))
        self.assertTrue(
            any(r["related_via"].startswith("shared-field") or
                r["related_via"] == "lexicon-pair" for r in fired),
            "two coins sharing a denom field with no equality check must fire")


class TestCoveredNegativeSilent(unittest.TestCase):
    def test_membership_binding_silences(self):
        rows = _rows(SOL_GUARDED)
        self.assertTrue(rows, "the pair must still be enumerated as a point")
        self.assertFalse(_fired(rows),
                         "registry.contains(pool) binds the pair -> SILENT")
        self.assertTrue(all(r["has_pair_binding"] for r in rows))

    def test_go_backref_binding_silences(self):
        self.assertFalse(_fired(_rows(GO_GUARDED, rel="graph.go")),
                         "child.parent == parent.id binds the pair -> SILENT")


class TestUnrelatedNotEnumerated(unittest.TestCase):
    def test_token_recipient_not_a_pairing(self):
        rows = _rows(SOL_UNRELATED)
        self.assertEqual(
            rows, [],
            "unrelated handles (token, recipient) are not a must-move-together "
            "set and must not be enumerated (no FP)")


class TestNeutralizeCorePredicate(unittest.TestCase):
    """Neutralizing the core binding predicate (pretend the pairing is ALWAYS
    asserted) makes the planted positive STOP firing -> the predicate is
    load-bearing (build-spec leg 3)."""

    def test_binding_always_true_kills_the_finding(self):
        orig = XR.has_pair_binding
        try:
            XR.has_pair_binding = lambda *a, **k: True
            self.assertFalse(
                _fired(_rows(SOL_POSITIVE)),
                "with the binding predicate neutralized (always asserted) the "
                "unchecked-pairing finding must vanish - proves it is load-bearing")
            self.assertFalse(_fired(_rows(GO_POSITIVE, rel="graph.go")))
        finally:
            XR.has_pair_binding = orig

    def test_predicate_restored_fires_again(self):
        self.assertTrue(_fired(_rows(SOL_POSITIVE)),
                        "after restore the positive fires again (no leak)")


class TestAdvisoryContract(unittest.TestCase):
    def test_every_row_advisory_needs_fuzz(self):
        for r in _rows(SOL_POSITIVE):
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertTrue(r["advisory"])
            self.assertFalse(r["auto_credit"])
            self.assertEqual(r["capability"], "EXT2_02")
            for k in ("file", "line", "function", "handle_a", "handle_b",
                      "related_via", "co_passed_handles"):
                self.assertIn(k, r)


class TestMutationVerifyShape(unittest.TestCase):
    """The mutation-verify shape proven on real fleet code (nuva
    interest.go::CalculateExpiration), pinned as an in-repo fixture: a real
    cross-handle relational assertion, when WEAKENED to a single-handle predicate,
    flips SILENT -> FIRE; the sibling with its own guard stays SILENT."""

    ORIGINAL = """
package interest
func CalculateExpiration(principal sdk.Coin, vaultReserves sdk.Coin) error {
    if principal.Denom != vaultReserves.Denom {
        return errDenomMismatch
    }
    if principal.IsZero() {
        return nil
    }
    return nil
}
func CalculatePeriods(vaultReserves sdk.Coin, principal sdk.Coin) error {
    if vaultReserves.Denom != principal.Denom {
        return errDenomMismatch
    }
    return nil
}
"""
    # BEHAVIOR-CHANGING weakening: the cross-handle `principal.Denom !=
    # vaultReserves.Denom` becomes a single-handle non-empty check. vaultReserves
    # stays dereferenced but the pairing is gone -> mismatched denoms pass.
    MUTANT = ORIGINAL.replace(
        "    if principal.Denom != vaultReserves.Denom {\n"
        "        return errDenomMismatch\n"
        "    }\n"
        "    if principal.IsZero() {",
        "    if vaultReserves.Denom == \"\" {\n"
        "        return errBadDenom\n"
        "    }\n"
        "    if principal.IsZero() {",
    )

    def test_original_silent_mutant_fires(self):
        orig = _rows(self.ORIGINAL, rel="interest.go")
        ce_o = [r for r in orig if r["function"] == "CalculateExpiration"]
        self.assertTrue(ce_o, "CalculateExpiration must be enumerated")
        self.assertFalse(any(r["fires"] for r in ce_o),
                         "ORIGINAL: cross-handle denom assertion present -> SILENT")

        mut = _rows(self.MUTANT, rel="interest.go")
        ce_m = [r for r in mut if r["function"] == "CalculateExpiration"]
        self.assertTrue(any(r["fires"] for r in ce_m),
                        "MUTANT: weakened to single-handle check -> FIRES")

    def test_sibling_guard_stays_silent(self):
        mut = _rows(self.MUTANT, rel="interest.go")
        cp = [r for r in mut if r["function"] == "CalculatePeriods"]
        self.assertTrue(cp)
        self.assertFalse(any(r["fires"] for r in cp),
                         "the sibling with its own denom guard stays SILENT "
                         "(the fire is specific to the weakened function)")


class TestGeneratedFileExclusion(unittest.TestCase):
    """The walk reuses tools/lib/synthetic_target_exclusion.py + declared-control
    _is_generated_source: machine-generated (.pulsar.go / `Code generated ... DO
    NOT EDIT`), test, and chimera scaffolding must never enter the corpus."""

    def _tmp(self):
        import tempfile
        return pathlib.Path(tempfile.mkdtemp())

    def test_iter_skips_codegen_and_tests_keeps_handwritten(self):
        d = self._tmp()
        (d / "vault.pulsar.go").write_text("package v\nfunc F(a *Pool, b *Registry){}\n")
        (d / "gen.go").write_text(
            "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage v\n")
        (d / "keeper_test.go").write_text("package v\nfunc F(a *Pool, b *Registry){}\n")
        (d / "keeper.go").write_text("package v\nfunc Do(a *Pool, b *Registry){}\n")
        names = {p.name for p in XR._iter_source_files(d)}
        self.assertIn("keeper.go", names)
        self.assertNotIn("vault.pulsar.go", names)
        self.assertNotIn("gen.go", names)
        self.assertNotIn("keeper_test.go", names)


if __name__ == "__main__":
    unittest.main()
