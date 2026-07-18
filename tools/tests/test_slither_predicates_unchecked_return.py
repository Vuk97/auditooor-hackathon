#!/usr/bin/env python3
"""Unchecked return-value oracle - Glider gap W6 P1. Regression + mutation pinning
of the predicates added to ``tools/slither_predicates.py``:

  - ``unchecked_return_values``         - flags a transfer / transferFrom / .call /
                                          .send / delegatecall whose boolean success
                                          RETURN value is never consumed by any
                                          downstream IR (no require/assert/if-revert/
                                          return/read). Conservative / never-FP.
  - ``closure_unchecked_return_values`` - own-body + forward closure variant.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
is tested without Slither. Mutation evidence:
``test_mutation_wrap_transfer_in_require_flips_to_clean`` wraps the bare
`token.transfer(...)` in `require(...)` and asserts the suspect flips FLAGGED ->
clean (non-vacuity: the oracle keys on return-value CONSUMPTION, not on the mere
presence of a transfer). Never-false-positive: a require-consumed transfer, a
SafeERC20 wrapper, a `(bool ok,)=x.call(); require(ok);` low-level call, and an
`address.transfer` (no bool return) all yield NO suspect.

This keys on RETURN-value CONSUMPTION and is DISTINCT from cap-3 (taint of INPUTS
to sinks) and cap-8 / W4 (external-call-then-write ORDERING); it does not duplicate
either.
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
    _slither_available(),
    "slither-analyzer not importable; unchecked-return tests need a real compile",
)


def _compile(path):
    from slither import Slither

    return Slither(str(path))


def _all_suspects(sl):
    """Every (contract, function, callee, kind) suspect across the compilation."""
    out = []
    for c in sl.contracts:
        for f in c.functions:
            if not getattr(f, "nodes", None):
                continue
            res = sp.unchecked_return_values(f)
            if sp.is_degraded(res):
                continue
            for r in res:
                out.append((c.name, f.name, r["callee"], r["kind"]))
    return out


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class UncheckedReturnDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_unchecked_return_values_degrades(self):
        self.assertTrue(sp.is_degraded(sp.unchecked_return_values(self._Dummy())))

    def test_closure_unchecked_return_values_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_unchecked_return_values(self._Dummy()))
        )

    def test_exports_present(self):
        self.assertIn("unchecked_return_values", sp.__all__)
        self.assertIn("closure_unchecked_return_values", sp.__all__)


# ─── Semantic path: positive (FLAGGED) ───────────────────────────────────────


@SKIP_NO_SLITHER
class UncheckedReturnPositiveTest(unittest.TestCase):
    def test_bare_transfer_and_transferfrom_flagged(self):
        sl = _compile(FX / "unchecked_transfer_suspect.sol")
        sus = _all_suspects(sl)
        callees = {(fn, callee, kind) for (_c, fn, callee, kind) in sus}
        self.assertIn(("pay", "transfer", "transfer"), callees)
        self.assertIn(("pull", "transferFrom", "transfer"), callees)

    def test_bare_lowlevel_call_and_send_flagged(self):
        sl = _compile(FX / "unchecked_lowlevel_call_suspect.sol")
        sus = _all_suspects(sl)
        callees = {(fn, callee, kind) for (_c, fn, callee, kind) in sus}
        self.assertIn(("forward", "call", "low_level_call"), callees)
        self.assertIn(("send_eth", "send", "low_level_call"), callees)

    def test_record_shape(self):
        sl = _compile(FX / "unchecked_transfer_suspect.sol")
        for c in sl.contracts:
            for f in c.functions:
                if f.name != "pay":
                    continue
                recs = sp.unchecked_return_values(f)
                self.assertTrue(recs and not sp.is_degraded(recs))
                r = recs[0]
                for k in ("contract", "function", "call_line", "callee", "kind",
                          "at_file", "at_line", "severity_hint"):
                    self.assertIn(k, r)
                self.assertEqual(r["severity_hint"], "unchecked-return")
                self.assertEqual(r["kind"], "transfer")
                return
        self.fail("pay() not found")


# ─── Semantic path: negative (NOT FLAGGED, never-FP) ─────────────────────────


@SKIP_NO_SLITHER
class UncheckedReturnNegativeTest(unittest.TestCase):
    def test_require_consumed_transfer_clean(self):
        sl = _compile(FX / "checked_transfer_clean.sol")
        self.assertEqual(_all_suspects(sl), [])

    def test_safe_erc20_wrapper_clean(self):
        # The consumer (SafeErc20Clean.pay) does a LibraryCall to safeTransfer
        # (not a target); the bool transfer lives inside the wrapper where it is
        # consumed by the wrapper's require -> no suspect anywhere.
        sl = _compile(FX / "safe_erc20_clean.sol")
        self.assertEqual(_all_suspects(sl), [])

    def test_lowlevel_checked_clean(self):
        # (bool ok,) = to.call(data); require(ok);  -> consumed via Unpack -> clean.
        sl = _compile(FX / "lowlevel_checked_clean.sol")
        self.assertEqual(_all_suspects(sl), [])


# ─── Mutation non-vacuity ────────────────────────────────────────────────────


@SKIP_NO_SLITHER
class UncheckedReturnMutationTest(unittest.TestCase):
    """Non-vacuity: the base flags exactly one bare transfer; wrapping it in
    `require(...)` (consuming the return) must flip FLAGGED -> clean."""

    def test_base_flags_one_bare_transfer(self):
        sl = _compile(FX / "unchecked_return_mutation_base.sol")
        sus = _all_suspects(sl)
        self.assertEqual(len(sus), 1, f"expected 1 suspect, got {sus}")
        self.assertEqual(sus[0][1:], ("pay", "transfer", "transfer"))

    def test_mutation_wrap_transfer_in_require_flips_to_clean(self):
        base = (FX / "unchecked_return_mutation_base.sol").read_text()
        mutant_src = base.replace(
            "token.transfer(to, amount);",
            'require(token.transfer(to, amount), "transfer failed");',
        )
        self.assertNotEqual(base, mutant_src, "mutation must change the source")
        with tempfile.NamedTemporaryFile(
            "w", suffix=".sol", delete=False
        ) as fh:
            fh.write(mutant_src)
            mutant_path = fh.name
        try:
            sl = _compile(pathlib.Path(mutant_path))
            sus = _all_suspects(sl)
            self.assertEqual(
                sus, [], f"require-wrapped transfer must be CLEAN, got {sus}"
            )
        finally:
            pathlib.Path(mutant_path).unlink(missing_ok=True)


# ─── Closure variant ─────────────────────────────────────────────────────────


@SKIP_NO_SLITHER
class UncheckedReturnClosureTest(unittest.TestCase):
    def test_closure_is_superset_of_own_on_suspect(self):
        sl = _compile(FX / "unchecked_transfer_suspect.sol")
        for c in sl.contracts:
            for f in c.functions:
                if f.name != "pay":
                    continue
                own = sp.unchecked_return_values(f)
                clo = sp.closure_unchecked_return_values(f)
                self.assertFalse(sp.is_degraded(own) or sp.is_degraded(clo))
                # Closure never returns fewer than own (adds reach, not FP).
                self.assertGreaterEqual(len(clo), len(own))
                return
        self.fail("pay() not found")

    def test_closure_clean_stays_clean(self):
        sl = _compile(FX / "checked_transfer_clean.sol")
        for c in sl.contracts:
            for f in c.functions:
                if f.name != "pay":
                    continue
                clo = sp.closure_unchecked_return_values(f)
                self.assertFalse(sp.is_degraded(clo))
                self.assertEqual(clo, [])
                return
        self.fail("pay() not found")


if __name__ == "__main__":
    unittest.main()
