#!/usr/bin/env python3
"""Non-vacuous tests for tools/js-oscript-value-moving-surface.py (capability C1).

NON-VACUITY CONTRACT (the three legs required of every capability test):
  1. PLANTED POSITIVE fires  - an unguarded JS/Oscript value-move is reported.
  2. GUARDED NEGATIVE silent  - the same move with a validation/authorization
     guard before it is NOT reported.
  3. NEUTRALIZING the core predicate makes the positive FAIL - if guard-dominance
     is forced always-true (the invariant can never be violated), the planted
     positive stops firing. This proves the test exercises the real predicate,
     not an incidental code path.

Plus a MUTATION-VERIFY leg that mirrors the real-fleet check: a guarded unit is
silent; removing its guard (weakening the enforcement) makes it fire. A second,
optional leg runs the SAME mutation on the real obyte fleet source when present
(read-only; the mutation lives only on an in-memory copy).

ZERO committed-workspace literals in the hermetic tests: synthetic sources +
tmp dirs throughout. The optional fleet leg is skipUnless-gated on the path.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "js-oscript-value-moving-surface.py"


def _load():
    spec = importlib.util.spec_from_file_location("c1_value_moving_surface", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["c1_value_moving_surface"] = mod
    spec.loader.exec_module(mod)
    return mod


c1 = _load()

# ---------------------------------------------------------------------------
# Synthetic sources.
# ---------------------------------------------------------------------------
# An UNGUARDED value-mover: sends a payment with no validation/authorization
# before the send. -> must FIRE.
_JS_UNGUARDED = """
var dag = require('./dag.js');
function payout(params){
    var out = params.to_address;
    var amount = params.amount;
    dag.sendPayment({ to_address: out, amount: amount });
}
"""

# A GUARDED value-mover: the SAME send, but a validation guard dominates it.
# -> must stay SILENT.
_JS_GUARDED = """
var dag = require('./dag.js');
var ValidationUtils = require('./validation_utils.js');
function payout(params){
    if (!ValidationUtils.isValidAddress(params.to_address))
        throw Error('bad address');
    dag.sendPayment({ to_address: params.to_address, amount: params.amount });
}
"""

# A NON-value-moving JS unit: no sink at all. -> never in surface, never fires.
_JS_INERT = """
function formatName(x){
    return String(x).trim().toLowerCase();
}
"""

# Ledger-write discrimination: compound credit (+=) is a value-move; a plain
# map-build assignment from a DB read is NOT (this is the FP-tightening).
_JS_LEDGER_COMPOUND = """
function credit(rows){
    balances[addr] += spent;
}
"""
_JS_LEDGER_PLAIN_MAPBUILD = """
function loadBalances(rows){
    rows.forEach(function(row){ balances[row.address] = row.balance; });
    return balances;
}
"""

# Oscript: an unguarded payment message vs one with a bounce/require guard.
_OSCRIPT_UNGUARDED = """
{
    messages: [
        { app: 'payment', payload: { outputs: [{address: trigger.address, amount: 1000}] } }
    ]
}
"""
_OSCRIPT_GUARDED = """
{
    messages: [
        { if: "{trigger.data.ok}", app: 'payment', payload: { outputs: [{address: trigger.address, amount: 1000}] } }
    ]
}
"""


class CorePredicateTest(unittest.TestCase):
    def test_planted_positive_fires(self):
        self.assertIsNotNone(
            c1.unguarded_value_move(_JS_UNGUARDED, "js"),
            "unguarded sendPayment must be reported",
        )

    def test_guarded_negative_silent(self):
        self.assertIsNone(
            c1.unguarded_value_move(_JS_GUARDED, "js"),
            "a ValidationUtils/throw guard before the send must silence it",
        )

    def test_inert_unit_not_value_moving(self):
        self.assertIsNone(c1.unguarded_value_move(_JS_INERT, "js"))

    def test_neutralizing_core_predicate_kills_positive(self):
        """Force guard-dominance to always hold -> the planted positive must
        STOP firing. This is the non-vacuity lever."""
        orig = c1._first_guard_offset
        try:
            c1._first_guard_offset = lambda body, guard_re, before: 0  # always "guarded"
            self.assertIsNone(
                c1.unguarded_value_move(_JS_UNGUARDED, "js"),
                "with guard-dominance forced true the positive must not fire",
            )
        finally:
            c1._first_guard_offset = orig
        # And it fires again once the real predicate is restored.
        self.assertIsNotNone(c1.unguarded_value_move(_JS_UNGUARDED, "js"))


class MutationVerifyStyleTest(unittest.TestCase):
    """Guarded unit is silent; removing the guard (weakening the enforcement)
    makes it fire - the mutation-verify shape, hermetic edition."""

    def test_guard_removal_flips_silent_to_fire(self):
        self.assertIsNone(c1.unguarded_value_move(_JS_GUARDED, "js"))
        # Remove the guard lines only; the value-move is untouched.
        mutated = "\n".join(
            ln for ln in _JS_GUARDED.splitlines()
            if "ValidationUtils" not in ln and "throw Error" not in ln
        )
        self.assertIsNotNone(
            c1.unguarded_value_move(mutated, "js"),
            "guard-weakened copy must fire",
        )


class LedgerDiscriminationTest(unittest.TestCase):
    def test_compound_credit_is_value_move(self):
        self.assertIsNotNone(c1.unguarded_value_move(_JS_LEDGER_COMPOUND, "js"))

    def test_plain_mapbuild_is_not_value_move(self):
        # A plain `balances[k] = row.balance` map-build must NOT be a sink
        # (else the screen floods with read-map false positives).
        self.assertIsNone(c1.unguarded_value_move(_JS_LEDGER_PLAIN_MAPBUILD, "js"))


# ---------------------------------------------------------------------------
# FP-fix regression: extended guard vocabulary + delegation/recursion suppress.
# ---------------------------------------------------------------------------
# Bare-if gate (no throw/require): an ``if (`` before the move is a precondition
# branch -> SILENT.
_JS_IF_GUARDED = """
function payout(p){
    if (!p.to_address) return;
    payToAddress(p.to_address, p.amount);
}
"""
# Ternary gate before the move -> SILENT.
_JS_TERNARY_GUARDED = """
function payout(p){
    var n = p.send_all ? 0 : p.amount;
    payToAddress(p.to_address, n);
}
"""
# Obyte error-callback return-guard (`return <expr>.ifNotEnoughFunds(`) -> SILENT.
_JS_IFERROR_RETURN_GUARDED = """
function payout(callbacks, p){
    return callbacks.ifNotEnoughFunds("insufficient");
    payToAddress(p.to_address, p.amount);
}
"""


class ExtendedGuardVocabularyTest(unittest.TestCase):
    def test_bare_if_guard_silences(self):
        self.assertIsNone(c1.unguarded_value_move(_JS_IF_GUARDED, "js"))

    def test_ternary_guard_silences(self):
        self.assertIsNone(c1.unguarded_value_move(_JS_TERNARY_GUARDED, "js"))

    def test_iferror_return_guard_silences(self):
        self.assertIsNone(c1.unguarded_value_move(_JS_IFERROR_RETURN_GUARDED, "js"))

    def test_optional_chaining_is_not_a_ternary_guard(self):
        # ``?.`` / ``??`` must NOT be mistaken for a ternary guard -> still fires.
        body = "function pay(p){ var x = p?.meta ?? 0; payToAddress(p.to, p.amount); }"
        self.assertIsNotNone(c1.unguarded_value_move(body, "js"))


# A guarded inner mover + a pure delegating wrapper forwarding into it (the
# composeAndSave* / composePaymentJoint obyte shape). File-level: wrapper must
# be SUPPRESSED, inner is silent (guarded) -> zero findings.
# The inner is named with a real sink verb (``compose...PaymentJoint``) so the
# wrapper's forwarding call is itself recognised as a value-move sink - exactly
# the obyte composeAndSave* -> compose* shape.
_JS_DELEGATION_SAFE = """
function composeDivisibleAssetPaymentJoint(p){
    if (!p.to) return;
    payToAddress(p.to, p.amount);
}
function composeAndSaveDivisibleAssetPaymentJoint(p){
    composeDivisibleAssetPaymentJoint(withSave(p));
}
"""
# Recursive self-call whose sole sink IS the self-call (composeJoint->composeJoint
# shape) -> SUPPRESSED (enforcement lives at the guarded base of the recursion).
_JS_RECURSIVE = """
function sendAllBytes(p){
    sendAllBytes(clone(p));
}
"""
# Delegation into an UNGUARDED inner mover: NOT suppressed - both fire. Proves
# the suppression is targeted (only folds wrappers of a guarded/safe callee).
_JS_DELEGATION_UNGUARDED_INNER = """
function composeJoint(p){
    payToAddress(p.to, p.amount);
}
function wrap(p){
    composeJoint(p);
}
"""


class DelegationRecursionSuppressionTest(unittest.TestCase):
    def test_delegating_wrapper_to_guarded_inner_suppressed(self):
        surface, findings, exempt = c1.screen_file("src/compose.js", _JS_DELEGATION_SAFE)
        self.assertIsNone(exempt)
        self.assertEqual(len(surface), 2, "both movers are on the census")
        self.assertEqual(findings, [], "guarded inner + delegating wrapper -> silent")

    def test_recursive_self_call_suppressed(self):
        surface, findings, exempt = c1.screen_file("src/rec.js", _JS_RECURSIVE)
        self.assertEqual(findings, [], "same-named recursive self-call -> silent")

    def test_delegation_to_unguarded_inner_still_fires(self):
        # Non-vacuity at file level: if the inner mover is genuinely unguarded,
        # suppression must NOT hide it (or its wrapper).
        surface, findings, exempt = c1.screen_file(
            "src/leaky.js", _JS_DELEGATION_UNGUARDED_INNER
        )
        fired = {f["unit"] for f in findings}
        self.assertIn("composeJoint", fired)
        self.assertIn("wrap", fired)

    def test_unguarded_leaf_primitive_still_fires(self):
        # A real payment primitive (not an in-file delegation) with no guard
        # must still fire - the suppression only folds in-file wrappers.
        body = "function drain(p){ var t = p.to; payToAddress(t, p.amount); }"
        surface, findings, exempt = c1.screen_file("src/evil.js", body)
        self.assertEqual({f["unit"] for f in findings}, {"drain"})


# Fleet FP regression: the four real obyte green files must produce ZERO
# findings (they were the fleet false-positives this fix targets).
_FLEET_DIR = Path("/Users/wolf/audits/obyte/src/ocore")
_FLEET_FP_FILES = ["composer.js", "divisible_asset.js", "indivisible_asset.js", "wallet.js"]


class RealFleetNoFalsePositiveTest(unittest.TestCase):
    @unittest.skipUnless(_FLEET_DIR.is_dir(), "obyte fleet source not present")
    def test_named_fp_files_are_clean(self):
        for fn in _FLEET_FP_FILES:
            p = _FLEET_DIR / fn
            if not p.is_file():
                continue
            _surface, findings, _exempt = c1.screen_file(
                "src/ocore/" + fn, p.read_text(errors="replace")
            )
            self.assertEqual(
                findings, [],
                f"{fn} is real green obyte JS and must report no FP; got "
                f"{[x['unit'] for x in findings]}",
            )


class OscriptTest(unittest.TestCase):
    def test_unguarded_payment_fires(self):
        self.assertIsNotNone(c1.unguarded_value_move(_OSCRIPT_UNGUARDED, "oscript"))

    def test_guarded_payment_silent(self):
        self.assertIsNone(c1.unguarded_value_move(_OSCRIPT_GUARDED, "oscript"))


class FileLevelExemptionTest(unittest.TestCase):
    def test_config_file_exempted(self):
        # A *.config.js file is non-value-moving infra -> exempt, no surface.
        surface, findings, exempt = c1.screen_file(
            "pkg/webpack.config.js", "module.exports = { entry: './x' };"
        )
        self.assertEqual(surface, [])
        self.assertEqual(findings, [])
        self.assertIsNotNone(exempt)

    def test_non_js_oscript_is_not_applicable(self):
        surface, findings, exempt = c1.screen_file(
            "src/Vault.sol", "function f() public { token.transfer(a, b); }"
        )
        self.assertEqual((surface, findings, exempt), ([], [], None))

    def test_value_moving_file_kept_and_screened(self):
        surface, findings, exempt = c1.screen_file("src/wallet.js", _JS_UNGUARDED)
        self.assertIsNone(exempt)
        self.assertEqual(len(surface), 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["verdict"], "needs-fuzz")


class ReportShapeAndAdvisoryTest(unittest.TestCase):
    def test_enumerate_and_rc0(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "pay.js").write_text(_JS_UNGUARDED, encoding="utf-8")
            (ws / "src" / "safe.js").write_text(_JS_GUARDED, encoding="utf-8")
            (ws / "src" / "util.js").write_text(_JS_INERT, encoding="utf-8")
            out = ws / "report.json"
            rc = c1._main([str(ws), "--out", str(out)])
            self.assertEqual(rc, 0, "advisory screen must always exit rc=0")
            rep = json.loads(out.read_text())
            self.assertTrue(rep["advisory"])
            self.assertEqual(rep["verdict"], "needs-fuzz")
            fired = {f["unit"] for f in rep["findings"]}
            self.assertIn("payout", fired)
            # safe.js payout is guarded -> exactly one firing overall.
            self.assertEqual(rep["fire_count"], 1)
            self.assertGreaterEqual(rep["surface_count"], 2)

    def test_no_findings_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "safe.js").write_text(_JS_GUARDED, encoding="utf-8")
            rep = c1.enumerate_surface(ws)
            self.assertEqual(rep["verdict"], "no-findings")
            self.assertEqual(rep["fire_count"], 0)


# ---------------------------------------------------------------------------
# OPTIONAL: mutation-verify on the REAL obyte fleet source (read-only). The
# mutation exists only on an in-memory copy; the file on disk is never touched.
# ---------------------------------------------------------------------------
_FLEET = Path("/Users/wolf/audits/obyte/src/ocore/divisible_asset.js")


class RealFleetMutationVerifyTest(unittest.TestCase):
    @unittest.skipUnless(_FLEET.is_file(), "obyte fleet source not present")
    def test_real_guarded_fn_silent_then_fires_on_guard_removal(self):
        src = _FLEET.read_text(errors="replace")
        body = dict(c1.js_units(src)).get("composeDivisibleAssetPaymentJoint")
        self.assertIsNotNone(body, "target fn must be extractable")
        # Guarded in production -> SILENT.
        self.assertIsNone(
            c1.unguarded_value_move(body, "js"),
            "real guarded composeDivisibleAssetPaymentJoint must be silent",
        )
        # Weaken the enforcement on an in-memory copy: strip EVERY guard-bearing
        # line (throw / ValidationUtils / bare-if / ternary / assert / ...) that
        # precedes the value-move. The sink line itself carries no guard token,
        # so removing all guards leaves a genuinely-unguarded move -> FIRES.
        mutated = "\n".join(
            ln for ln in body.splitlines()
            if c1._JS_GUARD_RE.search(ln) is None
        )
        self.assertIsNotNone(
            c1.unguarded_value_move(mutated, "js"),
            "guard-stripped copy must fire",
        )


if __name__ == "__main__":
    unittest.main()
