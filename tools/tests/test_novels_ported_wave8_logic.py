"""
tools/tests/test_novels_ported_wave8_logic.py

LANE port-top-novels guard tests. Proves the 5 CRITICAL Novel:YES records ported
this wave are:

  1. WIRED - each new GINV-* id is present in the SHARED goal-invariant template
     registry (load_goal_templates()), under the intended impact_id.
  2. NON-VACUOUS - every role of each template BINDS against a genuine source body
     that reproduces the exploit shape (is-usable), using the REAL resolver
     gis._resolve_role (the same code path the synthesizer runs).
  3. NEVER-FALSE-PASS - a pure-math helper (none of the machinery) leaves at least
     one role of every template UNBOUND, so the template is never credited on
     unrelated code.
  4. DRAINED - the owned drain ledger reports the DETECTOR-class unported count
     falling by exactly 5 (41 -> 36).

GUARD-RAIL note: the templates encode the exploit LOGIC as a GOAL RELATION
(goal_statement + relational_form); the binds are conservative multi-token
machinery anchors, NOT a same-body detector regex.
"""
from __future__ import annotations

import importlib.util as _ilu
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_LIB = _REPO_ROOT / "tools" / "lib" / "goal_invariant_synth.py"
_DRAIN = _REPO_ROOT / "tools" / "novels-ported-drain.py"


def _load(name: str, path: Path):
    spec = _ilu.spec_from_file_location(name, str(path))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


gis = _load("goal_invariant_synth", _LIB)
drain = _load("novels_ported_drain", _DRAIN)


# (impact_id, template_id, function_name, genuine_body, auth_sig_tail). Each
# genuine body reproduces the exploit shape from the cited novel and must bind
# ALL roles of the template through the REAL resolver.
_CASES = [
    (
        "direct-theft-funds",
        "GINV-privileged-transferFrom-uses-caller-not-arbitrary-from",
        "vestingDeposit",
        # NOVELS_UNPORTED #44: admin fn pulls from a caller-supplied `from`.
        # The guard is a signature modifier (onlyRole), passed via auth_sig_tail.
        """{
            token.safeTransferFrom(from, address(this), amount);
        }""",
        "onlyRole(ADMIN_ROLE)",
    ),
    (
        "reentrancy",
        "GINV-flashloan-callback-binds-initiator-to-self",
        "executeOperation",
        # NOVELS_UNPORTED #20: callback checks the pool but not initiator==this.
        """{
            require(msg.sender == address(POOL), "!pool");
            IERC20(asset).approve(spender, amount);
            return true;
        }""",
        "",
    ),
    (
        "share-supply-inflation",
        "GINV-totalAssets-nets-pending-withdraw-queue",
        "totalAssets",
        # NOVELS_UNPORTED #23: totalAssets adds an unremoved pending-withdraw map.
        """{
            uint256 sum = asset.balanceOf(address(this));
            for (uint i; i < withdrawKeys.length; i++) {
                sum += pendingWithdraw[withdrawKeys[i]].assets;
            }
            return sum;
        }""",
        "",
    ),
    (
        "access-control-bypass",
        "GINV-admin-role-not-role-admin-of-operational-role",
        "initialize",
        # NOVELS_UNPORTED #34: initializer grants DEFAULT_ADMIN_ROLE + OPERATOR_ROLE.
        """{
            _grantRole(DEFAULT_ADMIN_ROLE, owner);
            _grantRole(OPERATOR_ROLE, keeper);
        }""",
        "",
    ),
    (
        "liquidation-abuse",
        "GINV-liquidation-clears-all-coupled-position-fields",
        "liquidate",
        # NOVELS_UNPORTED #5: liquidation zeroes amount, leaves frozenCollateral.
        """{
            require(isLiquidatable(id));
            positions[id].amount = 0;
            if (positions[id].frozenCollateral > 0) { revert(); }
        }""",
        "",
    ),
]

_PURE_MATH_BODY = """{
    uint256 r = a + b;
    return r * c;
}"""


def _template_for(impact_id: str, template_id: str):
    tmpl = gis.load_goal_templates()
    for t in tmpl.get(impact_id, []):
        if str(t.get("id")) == template_id:
            return t
    return None


def _bind_roles(template, *, function_name: str, body: str, auth_sig_tail: str = ""):
    """Run the REAL resolver over each role; return (bound, unbound) role lists."""
    bound, unbound = [], []
    for b in template.get("binds") or []:
        role = str((b or {}).get("role") or "").strip()
        if not role:
            continue
        match_any = [p for p in (b.get("match_any") or []) if isinstance(p, str)]
        match_in = str(b.get("match_in") or "body")
        tok = gis._resolve_role(
            role,
            function_name=function_name,
            function_signature=f"{function_name}()",
            source_body=body,
            auth_sig_tail=auth_sig_tail,
            match_any=match_any,
            match_in=match_in,
        )
        (bound if tok else unbound).append(role)
    return bound, unbound


class TestWave8LogicNovels(unittest.TestCase):
    def test_templates_wired_into_shared_registry(self):
        for impact_id, tid, _fn, _body, _auth in _CASES:
            with self.subTest(tid=tid):
                self.assertIsNotNone(
                    _template_for(impact_id, tid),
                    f"{tid} not found under {impact_id} in load_goal_templates()",
                )

    def test_all_roles_bind_on_genuine_body(self):
        for impact_id, tid, fn, body, auth in _CASES:
            with self.subTest(tid=tid):
                t = _template_for(impact_id, tid)
                self.assertIsNotNone(t)
                self.assertTrue(t.get("binds"), f"{tid} has no binds")
                bound, unbound = _bind_roles(
                    t, function_name=fn, body=body, auth_sig_tail=auth
                )
                self.assertEqual(
                    unbound, [], f"{tid} left roles UNBOUND on genuine body: {unbound}"
                )
                self.assertGreaterEqual(len(bound), 2)

    def test_never_false_pass_on_pure_math(self):
        for impact_id, tid, _fn, _body, _auth in _CASES:
            with self.subTest(tid=tid):
                t = _template_for(impact_id, tid)
                _bound, unbound = _bind_roles(
                    t, function_name="pureMath", body=_PURE_MATH_BODY
                )
                self.assertTrue(
                    unbound,
                    f"{tid} bound ALL roles on pure-math body (false-pass risk)",
                )

    def test_goal_statement_is_a_relation_not_a_regex(self):
        # Every ported template must carry a relational_form and a goal_statement
        # that states a RELATION (contains 'implies'/'==' style relational word),
        # proving the LOGIC lives in the query, not the binds.
        rel_vocab = ("implies", "==", "<=", ">=", "never", "must")
        for impact_id, tid, _fn, _b, _a in _CASES:
            with self.subTest(tid=tid):
                t = _template_for(impact_id, tid)
                self.assertIn(
                    str(t.get("relational_form")),
                    {"implies", "eq", "le", "ge", "ordering", "reachability", "delta"},
                )
                gs = str(t.get("goal_statement") or "").lower()
                self.assertTrue(
                    any(w in gs for w in rel_vocab),
                    f"{tid} goal_statement is not phrased as a relation",
                )

    def test_drain_dropped_by_five(self):
        report = drain.compute_drain(drain.load_ledger())
        self.assertEqual(report["detector_universe"], 46)
        self.assertEqual(report["unported_before"], 41)
        self.assertEqual(report["unported_after"], 36)
        self.assertEqual(report["drop"], 5)
        self.assertEqual(report["ported_this_lane"], 5)


if __name__ == "__main__":
    unittest.main()
