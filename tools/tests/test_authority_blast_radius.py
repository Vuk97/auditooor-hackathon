#!/usr/bin/env python3
"""A3 authority-blast-radius - non-vacuous regression.

Pins tools/authority-blast-radius.py: it consumes acl-matrix's role_uses /
role_grants / priv_writes and flags (a) BLAST-RADIUS (one role over >1 impact
class) and (b) PRIVILEGE-INVERSION (a lower-privilege role grants a more
powerful role). Every emitted row is verdict="needs-fuzz".

Honesty (R80): the end-to-end cases require a real Slither compile of the
in-tree fixture; if Slither is not importable they SKIP (no faked pass). The
pure-predicate cases run WITHOUT Slither.

Non-vacuity: mutating the impact-span predicate (`len(union) > 1` -> `> 0`) or
the inversion predicate (`grank < power` -> `grank <= power`) breaks a case:
  - FEE_ROLE spans one impact -> `> 0` would flag it (asserted NOT flagged).
  - MANAGER_ROLE grants ORACLE_ROLE at EQUAL power -> `<=` would flag it
    (asserted NOT flagged); OPERATOR_ROLE at strictly-lower power IS flagged.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "authority_blast_radius" / "Vault.sol"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "authority_blast_radius_t", TOOLS / "authority-blast-radius.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


A3 = _load_tool()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401
        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; end-to-end A3 cases need a real compile")


class TestPredicateUnits(unittest.TestCase):
    """Pure predicate logic - no Slither needed."""

    def test_classify_impacts_multi_and_single(self):
        self.assertEqual(A3.classify_impacts({"fn": "pauseVault"}), {"pause"})
        self.assertEqual(A3.classify_impacts({"fn": "setProtocolFee"}), {"fee"})
        self.assertIn("fund-movement",
                      A3.classify_impacts({"fn": "withdrawTo"}))
        self.assertEqual(A3.classify_impacts({"fn": "noop"}), set())

    def test_name_rank_ordering(self):
        self.assertEqual(A3._name_rank("DEFAULT_ADMIN_ROLE"), 3)
        self.assertEqual(A3._name_rank("MANAGER_ROLE"), 2)
        self.assertEqual(A3._name_rank("OPERATOR_ROLE"), 1)

    def test_role_power_uses_impact_severity(self):
        # a plainly-named role that guards a fund sink confers power 3
        self.assertEqual(A3._role_power("POWERFUL_ROLE", {"fund-movement"}), 3)
        self.assertEqual(A3._role_power("ORACLE_ROLE", {"oracle"}), 2)

    def test_inversion_is_strict(self):
        # equal privilege must NOT be an inversion (strict `<`)
        self.assertFalse(A3._name_rank("MANAGER_ROLE")
                         < A3._role_power("ORACLE_ROLE", {"oracle"}))
        self.assertTrue(A3._name_rank("OPERATOR_ROLE")
                        < A3._role_power("POWERFUL_ROLE", {"fund-movement"}))


class TestStrictContract(unittest.TestCase):
    """Strict closure must be exact and must not depend on Slither fixtures."""

    def _fake_acl(self):
        rows = [
            {"contract": "Vault", "fn": "pauseVault",
             "roles_via_mods": ["BROAD_ROLE"], "roles_via_requires": [],
             "writes_to": ["paused"], "priv_writes": ["paused"]},
            {"contract": "Vault", "fn": "withdrawEmergency",
             "roles_via_mods": ["BROAD_ROLE"], "roles_via_requires": [],
             "writes_to": ["balance"], "priv_writes": ["balance"]},
        ]

        class FakeACL:
            @staticmethod
            def _analyze(_ws):
                return (rows, [], [], defaultdict(list),
                        {"BROAD_ROLE": [("Vault", "pauseVault"),
                                         ("Vault", "withdrawEmergency")]})
        return FakeACL()

    def test_strict_open_hypothesis_cannot_report_success(self):
        old_prereqs = A3._strict_prerequisites
        old_index = A3._index_functions
        try:
            A3._strict_prerequisites = lambda _pred: []
            A3._index_functions = lambda _ws, needed, _pred: {
                key: (True, "src/Vault.sol:1") for key in needed}
            hyps, acc = A3.analyze(pathlib.Path("/tmp/a3-strict-test"),
                                   self._fake_acl(), object(), strict=True)
            self.assertEqual(len(hyps), 1)
            self.assertFalse(acc["strict_ok"])
            self.assertIn("unresolved-applicable-hypotheses",
                          acc["strict_blockers"])

            sid = hyps[0]["stable_id"]
            self.assertEqual(sid, hyps[0]["hypothesis_id"])
            _hyps, closed = A3.analyze(
                pathlib.Path("/tmp/a3-strict-test"), self._fake_acl(), object(),
                strict=True, dispositions={sid: "not-applicable"})
            self.assertTrue(closed["strict_ok"])
            self.assertEqual(closed["dispositioned_hypotheses"], [sid])
        finally:
            A3._strict_prerequisites = old_prereqs
            A3._index_functions = old_index

    def test_disposition_requires_exact_stable_id_and_terminal_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = pathlib.Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "authority_blast_radius_dispositions.jsonl").write_text(
                json.dumps({"role": "BROAD_ROLE", "disposition": "resolved"})
                + "\n" + json.dumps({"stable_id": "A3-missing",
                                        "disposition": "needs-fuzz"}) + "\n")
            valid, invalid = A3.load_typed_dispositions(ws)
            self.assertEqual(valid, {})
            self.assertEqual(len(invalid), 2)

    def test_strict_empty_acl_materialization_is_degraded(self):
        class EmptyACL:
            @staticmethod
            def _analyze(_ws):
                return ([], [], [], {}, {})

        old_prereqs = A3._strict_prerequisites
        try:
            A3._strict_prerequisites = lambda _pred: []
            _hyps, acc = A3.analyze(pathlib.Path("/tmp/a3-empty"),
                                    EmptyACL(), object(), strict=True)
            self.assertFalse(acc["strict_ok"])
            self.assertIn("degraded-acl-no-roles", acc["strict_blockers"])
        finally:
            A3._strict_prerequisites = old_prereqs


@SKIP_NO_SLITHER
class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="a3_"))
        (cls.tmp / "src").mkdir(parents=True, exist_ok=True)
        shutil.copy(FX, cls.tmp / "src" / "Vault.sol")
        acl = A3._load_acl()
        pred = A3._load_predicates()
        cls.hyps, cls.acc = A3.analyze(cls.tmp, acl, pred)
        cls.by_role = {}
        for h in cls.hyps:
            cls.by_role.setdefault((h["flag_kind"], h["role"]), h)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_all_needs_fuzz(self):
        self.assertTrue(self.hyps, "expected at least one hypothesis")
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_blast_radius_flags_broad_role_over_two_impacts(self):
        h = self.by_role.get(("blast-radius", "BROAD_ROLE"))
        self.assertIsNotNone(h, "BROAD_ROLE (pause+fund) must be blast-radius")
        self.assertIn("pause", h["distinct_impact_classes"])
        self.assertIn("fund-movement", h["distinct_impact_classes"])
        self.assertGreater(len(h["distinct_impact_classes"]), 1)

    def test_single_impact_role_not_flagged(self):
        # FEE_ROLE guards two fee setters == one impact class -> NOT blast
        self.assertIsNone(self.by_role.get(("blast-radius", "FEE_ROLE")))
        self.assertIsNone(self.by_role.get(("blast-radius", "CONFIG_ROLE")))
        self.assertIsNone(self.by_role.get(("blast-radius", "ORACLE_ROLE")))

    def test_privilege_inversion_weak_grants_strong(self):
        h = self.by_role.get(("privilege-inversion", "POWERFUL_ROLE"))
        self.assertIsNotNone(h, "OPERATOR granting POWERFUL must invert")
        self.assertEqual(h["grant_guard_role"], "OPERATOR_ROLE")
        self.assertLess(h["grant_guard_rank"], h["granted_power_rank"])

    def test_admin_grant_and_equal_power_grant_not_flagged(self):
        # DEFAULT_ADMIN grants CONFIG (higher guard) -> no inversion
        self.assertIsNone(
            self.by_role.get(("privilege-inversion", "CONFIG_ROLE")))
        # MANAGER (rank 2) grants ORACLE (power 2) -> EQUAL -> no inversion
        self.assertIsNone(
            self.by_role.get(("privilege-inversion", "ORACLE_ROLE")))

    def test_guard_present_confirmed_via_closure(self):
        h = self.by_role.get(("blast-radius", "BROAD_ROLE"))
        self.assertTrue(h["guard_present_confirmed"])

    def test_ownership_transfer_excluded_no_lido_style_fp(self):
        # OWNER_ROLE guards transferOwnership (ownership handover, DEFERRED to
        # two-step-ownership) + setImplementation (owner-implementation). After
        # the exclusion the role spans only owner-implementation -> NO flag.
        self.assertIsNone(self.by_role.get(("blast-radius", "OWNER_ROLE")))

    def test_disabling_ownership_exclusion_resurrects_fp(self):
        # Non-vacuity: with the exclusion off, transferOwnership's "transfer"
        # token spuriously adds fund-movement, so OWNER_ROLE flags a 2-class
        # span (the measured lido false positive that caused the A3 REJECT).
        orig = A3._is_ownership_transfer_fn
        try:
            A3._is_ownership_transfer_fn = lambda fn: False
            hyps, _ = A3.analyze(self.tmp, A3._load_acl(),
                                 A3._load_predicates())
            owner_flags = [
                h for h in hyps
                if h["flag_kind"] == "blast-radius" and h["role"] == "OWNER_ROLE"]
            self.assertTrue(
                owner_flags,
                "without the exclusion the transferOwnership FP must resurface")
            self.assertIn("fund-movement",
                          owner_flags[0]["distinct_impact_classes"])
            self.assertIn("owner-implementation",
                          owner_flags[0]["distinct_impact_classes"])
        finally:
            A3._is_ownership_transfer_fn = orig

    def test_mutation_collapsing_impacts_kills_blast_flag(self):
        # Non-vacuity: if every sink maps to ONE impact, BROAD stops flagging.
        orig = A3.classify_impacts
        try:
            A3.classify_impacts = lambda row: (
                {"fee"} if str(row.get("fn", "")).lower() not in
                ("grantpowerful", "grantconfig", "grantoracleadmin") else set())
            hyps, _ = A3.analyze(self.tmp, A3._load_acl(),
                                 A3._load_predicates())
            blasts = [h for h in hyps if h["flag_kind"] == "blast-radius"]
            self.assertEqual(blasts, [],
                             "collapsing impacts must remove blast flags")
        finally:
            A3.classify_impacts = orig


if __name__ == "__main__":
    unittest.main()
