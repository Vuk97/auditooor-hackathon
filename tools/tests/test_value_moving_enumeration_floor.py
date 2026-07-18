#!/usr/bin/env python3
"""Regression tests for the value-moving-functions.py enumeration-floor fix.

Covers the two categories added to close the ROOT-CAUSE blind spots proven by
a real 72h audit (both extended, gated behind AUDITOOOR_VALUE_MOVING_EXTENDED,
default ON since they only ever ADD candidates, never remove any):

  C. "guarded-callee": a callee with NO direct transfer/ledger hit that is
     invoked from within a comparison-guarded conditional branch of an
     already value-moving caller, in the SAME file - flagged
     guarded_callee_hit=true, citing the caller.

  D. "authz_write_hit": a function that writes a role/permission-shaped
     mapping (not a token/balance field) - flagged authz_write_hit=true via
     a SEPARATE regex tier (_is_authz_field), which must never weaken or
     broaden _is_value_field (the token/balance-tuned filter).

Also verifies:
  - the AUDITOOOR_VALUE_MOVING_EXTENDED=0 escape hatch reproduces the
    pre-extension A/B-only record shape/count exactly (backward compat).
  - the OutputStructureTest record-schema keys from the existing suite are
    still all present (no key removed/renamed).
  - no false-positive explosion: an ordinary getter/view function, and a
    helper called from an UNguarded branch or a plain boolean flag branch,
    are NOT newly flagged.

ZERO workspace literals - tmp dirs used throughout.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "value-moving-functions.py"
_MOD_NAME = "value_moving_enumeration_floor_under_test"


def _load():
    spec = importlib.util.spec_from_file_location(_MOD_NAME, _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


vmf = _load()


class _WS:
    """Minimal scratch workspace builder (mirrors test_value_moving_functions.py)."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "src").mkdir()
        (self.root / ".auditooor").mkdir()

    def add(self, rel: str, body: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _by_name(records, name):
    return next((r for r in records if r["function"] == name), None)


# ---------------------------------------------------------------------------
# Category C: guarded-branch callee.
#
# Fixture shape mirrors the class proven missing in a real 72h audit: a
# private valuation-loss-splitter helper invoked ONLY inside a comparison-
# guarded branch of an already value-moving caller (test-fixture naming is
# generic here; the real-world instance is cited only in this comment, per
# instructions to keep the detection code itself workspace-agnostic).
# ---------------------------------------------------------------------------
class GuardedBranchCalleeTest(unittest.TestCase):
    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/Vault.sol",
            "contract Vault {\n"
            "    mapping(address => uint256) balances;\n"
            "    uint256 threshold;\n"
            "\n"
            "    // Caller IS value-moving via a direct transfer.\n"
            "    function settle(address to, uint256 price) external {\n"
            "        if (price < threshold) {\n"
            "            _splitLoss(to, price);\n"
            "        }\n"
            "        safeTransfer(to, price);\n"
            "    }\n"
            "\n"
            "    // Callee has NO direct transfer/ledger hit of its own.\n"
            "    function _splitLoss(address to, uint256 price) private {\n"
            "        emit LossSplit(to, price);\n"
            "    }\n"
            "\n"
            "    // Called from an UNGUARDED plain-flag branch - must NOT be flagged.\n"
            "    function maybeLog(bool verbose) external {\n"
            "        if (verbose) {\n"
            "            _noopLogger();\n"
            "        }\n"
            "        safeTransfer(msg.sender, 1);\n"
            "    }\n"
            "\n"
            "    function _noopLogger() private pure {\n"
            "        return;\n"
            "    }\n"
            "\n"
            "    function getBalance(address u) external view returns (uint256) {\n"
            "        return balances[u];\n"
            "    }\n"
            "}\n",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_guarded_callee_flagged(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "_splitLoss")
        self.assertIsNotNone(
            rec, "guarded-branch callee _splitLoss must be enumerated"
        )
        self.assertTrue(
            rec.get("guarded_callee_hit"),
            f"_splitLoss must carry guarded_callee_hit=true; got: {rec}",
        )
        self.assertEqual(
            rec.get("guarded_callee_caller"), "settle",
            "guarded_callee_caller must cite the value-moving caller by name",
        )
        # Additive only: base A/B fields must remain present and false.
        self.assertFalse(rec["transfer_hit"])
        self.assertFalse(rec["ledger_write_hit"])

    def test_unguarded_plain_flag_callee_not_flagged(self):
        """A callee invoked from a plain boolean-flag 'if (verbose)' branch
        (no comparison operator) must NOT be flagged - the spec requires a
        comparison-guarded branch, not every conditional."""
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "_noopLogger")
        self.assertIsNone(
            rec, f"_noopLogger (unguarded plain-flag branch) incorrectly flagged: {rec}"
        )

    def test_ordinary_getter_not_flagged(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "getBalance")
        self.assertIsNone(
            rec, f"ordinary view getter getBalance incorrectly flagged: {rec}"
        )

    def test_value_moving_caller_still_flagged_via_ab(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "settle")
        self.assertIsNotNone(rec, "settle (direct transfer) must remain value-moving")
        self.assertTrue(rec["transfer_hit"])


# ---------------------------------------------------------------------------
# Category D: authz-write (role/permission mapping write).
# ---------------------------------------------------------------------------
class AuthzWriteTest(unittest.TestCase):
    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/Access.sol",
            "contract Access {\n"
            "    mapping(address => bool) role;\n"
            "    mapping(address => uint256) balances;\n"
            "\n"
            "    // Pure role-grant setter - NO token/balance write at all.\n"
            "    function grantOperator(address addr) external {\n"
            "        role[addr] = true;\n"
            "    }\n"
            "\n"
            "    // Ordinary balance write - must NOT be tagged authz_write_hit.\n"
            "    function credit(address u, uint256 v) external {\n"
            "        balances[u] += v;\n"
            "    }\n"
            "\n"
            "    function isOperator(address addr) external view returns (bool) {\n"
            "        return role[addr];\n"
            "    }\n"
            "}\n",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_role_grant_setter_flagged(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "grantOperator")
        self.assertIsNotNone(
            rec, "role-grant setter grantOperator must be enumerated"
        )
        self.assertTrue(
            rec.get("authz_write_hit"),
            f"grantOperator must carry authz_write_hit=true; got: {rec}",
        )
        self.assertIn("role", rec.get("authz_write_evidence", []))
        # It has no direct token/balance write - A/B must stay false.
        self.assertFalse(rec["transfer_hit"])
        self.assertFalse(rec["ledger_write_hit"])

    def test_ordinary_balance_write_not_authz_tagged(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "credit")
        self.assertIsNotNone(rec, "credit (balance write) must remain value-moving via B")
        self.assertTrue(rec["ledger_write_hit"])
        self.assertFalse(
            rec.get("authz_write_hit", False),
            "ordinary balance write must NOT be mis-tagged authz_write_hit",
        )

    def test_view_getter_not_flagged(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "isOperator")
        self.assertIsNone(
            rec, f"view getter isOperator incorrectly flagged: {rec}"
        )


class AuthzGrantRoleCallTest(unittest.TestCase):
    """grantRole(...)-shaped call sites (OZ AccessControl / custom
    equivalents) are a strong authz signal even without a bare
    ``field[key] = value`` write (e.g. delegated to an internal library)."""

    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/RoleAdmin.sol",
            "contract RoleAdmin is AccessControl {\n"
            "    function addAdmin(address addr) external {\n"
            "        grantRole(ADMIN_ROLE, addr);\n"
            "    }\n"
            "}\n",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_grant_role_call_flagged(self):
        records = vmf.enumerate_value_moving(self.ws.root)
        rec = _by_name(records, "addAdmin")
        self.assertIsNotNone(rec, "addAdmin (grantRole call) must be enumerated")
        self.assertTrue(rec.get("authz_write_hit"))


# ---------------------------------------------------------------------------
# Backward-compat: AUDITOOOR_VALUE_MOVING_EXTENDED=0 reproduces pre-extension
# behavior exactly (A/B-only union, same record keys as before).
# ---------------------------------------------------------------------------
class ExtendedGateBackwardCompatTest(unittest.TestCase):
    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/Vault.sol",
            "contract Vault {\n"
            "    mapping(address => uint256) balances;\n"
            "    mapping(address => bool) role;\n"
            "    uint256 threshold;\n"
            "\n"
            "    function settle(address to, uint256 price) external {\n"
            "        if (price < threshold) {\n"
            "            _splitLoss(to, price);\n"
            "        }\n"
            "        safeTransfer(to, price);\n"
            "    }\n"
            "\n"
            "    function _splitLoss(address to, uint256 price) private {\n"
            "        emit LossSplit(to, price);\n"
            "    }\n"
            "\n"
            "    function grantOperator(address addr) external {\n"
            "        role[addr] = true;\n"
            "    }\n"
            "}\n",
        )
        self._prev = os.environ.get("AUDITOOOR_VALUE_MOVING_EXTENDED")

    def tearDown(self):
        self.ws.cleanup()
        if self._prev is None:
            os.environ.pop("AUDITOOOR_VALUE_MOVING_EXTENDED", None)
        else:
            os.environ["AUDITOOOR_VALUE_MOVING_EXTENDED"] = self._prev

    def test_extended_off_drops_new_categories(self):
        os.environ["AUDITOOOR_VALUE_MOVING_EXTENDED"] = "0"
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records}
        # Category C/D-only functions must vanish entirely when disabled.
        self.assertNotIn("_splitLoss", names,
                         "guarded-callee-only fn must not appear when EXTENDED=0")
        self.assertNotIn("grantOperator", names,
                         "authz-only fn must not appear when EXTENDED=0")
        # settle remains value-moving via A (direct transfer) regardless.
        self.assertIn("settle", names)
        rec = _by_name(records, "settle")
        # No extended keys leak into the record when the gate is off.
        self.assertNotIn("guarded_callee_hit", rec)
        self.assertNotIn("authz_write_hit", rec)

    def test_extended_default_on_adds_categories(self):
        os.environ.pop("AUDITOOOR_VALUE_MOVING_EXTENDED", None)
        records = vmf.enumerate_value_moving(self.ws.root)
        names = {r["function"] for r in records}
        self.assertIn("_splitLoss", names)
        self.assertIn("grantOperator", names)

    def test_base_record_keys_always_present(self):
        """Regardless of the extended gate, every existing key from the
        documented schema (OutputStructureTest in test_value_moving_functions.py)
        must remain present and unchanged - additive-only guarantee."""
        for env_val in ("0", "1"):
            os.environ["AUDITOOOR_VALUE_MOVING_EXTENDED"] = env_val
            records = vmf.enumerate_value_moving(self.ws.root)
            rec = _by_name(records, "settle")
            self.assertIsNotNone(rec)
            for key in ("file", "function", "language",
                        "transfer_hit", "ledger_write_hit",
                        "transfer_evidence", "ledger_write_evidence"):
                self.assertIn(key, rec,
                             f"missing base key '{key}' with EXTENDED={env_val}: {rec}")


# ---------------------------------------------------------------------------
# run() end-to-end: JSON output remains schema-stable with extended fields.
# ---------------------------------------------------------------------------
class RunOutputExtendedSchemaTest(unittest.TestCase):
    def setUp(self):
        self.ws = _WS()
        self.ws.add(
            "src/Vault.sol",
            "contract Vault {\n"
            "    mapping(address => bool) role;\n"
            "    function grantOperator(address addr) external {\n"
            "        role[addr] = true;\n"
            "    }\n"
            "}\n",
        )

    def tearDown(self):
        self.ws.cleanup()

    def test_run_writes_valid_json_with_extended_fields(self):
        out = vmf.run(self.ws.root)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("functions", payload)
        rec = _by_name(payload["functions"], "grantOperator")
        self.assertIsNotNone(rec)
        self.assertTrue(rec.get("authz_write_hit"))
        # Original required keys still present.
        for key in ("file", "function", "language",
                    "transfer_hit", "ledger_write_hit",
                    "transfer_evidence", "ledger_write_evidence"):
            self.assertIn(key, rec)


if __name__ == "__main__":
    unittest.main(verbosity=2)
