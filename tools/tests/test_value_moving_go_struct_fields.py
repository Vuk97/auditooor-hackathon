#!/usr/bin/env python3
"""Regression (SCC capability-depth loop 2026-07-08, task_143f301f): the Go VMF
ledger-write extractor must capture STRUCT-FIELD assignments on a local struct
(`vault.TotalShares = ...`), the cosmos must-move-together / partial-flush surface.

Before this, the Go write regexes only matched `k.Field=`/bare `field=` (the
`(?<![.\\w])` lookbehind BLOCKED a member field), so the Provenance vault's coupled
fields (TotalShares/Principal/OutstandingAumFee, written on a local `vault` struct
fetched from a collection then .Set back) were invisible - the SCC conserved-with lane
never saw them (measured on NUVA: Go VMF evidence held collection/local names like
`VaultAccount`/`vault`/`fee`, never `TotalShares`/`Principal`). Self-contained (the
fixture-based GoFixtureTest is separately broken by missing fixture files)."""
import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("vmf_sf", _T / "value-moving-functions.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["vmf_sf"] = _m
_spec.loader.exec_module(_m)


def _captured_value_fields(src: str) -> set:
    fields = set()
    for rx in _m._WRITE_RES["go"]:
        for match in rx.finditer(src):
            tok = match.group(1)
            if tok and _m._is_value_field(tok):
                fields.add(tok)
    return fields


class TestGoStructFieldLedgerWrites(unittest.TestCase):
    RECONCILE = (
        "func (k Keeper) reconcileVault(ctx context.Context, vault types.VaultAccount) {\n"
        "    vault.TotalShares = vault.TotalShares.Add(shares)\n"
        "    vault.Principal = vault.Principal.Add(principalDelta)\n"
        "    vault.OutstandingAumFee = newFee\n"
        "    k.VaultAccounts.Set(ctx, addr, vault)\n"
        "}\n"
    )

    def test_coupled_struct_fields_captured(self):
        got = _captured_value_fields(self.RECONCILE)
        for f in ("TotalShares", "Principal", "OutstandingAumFee"):
            self.assertIn(f, got, f"coupled field {f} must be captured; got {sorted(got)}")

    def test_partial_flush_fn_captures_subset(self):
        # a partial-update fn writes ONLY Principal -> a strict subset of the coupled set.
        partial = (
            "func (k Keeper) badUpdate(ctx context.Context, vault types.VaultAccount) {\n"
            "    vault.Principal = vault.Principal.Add(d)\n"
            "    k.VaultAccounts.Set(ctx, addr, vault)\n"
            "}\n"
        )
        got = _captured_value_fields(partial)
        self.assertIn("Principal", got)
        self.assertNotIn("TotalShares", got, "partial writer must omit TotalShares")

    def test_principal_is_a_value_root(self):
        # `principal` was missing from _VALUE_ROOTS, so a bare `principal` field was
        # dropped as non-value even when captured.
        self.assertTrue(_m._is_value_field("Principal"))
        self.assertTrue(_m._is_value_field("principalPending"))

    def test_non_value_member_not_flagged(self):
        # a non-ledger member assignment (owner/paused/timestamp) must NOT be captured -
        # the broadened member-field regex is value-filtered, not a blanket `.x=` grab.
        # The `k.VaultAccounts.Set(...)` store writeback IS credited (a genuine
        # collections store write), so the only captured token is the store receiver;
        # the non-value members stay out.
        src = (
            "func (k Keeper) setMeta(ctx context.Context, vault types.VaultAccount) {\n"
            "    vault.owner = addr\n"
            "    vault.paused = true\n"
            "    vault.updatedAt = now\n"
            "    k.VaultAccounts.Set(ctx, addr, vault)\n"
            "}\n"
        )
        got = _captured_value_fields(src)
        for member in ("owner", "paused", "updatedAt"):
            self.assertNotIn(member, got,
                             f"non-value struct member {member} must not be a ledger write")
        self.assertEqual(got, {"VaultAccounts"},
                         "only the collections store writeback is credited")

    def test_equality_not_mistaken_for_write(self):
        # a comparison `vault.TotalShares == x` is NOT a write.
        src = "if vault.TotalShares == expected { return }\n"
        self.assertEqual(_captured_value_fields(src), set())


if __name__ == "__main__":
    unittest.main()
