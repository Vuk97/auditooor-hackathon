"""Regression: value-moving-functions excludes Cosmos-SDK lifecycle hooks (2026-07-14).

InitGenesis / ExportGenesis (run once at chain genesis by the module manager) and a
ctx-only Migrate* store-migration (run once under a gov-gated upgrade) write the
KVStore but are NOT attacker-reachable, so they are not fuzzable value-moving assets
(the value-moving analog of the genesis/migration scaffolding go_entrypoint_surface
already excludes). A user-facing Migrate* MSG handler (second msg/request param) IS
attacker-reachable and must stay value-moving - the false-negative guard.
"""
import importlib.util
import pathlib
import sys
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "value-moving-functions.py"
_spec = importlib.util.spec_from_file_location("_vmf_lifecycle", _TOOL)
_m = importlib.util.module_from_spec(_spec)
sys.modules["_vmf_lifecycle"] = _m
_spec.loader.exec_module(_m)


class VmfCosmosLifecycleExclusion(unittest.TestCase):
    def test_initgenesis_excluded(self):
        self.assertTrue(_m._go_fn_is_lifecycle(
            "InitGenesis", "func (k Keeper) InitGenesis(ctx sdk.Context, g *types.GenesisState)"))

    def test_exportgenesis_excluded(self):
        self.assertTrue(_m._go_fn_is_lifecycle(
            "ExportGenesis", "func (k Keeper) ExportGenesis(ctx sdk.Context)"))

    def test_ctx_only_migrate_excluded(self):
        self.assertTrue(_m._go_fn_is_lifecycle(
            "MigrateVaultAccountPaymentDenomDefaults",
            "func (k Keeper) MigrateVaultAccountPaymentDenomDefaults(ctx sdk.Context)"))
        # cosmos Migrator receiver + context.Context variant
        self.assertTrue(_m._go_fn_is_lifecycle(
            "Migrate1to2", "func (m Migrator) Migrate1to2(ctx context.Context)"))

    def test_msg_handler_migrate_kept(self):
        # FALSE-NEGATIVE GUARD: a user-facing migration msg handler takes a second
        # msg/request param -> attacker-reachable -> must NOT be excluded.
        self.assertFalse(_m._go_fn_is_lifecycle(
            "MigratePosition",
            "func (k msgServer) MigratePosition(goCtx context.Context, msg *types.MsgMigratePosition)"))

    def test_ordinary_value_mover_kept(self):
        self.assertFalse(_m._go_fn_is_lifecycle(
            "Send", "func (k Keeper) Send(ctx sdk.Context, from, to sdk.AccAddress)"))
        # a fn merely starting with 'M' but not Migrate is untouched
        self.assertFalse(_m._go_fn_is_lifecycle(
            "MintCoins", "func (k Keeper) MintCoins(ctx sdk.Context, amt sdk.Coins)"))


if __name__ == "__main__":
    unittest.main()
