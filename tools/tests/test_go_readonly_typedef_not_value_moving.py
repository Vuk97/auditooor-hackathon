#!/usr/bin/env python3
"""Regression test for the Go FILE/PACKAGE-SHAPE false-positive narrowing in
tools/value-moving-functions.py (axelar-dlt 2026-07-13).

The classifier over-flagged three Go shapes that can NEVER move the on-chain
ledger. This test pins the DROP behaviour AND - critically - the KEEP behaviour
that guards against a false-negative:

  DROP  (1) read-only gRPC query server file (Querier receiver OR grpc_query.go
            with all-Request/Response exported methods)
  DROP  (2) pure type-def file (types/types.go) fn that only mutates its own
            receiver struct field in memory (no store handle, no transfer)
  DROP  (3) client CLI file (.../client/cli/...)

  KEEP  (K1) a KEEPER receiver-field write that IS persisted via a `.Set(` store
             call - a real value-mover, MUST stay flagged (false-negative guard)
  KEEP  (K2) a real bank-send function - MUST stay flagged
  KEEP  (K3) a type-def-file fn that DOES a bank transfer - MUST stay flagged
             (shape (2) is per-function, not a blanket file suppression)

Zero workspace literals - synthetic fixtures in a temp dir throughout.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "value-moving-functions.py"
_MOD_NAME = "value_moving_functions"


def _load():
    spec = importlib.util.spec_from_file_location(_MOD_NAME, _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


vmf = _load()


class _WS:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / ".auditooor").mkdir()

    def add(self, rel: str, body: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _fn_set(records):
    return {(Path(r["file"]).name, r["function"]) for r in records}


# ---------------------------------------------------------------------------
# Synthetic Go fixtures.
# ---------------------------------------------------------------------------

# (1) Read-only gRPC query server: Querier receiver, Request->Response methods.
# `assets = append(...)` is a local build that the bare-assign guard would
# already localize, but the whole file must drop regardless.
_QUERY_SERVER = """package keeper

type Querier struct{ keeper Keeper }

func (q Querier) Assets(c context.Context, req *types.AssetsRequest) (*types.AssetsResponse, error) {
	assets := []string{}
	for _, a := range q.keeper.getAssets(c) {
		assets = append(assets, a)
	}
	return &types.AssetsResponse{Assets: assets}, nil
}

func (q Querier) Balances(c context.Context, req *types.BalancesRequest) (*types.BalancesResponse, error) {
	balances := q.keeper.readBalances(c)
	return &types.BalancesResponse{Balances: balances}, nil
}
"""

# (1b) grpc_query.go with a NON-Querier receiver (permission-module shape:
# receiver is `Keeper`), still read-only Request->Response -> drop by filename.
_QUERY_SERVER_KEEPER_RECV = """package keeper

func (k Keeper) Governance(c context.Context, req *types.GovernanceRequest) (*types.GovernanceResponse, error) {
	role := k.getRole(c)
	return &types.GovernanceResponse{Role: role}, nil
}
"""

# (2) Pure type-def file: receiver-field append, no store handle -> DROP AddAsset.
_TYPES_TYPEDEF = """package types

func (m *ChainState) AddAsset(asset exported.Asset) error {
	if m.HasAsset(asset.Denom) {
		return fmt.Errorf("already registered")
	}
	m.Assets = append(m.Assets, asset)
	return nil
}

func (m *ChainState) HasAsset(denom string) bool {
	for _, a := range m.Assets {
		if a.Denom == denom {
			return true
		}
	}
	return false
}
"""

# (K3) type-def file fn that DOES a real bank transfer -> per-function KEEP.
_TYPES_TYPEDEF_WITH_TRANSFER = """package types

func (m *Escrow) Settle(ctx sdk.Context, bank BankKeeper, to sdk.AccAddress) error {
	m.Balance = m.Balance.Sub(m.Pending)
	return bank.SendCoins(ctx, m.Addr, to, m.Pending)
}
"""

# (3) client CLI file: builds messages, never executes state -> DROP whole file.
_CLIENT_CLI = """package cli

func GetCmdSendTokens() *cobra.Command {
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			msg := types.NewMsgTransfer(from, to, amount)
			balance := computeBalance(amount)
			_ = balance
			return tx.GenerateOrBroadcastTxCLI(clientCtx, flags, msg)
		},
	}
	return cmd
}
"""

# (K1) KEEPER receiver-field write PERSISTED via a `.Set(` store call. This is a
# genuine value-mover and MUST stay flagged (the false-negative guard).
_KEEPER_PERSISTED_WRITE = """package keeper

func (k Keeper) AddReward(ctx sdk.Context, addr sdk.AccAddress, amount sdk.Coin) {
	pool := k.getPool(ctx)
	pool.RewardAmount = pool.RewardAmount.Add(amount)
	k.Pools.Set(ctx, addr, pool)
}
"""

# (K2) real bank-send function -> KEEP.
_KEEPER_BANK_SEND = """package keeper

func (k Keeper) Payout(ctx sdk.Context, to sdk.AccAddress, coins sdk.Coins) error {
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "module", to, coins)
}
"""


class GoShapeNarrowingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("x/nexus/keeper/grpc_query.go", _QUERY_SERVER)
        cls.ws.add("x/permission/keeper/grpc_query.go", _QUERY_SERVER_KEEPER_RECV)
        cls.ws.add("x/nexus/types/types.go", _TYPES_TYPEDEF)
        cls.ws.add("x/escrow/types/types.go", _TYPES_TYPEDEF_WITH_TRANSFER)
        cls.ws.add("x/axelarnet/client/cli/tx.go", _CLIENT_CLI)
        cls.ws.add("x/reward/keeper/reward_pool.go", _KEEPER_PERSISTED_WRITE)
        cls.ws.add("x/bank/keeper/payout.go", _KEEPER_BANK_SEND)
        cls.records = vmf.enumerate_value_moving(cls.ws.root)
        cls.fn_set = _fn_set(cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    # ---- DROP cases -------------------------------------------------------
    def test_query_server_querier_recv_dropped(self):
        for fn in ("Assets", "Balances"):
            self.assertNotIn(("grpc_query.go", fn), self.fn_set,
                             f"query-server {fn} should be dropped; got {self.fn_set}")

    def test_query_server_keeper_recv_grpc_filename_dropped(self):
        self.assertNotIn(("grpc_query.go", "Governance"), self.fn_set,
                         "grpc_query.go with Keeper receiver should still drop")

    def test_typedef_inmemory_append_dropped(self):
        self.assertNotIn(("types.go", "AddAsset"), self.fn_set,
                         "in-memory receiver-field append should be dropped")

    def test_client_cli_dropped(self):
        self.assertNotIn(("tx.go", "GetCmdSendTokens"), self.fn_set,
                         "client CLI builder should be dropped")

    # ---- KEEP cases (false-negative guards) -------------------------------
    def test_keeper_persisted_write_kept(self):
        self.assertIn(("reward_pool.go", "AddReward"), self.fn_set,
                      "persisted keeper receiver-field write (.Set) MUST stay flagged")

    def test_keeper_bank_send_kept(self):
        self.assertIn(("payout.go", "Payout"), self.fn_set,
                      "real bank-send MUST stay flagged")

    def test_typedef_file_with_transfer_kept(self):
        self.assertIn(("types.go", "Settle"), self.fn_set,
                      "type-def fn that does a bank transfer MUST stay flagged "
                      "(shape (2) is per-function, not a blanket file drop)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
