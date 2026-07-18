#!/usr/bin/env python3
"""Cosmos-SDK CAP-021 predicate coverage tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location("live_target_intelligence_report", _TOOL_PATH)
assert _spec is not None and _spec.loader is not None
ltir_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ltir_mod)

import unittest


class Cap021CosmosPredicateMatchTest(unittest.TestCase):
    """CAP-021 COSMOS app-chain predicate true/false fixtures."""

    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "cosmos-appchain-ante-ordering",
            matched_p1=[inv_id],
            file_line="app/handler.go:1",
            snippet=source[:120],
            source_context=source,
            source_contract_context=source,
        )

    def test_inv_cosmos_001_direct_keeper_dispatch(self) -> None:
        tp = """
        func (k Keeper) Handle(ctx sdk.Context, msg sdk.Msg) error {
          return k.msgServer.HandleMsgCreateOrder(ctx, msg)
        }
        """

        fp = """
        func (k Keeper) Handle(ctx sdk.Context, msg sdk.Msg) error {
          return k.anteHandler(ctx, msg)
        }
        """

        self.assertEqual(self._semantic("INV-COSMOS-001", tp), ["INV-COSMOS-001"])
        self.assertEqual(self._semantic("INV-COSMOS-001", fp), [])

    def test_inv_cosmos_002_process_proposal_without_txs_validation(self) -> None:
        tp = """
        func (k Keeper) ProcessProposal(ctx sdk.Context, req *abci.RequestProcessProposal) abci.ResponseProcessProposal {
          return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}
        }
        """

        fp = """
        func (k Keeper) ProcessProposal(ctx sdk.Context, req *abci.RequestProcessProposal) abci.ResponseProcessProposal {
          if req.Txs == nil || len(req.Txs) == 0 {
            return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
          }
          return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}
        }
        """

        self.assertEqual(self._semantic("INV-COSMOS-002", tp), ["INV-COSMOS-002"])
        self.assertEqual(self._semantic("INV-COSMOS-002", fp), [])

    def test_inv_cosmos_003_recv_packet_without_open_channel_guard(self) -> None:
        tp = """
        func (k Keeper) RecvPacket(ctx sdk.Context, packet channeltypes.Packet) error {
          return k.processPacket(ctx, packet)
        }
        """

        fp = """
        func (k Keeper) RecvPacket(ctx sdk.Context, packet channeltypes.Packet, channel channeltypes.Channel) error {
          if channel.State != channeltypes.OPEN {
            return fmt.Errorf(\"channel not open\")
          }
          return k.processPacket(ctx, packet, channel)
        }
        """

        self.assertEqual(self._semantic("INV-COSMOS-003", tp), ["INV-COSMOS-003"])
        self.assertEqual(self._semantic("INV-COSMOS-003", fp), [])

    def test_inv_cosmos_004_feecollector_send_without_module_account_guard(self) -> None:
        tp = """
        func (k Keeper) Send(ctx sdk.Context, sender, recipient string, amt sdk.Coins) error {
          return k.bank.SendCoinsFromModuleToAccount(ctx, k.ModuleName, recipient, amt)
        }
        """

        fp = """
        func (k Keeper) Send(ctx sdk.Context, sender, recipient string, amt sdk.Coins) error {
          if k.accountKeeper.GetModuleAccount(ctx, k.ModuleName) == nil {
            return errors.New(\"module account missing\")
          }
          return k.bank.SendCoinsFromModuleToAccount(ctx, k.ModuleName, recipient, amt)
        }
        """

        self.assertEqual(self._semantic("INV-COSMOS-004", tp), ["INV-COSMOS-004"])
        self.assertEqual(self._semantic("INV-COSMOS-004", fp), [])

