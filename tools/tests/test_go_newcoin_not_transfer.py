#!/usr/bin/env python3
"""test_go_newcoin_not_transfer.py

Generic precision fix (2026-07-03, surfaced on NUVA): the Go value-moving detector
counted `sdk.NewCoin(` as a transfer_hit. But sdk.NewCoin is a CONSTRUCTOR (builds a
Coin value - fee calc, event/struct init, zero-balance account construction), NOT a
custody move. This false-flagged every Cosmos coin-constructing function as a custody
mover, which blocked legitimate non-economic dispositions (the disposition lib rejects
any transfer_hit file, so a pure constructor like `NewVaultAccount` could never be
dropped from the value-moving floor). Real transfers keep transfer_hit=True via the
SendCoins / SendCoinsFromModuleTo* / bank.Send* / MintCoins / BurnCoins patterns.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "value-moving-functions.py"


def _load():
    spec = importlib.util.spec_from_file_location("value_moving_functions", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["value_moving_functions"] = m
    spec.loader.exec_module(m)
    return m


class TestGoNewCoinNotTransfer(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.go = self.m._TRANSFER_RES["go"]

    def _hit(self, code):
        return any(rx.search(code) for rx in self.go)

    def test_newcoin_constructor_is_not_a_transfer(self):
        self.assertFalse(self._hit("TotalShares: sdk.NewCoin(shareDenom, sdkmath.ZeroInt())"))
        self.assertFalse(self._hit("fee := sdk.NewCoin(paymentDenom, feeAmt)"))

    def test_real_transfers_still_hit(self):
        self.assertTrue(self._hit("k.bankKeeper.SendCoins(ctx, from, to, amt)"))
        self.assertTrue(self._hit("SendCoinsFromModuleToAccount(ctx, mod, acc, coins)"))
        self.assertTrue(self._hit("k.bankKeeper.MintCoins(ctx, mod, coins)"))
        self.assertTrue(self._hit("k.bankKeeper.BurnCoins(ctx, mod, coins)"))
        self.assertTrue(self._hit("bank.Send(ctx, a, b)"))

    def test_no_bare_newcoin_pattern_remains(self):
        src = _TOOL.read_text(encoding="utf-8")
        # the pattern must not be an ACTIVE compiled matcher (comment mention is fine)
        self.assertNotIn('re.compile(r"\\bsdk\\.NewCoin\\s*\\(")', src)


if __name__ == "__main__":
    unittest.main()
