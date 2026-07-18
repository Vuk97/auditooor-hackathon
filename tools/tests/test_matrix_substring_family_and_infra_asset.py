#!/usr/bin/env python3
"""Regression (axelar-dlt 2026-07-13) for two completeness-matrix INFRA false-positives:

1. SUBSTRING FAMILY DETECTION: the cdp_liquity strong cues 'ltv'/'icr' fired as raw
   SUBSTRINGS inside unrelated identifiers (defaultVoting, resultValidator,
   trafficRequest), mis-tagging a Cosmos cross-chain BRIDGE (no CDP/trove/collateral-
   ratio surface) as cdp_liquity and fabricating an unsatisfiable family-invariant
   denominator. A bridge-shaped ws with NO CDP signals must NOT get cdp_liquity; a ws
   with real trove/icr/mcr signals still does. Fix = whole-token cue matching.

2. PURE-INFRA PER-FILE ASSET: a logger / non-value util file (zero transfer_hit,
   zero ledger_write_hit, no source value-token) was counted as a per-file asset that
   each needed 10 invariant categories, inflating the floor. A pure-infra file is NOT
   counted; a value-moving file still is. Fix reuses the value-moving signal.
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_substring_infra", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestSubstringFamilyDetection(unittest.TestCase):
    def _ws_go(self, name: str, body: str) -> Path:
        ws = Path(tempfile.mkdtemp())
        rel = f"src/{name}"
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        aud = ws / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        (aud / "inscope_units.jsonl").write_text(
            '{"file": "%s", "function": "Handle"}\n' % rel)
        return ws

    def test_bridge_with_no_cdp_signal_does_not_get_cdp_liquity(self):
        # Cosmos bridge: 'ltv'/'icr' appear ONLY as substrings of unrelated
        # identifiers (defaultVoting, resultValidator, trafficRequest, sicRequest).
        # No standalone ltv/icr/trove/mcr token -> cdp_liquity must NOT be claimed.
        body = (
            "package keeper\n"
            "// cross-chain bridge relayer attestation lock mint\n"
            "func Handle() {\n"
            "  defaultVotingThreshold := 1\n"       # contains 'ltv'
            "  resultValidator := 2\n"              # contains 'ltv'
            "  trafficRequest := 3\n"               # contains 'icr'
            "  sicRequest := 4\n"                   # contains 'icr'
            "  _ = defaultVotingThreshold; _ = resultValidator\n"
            "  _ = trafficRequest; _ = sicRequest\n"
            "  relayer()\n}\n"
        )
        fams = _m._detect_protocol_families(self._ws_go("message_handler.go", body))
        self.assertNotIn("cdp_liquity", fams)
        self.assertIn("bridge_lock_mint", fams)

    def test_real_cdp_with_trove_icr_still_tagged(self):
        body = (
            "package cdp\n"
            "// trove icr mcr collateral liquidate\n"
            "func Handle() {\n"
            "  icr := computeICR()\n"     # standalone 'icr' token
            "  mcr := minRatio()\n"       # standalone 'mcr' token
            "  _ = icr; _ = mcr\n}\n"
        )
        fams = _m._detect_protocol_families(self._ws_go("trove.go", body))
        self.assertIn("cdp_liquity", fams)


class TestInfraFileAsset(unittest.TestCase):
    def _ws(self) -> Path:
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        # pure-infra logger: no transfer / ledger-write / value token
        (ws / "src" / "nopLogger.go").write_text(
            "package utils\nfunc (l NOP) Info(msg string) {}\n"
            "func (l NOP) Error(msg string) {}\n")
        # value-mover: sends coins via bank keeper
        (ws / "src" / "keeper.go").write_text(
            "package bank\nfunc (k Keeper) Send(ctx Ctx) {\n"
            "  k.bankKeeper.SendCoins(ctx, from, to, amt)\n}\n")
        # value-moving-functions artifact: only keeper.go carries transfer_hit
        import json
        (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({
            "functions": [
                {"file": "src/keeper.go", "function": "Send",
                 "transfer_hit": True, "ledger_write_hit": False},
            ]}))
        return ws

    def test_pure_infra_file_has_no_value_signal(self):
        ws = self._ws()
        vm, present = _m._value_moving_files(ws)
        self.assertTrue(present)
        self.assertFalse(
            _m._file_has_value_signal(ws, "src/nopLogger.go", vm),
            "pure-infra logger must carry no value signal (droppable from per-file floor)")

    def test_value_moving_file_still_has_value_signal(self):
        ws = self._ws()
        vm, present = _m._value_moving_files(ws)
        self.assertTrue(present)
        self.assertTrue(
            _m._file_has_value_signal(ws, "src/keeper.go", vm),
            "a transfer_hit file must still count as a per-file asset")

    def test_fail_closed_when_artifact_absent(self):
        # no value_moving_functions.json -> artifact_present False. The drop-site gates
        # the infra drop on _vm_present, so absent -> NO file is ever dropped (the floor
        # keeps every asset an obligation). Contract asserted here = present is False.
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "nopLogger.go").write_text("package utils\nfunc Info() {}\n")
        vm, present = _m._value_moving_files(ws)
        self.assertFalse(present)
        self.assertEqual(vm, set())


if __name__ == "__main__":
    unittest.main()
