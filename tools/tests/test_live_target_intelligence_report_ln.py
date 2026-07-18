#!/usr/bin/env python3
"""Focused LIGHTNING / UTXO / statechain P1 predicate tests."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_ln", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


def _semantic(inv_id: str, source: str) -> list[str]:
    return ltir_mod._semantic_p1_matches(
        "smiv-lightning-direct",
        matched_p1=[inv_id],
        file_line="contracts/Lightning.sol:1",
        snippet="",
        source_context=source,
        source_contract_context=source,
    )


class LnPredicateSemanticsTest(unittest.TestCase):
    def test_lightning_true_positives(self) -> None:
        cases = {
            "INV-LN-001": (
                "contract BadHTLC {\n"
                "  function htlcSuccessTx(bytes32 _paymentHash, uint256 nLockTime) external { }\n"
                "  function htlcTimeoutTx(bytes32 _paymentHash, uint256 refundMaturity) external { }\n"
                "  function claim(bytes32 h, uint256 nLockTime, uint256 refundMaturity) external {\n"
                "    if (nLockTime < block.timestamp + 3600) { /* no SAFETY_MARGIN check */ }\n"
                "  }\n"
                "}\n"
            ),
            "INV-LN-002": (
                "module thresh {\n"
                "  fun configure_signing(threshold: u8, required_signers: vector<Address>, attackers: vector<Address>) {\n"
                "    let threshold = threshold;\n"
                "    let parties: vector<Address> = required_signers;\n"
                "    let _bad = 0;\n"
                "    // missing required_signers ∩ attackers enumeration\n"
                "  }\n"
                "}\n"
            ),
            "INV-LN-003": (
                "fn monitor_watchtower(block: &Block, watched_outpoints: &Vec<OutPoint>) {\n"
                "  // currently checks only one stored outpoint\n"
                "  let target = watched_outpoints[0];\n"
                "  if target.txid != block.txs[0].txid {\n"
                "    return;\n"
                "  }\n"
                "}\n"
            ),
            "INV-LN-004": (
                "contract ForceClose {\n"
                "  function forceClose(bytes32 stateHash, bytes32 revocationSecret) external {\n"
                "    // no revocation_key verification\n"
                "    delete channels[stateHash];\n"
                "  }\n"
                "}\n"
            ),
        }
        for inv_id, source in cases.items():
            self.assertEqual(_semantic(inv_id, source), [inv_id], inv_id)

    def test_lightning_false_positives(self) -> None:
        cases = {
            "INV-LN-001": (
                "contract SafeHTLC {\n"
                "  function htlcSuccessTx(bytes32 hash, uint256 nLockTime) external {}\n"
                "  function htlcTimeoutTx(bytes32 hash, uint256 refundMaturity) external {}\n"
                "  function claim(bytes32 h, uint256 refundMaturity, uint256 SAFETY_MARGIN) external {\n"
                "    require(nLockTime < refundMaturity - SAFETY_MARGIN);\n"
                "  }\n"
                "}\n"
            ),
            "INV-LN-002": (
                "module thresh {\n"
                "  // threshold setup\n"
                "  fun configure_signing(required_signers: vector<Address>, attackers: vector<Address>) {\n"
                "    let risky = required_signers\n"
                "      .intersect(attackers);\n"
                "    if (!risky.is_empty()) { abort(0) }\n"
                "  }\n"
                "}\n"
            ),
            "INV-LN-003": (
                "fn monitor_watchtower(block: &Block, watched_outpoints: &Vec<OutPoint>) {\n"
                "  for tx in block.txs {\n"
                "    if watched_outpoints.contains(&tx.outpoint) { trigger(tx) }\n"
                "  }\n"
                "}\n"
            ),
            "INV-LN-004": (
                "contract ForceClose {\n"
                "  function forceClose(bytes32 stateHash, bytes32 revocation_key) external {\n"
                "    let revocation_key = derive_revocation_key(stateHash);\n"
                "    if (isRevoked(revocation_key)) { require(revocation_key == bytes32(0)); }\n"
                "    delete channels[stateHash];\n"
                "  }\n"
                "}\n"
            ),
        }
        for inv_id, source in cases.items():
            self.assertEqual(_semantic(inv_id, source), [], inv_id)


if __name__ == "__main__":
    unittest.main()
